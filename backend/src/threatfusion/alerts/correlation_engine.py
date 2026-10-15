"""Provenance-gated dual-window alert correlation engine and reduction metrics.

Implements the fail-closed correlation architecture for TF-008:
1. EntityProvenanceContract: strict immutable descriptor for alert candidate provenance.
2. Fail-Closed UNSW-NB15 Rule: unverified provenance (missing entity_namespace_id,
   clock_synchronized=False, or missing endpoints) strictly produces singleton incidents.
3. Dual-Window Correlation for authenticated entity-bearing alerts:
   - 30-Second Burst Window (BURST_WINDOW_SECONDS = 30) for identical 5-tuples.
   - 10-Minute Campaign Window (CAMPAIGN_WINDOW_SECONDS = 600) for same endpoint pair.
4. Empirical Alert Fatigue Reduction and 100% Critical Scenario Retention Safety Gate.
5. Transactional SQLite persistence for correlated incidents.
"""

from __future__ import annotations

import hashlib
import sqlite3
import stat
import struct
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from threatfusion.schemas.alert_candidate import AlertCandidate

BURST_WINDOW_SECONDS = 30.0
CAMPAIGN_WINDOW_SECONDS = 600.0
SQLITE_BUSY_TIMEOUT_MS = 500

INCIDENT_SCHEMA_VERSION = "incident_record_v1"
ALERT_REDUCTION_SCHEMA_VERSION = "alert_reduction_summary_v1"
INCIDENT_REPOSITORY_SCHEMA_IDENTITY = "incident_sqlite_v1"
INCIDENT_REPOSITORY_SCHEMA_VERSION = 1


class CorrelationSafetyError(RuntimeError):
    """Raised when a correlation safety invariant is violated."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _identity_digest(domain: str, parts: tuple[str, ...]) -> str:
    digest = hashlib.sha256(domain.encode("ascii") + b"\0")
    for part in parts:
        encoded = part.encode("utf-8")
        digest.update(struct.pack(">I", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()


def derive_incident_id(correlation_rule_id: str, constituent_alert_ids: tuple[str, ...]) -> str:
    """Deterministically derive a tamper-evident incident identifier."""
    sorted_ids = sorted(constituent_alert_ids)
    parts = (INCIDENT_SCHEMA_VERSION, correlation_rule_id, *sorted_ids)
    return f"incident_v1:{_identity_digest('threatfusion:incident', parts)}"


@dataclass(frozen=True, slots=True)
class EntityProvenanceContract:
    """Strict immutable provenance descriptor for alert candidates."""

    entity_namespace_id: str | None = None
    clock_synchronized: bool = False
    src_entity_id: str | None = None
    dst_entity_id: str | None = None
    protocol: str | None = None
    service_or_port: str | None = None
    observed_at_utc: str | None = None

    def is_verified(self) -> bool:
        """Fail-closed check: requires namespace, synchronized clock, and both endpoints."""
        return (
            self.entity_namespace_id is not None
            and bool(self.entity_namespace_id.strip())
            and self.clock_synchronized is True
            and self.src_entity_id is not None
            and bool(self.src_entity_id.strip())
            and self.dst_entity_id is not None
            and bool(self.dst_entity_id.strip())
        )


@dataclass(frozen=True, slots=True)
class CorrelatableAlert:
    """AlertCandidate coupled with its verified or unverified entity provenance."""

    candidate: AlertCandidate
    provenance: EntityProvenanceContract | None = None


@dataclass(frozen=True, slots=True)
class IncidentRecord:
    """Correlated security incident grouping one or more alert candidates."""

    schema_version: str
    incident_id: str
    correlation_mode: str  # singleton_unverified_provenance, singleton_verified_provenance, burst_correlated, campaign_correlated
    window_type: str  # none, burst_30s, campaign_600s
    correlation_rule_id: str
    entity_namespace_id: str | None
    constituent_alert_ids: tuple[str, ...]
    constituent_alert_count: int
    max_probability_score: float
    escalated_decision: str
    earliest_observed_at: str
    latest_observed_at: str
    provenance_status: str
    created_at: str


@dataclass(frozen=True, slots=True)
class AlertReductionSummary:
    """Empirical fatigue reduction metrics and 100% critical scenario retention evidence."""

    schema_version: str
    total_alerts: int
    total_incidents: int
    reduction_ratio: float
    critical_alerts_input: int
    critical_alerts_retained: int
    critical_retention_ratio: float


@dataclass(frozen=True, slots=True)
class IncidentCorrelationResult:
    """Bundle of resulting incidents and verified reduction summary."""

    incidents: tuple[IncidentRecord, ...]
    summary: AlertReductionSummary

    def __iter__(self):
        """Allow unpacking: incidents, summary = correlate_alert_candidates(...)."""
        return iter((self.incidents, self.summary))


def _parse_timestamp(candidate: AlertCandidate, provenance: EntityProvenanceContract) -> float:
    if provenance.observed_at_utc:
        try:
            iso_str = provenance.observed_at_utc.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.timestamp()
        except Exception:
            pass
    return candidate.observed_at.timestamp()


def _is_critical_alert(alert: AlertCandidate) -> bool:
    return alert.decision == "Attack" or alert.uncalibrated_model_score >= alert.decision_threshold


def compute_alert_reduction_metrics(
    alerts: Sequence[AlertCandidate | CorrelatableAlert],
    incidents: Sequence[IncidentRecord],
) -> AlertReductionSummary:
    """Validate 100% critical scenario retention and compute alert reduction ratio.

    Raises CorrelationSafetyError if any input alert (especially critical alert)
    is dropped, omitted, or orphaned.
    """
    normalized_alerts: list[AlertCandidate] = [
        a.candidate if isinstance(a, CorrelatableAlert) else a for a in alerts
    ]
    total_alerts = len(normalized_alerts)
    total_incidents = len(incidents)

    if total_alerts == 0:
        return AlertReductionSummary(
            schema_version=ALERT_REDUCTION_SCHEMA_VERSION,
            total_alerts=0,
            total_incidents=0,
            reduction_ratio=0.0,
            critical_alerts_input=0,
            critical_alerts_retained=0,
            critical_retention_ratio=1.0,
        )

    # Verify every alert appears in exactly one incident
    assigned_alert_ids: list[str] = []
    for inc in incidents:
        assigned_alert_ids.extend(inc.constituent_alert_ids)

    seen_set = set(assigned_alert_ids)
    if len(assigned_alert_ids) != len(seen_set):
        raise CorrelationSafetyError("duplicate_alert_assignment")

    input_id_set = {a.alert_candidate_id for a in normalized_alerts}
    if seen_set != input_id_set:
        raise CorrelationSafetyError("critical_alert_dropped")

    # Critical retention check
    critical_alerts_input = sum(1 for a in normalized_alerts if _is_critical_alert(a))
    critical_alerts_retained = 0

    candidate_by_id = {a.alert_candidate_id: a for a in normalized_alerts}
    for inc in incidents:
        constituent_candidates = [
            candidate_by_id[aid] for aid in inc.constituent_alert_ids if aid in candidate_by_id
        ]
        # Invariant check: incident escalated_decision must preserve Attack if any constituent is Attack
        if any(_is_critical_alert(c) for c in constituent_candidates):
            if inc.escalated_decision != "Attack":
                raise CorrelationSafetyError("critical_decision_downgraded")
            critical_alerts_retained += sum(
                1 for c in constituent_candidates if _is_critical_alert(c)
            )

    if critical_alerts_input > 0 and critical_alerts_retained != critical_alerts_input:
        raise CorrelationSafetyError("critical_alert_dropped")

    critical_retention_ratio = 1.0
    reduction_ratio = 1.0 - (total_incidents / total_alerts)

    return AlertReductionSummary(
        schema_version=ALERT_REDUCTION_SCHEMA_VERSION,
        total_alerts=total_alerts,
        total_incidents=total_incidents,
        reduction_ratio=reduction_ratio,
        critical_alerts_input=critical_alerts_input,
        critical_alerts_retained=critical_alerts_retained,
        critical_retention_ratio=critical_retention_ratio,
    )


def correlate_alert_candidates(
    alerts: Sequence[AlertCandidate | CorrelatableAlert],
    provenance_map: Mapping[str, EntityProvenanceContract] | None = None,
) -> IncidentCorrelationResult:
    """Execute dual-window correlation with fail-closed provenance gating."""
    if not alerts:
        summary = compute_alert_reduction_metrics([], [])
        return IncidentCorrelationResult(incidents=(), summary=summary)

    # Normalize inputs into (candidate, provenance, timestamp)
    items: list[tuple[AlertCandidate, EntityProvenanceContract, float]] = []
    for item in alerts:
        if isinstance(item, CorrelatableAlert):
            cand = item.candidate
            prov = item.provenance or (
                provenance_map.get(cand.alert_candidate_id) if provenance_map else None
            )
        else:
            cand = item
            prov = provenance_map.get(cand.alert_candidate_id) if provenance_map else None

        if prov is None:
            prov = EntityProvenanceContract()

        ts = _parse_timestamp(cand, prov)
        items.append((cand, prov, ts))

    incidents_list: list[IncidentRecord] = []
    now_iso = datetime.now(UTC).isoformat()

    # 1. Separate unverified provenance (Fail-closed UNSW-NB15 rule)
    unverified_items = [it for it in items if not it[1].is_verified()]
    verified_items = [it for it in items if it[1].is_verified()]

    for cand, _prov, _ts in unverified_items:
        inc_id = derive_incident_id(
            "corr_singleton_unverified_provenance_v1", (cand.alert_candidate_id,)
        )
        incidents_list.append(
            IncidentRecord(
                schema_version=INCIDENT_SCHEMA_VERSION,
                incident_id=inc_id,
                correlation_mode="singleton_unverified_provenance",
                window_type="none",
                correlation_rule_id="corr_singleton_unverified_provenance_v1",
                entity_namespace_id=None,
                constituent_alert_ids=(cand.alert_candidate_id,),
                constituent_alert_count=1,
                max_probability_score=cand.uncalibrated_model_score,
                escalated_decision=cand.decision,
                earliest_observed_at=cand.observed_at.isoformat(),
                latest_observed_at=cand.observed_at.isoformat(),
                provenance_status="unverified_provenance",
                created_at=now_iso,
            )
        )

    # 2. Dual-window correlation for verified items
    # Partition by entity_namespace_id to guarantee cross-namespace isolation
    by_namespace: dict[str, list[tuple[AlertCandidate, EntityProvenanceContract, float]]] = (
        defaultdict(list)
    )
    for it in verified_items:
        ns = it[1].entity_namespace_id
        assert ns is not None
        by_namespace[ns].append(it)

    for ns, ns_items in by_namespace.items():
        # Sort items chronologically with tie-breaker by alert_candidate_id
        ns_items.sort(key=lambda x: (x[2], x[0].alert_candidate_id))

        # Pass 1: 30-Second Burst Window for 5-tuples
        by_5tuple: dict[
            tuple[str, str, str, str],
            list[tuple[AlertCandidate, EntityProvenanceContract, float]],
        ] = defaultdict(list)
        for it in ns_items:
            prov = it[1]
            k5 = (
                prov.src_entity_id or "",
                prov.dst_entity_id or "",
                (prov.protocol or "").lower(),
                (prov.service_or_port or "").lower(),
            )
            by_5tuple[k5].append(it)

        burst_clustered_ids: set[str] = set()
        unclustered_verified: list[tuple[AlertCandidate, EntityProvenanceContract, float]] = []

        for _k5, tuple_items in by_5tuple.items():
            tuple_items.sort(key=lambda x: (x[2], x[0].alert_candidate_id))
            current_cluster: list[tuple[AlertCandidate, EntityProvenanceContract, float]] = []
            anchor_t: float | None = None

            for it in tuple_items:
                if anchor_t is None:
                    anchor_t = it[2]
                    current_cluster.append(it)
                elif it[2] - anchor_t <= BURST_WINDOW_SECONDS:
                    current_cluster.append(it)
                else:
                    # Flush previous cluster
                    if len(current_cluster) >= 2:
                        cands = [x[0] for x in current_cluster]
                        ids = tuple(c.alert_candidate_id for c in cands)
                        burst_clustered_ids.update(ids)
                        inc_id = derive_incident_id("corr_burst_5tuple_30s_v1", ids)
                        incidents_list.append(
                            IncidentRecord(
                                schema_version=INCIDENT_SCHEMA_VERSION,
                                incident_id=inc_id,
                                correlation_mode="burst_correlated",
                                window_type="burst_30s",
                                correlation_rule_id="corr_burst_5tuple_30s_v1",
                                entity_namespace_id=ns,
                                constituent_alert_ids=ids,
                                constituent_alert_count=len(ids),
                                max_probability_score=max(
                                    c.uncalibrated_model_score for c in cands
                                ),
                                escalated_decision=(
                                    "Attack"
                                    if any(c.decision == "Attack" for c in cands)
                                    else cands[0].decision
                                ),
                                earliest_observed_at=min(c.observed_at.isoformat() for c in cands),
                                latest_observed_at=max(c.observed_at.isoformat() for c in cands),
                                provenance_status="verified_entity_bearing",
                                created_at=now_iso,
                            )
                        )
                    else:
                        unclustered_verified.extend(current_cluster)
                    anchor_t = it[2]
                    current_cluster = [it]

            if current_cluster:
                if len(current_cluster) >= 2:
                    cands = [x[0] for x in current_cluster]
                    ids = tuple(c.alert_candidate_id for c in cands)
                    burst_clustered_ids.update(ids)
                    inc_id = derive_incident_id("corr_burst_5tuple_30s_v1", ids)
                    incidents_list.append(
                        IncidentRecord(
                            schema_version=INCIDENT_SCHEMA_VERSION,
                            incident_id=inc_id,
                            correlation_mode="burst_correlated",
                            window_type="burst_30s",
                            correlation_rule_id="corr_burst_5tuple_30s_v1",
                            entity_namespace_id=ns,
                            constituent_alert_ids=ids,
                            constituent_alert_count=len(ids),
                            max_probability_score=max(c.uncalibrated_model_score for c in cands),
                            escalated_decision=(
                                "Attack"
                                if any(c.decision == "Attack" for c in cands)
                                else cands[0].decision
                            ),
                            earliest_observed_at=min(c.observed_at.isoformat() for c in cands),
                            latest_observed_at=max(c.observed_at.isoformat() for c in cands),
                            provenance_status="verified_entity_bearing",
                            created_at=now_iso,
                        )
                    )
                else:
                    unclustered_verified.extend(current_cluster)

        # Pass 2: 10-Minute Campaign Window for unclustered verified items
        by_host_pair: dict[
            frozenset[str],
            list[tuple[AlertCandidate, EntityProvenanceContract, float]],
        ] = defaultdict(list)
        for it in unclustered_verified:
            prov = it[1]
            pair_key = frozenset({prov.src_entity_id or "", prov.dst_entity_id or ""})
            by_host_pair[pair_key].append(it)

        for _pair_key, pair_items in by_host_pair.items():
            pair_items.sort(key=lambda x: (x[2], x[0].alert_candidate_id))
            current_cluster = []
            anchor_t = None

            for it in pair_items:
                if anchor_t is None:
                    anchor_t = it[2]
                    current_cluster.append(it)
                elif it[2] - anchor_t <= CAMPAIGN_WINDOW_SECONDS:
                    current_cluster.append(it)
                else:
                    # Flush previous cluster
                    if len(current_cluster) >= 2:
                        cands = [x[0] for x in current_cluster]
                        ids = tuple(c.alert_candidate_id for c in cands)
                        inc_id = derive_incident_id("corr_campaign_entity_pair_600s_v1", ids)
                        incidents_list.append(
                            IncidentRecord(
                                schema_version=INCIDENT_SCHEMA_VERSION,
                                incident_id=inc_id,
                                correlation_mode="campaign_correlated",
                                window_type="campaign_600s",
                                correlation_rule_id="corr_campaign_entity_pair_600s_v1",
                                entity_namespace_id=ns,
                                constituent_alert_ids=ids,
                                constituent_alert_count=len(ids),
                                max_probability_score=max(
                                    c.uncalibrated_model_score for c in cands
                                ),
                                escalated_decision=(
                                    "Attack"
                                    if any(c.decision == "Attack" for c in cands)
                                    else cands[0].decision
                                ),
                                earliest_observed_at=min(c.observed_at.isoformat() for c in cands),
                                latest_observed_at=max(c.observed_at.isoformat() for c in cands),
                                provenance_status="verified_entity_bearing",
                                created_at=now_iso,
                            )
                        )
                    else:
                        # Single item -> verified singleton incident
                        single_cand = current_cluster[0][0]
                        inc_id = derive_incident_id(
                            "corr_singleton_verified_v1",
                            (single_cand.alert_candidate_id,),
                        )
                        incidents_list.append(
                            IncidentRecord(
                                schema_version=INCIDENT_SCHEMA_VERSION,
                                incident_id=inc_id,
                                correlation_mode="singleton_verified_provenance",
                                window_type="none",
                                correlation_rule_id="corr_singleton_verified_v1",
                                entity_namespace_id=ns,
                                constituent_alert_ids=(single_cand.alert_candidate_id,),
                                constituent_alert_count=1,
                                max_probability_score=single_cand.uncalibrated_model_score,
                                escalated_decision=single_cand.decision,
                                earliest_observed_at=single_cand.observed_at.isoformat(),
                                latest_observed_at=single_cand.observed_at.isoformat(),
                                provenance_status="verified_entity_bearing",
                                created_at=now_iso,
                            )
                        )
                    anchor_t = it[2]
                    current_cluster = [it]

            if current_cluster:
                if len(current_cluster) >= 2:
                    cands = [x[0] for x in current_cluster]
                    ids = tuple(c.alert_candidate_id for c in cands)
                    inc_id = derive_incident_id("corr_campaign_entity_pair_600s_v1", ids)
                    incidents_list.append(
                        IncidentRecord(
                            schema_version=INCIDENT_SCHEMA_VERSION,
                            incident_id=inc_id,
                            correlation_mode="campaign_correlated",
                            window_type="campaign_600s",
                            correlation_rule_id="corr_campaign_entity_pair_600s_v1",
                            entity_namespace_id=ns,
                            constituent_alert_ids=ids,
                            constituent_alert_count=len(ids),
                            max_probability_score=max(c.uncalibrated_model_score for c in cands),
                            escalated_decision=(
                                "Attack"
                                if any(c.decision == "Attack" for c in cands)
                                else cands[0].decision
                            ),
                            earliest_observed_at=min(c.observed_at.isoformat() for c in cands),
                            latest_observed_at=max(c.observed_at.isoformat() for c in cands),
                            provenance_status="verified_entity_bearing",
                            created_at=now_iso,
                        )
                    )
                else:
                    single_cand = current_cluster[0][0]
                    inc_id = derive_incident_id(
                        "corr_singleton_verified_v1", (single_cand.alert_candidate_id,)
                    )
                    incidents_list.append(
                        IncidentRecord(
                            schema_version=INCIDENT_SCHEMA_VERSION,
                            incident_id=inc_id,
                            correlation_mode="singleton_verified_provenance",
                            window_type="none",
                            correlation_rule_id="corr_singleton_verified_v1",
                            entity_namespace_id=ns,
                            constituent_alert_ids=(single_cand.alert_candidate_id,),
                            constituent_alert_count=1,
                            max_probability_score=single_cand.uncalibrated_model_score,
                            escalated_decision=single_cand.decision,
                            earliest_observed_at=single_cand.observed_at.isoformat(),
                            latest_observed_at=single_cand.observed_at.isoformat(),
                            provenance_status="verified_entity_bearing",
                            created_at=now_iso,
                        )
                    )

    # Sort final incidents deterministically by (earliest_observed_at, incident_id)
    incidents_list.sort(key=lambda x: (x.earliest_observed_at, x.incident_id))
    incidents_tuple = tuple(incidents_list)

    # Compute and verify reduction metrics
    summary = compute_alert_reduction_metrics(alerts, incidents_tuple)
    return IncidentCorrelationResult(incidents=incidents_tuple, summary=summary)


# --- SQLite Repository for Incident Persistence ---

_CREATE_INCIDENTS_METADATA = """
CREATE TABLE repository_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
"""

_CREATE_INCIDENTS_TABLE = """
CREATE TABLE incidents (
    schema_version TEXT NOT NULL,
    incident_id TEXT PRIMARY KEY,
    correlation_mode TEXT NOT NULL,
    window_type TEXT NOT NULL,
    correlation_rule_id TEXT NOT NULL,
    entity_namespace_id TEXT,
    constituent_alert_count INTEGER NOT NULL,
    max_probability_score REAL NOT NULL,
    escalated_decision TEXT NOT NULL,
    earliest_observed_at TEXT NOT NULL,
    latest_observed_at TEXT NOT NULL,
    provenance_status TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;
"""

_CREATE_CONSTITUENTS_TABLE = """
CREATE TABLE incident_constituent_alerts (
    incident_id TEXT NOT NULL,
    alert_candidate_id TEXT NOT NULL,
    PRIMARY KEY (incident_id, alert_candidate_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
) STRICT;
"""

_CREATE_CONSTITUENTS_INDEX = """
CREATE INDEX idx_constituent_alert_id ON incident_constituent_alerts(alert_candidate_id);
"""


class IncidentSqliteRepository:
    """Fail-closed, transactional SQLite storage for IncidentRecords."""

    def __init__(self, database_path: Path | str) -> None:
        self.path = Path(database_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.path),
            timeout=SQLITE_BUSY_TIMEOUT_MS / 1000.0,
            isolation_level=None,  # autocommit / explicit transactions
        )
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS};")
        return conn

    def _init_db(self) -> None:
        created = not self.path.exists()
        if created:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Create file with 0600 permissions
            self.path.touch(mode=0o600, exist_ok=False)

        conn = self._connect()
        try:
            with conn:
                conn.execute("BEGIN IMMEDIATE;")
                # Check metadata
                tables = {
                    r[0]
                    for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table';"
                    ).fetchall()
                }
                if "repository_metadata" not in tables:
                    conn.execute(_CREATE_INCIDENTS_METADATA)
                    conn.execute(
                        "INSERT INTO repository_metadata (key, value) VALUES ('schema_identity', ?);",
                        (INCIDENT_REPOSITORY_SCHEMA_IDENTITY,),
                    )
                    conn.execute(
                        "INSERT INTO repository_metadata (key, value) VALUES ('schema_version', ?);",
                        (str(INCIDENT_REPOSITORY_SCHEMA_VERSION),),
                    )
                    conn.execute(_CREATE_INCIDENTS_TABLE)
                    conn.execute(_CREATE_CONSTITUENTS_TABLE)
                    conn.execute(_CREATE_CONSTITUENTS_INDEX)
                else:
                    # Verify schema identity
                    row = conn.execute(
                        "SELECT value FROM repository_metadata WHERE key='schema_identity';"
                    ).fetchone()
                    if not row or row[0] != INCIDENT_REPOSITORY_SCHEMA_IDENTITY:
                        raise CorrelationSafetyError("repository_schema_mismatch")
        finally:
            conn.close()

        # Enforce mode 0600
        mode = stat.S_IMODE(self.path.stat().st_mode)
        if mode != 0o600:
            self.path.chmod(0o600)

    def insert(self, incident: IncidentRecord) -> None:
        """Atomically persist one incident and its constituent alert references."""
        conn = self._connect()
        try:
            with conn:
                conn.execute("BEGIN IMMEDIATE;")
                # Idempotency check
                existing = conn.execute(
                    "SELECT incident_id FROM incidents WHERE incident_id = ?;",
                    (incident.incident_id,),
                ).fetchone()
                if existing:
                    return

                conn.execute(
                    """
                    INSERT INTO incidents (
                        schema_version, incident_id, correlation_mode, window_type,
                        correlation_rule_id, entity_namespace_id, constituent_alert_count,
                        max_probability_score, escalated_decision, earliest_observed_at,
                        latest_observed_at, provenance_status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        incident.schema_version,
                        incident.incident_id,
                        incident.correlation_mode,
                        incident.window_type,
                        incident.correlation_rule_id,
                        incident.entity_namespace_id,
                        incident.constituent_alert_count,
                        incident.max_probability_score,
                        incident.escalated_decision,
                        incident.earliest_observed_at,
                        incident.latest_observed_at,
                        incident.provenance_status,
                        incident.created_at,
                    ),
                )
                for aid in incident.constituent_alert_ids:
                    conn.execute(
                        """
                        INSERT INTO incident_constituent_alerts (incident_id, alert_candidate_id)
                        VALUES (?, ?);
                        """,
                        (incident.incident_id, aid),
                    )
        finally:
            conn.close()

    def insert_many(self, incidents: Sequence[IncidentRecord]) -> None:
        """Atomically persist a batch of incidents in a single transaction."""
        conn = self._connect()
        try:
            with conn:
                conn.execute("BEGIN IMMEDIATE;")
                for inc in incidents:
                    existing = conn.execute(
                        "SELECT incident_id FROM incidents WHERE incident_id = ?;",
                        (inc.incident_id,),
                    ).fetchone()
                    if existing:
                        continue
                    conn.execute(
                        """
                        INSERT INTO incidents (
                            schema_version, incident_id, correlation_mode, window_type,
                            correlation_rule_id, entity_namespace_id, constituent_alert_count,
                            max_probability_score, escalated_decision, earliest_observed_at,
                            latest_observed_at, provenance_status, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            inc.schema_version,
                            inc.incident_id,
                            inc.correlation_mode,
                            inc.window_type,
                            inc.correlation_rule_id,
                            inc.entity_namespace_id,
                            inc.constituent_alert_count,
                            inc.max_probability_score,
                            inc.escalated_decision,
                            inc.earliest_observed_at,
                            inc.latest_observed_at,
                            inc.provenance_status,
                            inc.created_at,
                        ),
                    )
                    for aid in inc.constituent_alert_ids:
                        conn.execute(
                            """
                            INSERT INTO incident_constituent_alerts (incident_id, alert_candidate_id)
                            VALUES (?, ?);
                            """,
                            (inc.incident_id, aid),
                        )
        finally:
            conn.close()

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        """Lookup an incident by its ID."""
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT
                    schema_version, incident_id, correlation_mode, window_type,
                    correlation_rule_id, entity_namespace_id, constituent_alert_count,
                    max_probability_score, escalated_decision, earliest_observed_at,
                    latest_observed_at, provenance_status, created_at
                FROM incidents WHERE incident_id = ?;
                """,
                (incident_id,),
            ).fetchone()
            if not row:
                return None

            constituents = conn.execute(
                "SELECT alert_candidate_id FROM incident_constituent_alerts WHERE incident_id = ? ORDER BY alert_candidate_id;",
                (incident_id,),
            ).fetchall()
            ids = tuple(r[0] for r in constituents)

            return IncidentRecord(
                schema_version=row[0],
                incident_id=row[1],
                correlation_mode=row[2],
                window_type=row[3],
                correlation_rule_id=row[4],
                entity_namespace_id=row[5],
                constituent_alert_ids=ids,
                constituent_alert_count=row[6],
                max_probability_score=float(row[7]),
                escalated_decision=row[8],
                earliest_observed_at=row[9],
                latest_observed_at=row[10],
                provenance_status=row[11],
                created_at=row[12],
            )
        finally:
            conn.close()

    def get_incident_for_alert(self, alert_candidate_id: str) -> IncidentRecord | None:
        """Find the correlated incident containing a specific alert candidate."""
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT i.schema_version, i.incident_id, i.correlation_mode, i.window_type,
                       i.correlation_rule_id, i.entity_namespace_id, i.constituent_alert_count,
                       i.max_probability_score, i.escalated_decision, i.earliest_observed_at,
                       i.latest_observed_at, i.provenance_status, i.created_at
                FROM incidents i
                JOIN incident_constituent_alerts ica ON i.incident_id = ica.incident_id
                WHERE ica.alert_candidate_id = ?;
                """,
                (alert_candidate_id,),
            ).fetchone()
            if not row:
                return None

            inc_id = row[1]
            constituents = conn.execute(
                "SELECT alert_candidate_id FROM incident_constituent_alerts WHERE incident_id = ? ORDER BY alert_candidate_id;",
                (inc_id,),
            ).fetchall()
            ids = tuple(r[0] for r in constituents)

            return IncidentRecord(
                schema_version=row[0],
                incident_id=row[1],
                correlation_mode=row[2],
                window_type=row[3],
                correlation_rule_id=row[4],
                entity_namespace_id=row[5],
                constituent_alert_ids=ids,
                constituent_alert_count=row[6],
                max_probability_score=float(row[7]),
                escalated_decision=row[8],
                earliest_observed_at=row[9],
                latest_observed_at=row[10],
                provenance_status=row[11],
                created_at=row[12],
            )
        finally:
            conn.close()

    def list_incidents(self, limit: int = 50, offset: int = 0) -> tuple[IncidentRecord, ...]:
        """List persisted incidents ordered by earliest_observed_at DESC."""
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT
                    schema_version, incident_id, correlation_mode, window_type,
                    correlation_rule_id, entity_namespace_id, constituent_alert_count,
                    max_probability_score, escalated_decision, earliest_observed_at,
                    latest_observed_at, provenance_status, created_at
                FROM incidents
                ORDER BY earliest_observed_at DESC, incident_id ASC
                LIMIT ? OFFSET ?;
                """,
                (limit, offset),
            ).fetchall()

            results = []
            for r in rows:
                inc_id = r[1]
                constituents = conn.execute(
                    "SELECT alert_candidate_id FROM incident_constituent_alerts WHERE incident_id = ? ORDER BY alert_candidate_id;",
                    (inc_id,),
                ).fetchall()
                ids = tuple(c[0] for c in constituents)
                results.append(
                    IncidentRecord(
                        schema_version=r[0],
                        incident_id=r[1],
                        correlation_mode=r[2],
                        window_type=r[3],
                        correlation_rule_id=r[4],
                        entity_namespace_id=r[5],
                        constituent_alert_ids=ids,
                        constituent_alert_count=r[6],
                        max_probability_score=float(r[7]),
                        escalated_decision=r[8],
                        earliest_observed_at=r[9],
                        latest_observed_at=r[10],
                        provenance_status=r[11],
                        created_at=r[12],
                    )
                )
            return tuple(results)
        finally:
            conn.close()

    def count_incidents(self) -> int:
        """Count total incidents in repository."""
        conn = self._connect()
        try:
            row = conn.execute("SELECT COUNT(*) FROM incidents;").fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()
