"""Provenance-gated dual-window alert correlation engine and reduction metrics.

Implements the fail-closed correlation architecture for TF-008, TF-009, and Phases P3/P4:
1. EntityProvenanceContract: strict immutable descriptor for alert candidate provenance,
   including entity validity interval, address reuse / NAT ambiguity, and clock skew bounds.
2. Candidate Deduplication vs. Incident Grouping: repeated submissions of identical alert candidates
   collapse cleanly without inflating constituent counts.
3. Fail-Closed Provenance Gating: unverified provenance, NAT / address reuse ambiguity, clock skew
   exceeding 5.0s, or timestamps outside entity validity intervals strictly produce singleton incidents.
4. Dual-Window Correlation for authenticated entity-bearing alerts:
   - 30-Second Burst Window (BURST_WINDOW_SECONDS = 30.0) for identical 5-tuples.
   - 10-Minute Campaign Window (CAMPAIGN_WINDOW_SECONDS = 600.0) for same endpoint pair.
5. Out-of-Order / Late-Arriving Event Sorting: deterministic ordering produces identical incident clusters.
6. Per-Event Grouping Justification: structured audit metadata stored for each constituent alert.
7. Audited Grouping Correction: investigator-directed manual split/reassignment with idempotent UUIDv4 replay.
8. Empirical Alert Fatigue Reduction and 100% Critical Scenario Retention Safety Gate.
9. Transactional SQLite persistence for correlated incidents and grouping corrections.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import stat
import struct
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threatfusion.schemas.alert_candidate import AlertCandidate

BURST_WINDOW_SECONDS = 30.0
CAMPAIGN_WINDOW_SECONDS = 600.0
MAX_ALLOWABLE_CLOCK_SKEW_SECONDS = 5.0
SQLITE_BUSY_TIMEOUT_MS = 5000

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
    validity_start_utc: str | None = None
    validity_end_utc: str | None = None
    address_reuse_or_nat: bool = False
    max_clock_skew_seconds: float = 0.0
    source_mode: str | None = None
    entity_role: str | None = None
    clock_origin: str | None = None

    @property
    def src_ip(self) -> str | None:
        if not self.src_entity_id:
            return None
        val = self.src_entity_id
        for prefix in (
            "attacker:",
            "victim:",
            "client:",
            "server:",
            "sensor:",
            "node:",
            "host:",
            "vm:",
        ):
            if val.startswith(prefix):
                return val[len(prefix) :]
        return val

    @property
    def dst_ip(self) -> str | None:
        if not self.dst_entity_id:
            return None
        val = self.dst_entity_id
        for prefix in (
            "attacker:",
            "victim:",
            "client:",
            "server:",
            "sensor:",
            "node:",
            "host:",
            "vm:",
        ):
            if val.startswith(prefix):
                return val[len(prefix) :]
        return val

    def verification_rejection_reason(self) -> str | None:
        """Return the specific rejection reason if provenance is unverified, or None if verified."""
        if not self.entity_namespace_id or not self.entity_namespace_id.strip():
            return "missing_entity_namespace"
        if self.clock_synchronized is not True:
            return "clock_not_synchronized"
        if not self.src_entity_id or not self.src_entity_id.strip():
            return "missing_src_entity_id"
        if not self.dst_entity_id or not self.dst_entity_id.strip():
            return "missing_dst_entity_id"
        if self.address_reuse_or_nat is True:
            return "nat_address_reuse_ambiguous"
        if self.max_clock_skew_seconds > MAX_ALLOWABLE_CLOCK_SKEW_SECONDS:
            return "clock_skew_exceeded"
        if self.observed_at_utc:
            try:
                obs_dt = datetime.fromisoformat(self.observed_at_utc.replace("Z", "+00:00"))
                if obs_dt.tzinfo is None:
                    obs_dt = obs_dt.replace(tzinfo=UTC)
                if self.validity_start_utc:
                    v_start = datetime.fromisoformat(self.validity_start_utc.replace("Z", "+00:00"))
                    if v_start.tzinfo is None:
                        v_start = v_start.replace(tzinfo=UTC)
                    if obs_dt < v_start:
                        return "outside_entity_validity_interval"
                if self.validity_end_utc:
                    v_end = datetime.fromisoformat(self.validity_end_utc.replace("Z", "+00:00"))
                    if v_end.tzinfo is None:
                        v_end = v_end.replace(tzinfo=UTC)
                    if obs_dt > v_end:
                        return "outside_entity_validity_interval"
            except Exception:
                return "invalid_timestamp_bounds"
        return None

    def is_verified(self) -> bool:
        """Fail-closed check: requires namespace, synchronized clock, valid endpoints, no NAT, within skew/interval."""
        return self.verification_rejection_reason() is None


@dataclass(frozen=True, slots=True)
class CorrelatableAlert:
    """AlertCandidate coupled with its verified or unverified entity provenance."""

    candidate: AlertCandidate
    provenance: EntityProvenanceContract | None = None


@dataclass(frozen=True, slots=True)
class MemberJustification:
    """Structured audit justification for an alert's membership in a correlated incident."""

    anchor_alert_id: str
    delta_seconds: float
    matched_relationship_key: str
    rule_id: str
    provenance_summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor_alert_id": self.anchor_alert_id,
            "delta_seconds": self.delta_seconds,
            "matched_relationship_key": self.matched_relationship_key,
            "rule_id": self.rule_id,
            "provenance_summary": self.provenance_summary,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MemberJustification:
        return cls(
            anchor_alert_id=str(data.get("anchor_alert_id", "")),
            delta_seconds=float(data.get("delta_seconds", 0.0)),
            matched_relationship_key=str(data.get("matched_relationship_key", "")),
            rule_id=str(data.get("rule_id", "")),
            provenance_summary=str(data.get("provenance_summary", "")),
        )


@dataclass(frozen=True, slots=True)
class IncidentRecord:
    """Correlated security incident grouping one or more alert candidates."""

    schema_version: str
    incident_id: str
    correlation_mode: str  # singleton_unverified_provenance, singleton_verified_provenance, burst_correlated, campaign_correlated, manual_correction_split
    window_type: str  # none, burst_30s, campaign_600s, manual
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
    member_justifications: Mapping[str, MemberJustification] = field(default_factory=dict)
    t_flow_ingest: float | None = None
    t_rag_grounded: float | None = None
    t_investigation: float | None = None


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
    # Unique candidates only for metric calculation
    unique_candidates: list[AlertCandidate] = []
    seen_ids: set[str] = set()
    for c in normalized_alerts:
        if c.alert_candidate_id in seen_ids:
            continue
        seen_ids.add(c.alert_candidate_id)
        unique_candidates.append(c)

    total_alerts = len(unique_candidates)
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

    input_id_set = {a.alert_candidate_id for a in unique_candidates}
    if seen_set != input_id_set:
        raise CorrelationSafetyError("critical_alert_dropped")

    # Critical retention check
    critical_alerts_input = sum(1 for a in unique_candidates if _is_critical_alert(a))
    critical_alerts_retained = 0

    candidate_by_id = {a.alert_candidate_id: a for a in unique_candidates}
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
    """Execute dual-window correlation with fail-closed provenance gating.

    Handles candidate deduplication vs grouping, out-of-order arrival, exact boundary times,
    and records member justifications for each constituent alert.
    """
    if not alerts:
        summary = compute_alert_reduction_metrics([], [])
        return IncidentCorrelationResult(incidents=(), summary=summary)

    # 1. Candidate Deduplication: repeated submissions of the exact same candidate
    # are collapsed without inflating constituent counts.
    deduped_alerts: list[AlertCandidate | CorrelatableAlert] = []
    seen_candidate_ids: set[str] = set()
    for item in alerts:
        cand_id = (
            item.candidate.alert_candidate_id
            if isinstance(item, CorrelatableAlert)
            else item.alert_candidate_id
        )
        if cand_id in seen_candidate_ids:
            continue
        seen_candidate_ids.add(cand_id)
        deduped_alerts.append(item)

    # Normalize inputs into (candidate, provenance, timestamp)
    items: list[tuple[AlertCandidate, EntityProvenanceContract, float]] = []
    for item in deduped_alerts:
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

    # 2. Separate unverified provenance (Fail-closed UNSW-NB15, NAT, clock skew, and validity limits)
    unverified_items = [it for it in items if not it[1].is_verified()]
    verified_items = [it for it in items if it[1].is_verified()]

    for cand, prov, _ts in unverified_items:
        rejection_reason = prov.verification_rejection_reason() or "unverified_provenance"
        if rejection_reason in {
            "missing_entity_namespace",
            "clock_not_synchronized",
            "missing_src_entity_id",
            "missing_dst_entity_id",
        }:
            status_label = "unverified_provenance"
        else:
            status_label = rejection_reason

        inc_id = derive_incident_id(
            "corr_singleton_unverified_provenance_v1", (cand.alert_candidate_id,)
        )
        just = MemberJustification(
            anchor_alert_id=cand.alert_candidate_id,
            delta_seconds=0.0,
            matched_relationship_key="none",
            rule_id="corr_singleton_unverified_provenance_v1",
            provenance_summary=rejection_reason,
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
                provenance_status=status_label,
                created_at=now_iso,
                member_justifications={cand.alert_candidate_id: just},
            )
        )

    # 3. Dual-window correlation for verified items
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
        # Guarantees out-of-order and late events produce identical groupings
        ns_items.sort(key=lambda x: (x[2], x[0].alert_candidate_id))

        # Pass 1: 30-Second Burst Window for exact 5-tuples
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
                        anchor_id = current_cluster[0][0].alert_candidate_id
                        justs = {}
                        for cit in current_cluster:
                            c, p, t = cit
                            justs[c.alert_candidate_id] = MemberJustification(
                                anchor_alert_id=anchor_id,
                                delta_seconds=round(t - anchor_t, 6),
                                matched_relationship_key=f"{p.src_entity_id}:{p.dst_entity_id}:{p.protocol}:{p.service_or_port}",
                                rule_id="corr_burst_5tuple_30s_v1",
                                provenance_summary=f"namespace={ns},clock_synchronized=True,skew={p.max_clock_skew_seconds}s",
                            )
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
                                member_justifications=justs,
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
                    anchor_id = current_cluster[0][0].alert_candidate_id
                    justs = {}
                    for cit in current_cluster:
                        c, p, t = cit
                        justs[c.alert_candidate_id] = MemberJustification(
                            anchor_alert_id=anchor_id,
                            delta_seconds=round(t - anchor_t, 6) if anchor_t is not None else 0.0,
                            matched_relationship_key=f"{p.src_entity_id}:{p.dst_entity_id}:{p.protocol}:{p.service_or_port}",
                            rule_id="corr_burst_5tuple_30s_v1",
                            provenance_summary=f"namespace={ns},clock_synchronized=True,skew={p.max_clock_skew_seconds}s",
                        )
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
                            member_justifications=justs,
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
                        anchor_id = current_cluster[0][0].alert_candidate_id
                        justs = {}
                        for cit in current_cluster:
                            c, p, t = cit
                            sorted_ep = sorted([p.src_entity_id or "", p.dst_entity_id or ""])
                            justs[c.alert_candidate_id] = MemberJustification(
                                anchor_alert_id=anchor_id,
                                delta_seconds=round(t - anchor_t, 6),
                                matched_relationship_key=f"{sorted_ep[0]}<->{sorted_ep[1]}",
                                rule_id="corr_campaign_entity_pair_600s_v1",
                                provenance_summary=f"namespace={ns},clock_synchronized=True,skew={p.max_clock_skew_seconds}s",
                            )
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
                                member_justifications=justs,
                            )
                        )
                    else:
                        # Single item -> verified singleton incident
                        single_cand = current_cluster[0][0]
                        inc_id = derive_incident_id(
                            "corr_singleton_verified_v1",
                            (single_cand.alert_candidate_id,),
                        )
                        just = MemberJustification(
                            anchor_alert_id=single_cand.alert_candidate_id,
                            delta_seconds=0.0,
                            matched_relationship_key="singleton_verified",
                            rule_id="corr_singleton_verified_v1",
                            provenance_summary=f"namespace={ns},clock_synchronized=True",
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
                                member_justifications={single_cand.alert_candidate_id: just},
                            )
                        )
                    anchor_t = it[2]
                    current_cluster = [it]

            if current_cluster:
                if len(current_cluster) >= 2:
                    cands = [x[0] for x in current_cluster]
                    ids = tuple(c.alert_candidate_id for c in cands)
                    inc_id = derive_incident_id("corr_campaign_entity_pair_600s_v1", ids)
                    anchor_id = current_cluster[0][0].alert_candidate_id
                    justs = {}
                    for cit in current_cluster:
                        c, p, t = cit
                        sorted_ep = sorted([p.src_entity_id or "", p.dst_entity_id or ""])
                        justs[c.alert_candidate_id] = MemberJustification(
                            anchor_alert_id=anchor_id,
                            delta_seconds=(round(t - anchor_t, 6) if anchor_t is not None else 0.0),
                            matched_relationship_key=f"{sorted_ep[0]}<->{sorted_ep[1]}",
                            rule_id="corr_campaign_entity_pair_600s_v1",
                            provenance_summary=f"namespace={ns},clock_synchronized=True,skew={p.max_clock_skew_seconds}s",
                        )
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
                            member_justifications=justs,
                        )
                    )
                else:
                    single_cand = current_cluster[0][0]
                    inc_id = derive_incident_id(
                        "corr_singleton_verified_v1", (single_cand.alert_candidate_id,)
                    )
                    just = MemberJustification(
                        anchor_alert_id=single_cand.alert_candidate_id,
                        delta_seconds=0.0,
                        matched_relationship_key="singleton_verified",
                        rule_id="corr_singleton_verified_v1",
                        provenance_summary=f"namespace={ns},clock_synchronized=True",
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
                            member_justifications={single_cand.alert_candidate_id: just},
                        )
                    )

    # Sort final incidents deterministically by (earliest_observed_at, incident_id)
    incidents_list.sort(key=lambda x: (x.earliest_observed_at, x.incident_id))
    incidents_tuple = tuple(incidents_list)

    # Compute and verify reduction metrics
    summary = compute_alert_reduction_metrics(deduped_alerts, incidents_tuple)
    return IncidentCorrelationResult(incidents=incidents_tuple, summary=summary)


class IncidentCorrelationEngine:
    """Enterprise Incident Correlation Engine wrapping dual-window correlation."""

    def __init__(self, repo: IncidentSqliteRepository | None = None) -> None:
        self.repo = repo

    def correlate(
        self,
        alerts: Sequence[AlertCandidate | CorrelatableAlert],
        provenance_map: Mapping[str, EntityProvenanceContract] | None = None,
    ) -> IncidentCorrelationResult:
        res = correlate_alert_candidates(alerts, provenance_map=provenance_map)
        if self.repo is not None and res.incidents:
            self.repo.insert_many(res.incidents)
        return res


# --- SQLite Repository for Incident Persistence & Audited Corrections ---

_CREATE_INCIDENTS_METADATA = """
CREATE TABLE IF NOT EXISTS repository_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
"""

_CREATE_INCIDENTS_TABLE = """
CREATE TABLE IF NOT EXISTS incidents (
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
    created_at TEXT NOT NULL,
    t_flow_ingest REAL,
    t_rag_grounded REAL,
    t_investigation REAL
) STRICT;
"""

_CREATE_CONSTITUENTS_TABLE = """
CREATE TABLE IF NOT EXISTS incident_constituent_alerts (
    incident_id TEXT NOT NULL,
    alert_candidate_id TEXT NOT NULL,
    member_justification TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (incident_id, alert_candidate_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
) STRICT;
"""

_CREATE_CONSTITUENTS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_constituent_alert_id ON incident_constituent_alerts(alert_candidate_id);
"""

_CREATE_CORRECTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS incident_grouping_corrections (
    correction_request_id TEXT PRIMARY KEY,
    alert_candidate_id TEXT NOT NULL,
    original_incident_id TEXT NOT NULL,
    target_incident_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;
"""

_CREATE_CORRECTIONS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_grouping_correction_alert ON incident_grouping_corrections(alert_candidate_id);
"""


class IncidentSqliteRepository:
    """Fail-closed, transactional SQLite storage for IncidentRecords and Grouping Corrections."""

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
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        created = not self.path.exists()
        if created:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch(mode=0o600, exist_ok=False)

        conn = self._connect()
        try:
            with conn:
                conn.execute("BEGIN IMMEDIATE;")
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
                    conn.execute(_CREATE_CORRECTIONS_TABLE)
                    conn.execute(_CREATE_CORRECTIONS_INDEX)
                    conn.execute(f"PRAGMA user_version = {INCIDENT_REPOSITORY_SCHEMA_VERSION};")
                else:
                    # Verify schema identity
                    row = conn.execute(
                        "SELECT value FROM repository_metadata WHERE key='schema_identity';"
                    ).fetchone()
                    if not row or row[0] != INCIDENT_REPOSITORY_SCHEMA_IDENTITY:
                        raise CorrelationSafetyError("repository_schema_mismatch")

                    # Check for schema migrations
                    cols = {
                        c[1]
                        for c in conn.execute(
                            "PRAGMA table_info(incident_constituent_alerts);"
                        ).fetchall()
                    }
                    if "member_justification" not in cols:
                        conn.execute(
                            "ALTER TABLE incident_constituent_alerts ADD COLUMN member_justification TEXT NOT NULL DEFAULT '{}';"
                        )

                    cols_inc = {
                        c[1] for c in conn.execute("PRAGMA table_info(incidents);").fetchall()
                    }
                    if "t_flow_ingest" not in cols_inc:
                        conn.execute("ALTER TABLE incidents ADD COLUMN t_flow_ingest REAL;")
                    if "t_rag_grounded" not in cols_inc:
                        conn.execute("ALTER TABLE incidents ADD COLUMN t_rag_grounded REAL;")
                    if "t_investigation" not in cols_inc:
                        conn.execute("ALTER TABLE incidents ADD COLUMN t_investigation REAL;")

                    conn.execute(_CREATE_CORRECTIONS_TABLE)
                    conn.execute(_CREATE_CORRECTIONS_INDEX)
                    conn.execute(f"PRAGMA user_version = {INCIDENT_REPOSITORY_SCHEMA_VERSION};")
                self._verify_schema(conn)
        finally:
            conn.close()

        mode = stat.S_IMODE(self.path.stat().st_mode)
        if mode != 0o600:
            self.path.chmod(0o600)

    @property
    def _database_path(self) -> Path:
        return self.path

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            row = connection.execute(
                "SELECT value FROM repository_metadata WHERE key='schema_identity';"
            ).fetchone()
            if (
                not row
                or row[0] != INCIDENT_REPOSITORY_SCHEMA_IDENTITY
                or version != INCIDENT_REPOSITORY_SCHEMA_VERSION
            ):
                raise CorrelationSafetyError("repository_schema_mismatch")
        except sqlite3.Error:
            raise CorrelationSafetyError("repository_schema_mismatch") from None

    def insert(self, incident: IncidentRecord) -> None:
        """Atomically persist one incident and its constituent alert references."""
        conn = self._connect()
        try:
            with conn:
                conn.execute("BEGIN IMMEDIATE;")
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
                        latest_observed_at, provenance_status, created_at,
                        t_flow_ingest, t_rag_grounded, t_investigation
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                        incident.t_flow_ingest,
                        incident.t_rag_grounded,
                        incident.t_investigation,
                    ),
                )
                for aid in incident.constituent_alert_ids:
                    just = incident.member_justifications.get(aid)
                    just_json = json.dumps(just.to_dict()) if just else "{}"
                    conn.execute(
                        """
                        INSERT INTO incident_constituent_alerts (incident_id, alert_candidate_id, member_justification)
                        VALUES (?, ?, ?);
                        """,
                        (incident.incident_id, aid, just_json),
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
                            latest_observed_at, provenance_status, created_at,
                            t_flow_ingest, t_rag_grounded, t_investigation
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                            inc.t_flow_ingest,
                            inc.t_rag_grounded,
                            inc.t_investigation,
                        ),
                    )
                    for aid in inc.constituent_alert_ids:
                        just = inc.member_justifications.get(aid)
                        just_json = json.dumps(just.to_dict()) if just else "{}"
                        conn.execute(
                            """
                            INSERT INTO incident_constituent_alerts (incident_id, alert_candidate_id, member_justification)
                            VALUES (?, ?, ?);
                            """,
                            (inc.incident_id, aid, just_json),
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
                    latest_observed_at, provenance_status, created_at,
                    t_flow_ingest, t_rag_grounded, t_investigation
                FROM incidents WHERE incident_id = ?;
                """,
                (incident_id,),
            ).fetchone()
            if not row:
                return None

            constituents = conn.execute(
                "SELECT alert_candidate_id, member_justification FROM incident_constituent_alerts WHERE incident_id = ? ORDER BY alert_candidate_id;",
                (incident_id,),
            ).fetchall()
            ids = tuple(r[0] for r in constituents)
            justs: dict[str, MemberJustification] = {}
            for r in constituents:
                aid = r[0]
                raw_j = r[1]
                if raw_j and raw_j != "{}":
                    try:
                        justs[aid] = MemberJustification.from_dict(json.loads(raw_j))
                    except Exception:
                        pass

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
                member_justifications=justs,
                t_flow_ingest=row[13] if len(row) > 13 else None,
                t_rag_grounded=row[14] if len(row) > 14 else None,
                t_investigation=row[15] if len(row) > 15 else None,
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
                       i.latest_observed_at, i.provenance_status, i.created_at,
                       i.t_flow_ingest, i.t_rag_grounded, i.t_investigation
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
                "SELECT alert_candidate_id, member_justification FROM incident_constituent_alerts WHERE incident_id = ? ORDER BY alert_candidate_id;",
                (inc_id,),
            ).fetchall()
            ids = tuple(r[0] for r in constituents)
            justs: dict[str, MemberJustification] = {}
            for r in constituents:
                aid = r[0]
                raw_j = r[1]
                if raw_j and raw_j != "{}":
                    try:
                        justs[aid] = MemberJustification.from_dict(json.loads(raw_j))
                    except Exception:
                        pass

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
                member_justifications=justs,
                t_flow_ingest=row[13] if len(row) > 13 else None,
                t_rag_grounded=row[14] if len(row) > 14 else None,
                t_investigation=row[15] if len(row) > 15 else None,
            )
        finally:
            conn.close()

    def record_investigation_telemetry(
        self,
        incident_id: str,
        t_flow_ingest: float,
        t_rag_grounded: float,
        t_investigation: float | None = None,
    ) -> float:
        """Record deterministic MTTI telemetry timestamps for an incident."""
        calc_investigation = (
            round(max(0.0, float(t_rag_grounded) - float(t_flow_ingest)), 6)
            if t_investigation is None
            else float(t_investigation)
        )
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    UPDATE incidents
                    SET t_flow_ingest = ?, t_rag_grounded = ?, t_investigation = ?
                    WHERE incident_id = ?;
                    """,
                    (float(t_flow_ingest), float(t_rag_grounded), calc_investigation, incident_id),
                )
        finally:
            conn.close()
        return calc_investigation

    def list_incident_timings(self) -> list[dict[str, Any]]:
        """Return list of recorded incident MTTI intervals without clock drift."""
        conn = self._connect()
        try:
            rows = conn.execute("""
                SELECT incident_id, t_flow_ingest, t_rag_grounded, t_investigation
                FROM incidents
                WHERE t_investigation IS NOT NULL
                ORDER BY created_at ASC;
                """).fetchall()
            return [
                {
                    "incident_id": r[0],
                    "t_flow_ingest": r[1],
                    "t_rag_grounded": r[2],
                    "t_investigation": r[3],
                }
                for r in rows
            ]
        finally:
            conn.close()

    def correct_incident_grouping(
        self,
        alert_candidate_id: str,
        *,
        new_incident_id: str | None = None,
        actor_id: str,
        reason: str,
        correction_request_id: str,
    ) -> IncidentRecord:
        """Split an erroneously grouped alert into a separate corrected incident with audit and replay safety."""
        if not alert_candidate_id or not alert_candidate_id.strip():
            raise CorrelationSafetyError("alert_candidate_id_required")
        if not actor_id or not actor_id.strip():
            raise CorrelationSafetyError("actor_id_required")
        if not reason or not reason.strip():
            raise CorrelationSafetyError("reason_required")
        if not correction_request_id or not correction_request_id.strip():
            raise CorrelationSafetyError("correction_request_id_required")

        conn = self._connect()
        try:
            with conn:
                conn.execute("BEGIN IMMEDIATE;")

                # Idempotency check: replay of exact correction_request_id
                existing_corr = conn.execute(
                    """
                    SELECT alert_candidate_id, target_incident_id, actor_id
                    FROM incident_grouping_corrections
                    WHERE correction_request_id = ?;
                    """,
                    (correction_request_id,),
                ).fetchone()

                if existing_corr is not None:
                    if existing_corr[0] == alert_candidate_id and existing_corr[2] == actor_id:
                        target_id = existing_corr[1]
                        row = conn.execute(
                            """
                            SELECT
                                schema_version, incident_id, correlation_mode, window_type,
                                correlation_rule_id, entity_namespace_id, constituent_alert_count,
                                max_probability_score, escalated_decision, earliest_observed_at,
                                latest_observed_at, provenance_status, created_at
                            FROM incidents WHERE incident_id = ?;
                            """,
                            (target_id,),
                        ).fetchone()
                        if row is not None:
                            constituents = conn.execute(
                                "SELECT alert_candidate_id, member_justification FROM incident_constituent_alerts WHERE incident_id = ? ORDER BY alert_candidate_id;",
                                (target_id,),
                            ).fetchall()
                            ids = tuple(r[0] for r in constituents)
                            justs: dict[str, MemberJustification] = {}
                            for r in constituents:
                                if r[1] and r[1] != "{}":
                                    try:
                                        justs[r[0]] = MemberJustification.from_dict(
                                            json.loads(r[1])
                                        )
                                    except Exception:
                                        pass
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
                                member_justifications=justs,
                            )
                    raise CorrelationSafetyError("correction_request_conflict")

                # Find current incident containing this candidate
                current_inc_row = conn.execute(
                    """
                    SELECT i.incident_id, i.constituent_alert_count, i.entity_namespace_id,
                           i.max_probability_score, i.escalated_decision, i.earliest_observed_at,
                           i.latest_observed_at, ica.member_justification
                    FROM incidents i
                    JOIN incident_constituent_alerts ica ON i.incident_id = ica.incident_id
                    WHERE ica.alert_candidate_id = ?;
                    """,
                    (alert_candidate_id,),
                ).fetchone()

                if not current_inc_row:
                    raise CorrelationSafetyError("alert_not_found")

                orig_incident_id = current_inc_row[0]
                orig_count = current_inc_row[1]
                entity_namespace_id = current_inc_row[2]
                max_score = current_inc_row[3]
                escalated_decision = current_inc_row[4]
                earliest_obs = current_inc_row[5]
                latest_obs = current_inc_row[6]
                now_iso = datetime.now(UTC).isoformat()

                if orig_count <= 1:
                    # Already singleton
                    target_incident_id = orig_incident_id
                    conn.execute(
                        """
                        INSERT INTO incident_grouping_corrections (
                            correction_request_id, alert_candidate_id, original_incident_id,
                            target_incident_id, actor_id, reason, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            correction_request_id,
                            alert_candidate_id,
                            orig_incident_id,
                            target_incident_id,
                            actor_id,
                            reason,
                            now_iso,
                        ),
                    )
                else:
                    target_incident_id = new_incident_id or derive_incident_id(
                        "corr_manual_correction_split_v1", (alert_candidate_id,)
                    )

                    # Remove from original incident
                    conn.execute(
                        "DELETE FROM incident_constituent_alerts WHERE incident_id = ? AND alert_candidate_id = ?;",
                        (orig_incident_id, alert_candidate_id),
                    )
                    conn.execute(
                        "UPDATE incidents SET constituent_alert_count = constituent_alert_count - 1 WHERE incident_id = ?;",
                        (orig_incident_id,),
                    )

                    # Insert target incident
                    new_just = MemberJustification(
                        anchor_alert_id=alert_candidate_id,
                        delta_seconds=0.0,
                        matched_relationship_key="manual_split",
                        rule_id="corr_manual_correction_split_v1",
                        provenance_summary=f"manual_split by actor={actor_id}: {reason}",
                    )
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
                            INCIDENT_SCHEMA_VERSION,
                            target_incident_id,
                            "manual_correction_split",
                            "manual",
                            "corr_manual_correction_split_v1",
                            entity_namespace_id,
                            1,
                            max_score,
                            escalated_decision,
                            earliest_obs,
                            latest_obs,
                            "manual_corrected",
                            now_iso,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO incident_constituent_alerts (incident_id, alert_candidate_id, member_justification)
                        VALUES (?, ?, ?);
                        """,
                        (
                            target_incident_id,
                            alert_candidate_id,
                            json.dumps(new_just.to_dict()),
                        ),
                    )

                    # Record correction audit entry
                    conn.execute(
                        """
                        INSERT INTO incident_grouping_corrections (
                            correction_request_id, alert_candidate_id, original_incident_id,
                            target_incident_id, actor_id, reason, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            correction_request_id,
                            alert_candidate_id,
                            orig_incident_id,
                            target_incident_id,
                            actor_id,
                            reason,
                            now_iso,
                        ),
                    )

            return self.get_incident(target_incident_id)  # type: ignore[return-value]
        finally:
            conn.close()

    def get_grouping_corrections(
        self, alert_candidate_id: str | None = None
    ) -> list[dict[str, Any]]:
        """List grouping correction audit entries."""
        conn = self._connect()
        try:
            if alert_candidate_id is not None:
                rows = conn.execute(
                    """
                    SELECT correction_request_id, alert_candidate_id, original_incident_id,
                           target_incident_id, actor_id, reason, created_at
                    FROM incident_grouping_corrections
                    WHERE alert_candidate_id = ?
                    ORDER BY created_at ASC;
                    """,
                    (alert_candidate_id,),
                ).fetchall()
            else:
                rows = conn.execute("""
                    SELECT correction_request_id, alert_candidate_id, original_incident_id,
                           target_incident_id, actor_id, reason, created_at
                    FROM incident_grouping_corrections
                    ORDER BY created_at ASC;
                    """).fetchall()

            return [
                {
                    "correction_request_id": r[0],
                    "alert_candidate_id": r[1],
                    "original_incident_id": r[2],
                    "target_incident_id": r[3],
                    "actor_id": r[4],
                    "reason": r[5],
                    "created_at": r[6],
                }
                for r in rows
            ]
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
                    "SELECT alert_candidate_id, member_justification FROM incident_constituent_alerts WHERE incident_id = ? ORDER BY alert_candidate_id;",
                    (inc_id,),
                ).fetchall()
                ids = tuple(c[0] for c in constituents)
                justs: dict[str, MemberJustification] = {}
                for c in constituents:
                    if c[1] and c[1] != "{}":
                        try:
                            justs[c[0]] = MemberJustification.from_dict(json.loads(c[1]))
                        except Exception:
                            pass
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
                        member_justifications=justs,
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
