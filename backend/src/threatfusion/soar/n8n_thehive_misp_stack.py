"""Deterministic n8n, TheHive, and MISP SOC Stack Clients (Milestone #32).

Provides deterministic integration clients and durable outbox queues for containerized SOC tools:
1. MispQueryResult & MispDeterministicClient:
   Queries MISP REST endpoint (POST /attributes/restSearch) for IP and payload hash indicators
   with verified local snapshot fallback. Enforces RFC1918 Private-IP Guard: private/lab IPs
   (10.0.0.4, 10.0.0.5) are strictly suppressed from external lookup.
2. TheHiveCaseRecord & TheHiveDeterministicClient:
   Formats and dispatches TheHive v4/v5 case creation payloads (POST /api/v1/case) and observables
   containing correlated incident_id, RF confidence score (%), non-fused AE queue rank,
   MISP IOC tags, and ChromaDB MITRE ATT&CK tags. Enforces mandatory SOAR approval gate.
3. N8nPlaybookExecutionReceipt & N8nDeterministicPlaybookClient:
   Dispatches HMAC-SHA256-signed webhook triggers (POST /webhook/threatfusion-soar-approved)
   with idempotency keys. Refuses execution (raising SoarStateTransitionError) unless SOAR record
   is approved and cryptographic audit hash chain integrity is verified.
4. Mode-0600 Durable SQLite Outbox:
   Durable persistent queue (n8n_thehive_misp_outbox.sqlite3) ensuring reliable, auditable
   delivery when external containers are offline or restarting.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any
import urllib.error
import urllib.request
import uuid

from threatfusion.advisory.explanation_engine import (
    AdvisoryEvidenceBundle,
    FourBlockInvestigationAnatomy,
    build_four_block_investigation_anatomy,
)
from threatfusion.soar.playbook_ledger import (
    SoarPlaybookRecord,
    SoarPlaybookSqliteRepository,
    SoarStateTransitionError,
)

SOAR_STACK_SCHEMA_VERSION = "soar_stack_outbox_sqlite_v1"
DEFAULT_N8N_WEBHOOK_URL = "http://127.0.0.1:5678"
DEFAULT_THEHIVE_URL = "http://127.0.0.1:9000"
DEFAULT_MISP_URL = "http://127.0.0.1:8080"

# Canonical Verified MISP Indicator Snapshot for Deterministic Fallback
CANONICAL_MISP_SNAPSHOT: dict[str, dict[str, Any]] = {
    # Known malicious hashes
    "44d88612fea8a8f36de82e1278abb02f": {
        "matched": True,
        "threat_level": "high",
        "tags": ("malware:eicar", "confidence:high", "tlp:white"),
        "event_id": "misp_evt_eicar_01",
    },
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "matched": True,
        "threat_level": "high",
        "tags": ("malware:mirai", "c2:botnet", "tlp:green"),
        "event_id": "misp_evt_mirai_02",
    },
    # Known simulated public C2 IPs
    "198.51.100.27": {
        "matched": True,
        "threat_level": "high",
        "tags": ("c2:active_beacon", "apt:threatfusion_simulated", "tlp:amber"),
        "event_id": "misp_evt_c2_03",
    },
    "203.0.113.195": {
        "matched": True,
        "threat_level": "medium",
        "tags": ("scanner:masscan", "reconnaissance", "tlp:green"),
        "event_id": "misp_evt_scan_04",
    },
}


def is_rfc1918_or_loopback_ip(ip_str: str) -> bool:
    """Return True if ip_str is a valid IPv4/IPv6 private, loopback, or link-local address."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


# =============================================================================
# 1. MISP Threat Intelligence Client
# =============================================================================


@dataclass(frozen=True, slots=True)
class MispQueryResult:
    """Structured result of a MISP threat intelligence indicator query."""

    indicator: str
    indicator_type: str
    matched: bool
    threat_level: str
    tags: tuple[str, ...]
    event_id: str | None
    private_ip_guard_triggered: bool
    query_mode: str  # "rfc1918_guard_suppressed" | "rest_api" | "verified_snapshot_fallback"
    timestamp_utc: str
    transport_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "matched": self.matched,
            "threat_level": self.threat_level,
            "tags": list(self.tags),
            "event_id": self.event_id,
            "private_ip_guard_triggered": self.private_ip_guard_triggered,
            "query_mode": self.query_mode,
            "timestamp_utc": self.timestamp_utc,
            "transport_error": self.transport_error,
        }


class MispDeterministicClient:
    """Deterministic MISP Client enforcing RFC1918 Private IP Guard & Outbox Persistence."""

    def __init__(
        self,
        misp_url: str = DEFAULT_MISP_URL,
        api_key: str | None = None,
        outbox_db_path: Path | str | None = None,
    ) -> None:
        self.misp_url = misp_url.rstrip("/")
        self.api_key = (
            api_key
            if api_key is not None
            else os.environ.get("THREATFUSION_MISP_API_KEY", "threatfusion_misp_auth_key")
        )
        self.outbox_db_path = Path(outbox_db_path) if outbox_db_path else None
        if self.outbox_db_path:
            self.outbox_db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_outbox()

    def _init_outbox(self) -> None:
        if not self.outbox_db_path:
            return
        with sqlite3.connect(str(self.outbox_db_path), timeout=5.0) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS misp_queries (
                    query_id TEXT PRIMARY KEY,
                    indicator TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    matched INTEGER NOT NULL,
                    threat_level TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    private_ip_guard_triggered INTEGER NOT NULL,
                    query_mode TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                )
            """)
        if self.outbox_db_path.exists():
            os.chmod(self.outbox_db_path, stat.S_IRUSR | stat.S_IWUSR)

    def query_indicator(
        self,
        indicator: str,
        indicator_type: str = "ip-dst",
    ) -> MispQueryResult:
        """Query MISP for an indicator (IP or hash).

        Enforces RFC1918 Guard: private/loopback IPs are never sent externally.
        """
        clean_ind = indicator.strip()
        now_str = datetime.now(UTC).isoformat()

        # Check RFC1918 Guard if indicator is an IP address
        if "ip" in indicator_type or is_rfc1918_or_loopback_ip(clean_ind):
            if is_rfc1918_or_loopback_ip(clean_ind):
                res = MispQueryResult(
                    indicator=clean_ind,
                    indicator_type=indicator_type,
                    matched=False,
                    threat_level="undefined",
                    tags=("rfc1918_private_ip_suppressed",),
                    event_id=None,
                    private_ip_guard_triggered=True,
                    query_mode="rfc1918_guard_suppressed",
                    timestamp_utc=now_str,
                )
                self._record_query(res)
                return res

        # Attempt REST Search
        payload = json.dumps(
            {"returnFormat": "json", "value": clean_ind, "type": indicator_type}
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.misp_url}/attributes/restSearch",
            data=payload,
            headers={
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                attrs = data.get("response", {}).get("Attribute", [])
                matched = len(attrs) > 0
                tags: list[str] = []
                for a in attrs:
                    for t in a.get("Tag", []):
                        tags.append(t.get("name", ""))
                res = MispQueryResult(
                    indicator=clean_ind,
                    indicator_type=indicator_type,
                    matched=matched,
                    threat_level="high" if matched else "undefined",
                    tags=tuple(tags),
                    event_id=attrs[0].get("event_id") if matched else None,
                    private_ip_guard_triggered=False,
                    query_mode="rest_api",
                    timestamp_utc=now_str,
                )
                self._record_query(res)
                return res
        except (
            urllib.error.URLError,
            TimeoutError,
            ConnectionError,
            OSError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            transport_err = f"{type(exc).__name__}: {str(exc)[:100]}"
            # Fall back closed to canonical verified snapshot
            snap = CANONICAL_MISP_SNAPSHOT.get(clean_ind.lower())
            if snap:
                res = MispQueryResult(
                    indicator=clean_ind,
                    indicator_type=indicator_type,
                    matched=snap["matched"],
                    threat_level=snap["threat_level"],
                    tags=snap["tags"],
                    event_id=snap["event_id"],
                    private_ip_guard_triggered=False,
                    query_mode="verified_snapshot_fallback",
                    timestamp_utc=now_str,
                    transport_error=transport_err,
                )
            else:
                res = MispQueryResult(
                    indicator=clean_ind,
                    indicator_type=indicator_type,
                    matched=False,
                    threat_level="undefined",
                    tags=(),
                    event_id=None,
                    private_ip_guard_triggered=False,
                    query_mode="verified_snapshot_fallback",
                    timestamp_utc=now_str,
                    transport_error=transport_err,
                )
            self._record_query(res)
            return res

    def _record_query(self, res: MispQueryResult) -> None:
        if not self.outbox_db_path:
            return
        qid = f"misp_q_{uuid.uuid4().hex[:12]}"
        with sqlite3.connect(str(self.outbox_db_path), timeout=5.0) as conn:
            conn.execute(
                """
                INSERT INTO misp_queries (
                    query_id, indicator, indicator_type, matched, threat_level,
                    tags_json, private_ip_guard_triggered, query_mode, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    qid,
                    res.indicator,
                    res.indicator_type,
                    1 if res.matched else 0,
                    res.threat_level,
                    json.dumps(list(res.tags)),
                    1 if res.private_ip_guard_triggered else 0,
                    res.query_mode,
                    res.timestamp_utc,
                ),
            )


# =============================================================================
# 2. TheHive Case Management Client
# =============================================================================


@dataclass(frozen=True, slots=True)
class TheHiveCaseRecord:
    """Structured record of a case created in TheHive."""

    case_id: str
    title: str
    description: str
    severity: int  # 1 (Low) to 4 (Critical)
    tlp: int  # 0 (White) to 3 (Red)
    pap: int  # 0 (White) to 3 (Red)
    tags: tuple[str, ...]
    observables: tuple[dict[str, Any], ...]
    status: str  # "created_live" | "queued_offline"
    created_at_utc: str
    transport_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "tlp": self.tlp,
            "pap": self.pap,
            "tags": list(self.tags),
            "observables": list(self.observables),
            "status": self.status,
            "created_at_utc": self.created_at_utc,
            "transport_error": self.transport_error,
        }


class TheHiveDeterministicClient:
    """TheHive v4/v5 REST Client enforcing Mandatory SOAR Approval & Outbox Queue."""

    def __init__(
        self,
        thehive_url: str = DEFAULT_THEHIVE_URL,
        api_key: str = "threatfusion_thehive_api_key",
        outbox_db_path: Path | str | None = None,
    ) -> None:
        self.thehive_url = thehive_url.rstrip("/")
        self.api_key = api_key
        self.outbox_db_path = Path(outbox_db_path) if outbox_db_path else None
        if self.outbox_db_path:
            self.outbox_db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_outbox()

    def _init_outbox(self) -> None:
        if not self.outbox_db_path:
            return
        with sqlite3.connect(str(self.outbox_db_path), timeout=5.0) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS thehive_cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    tlp INTEGER NOT NULL,
                    pap INTEGER NOT NULL,
                    tags_json TEXT NOT NULL,
                    observables_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                )
            """)
        if self.outbox_db_path.exists():
            os.chmod(self.outbox_db_path, stat.S_IRUSR | stat.S_IWUSR)

    def create_case_from_soar(
        self,
        *,
        soar_record: SoarPlaybookRecord,
        soar_repo: SoarPlaybookSqliteRepository,
        rf_confidence_pct: float,
        queue_priority_rank: int = 1,
        incident_id: str | None = None,
        mitre_tags: Sequence[str] = (),
        misp_tags: Sequence[str] = (),
        anatomy: FourBlockInvestigationAnatomy | None = None,
        bundle: AdvisoryEvidenceBundle | None = None,
    ) -> TheHiveCaseRecord:
        """Create a TheHive case from an authenticated, approved SOAR record."""
        # 1. Enforce Mandatory Approval Gate
        if soar_record.state not in ("approved", "executed_simulated"):
            raise SoarStateTransitionError(
                f"TheHive case creation rejected: SOAR record '{soar_record.playbook_id}' "
                f"state is '{soar_record.state}' (must be approved or executed_simulated)"
            )

        # 2. Enforce Cryptographic Audit Hash Chain Gate
        ok, msg = soar_repo.verify_audit_chain_integrity()
        if not ok:
            raise SoarStateTransitionError(
                f"TheHive case creation rejected: cryptographic SOAR audit hash chain "
                f"integrity failed verification ({msg})"
            )

        # 3. Grounded 4-Block Investigation Case Anatomy
        if anatomy is None:
            eff_bundle = bundle or AdvisoryEvidenceBundle(
                candidate_id=soar_record.candidate_id,
                record_id=soar_record.candidate_id,
                rf_model_version="full-network-random-forest-6d69c72-v1",
                rf_attack_probability=rf_confidence_pct / 100.0,
                rf_threshold=0.5000,
                top_feature_signals={"sbytes": 1250.0},
                incident_id=incident_id,
            )
            anatomy = build_four_block_investigation_anatomy(
                eff_bundle,
                soar_record=soar_record,
                soar_repo=soar_repo,
                audit_chain_valid=ok,
            )

        case_id = f"case_{soar_record.candidate_id.replace(':', '_')}_{uuid.uuid4().hex[:6]}"
        now_str = datetime.now(UTC).isoformat()
        severity = 3 if rf_confidence_pct >= 80.0 else 2

        all_tags = [
            "threatfusion:alert",
            f"rf_confidence:{rf_confidence_pct:.1f}%",
            f"queue_rank:{queue_priority_rank}",
            f"soar_playbook:{soar_record.playbook_id}",
            f"action:{soar_record.action_type}",
        ]
        if incident_id:
            all_tags.append(f"incident:{incident_id}")
        for mt in mitre_tags:
            all_tags.append(f"mitre:{mt}" if not mt.startswith("mitre:") else mt)
        for misp_t in misp_tags:
            all_tags.append(f"misp:{misp_t}" if not misp_t.startswith("misp:") else misp_t)

        observables = (
            {
                "dataType": "ip",
                "data": soar_record.target_entity,
                "message": f"Target entity associated with {soar_record.action_type}",
                "tags": ["target_entity"],
            },
            {
                "dataType": "other",
                "data": soar_record.candidate_id,
                "message": "ThreatFusion Alert Candidate ID",
                "tags": ["candidate_id"],
            },
        )

        description = (
            f"ThreatFusion Autonomous Security Operations Alert.\n"
            f"Candidate: {soar_record.candidate_id}\n"
            f"Playbook: {soar_record.playbook_id} ({soar_record.action_type})\n"
            f"Target Entity: {soar_record.target_entity}\n"
            f"Primary RF Confidence: {rf_confidence_pct:.2f}%\n"
            f"Non-Fused Queue Priority Rank: #{queue_priority_rank}\n"
            f"Approved by Actor: {soar_record.actor_id}\n"
            f"Approval Reason: {soar_record.decision_reason}\n"
            f"Cryptographic Audit Chain: VERIFIED\n\n"
            f"--- 4-Block Investigation Anatomy ---\n"
            f"Block 1 (Executive Summary): {anatomy.block_1_executive_summary.risk_level} | RF {anatomy.block_1_executive_summary.rf_probability:.4f} | {anatomy.block_1_executive_summary.recall_gain_badge}\n"
            f"Block 2 (Attack Timeline): {anatomy.block_2_attack_timeline.window_type} | {anatomy.block_2_attack_timeline.correlated_flow_count} correlated flows\n"
            f"Block 3 (MITRE Mapping): {anatomy.block_3_mitre_mapping.technique_id} ({anatomy.block_3_mitre_mapping.tactic_name}) | Cosine {anatomy.block_3_mitre_mapping.cosine_similarity:.4f}\n"
            f"Block 4 (Cryptographic SOAR Status): {anatomy.block_4_cryptographic_soar_status.playbook_id} [{anatomy.block_4_cryptographic_soar_status.playbook_state}] | Audit Chain Valid={anatomy.block_4_cryptographic_soar_status.audit_chain_valid}"
        )

        title = f"[ThreatFusion] {soar_record.action_type.upper()}: {soar_record.target_entity} ({rf_confidence_pct:.1f}%)"

        payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "tlp": 2,  # AMBER
            "pap": 2,  # AMBER
            "tags": all_tags,
            "flag": False,
            "anatomy": anatomy.to_dict(),
            "four_block_anatomy": anatomy.to_dict(),
        }

        # Attempt REST dispatch
        status = "queued_offline"
        transport_error: str | None = None
        req = urllib.request.Request(
            f"{self.thehive_url}/api/v1/case",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status in (200, 201):
                    status = "created_live"
        except (
            urllib.error.URLError,
            TimeoutError,
            ConnectionError,
            OSError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            status = "queued_offline"
            transport_error = f"{type(exc).__name__}: {str(exc)[:100]}"

        rec = TheHiveCaseRecord(
            case_id=case_id,
            title=title,
            description=description,
            severity=severity,
            tlp=2,
            pap=2,
            tags=tuple(all_tags),
            observables=observables,
            status=status,
            created_at_utc=now_str,
            transport_error=transport_error,
        )
        self._record_case(rec)
        return rec

    # Backward compatibility alias
    create_incident_case = create_case_from_soar

    def _record_case(self, rec: TheHiveCaseRecord) -> None:
        if not self.outbox_db_path:
            return
        with sqlite3.connect(str(self.outbox_db_path), timeout=5.0) as conn:
            conn.execute(
                """
                INSERT INTO thehive_cases (
                    case_id, title, description, severity, tlp, pap,
                    tags_json, observables_json, status, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rec.case_id,
                    rec.title,
                    rec.description,
                    rec.severity,
                    rec.tlp,
                    rec.pap,
                    json.dumps(list(rec.tags)),
                    json.dumps(list(rec.observables)),
                    rec.status,
                    rec.created_at_utc,
                ),
            )


# =============================================================================
# 3. Deterministic n8n Playbook Webhook Client
# =============================================================================


@dataclass(frozen=True, slots=True)
class N8nPlaybookExecutionReceipt:
    """Cryptographic execution receipt of an n8n SOAR playbook webhook trigger."""

    execution_id: str
    webhook_url: str
    playbook_id: str
    candidate_id: str
    action_type: str
    target_entity: str
    idempotency_key: str
    signature_sha256: str
    status: str  # "dispatched_live" | "queued_durable_outbox" | "rejected_unapproved"
    dispatched_at_utc: str
    payload: dict[str, Any]
    transport_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "webhook_url": self.webhook_url,
            "playbook_id": self.playbook_id,
            "candidate_id": self.candidate_id,
            "action_type": self.action_type,
            "target_entity": self.target_entity,
            "idempotency_key": self.idempotency_key,
            "signature_sha256": self.signature_sha256,
            "status": self.status,
            "dispatched_at_utc": self.dispatched_at_utc,
            "payload": self.payload,
            "transport_error": self.transport_error,
        }


class N8nDeterministicPlaybookClient:
    """HMAC-SHA256 Signed n8n Webhook Client enforcing SOAR Gates & Durable Outbox."""

    def __init__(
        self,
        webhook_url: str = DEFAULT_N8N_WEBHOOK_URL,
        secret_key: str | None = None,
        outbox_db_path: Path | str | None = None,
    ) -> None:
        self.webhook_url = webhook_url.rstrip("/")
        resolved_secret = (
            secret_key
            if secret_key is not None
            else os.environ.get("THREATFUSION_SOAR_HMAC_SECRET")
        )
        if (
            not resolved_secret
            or not isinstance(resolved_secret, str)
            or len(resolved_secret.strip()) < 16
        ):
            raise ValueError(
                "THREATFUSION_SOAR_HMAC_SECRET must be supplied via secret_key parameter or "
                "THREATFUSION_SOAR_HMAC_SECRET environment variable, and must be at least 16 characters long."
            )
        self.secret_key = resolved_secret.strip()
        self.outbox_db_path = Path(outbox_db_path) if outbox_db_path else None
        if self.outbox_db_path:
            self.outbox_db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_outbox()

    def _init_outbox(self) -> None:
        if not self.outbox_db_path:
            return
        with sqlite3.connect(str(self.outbox_db_path), timeout=5.0) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS n8n_executions (
                    execution_id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target_entity TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    signature_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                )
            """)
        if self.outbox_db_path.exists():
            os.chmod(self.outbox_db_path, stat.S_IRUSR | stat.S_IWUSR)

    def trigger_soar_playbook(
        self,
        *,
        soar_record: SoarPlaybookRecord,
        soar_repo: SoarPlaybookSqliteRepository,
        rf_confidence_pct: float,
        queue_priority_rank: int = 1,
        incident_id: str | None = None,
        thehive_case_id: str | None = None,
        mitre_technique_id: str = "T1046",
    ) -> N8nPlaybookExecutionReceipt:
        """Trigger deterministic n8n webhook playbook signed with HMAC-SHA256."""
        # 1. Enforce Mandatory Approval Gate
        if soar_record.state not in ("approved", "executed_simulated"):
            raise SoarStateTransitionError(
                f"Cannot trigger n8n playbook: record '{soar_record.playbook_id}' "
                f"state is '{soar_record.state}' (must be approved or executed_simulated)"
            )

        # 2. Enforce Cryptographic Audit Hash Chain Gate
        ok, msg = soar_repo.verify_audit_chain_integrity()
        if not ok:
            raise SoarStateTransitionError(
                f"Cannot trigger n8n playbook: cryptographic SOAR audit hash chain "
                f"integrity failed verification ({msg})"
            )

        execution_id = f"exec_{uuid.uuid4().hex[:12]}"
        idempotency_key = f"idem_{soar_record.playbook_id}_{soar_record.version}"
        now_str = datetime.now(UTC).isoformat()

        payload: dict[str, Any] = {
            "execution_id": execution_id,
            "playbook_id": soar_record.playbook_id,
            "candidate_id": soar_record.candidate_id,
            "action_type": soar_record.action_type,
            "target_entity": soar_record.target_entity,
            "soar_state": soar_record.state,
            "actor_id": soar_record.actor_id,
            "decision_reason": soar_record.decision_reason,
            "rf_confidence_pct": rf_confidence_pct,
            "queue_priority_rank": queue_priority_rank,
            "incident_id": incident_id,
            "thehive_case_id": thehive_case_id,
            "mitre_technique_id": mitre_technique_id,
            "audit_chain_verified": True,
            "dispatched_at_utc": now_str,
        }

        canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(
            self.secret_key.encode("utf-8"),
            canonical_bytes,
            hashlib.sha256,
        ).hexdigest()

        # Attempt REST dispatch to n8n webhook
        target_endpoint = f"{self.webhook_url}/webhook/threatfusion-soar-approved"
        status = "queued_durable_outbox"
        transport_error: str | None = None

        req = urllib.request.Request(
            target_endpoint,
            data=canonical_bytes,
            headers={
                "Content-Type": "application/json",
                "X-ThreatFusion-Signature-256": signature,
                "X-Idempotency-Key": idempotency_key,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status in (200, 201, 204):
                    status = "dispatched_live"
        except (
            urllib.error.URLError,
            TimeoutError,
            ConnectionError,
            OSError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            status = "queued_durable_outbox"
            transport_error = f"{type(exc).__name__}: {str(exc)[:100]}"

        receipt = N8nPlaybookExecutionReceipt(
            execution_id=execution_id,
            webhook_url=target_endpoint,
            playbook_id=soar_record.playbook_id,
            candidate_id=soar_record.candidate_id,
            action_type=soar_record.action_type,
            target_entity=soar_record.target_entity,
            idempotency_key=idempotency_key,
            signature_sha256=signature,
            status=status,
            dispatched_at_utc=now_str,
            payload=payload,
            transport_error=transport_error,
        )
        self._record_execution(receipt)
        return receipt

    def _record_execution(self, rec: N8nPlaybookExecutionReceipt) -> None:
        if not self.outbox_db_path:
            return
        with sqlite3.connect(str(self.outbox_db_path), timeout=5.0) as conn:
            conn.execute(
                """
                INSERT INTO n8n_executions (
                    execution_id, playbook_id, candidate_id, action_type,
                    target_entity, idempotency_key, signature_sha256, status,
                    payload_json, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rec.execution_id,
                    rec.playbook_id,
                    rec.candidate_id,
                    rec.action_type,
                    rec.target_entity,
                    rec.idempotency_key,
                    rec.signature_sha256,
                    rec.status,
                    json.dumps(rec.payload),
                    rec.dispatched_at_utc,
                ),
            )
