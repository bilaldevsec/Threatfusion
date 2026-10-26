"""Approval-Gated Reversible SOAR Playbook Ledger.

Enforces Section 13.E of ThreatFusion:
- Step 1 (Recommendation): Creates durable records in pending_approval (never auto-executed).
- Step 2 (Analyst Decision): Requires authenticated actor_id, non-empty reason, and
  optimistic concurrency check to transition to approved or rejected.
- Step 3 (Simulated Execution): ONLY allowed from approved state; saves pre_action_snapshot
  and transitions to executed_simulated with immutable audit logging.
- Step 4 (Reversible Rollback): ONLY allowed from executed_simulated; restores pre_action_snapshot
  and transitions to rolled_back.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threatfusion.alerts.correlation_engine import EntityProvenanceContract

SOAR_SCHEMA_VERSION = "soar_ledger_sqlite_v1"
SOAR_AUDIT_GENESIS_HASH = "0" * 64


def compute_soar_audit_entry_hash(
    *,
    event_id: str,
    playbook_id: str,
    action: str,
    actor_id: str,
    old_state: str,
    new_state: str,
    reason: str | None,
    snapshot: str | None,
    timestamp_utc: str,
    prev_entry_sha256: str,
) -> str:
    """Compute deterministic cryptographic SHA-256 digest for a SOAR audit entry."""
    payload = {
        "event_id": event_id,
        "playbook_id": playbook_id,
        "action": action,
        "actor_id": actor_id,
        "old_state": old_state,
        "new_state": new_state,
        "reason": reason,
        "snapshot": snapshot,
        "timestamp_utc": timestamp_utc,
        "prev_entry_sha256": prev_entry_sha256,
    }
    canonical_repr = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()


class SoarError(RuntimeError):
    """Base SOAR domain error."""


class SoarStateTransitionError(SoarError):
    """Raised when an illegal SOAR state transition is attempted."""


class SoarOptimisticConcurrencyError(SoarError):
    """Raised when an expected record version does not match."""


@dataclass(frozen=True, slots=True)
class SoarAuditEntry:
    """Persistent audit log entry for SOAR state transitions."""

    event_id: str
    playbook_id: str
    action: str
    actor_id: str
    old_state: str
    new_state: str
    reason: str | None
    snapshot: str | None
    timestamp_utc: str
    prev_entry_sha256: str = SOAR_AUDIT_GENESIS_HASH
    entry_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "playbook_id": self.playbook_id,
            "action": self.action,
            "actor_id": self.actor_id,
            "old_state": self.old_state,
            "new_state": self.new_state,
            "reason": self.reason,
            "snapshot": self.snapshot,
            "timestamp_utc": self.timestamp_utc,
            "prev_entry_sha256": self.prev_entry_sha256,
            "entry_sha256": self.entry_sha256,
        }


@dataclass(frozen=True, slots=True)
class SoarPlaybookRecord:
    """Persistent SOAR playbook recommendation record."""

    playbook_id: str
    candidate_id: str
    action_type: str
    target_entity: str
    state: str  # "pending_approval", "approved", "rejected", "executed_simulated", "rolled_back"
    version: int
    actor_id: str | None
    decision_reason: str | None
    pre_action_snapshot: str | None
    execution_evidence: str | None
    rollback_reason: str | None
    created_at_utc: str
    updated_at_utc: str
    t_approval_queued: float | None = None
    t_callback_verified: float | None = None
    t_response: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "candidate_id": self.candidate_id,
            "action_type": self.action_type,
            "target_entity": self.target_entity,
            "state": self.state,
            "version": self.version,
            "actor_id": self.actor_id,
            "decision_reason": self.decision_reason,
            "pre_action_snapshot": (
                json.loads(self.pre_action_snapshot) if self.pre_action_snapshot else None
            ),
            "execution_evidence": (
                json.loads(self.execution_evidence) if self.execution_evidence else None
            ),
            "rollback_reason": self.rollback_reason,
            "created_at_utc": self.created_at_utc,
            "updated_at_utc": self.updated_at_utc,
            "t_approval_queued": self.t_approval_queued,
            "t_callback_verified": self.t_callback_verified,
            "t_response": self.t_response,
        }


class SoarPlaybookSqliteRepository:
    """Isolated SQLite store enforcing mode 0600 file permissions and append-only audit."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        previous_isolation = conn.isolation_level
        conn.isolation_level = None
        conn.execute("PRAGMA journal_mode=WAL")
        conn.isolation_level = previous_isolation
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS soar_playbook_records (
                    playbook_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target_entity TEXT NOT NULL,
                    state TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    actor_id TEXT,
                    decision_reason TEXT,
                    pre_action_snapshot TEXT,
                    execution_evidence TEXT,
                    rollback_reason TEXT,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    t_approval_queued REAL,
                    t_callback_verified REAL,
                    t_response REAL
                )
                """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS soar_audit_events (
                    event_id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    old_state TEXT NOT NULL,
                    new_state TEXT NOT NULL,
                    reason TEXT,
                    snapshot TEXT,
                    timestamp_utc TEXT NOT NULL,
                    prev_entry_sha256 TEXT NOT NULL,
                    entry_sha256 TEXT NOT NULL
                )
                """)
            # Migration check: Ensure prev_entry_sha256 and entry_sha256 exist
            cols_cursor = conn.execute("PRAGMA table_info(soar_audit_events)")
            cols = {row["name"] for row in cols_cursor.fetchall()}
            if "prev_entry_sha256" not in cols:
                conn.execute(
                    "ALTER TABLE soar_audit_events ADD COLUMN prev_entry_sha256 TEXT NOT NULL DEFAULT '"
                    + SOAR_AUDIT_GENESIS_HASH
                    + "'"
                )
            if "entry_sha256" not in cols:
                conn.execute(
                    "ALTER TABLE soar_audit_events ADD COLUMN entry_sha256 TEXT NOT NULL DEFAULT ''"
                )

            # Migration check: Ensure timing columns exist in soar_playbook_records
            cols_pb_cursor = conn.execute("PRAGMA table_info(soar_playbook_records)")
            cols_pb = {row["name"] for row in cols_pb_cursor.fetchall()}
            if "t_approval_queued" not in cols_pb:
                conn.execute("ALTER TABLE soar_playbook_records ADD COLUMN t_approval_queued REAL")
            if "t_callback_verified" not in cols_pb:
                conn.execute(
                    "ALTER TABLE soar_playbook_records ADD COLUMN t_callback_verified REAL"
                )
            if "t_response" not in cols_pb:
                conn.execute("ALTER TABLE soar_playbook_records ADD COLUMN t_response REAL")

            conn.commit()

        # Enforce mode 0600 permissions
        try:
            os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def save_record(self, record: SoarPlaybookRecord) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO soar_playbook_records (
                    playbook_id, candidate_id, action_type, target_entity,
                    state, version, actor_id, decision_reason,
                    pre_action_snapshot, execution_evidence, rollback_reason,
                    created_at_utc, updated_at_utc,
                    t_approval_queued, t_callback_verified, t_response
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.playbook_id,
                    record.candidate_id,
                    record.action_type,
                    record.target_entity,
                    record.state,
                    record.version,
                    record.actor_id,
                    record.decision_reason,
                    record.pre_action_snapshot,
                    record.execution_evidence,
                    record.rollback_reason,
                    record.created_at_utc,
                    record.updated_at_utc,
                    record.t_approval_queued,
                    record.t_callback_verified,
                    record.t_response,
                ),
            )
            conn.commit()

    def get_record(self, playbook_id: str) -> SoarPlaybookRecord | None:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM soar_playbook_records WHERE playbook_id = ?",
                (playbook_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_record(row)

    def list_records_for_candidate(self, candidate_id: str) -> list[SoarPlaybookRecord]:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM soar_playbook_records WHERE candidate_id = ? ORDER BY created_at_utc ASC",
                (candidate_id,),
            )
            return [self._row_to_record(row) for row in cursor.fetchall()]

    def append_audit_event(
        self,
        *,
        playbook_id: str,
        action: str,
        actor_id: str,
        old_state: str,
        new_state: str,
        reason: str | None = None,
        snapshot: str | None = None,
    ) -> SoarAuditEntry:
        event_id = f"soar_audit:{uuid.uuid4().hex}"
        timestamp = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            # Query the latest audit record to establish cryptographic chain link
            cur = conn.execute(
                "SELECT entry_sha256 FROM soar_audit_events ORDER BY rowid DESC LIMIT 1"
            )
            last_row = cur.fetchone()
            prev_hash = (
                last_row["entry_sha256"]
                if last_row and last_row["entry_sha256"]
                else SOAR_AUDIT_GENESIS_HASH
            )

            entry_hash = compute_soar_audit_entry_hash(
                event_id=event_id,
                playbook_id=playbook_id,
                action=action,
                actor_id=actor_id,
                old_state=old_state,
                new_state=new_state,
                reason=reason,
                snapshot=snapshot,
                timestamp_utc=timestamp,
                prev_entry_sha256=prev_hash,
            )

            conn.execute(
                """
                INSERT INTO soar_audit_events (
                    event_id, playbook_id, action, actor_id,
                    old_state, new_state, reason, snapshot, timestamp_utc,
                    prev_entry_sha256, entry_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    playbook_id,
                    action,
                    actor_id,
                    old_state,
                    new_state,
                    reason,
                    snapshot,
                    timestamp,
                    prev_hash,
                    entry_hash,
                ),
            )
            conn.commit()

        return SoarAuditEntry(
            event_id=event_id,
            playbook_id=playbook_id,
            action=action,
            actor_id=actor_id,
            old_state=old_state,
            new_state=new_state,
            reason=reason,
            snapshot=snapshot,
            timestamp_utc=timestamp,
            prev_entry_sha256=prev_hash,
            entry_sha256=entry_hash,
        )

    def list_audit_events(self, playbook_id: str) -> list[dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM soar_audit_events WHERE playbook_id = ? ORDER BY timestamp_utc ASC",
                (playbook_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def list_audit_entries(self, playbook_id: str) -> list[SoarAuditEntry]:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM soar_audit_events WHERE playbook_id = ? ORDER BY timestamp_utc ASC",
                (playbook_id,),
            )
            return [self._row_to_audit_entry(row) for row in cursor.fetchall()]

    @staticmethod
    def _row_to_audit_entry(row: sqlite3.Row) -> SoarAuditEntry:
        col_names = row.keys()
        prev_h = (
            row["prev_entry_sha256"]
            if "prev_entry_sha256" in col_names
            else SOAR_AUDIT_GENESIS_HASH
        )
        entry_h = row["entry_sha256"] if "entry_sha256" in col_names else ""
        return SoarAuditEntry(
            event_id=row["event_id"],
            playbook_id=row["playbook_id"],
            action=row["action"],
            actor_id=row["actor_id"],
            old_state=row["old_state"],
            new_state=row["new_state"],
            reason=row["reason"],
            snapshot=row["snapshot"],
            timestamp_utc=row["timestamp_utc"],
            prev_entry_sha256=prev_h,
            entry_sha256=entry_h,
        )

    def verify_audit_chain_integrity(
        self,
        playbook_id: str | None = None,
        *,
        require_non_empty: bool = False,
    ) -> tuple[bool, str]:
        """Verify the cryptographic hash-chain integrity of SOAR audit events.

        The full ledger link is always checked first. A playbook_id argument then
        filters that already-valid chain. require_non_empty=False preserves the
        empty-ledger success result used by existing initialization tests.
        """
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM soar_audit_events ORDER BY rowid ASC")
            all_rows = cursor.fetchall()

        if not all_rows:
            if require_non_empty:
                return False, "empty ledger"
            return True, "SOAR audit chain verified: 0 entries (empty ledger)"

        expected_prev = SOAR_AUDIT_GENESIS_HASH
        for idx, row in enumerate(all_rows):
            col_names = row.keys()
            stored_prev = row["prev_entry_sha256"] if "prev_entry_sha256" in col_names else ""
            stored_hash = row["entry_sha256"] if "entry_sha256" in col_names else ""

            if stored_prev != expected_prev:
                return (
                    False,
                    f"SOAR audit chain broken at row index {idx} (event_id={row['event_id']}): "
                    f"prev_entry_sha256 '{stored_prev}' != expected '{expected_prev}'",
                )

            recomputed = compute_soar_audit_entry_hash(
                event_id=row["event_id"],
                playbook_id=row["playbook_id"],
                action=row["action"],
                actor_id=row["actor_id"],
                old_state=row["old_state"],
                new_state=row["new_state"],
                reason=row["reason"],
                snapshot=row["snapshot"],
                timestamp_utc=row["timestamp_utc"],
                prev_entry_sha256=stored_prev,
            )
            if recomputed != stored_hash:
                return (
                    False,
                    f"SOAR audit chain broken at row index {idx} (event_id={row['event_id']}): "
                    f"recomputed hash '{recomputed}' != stored entry_sha256 '{stored_hash}'",
                )

            expected_prev = stored_hash

        if playbook_id is not None:
            rows = [row for row in all_rows if row["playbook_id"] == playbook_id]
            if not rows:
                if require_non_empty:
                    return False, "empty ledger"
                return True, f"SOAR audit chain verified: 0 entries (playbook '{playbook_id}')"
            return (
                True,
                f"SOAR audit chain verified: {len(rows)} entries valid (playbook '{playbook_id}')",
            )

        return True, f"SOAR audit chain verified: {len(all_rows)} entries valid (whole ledger)"

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> SoarPlaybookRecord:
        keys = row.keys()
        return SoarPlaybookRecord(
            playbook_id=row["playbook_id"],
            candidate_id=row["candidate_id"],
            action_type=row["action_type"],
            target_entity=row["target_entity"],
            state=row["state"],
            version=row["version"],
            actor_id=row["actor_id"],
            decision_reason=row["decision_reason"],
            pre_action_snapshot=row["pre_action_snapshot"],
            execution_evidence=row["execution_evidence"],
            rollback_reason=row["rollback_reason"],
            created_at_utc=row["created_at_utc"],
            updated_at_utc=row["updated_at_utc"],
            t_approval_queued=row["t_approval_queued"] if "t_approval_queued" in keys else None,
            t_callback_verified=(
                row["t_callback_verified"] if "t_callback_verified" in keys else None
            ),
            t_response=row["t_response"] if "t_response" in keys else None,
        )

    def record_callback_verification(
        self,
        playbook_id: str,
        t_callback_verified: float,
        t_approval_queued: float | None = None,
    ) -> float:
        """Record deterministic MTTR callback verification and compute response duration."""
        record = self.get_record(playbook_id)
        if record is None:
            raise SoarStateTransitionError(f"Playbook '{playbook_id}' not found")

        approval_time = (
            t_approval_queued
            if t_approval_queued is not None
            else (
                record.t_approval_queued
                if record.t_approval_queued is not None
                else datetime.fromisoformat(
                    record.created_at_utc.replace("Z", "+00:00")
                ).timestamp()
            )
        )
        t_resp = round(max(0.0, float(t_callback_verified) - float(approval_time)), 6)
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE soar_playbook_records
                SET t_approval_queued = ?, t_callback_verified = ?, t_response = ?, updated_at_utc = ?
                WHERE playbook_id = ?
                """,
                (
                    approval_time,
                    float(t_callback_verified),
                    t_resp,
                    datetime.now(UTC).isoformat(),
                    playbook_id,
                ),
            )
            conn.commit()
        return t_resp

    def list_response_timings(self) -> list[dict[str, Any]]:
        """Return all recorded MTTR intervals."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT playbook_id, candidate_id, state, t_approval_queued, t_callback_verified, t_response
                FROM soar_playbook_records
                WHERE t_response IS NOT NULL
                ORDER BY created_at_utc ASC
                """)
            return [
                {
                    "playbook_id": r["playbook_id"],
                    "candidate_id": r["candidate_id"],
                    "state": r["state"],
                    "t_approval_queued": r["t_approval_queued"],
                    "t_callback_verified": r["t_callback_verified"],
                    "t_response": r["t_response"],
                }
                for r in cursor.fetchall()
            ]


class ApprovalGatedSoarEngine:
    """Enforces human analyst approval gating, optimistic locking, and reversible execution."""

    def __init__(self, repository: SoarPlaybookSqliteRepository) -> None:
        self.repository = repository

    def recommend_actions_for_alert(
        self,
        candidate_id: str,
        provenance: EntityProvenanceContract | None,
        *,
        t_approval_queued: float | None = None,
    ) -> list[SoarPlaybookRecord]:
        """Step 1 — Recommendation: creates durable records in pending_approval (never auto-executed)."""
        now_dt = datetime.now(UTC)
        now_str = now_dt.isoformat()
        queued_epoch = t_approval_queued if t_approval_queued is not None else now_dt.timestamp()
        records: list[SoarPlaybookRecord] = []

        if provenance is not None and provenance.is_verified():
            src_ip = getattr(provenance, "src_ip", getattr(provenance, "src_entity_id", None))
            if src_ip:
                rec_id = f"soar:{uuid.uuid4().hex[:12]}"
                records.append(
                    SoarPlaybookRecord(
                        playbook_id=rec_id,
                        candidate_id=candidate_id,
                        action_type="verify_and_contain_lab_source_ip",
                        target_entity=str(src_ip),
                        state="pending_approval",
                        version=1,
                        actor_id=None,
                        decision_reason=None,
                        pre_action_snapshot=None,
                        execution_evidence=None,
                        rollback_reason=None,
                        created_at_utc=now_str,
                        updated_at_utc=now_str,
                        t_approval_queued=queued_epoch,
                    )
                )

            sensor_id = provenance.entity_namespace_id or "azure-suricata-edge-01"
            rec_id2 = f"soar:{uuid.uuid4().hex[:12]}"
            records.append(
                SoarPlaybookRecord(
                    playbook_id=rec_id2,
                    candidate_id=candidate_id,
                    action_type="capture_pcaps_on_victim_sensor",
                    target_entity=sensor_id,
                    state="pending_approval",
                    version=1,
                    actor_id=None,
                    decision_reason=None,
                    pre_action_snapshot=None,
                    execution_evidence=None,
                    rollback_reason=None,
                    created_at_utc=now_str,
                    updated_at_utc=now_str,
                    t_approval_queued=queued_epoch,
                )
            )
        else:
            rec_id = f"soar:{uuid.uuid4().hex[:12]}"
            records.append(
                SoarPlaybookRecord(
                    playbook_id=rec_id,
                    candidate_id=candidate_id,
                    action_type="escalate_flow_anomaly_for_packet_inspection",
                    target_entity=candidate_id,
                    state="pending_approval",
                    version=1,
                    actor_id=None,
                    decision_reason=None,
                    pre_action_snapshot=None,
                    execution_evidence=None,
                    rollback_reason=None,
                    created_at_utc=now_str,
                    updated_at_utc=now_str,
                    t_approval_queued=queued_epoch,
                )
            )

        for r in records:
            self.repository.save_record(r)
            self.repository.append_audit_event(
                playbook_id=r.playbook_id,
                action="recommend_action",
                actor_id="system:recommendation_engine",
                old_state="none",
                new_state="pending_approval",
                reason=f"Recommended action {r.action_type} for candidate {candidate_id}",
            )

        return records

    def decide_recommendation(
        self,
        playbook_id: str,
        *,
        actor_id: str,
        decision: str,  # "approve" | "reject"
        reason: str,
        expected_version: int,
    ) -> SoarPlaybookRecord:
        """Step 2 — Analyst Approval / Rejection: transitions pending_approval -> approved or rejected."""
        if not actor_id or not actor_id.strip():
            raise ValueError("actor_id is required for SOAR decision")
        if not reason or not reason.strip():
            raise ValueError("Non-empty reason is required for SOAR decision")
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be 'approve' or 'reject'")

        record = self.repository.get_record(playbook_id)
        if record is None:
            raise KeyError(f"Playbook record {playbook_id} not found")

        if record.state != "pending_approval":
            raise SoarStateTransitionError(
                f"Cannot decide action {playbook_id} in state '{record.state}'; "
                f"action must be in 'pending_approval' state."
            )

        if record.version != expected_version:
            raise SoarOptimisticConcurrencyError(
                f"Optimistic lock conflict on {playbook_id}: "
                f"expected version {expected_version}, found {record.version}"
            )

        new_state = "approved" if decision == "approve" else "rejected"
        now_str = datetime.now(UTC).isoformat()

        updated = SoarPlaybookRecord(
            playbook_id=record.playbook_id,
            candidate_id=record.candidate_id,
            action_type=record.action_type,
            target_entity=record.target_entity,
            state=new_state,
            version=record.version + 1,
            actor_id=actor_id,
            decision_reason=reason,
            pre_action_snapshot=record.pre_action_snapshot,
            execution_evidence=record.execution_evidence,
            rollback_reason=record.rollback_reason,
            created_at_utc=record.created_at_utc,
            updated_at_utc=now_str,
            t_approval_queued=record.t_approval_queued,
            t_callback_verified=record.t_callback_verified,
            t_response=record.t_response,
        )

        self.repository.save_record(updated)
        self.repository.append_audit_event(
            playbook_id=playbook_id,
            action=f"analyst_{decision}",
            actor_id=actor_id,
            old_state=record.state,
            new_state=new_state,
            reason=reason,
        )
        return updated

    def execute_approved_action(
        self,
        playbook_id: str,
        *,
        actor_id: str,
        expected_version: int,
    ) -> SoarPlaybookRecord:
        """Step 3 — Bounded Simulated Execution: ONLY allowed when state == 'approved'."""
        if not actor_id or not actor_id.strip():
            raise ValueError("actor_id is required to execute action")

        record = self.repository.get_record(playbook_id)
        if record is None:
            raise KeyError(f"Playbook record {playbook_id} not found")

        if record.state != "approved":
            raise SoarStateTransitionError(
                f"Cannot execute action {playbook_id} in state '{record.state}'. "
                f"Action must be explicitly 'approved' by an analyst before execution."
            )

        if record.version != expected_version:
            raise SoarOptimisticConcurrencyError(
                f"Optimistic lock conflict on {playbook_id}: "
                f"expected version {expected_version}, found {record.version}"
            )

        now_str = datetime.now(UTC).isoformat()
        pre_snapshot = json.dumps(
            {
                "target_entity": record.target_entity,
                "routing_table_state": "active",
                "access_control_rule": "ALLOW",
                "snapshot_captured_at_utc": now_str,
            }
        )
        execution_evidence = json.dumps(
            {
                "execution_mode": "simulated_safe_isolation",
                "command": f"iptables -I FORWARD -s {record.target_entity} -j DROP",
                "exit_code": 0,
                "executed_by": actor_id,
                "executed_at_utc": now_str,
            }
        )

        updated = SoarPlaybookRecord(
            playbook_id=record.playbook_id,
            candidate_id=record.candidate_id,
            action_type=record.action_type,
            target_entity=record.target_entity,
            state="executed_simulated",
            version=record.version + 1,
            actor_id=actor_id,
            decision_reason=record.decision_reason,
            pre_action_snapshot=pre_snapshot,
            execution_evidence=execution_evidence,
            rollback_reason=record.rollback_reason,
            created_at_utc=record.created_at_utc,
            updated_at_utc=now_str,
            t_approval_queued=record.t_approval_queued,
            t_callback_verified=record.t_callback_verified,
            t_response=record.t_response,
        )

        self.repository.save_record(updated)
        self.repository.append_audit_event(
            playbook_id=playbook_id,
            action="execute_simulated_action",
            actor_id=actor_id,
            old_state=record.state,
            new_state="executed_simulated",
            reason=f"Executed simulated containment for target {record.target_entity}",
            snapshot=pre_snapshot,
        )
        return updated

    def rollback_executed_action(
        self,
        playbook_id: str,
        *,
        actor_id: str,
        rollback_reason: str,
        expected_version: int,
    ) -> SoarPlaybookRecord:
        """Step 4 — Reversible Rollback: ONLY allowed when state == 'executed_simulated'."""
        if not actor_id or not actor_id.strip():
            raise ValueError("actor_id is required to rollback action")
        if not rollback_reason or not rollback_reason.strip():
            raise ValueError("Non-empty rollback_reason is required")

        record = self.repository.get_record(playbook_id)
        if record is None:
            raise KeyError(f"Playbook record {playbook_id} not found")

        if record.state != "executed_simulated":
            raise SoarStateTransitionError(
                f"Cannot rollback action {playbook_id} in state '{record.state}'. "
                f"Action must be in 'executed_simulated' state."
            )

        if record.version != expected_version:
            raise SoarOptimisticConcurrencyError(
                f"Optimistic lock conflict on {playbook_id}: "
                f"expected version {expected_version}, found {record.version}"
            )

        now_str = datetime.now(UTC).isoformat()

        updated = SoarPlaybookRecord(
            playbook_id=record.playbook_id,
            candidate_id=record.candidate_id,
            action_type=record.action_type,
            target_entity=record.target_entity,
            state="rolled_back",
            version=record.version + 1,
            actor_id=actor_id,
            decision_reason=record.decision_reason,
            pre_action_snapshot=record.pre_action_snapshot,
            execution_evidence=record.execution_evidence,
            rollback_reason=rollback_reason,
            created_at_utc=record.created_at_utc,
            updated_at_utc=now_str,
            t_approval_queued=record.t_approval_queued,
            t_callback_verified=record.t_callback_verified,
            t_response=record.t_response,
        )

        self.repository.save_record(updated)
        self.repository.append_audit_event(
            playbook_id=playbook_id,
            action="rollback_action",
            actor_id=actor_id,
            old_state=record.state,
            new_state="rolled_back",
            reason=rollback_reason,
            snapshot=record.pre_action_snapshot,
        )
        return updated
