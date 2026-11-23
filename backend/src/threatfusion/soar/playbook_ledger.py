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
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import stat
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from threatfusion.alerts.correlation_engine import EntityProvenanceContract
from threatfusion.db.sqlite_permissions import (
    ensure_secure_parent_dir,
    harden_sqlite_permissions,
    precreate_sqlite_0600,
    scoped_umask_077,
)

UTC = timezone.utc


SOAR_SCHEMA_VERSION = "soar_ledger_sqlite_v1"
SOAR_AUDIT_GENESIS_HASH = "0" * 64
_LEDGER_KEY_SUFFIX = ".ledger_hmac_key"


class SoarError(RuntimeError):
    """Base SOAR domain error."""


def _ledger_hmac(secret: str | None, canonical_repr: str) -> str:
    key = secret if secret is not None else os.environ.get("THREATFUSION_SOAR_HMAC_SECRET")
    if not key:
        raise SoarError("missing_ledger_secret")
    return hmac.new(key.encode("utf-8"), canonical_repr.encode("utf-8"), hashlib.sha256).hexdigest()


def compute_canonical_audit_entry_hash(
    *,
    prev_entry_sha256: str,
    sequence_id: int,
    playbook_id: str,
    candidate_id: str,
    state: str,
    actor: str,
    reason: str | None,
    timestamp_utc: str,
    ledger_secret: str | None = None,
) -> str:
    """HMAC one ledger row from the canonical chain fields. Genesis is ``0`` * 64."""
    payload = {
        "actor": actor,
        "candidate_id": candidate_id,
        "playbook_id": playbook_id,
        "prev_entry_sha256": prev_entry_sha256,
        "reason": "" if reason is None else reason,
        "sequence_id": int(sequence_id),
        "state": state,
        "timestamp_utc": timestamp_utc,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return _ledger_hmac(ledger_secret, encoded)


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
    ledger_secret: str | None = None,
) -> str:
    """HMAC one SOAR audit entry. An unkeyed SHA-256 rewrite does not match."""
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
    return _ledger_hmac(ledger_secret, canonical_repr)


def seal_head_hmac(secret: str, expected_count: int, head_entry_sha256: str) -> str:
    if not secret:
        raise SoarError("missing_ledger_secret")
    material = f"{int(expected_count)}:{head_entry_sha256}"
    return hmac.new(secret.encode("utf-8"), material.encode("utf-8"), hashlib.sha256).hexdigest()


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

    def __init__(self, db_path: Path | str, ledger_secret: str | None = None) -> None:
        self.db_path = Path(db_path)
        ensure_secure_parent_dir(self.db_path.parent)
        self._ledger_secret = self._resolve_ledger_secret(ledger_secret)
        self._append_lock = threading.Lock()
        self._init_db()

    def _hmac_key_path(self) -> Path:
        return self.db_path.with_name(self.db_path.name + _LEDGER_KEY_SUFFIX)

    def _read_sidecar_key(self) -> str:
        path = self._hmac_key_path()
        if path.is_symlink() or not path.is_file():
            return ""
        try:
            info = path.lstat()
        except OSError:
            return ""
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return ""
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            return ""
        try:
            stored = path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        return stored

    def _write_sidecar_key(self, key: str) -> str:
        if not key:
            return ""
        path = self._hmac_key_path()
        if path.is_symlink():
            return ""
        existing = self._read_sidecar_key()
        if existing:
            return existing
        try:
            with scoped_umask_077():
                fd = os.open(
                    str(path),
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                    0o600,
                )
        except FileExistsError:
            return self._read_sidecar_key()
        except OSError:
            return ""
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            os.write(fd, (key + "\n").encode("utf-8"))
        except OSError:
            return ""
        finally:
            os.close(fd)
        return key

    def _resolve_ledger_secret(self, ledger_secret: str | None) -> str:
        """Use an explicit secret, the environment, or a mode-0600 sidecar.

        An empty key is never used. When ``THREATFUSION_SOAR_HMAC_SECRET`` is
        unset, the sidecar lets a second process open the same SQLite path and
        recompute the same seal.
        """
        env_name = "THREATFUSION_SOAR_HMAC_SECRET"
        env_value = os.environ.get(env_name, "")
        if ledger_secret:
            if env_name not in os.environ:
                self._write_sidecar_key(ledger_secret)
            return ledger_secret
        if env_value:
            return env_value
        return self._read_sidecar_key() or self._write_sidecar_key(secrets.token_hex(32))

    def _get_connection(self) -> sqlite3.Connection:
        with scoped_umask_077():
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
        ensure_secure_parent_dir(self.db_path.parent)
        try:
            info = self.db_path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise SoarError("soar_db_not_regular_file")
        except FileNotFoundError:
            precreate_sqlite_0600(self.db_path)
        with scoped_umask_077():
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
                        entry_sha256 TEXT NOT NULL,
                        sequence_id INTEGER,
                        candidate_id TEXT,
                        canonical_entry_sha256 TEXT
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
                if "sequence_id" not in cols:
                    conn.execute("ALTER TABLE soar_audit_events ADD COLUMN sequence_id INTEGER")
                if "candidate_id" not in cols:
                    conn.execute("ALTER TABLE soar_audit_events ADD COLUMN candidate_id TEXT")
                if "canonical_entry_sha256" not in cols:
                    conn.execute(
                        "ALTER TABLE soar_audit_events ADD COLUMN canonical_entry_sha256 TEXT"
                    )

                # Migration check: Ensure timing columns exist in soar_playbook_records
                cols_pb_cursor = conn.execute("PRAGMA table_info(soar_playbook_records)")
                cols_pb = {row["name"] for row in cols_pb_cursor.fetchall()}
                if "t_approval_queued" not in cols_pb:
                    conn.execute(
                        "ALTER TABLE soar_playbook_records ADD COLUMN t_approval_queued REAL"
                    )
                if "t_callback_verified" not in cols_pb:
                    conn.execute(
                        "ALTER TABLE soar_playbook_records ADD COLUMN t_callback_verified REAL"
                    )
                if "t_response" not in cols_pb:
                    conn.execute("ALTER TABLE soar_playbook_records ADD COLUMN t_response REAL")

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS soar_ledger_head_seal (
                        seal_id INTEGER PRIMARY KEY CHECK (seal_id = 1),
                        expected_count INTEGER NOT NULL,
                        head_entry_sha256 TEXT NOT NULL,
                        head_seal_hmac TEXT NOT NULL
                    )
                    """)
                conn.execute("""
                    CREATE TRIGGER IF NOT EXISTS soar_audit_events_append_only_delete
                    BEFORE DELETE ON soar_audit_events
                    BEGIN
                        SELECT RAISE(ABORT, 'soar_audit_ledger_append_only');
                    END
                    """)
                conn.execute("""
                    CREATE TRIGGER IF NOT EXISTS soar_audit_events_append_only_update
                    BEFORE UPDATE ON soar_audit_events
                    BEGIN
                        SELECT RAISE(ABORT, 'soar_audit_ledger_append_only');
                    END
                    """)

                conn.commit()
        harden_sqlite_permissions(self.db_path)

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
        harden_sqlite_permissions(self.db_path)

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

    def _append_audit_event_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        playbook_id: str,
        action: str,
        actor_id: str,
        old_state: str,
        new_state: str,
        reason: str | None = None,
        snapshot: str | None = None,
        candidate_id: str | None = None,
    ) -> SoarAuditEntry:
        event_id = f"soar_audit:{uuid.uuid4().hex}"
        timestamp = datetime.now(UTC).isoformat()
        cur = conn.execute("SELECT entry_sha256 FROM soar_audit_events ORDER BY rowid DESC LIMIT 1")
        last_row = cur.fetchone()
        prev_hash = (
            last_row["entry_sha256"]
            if last_row and last_row["entry_sha256"]
            else SOAR_AUDIT_GENESIS_HASH
        )
        count_row = conn.execute("SELECT COUNT(*) AS n FROM soar_audit_events").fetchone()
        sequence_id = int(count_row["n"]) + 1
        if candidate_id is None:
            candidate_row = conn.execute(
                "SELECT candidate_id FROM soar_playbook_records WHERE playbook_id = ?",
                (playbook_id,),
            ).fetchone()
            resolved_candidate_id = (
                str(candidate_row["candidate_id"])
                if candidate_row and candidate_row["candidate_id"]
                else ""
            )
        else:
            resolved_candidate_id = str(candidate_id)
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
            ledger_secret=self._ledger_secret,
        )
        canonical_hash = compute_canonical_audit_entry_hash(
            prev_entry_sha256=prev_hash,
            sequence_id=sequence_id,
            playbook_id=playbook_id,
            candidate_id=resolved_candidate_id,
            state=new_state,
            actor=actor_id,
            reason=reason,
            timestamp_utc=timestamp,
            ledger_secret=self._ledger_secret,
        )
        conn.execute(
            """
            INSERT INTO soar_audit_events (
                event_id, playbook_id, action, actor_id,
                old_state, new_state, reason, snapshot, timestamp_utc,
                prev_entry_sha256, entry_sha256, sequence_id,
                candidate_id, canonical_entry_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                sequence_id,
                resolved_candidate_id,
                canonical_hash,
            ),
        )
        seal = seal_head_hmac(self._ledger_secret, sequence_id, entry_hash)
        conn.execute(
            """
            INSERT INTO soar_ledger_head_seal (
                seal_id, expected_count, head_entry_sha256, head_seal_hmac
            ) VALUES (1, ?, ?, ?)
            ON CONFLICT(seal_id) DO UPDATE SET
                expected_count = excluded.expected_count,
                head_entry_sha256 = excluded.head_entry_sha256,
                head_seal_hmac = excluded.head_seal_hmac
            """,
            (sequence_id, entry_hash, seal),
        )
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

    def create_record_with_audit_atomic(
        self,
        record: SoarPlaybookRecord,
        *,
        action: str = "recommend_action",
        actor_id: str = "system:recommendation_engine",
        old_state: str = "none",
        reason: str | None = None,
        snapshot: str | None = None,
    ) -> SoarAuditEntry:
        """Atomically insert a new playbook record and append its audit event + seal."""
        with self._append_lock:
            conn = self._get_connection()
            try:
                conn.isolation_level = None
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO soar_playbook_records (
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
                entry = self._append_audit_event_in_tx(
                    conn,
                    playbook_id=record.playbook_id,
                    action=action,
                    actor_id=actor_id,
                    old_state=old_state,
                    new_state=record.state,
                    reason=reason,
                    snapshot=snapshot,
                    candidate_id=record.candidate_id,
                )
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                conn.close()
                harden_sqlite_permissions(self.db_path)
        return entry

    def transition_record_with_audit_atomic(
        self,
        updated: SoarPlaybookRecord,
        *,
        expected_version: int,
        expected_state: str,
        action: str,
        actor_id: str,
        reason: str | None = None,
        snapshot: str | None = None,
        reject_if_sibling_rejected: bool = False,
        expected_actor_id: str | None = None,
        verify_audit_chain_in_tx: bool = False,
    ) -> SoarAuditEntry:
        """Atomically CAS-update a playbook record and append its audit event + seal."""
        with self._append_lock:
            conn = self._get_connection()
            try:
                conn.isolation_level = None
                conn.execute("BEGIN IMMEDIATE")
                if reject_if_sibling_rejected:
                    sibling_rows = conn.execute(
                        "SELECT state, version, updated_at_utc FROM soar_playbook_records "
                        "WHERE candidate_id = ?",
                        (updated.candidate_id,),
                    ).fetchall()
                    if sibling_rows:
                        latest = max(
                            sibling_rows,
                            key=lambda r: (int(r["version"]), str(r["updated_at_utc"] or "")),
                        )
                        if str(latest["state"]) == "rejected":
                            raise ValueError("playbook_already_rejected")
                if expected_actor_id is not None:
                    current_row = conn.execute(
                        "SELECT state, version, actor_id FROM soar_playbook_records "
                        "WHERE playbook_id = ?",
                        (updated.playbook_id,),
                    ).fetchone()
                    if current_row is None:
                        raise KeyError(f"Playbook record {updated.playbook_id} not found")
                    if str(current_row["state"]) != expected_state:
                        raise SoarStateTransitionError(
                            f"Cannot transition action {updated.playbook_id} in state "
                            f"'{current_row['state']}'; expected '{expected_state}'."
                        )
                    if int(current_row["version"]) != expected_version:
                        raise SoarOptimisticConcurrencyError(
                            f"Optimistic lock conflict on {updated.playbook_id}: "
                            f"expected version {expected_version}, found {current_row['version']}"
                        )
                    if str(current_row["actor_id"] or "") != expected_actor_id:
                        raise SoarStateTransitionError(
                            f"Cannot rollback action {updated.playbook_id}: "
                            "actor does not match the executor."
                        )
                if verify_audit_chain_in_tx:
                    chain_ok, chain_message = self._verify_audit_chain_in_tx(
                        conn, updated.playbook_id, require_non_empty=True
                    )
                    if not chain_ok:
                        raise SoarStateTransitionError(
                            f"Cannot rollback action {updated.playbook_id}: "
                            f"audit chain verification failed ({chain_message})."
                        )
                cur = conn.execute(
                    """
                    UPDATE soar_playbook_records
                    SET candidate_id = ?, action_type = ?, target_entity = ?,
                        state = ?, version = ?, actor_id = ?, decision_reason = ?,
                        pre_action_snapshot = ?, execution_evidence = ?, rollback_reason = ?,
                        created_at_utc = ?, updated_at_utc = ?,
                        t_approval_queued = ?, t_callback_verified = ?, t_response = ?
                    WHERE playbook_id = ? AND version = ? AND state = ?
                    """,
                    (
                        updated.candidate_id,
                        updated.action_type,
                        updated.target_entity,
                        updated.state,
                        updated.version,
                        updated.actor_id,
                        updated.decision_reason,
                        updated.pre_action_snapshot,
                        updated.execution_evidence,
                        updated.rollback_reason,
                        updated.created_at_utc,
                        updated.updated_at_utc,
                        updated.t_approval_queued,
                        updated.t_callback_verified,
                        updated.t_response,
                        updated.playbook_id,
                        expected_version,
                        expected_state,
                    ),
                )
                if cur.rowcount != 1:
                    existing = conn.execute(
                        "SELECT state, version FROM soar_playbook_records WHERE playbook_id = ?",
                        (updated.playbook_id,),
                    ).fetchone()
                    if existing is None:
                        raise KeyError(f"Playbook record {updated.playbook_id} not found")
                    if str(existing["state"]) != expected_state:
                        raise SoarStateTransitionError(
                            f"Cannot transition action {updated.playbook_id} in state "
                            f"'{existing['state']}'; expected '{expected_state}'."
                        )
                    raise SoarOptimisticConcurrencyError(
                        f"Optimistic lock conflict on {updated.playbook_id}: "
                        f"expected version {expected_version}, found {existing['version']}"
                    )
                entry = self._append_audit_event_in_tx(
                    conn,
                    playbook_id=updated.playbook_id,
                    action=action,
                    actor_id=actor_id,
                    old_state=expected_state,
                    new_state=updated.state,
                    reason=reason,
                    snapshot=snapshot,
                    candidate_id=updated.candidate_id,
                )
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                conn.close()
                harden_sqlite_permissions(self.db_path)
        return entry

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
        with self._append_lock:
            conn = self._get_connection()
            try:
                conn.isolation_level = None
                conn.execute("BEGIN IMMEDIATE")
                entry = self._append_audit_event_in_tx(
                    conn,
                    playbook_id=playbook_id,
                    action=action,
                    actor_id=actor_id,
                    old_state=old_state,
                    new_state=new_state,
                    reason=reason,
                    snapshot=snapshot,
                )
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                conn.close()
                harden_sqlite_permissions(self.db_path)
        return entry

    def list_audit_events(self, playbook_id: str) -> list[dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM soar_audit_events WHERE playbook_id = ? ORDER BY rowid ASC",
                (playbook_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def list_audit_entries(self, playbook_id: str) -> list[SoarAuditEntry]:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM soar_audit_events WHERE playbook_id = ? ORDER BY rowid ASC",
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

    def reseal_audit_chain_with_current_secret(self) -> bool:
        """Recompute stored row hashes with the current HMAC secret.

        A daemon restart can leave rows that were signed by an older secret.
        Event content stays. The append-only trigger is restored before return.
        """
        if not self._ledger_secret:
            return False
        with self._append_lock:
            conn = self._get_connection()
            try:
                conn.isolation_level = None
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("DROP TRIGGER IF EXISTS soar_audit_events_append_only_update")
                rows = conn.execute(
                    "SELECT rowid, * FROM soar_audit_events ORDER BY rowid ASC"
                ).fetchall()
                previous = SOAR_AUDIT_GENESIS_HASH
                for index, row in enumerate(rows):
                    sequence_id = index + 1
                    candidate_id = (
                        str(row["candidate_id"] or "") if "candidate_id" in row.keys() else ""
                    )
                    entry_hash = compute_soar_audit_entry_hash(
                        event_id=row["event_id"],
                        playbook_id=row["playbook_id"],
                        action=row["action"],
                        actor_id=row["actor_id"],
                        old_state=row["old_state"],
                        new_state=row["new_state"],
                        reason=row["reason"],
                        snapshot=row["snapshot"],
                        timestamp_utc=row["timestamp_utc"],
                        prev_entry_sha256=previous,
                        ledger_secret=self._ledger_secret,
                    )
                    canonical_hash = compute_canonical_audit_entry_hash(
                        prev_entry_sha256=previous,
                        sequence_id=sequence_id,
                        playbook_id=row["playbook_id"],
                        candidate_id=candidate_id,
                        state=row["new_state"],
                        actor=row["actor_id"],
                        reason=row["reason"],
                        timestamp_utc=row["timestamp_utc"],
                        ledger_secret=self._ledger_secret,
                    )
                    conn.execute(
                        """
                        UPDATE soar_audit_events
                        SET prev_entry_sha256 = ?, entry_sha256 = ?, sequence_id = ?,
                            candidate_id = ?, canonical_entry_sha256 = ?
                        WHERE rowid = ?
                        """,
                        (
                            previous,
                            entry_hash,
                            sequence_id,
                            candidate_id,
                            canonical_hash,
                            int(row["rowid"]),
                        ),
                    )
                    previous = entry_hash
                if rows:
                    seal = seal_head_hmac(self._ledger_secret, len(rows), previous)
                    conn.execute(
                        """
                        INSERT INTO soar_ledger_head_seal (
                            seal_id, expected_count, head_entry_sha256, head_seal_hmac
                        ) VALUES (1, ?, ?, ?)
                        ON CONFLICT(seal_id) DO UPDATE SET
                            expected_count = excluded.expected_count,
                            head_entry_sha256 = excluded.head_entry_sha256,
                            head_seal_hmac = excluded.head_seal_hmac
                        """,
                        (len(rows), previous, seal),
                    )
                # Recreate append-only update trigger atomically BEFORE COMMIT so it is never absent.
                conn.execute("""
                    CREATE TRIGGER IF NOT EXISTS soar_audit_events_append_only_update
                    BEFORE UPDATE ON soar_audit_events
                    BEGIN
                        SELECT RAISE(ABORT, 'soar_audit_ledger_append_only');
                    END
                    """)
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                conn.close()
                harden_sqlite_permissions(self.db_path)
        verified, _message = self.verify_audit_chain_integrity(require_non_empty=False)
        return verified or _message == "empty ledger"

    def _verify_audit_chain_in_tx(
        self,
        conn: sqlite3.Connection,
        playbook_id: str | None = None,
        *,
        require_non_empty: bool = True,
    ) -> tuple[bool, str]:
        """Verify keyed hash chain and head seal on an active transaction connection."""
        if not self._ledger_secret:
            return False, "missing_ledger_secret"
        cursor = conn.execute("SELECT * FROM soar_audit_events ORDER BY rowid ASC")
        all_rows = cursor.fetchall()
        seal_row = conn.execute(
            "SELECT expected_count, head_entry_sha256, head_seal_hmac "
            "FROM soar_ledger_head_seal WHERE seal_id = 1"
        ).fetchone()
        return self._evaluate_audit_chain_rows(
            all_rows,
            seal_row,
            playbook_id=playbook_id,
            require_non_empty=require_non_empty,
        )

    def verify_audit_chain_integrity(
        self,
        playbook_id: str | None = None,
        *,
        require_non_empty: bool = True,
    ) -> tuple[bool, str]:
        """Verify the keyed hash chain and the sealed head counter.

        An empty ledger is not sound. A tail deletion or an unkeyed rewrite fails.
        A ledger with no resolvable HMAC secret is not sound.
        """
        if not self._ledger_secret:
            return False, "missing_ledger_secret"
        with self._append_lock:
            conn = self._get_connection()
            try:
                conn.isolation_level = None
                conn.execute("BEGIN DEFERRED")
                result = self._verify_audit_chain_in_tx(
                    conn,
                    playbook_id=playbook_id,
                    require_non_empty=require_non_empty,
                )
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                conn.close()
        return result

    def _evaluate_audit_chain_rows(
        self,
        all_rows: list[sqlite3.Row],
        seal_row: sqlite3.Row | None,
        *,
        playbook_id: str | None = None,
        require_non_empty: bool = True,
    ) -> tuple[bool, str]:
        if not all_rows:
            return False, "empty ledger"
        if require_non_empty and seal_row is None:
            return False, "empty ledger"

        expected_prev = SOAR_AUDIT_GENESIS_HASH
        for idx, row in enumerate(all_rows):
            col_names = row.keys()
            stored_prev = row["prev_entry_sha256"] if "prev_entry_sha256" in col_names else ""
            stored_hash = row["entry_sha256"] if "entry_sha256" in col_names else ""

            if not hmac.compare_digest(str(stored_prev or ""), str(expected_prev)):
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
                ledger_secret=self._ledger_secret,
            )
            if not hmac.compare_digest(str(recomputed), str(stored_hash or "")):
                return (
                    False,
                    f"SOAR audit chain broken at row index {idx} (event_id={row['event_id']}): "
                    f"recomputed hash '{recomputed}' != stored entry_sha256 '{stored_hash}'",
                )

            seq_val = row["sequence_id"] if "sequence_id" in col_names else None
            if seq_val is None or int(seq_val) != idx + 1:
                return (
                    False,
                    f"SOAR audit chain broken at row index {idx} (event_id={row['event_id']}): "
                    f"sequence_id {seq_val} != {idx + 1}",
                )

            stored_canonical = (
                str(row["canonical_entry_sha256"] or "")
                if "canonical_entry_sha256" in col_names
                else ""
            )
            if not stored_canonical:
                return (
                    False,
                    f"SOAR audit chain broken at row index {idx} (event_id={row['event_id']}): "
                    "canonical_entry_sha256 missing or empty",
                )
            canonical = compute_canonical_audit_entry_hash(
                prev_entry_sha256=stored_prev,
                sequence_id=int(seq_val),
                playbook_id=row["playbook_id"],
                candidate_id=(
                    str(row["candidate_id"] or "") if "candidate_id" in col_names else ""
                ),
                state=row["new_state"],
                actor=row["actor_id"],
                reason=row["reason"],
                timestamp_utc=row["timestamp_utc"],
                ledger_secret=self._ledger_secret,
            )
            if not hmac.compare_digest(str(canonical), stored_canonical):
                return (
                    False,
                    f"SOAR audit chain broken at row index {idx} (event_id={row['event_id']}): "
                    f"recomputed hash '{canonical}' != stored canonical_entry_sha256 "
                    f"'{stored_canonical}'",
                )

            expected_prev = stored_hash

        if seal_row is None:
            return False, "empty ledger"
        expected_seal = seal_head_hmac(
            self._ledger_secret,
            int(seal_row["expected_count"]),
            str(seal_row["head_entry_sha256"]),
        )
        if (
            int(seal_row["expected_count"]) != len(all_rows)
            or not hmac.compare_digest(
                str(seal_row["head_entry_sha256"] or ""),
                str(all_rows[-1]["entry_sha256"] or ""),
            )
            or not hmac.compare_digest(expected_seal, str(seal_row["head_seal_hmac"] or ""))
        ):
            return False, "SOAR audit head seal mismatch"

        if playbook_id is not None:
            rows = [row for row in all_rows if row["playbook_id"] == playbook_id]
            if not rows:
                return False, "empty ledger"
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
        harden_sqlite_permissions(self.db_path)
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
            self.repository.create_record_with_audit_atomic(
                r,
                action="recommend_action",
                actor_id="system:recommendation_engine",
                old_state="none",
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

        if decision == "approve":
            siblings = self.repository.list_records_for_candidate(record.candidate_id)
            latest = max(
                siblings or (record,),
                key=lambda item: (item.version, item.updated_at_utc or ""),
            )
            if record.state == "rejected" or latest.state == "rejected":
                raise ValueError("playbook_already_rejected")

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

        self.repository.transition_record_with_audit_atomic(
            updated,
            expected_version=expected_version,
            expected_state="pending_approval",
            action=f"analyst_{decision}",
            actor_id=actor_id,
            reason=reason,
            reject_if_sibling_rejected=(decision == "approve"),
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

        if record.action_type == "verify_and_contain_lab_source_ip":
            try:
                validated_ip = str(ipaddress.ip_address(str(record.target_entity).strip()))
            except ValueError as exc:
                raise SoarStateTransitionError(
                    f"Invalid IP target_entity for containment playbook {playbook_id}"
                ) from exc
            command_str = f"iptables -I FORWARD -s {validated_ip} -j DROP"
        else:
            command_str = f"simulated_action:{record.action_type}"

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
                "command": command_str,
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

        self.repository.transition_record_with_audit_atomic(
            updated,
            expected_version=expected_version,
            expected_state="approved",
            action="execute_simulated_action",
            actor_id=actor_id,
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
        if record.actor_id != actor_id.strip():
            raise SoarStateTransitionError(
                f"Cannot rollback action {playbook_id}: actor does not match the executor."
            )
        chain_ok, chain_message = self.repository.verify_audit_chain_integrity(
            playbook_id, require_non_empty=True
        )
        if not chain_ok:
            raise SoarStateTransitionError(
                f"Cannot rollback action {playbook_id}: audit chain verification failed "
                f"({chain_message})."
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

        self.repository.transition_record_with_audit_atomic(
            updated,
            expected_version=expected_version,
            expected_state="executed_simulated",
            action="rollback_action",
            actor_id=actor_id,
            reason=rollback_reason,
            snapshot=record.pre_action_snapshot,
            expected_actor_id=actor_id.strip(),
            verify_audit_chain_in_tx=True,
        )
        return updated
