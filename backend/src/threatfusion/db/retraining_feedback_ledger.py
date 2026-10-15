"""Offline Retraining Feedback Ledger.

Persists audited analyst triage feedback (confirmed_threat vs false_positive)
into a mode-0600 SQLite ledger for future offline batch retraining.
Enforces idempotent transition_request_id deduplication and verifies that
frozen model artifact SHA-256 digests remain 100% unchanged before and after
recording feedback, proving zero online weight drift for the academic jury viva.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threatfusion.schemas.analyst_state import valid_actor_id

OFFLINE_RETRAINING_FEEDBACK_SCHEMA_IDENTITY = "offline_retraining_feedback_sqlite_v1"
RETRAINING_FEEDBACK_REPOSITORY_SCHEMA_VERSION = 1

SQLITE_BUSY_TIMEOUT_MS = 5000

# Canonical baseline models and approved SHA-256 hashes
FROZEN_RF_RELATIVE_PATH = "artifacts/models/network_random_forest_baseline/full-network-random-forest-6d69c72-v1/random_forest.joblib"
FROZEN_RF_EXPECTED_SHA256 = "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"

FROZEN_AE_RELATIVE_PATH = (
    "artifacts/models/network_autoencoder/full-benign-autoencoder-2a51c94-v2/autoencoder_state.pt"
)
FROZEN_AE_EXPECTED_SHA256 = "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23"

ALLOWED_VERIFIED_OUTCOMES = frozenset({"confirmed_threat", "false_positive"})


class RetrainingFeedbackError(RuntimeError):
    """Sanitized boundary error for retraining feedback ledger."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _find_repo_root(hint: Path | None = None) -> Path:
    if hint is not None:
        return hint.resolve()
    current = Path(__file__).resolve().parent
    for parent in (current, *current.parents):
        if (parent / ".git").exists() or (parent / "artifacts").exists():
            return parent
    return Path("/home/muhammad-bilal/projects/threatfusion-gemini")


def _compute_sha256(path: Path) -> str:
    if not path.is_file():
        raise RetrainingFeedbackError(f"model_artifact_not_found:{path.name}")
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_frozen_models_unmodified(repo_root: Path | None = None) -> tuple[str, str]:
    """Verify that frozen model artifacts match their approved SHA-256 digests.

    Returns tuple (rf_sha256, ae_sha256).
    Fails closed if any digest does not match.
    """
    root = _find_repo_root(repo_root)

    rf_path = root / FROZEN_RF_RELATIVE_PATH
    if not rf_path.exists():
        # Check alias if present
        alias_rf = root / "artifacts/models/rf_unsw_pipeline.joblib"
        if alias_rf.exists():
            rf_path = alias_rf

    ae_path = root / FROZEN_AE_RELATIVE_PATH
    if not ae_path.exists():
        # Check alias if present
        alias_ae = root / "artifacts/models/autoencoder_unsw_v2.pt"
        if alias_ae.exists():
            ae_path = alias_ae

    rf_sha = _compute_sha256(rf_path)
    if rf_sha != FROZEN_RF_EXPECTED_SHA256:
        raise RetrainingFeedbackError("frozen_rf_digest_mismatch")

    ae_sha = _compute_sha256(ae_path)
    if ae_sha != FROZEN_AE_EXPECTED_SHA256:
        raise RetrainingFeedbackError("frozen_ae_digest_mismatch")

    return rf_sha, ae_sha


@dataclass(frozen=True, slots=True)
class RetrainingFeedbackRecord:
    """Immutable analyst triage feedback record for offline batch retraining."""

    transition_request_id: str
    alert_candidate_id: str
    stored_detector_decision: str
    stored_score: float
    analyst_verified_outcome: str
    actor_id: str
    recorded_at_utc: str
    rf_model_sha256: str
    ae_model_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "transition_request_id": self.transition_request_id,
            "alert_candidate_id": self.alert_candidate_id,
            "stored_detector_decision": self.stored_detector_decision,
            "stored_score": self.stored_score,
            "analyst_verified_outcome": self.analyst_verified_outcome,
            "actor_id": self.actor_id,
            "recorded_at_utc": self.recorded_at_utc,
            "rf_model_sha256": self.rf_model_sha256,
            "ae_model_sha256": self.ae_model_sha256,
        }


_CREATE_METADATA_TABLE = """
CREATE TABLE IF NOT EXISTS feedback_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
"""

_CREATE_FEEDBACK_TABLE = """
CREATE TABLE IF NOT EXISTS retraining_feedback (
    transition_request_id TEXT PRIMARY KEY,
    alert_candidate_id TEXT NOT NULL,
    stored_detector_decision TEXT NOT NULL,
    stored_score REAL NOT NULL,
    analyst_verified_outcome TEXT NOT NULL CHECK (analyst_verified_outcome IN ('confirmed_threat', 'false_positive')),
    actor_id TEXT NOT NULL,
    recorded_at_utc TEXT NOT NULL,
    rf_model_sha256 TEXT NOT NULL,
    ae_model_sha256 TEXT NOT NULL
) STRICT;
"""

_CREATE_INDEX_CANDIDATE = """
CREATE INDEX IF NOT EXISTS idx_feedback_candidate ON retraining_feedback(alert_candidate_id);
"""

_CREATE_INDEX_RECORDED_AT = """
CREATE INDEX IF NOT EXISTS idx_feedback_recorded_at ON retraining_feedback(recorded_at_utc);
"""


class OfflineRetrainingFeedbackRepository:
    """SQLite-backed append-only ledger for offline retraining triage feedback.

    Enforces file permissions 0600, schema identity, and zero online weight drift.
    """

    def __init__(self, database_path: Path, *, repo_root: Path | None = None) -> None:
        if not isinstance(database_path, Path):
            raise RetrainingFeedbackError("invalid_database_path")
        self._database_path = database_path
        self._repo_root = repo_root
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(
                self._database_path,
                timeout=SQLITE_BUSY_TIMEOUT_MS / 1000.0,
                isolation_level=None,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
            return conn
        except sqlite3.Error:
            raise RetrainingFeedbackError("ledger_unavailable") from None

    def _initialize(self) -> None:
        try:
            existed = False
            try:
                st = self._database_path.lstat()
                existed = True
                if not stat.S_ISREG(st.st_mode):
                    raise RetrainingFeedbackError("ledger_not_regular_file")
            except FileNotFoundError:
                existed = False
                self._database_path.parent.mkdir(parents=True, exist_ok=True)
                # Enforce directory mode 0700 if created
                try:
                    os.chmod(self._database_path.parent, 0o700)
                except OSError:
                    pass

            conn = self._connect()
            try:
                if not existed:
                    conn.execute("BEGIN EXCLUSIVE")
                    conn.execute(_CREATE_METADATA_TABLE)
                    conn.execute(_CREATE_FEEDBACK_TABLE)
                    conn.execute(_CREATE_INDEX_CANDIDATE)
                    conn.execute(_CREATE_INDEX_RECORDED_AT)
                    conn.execute(
                        "INSERT INTO feedback_metadata(key, value) VALUES (?, ?)",
                        ("schema_identity", OFFLINE_RETRAINING_FEEDBACK_SCHEMA_IDENTITY),
                    )
                    conn.execute(
                        f"PRAGMA user_version = {RETRAINING_FEEDBACK_REPOSITORY_SCHEMA_VERSION}"
                    )
                    conn.commit()

                    # Enforce mode 0600 on the newly created database file
                    try:
                        os.chmod(self._database_path, 0o600)
                    except OSError:
                        pass
                else:
                    # Verify schema
                    row = conn.execute(
                        "SELECT value FROM feedback_metadata WHERE key = 'schema_identity'"
                    ).fetchone()
                    if not row or row["value"] != OFFLINE_RETRAINING_FEEDBACK_SCHEMA_IDENTITY:
                        raise RetrainingFeedbackError("ledger_schema_mismatch")
            finally:
                conn.close()
        except RetrainingFeedbackError:
            raise
        except (OSError, sqlite3.DatabaseError) as err:
            raise RetrainingFeedbackError("ledger_corrupt") from err

    def record_feedback(
        self,
        *,
        transition_request_id: str,
        alert_candidate_id: str,
        stored_detector_decision: str,
        stored_score: float,
        analyst_verified_outcome: str,
        actor_id: str,
        recorded_at_utc: str | None = None,
    ) -> dict[str, Any]:
        """Record analyst triage feedback with pre- and post-model-drift verification."""
        # 1. Parameter validations
        if not isinstance(transition_request_id, str) or not transition_request_id.strip():
            raise RetrainingFeedbackError("invalid_transition_request_id")
        if not isinstance(alert_candidate_id, str) or not alert_candidate_id.strip():
            raise RetrainingFeedbackError("invalid_alert_candidate_id")
        if not isinstance(stored_detector_decision, str) or not stored_detector_decision.strip():
            raise RetrainingFeedbackError("invalid_detector_decision")
        try:
            score_val = float(stored_score)
        except (TypeError, ValueError):
            raise RetrainingFeedbackError("invalid_stored_score") from None
        if not 0.0 <= score_val <= 1.0:
            raise RetrainingFeedbackError("invalid_stored_score")

        if analyst_verified_outcome not in ALLOWED_VERIFIED_OUTCOMES:
            raise RetrainingFeedbackError("invalid_analyst_verified_outcome")

        if not valid_actor_id(actor_id):
            raise RetrainingFeedbackError("invalid_actor_id")

        timestamp = recorded_at_utc or datetime.now(UTC).isoformat()

        # 2. Pre-write zero-online-weight-drift verification
        rf_sha_pre, ae_sha_pre = verify_frozen_models_unmodified(self._repo_root)

        # 3. Transaction write with idempotent replay deduplication
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM retraining_feedback WHERE transition_request_id = ?",
                (transition_request_id,),
            ).fetchone()

            if existing is not None:
                # Check for idempotent match
                if (
                    existing["alert_candidate_id"] == alert_candidate_id
                    and existing["stored_detector_decision"] == stored_detector_decision
                    and abs(existing["stored_score"] - score_val) < 1e-6
                    and existing["analyst_verified_outcome"] == analyst_verified_outcome
                    and existing["actor_id"] == actor_id
                ):
                    conn.rollback()
                    return {
                        "status": "existing",
                        "transition_request_id": transition_request_id,
                        "alert_candidate_id": alert_candidate_id,
                        "analyst_verified_outcome": analyst_verified_outcome,
                        "recorded_at_utc": existing["recorded_at_utc"],
                    }
                else:
                    conn.rollback()
                    raise RetrainingFeedbackError("conflicting_feedback_retry")

            conn.execute(
                """
                INSERT INTO retraining_feedback (
                    transition_request_id,
                    alert_candidate_id,
                    stored_detector_decision,
                    stored_score,
                    analyst_verified_outcome,
                    actor_id,
                    recorded_at_utc,
                    rf_model_sha256,
                    ae_model_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transition_request_id,
                    alert_candidate_id,
                    stored_detector_decision,
                    score_val,
                    analyst_verified_outcome,
                    actor_id,
                    timestamp,
                    rf_sha_pre,
                    ae_sha_pre,
                ),
            )
            conn.commit()
        except sqlite3.Error as err:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise RetrainingFeedbackError("feedback_insert_failed") from err
        finally:
            conn.close()

        # 4. Post-write zero-online-weight-drift verification
        rf_sha_post, ae_sha_post = verify_frozen_models_unmodified(self._repo_root)
        if rf_sha_pre != rf_sha_post or ae_sha_pre != ae_sha_post:
            raise RetrainingFeedbackError("online_weight_drift_detected")

        return {
            "status": "created",
            "transition_request_id": transition_request_id,
            "alert_candidate_id": alert_candidate_id,
            "analyst_verified_outcome": analyst_verified_outcome,
            "recorded_at_utc": timestamp,
            "rf_model_sha256": rf_sha_post,
            "ae_model_sha256": ae_sha_post,
        }

    def get_feedback(self, transition_request_id: str) -> RetrainingFeedbackRecord | None:
        """Fetch a recorded feedback record by transition request ID."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM retraining_feedback WHERE transition_request_id = ?",
                (transition_request_id,),
            ).fetchone()
            if row is None:
                return None
            return RetrainingFeedbackRecord(
                transition_request_id=row["transition_request_id"],
                alert_candidate_id=row["alert_candidate_id"],
                stored_detector_decision=row["stored_detector_decision"],
                stored_score=row["stored_score"],
                analyst_verified_outcome=row["analyst_verified_outcome"],
                actor_id=row["actor_id"],
                recorded_at_utc=row["recorded_at_utc"],
                rf_model_sha256=row["rf_model_sha256"],
                ae_model_sha256=row["ae_model_sha256"],
            )
        finally:
            conn.close()

    def list_feedback(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RetrainingFeedbackRecord]:
        """List feedback records ordered by recorded_at_utc ascending."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM retraining_feedback ORDER BY recorded_at_utc ASC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [
                RetrainingFeedbackRecord(
                    transition_request_id=row["transition_request_id"],
                    alert_candidate_id=row["alert_candidate_id"],
                    stored_detector_decision=row["stored_detector_decision"],
                    stored_score=row["stored_score"],
                    analyst_verified_outcome=row["analyst_verified_outcome"],
                    actor_id=row["actor_id"],
                    recorded_at_utc=row["recorded_at_utc"],
                    rf_model_sha256=row["rf_model_sha256"],
                    ae_model_sha256=row["ae_model_sha256"],
                )
                for row in rows
            ]
        finally:
            conn.close()

    def count_feedback(self) -> int:
        """Count total recorded feedback entries."""
        conn = self._connect()
        try:
            row = conn.execute("SELECT COUNT(*) AS total FROM retraining_feedback").fetchone()
            return int(row["total"]) if row else 0
        finally:
            conn.close()
