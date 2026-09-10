"""Small fail-closed SQLite repository for immutable AlertCandidate rows."""

from __future__ import annotations

import math
import sqlite3
import stat
from dataclasses import dataclass, fields
from datetime import datetime
from pathlib import Path

from threatfusion.schemas.alert_candidate import AlertCandidate, AlertCandidateError

ALERT_REPOSITORY_SCHEMA_VERSION = 1
ALERT_REPOSITORY_SCHEMA_IDENTITY = "alert_candidate_sqlite_v1"
MAX_ALERT_LIST_LIMIT = 100
MAX_ALERT_LIST_OFFSET = 1_000_000
SQLITE_BUSY_TIMEOUT_MS = 500
MODEL_SCORE_RETRY_ABS_TOLERANCE = 1e-15

_COLUMNS = tuple(field.name for field in fields(AlertCandidate))
_COLUMN_LIST = ", ".join(_COLUMNS)
_PLACEHOLDERS = ", ".join("?" for _ in _COLUMNS)
_CREATE_METADATA = """
CREATE TABLE repository_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT
"""
_CREATE_CANDIDATES = """
CREATE TABLE alert_candidates (
    schema_version TEXT NOT NULL,
    alert_candidate_id TEXT PRIMARY KEY,
    source_event_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    detector_identity TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    model_identity TEXT NOT NULL,
    model_version TEXT NOT NULL,
    model_artifact_sha256 TEXT NOT NULL,
    feature_contract_identity TEXT NOT NULL,
    source_representation_identity TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    uncalibrated_model_score REAL NOT NULL,
    decision_threshold REAL NOT NULL,
    decision_policy_version TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision = 'Attack'),
    inference_status TEXT NOT NULL CHECK (inference_status = 'completed'),
    reason TEXT NOT NULL CHECK (reason = 'inference_succeeded')
) STRICT
"""
_EXPECTED_METADATA_COLUMNS = (
    ("key", "TEXT", 1, 1),
    ("value", "TEXT", 1, 0),
)
_EXPECTED_CANDIDATE_COLUMNS = (
    ("schema_version", "TEXT", 1, 0),
    ("alert_candidate_id", "TEXT", 1, 1),
    ("source_event_id", "TEXT", 1, 0),
    ("correlation_id", "TEXT", 1, 0),
    ("detector_identity", "TEXT", 1, 0),
    ("detector_version", "TEXT", 1, 0),
    ("model_identity", "TEXT", 1, 0),
    ("model_version", "TEXT", 1, 0),
    ("model_artifact_sha256", "TEXT", 1, 0),
    ("feature_contract_identity", "TEXT", 1, 0),
    ("source_representation_identity", "TEXT", 1, 0),
    ("observed_at", "TEXT", 1, 0),
    ("created_at", "TEXT", 1, 0),
    ("uncalibrated_model_score", "REAL", 1, 0),
    ("decision_threshold", "REAL", 1, 0),
    ("decision_policy_version", "TEXT", 1, 0),
    ("decision", "TEXT", 1, 0),
    ("inference_status", "TEXT", 1, 0),
    ("reason", "TEXT", 1, 0),
)


class AlertPersistenceError(RuntimeError):
    """Sanitized repository error without SQL, paths, or SQLite details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class AlertInsertResult:
    """Distinguish a new durable row from an idempotent retry."""

    disposition: str
    reason: str
    candidate: AlertCandidate


def _values(candidate: AlertCandidate) -> tuple[object, ...]:
    return tuple(
        value.isoformat() if type(value) is datetime else value
        for value in (getattr(candidate, column) for column in _COLUMNS)
    )


def _candidate(row: sqlite3.Row) -> AlertCandidate:
    try:
        payload = dict(row)
        payload["observed_at"] = datetime.fromisoformat(payload["observed_at"])
        payload["created_at"] = datetime.fromisoformat(payload["created_at"])
        return AlertCandidate(**payload)
    except (AlertCandidateError, TypeError, ValueError):
        raise AlertPersistenceError("database_record_invalid") from None


def _stable_content_without_score(candidate: AlertCandidate) -> tuple[object, ...]:
    """Retain exact identity evidence while excluding attempt metadata and score."""
    return tuple(
        getattr(candidate, column)
        for column in _COLUMNS
        if column not in {"correlation_id", "created_at", "uncalibrated_model_score"}
    )


def _same_detection_evidence(stored: AlertCandidate, attempted: AlertCandidate) -> bool:
    return _stable_content_without_score(stored) == _stable_content_without_score(
        attempted
    ) and math.isclose(
        stored.uncalibrated_model_score,
        attempted.uncalibrated_model_score,
        rel_tol=0.0,
        abs_tol=MODEL_SCORE_RETRY_ABS_TOLERANCE,
    )


class AlertCandidateRepository:
    """SQLite-backed, bounded repository with one connection per atomic operation."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self._database_path,
                timeout=SQLITE_BUSY_TIMEOUT_MS / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 500")
            return connection
        except sqlite3.Error:
            raise AlertPersistenceError("database_unavailable") from None

    def _initialize(self) -> None:
        try:
            try:
                info = self._database_path.lstat()
                existed = True
                if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
                    raise AlertPersistenceError("database_corrupt")
            except FileNotFoundError:
                existed = False
                self._database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = self._connect()
            try:
                check = connection.execute("PRAGMA quick_check").fetchone()
                if check is None or check[0] != "ok":
                    raise AlertPersistenceError("database_corrupt")
                if not existed:
                    connection.execute("BEGIN EXCLUSIVE")
                    connection.execute(_CREATE_METADATA)
                    connection.execute(_CREATE_CANDIDATES)
                    connection.execute(
                        "INSERT INTO repository_metadata(key, value) VALUES (?, ?)",
                        ("schema_identity", ALERT_REPOSITORY_SCHEMA_IDENTITY),
                    )
                    connection.execute(f"PRAGMA user_version = {ALERT_REPOSITORY_SCHEMA_VERSION}")
                    connection.commit()
                self._verify_schema(connection)
            finally:
                connection.close()
        except AlertPersistenceError:
            raise
        except (OSError, sqlite3.DatabaseError):
            raise AlertPersistenceError("database_corrupt") from None

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            metadata = connection.execute(
                "SELECT value FROM repository_metadata WHERE key = ?", ("schema_identity",)
            ).fetchone()
            metadata_count = connection.execute(
                "SELECT COUNT(*) FROM repository_metadata"
            ).fetchone()[0]
            metadata_columns = tuple(
                (row[1], row[2], row[3], row[5])
                for row in connection.execute("PRAGMA table_info(repository_metadata)")
            )
            candidate_columns = tuple(
                (row[1], row[2], row[3], row[5])
                for row in connection.execute("PRAGMA table_info(alert_candidates)")
            )
        except sqlite3.Error:
            raise AlertPersistenceError("database_schema_mismatch") from None
        if (
            version != ALERT_REPOSITORY_SCHEMA_VERSION
            or metadata is None
            or metadata[0] != ALERT_REPOSITORY_SCHEMA_IDENTITY
            or metadata_count != 1
            or metadata_columns != _EXPECTED_METADATA_COLUMNS
            or candidate_columns != _EXPECTED_CANDIDATE_COLUMNS
        ):
            raise AlertPersistenceError("database_schema_mismatch")

    def insert(self, candidate: AlertCandidate) -> AlertInsertResult:
        """Atomically insert, return the first row on retry, or reject a content conflict."""
        if type(candidate) is not AlertCandidate:
            raise AlertPersistenceError("alert_candidate_type_invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                f"SELECT {_COLUMN_LIST} FROM alert_candidates WHERE alert_candidate_id = ?",
                (candidate.alert_candidate_id,),
            ).fetchone()
            if row is None:
                connection.execute(
                    f"INSERT INTO alert_candidates ({_COLUMN_LIST}) VALUES ({_PLACEHOLDERS})",
                    _values(candidate),
                )
                connection.commit()
                return AlertInsertResult("created", "alert_candidate_created", candidate)
            stored = _candidate(row)
            if not _same_detection_evidence(stored, candidate):
                raise AlertPersistenceError("alert_candidate_identity_conflict")
            connection.commit()
            return AlertInsertResult("existing", "alert_candidate_already_exists", stored)
        except AlertPersistenceError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            if getattr(exc, "sqlite_errorcode", None) in {
                sqlite3.SQLITE_BUSY,
                sqlite3.SQLITE_LOCKED,
            }:
                raise AlertPersistenceError("database_busy") from None
            raise AlertPersistenceError("database_write_failed") from None
        finally:
            connection.close()

    def get(self, alert_candidate_id: str) -> AlertCandidate | None:
        """Retrieve one candidate using a bounded canonical identifier."""
        if type(alert_candidate_id) is not str or len(alert_candidate_id) > 128:
            raise AlertPersistenceError("alert_candidate_id_invalid")
        connection = self._connect()
        try:
            row = connection.execute(
                f"SELECT {_COLUMN_LIST} FROM alert_candidates WHERE alert_candidate_id = ?",
                (alert_candidate_id,),
            ).fetchone()
            return None if row is None else _candidate(row)
        except AlertPersistenceError:
            raise
        except sqlite3.Error:
            raise AlertPersistenceError("database_read_failed") from None
        finally:
            connection.close()

    def list(self, *, limit: int = 50, offset: int = 0) -> tuple[AlertCandidate, ...]:
        """Return a bounded page in deterministic first-created order."""
        if type(limit) is not int or not 1 <= limit <= MAX_ALERT_LIST_LIMIT:
            raise AlertPersistenceError("list_limit_invalid")
        if type(offset) is not int or not 0 <= offset <= MAX_ALERT_LIST_OFFSET:
            raise AlertPersistenceError("list_offset_invalid")
        connection = self._connect()
        try:
            rows = connection.execute(
                f"SELECT {_COLUMN_LIST} FROM alert_candidates "
                "ORDER BY created_at ASC, alert_candidate_id ASC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return tuple(_candidate(row) for row in rows)
        except AlertPersistenceError:
            raise
        except sqlite3.Error:
            raise AlertPersistenceError("database_read_failed") from None
        finally:
            connection.close()
