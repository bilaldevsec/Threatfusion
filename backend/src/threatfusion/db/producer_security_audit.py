"""Bounded local security-audit persistence for the producer boundary.

The contract accepts only fixed internal evidence. It deliberately has no message,
exception, payload, endpoint, feature, prediction, label, or filesystem field.
"""

from __future__ import annotations

import sqlite3
import stat
import uuid
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

from threatfusion.api.producer_admission import (
    REGISTERED_UNSW_PRODUCER_ID,
    REGISTERED_UNSW_SOURCE_CONTRACT,
)
from threatfusion.db.alert_repository import SQLITE_BUSY_TIMEOUT_MS

AUDIT_EVENT_SCHEMA_VERSION = "producer_security_audit_event_v1"
AUDIT_REPOSITORY_SCHEMA_VERSION = 1
AUDIT_REPOSITORY_SCHEMA_IDENTITY = "producer_security_audit_sqlite_v1"
MAX_AUDIT_EVENTS = 100_000
MAX_AUDIT_LIST_LIMIT = 100

EVENT_TYPES = frozenset(
    {
        "authentication_rejected",
        "producer_admission_rejected",
        "rate_limited",
        "server_busy",
        "request_admitted",
        "replay_in_progress",
        "replay_conflict",
        "replay_outcome_unknown",
        "request_completed",
        "internal_failure",
    }
)

_EVENT_DISPOSITIONS = frozenset(
    {
        ("authentication_rejected", "authentication", "rejected", "authentication_failed"),
        ("authentication_rejected", "authentication", "rejected", "credential_disabled"),
        ("authentication_rejected", "authentication", "rejected", "credential_revoked"),
        (
            "authentication_rejected",
            "authentication",
            "rejected",
            "credential_not_yet_valid",
        ),
        ("authentication_rejected", "authentication", "rejected", "credential_expired"),
        (
            "producer_admission_rejected",
            "admission",
            "rejected",
            "producer_mismatch",
        ),
        (
            "producer_admission_rejected",
            "admission",
            "rejected",
            "source_contract_denied",
        ),
        ("producer_admission_rejected", "admission", "rejected", "invalid_request"),
        (
            "producer_admission_rejected",
            "admission",
            "rejected",
            "request_time_invalid",
        ),
        (
            "producer_admission_rejected",
            "admission",
            "rejected",
            "request_too_large",
        ),
        ("producer_admission_rejected", "admission", "rejected", "body_incomplete"),
        ("rate_limited", "rate_control", "rejected", "rate_limited"),
        ("server_busy", "concurrency_control", "rejected", "server_busy"),
        ("request_admitted", "admission", "admitted", "request_admitted"),
        ("replay_in_progress", "replay", "deferred", "request_in_progress"),
        ("replay_conflict", "replay", "rejected", "request_replay_rejected"),
        ("replay_outcome_unknown", "replay", "unknown", "outcome_unknown"),
        ("request_completed", "completion", "completed", "request_completed"),
        ("internal_failure", "internal", "failed", "internal_error"),
        ("internal_failure", "internal", "failed", "registry_invalid"),
        ("internal_failure", "internal", "failed", "clock_unavailable"),
        ("internal_failure", "processing", "failed", "request_timeout"),
        ("internal_failure", "processing", "failed", "processing_timeout"),
        ("internal_failure", "audit", "failed", "audit_unavailable"),
    }
)
PROCESSING_STAGES = frozenset(item[1] for item in _EVENT_DISPOSITIONS)
OUTCOMES = frozenset(item[2] for item in _EVENT_DISPOSITIONS)
REASON_CODES = frozenset(item[3] for item in _EVENT_DISPOSITIONS)
_DISPOSITION_CHECK = " OR ".join(
    "(event_type = {0!r} AND processing_stage = {1!r} "
    "AND outcome = {2!r} AND reason_code = {3!r})".format(*item)
    for item in sorted(_EVENT_DISPOSITIONS)
)

_OPTIONAL_DIGEST_FIELDS = ("credential_sha256", "request_id_sha256", "body_sha256")
_CREATE_METADATA = """
CREATE TABLE audit_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT
"""
_CREATE_EVENTS = f"""
CREATE TABLE audit_events (
    schema_version TEXT NOT NULL CHECK (schema_version = '{AUDIT_EVENT_SCHEMA_VERSION}'),
    audit_event_id TEXT PRIMARY KEY NOT NULL CHECK (length(audit_event_id) = 36),
    event_time TEXT NOT NULL CHECK (length(event_time) BETWEEN 25 AND 32),
    correlation_id TEXT CHECK (correlation_id IS NULL OR length(correlation_id) = 36),
    event_type TEXT NOT NULL CHECK (event_type IN ({', '.join(repr(v) for v in sorted(EVENT_TYPES))})),
    processing_stage TEXT NOT NULL
        CHECK (processing_stage IN ({', '.join(repr(v) for v in sorted(PROCESSING_STAGES))})),
    outcome TEXT NOT NULL CHECK (outcome IN ({', '.join(repr(v) for v in sorted(OUTCOMES))})),
    reason_code TEXT NOT NULL CHECK (reason_code IN ({', '.join(repr(v) for v in sorted(REASON_CODES))})),
    producer_id TEXT CHECK (producer_id IS NULL OR producer_id = '{REGISTERED_UNSW_PRODUCER_ID}'),
    source_contract_id TEXT
        CHECK (source_contract_id IS NULL OR source_contract_id = '{REGISTERED_UNSW_SOURCE_CONTRACT}'),
    credential_sha256 TEXT
        CHECK (credential_sha256 IS NULL OR
               (length(credential_sha256) = 64
                AND credential_sha256 NOT GLOB '*[^0-9a-f]*')),
    request_id_sha256 TEXT
        CHECK (request_id_sha256 IS NULL OR
               (length(request_id_sha256) = 64
                AND request_id_sha256 NOT GLOB '*[^0-9a-f]*')),
    body_sha256 TEXT
        CHECK (body_sha256 IS NULL OR
               (length(body_sha256) = 64 AND body_sha256 NOT GLOB '*[^0-9a-f]*')),
    CHECK ({_DISPOSITION_CHECK})
) STRICT
"""
_CREATE_ORDER_INDEX = """
CREATE UNIQUE INDEX audit_events_time_id_uq ON audit_events(event_time, audit_event_id)
"""
_EXPECTED_METADATA_COLUMNS = (("key", "TEXT", 1, 1), ("value", "TEXT", 1, 0))
_EXPECTED_EVENT_COLUMNS = (
    ("schema_version", "TEXT", 1, 0),
    ("audit_event_id", "TEXT", 1, 1),
    ("event_time", "TEXT", 1, 0),
    ("correlation_id", "TEXT", 0, 0),
    ("event_type", "TEXT", 1, 0),
    ("processing_stage", "TEXT", 1, 0),
    ("outcome", "TEXT", 1, 0),
    ("reason_code", "TEXT", 1, 0),
    ("producer_id", "TEXT", 0, 0),
    ("source_contract_id", "TEXT", 0, 0),
    ("credential_sha256", "TEXT", 0, 0),
    ("request_id_sha256", "TEXT", 0, 0),
    ("body_sha256", "TEXT", 0, 0),
)
_EXPECTED_INDEXES = {"audit_events_time_id_uq": (True, ("event_time", "audit_event_id"))}


class ProducerSecurityAuditError(RuntimeError):
    """Sanitized failure without SQL, paths, exceptions, or submitted values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return "<ProducerSecurityAuditError>"


def _is_uuid4(value: object) -> bool:
    if type(value) is not str or len(value) != 36:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_utc(value: object) -> bool:
    return type(value) is datetime and value.tzinfo is UTC


@dataclass(frozen=True, slots=True, repr=False)
class ProducerSecurityAuditEvent:
    """Immutable, privacy-minimized internal v1 audit event."""

    schema_version: str
    audit_event_id: str
    event_time: datetime
    correlation_id: str | None
    event_type: str
    processing_stage: str
    outcome: str
    reason_code: str
    producer_id: str | None = None
    source_contract_id: str | None = None
    credential_sha256: str | None = None
    request_id_sha256: str | None = None
    body_sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            self.schema_version != AUDIT_EVENT_SCHEMA_VERSION
            or not _is_uuid4(self.audit_event_id)
            or not _is_utc(self.event_time)
            or (self.correlation_id is not None and not _is_uuid4(self.correlation_id))
            or type(self.event_type) is not str
            or self.event_type not in EVENT_TYPES
            or type(self.processing_stage) is not str
            or self.processing_stage not in PROCESSING_STAGES
            or type(self.outcome) is not str
            or self.outcome not in OUTCOMES
            or type(self.reason_code) is not str
            or self.reason_code not in REASON_CODES
            or (
                self.event_type,
                self.processing_stage,
                self.outcome,
                self.reason_code,
            )
            not in _EVENT_DISPOSITIONS
            or self.producer_id not in {None, REGISTERED_UNSW_PRODUCER_ID}
            or self.source_contract_id not in {None, REGISTERED_UNSW_SOURCE_CONTRACT}
            or any(
                value is not None and not _is_sha256(value)
                for value in (
                    self.credential_sha256,
                    self.request_id_sha256,
                    self.body_sha256,
                )
            )
        ):
            raise ProducerSecurityAuditError("audit_event_invalid")

    def __repr__(self) -> str:
        return "<ProducerSecurityAuditEvent>"


_COLUMNS = tuple(field.name for field in fields(ProducerSecurityAuditEvent))
_COLUMN_LIST = ", ".join(_COLUMNS)
_PLACEHOLDERS = ", ".join("?" for _ in _COLUMNS)


def create_producer_security_audit_event(
    *,
    event_type: str,
    processing_stage: str,
    outcome: str,
    reason_code: str,
    correlation_id: str | None = None,
    producer_id: str | None = None,
    source_contract_id: str | None = None,
    credential_sha256: str | None = None,
    request_id_sha256: str | None = None,
    body_sha256: str | None = None,
    trusted_now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ProducerSecurityAuditEvent:
    """Create one event with a server UUID and trusted UTC clock reading."""
    if not callable(trusted_now):
        raise ProducerSecurityAuditError("trusted_time_unavailable")
    try:
        event_time = trusted_now()
    except Exception:
        raise ProducerSecurityAuditError("trusted_time_unavailable") from None
    if not _is_utc(event_time):
        raise ProducerSecurityAuditError("trusted_time_unavailable")
    return ProducerSecurityAuditEvent(
        schema_version=AUDIT_EVENT_SCHEMA_VERSION,
        audit_event_id=str(uuid.uuid4()),
        event_time=event_time,
        correlation_id=correlation_id,
        event_type=event_type,
        processing_stage=processing_stage,
        outcome=outcome,
        reason_code=reason_code,
        producer_id=producer_id,
        source_contract_id=source_contract_id,
        credential_sha256=credential_sha256,
        request_id_sha256=request_id_sha256,
        body_sha256=body_sha256,
    )


@dataclass(frozen=True, slots=True, repr=False)
class AuditAppendResult:
    """Sanitized result of an atomic append or identical retry."""

    disposition: str
    audit_event_id: str
    status: str
    reason: str

    def __post_init__(self) -> None:
        expected = {
            "created": ("available", "audit_event_created"),
            "existing": ("available", "audit_event_existing"),
        }
        if (
            type(self.disposition) is not str
            or self.disposition not in expected
            or not _is_uuid4(self.audit_event_id)
            or (self.status, self.reason) != expected[self.disposition]
        ):
            raise ProducerSecurityAuditError("audit_result_invalid")

    def __repr__(self) -> str:
        return "<AuditAppendResult>"


def _sql_shape(value: str) -> str:
    return " ".join(value.split())


def _values(event: ProducerSecurityAuditEvent) -> tuple[object, ...]:
    return tuple(
        value.isoformat() if type(value) is datetime else value
        for value in (getattr(event, column) for column in _COLUMNS)
    )


def _event(row: sqlite3.Row) -> ProducerSecurityAuditEvent:
    try:
        payload = dict(row)
        payload["event_time"] = datetime.fromisoformat(payload["event_time"])
        return ProducerSecurityAuditEvent(**payload)
    except (ProducerSecurityAuditError, TypeError, ValueError):
        raise ProducerSecurityAuditError("audit_record_invalid") from None


def _equivalent(stored: ProducerSecurityAuditEvent, attempted: ProducerSecurityAuditEvent) -> bool:
    # The first trusted time and handling correlation are attempt metadata. A durable event ID
    # names the logical audit fact, so retries may reconstruct those two values while every
    # security-relevant classification and canonical digest must remain identical.
    excluded = {"event_time", "correlation_id"}
    return all(
        getattr(stored, column) == getattr(attempted, column)
        for column in _COLUMNS
        if column not in excluded
    )


def _database_error(exc: sqlite3.Error, *, write: bool) -> ProducerSecurityAuditError:
    if getattr(exc, "sqlite_errorcode", None) in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        return ProducerSecurityAuditError("audit_busy")
    return ProducerSecurityAuditError("audit_write_failed" if write else "audit_read_failed")


class ProducerSecurityAuditRepository:
    """Append-only application API over one bounded local SQLite audit table."""

    def __init__(self, database_path: Path, *, _capacity_limit: int = MAX_AUDIT_EVENTS) -> None:
        if (
            not isinstance(database_path, Path)
            or type(_capacity_limit) is not int
            or not 1 <= _capacity_limit <= MAX_AUDIT_EVENTS
        ):
            raise ProducerSecurityAuditError("audit_configuration_invalid")
        self._database_path = database_path
        self._capacity_limit = _capacity_limit
        self._initialize()

    def __repr__(self) -> str:
        return "<ProducerSecurityAuditRepository>"

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self._database_path,
                timeout=SQLITE_BUSY_TIMEOUT_MS / 1000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
            return connection
        except sqlite3.Error:
            raise ProducerSecurityAuditError("audit_unavailable") from None

    def _initialize(self) -> None:
        try:
            try:
                information = self._database_path.lstat()
                existed = True
                if not stat.S_ISREG(information.st_mode) or information.st_size == 0:
                    raise ProducerSecurityAuditError("audit_corrupt")
            except FileNotFoundError:
                existed = False
                self._database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = self._connect()
            try:
                self._verify_integrity(connection)
                if not existed:
                    connection.execute("BEGIN EXCLUSIVE")
                    connection.execute(_CREATE_METADATA)
                    connection.execute(_CREATE_EVENTS)
                    connection.execute(_CREATE_ORDER_INDEX)
                    connection.execute(
                        "INSERT INTO audit_metadata(key, value) VALUES (?, ?)",
                        ("schema_identity", AUDIT_REPOSITORY_SCHEMA_IDENTITY),
                    )
                    connection.execute(f"PRAGMA user_version = {AUDIT_REPOSITORY_SCHEMA_VERSION}")
                    connection.commit()
                self._verify_schema(connection)
            finally:
                connection.close()
        except ProducerSecurityAuditError:
            raise
        except (OSError, sqlite3.DatabaseError):
            raise ProducerSecurityAuditError("audit_corrupt") from None

    @staticmethod
    def _verify_integrity(connection: sqlite3.Connection) -> None:
        try:
            result = connection.execute("PRAGMA quick_check").fetchone()
        except sqlite3.Error:
            raise ProducerSecurityAuditError("audit_corrupt") from None
        if result is None or result[0] != "ok":
            raise ProducerSecurityAuditError("audit_integrity_failed")

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            metadata = dict(connection.execute("SELECT key, value FROM audit_metadata"))
            metadata_columns = tuple(
                (row[1], row[2], row[3], row[5])
                for row in connection.execute("PRAGMA table_info(audit_metadata)")
            )
            event_columns = tuple(
                (row[1], row[2], row[3], row[5])
                for row in connection.execute("PRAGMA table_info(audit_events)")
            )
            tables = {
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
                if not row[0].startswith("sqlite_")
            }
            table_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'"
            ).fetchone()
            metadata_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'audit_metadata'"
            ).fetchone()
            indexes = {}
            for row in connection.execute("PRAGMA index_list(audit_events)"):
                name = row[1]
                if name.startswith("sqlite_autoindex"):
                    continue
                columns = tuple(
                    item[2] for item in connection.execute(f'PRAGMA index_info("{name}")')
                )
                indexes[name] = (bool(row[2]), columns)
            index_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'index' "
                "AND name = 'audit_events_time_id_uq'"
            ).fetchone()
        except sqlite3.Error:
            raise ProducerSecurityAuditError("audit_schema_mismatch") from None
        if (
            version != AUDIT_REPOSITORY_SCHEMA_VERSION
            or metadata != {"schema_identity": AUDIT_REPOSITORY_SCHEMA_IDENTITY}
            or metadata_columns != _EXPECTED_METADATA_COLUMNS
            or event_columns != _EXPECTED_EVENT_COLUMNS
            or tables != {"audit_metadata", "audit_events"}
            or table_sql is None
            or metadata_sql is None
            or index_sql is None
            or _sql_shape(table_sql[0]) != _sql_shape(_CREATE_EVENTS)
            or _sql_shape(metadata_sql[0]) != _sql_shape(_CREATE_METADATA)
            or indexes != _EXPECTED_INDEXES
            or _sql_shape(index_sql[0]) != _sql_shape(_CREATE_ORDER_INDEX)
        ):
            raise ProducerSecurityAuditError("audit_schema_mismatch")

    def append(self, event: ProducerSecurityAuditEvent) -> AuditAppendResult:
        """Atomically append, accept an equivalent retry, or fail closed."""
        if type(event) is not ProducerSecurityAuditEvent:
            raise ProducerSecurityAuditError("audit_event_type_invalid")
        try:
            validated = ProducerSecurityAuditEvent(
                **{column: getattr(event, column) for column in _COLUMNS}
            )
        except (AttributeError, ProducerSecurityAuditError, TypeError):
            raise ProducerSecurityAuditError("audit_event_invalid") from None
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                f"SELECT {_COLUMN_LIST} FROM audit_events WHERE audit_event_id = ?",
                (validated.audit_event_id,),
            ).fetchone()
            if row is not None:
                stored = _event(row)
                if not _equivalent(stored, validated):
                    raise ProducerSecurityAuditError("audit_event_identity_conflict")
                connection.commit()
                return AuditAppendResult(
                    "existing", stored.audit_event_id, "available", "audit_event_existing"
                )
            count = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            if type(count) is not int or count < 0:
                raise ProducerSecurityAuditError("audit_record_invalid")
            if count >= self._capacity_limit:
                raise ProducerSecurityAuditError("audit_capacity_reached")
            connection.execute(
                f"INSERT INTO audit_events ({_COLUMN_LIST}) VALUES ({_PLACEHOLDERS})",
                _values(validated),
            )
            connection.commit()
            return AuditAppendResult(
                "created", validated.audit_event_id, "available", "audit_event_created"
            )
        except ProducerSecurityAuditError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise _database_error(exc, write=True) from None
        finally:
            connection.close()

    def list(self, *, limit: int = 50) -> tuple[ProducerSecurityAuditEvent, ...]:
        """Return at most 100 events in stable trusted-time/event-ID order."""
        if type(limit) is not int or not 1 <= limit <= MAX_AUDIT_LIST_LIMIT:
            raise ProducerSecurityAuditError("audit_list_limit_invalid")
        connection = self._connect()
        try:
            rows = connection.execute(
                f"SELECT {_COLUMN_LIST} FROM audit_events "
                "ORDER BY event_time ASC, audit_event_id ASC LIMIT ?",
                (limit,),
            ).fetchall()
            return tuple(_event(row) for row in rows)
        except ProducerSecurityAuditError:
            raise
        except sqlite3.Error as exc:
            raise _database_error(exc, write=False) from None
        finally:
            connection.close()
