"""Bounded local security-audit persistence for the analyst boundary."""

from __future__ import annotations

import sqlite3
import stat
import uuid
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

from threatfusion.db.alert_repository import SQLITE_BUSY_TIMEOUT_MS
from threatfusion.schemas.analyst_state import valid_actor_id

AUDIT_EVENT_SCHEMA_VERSION = "analyst_security_audit_event_v1"
AUDIT_REPOSITORY_SCHEMA_VERSION = 1
AUDIT_REPOSITORY_SCHEMA_IDENTITY = "analyst_security_audit_sqlite_v1"
MAX_AUDIT_EVENTS = 100_000
MAX_AUDIT_LIST_LIMIT = 100

EVENT_TYPES = frozenset(
    {
        "authentication_rejected",
        "authorization_rejected",
        "request_rejected",
        "request_admitted",
        "request_completed",
        "internal_failure",
    }
)

_EVENT_DISPOSITIONS = frozenset(
    {
        ("authentication_rejected", "authentication", "rejected", "authentication_failed"),
        ("authorization_rejected", "authorization", "rejected", "forbidden"),
        ("request_rejected", "admission", "rejected", "request_invalid"),
        ("request_admitted", "admission", "admitted", "request_admitted"),
        ("request_completed", "completion", "completed", "request_completed"),
        ("internal_failure", "internal", "failed", "internal_error"),
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
    event_type TEXT NOT NULL CHECK (event_type IN ({", ".join(repr(v) for v in sorted(EVENT_TYPES))})),
    processing_stage TEXT NOT NULL
        CHECK (processing_stage IN ({", ".join(repr(v) for v in sorted(PROCESSING_STAGES))})),
    outcome TEXT NOT NULL CHECK (outcome IN ({", ".join(repr(v) for v in sorted(OUTCOMES))})),
    reason_code TEXT NOT NULL CHECK (reason_code IN ({", ".join(repr(v) for v in sorted(REASON_CODES))})),
    actor_id TEXT CHECK (actor_id IS NULL OR (length(actor_id) >= 1 AND length(actor_id) <= 64)),
    credential_sha256 TEXT
        CHECK (credential_sha256 IS NULL OR
               (length(credential_sha256) = 64
                AND credential_sha256 NOT GLOB '*[^0-9a-f]*')),
    request_route TEXT CHECK (request_route IS NULL OR length(request_route) <= 256),
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
    ("actor_id", "TEXT", 0, 0),
    ("credential_sha256", "TEXT", 0, 0),
    ("request_route", "TEXT", 0, 0),
    ("body_sha256", "TEXT", 0, 0),
)
_EXPECTED_INDEXES = {"audit_events_time_id_uq": (True, ("event_time", "audit_event_id"))}


class AnalystSecurityAuditError(RuntimeError):
    """Sanitized failure without SQL, paths, exceptions, or submitted values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return "<AnalystSecurityAuditError>"


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
class AnalystSecurityAuditEvent:
    """Immutable, privacy-minimized internal v1 audit event."""

    schema_version: str
    audit_event_id: str
    event_time: datetime
    correlation_id: str | None
    event_type: str
    processing_stage: str
    outcome: str
    reason_code: str
    actor_id: str | None = None
    credential_sha256: str | None = None
    request_route: str | None = None
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
            or (self.actor_id is not None and not valid_actor_id(self.actor_id))
            or (
                self.request_route is not None
                and not (
                    type(self.request_route) is str
                    and len(self.request_route.encode("utf-8")) <= 256
                )
            )
            or any(
                value is not None and not _is_sha256(value)
                for value in (
                    self.credential_sha256,
                    self.body_sha256,
                )
            )
        ):
            raise AnalystSecurityAuditError("audit_event_invalid")

    def __repr__(self) -> str:
        return "<AnalystSecurityAuditEvent>"


_COLUMNS = tuple(field.name for field in fields(AnalystSecurityAuditEvent))
_COLUMN_LIST = ", ".join(_COLUMNS)
_PLACEHOLDERS = ", ".join("?" for _ in _COLUMNS)


def create_analyst_security_audit_event(
    *,
    event_type: str,
    processing_stage: str,
    outcome: str,
    reason_code: str,
    correlation_id: str | None = None,
    actor_id: str | None = None,
    credential_sha256: str | None = None,
    request_route: str | None = None,
    body_sha256: str | None = None,
    trusted_now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> AnalystSecurityAuditEvent:
    """Create one event with a server UUID and trusted UTC clock reading."""
    if not callable(trusted_now):
        raise AnalystSecurityAuditError("trusted_time_unavailable")
    try:
        event_time = trusted_now()
    except Exception:
        raise AnalystSecurityAuditError("trusted_time_unavailable") from None
    if not _is_utc(event_time):
        raise AnalystSecurityAuditError("trusted_time_unavailable")
    return AnalystSecurityAuditEvent(
        schema_version=AUDIT_EVENT_SCHEMA_VERSION,
        audit_event_id=str(uuid.uuid4()),
        event_time=event_time,
        correlation_id=correlation_id,
        event_type=event_type,
        processing_stage=processing_stage,
        outcome=outcome,
        reason_code=reason_code,
        actor_id=actor_id,
        credential_sha256=credential_sha256,
        request_route=request_route,
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
            raise AnalystSecurityAuditError("audit_result_invalid")

    def __repr__(self) -> str:
        return "<AuditAppendResult>"


def _sql_shape(value: str) -> str:
    return " ".join(value.split())


def _values(event: AnalystSecurityAuditEvent) -> tuple[object, ...]:
    return tuple(
        value.isoformat() if type(value) is datetime else value
        for value in (getattr(event, column) for column in _COLUMNS)
    )


def _event(row: sqlite3.Row) -> AnalystSecurityAuditEvent:
    try:
        payload = dict(row)
        payload["event_time"] = datetime.fromisoformat(payload["event_time"])
        return AnalystSecurityAuditEvent(**payload)
    except (AnalystSecurityAuditError, TypeError, ValueError):
        raise AnalystSecurityAuditError("audit_record_invalid") from None


def _equivalent(stored: AnalystSecurityAuditEvent, attempted: AnalystSecurityAuditEvent) -> bool:
    excluded = {"event_time", "correlation_id"}
    return all(
        getattr(stored, column) == getattr(attempted, column)
        for column in _COLUMNS
        if column not in excluded
    )


def _database_error(exc: sqlite3.Error, *, write: bool) -> AnalystSecurityAuditError:
    if getattr(exc, "sqlite_errorcode", None) in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        return AnalystSecurityAuditError("audit_busy")
    return AnalystSecurityAuditError("audit_write_failed" if write else "audit_read_failed")


class AnalystSecurityAuditRepository:
    """Append-only application API over one bounded local SQLite audit table."""

    def __init__(self, database_path: Path, *, _capacity_limit: int = MAX_AUDIT_EVENTS) -> None:
        if (
            not isinstance(database_path, Path)
            or type(_capacity_limit) is not int
            or not 1 <= _capacity_limit <= MAX_AUDIT_EVENTS
        ):
            raise AnalystSecurityAuditError("audit_configuration_invalid")
        self._database_path = database_path
        self._capacity_limit = _capacity_limit
        self._initialize()

    def __repr__(self) -> str:
        return "<AnalystSecurityAuditRepository>"

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
            raise AnalystSecurityAuditError("audit_unavailable") from None

    def _initialize(self) -> None:
        try:
            try:
                information = self._database_path.lstat()
                existed = True
                if not stat.S_ISREG(information.st_mode) or information.st_size == 0:
                    raise AnalystSecurityAuditError("audit_corrupt")
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
        except AnalystSecurityAuditError:
            raise
        except (OSError, sqlite3.DatabaseError):
            raise AnalystSecurityAuditError("audit_corrupt") from None

    @staticmethod
    def _verify_integrity(connection: sqlite3.Connection) -> None:
        try:
            result = connection.execute("PRAGMA quick_check").fetchone()
        except sqlite3.Error:
            raise AnalystSecurityAuditError("audit_corrupt") from None
        if result is None or result[0] != "ok":
            raise AnalystSecurityAuditError("audit_integrity_failed")

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
            raise AnalystSecurityAuditError("audit_schema_mismatch") from None
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
            raise AnalystSecurityAuditError("audit_schema_mismatch")

    def append(self, event: AnalystSecurityAuditEvent) -> AuditAppendResult:
        if type(event) is not AnalystSecurityAuditEvent:
            raise AnalystSecurityAuditError("audit_event_type_invalid")
        try:
            validated = AnalystSecurityAuditEvent(
                **{column: getattr(event, column) for column in _COLUMNS}
            )
        except (AttributeError, AnalystSecurityAuditError, TypeError):
            raise AnalystSecurityAuditError("audit_event_invalid") from None
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
                    raise AnalystSecurityAuditError("audit_event_identity_conflict")
                connection.commit()
                return AuditAppendResult(
                    "existing", stored.audit_event_id, "available", "audit_event_existing"
                )
            count = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            if type(count) is not int or count < 0:
                raise AnalystSecurityAuditError("audit_record_invalid")
            if count >= self._capacity_limit:
                raise AnalystSecurityAuditError("audit_capacity_reached")
            connection.execute(
                f"INSERT INTO audit_events ({_COLUMN_LIST}) VALUES ({_PLACEHOLDERS})",
                _values(validated),
            )
            connection.commit()
            return AuditAppendResult(
                "created", validated.audit_event_id, "available", "audit_event_created"
            )
        except AnalystSecurityAuditError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise _database_error(exc, write=True) from None
        finally:
            connection.close()

    def list(self, *, limit: int = 50) -> tuple[AnalystSecurityAuditEvent, ...]:
        if type(limit) is not int or not 1 <= limit <= MAX_AUDIT_LIST_LIMIT:
            raise AnalystSecurityAuditError("audit_list_limit_invalid")
        connection = self._connect()
        try:
            rows = connection.execute(
                f"SELECT {_COLUMN_LIST} FROM audit_events "
                "ORDER BY event_time ASC, audit_event_id ASC LIMIT ?",
                (limit,),
            ).fetchall()
            return tuple(_event(row) for row in rows)
        except AnalystSecurityAuditError:
            raise
        except sqlite3.Error as exc:
            raise _database_error(exc, write=False) from None
        finally:
            connection.close()
