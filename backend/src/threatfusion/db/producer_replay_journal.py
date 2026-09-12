"""Durable three-state replay journal for validated producer admission records."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sqlite3
import stat
import struct
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from threatfusion.api.producer_admission import (
    MAX_RECORDS,
    MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_BYTES,
    ProducerAdmissionError,
    ValidatedAdmissionRecord,
    decode_producer_response,
)
from threatfusion.db.alert_repository import SQLITE_BUSY_TIMEOUT_MS

REPLAY_JOURNAL_SCHEMA_VERSION = 1
REPLAY_JOURNAL_SCHEMA_IDENTITY = "producer_replay_journal_sqlite_v1"
REPLAY_RECORD_SCHEMA_VERSION = "producer_replay_journal_record_v1"
REPLAY_OWNER_MODEL = "explicit_single_service_generation_v1"

STATE_IN_PROGRESS = "in_progress"
STATE_COMPLETED = "completed"
STATE_OUTCOME_UNKNOWN = "outcome_unknown"

_CREATE_METADATA = """
CREATE TABLE journal_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT
"""
_CREATE_REQUESTS = f"""
CREATE TABLE replay_requests (
    record_schema_version TEXT NOT NULL
        CHECK (record_schema_version = '{REPLAY_RECORD_SCHEMA_VERSION}'),
    request_id TEXT PRIMARY KEY NOT NULL CHECK (length(request_id) = 36),
    producer_id TEXT NOT NULL CHECK (length(producer_id) BETWEEN 1 AND 128),
    credential_id TEXT NOT NULL
        CHECK (length(credential_id) = 64 AND credential_id NOT GLOB '*[^0-9a-f]*'),
    nonce_sha256 TEXT NOT NULL
        CHECK (length(nonce_sha256) = 64 AND nonce_sha256 NOT GLOB '*[^0-9a-f]*'),
    body_sha256 TEXT NOT NULL
        CHECK (length(body_sha256) = 64 AND body_sha256 NOT GLOB '*[^0-9a-f]*'),
    produced_at TEXT NOT NULL CHECK (length(produced_at) BETWEEN 20 AND 32),
    received_at TEXT NOT NULL CHECK (length(received_at) BETWEEN 20 AND 32),
    first_correlation_id TEXT NOT NULL CHECK (length(first_correlation_id) = 36),
    method TEXT NOT NULL CHECK (method = 'POST'),
    target TEXT NOT NULL CHECK (target = '/v1/ingest/unsw-registered'),
    content_type TEXT NOT NULL CHECK (content_type = 'application/json'),
    content_length INTEGER NOT NULL CHECK (content_length BETWEEN 1 AND {MAX_REQUEST_BODY_BYTES}),
    source_contract TEXT NOT NULL CHECK (length(source_contract) BETWEEN 1 AND 64),
    record_count INTEGER NOT NULL CHECK (record_count BETWEEN 1 AND {MAX_RECORDS}),
    ordered_records_sha256 TEXT NOT NULL
        CHECK (length(ordered_records_sha256) = 64
               AND ordered_records_sha256 NOT GLOB '*[^0-9a-f]*'),
    state TEXT NOT NULL CHECK (state IN ('{STATE_IN_PROGRESS}', '{STATE_COMPLETED}',
                                         '{STATE_OUTCOME_UNKNOWN}')),
    service_generation_id TEXT NOT NULL CHECK (length(service_generation_id) = 36),
    claim_token_sha256 TEXT
        CHECK (claim_token_sha256 IS NULL OR
               (length(claim_token_sha256) = 64
                AND claim_token_sha256 NOT GLOB '*[^0-9a-f]*')),
    claimed_at TEXT NOT NULL CHECK (length(claimed_at) BETWEEN 20 AND 32),
    completed_at TEXT CHECK (completed_at IS NULL OR length(completed_at) BETWEEN 20 AND 32),
    recovered_at TEXT CHECK (recovered_at IS NULL OR length(recovered_at) BETWEEN 20 AND 32),
    response_bytes BLOB CHECK (response_bytes IS NULL OR
                               length(response_bytes) BETWEEN 1 AND {MAX_RESPONSE_BYTES}),
    response_sha256 TEXT
        CHECK (response_sha256 IS NULL OR
               (length(response_sha256) = 64 AND response_sha256 NOT GLOB '*[^0-9a-f]*')),
    CHECK (
        (state = '{STATE_IN_PROGRESS}' AND claim_token_sha256 IS NOT NULL
         AND completed_at IS NULL AND recovered_at IS NULL
         AND response_bytes IS NULL AND response_sha256 IS NULL)
        OR
        (state = '{STATE_COMPLETED}' AND claim_token_sha256 IS NULL
         AND completed_at IS NOT NULL AND recovered_at IS NULL
         AND response_bytes IS NOT NULL AND response_sha256 IS NOT NULL)
        OR
        (state = '{STATE_OUTCOME_UNKNOWN}' AND claim_token_sha256 IS NULL
         AND completed_at IS NULL AND recovered_at IS NOT NULL
         AND response_bytes IS NULL AND response_sha256 IS NULL)
    )
) STRICT
"""
_CREATE_REQUEST_INDEX = """
CREATE UNIQUE INDEX replay_request_id_uq ON replay_requests(request_id)
"""
_CREATE_NONCE_INDEX = """
CREATE UNIQUE INDEX replay_nonce_sha256_uq ON replay_requests(nonce_sha256)
"""
_CREATE_RECOVERY_INDEX = """
CREATE INDEX replay_recovery_state_generation
ON replay_requests(state, service_generation_id)
"""

_EXPECTED_METADATA_COLUMNS = (("key", "TEXT", 1, 1), ("value", "TEXT", 1, 0))
_EXPECTED_REQUEST_COLUMNS = (
    ("record_schema_version", "TEXT", 1, 0),
    ("request_id", "TEXT", 1, 1),
    ("producer_id", "TEXT", 1, 0),
    ("credential_id", "TEXT", 1, 0),
    ("nonce_sha256", "TEXT", 1, 0),
    ("body_sha256", "TEXT", 1, 0),
    ("produced_at", "TEXT", 1, 0),
    ("received_at", "TEXT", 1, 0),
    ("first_correlation_id", "TEXT", 1, 0),
    ("method", "TEXT", 1, 0),
    ("target", "TEXT", 1, 0),
    ("content_type", "TEXT", 1, 0),
    ("content_length", "INTEGER", 1, 0),
    ("source_contract", "TEXT", 1, 0),
    ("record_count", "INTEGER", 1, 0),
    ("ordered_records_sha256", "TEXT", 1, 0),
    ("state", "TEXT", 1, 0),
    ("service_generation_id", "TEXT", 1, 0),
    ("claim_token_sha256", "TEXT", 0, 0),
    ("claimed_at", "TEXT", 1, 0),
    ("completed_at", "TEXT", 0, 0),
    ("recovered_at", "TEXT", 0, 0),
    ("response_bytes", "BLOB", 0, 0),
    ("response_sha256", "TEXT", 0, 0),
)
_EXPECTED_INDEXES = {
    "replay_request_id_uq": (True, ("request_id",)),
    "replay_nonce_sha256_uq": (True, ("nonce_sha256",)),
    "replay_recovery_state_generation": (False, ("state", "service_generation_id")),
}


class ProducerReplayJournalError(RuntimeError):
    """Sanitized journal failure without SQL, paths, tokens, or submitted values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return "<ProducerReplayJournalError>"


@dataclass(frozen=True, slots=True, repr=False)
class ReplayClaim:
    """Unpredictable proof that one service generation owns an active claim."""

    request_id: str
    service_generation_id: str
    ownership_token: str

    def __repr__(self) -> str:
        return "<ReplayClaim>"


@dataclass(frozen=True, slots=True, repr=False)
class ReplayClaimResult:
    """Sanitized claim disposition with a token only for the successful first claimant."""

    disposition: str
    reason: str
    claim: ReplayClaim | None
    cached_response: bytes | None
    first_correlation_id: str

    def __repr__(self) -> str:
        return "<ReplayClaimResult>"


def _is_uuid4(value: object) -> bool:
    if type(value) is not str or len(value) != 36:
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _is_utc(value: object) -> bool:
    return type(value) is datetime and value.tzinfo is UTC


def _is_ownership_token(value: object) -> bool:
    if type(value) is not str or len(value) != 43:
        return False
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, UnicodeError):
        return False
    return (
        len(decoded) == 32
        and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == value
    )


def _sql_shape(value: str) -> str:
    return " ".join(value.split())


def _ordered_records_sha256(record: ValidatedAdmissionRecord) -> str:
    digest = hashlib.sha256(b"threatfusion:producer-replay-records\0")
    for reference in record.records:
        digest.update(reference.source_member_sha256.encode("ascii"))
        digest.update(struct.pack(">Q", reference.row_number))
    return digest.hexdigest()


def _record_evidence(record: ValidatedAdmissionRecord) -> tuple[object, ...]:
    return (
        record.producer_id,
        record.credential_id,
        record.request_id,
        record.nonce_sha256,
        record.body_sha256,
        record.produced_at.isoformat(),
        record.method,
        record.target,
        record.content_type,
        record.content_length,
        record.source_contract,
        len(record.records),
        _ordered_records_sha256(record),
    )


def _row_evidence(row: sqlite3.Row) -> tuple[object, ...]:
    return (
        row["producer_id"],
        row["credential_id"],
        row["request_id"],
        row["nonce_sha256"],
        row["body_sha256"],
        row["produced_at"],
        row["method"],
        row["target"],
        row["content_type"],
        row["content_length"],
        row["source_contract"],
        row["record_count"],
        row["ordered_records_sha256"],
    )


def _database_error(exc: sqlite3.Error, *, write: bool) -> ProducerReplayJournalError:
    if getattr(exc, "sqlite_errorcode", None) in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        return ProducerReplayJournalError("journal_busy")
    return ProducerReplayJournalError("journal_write_failed" if write else "journal_read_failed")


class ProducerReplayJournal:
    """Single-node request journal; startup recovery requires external owner exclusivity."""

    def __init__(self, database_path: Path, *, service_generation_id: str) -> None:
        if not isinstance(database_path, Path) or not _is_uuid4(service_generation_id):
            raise ProducerReplayJournalError("journal_configuration_invalid")
        self._database_path = database_path
        self._service_generation_id = service_generation_id
        self._initialize()

    def __repr__(self) -> str:
        return "<ProducerReplayJournal>"

    @property
    def service_generation_id(self) -> str:
        return self._service_generation_id

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
            raise ProducerReplayJournalError("journal_unavailable") from None

    def _initialize(self) -> None:
        try:
            try:
                information = self._database_path.lstat()
                existed = True
                if not stat.S_ISREG(information.st_mode) or information.st_size == 0:
                    raise ProducerReplayJournalError("journal_corrupt")
            except FileNotFoundError:
                existed = False
                self._database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = self._connect()
            try:
                check = connection.execute("PRAGMA quick_check").fetchone()
                if check is None or check[0] != "ok":
                    raise ProducerReplayJournalError("journal_corrupt")
                if not existed:
                    connection.execute("BEGIN EXCLUSIVE")
                    connection.execute(_CREATE_METADATA)
                    connection.execute(_CREATE_REQUESTS)
                    connection.execute(_CREATE_REQUEST_INDEX)
                    connection.execute(_CREATE_NONCE_INDEX)
                    connection.execute(_CREATE_RECOVERY_INDEX)
                    connection.executemany(
                        "INSERT INTO journal_metadata(key, value) VALUES (?, ?)",
                        (
                            ("schema_identity", REPLAY_JOURNAL_SCHEMA_IDENTITY),
                            ("owner_model", REPLAY_OWNER_MODEL),
                        ),
                    )
                    connection.execute(f"PRAGMA user_version = {REPLAY_JOURNAL_SCHEMA_VERSION}")
                    connection.commit()
                self._verify_schema(connection)
            finally:
                connection.close()
        except ProducerReplayJournalError:
            raise
        except (OSError, sqlite3.DatabaseError):
            raise ProducerReplayJournalError("journal_corrupt") from None

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            metadata = dict(connection.execute("SELECT key, value FROM journal_metadata"))
            metadata_columns = tuple(
                (row[1], row[2], row[3], row[5])
                for row in connection.execute("PRAGMA table_info(journal_metadata)")
            )
            request_columns = tuple(
                (row[1], row[2], row[3], row[5])
                for row in connection.execute("PRAGMA table_info(replay_requests)")
            )
            table_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'replay_requests'"
            ).fetchone()
            metadata_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'journal_metadata'"
            ).fetchone()
            indexes = {}
            for row in connection.execute("PRAGMA index_list(replay_requests)"):
                name = row[1]
                if name.startswith("sqlite_autoindex"):
                    continue
                columns = tuple(
                    item[2] for item in connection.execute(f'PRAGMA index_info("{name}")')
                )
                indexes[name] = (bool(row[2]), columns)
            index_sql = {
                row[0]: _sql_shape(row[1])
                for row in connection.execute(
                    "SELECT name, sql FROM sqlite_master "
                    "WHERE type = 'index' AND tbl_name = 'replay_requests' AND sql IS NOT NULL"
                )
            }
        except sqlite3.Error:
            raise ProducerReplayJournalError("journal_schema_mismatch") from None
        expected_index_sql = {
            "replay_request_id_uq": _sql_shape(_CREATE_REQUEST_INDEX),
            "replay_nonce_sha256_uq": _sql_shape(_CREATE_NONCE_INDEX),
            "replay_recovery_state_generation": _sql_shape(_CREATE_RECOVERY_INDEX),
        }
        if (
            version != REPLAY_JOURNAL_SCHEMA_VERSION
            or metadata
            != {
                "schema_identity": REPLAY_JOURNAL_SCHEMA_IDENTITY,
                "owner_model": REPLAY_OWNER_MODEL,
            }
            or metadata_columns != _EXPECTED_METADATA_COLUMNS
            or request_columns != _EXPECTED_REQUEST_COLUMNS
            or table_sql is None
            or metadata_sql is None
            or _sql_shape(table_sql[0]) != _sql_shape(_CREATE_REQUESTS)
            or _sql_shape(metadata_sql[0]) != _sql_shape(_CREATE_METADATA)
            or indexes != _EXPECTED_INDEXES
            or index_sql != expected_index_sql
        ):
            raise ProducerReplayJournalError("journal_schema_mismatch")

    def _existing_rows(
        self, connection: sqlite3.Connection, record: ValidatedAdmissionRecord
    ) -> tuple[sqlite3.Row, ...]:
        return tuple(
            connection.execute(
                "SELECT * FROM replay_requests WHERE request_id = ? OR nonce_sha256 = ?",
                (record.request_id, record.nonce_sha256),
            )
        )

    def _completed_response(self, row: sqlite3.Row) -> bytes:
        response = row["response_bytes"]
        digest = row["response_sha256"]
        if type(response) is not bytes or type(digest) is not str:
            raise ProducerReplayJournalError("journal_record_invalid")
        actual = hashlib.sha256(response).hexdigest()
        if not hmac.compare_digest(actual, digest):
            raise ProducerReplayJournalError("journal_record_invalid")
        try:
            decoded = decode_producer_response(response)
        except ProducerAdmissionError:
            raise ProducerReplayJournalError("journal_record_invalid") from None
        if decoded.correlation_id != row["first_correlation_id"]:
            raise ProducerReplayJournalError("journal_record_invalid")
        return bytes(response)

    def claim(self, record: ValidatedAdmissionRecord, *, claimed_at: datetime) -> ReplayClaimResult:
        """Atomically claim a new request or return its terminal/current replay disposition."""
        if type(record) is not ValidatedAdmissionRecord or not _is_utc(claimed_at):
            raise ProducerReplayJournalError("journal_request_invalid")
        ownership_token = secrets.token_urlsafe(32)
        token_sha256 = hashlib.sha256(ownership_token.encode("ascii")).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = self._existing_rows(connection, record)
            if rows:
                if len(rows) != 1 or _row_evidence(rows[0]) != _record_evidence(record):
                    raise ProducerReplayJournalError("request_replay_rejected")
                row = rows[0]
                if row["state"] == STATE_IN_PROGRESS:
                    connection.commit()
                    return ReplayClaimResult(
                        STATE_IN_PROGRESS,
                        "request_in_progress",
                        None,
                        None,
                        row["first_correlation_id"],
                    )
                if row["state"] == STATE_COMPLETED:
                    response = self._completed_response(row)
                    connection.commit()
                    return ReplayClaimResult(
                        STATE_COMPLETED,
                        "request_completed",
                        None,
                        response,
                        row["first_correlation_id"],
                    )
                if row["state"] == STATE_OUTCOME_UNKNOWN:
                    connection.commit()
                    return ReplayClaimResult(
                        STATE_OUTCOME_UNKNOWN,
                        "outcome_unknown",
                        None,
                        None,
                        row["first_correlation_id"],
                    )
                raise ProducerReplayJournalError("journal_record_invalid")
            try:
                validated = ValidatedAdmissionRecord(
                    correlation_id=record.correlation_id,
                    producer_id=record.producer_id,
                    credential_id=record.credential_id,
                    request_id=record.request_id,
                    produced_at=record.produced_at,
                    received_at=record.received_at,
                    nonce_sha256=record.nonce_sha256,
                    body_sha256=record.body_sha256,
                    method=record.method,
                    target=record.target,
                    content_type=record.content_type,
                    content_length=record.content_length,
                    source_contract=record.source_contract,
                    records=record.records,
                )
            except ProducerAdmissionError:
                raise ProducerReplayJournalError("journal_request_invalid") from None
            evidence = _record_evidence(validated)
            connection.execute(
                """
                INSERT INTO replay_requests (
                    record_schema_version, request_id, producer_id, credential_id,
                    nonce_sha256, body_sha256, produced_at, received_at,
                    first_correlation_id, method, target, content_type, content_length,
                    source_contract, record_count, ordered_records_sha256, state,
                    service_generation_id, claim_token_sha256, claimed_at,
                    completed_at, recovered_at, response_bytes, response_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          NULL, NULL, NULL, NULL)
                """,
                (
                    REPLAY_RECORD_SCHEMA_VERSION,
                    validated.request_id,
                    validated.producer_id,
                    validated.credential_id,
                    validated.nonce_sha256,
                    validated.body_sha256,
                    validated.produced_at.isoformat(),
                    validated.received_at.isoformat(),
                    validated.correlation_id,
                    validated.method,
                    validated.target,
                    validated.content_type,
                    validated.content_length,
                    validated.source_contract,
                    evidence[-2],
                    evidence[-1],
                    STATE_IN_PROGRESS,
                    self._service_generation_id,
                    token_sha256,
                    claimed_at.isoformat(),
                ),
            )
            connection.commit()
            return ReplayClaimResult(
                STATE_IN_PROGRESS,
                "request_claimed",
                ReplayClaim(validated.request_id, self._service_generation_id, ownership_token),
                None,
                validated.correlation_id,
            )
        except ProducerReplayJournalError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise _database_error(exc, write=True) from None
        finally:
            connection.close()

    def complete(self, claim: ReplayClaim, response: bytes, *, completed_at: datetime) -> bytes:
        """Atomically persist a validated cached response for the exact active owner token."""
        if type(claim) is not ReplayClaim or not _is_utc(completed_at):
            raise ProducerReplayJournalError("claim_not_active")
        if (
            not _is_uuid4(claim.request_id)
            or not _is_uuid4(claim.service_generation_id)
            or not _is_ownership_token(claim.ownership_token)
        ):
            raise ProducerReplayJournalError("claim_not_active")
        if type(response) is not bytes or not 1 <= len(response) <= MAX_RESPONSE_BYTES:
            raise ProducerReplayJournalError("cached_response_invalid")
        try:
            decoded = decode_producer_response(response)
        except ProducerAdmissionError:
            raise ProducerReplayJournalError("cached_response_invalid") from None
        response_sha256 = hashlib.sha256(response).hexdigest()
        token_sha256 = hashlib.sha256(claim.ownership_token.encode("ascii")).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM replay_requests WHERE request_id = ?", (claim.request_id,)
            ).fetchone()
            if (
                row is None
                or row["state"] != STATE_IN_PROGRESS
                or claim.service_generation_id != self._service_generation_id
                or row["service_generation_id"] != self._service_generation_id
                or type(row["claim_token_sha256"]) is not str
                or not hmac.compare_digest(row["claim_token_sha256"], token_sha256)
                or decoded.correlation_id != row["first_correlation_id"]
            ):
                raise ProducerReplayJournalError("claim_not_active")
            connection.execute(
                """
                UPDATE replay_requests
                SET state = ?, claim_token_sha256 = NULL, completed_at = ?,
                    response_bytes = ?, response_sha256 = ?
                WHERE request_id = ?
                """,
                (
                    STATE_COMPLETED,
                    completed_at.isoformat(),
                    response,
                    response_sha256,
                    claim.request_id,
                ),
            )
            connection.commit()
            return bytes(response)
        except ProducerReplayJournalError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise _database_error(exc, write=True) from None
        finally:
            connection.close()

    def recover_abandoned_generation(
        self, *, abandoned_generation_id: str, recovered_at: datetime
    ) -> int:
        """Mark one externally proven-stopped generation unknown; never infer abandonment itself."""
        if (
            not _is_uuid4(abandoned_generation_id)
            or abandoned_generation_id == self._service_generation_id
            or not _is_utc(recovered_at)
        ):
            raise ProducerReplayJournalError("recovery_request_invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE replay_requests
                SET state = ?, claim_token_sha256 = NULL, recovered_at = ?
                WHERE state = ? AND service_generation_id = ?
                """,
                (
                    STATE_OUTCOME_UNKNOWN,
                    recovered_at.isoformat(),
                    STATE_IN_PROGRESS,
                    abandoned_generation_id,
                ),
            )
            changed = cursor.rowcount
            connection.commit()
            return changed
        except sqlite3.Error as exc:
            connection.rollback()
            raise _database_error(exc, write=True) from None
        finally:
            connection.close()
