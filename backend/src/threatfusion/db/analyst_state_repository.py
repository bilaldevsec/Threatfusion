"""Fail-closed SQLite persistence for the bounded per-alert analyst workflow."""

from __future__ import annotations

import sqlite3
import stat
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from threatfusion.db.alert_repository import (
    MAX_ALERT_LIST_LIMIT,
    MAX_ALERT_LIST_OFFSET,
    AlertCandidateRepository,
    AlertPersistenceError,
)
from threatfusion.schemas.analyst_state import (
    ANALYST_TRANSITION_SCHEMA_VERSION,
    AnalystAlertDetail,
    AnalystAlertListItem,
    AnalystAuthorizationRegistry,
    AnalystCapability,
    AnalystStateError,
    AnalystStateSnapshot,
    AnalystTransitionEvent,
    AnalystTransitionResult,
    canonical_uuid4,
    is_alert_candidate_id,
    is_utc,
    valid_rationale,
)

ANALYST_REPOSITORY_SCHEMA_VERSION = 1
ANALYST_REPOSITORY_SCHEMA_IDENTITY = "analyst_state_sqlite_v1"
SQLITE_BUSY_TIMEOUT_MS = 500

_CREATE_METADATA = """
CREATE TABLE repository_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT
"""
_CREATE_STATES = """
CREATE TABLE analyst_states (
    alert_candidate_id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('in_review', 'closed', 'escalated')),
    version INTEGER NOT NULL CHECK (version IN (1, 2)),
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    last_transition_id TEXT NOT NULL UNIQUE,
    CHECK (
        (state = 'in_review' AND version = 1)
        OR (state IN ('closed', 'escalated') AND version = 2)
    )
) STRICT
"""
_CREATE_TRANSITIONS = """
CREATE TABLE analyst_transition_events (
    schema_version TEXT NOT NULL,
    transition_id TEXT PRIMARY KEY,
    alert_candidate_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence IN (1, 2)),
    expected_version INTEGER NOT NULL CHECK (expected_version IN (0, 1)),
    from_state TEXT NOT NULL CHECK (from_state IN ('new', 'in_review')),
    to_state TEXT NOT NULL CHECK (to_state IN ('in_review', 'closed', 'escalated')),
    actor_id TEXT NOT NULL,
    rationale TEXT NOT NULL,
    transitioned_at TEXT NOT NULL,
    FOREIGN KEY (alert_candidate_id) REFERENCES analyst_states(alert_candidate_id),
    UNIQUE (alert_candidate_id, sequence),
    CHECK (
        (sequence = 1 AND expected_version = 0 AND from_state = 'new' AND to_state = 'in_review')
        OR
        (sequence = 2 AND expected_version = 1 AND from_state = 'in_review'
            AND to_state IN ('closed', 'escalated'))
    )
) STRICT
"""

_EXPECTED_METADATA_COLUMNS = (
    ("key", "TEXT", 1, 1),
    ("value", "TEXT", 1, 0),
)
_EXPECTED_STATE_COLUMNS = (
    ("alert_candidate_id", "TEXT", 1, 1),
    ("state", "TEXT", 1, 0),
    ("version", "INTEGER", 1, 0),
    ("updated_at", "TEXT", 1, 0),
    ("updated_by", "TEXT", 1, 0),
    ("last_transition_id", "TEXT", 1, 0),
)
_EXPECTED_TRANSITION_COLUMNS = (
    ("schema_version", "TEXT", 1, 0),
    ("transition_id", "TEXT", 1, 1),
    ("alert_candidate_id", "TEXT", 1, 0),
    ("sequence", "INTEGER", 1, 0),
    ("expected_version", "INTEGER", 1, 0),
    ("from_state", "TEXT", 1, 0),
    ("to_state", "TEXT", 1, 0),
    ("actor_id", "TEXT", 1, 0),
    ("rationale", "TEXT", 1, 0),
    ("transitioned_at", "TEXT", 1, 0),
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _table_columns(connection: sqlite3.Connection, table: str) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (row[1], row[2], row[3], row[5])
        for row in connection.execute(f"PRAGMA table_info({table})")
    )


def _implicit_new(alert_candidate_id: str) -> AnalystStateSnapshot:
    return AnalystStateSnapshot(alert_candidate_id, "new", 0, None, None, None)


def _state_from_row(row: sqlite3.Row | None, alert_candidate_id: str) -> AnalystStateSnapshot:
    if row is None:
        return _implicit_new(alert_candidate_id)
    try:
        return AnalystStateSnapshot(
            alert_candidate_id=row["alert_candidate_id"],
            state=row["state"],
            version=row["version"],
            updated_at=datetime.fromisoformat(row["updated_at"]),
            updated_by=row["updated_by"],
            last_transition_id=row["last_transition_id"],
        )
    except (AnalystStateError, TypeError, ValueError):
        raise AnalystStateError("database_record_invalid") from None


def _transition_from_row(row: sqlite3.Row) -> AnalystTransitionEvent:
    try:
        return AnalystTransitionEvent(
            schema_version=row["schema_version"],
            transition_id=row["transition_id"],
            alert_candidate_id=row["alert_candidate_id"],
            sequence=row["sequence"],
            expected_version=row["expected_version"],
            from_state=row["from_state"],
            to_state=row["to_state"],
            actor_id=row["actor_id"],
            rationale=row["rationale"],
            transitioned_at=datetime.fromisoformat(row["transitioned_at"]),
        )
    except (AnalystStateError, TypeError, ValueError):
        raise AnalystStateError("database_record_invalid") from None


def _validate_history(
    alert_candidate_id: str,
    state: AnalystStateSnapshot,
    transitions: tuple[AnalystTransitionEvent, ...],
) -> None:
    if len(transitions) != state.version or any(
        event.sequence != index
        or event.alert_candidate_id != alert_candidate_id
        or (index > 1 and event.from_state != transitions[index - 2].to_state)
        for index, event in enumerate(transitions, 1)
    ):
        raise AnalystStateError("database_record_invalid")
    if transitions:
        latest = transitions[-1]
        if (
            latest.transition_id != state.last_transition_id
            or latest.to_state != state.state
            or latest.actor_id != state.updated_by
            or latest.transitioned_at != state.updated_at
        ):
            raise AnalystStateError("database_record_invalid")


class AnalystStateRepository:
    """Authorized list/detail and atomic state transitions over immutable alerts."""

    def __init__(
        self,
        database_path: Path,
        alert_repository: AlertCandidateRepository,
        authorization: AnalystAuthorizationRegistry,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if (
            not isinstance(database_path, Path)
            or type(alert_repository) is not AlertCandidateRepository
            or type(authorization) is not AnalystAuthorizationRegistry
            or not callable(clock)
        ):
            raise AnalystStateError("analyst_repository_configuration_invalid")
        self._database_path = database_path
        self._alerts = alert_repository
        self._authorization = authorization
        self._clock = clock
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
            connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
            return connection
        except sqlite3.Error:
            raise AnalystStateError("database_unavailable") from None

    def _initialize(self) -> None:
        try:
            try:
                info = self._database_path.lstat()
                existed = True
                if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
                    raise AnalystStateError("database_corrupt")
            except FileNotFoundError:
                existed = False
                self._database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = self._connect()
            try:
                check = connection.execute("PRAGMA quick_check").fetchone()
                if check is None or check[0] != "ok":
                    raise AnalystStateError("database_corrupt")
                if not existed:
                    connection.execute("BEGIN EXCLUSIVE")
                    connection.execute(_CREATE_METADATA)
                    connection.execute(_CREATE_STATES)
                    connection.execute(_CREATE_TRANSITIONS)
                    connection.execute(
                        "INSERT INTO repository_metadata(key, value) VALUES (?, ?)",
                        ("schema_identity", ANALYST_REPOSITORY_SCHEMA_IDENTITY),
                    )
                    connection.execute(f"PRAGMA user_version = {ANALYST_REPOSITORY_SCHEMA_VERSION}")
                    connection.commit()
                self._verify_schema(connection)
            finally:
                connection.close()
        except AnalystStateError:
            raise
        except (OSError, sqlite3.DatabaseError):
            raise AnalystStateError("database_corrupt") from None

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            metadata = connection.execute(
                "SELECT value FROM repository_metadata WHERE key = ?", ("schema_identity",)
            ).fetchone()
            metadata_count = connection.execute(
                "SELECT COUNT(*) FROM repository_metadata"
            ).fetchone()[0]
            foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            metadata_columns = _table_columns(connection, "repository_metadata")
            state_columns = _table_columns(connection, "analyst_states")
            transition_columns = _table_columns(connection, "analyst_transition_events")
        except sqlite3.Error:
            raise AnalystStateError("database_schema_mismatch") from None
        if (
            version != ANALYST_REPOSITORY_SCHEMA_VERSION
            or metadata is None
            or metadata[0] != ANALYST_REPOSITORY_SCHEMA_IDENTITY
            or metadata_count != 1
            or foreign_key_errors
            or tables != {"repository_metadata", "analyst_states", "analyst_transition_events"}
            or metadata_columns != _EXPECTED_METADATA_COLUMNS
            or state_columns != _EXPECTED_STATE_COLUMNS
            or transition_columns != _EXPECTED_TRANSITION_COLUMNS
        ):
            raise AnalystStateError("database_schema_mismatch")

    def _get_candidate(self, alert_candidate_id: str):
        try:
            return self._alerts.get(alert_candidate_id)
        except AlertPersistenceError:
            raise AnalystStateError("alert_repository_failed") from None

    def list_alerts(
        self,
        capability: AnalystCapability,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[AnalystAlertListItem, ...]:
        """Return a bounded alert page in immutable candidate creation order."""
        self._authorization.require_read(capability)
        if type(limit) is not int or not 1 <= limit <= MAX_ALERT_LIST_LIMIT:
            raise AnalystStateError("list_limit_invalid")
        if type(offset) is not int or not 0 <= offset <= MAX_ALERT_LIST_OFFSET:
            raise AnalystStateError("list_offset_invalid")
        try:
            candidates = self._alerts.list(limit=limit, offset=offset)
        except AlertPersistenceError:
            raise AnalystStateError("alert_repository_failed") from None
        if not candidates:
            return ()
        identifiers = tuple(candidate.alert_candidate_id for candidate in candidates)
        placeholders = ", ".join("?" for _ in identifiers)
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            state_rows = connection.execute(
                f"SELECT * FROM analyst_states WHERE alert_candidate_id IN ({placeholders})",
                identifiers,
            ).fetchall()
            transition_rows = connection.execute(
                f"SELECT * FROM analyst_transition_events "
                f"WHERE alert_candidate_id IN ({placeholders}) "
                "ORDER BY alert_candidate_id ASC, sequence ASC",
                identifiers,
            ).fetchall()
            connection.commit()
            states = {
                row["alert_candidate_id"]: _state_from_row(row, row["alert_candidate_id"])
                for row in state_rows
            }
            transitions: dict[str, list[AnalystTransitionEvent]] = {
                identifier: [] for identifier in identifiers
            }
            for row in transition_rows:
                event = _transition_from_row(row)
                transitions.setdefault(event.alert_candidate_id, []).append(event)
            for identifier in identifiers:
                state = states.get(identifier, _implicit_new(identifier))
                _validate_history(identifier, state, tuple(transitions[identifier]))
            return tuple(
                AnalystAlertListItem(
                    candidate=candidate,
                    analyst_state=states.get(
                        candidate.alert_candidate_id,
                        _implicit_new(candidate.alert_candidate_id),
                    ),
                )
                for candidate in candidates
            )
        except AnalystStateError:
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise AnalystStateError("database_read_failed") from None
        finally:
            connection.close()

    def get_alert(
        self, capability: AnalystCapability, alert_candidate_id: str
    ) -> AnalystAlertDetail | None:
        """Return immutable evidence, current state and complete bounded history."""
        self._authorization.require_read(capability)
        if not is_alert_candidate_id(alert_candidate_id):
            raise AnalystStateError("alert_candidate_id_invalid")
        candidate = self._get_candidate(alert_candidate_id)
        if candidate is None:
            return None
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            state_row = connection.execute(
                "SELECT * FROM analyst_states WHERE alert_candidate_id = ?",
                (alert_candidate_id,),
            ).fetchone()
            transition_rows = connection.execute(
                "SELECT * FROM analyst_transition_events WHERE alert_candidate_id = ? "
                "ORDER BY sequence ASC",
                (alert_candidate_id,),
            ).fetchall()
            connection.commit()
            state = _state_from_row(state_row, alert_candidate_id)
            transitions = tuple(_transition_from_row(row) for row in transition_rows)
            _validate_history(alert_candidate_id, state, transitions)
            return AnalystAlertDetail(candidate, state, transitions)
        except AnalystStateError:
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise AnalystStateError("database_read_failed") from None
        finally:
            connection.close()

    def transition(
        self,
        capability: AnalystCapability,
        *,
        alert_candidate_id: str,
        expected_version: int,
        to_state: str,
        transition_id: str,
        rationale: str,
    ) -> AnalystTransitionResult:
        """Atomically append one authorized state transition or replay it exactly."""
        actor_id = self._authorization.require_transition(capability)
        if not is_alert_candidate_id(alert_candidate_id):
            raise AnalystStateError("alert_candidate_id_invalid")
        if type(expected_version) is not int or not 0 <= expected_version <= 2:
            raise AnalystStateError("analyst_state_version_invalid")
        if type(to_state) is not str or to_state not in {"in_review", "closed", "escalated"}:
            raise AnalystStateError("analyst_target_state_invalid")
        if not canonical_uuid4(transition_id):
            raise AnalystStateError("analyst_transition_id_invalid")
        if not valid_rationale(rationale):
            raise AnalystStateError("analyst_rationale_invalid")
        if self._get_candidate(alert_candidate_id) is None:
            raise AnalystStateError("alert_candidate_not_found")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            state_row = connection.execute(
                "SELECT * FROM analyst_states WHERE alert_candidate_id = ?",
                (alert_candidate_id,),
            ).fetchone()
            history_rows = connection.execute(
                "SELECT * FROM analyst_transition_events WHERE alert_candidate_id = ? "
                "ORDER BY sequence ASC",
                (alert_candidate_id,),
            ).fetchall()
            current = _state_from_row(state_row, alert_candidate_id)
            history = tuple(_transition_from_row(row) for row in history_rows)
            _validate_history(alert_candidate_id, current, history)
            replay_row = connection.execute(
                "SELECT * FROM analyst_transition_events WHERE transition_id = ?",
                (transition_id,),
            ).fetchone()
            if replay_row is not None:
                event = _transition_from_row(replay_row)
                if (
                    event.alert_candidate_id != alert_candidate_id
                    or event.expected_version != expected_version
                    or event.to_state != to_state
                    or event.actor_id != actor_id
                    or event.rationale != rationale
                ):
                    raise AnalystStateError("analyst_transition_identity_conflict")
                connection.commit()
                return AnalystTransitionResult(
                    "existing", "analyst_transition_already_exists", current, event
                )
            if current.version != expected_version:
                raise AnalystStateError("analyst_state_version_conflict")
            allowed = {
                "new": {"in_review"},
                "in_review": {"closed", "escalated"},
                "closed": set(),
                "escalated": set(),
            }
            if to_state not in allowed[current.state]:
                raise AnalystStateError("analyst_transition_invalid")
            try:
                transitioned_at = self._clock()
            except Exception:
                raise AnalystStateError("analyst_clock_invalid") from None
            if not is_utc(transitioned_at):
                raise AnalystStateError("analyst_clock_invalid")
            sequence = current.version + 1
            event = AnalystTransitionEvent(
                schema_version=ANALYST_TRANSITION_SCHEMA_VERSION,
                transition_id=transition_id,
                alert_candidate_id=alert_candidate_id,
                sequence=sequence,
                expected_version=expected_version,
                from_state=current.state,
                to_state=to_state,
                actor_id=actor_id,
                rationale=rationale,
                transitioned_at=transitioned_at,
            )
            state_values = (
                to_state,
                sequence,
                transitioned_at.isoformat(),
                actor_id,
                transition_id,
            )
            if current.state == "new":
                connection.execute(
                    "INSERT INTO analyst_states "
                    "(alert_candidate_id, state, version, updated_at, updated_by, last_transition_id) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (alert_candidate_id, *state_values),
                )
            else:
                changed = connection.execute(
                    "UPDATE analyst_states SET state = ?, version = ?, updated_at = ?, "
                    "updated_by = ?, last_transition_id = ? "
                    "WHERE alert_candidate_id = ? AND version = ?",
                    (*state_values, alert_candidate_id, expected_version),
                )
                if changed.rowcount != 1:
                    raise AnalystStateError("analyst_state_version_conflict")
            connection.execute(
                "INSERT INTO analyst_transition_events "
                "(schema_version, transition_id, alert_candidate_id, sequence, expected_version, "
                "from_state, to_state, actor_id, rationale, transitioned_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.schema_version,
                    event.transition_id,
                    event.alert_candidate_id,
                    event.sequence,
                    event.expected_version,
                    event.from_state,
                    event.to_state,
                    event.actor_id,
                    event.rationale,
                    event.transitioned_at.isoformat(),
                ),
            )
            connection.commit()
            return AnalystTransitionResult(
                "created",
                "analyst_transition_created",
                AnalystStateSnapshot(
                    alert_candidate_id,
                    to_state,
                    sequence,
                    transitioned_at,
                    actor_id,
                    transition_id,
                ),
                event,
            )
        except AnalystStateError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            if getattr(exc, "sqlite_errorcode", None) in {
                sqlite3.SQLITE_BUSY,
                sqlite3.SQLITE_LOCKED,
            }:
                raise AnalystStateError("database_busy") from None
            raise AnalystStateError("database_write_failed") from None
        finally:
            connection.close()
