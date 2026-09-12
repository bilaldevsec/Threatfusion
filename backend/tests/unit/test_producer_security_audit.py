"""Bounded producer security-audit contract and SQLite repository tests."""

from __future__ import annotations

import copy
import math
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

import threatfusion.models.network_inference as inference
from threatfusion.api.producer_admission import (
    REGISTERED_UNSW_PRODUCER_ID,
    REGISTERED_UNSW_SOURCE_CONTRACT,
)
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.producer_replay_journal import ProducerReplayJournal
from threatfusion.db.producer_security_audit import (
    AUDIT_EVENT_SCHEMA_VERSION,
    AUDIT_REPOSITORY_SCHEMA_IDENTITY,
    AUDIT_REPOSITORY_SCHEMA_VERSION,
    EVENT_TYPES,
    MAX_AUDIT_EVENTS,
    MAX_AUDIT_LIST_LIMIT,
    AuditAppendResult,
    ProducerSecurityAuditError,
    ProducerSecurityAuditEvent,
    ProducerSecurityAuditRepository,
    create_producer_security_audit_event,
)

NOW = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
CORRELATION_ID = "11111111-1111-4111-8111-111111111111"

TAXONOMY = (
    ("authentication_rejected", "authentication", "rejected", "authentication_failed"),
    ("producer_admission_rejected", "admission", "rejected", "source_contract_denied"),
    ("rate_limited", "rate_control", "rejected", "rate_limited"),
    ("server_busy", "concurrency_control", "rejected", "server_busy"),
    ("request_admitted", "admission", "admitted", "request_admitted"),
    ("replay_in_progress", "replay", "deferred", "request_in_progress"),
    ("replay_conflict", "replay", "rejected", "request_replay_rejected"),
    ("replay_outcome_unknown", "replay", "unknown", "outcome_unknown"),
    ("request_completed", "completion", "completed", "request_completed"),
    ("internal_failure", "internal", "failed", "internal_error"),
)


@pytest.fixture(autouse=True)
def downstream_spies(monkeypatch):
    """Audit operations must never process replay, predict, or persist alerts."""
    calls: list[str] = []

    def forbidden(name):
        def call(*args, **kwargs):
            calls.append(name)
            pytest.fail(f"security audit invoked {name}")

        return call

    monkeypatch.setattr(ProducerReplayJournal, "claim", forbidden("replay processing"))
    monkeypatch.setattr(inference._FrozenNetworkPredictor, "infer", forbidden("prediction"))
    monkeypatch.setattr(AlertCandidateRepository, "insert", forbidden("alert persistence"))
    yield
    assert calls == []


def audit_event(
    taxonomy=TAXONOMY[-1],
    *,
    event_time: datetime = NOW,
    correlation_id: str | None = CORRELATION_ID,
    maximal: bool = False,
) -> ProducerSecurityAuditEvent:
    event_type, processing_stage, outcome, reason_code = taxonomy
    return create_producer_security_audit_event(
        event_type=event_type,
        processing_stage=processing_stage,
        outcome=outcome,
        reason_code=reason_code,
        correlation_id=correlation_id,
        producer_id=REGISTERED_UNSW_PRODUCER_ID if maximal else None,
        source_contract_id=REGISTERED_UNSW_SOURCE_CONTRACT if maximal else None,
        credential_sha256="a" * 64 if maximal else None,
        request_id_sha256="b" * 64 if maximal else None,
        body_sha256="c" * 64 if maximal else None,
        trusted_now=lambda: event_time,
    )


def forced_event(event: ProducerSecurityAuditEvent, **updates) -> ProducerSecurityAuditEvent:
    changed = copy.copy(event)
    for name, value in updates.items():
        object.__setattr__(changed, name, value)
    return changed


@pytest.mark.parametrize("taxonomy", TAXONOMY)
def test_every_frozen_event_type_has_a_valid_canonical_disposition(taxonomy):
    event = audit_event(taxonomy, correlation_id=None)
    assert (event.event_type, event.processing_stage, event.outcome, event.reason_code) == taxonomy
    assert event.event_type in EVENT_TYPES
    assert UUID(event.audit_event_id).version == 4


def test_valid_minimal_and_maximal_records_are_immutable_and_isolated():
    minimal = audit_event(correlation_id=None)
    maximal = audit_event(maximal=True)

    assert minimal.schema_version == maximal.schema_version == AUDIT_EVENT_SCHEMA_VERSION
    assert minimal.producer_id is None
    assert maximal.producer_id == REGISTERED_UNSW_PRODUCER_ID
    assert maximal.source_contract_id == REGISTERED_UNSW_SOURCE_CONTRACT
    assert maximal.credential_sha256 == "a" * 64
    assert repr(maximal) == "<ProducerSecurityAuditEvent>"
    with pytest.raises(FrozenInstanceError):
        maximal.reason_code = "changed"


@pytest.mark.parametrize(
    "updates",
    [
        {"processing_stage": "unknown"},
        {"outcome": "unknown_outcome"},
        {"reason_code": "unknown_reason"},
        {"processing_stage": "completion"},
    ],
)
def test_unknown_or_mismatched_stage_outcome_and_reason_are_rejected(updates):
    with pytest.raises(ProducerSecurityAuditError, match="^audit_event_invalid$"):
        replace(audit_event(), **updates)


def test_missing_extra_and_wrongly_typed_fields_are_rejected():
    values = {
        field.name: getattr(audit_event(), field.name)
        for field in fields(ProducerSecurityAuditEvent)
    }
    values.pop("event_type")
    with pytest.raises(TypeError):
        ProducerSecurityAuditEvent(**values)
    values["event_type"] = "internal_failure"
    values["message"] = "arbitrary client text"
    with pytest.raises(TypeError):
        ProducerSecurityAuditEvent(**values)
    with pytest.raises(ProducerSecurityAuditError, match="^audit_event_invalid$"):
        replace(audit_event(), event_type=["internal_failure"])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("audit_event_id", True),
        ("event_time", True),
        ("correlation_id", True),
        ("event_type", True),
        ("producer_id", True),
        ("credential_sha256", True),
        ("audit_event_id", "x" * 37),
        ("correlation_id", "x" * 37),
        ("producer_id", "x" * 129),
        ("source_contract_id", "x" * 65),
        ("credential_sha256", "a" * 65),
        ("request_id_sha256", "a" * 65),
        ("body_sha256", "a" * 65),
    ],
)
def test_boolean_wrong_types_and_oversized_values_are_rejected(field, value):
    with pytest.raises(ProducerSecurityAuditError, match="^audit_event_invalid$"):
        replace(audit_event(), **{field: value})


@pytest.mark.parametrize(
    ("field", "submitted"),
    [
        ("event_type", "client says authentication passed"),
        ("processing_stage", "/private/processing"),
        ("outcome", "SELECT * FROM secrets"),
        ("reason_code", "Traceback: secret token"),
        ("producer_id", "attacker-controlled-producer"),
        ("source_contract_id", "attacker_contract_v1"),
        ("body_sha256", "raw request body"),
    ],
)
def test_arbitrary_client_controlled_text_cannot_enter_contract(field, submitted):
    with pytest.raises(ProducerSecurityAuditError) as raised:
        replace(audit_event(), **{field: submitted})
    assert submitted not in str(raised.value)
    assert submitted not in repr(raised.value)


def test_factory_rejects_untrusted_clock_and_generates_distinct_server_ids():
    first = audit_event()
    second = audit_event()
    assert first.audit_event_id != second.audit_event_id
    for clock in (lambda: datetime(2026, 9, 13), lambda: "not time"):
        with pytest.raises(ProducerSecurityAuditError, match="^trusted_time_unavailable$"):
            create_producer_security_audit_event(
                event_type="request_completed",
                processing_stage="completion",
                outcome="completed",
                reason_code="request_completed",
                trusted_now=clock,
            )


def test_first_append_created_identical_append_existing_and_result_is_minimal(tmp_path):
    repository = ProducerSecurityAuditRepository(tmp_path / "audit.sqlite3")
    event = audit_event(maximal=True)

    created = repository.append(event)
    existing = repository.append(event)

    assert created == AuditAppendResult(
        "created", event.audit_event_id, "available", "audit_event_created"
    )
    assert existing == AuditAppendResult(
        "existing", event.audit_event_id, "available", "audit_event_existing"
    )
    assert {field.name for field in fields(created)} == {
        "disposition",
        "audit_event_id",
        "status",
        "reason",
    }
    assert repr(created) == "<AuditAppendResult>"


def test_same_id_different_security_content_conflicts_without_overwrite(tmp_path):
    repository = ProducerSecurityAuditRepository(tmp_path / "audit.sqlite3")
    first = audit_event(TAXONOMY[0])
    conflicting = forced_event(
        first,
        event_type="request_completed",
        processing_stage="completion",
        outcome="completed",
        reason_code="request_completed",
    )
    repository.append(first)

    with pytest.raises(ProducerSecurityAuditError, match="^audit_event_identity_conflict$"):
        repository.append(conflicting)

    assert repository.list() == (first,)


def test_time_and_correlation_are_retry_metadata_and_first_values_are_preserved(tmp_path):
    repository = ProducerSecurityAuditRepository(tmp_path / "audit.sqlite3")
    first = audit_event()
    retry = replace(
        first,
        event_time=NOW + timedelta(seconds=1),
        correlation_id="22222222-2222-4222-8222-222222222222",
    )
    repository.append(first)

    assert repository.append(retry).disposition == "existing"
    assert repository.list() == (first,)


def test_reopen_restart_preserves_events(tmp_path):
    path = tmp_path / "audit.sqlite3"
    event = audit_event(maximal=True)
    ProducerSecurityAuditRepository(path).append(event)

    reopened = ProducerSecurityAuditRepository(path)
    assert reopened.list() == (event,)
    assert reopened.append(event).disposition == "existing"


def test_concurrent_identical_append_has_exactly_one_created_result(tmp_path):
    path = tmp_path / "audit.sqlite3"
    repositories = [ProducerSecurityAuditRepository(path) for _ in range(8)]
    event = audit_event(maximal=True)
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda repository: repository.append(event), repositories))

    assert [result.disposition for result in results].count("created") == 1
    assert [result.disposition for result in results].count("existing") == 7
    assert ProducerSecurityAuditRepository(path).list() == (event,)


def test_concurrent_conflicting_append_creates_one_and_rejects_one(tmp_path):
    path = tmp_path / "audit.sqlite3"
    repositories = [ProducerSecurityAuditRepository(path) for _ in range(2)]
    first = audit_event(TAXONOMY[0])
    second = forced_event(
        first,
        event_type="request_completed",
        processing_stage="completion",
        outcome="completed",
        reason_code="request_completed",
    )

    def append(pair):
        repository, event = pair
        try:
            return repository.append(event).disposition
        except ProducerSecurityAuditError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(append, zip(repositories, (first, second), strict=True)))

    assert sorted(outcomes) == ["audit_event_identity_conflict", "created"]
    assert len(ProducerSecurityAuditRepository(path).list()) == 1


def test_append_transaction_rolls_back_under_injected_failure(tmp_path):
    path = tmp_path / "audit.sqlite3"
    repository = ProducerSecurityAuditRepository(path)
    first = audit_event()
    repository.append(first)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TRIGGER fail_audit_insert BEFORE INSERT ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'secret SQL and submitted value'); END"
        )
    second = audit_event(TAXONOMY[1])

    with pytest.raises(ProducerSecurityAuditError, match="^audit_write_failed$") as raised:
        repository.append(second)

    assert repository.list() == (first,)
    assert "secret" not in str(raised.value)
    assert "SQL" not in str(raised.value)


def test_sqlite_lock_wait_is_bounded_and_sanitized(tmp_path):
    path = tmp_path / "private-audit.sqlite3"
    repository = ProducerSecurityAuditRepository(path)
    lock = sqlite3.connect(path, isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(ProducerSecurityAuditError, match="^audit_busy$") as raised:
            repository.append(audit_event())
    finally:
        lock.rollback()
        lock.close()
    assert "private" not in str(raised.value)
    assert "sqlite" not in str(raised.value).lower()


def test_schema_version_tables_indexes_columns_and_constraints_are_exact(tmp_path):
    path = tmp_path / "audit.sqlite3"
    repository = ProducerSecurityAuditRepository(path)
    repository.append(audit_event())
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == (
            AUDIT_REPOSITORY_SCHEMA_VERSION
        )
        assert dict(connection.execute("SELECT key, value FROM audit_metadata")) == {
            "schema_identity": AUDIT_REPOSITORY_SCHEMA_IDENTITY
        }
        assert {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')"
            )
            if not row[0].startswith("sqlite_autoindex")
        } == {"audit_metadata", "audit_events", "audit_events_time_id_uq"}
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE audit_events SET event_type = 'arbitrary_message'")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE audit_events SET processing_stage = 'completion'")


@pytest.mark.parametrize("mutation", ["version", "table", "index", "constraint"])
def test_reopen_rejects_schema_index_or_constraint_drift(tmp_path, mutation):
    path = tmp_path / "audit.sqlite3"
    ProducerSecurityAuditRepository(path)
    with sqlite3.connect(path) as connection:
        if mutation == "version":
            connection.execute("PRAGMA user_version = 2")
        elif mutation == "table":
            connection.execute("ALTER TABLE audit_events ADD COLUMN message TEXT")
        elif mutation == "index":
            connection.execute("DROP INDEX audit_events_time_id_uq")
        else:
            connection.execute("PRAGMA writable_schema = ON")
            sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'"
            ).fetchone()[0]
            connection.execute(
                "UPDATE sqlite_master SET sql = ? WHERE type = 'table' AND name = 'audit_events'",
                (sql.replace("length(audit_event_id) = 36", "length(audit_event_id) > 0"),),
            )
    with pytest.raises(ProducerSecurityAuditError, match="^audit_schema_mismatch$"):
        ProducerSecurityAuditRepository(path)


def test_corrupt_database_is_not_replaced_and_error_is_sanitized(tmp_path):
    path = tmp_path / "private-audit.sqlite3"
    damaged = b"not sqlite /secret/path submitted body"
    path.write_bytes(damaged)
    with pytest.raises(ProducerSecurityAuditError, match="^audit_corrupt$") as raised:
        ProducerSecurityAuditRepository(path)
    assert path.read_bytes() == damaged
    assert "private" not in str(raised.value)
    assert "secret" not in str(raised.value)


def test_integrity_failure_is_detected_separately_from_schema_drift(tmp_path):
    path = tmp_path / "audit.sqlite3"
    repository = ProducerSecurityAuditRepository(path)
    repository.append(audit_event())
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("UPDATE audit_events SET event_type = 'invalid'")
    with pytest.raises(ProducerSecurityAuditError, match="^audit_integrity_failed$"):
        ProducerSecurityAuditRepository(path)


def test_listing_is_deterministic_and_strictly_bounded(tmp_path):
    repository = ProducerSecurityAuditRepository(tmp_path / "audit.sqlite3")
    events = [
        audit_event(TAXONOMY[index], event_time=NOW + timedelta(seconds=index // 2))
        for index in range(4)
    ]
    for event in reversed(events):
        repository.append(event)
    expected = tuple(sorted(events, key=lambda event: (event.event_time, event.audit_event_id)))

    assert repository.list(limit=2) == expected[:2]
    assert repository.list(limit=MAX_AUDIT_LIST_LIMIT) == expected


@pytest.mark.parametrize(
    "limit",
    [0, -1, True, MAX_AUDIT_LIST_LIMIT + 1, "1", 1.0, math.nan, math.inf, -math.inf],
)
def test_zero_negative_boolean_over_100_and_invalid_list_limits_fail(tmp_path, limit):
    with pytest.raises(ProducerSecurityAuditError, match="^audit_list_limit_invalid$"):
        ProducerSecurityAuditRepository(tmp_path / "audit.sqlite3", _capacity_limit=1).list(
            limit=limit
        )


def test_production_capacity_constant_and_small_internal_test_boundary(tmp_path):
    assert MAX_AUDIT_EVENTS == 100_000
    production = ProducerSecurityAuditRepository(tmp_path / "production.sqlite3")
    assert production._capacity_limit == 100_000

    bounded = ProducerSecurityAuditRepository(tmp_path / "bounded.sqlite3", _capacity_limit=2)
    first = audit_event(TAXONOMY[0])
    second = audit_event(TAXONOMY[1])
    bounded.append(first)
    bounded.append(second)
    with pytest.raises(ProducerSecurityAuditError, match="^audit_capacity_reached$"):
        bounded.append(audit_event(TAXONOMY[2]))

    assert bounded.append(first).disposition == "existing"
    assert bounded.list() == tuple(
        sorted((first, second), key=lambda event: (event.event_time, event.audit_event_id))
    )


def test_full_capacity_never_deletes_overwrites_or_wraps(tmp_path):
    path = tmp_path / "audit.sqlite3"
    repository = ProducerSecurityAuditRepository(path, _capacity_limit=1)
    first = audit_event(TAXONOMY[0], maximal=True)
    repository.append(first)
    conflicting = forced_event(
        first,
        event_type="request_completed",
        processing_stage="completion",
        outcome="completed",
        reason_code="request_completed",
    )

    with pytest.raises(ProducerSecurityAuditError, match="^audit_event_identity_conflict$"):
        repository.append(conflicting)
    with pytest.raises(ProducerSecurityAuditError, match="^audit_capacity_reached$"):
        repository.append(audit_event(TAXONOMY[1]))

    assert repository.list() == (first,)
    assert not hasattr(repository, "delete")
    assert not hasattr(repository, "update")


def test_database_has_only_allowlisted_columns_and_no_sensitive_values(tmp_path):
    path = tmp_path / "audit.sqlite3"
    repository = ProducerSecurityAuditRepository(path)
    repository.append(audit_event(maximal=True))
    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_events)")}
        stored = repr(connection.execute("SELECT * FROM audit_events").fetchone())
    assert columns == {field.name for field in fields(ProducerSecurityAuditEvent)}
    assert {
        "message",
        "exception",
        "stack_trace",
        "sql",
        "request_body",
        "raw_row",
        "features",
        "prediction",
        "source_endpoint",
        "destination_endpoint",
        "label",
        "attack_category",
        "certificate",
        "key",
        "filename",
        "path",
        "cached_response",
    }.isdisjoint(columns)
    for prohibited in ("192.0.2.1", "/private/path", "raw request", "Traceback", "SELECT"):
        assert prohibited not in stored


def test_database_wal_and_shm_names_are_ignored_by_git():
    candidates = (
        "runtime/producer-security-audit.sqlite3",
        "runtime/producer-security-audit.sqlite3-wal",
        "runtime/producer-security-audit.sqlite3-shm",
    )
    results = (
        subprocess.run(
            ["git", "check-ignore", "--quiet", candidate],
            cwd=Path(__file__).resolve().parents[3],
            check=False,
        )
        for candidate in candidates
    )
    assert all(result.returncode == 0 for result in results)
