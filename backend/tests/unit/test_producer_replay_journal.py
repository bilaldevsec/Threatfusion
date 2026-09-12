"""Durable producer replay journal tests using only temporary synthetic state."""

from __future__ import annotations

import copy
import json
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import threatfusion.models.network_inference as inference
from threatfusion.api.producer_admission import (
    INGEST_METHOD,
    INGEST_TARGET,
    JSON_CONTENT_TYPE,
    MAX_RESPONSE_BYTES,
    PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION,
    REGISTERED_UNSW_PRODUCER_ID,
    REGISTERED_UNSW_SOURCE_CONTRACT,
    ProducerEventReference,
    ProducerRecordDisposition,
    ProducerResponse,
    ValidatedAdmissionRecord,
    serialize_producer_response,
)
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.producer_replay_journal import (
    REPLAY_JOURNAL_SCHEMA_IDENTITY,
    REPLAY_JOURNAL_SCHEMA_VERSION,
    REPLAY_OWNER_MODEL,
    STATE_COMPLETED,
    STATE_IN_PROGRESS,
    STATE_OUTCOME_UNKNOWN,
    ProducerReplayJournal,
    ProducerReplayJournalError,
    ReplayClaim,
)

NOW = datetime(2026, 9, 12, 12, 0, tzinfo=UTC)
GENERATION = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
NEXT_GENERATION = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


@pytest.fixture(autouse=True)
def downstream_spies(monkeypatch):
    calls: list[str] = []

    def predictor_forbidden(*args, **kwargs):
        calls.append("predictor")
        pytest.fail("replay handling invoked the predictor")

    def repository_forbidden(*args, **kwargs):
        calls.append("repository")
        pytest.fail("replay handling invoked alert persistence")

    monkeypatch.setattr(inference._FrozenNetworkPredictor, "infer", predictor_forbidden)
    monkeypatch.setattr(AlertCandidateRepository, "insert", repository_forbidden)
    yield
    assert calls == []


def admission_record(**updates) -> ValidatedAdmissionRecord:
    values = {
        "correlation_id": "11111111-1111-4111-8111-111111111111",
        "producer_id": REGISTERED_UNSW_PRODUCER_ID,
        "credential_id": "a" * 64,
        "request_id": "22222222-2222-4222-8222-222222222222",
        "produced_at": NOW,
        "received_at": NOW + timedelta(seconds=1),
        "nonce_sha256": "b" * 64,
        "body_sha256": "c" * 64,
        "method": INGEST_METHOD,
        "target": INGEST_TARGET,
        "content_type": JSON_CONTENT_TYPE,
        "content_length": 512,
        "source_contract": REGISTERED_UNSW_SOURCE_CONTRACT,
        "records": (ProducerEventReference("d" * 64, 7),),
    }
    values.update(updates)
    return ValidatedAdmissionRecord(**values)


def forced_record(record: ValidatedAdmissionRecord, **updates) -> ValidatedAdmissionRecord:
    changed = copy.copy(record)
    for name, value in updates.items():
        object.__setattr__(changed, name, value)
    return changed


def response_for(correlation_id: str, *, reason: str = "request_completed") -> bytes:
    return serialize_producer_response(
        ProducerResponse(
            PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION,
            correlation_id,
            reason,
            (ProducerRecordDisposition(1, "created", "alert_candidate_created"),),
        )
    )


def journal(tmp_path: Path, generation: str = GENERATION) -> ProducerReplayJournal:
    return ProducerReplayJournal(
        tmp_path / "state" / "producer-replay.sqlite3",
        service_generation_id=generation,
    )


def test_first_claim_succeeds_with_unpredictable_ownership_proof(tmp_path):
    result = journal(tmp_path).claim(admission_record(), claimed_at=NOW)

    assert (result.disposition, result.reason) == (STATE_IN_PROGRESS, "request_claimed")
    assert result.claim is not None
    assert len(result.claim.ownership_token) == 43
    assert result.claim.ownership_token not in repr(result.claim)
    assert result.cached_response is None


def test_exact_in_progress_retry_gets_no_ownership_token(tmp_path):
    repository = journal(tmp_path)
    first = repository.claim(admission_record(), claimed_at=NOW)
    retry = repository.claim(admission_record(), claimed_at=NOW + timedelta(seconds=1))

    assert first.claim is not None
    assert (retry.disposition, retry.reason, retry.claim, retry.cached_response) == (
        STATE_IN_PROGRESS,
        "request_in_progress",
        None,
        None,
    )


def test_concurrent_exact_duplicates_have_one_winner_across_repository_instances(tmp_path):
    path = tmp_path / "producer-replay.sqlite3"
    first = ProducerReplayJournal(path, service_generation_id=GENERATION)
    second = ProducerReplayJournal(path, service_generation_id=GENERATION)
    record = admission_record()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda repository: repository.claim(record, claimed_at=NOW),
                (first, second),
            )
        )

    assert [result.reason for result in results].count("request_claimed") == 1
    assert [result.reason for result in results].count("request_in_progress") == 1
    assert sum(result.claim is not None for result in results) == 1


def test_completed_retry_returns_identical_cached_bytes_and_first_correlation(tmp_path):
    repository = journal(tmp_path)
    record = admission_record()
    claimed = repository.claim(record, claimed_at=NOW)
    response = response_for(record.correlation_id)
    assert repository.complete(claimed.claim, response, completed_at=NOW) == response

    retry_record = admission_record(
        correlation_id="33333333-3333-4333-8333-333333333333",
        received_at=NOW + timedelta(minutes=1),
    )
    retry = repository.claim(retry_record, claimed_at=NOW + timedelta(minutes=1))

    assert (retry.disposition, retry.reason) == (STATE_COMPLETED, "request_completed")
    assert retry.cached_response == response
    assert retry.cached_response is not response
    assert retry.first_correlation_id == record.correlation_id
    assert retry.claim is None


def test_reopen_preserves_first_completed_response(tmp_path):
    path = tmp_path / "producer-replay.sqlite3"
    record = admission_record()
    first = ProducerReplayJournal(path, service_generation_id=GENERATION)
    claimed = first.claim(record, claimed_at=NOW)
    response = response_for(record.correlation_id)
    first.complete(claimed.claim, response, completed_at=NOW)

    reopened = ProducerReplayJournal(path, service_generation_id=NEXT_GENERATION)
    retry = reopened.claim(record, claimed_at=NOW + timedelta(days=1))

    assert retry.disposition == STATE_COMPLETED
    assert retry.cached_response == response


@pytest.mark.parametrize(
    "updates",
    [
        {"producer_id": "different-producer"},
        {"credential_id": "e" * 64},
        {"request_id": "44444444-4444-4444-8444-444444444444"},
        {"nonce_sha256": "e" * 64},
        {"body_sha256": "e" * 64},
        {"produced_at": NOW + timedelta(seconds=1)},
        {"method": "PUT"},
        {"target": "/different"},
        {"content_type": "application/problem+json"},
        {"content_length": 513},
        {"source_contract": "different_source_v1"},
        {"records": (ProducerEventReference("e" * 64, 7),)},
    ],
    ids=(
        "producer",
        "credential",
        "request_id",
        "nonce",
        "body",
        "produced_at",
        "method",
        "target",
        "content_type",
        "content_length",
        "source_contract",
        "ordered_records",
    ),
)
def test_one_field_replay_conflicts_fail_closed_without_field_disclosure(tmp_path, updates):
    repository = journal(tmp_path)
    record = admission_record()
    repository.claim(record, claimed_at=NOW)
    conflicting = forced_record(record, **updates)

    with pytest.raises(ProducerReplayJournalError) as raised:
        repository.claim(conflicting, claimed_at=NOW)

    assert raised.value.code == "request_replay_rejected"
    assert str(raised.value) == "request_replay_rejected"
    assert all(str(value) not in str(raised.value) for value in updates.values())


def test_correlation_and_receive_time_do_not_change_retry_identity(tmp_path):
    repository = journal(tmp_path)
    first = admission_record()
    repository.claim(first, claimed_at=NOW)
    retry = admission_record(
        correlation_id="33333333-3333-4333-8333-333333333333",
        received_at=NOW + timedelta(hours=1),
    )

    result = repository.claim(retry, claimed_at=NOW + timedelta(hours=1))

    assert result.reason == "request_in_progress"
    assert result.first_correlation_id == first.correlation_id


@pytest.mark.parametrize("kind", ["wrong", "stale", "forged", "non_ascii"])
def test_wrong_stale_and_forged_claim_tokens_fail_closed(tmp_path, kind):
    repository = journal(tmp_path)
    first = repository.claim(admission_record(), claimed_at=NOW).claim
    other_record = admission_record(
        request_id="44444444-4444-4444-8444-444444444444",
        nonce_sha256="e" * 64,
        body_sha256="f" * 64,
    )
    other = repository.claim(other_record, claimed_at=NOW).claim
    candidates = {
        "wrong": ReplayClaim(first.request_id, NEXT_GENERATION, first.ownership_token),
        "stale": ReplayClaim(first.request_id, GENERATION, other.ownership_token),
        "forged": ReplayClaim(first.request_id, GENERATION, "A" * 43),
        "non_ascii": ReplayClaim(first.request_id, GENERATION, "é" * 43),
    }

    with pytest.raises(ProducerReplayJournalError, match="^claim_not_active$"):
        repository.complete(
            candidates[kind], response_for(admission_record().correlation_id), completed_at=NOW
        )


def test_double_completion_fails_closed_and_preserves_first_bytes(tmp_path):
    repository = journal(tmp_path)
    record = admission_record()
    claim = repository.claim(record, claimed_at=NOW).claim
    first = response_for(record.correlation_id)
    repository.complete(claim, first, completed_at=NOW)

    with pytest.raises(ProducerReplayJournalError, match="^claim_not_active$"):
        repository.complete(claim, first, completed_at=NOW + timedelta(seconds=1))
    assert repository.claim(record, claimed_at=NOW).cached_response == first


def test_explicit_startup_recovery_is_idempotent_and_terminal(tmp_path):
    path = tmp_path / "producer-replay.sqlite3"
    record = admission_record()
    old = ProducerReplayJournal(path, service_generation_id=GENERATION)
    claim = old.claim(record, claimed_at=NOW).claim
    restarted = ProducerReplayJournal(path, service_generation_id=NEXT_GENERATION)

    assert (
        restarted.recover_abandoned_generation(
            abandoned_generation_id=GENERATION, recovered_at=NOW + timedelta(minutes=1)
        )
        == 1
    )
    assert (
        restarted.recover_abandoned_generation(
            abandoned_generation_id=GENERATION, recovered_at=NOW + timedelta(minutes=2)
        )
        == 0
    )
    unknown = restarted.claim(record, claimed_at=NOW + timedelta(minutes=2))
    assert (unknown.disposition, unknown.reason, unknown.claim) == (
        STATE_OUTCOME_UNKNOWN,
        "outcome_unknown",
        None,
    )
    with pytest.raises(ProducerReplayJournalError, match="^claim_not_active$"):
        old.complete(claim, response_for(record.correlation_id), completed_at=NOW)


def test_additional_ordinary_connection_does_not_invalidate_live_claim(tmp_path):
    path = tmp_path / "producer-replay.sqlite3"
    record = admission_record()
    owner = ProducerReplayJournal(path, service_generation_id=GENERATION)
    claim = owner.claim(record, claimed_at=NOW).claim

    ProducerReplayJournal(path, service_generation_id=NEXT_GENERATION)
    response = response_for(record.correlation_id)

    assert owner.complete(claim, response, completed_at=NOW) == response


def test_recovery_does_not_change_completed_or_already_unknown_records(tmp_path):
    path = tmp_path / "producer-replay.sqlite3"
    old = ProducerReplayJournal(path, service_generation_id=GENERATION)
    completed_record = admission_record()
    completed_claim = old.claim(completed_record, claimed_at=NOW).claim
    completed_response = response_for(completed_record.correlation_id)
    old.complete(completed_claim, completed_response, completed_at=NOW)
    unknown_record = admission_record(
        request_id="44444444-4444-4444-8444-444444444444",
        nonce_sha256="e" * 64,
        body_sha256="f" * 64,
        correlation_id="33333333-3333-4333-8333-333333333333",
    )
    old.claim(unknown_record, claimed_at=NOW)
    restarted = ProducerReplayJournal(path, service_generation_id=NEXT_GENERATION)
    assert (
        restarted.recover_abandoned_generation(abandoned_generation_id=GENERATION, recovered_at=NOW)
        == 1
    )
    assert (
        restarted.recover_abandoned_generation(abandoned_generation_id=GENERATION, recovered_at=NOW)
        == 0
    )

    assert restarted.claim(completed_record, claimed_at=NOW).cached_response == completed_response
    assert restarted.claim(unknown_record, claimed_at=NOW).disposition == STATE_OUTCOME_UNKNOWN


def test_recovery_rejects_current_generation_as_not_proven_abandoned(tmp_path):
    with pytest.raises(ProducerReplayJournalError, match="^recovery_request_invalid$"):
        journal(tmp_path).recover_abandoned_generation(
            abandoned_generation_id=GENERATION, recovered_at=NOW
        )


def test_database_lock_wait_is_bounded_and_sanitized(tmp_path):
    path = tmp_path / "private-journal.sqlite3"
    repository = ProducerReplayJournal(path, service_generation_id=GENERATION)
    lock = sqlite3.connect(path, isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(ProducerReplayJournalError, match="^journal_busy$") as raised:
            repository.claim(admission_record(), claimed_at=NOW)
    finally:
        lock.rollback()
        lock.close()
    assert "private" not in str(raised.value)
    assert "sqlite" not in str(raised.value).lower()


def test_completion_transaction_rolls_back_under_injected_failure(tmp_path):
    path = tmp_path / "producer-replay.sqlite3"
    repository = ProducerReplayJournal(path, service_generation_id=GENERATION)
    record = admission_record()
    claim = repository.claim(record, claimed_at=NOW).claim
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TRIGGER reject_completion BEFORE UPDATE ON replay_requests "
            "BEGIN SELECT RAISE(ABORT, 'sensitive SQL'); END"
        )

    with pytest.raises(ProducerReplayJournalError, match="^journal_write_failed$"):
        repository.complete(claim, response_for(record.correlation_id), completed_at=NOW)

    assert repository.claim(record, claimed_at=NOW).reason == "request_in_progress"


@pytest.mark.parametrize("tamper", ["bytes", "digest"])
def test_tampered_cached_response_or_digest_is_detected(tmp_path, tamper):
    path = tmp_path / "producer-replay.sqlite3"
    repository = ProducerReplayJournal(path, service_generation_id=GENERATION)
    record = admission_record()
    claim = repository.claim(record, claimed_at=NOW).claim
    response = response_for(record.correlation_id)
    repository.complete(claim, response, completed_at=NOW)
    with sqlite3.connect(path) as connection:
        if tamper == "bytes":
            connection.execute("UPDATE replay_requests SET response_bytes = ?", (response + b" ",))
        else:
            connection.execute("UPDATE replay_requests SET response_sha256 = ?", ("0" * 64,))

    with pytest.raises(ProducerReplayJournalError, match="^journal_record_invalid$"):
        repository.claim(record, claimed_at=NOW)


@pytest.mark.parametrize(
    "response",
    [
        b"\xff",
        b"not json",
        json.dumps(
            {
                "schema_version": PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION,
                "correlation_id": admission_record().correlation_id,
                "reason": "request_completed",
                "records": [],
                "raw_features": "sensitive",
            }
        ).encode(),
        json.dumps(
            {
                "schema_version": PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION,
                "correlation_id": admission_record().correlation_id,
                "reason": [],
                "records": [],
            }
        ).encode(),
    ],
    ids=("invalid_utf8", "invalid_json", "unsanitized_extra_field", "wrong_reason_type"),
)
def test_invalid_or_unsanitized_cached_response_is_rejected(tmp_path, response):
    repository = journal(tmp_path)
    claim = repository.claim(admission_record(), claimed_at=NOW).claim
    with pytest.raises(ProducerReplayJournalError, match="^cached_response_invalid$"):
        repository.complete(claim, response, completed_at=NOW)


def test_exact_response_limit_is_accepted_and_one_byte_over_is_rejected(tmp_path):
    repository = journal(tmp_path)
    first_record = admission_record()
    first_claim = repository.claim(first_record, claimed_at=NOW).claim
    base = response_for(first_record.correlation_id)
    exact = base + b" " * (MAX_RESPONSE_BYTES - len(base))
    assert len(exact) == MAX_RESPONSE_BYTES
    assert repository.complete(first_claim, exact, completed_at=NOW) == exact

    second_record = admission_record(
        request_id="44444444-4444-4444-8444-444444444444",
        nonce_sha256="e" * 64,
        body_sha256="f" * 64,
        correlation_id="33333333-3333-4333-8333-333333333333",
    )
    second_claim = repository.claim(second_record, claimed_at=NOW).claim
    over = response_for(second_record.correlation_id) + b" " * MAX_RESPONSE_BYTES
    with pytest.raises(ProducerReplayJournalError, match="^cached_response_invalid$"):
        repository.complete(second_claim, over, completed_at=NOW)


def test_schema_version_metadata_tables_indexes_and_constraints_are_exact(tmp_path):
    path = tmp_path / "producer-replay.sqlite3"
    journal_instance = ProducerReplayJournal(path, service_generation_id=GENERATION)
    journal_instance.claim(admission_record(), claimed_at=NOW)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == (
            REPLAY_JOURNAL_SCHEMA_VERSION
        )
        assert dict(connection.execute("SELECT key, value FROM journal_metadata")) == {
            "schema_identity": REPLAY_JOURNAL_SCHEMA_IDENTITY,
            "owner_model": REPLAY_OWNER_MODEL,
        }
        assert {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')"
            )
            if not row[0].startswith("sqlite_autoindex")
        } == {
            "journal_metadata",
            "replay_requests",
            "replay_request_id_uq",
            "replay_nonce_sha256_uq",
            "replay_recovery_state_generation",
        }
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE replay_requests SET state = 'retryable_failed'")


@pytest.mark.parametrize("mutation", ["version", "table", "index", "constraint"])
def test_reopen_rejects_schema_or_constraint_drift(tmp_path, mutation):
    path = tmp_path / "producer-replay.sqlite3"
    ProducerReplayJournal(path, service_generation_id=GENERATION)
    with sqlite3.connect(path) as connection:
        if mutation == "version":
            connection.execute("PRAGMA user_version = 2")
        elif mutation == "table":
            connection.execute("ALTER TABLE replay_requests ADD COLUMN unexpected TEXT")
        elif mutation == "index":
            connection.execute("DROP INDEX replay_nonce_sha256_uq")
        else:
            connection.execute("PRAGMA writable_schema = ON")
            sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='replay_requests'"
            ).fetchone()[0]
            connection.execute(
                "UPDATE sqlite_master SET sql = ? WHERE type='table' AND name='replay_requests'",
                (sql.replace("content_length BETWEEN 1 AND 131072", "content_length >= 1"),),
            )
    with pytest.raises(ProducerReplayJournalError, match="^journal_schema_mismatch$"):
        ProducerReplayJournal(path, service_generation_id=NEXT_GENERATION)


def test_corrupt_database_is_not_replaced_and_error_is_sanitized(tmp_path):
    path = tmp_path / "sensitive-journal.sqlite3"
    damaged = b"not sqlite /sensitive/path submitted-value"
    path.write_bytes(damaged)
    with pytest.raises(ProducerReplayJournalError, match="^journal_corrupt$") as raised:
        ProducerReplayJournal(path, service_generation_id=GENERATION)
    assert path.read_bytes() == damaged
    assert "sensitive" not in str(raised.value)
    assert "/" not in str(raised.value)


def test_database_stores_only_minimum_hashed_replay_and_sanitized_response_fields(tmp_path):
    path = tmp_path / "producer-replay.sqlite3"
    repository = ProducerReplayJournal(path, service_generation_id=GENERATION)
    record = admission_record()
    claim = repository.claim(record, claimed_at=NOW).claim
    repository.complete(claim, response_for(record.correlation_id), completed_at=NOW)
    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(replay_requests)")}
        stored = repr(connection.execute("SELECT * FROM replay_requests").fetchone())
    assert {
        "raw_body",
        "nonce",
        "raw_row",
        "feature_values",
        "endpoint",
        "path",
        "label",
        "certificate",
        "private_key",
        "claim_token",
    }.isdisjoint(columns)
    for prohibited in (
        "192.0.2.1",
        "198.51.100.2",
        "/sensitive/path",
        "raw feature",
        "private key",
    ):
        assert prohibited not in stored


def test_database_wal_and_shm_names_are_ignored_by_git():
    candidates = (
        "runtime/producer-replay.sqlite3",
        "runtime/producer-replay.sqlite3-wal",
        "runtime/producer-replay.sqlite3-shm",
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
