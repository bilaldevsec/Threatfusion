"""Deterministic tests for the fixed synchronous producer orchestrator."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from types import MethodType, SimpleNamespace
from uuid import uuid4

import pytest

import threatfusion.api.producer_orchestrator as orchestration
from threatfusion.api.producer_admission import (
    PRODUCER_INGEST_REQUEST_SCHEMA_VERSION,
    REGISTERED_UNSW_PRODUCER_ID,
    REGISTERED_UNSW_PRODUCER_TYPE,
    REGISTERED_UNSW_SOURCE_CONTRACT,
    REGISTERED_UNSW_URI_SAN,
    TLS_VERSION,
    AdmittedProducer,
    CertificateRegistry,
    CertificateRegistryRecord,
    PeerCertificateEvidence,
    ProducerAdmissionError,
    decode_producer_response,
)
from threatfusion.api.producer_execution_gates import ProducerExecutionGates
from threatfusion.api.producer_orchestrator import (
    ProducerOrchestrator,
    ProducerOrchestratorError,
)
from threatfusion.api.producer_tls_transport import (
    AuthenticatedTlsSession,
    ProducerTlsListener,
    ProducerTlsTransportError,
    TransportCapability,
    ValidatedRequestHead,
)
from threatfusion.db.alert_repository import AlertCandidateRepository, AlertPersistenceError
from threatfusion.db.producer_replay_journal import ProducerReplayJournal
from threatfusion.db.producer_security_audit import (
    ProducerSecurityAuditError,
    ProducerSecurityAuditRepository,
)
from threatfusion.models.network_inference import (
    NetworkInferenceResult,
    NetworkModelChoice,
    RegisteredUnswInferenceResult,
    UnswNetworkInferenceBoundary,
)
from threatfusion.schemas.alert_candidate import derive_source_event_id

NOW = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
FINGERPRINT = "a" * 64
MEMBER = "b" * 64
GENERATION = "11111111-1111-4111-8111-111111111111"
NEXT_GENERATION = "22222222-2222-4222-8222-222222222222"


class FakeMonotonic:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class FakeConnection:
    def __init__(self, body: bytes, trace: list[str]) -> None:
        self.body = body
        self.trace = trace
        self.closed = False
        self.body_reads = 0
        self.writes: list[bytes] = []
        self.fail_head = False
        self.fail_body = False
        self.fail_write = False

    def read_request_head(self, capability):
        self.trace.append("head")
        if self.fail_head:
            self.closed = True
            raise ProducerTlsTransportError(
                "request_line_invalid", status_code=400, reason="request_line_invalid"
            )
        return (
            ValidatedRequestHead(
                "POST",
                "/v1/producer-events",
                "HTTP/1.1",
                "threatfusion-loopback",
                "application/json",
                len(self.body),
                "close",
                4,
                128,
            ),
            capability,
        )

    def read_body(self, capability):
        self.trace.append("body")
        self.body_reads += 1
        if self.fail_body:
            self.closed = True
            raise ProducerTlsTransportError(
                "body_incomplete", status_code=400, reason="body_incomplete"
            )
        return bytes(self.body), capability

    def write_response(self, capability, response):
        self.trace.append("write")
        self.writes.append(bytes(response))
        self.closed = True
        if self.fail_write:
            raise ProducerTlsTransportError(
                "response_write_failed", status_code=503, reason="internal_failure"
            )

    def close(self, capability):
        self.trace.append("close")
        self.closed = True


def registry() -> CertificateRegistry:
    return CertificateRegistry(
        (
            CertificateRegistryRecord(
                REGISTERED_UNSW_PRODUCER_ID,
                REGISTERED_UNSW_PRODUCER_TYPE,
                REGISTERED_UNSW_URI_SAN,
                FINGERPRINT,
                True,
                False,
                NOW - timedelta(days=1),
                NOW + timedelta(days=1),
                (REGISTERED_UNSW_SOURCE_CONTRACT,),
            ),
        )
    )


def peer() -> PeerCertificateEvidence:
    return PeerCertificateEvidence(
        TLS_VERSION,
        True,
        True,
        FINGERPRINT,
        (REGISTERED_UNSW_URI_SAN,),
    )


def body_for(
    *,
    request_id: str | None = None,
    nonce: str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    producer_id: str = REGISTERED_UNSW_PRODUCER_ID,
    source_contract: str = REGISTERED_UNSW_SOURCE_CONTRACT,
    rows: tuple[int, ...] = (1,),
) -> bytes:
    return json.dumps(
        {
            "schema_version": PRODUCER_INGEST_REQUEST_SCHEMA_VERSION,
            "producer_id": producer_id,
            "request_id": request_id or str(uuid4()),
            "produced_at": "2026-09-13T12:00:00Z",
            "nonce": nonce,
            "source_contract": source_contract,
            "records": [{"source_member_sha256": MEMBER, "row_number": row} for row in rows],
        },
        separators=(",", ":"),
    ).encode()


def registered(row: int, predicted: str = "Normal", *, rejected: bool = False):
    status = "rejected" if rejected else "completed"
    probability = None if rejected else (0.8 if predicted == "Attack" else 0.2)
    return RegisteredUnswInferenceResult(
        source_event_id=derive_source_event_id(
            source_representation="unsw_nb15.argus.raw_49.transaction_bytes.v1",
            manifest_sha256="c" * 64,
            source_member_sha256=MEMBER,
            row_number=row,
        ),
        observed_at=datetime(2015, 1, 22, tzinfo=UTC),
        model_artifact_sha256="d" * 64,
        inference=NetworkInferenceResult(
            correlation_id=str(uuid4()),
            model_identity="random_forest",
            model_version="network_random_forest_baseline_v1",
            contract_identity="network_behavior_v1",
            source_representation_identity="unsw_nb15.argus.raw_49.transaction_bytes.v1",
            attack_probability=probability,
            decision_threshold=0.5,
            predicted_class=None if rejected else predicted,
            status=status,
            reason="model_prediction_failed" if rejected else "inference_succeeded",
            processed_at=NOW.isoformat(),
            latency_ms=0.0,
        ),
    )


def fake_boundary(plan: dict[int, object], calls: list[tuple[object, ...]]):
    boundary = object.__new__(UnswNetworkInferenceBoundary)
    boundary._predictor = SimpleNamespace(
        audit_provenance={
            "primary_model": "random_forest",
            "automatic_fallback": False,
            "source_representation": "unsw_nb15.argus.raw_49.transaction_bytes.v1",
            "feature_contract": "network_behavior_v1",
            "maximum_batch_size": 256,
        }
    )

    def infer_registered(self, *, source_member_sha256, row_number, model):
        calls.append((source_member_sha256, row_number, model))
        selected = plan[row_number]
        if isinstance(selected, BaseException):
            raise selected
        if callable(selected):
            return selected()
        return selected

    def prepare_registered_batch(self, *, references):
        return references

    def infer_prepared_registered(self, prepared, *, model):
        source_member_sha256, row_number = prepared
        return self.infer_registered(
            source_member_sha256=source_member_sha256,
            row_number=row_number,
            model=model,
        )

    boundary.infer_registered = MethodType(infer_registered, boundary)
    boundary._prepare_registered_batch = MethodType(prepare_registered_batch, boundary)
    boundary._infer_prepared_registered = MethodType(infer_prepared_registered, boundary)
    return boundary


def fake_transport():
    transport = object.__new__(ProducerTlsListener)
    transport._listener = object()
    transport.open = MethodType(lambda self: None, transport)
    transport.close = MethodType(lambda self: None, transport)
    return transport


def session_for(body: bytes, trace: list[str]):
    admitted = registry().authenticate(peer(), trusted_now=NOW)
    connection = FakeConnection(body, trace)
    return (
        AuthenticatedTlsSession(
            connection,
            peer(),
            admitted,
            TransportCapability(str(uuid4()), "authenticated", "A" * 43),
        ),
        connection,
    )


def make_orchestrator(
    tmp_path: Path,
    *,
    plan: dict[int, object] | None = None,
    generation: str = GENERATION,
    replay_path: Path | None = None,
    audit_path: Path | None = None,
    alert_path: Path | None = None,
):
    inference_calls: list[tuple[object, ...]] = []
    clock = FakeMonotonic()
    replay = ProducerReplayJournal(
        replay_path or tmp_path / "replay.sqlite3",
        service_generation_id=generation,
    )
    audit = ProducerSecurityAuditRepository(audit_path or tmp_path / "audit.sqlite3")
    alerts = AlertCandidateRepository(alert_path or tmp_path / "alerts.sqlite3")
    gates = ProducerExecutionGates(monotonic_ns=lambda: int(clock.value * 1_000_000_000))
    boundary = fake_boundary(plan or {1: registered(1)}, inference_calls)
    orchestrator = ProducerOrchestrator(
        transport=fake_transport(),
        certificate_registry=registry(),
        execution_gates=gates,
        replay_journal=replay,
        security_audit=audit,
        inference_boundary=boundary,
        alert_repository=alerts,
        trusted_now=lambda: NOW,
        monotonic=clock,
    )
    return orchestrator, replay, audit, alerts, gates, inference_calls, clock


def process(orchestrator, body: bytes, trace: list[str] | None = None):
    selected_trace = [] if trace is None else trace
    session, connection = session_for(body, selected_trace)
    result = orchestrator._process_session(session)
    return result, connection


def decoded(connection: FakeConnection):
    return decode_producer_response(connection.writes[-1])


def test_exact_normal_success_has_zero_candidate_insertions(tmp_path, monkeypatch):
    orchestrator, _, audit, alerts, gates, calls, _ = make_orchestrator(tmp_path)
    insert_calls = 0
    original = alerts.insert
    original_audit = audit.append
    audit_order = []

    def insert(candidate):
        nonlocal insert_calls
        insert_calls += 1
        return original(candidate)

    def append(event):
        audit_order.append(event.event_type)
        return original_audit(event)

    monkeypatch.setattr(alerts, "insert", insert)
    monkeypatch.setattr(audit, "append", append)
    result, connection = process(orchestrator, body_for())

    response = decoded(connection)
    assert result.reason == response.reason == "request_completed"
    assert response.records[0].disposition == "not_actionable"
    assert response.records[0].predicted_class == "Normal"
    assert response.records[0].alert_candidate_id is None
    assert insert_calls == 0
    assert alerts.list() == ()
    assert len(calls) == 1
    assert audit_order == ["request_admitted", "request_completed"]
    snapshot = gates.snapshot()
    assert (snapshot.accepted_count, snapshot.released_count) == (1, 1)


def test_complete_fail_closed_order_is_exact(tmp_path, monkeypatch):
    trace: list[str] = []
    orchestrator, replay, audit, alerts, gates, _, _ = make_orchestrator(
        tmp_path, plan={1: registered(1, "Attack")}
    )
    session, _ = session_for(body_for(), trace)
    original_admit = orchestration.admit_producer_request
    original_acquire = gates.acquire
    original_claim = replay.claim
    original_audit = audit.append
    original_infer = orchestrator._inference.infer_registered
    original_insert = alerts.insert
    original_complete = replay.complete
    original_release = gates.release

    orchestrator._transport.accept_authenticated = MethodType(
        lambda self, registry, *, trusted_now: (trace.append("tls_identity"), session)[1],
        orchestrator._transport,
    )

    def admit(*args, **kwargs):
        trace.append("admission")
        return original_admit(*args, **kwargs)

    def acquire(producer):
        trace.append("gate")
        return original_acquire(producer)

    def claim(*args, **kwargs):
        trace.append("claim")
        return original_claim(*args, **kwargs)

    def append(event):
        trace.append(f"audit:{event.event_type}")
        return original_audit(event)

    def infer(**kwargs):
        trace.append("inference")
        return original_infer(**kwargs)

    def insert(candidate):
        trace.append("persistence")
        return original_insert(candidate)

    def complete(*args, **kwargs):
        trace.append("complete")
        return original_complete(*args, **kwargs)

    def release(lease):
        trace.append("release")
        return original_release(lease)

    monkeypatch.setattr(orchestration, "admit_producer_request", admit)
    monkeypatch.setattr(gates, "acquire", acquire)
    monkeypatch.setattr(replay, "claim", claim)
    monkeypatch.setattr(audit, "append", append)
    monkeypatch.setattr(orchestrator._inference, "infer_registered", infer)
    monkeypatch.setattr(alerts, "insert", insert)
    monkeypatch.setattr(replay, "complete", complete)
    monkeypatch.setattr(gates, "release", release)

    orchestrator.process_one()

    assert trace == [
        "tls_identity",
        "head",
        "body",
        "admission",
        "gate",
        "claim",
        "audit:request_admitted",
        "inference",
        "persistence",
        "audit:request_completed",
        "complete",
        "write",
        "release",
    ]


def test_attack_and_existing_candidate_are_stable_and_idempotent(tmp_path):
    orchestrator, _, _, alerts, _, calls, _ = make_orchestrator(
        tmp_path, plan={1: registered(1, "Attack")}
    )
    first, first_connection = process(orchestrator, body_for())
    second, second_connection = process(
        orchestrator,
        body_for(
            nonce="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        ),
    )

    first_record = decode_producer_response(first.response_bytes).records[0]
    second_record = decode_producer_response(second.response_bytes).records[0]
    assert first_record.disposition == "created"
    assert second_record.disposition == "existing"
    assert first_record.predicted_class == second_record.predicted_class == "Attack"
    assert first_record.alert_candidate_id == second_record.alert_candidate_id
    assert len(alerts.list()) == 1
    assert len(calls) == 2
    assert first_connection.closed and second_connection.closed


def test_mixed_batch_infers_all_before_attack_only_ordered_persistence(tmp_path, monkeypatch):
    orchestrator, _, _, alerts, _, calls, _ = make_orchestrator(
        tmp_path,
        plan={1: registered(1), 2: registered(2, "Attack"), 3: registered(3, rejected=True)},
    )
    trace: list[str] = []
    original_infer = orchestrator._inference.infer_registered
    original_insert = alerts.insert

    def infer(**kwargs):
        trace.append(f"infer:{kwargs['row_number']}")
        return original_infer(**kwargs)

    def insert(candidate):
        trace.append("insert")
        return original_insert(candidate)

    monkeypatch.setattr(orchestrator._inference, "infer_registered", infer)
    monkeypatch.setattr(alerts, "insert", insert)
    result, connection = process(orchestrator, body_for(rows=(1, 2, 3)))
    response = decode_producer_response(result.response_bytes)

    assert trace == ["infer:1", "infer:2", "infer:3", "insert"]
    assert [item.record_index for item in response.records] == [1, 2, 3]
    assert [item.disposition for item in response.records] == [
        "not_actionable",
        "created",
        "rejected",
    ]
    assert len(alerts.list()) == 1
    assert len(calls) == 3
    assert connection.closed


def test_completed_replay_is_byte_identical_with_zero_inference_or_alert_calls(
    tmp_path, monkeypatch
):
    request_id = str(uuid4())
    body = body_for(request_id=request_id)
    orchestrator, _, _, alerts, gates, calls, _ = make_orchestrator(tmp_path)
    first, _ = process(orchestrator, body)

    def forbidden(*args, **kwargs):
        pytest.fail("completed replay invoked alert persistence")

    monkeypatch.setattr(alerts, "insert", forbidden)
    retry, connection = process(orchestrator, body)
    assert retry.response_bytes == first.response_bytes
    assert connection.writes == [first.response_bytes]
    assert len(calls) == 1
    assert gates.snapshot().released_count == 2


def test_completed_retry_audit_failure_never_returns_successful_cached_response(
    tmp_path, monkeypatch
):
    body = body_for()
    orchestrator, _, audit, _, _, calls, _ = make_orchestrator(tmp_path)
    first, _ = process(orchestrator, body)
    original = audit.append

    def append(event):
        if event.event_type == "request_completed":
            raise ProducerSecurityAuditError("audit_write_failed")
        return original(event)

    monkeypatch.setattr(audit, "append", append)
    retry, connection = process(orchestrator, body)
    assert retry.reason == "audit_unavailable"
    assert retry.response_bytes != first.response_bytes
    assert decoded(connection).reason == "audit_unavailable"
    assert len(calls) == 1


def test_in_progress_conflict_and_outcome_unknown_have_zero_inference(tmp_path):
    request_id = str(uuid4())
    body = body_for(request_id=request_id)
    orchestrator, replay, _, alerts, _, calls, _ = make_orchestrator(tmp_path)
    admitted = orchestration.admit_producer_request(
        registry=registry(),
        peer=peer(),
        method="POST",
        target="/v1/ingest/unsw-registered",
        content_type="application/json",
        content_length=len(body),
        body_stream=orchestration.io.BytesIO(body),
        trusted_now=NOW,
    )
    replay.claim(admitted, claimed_at=NOW)
    in_progress, _ = process(orchestrator, body)
    assert in_progress.reason == "request_in_progress"

    conflict_body = body_for(
        request_id=request_id,
        nonce="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    )
    conflict_orchestrator, _, _, _, _, conflict_calls, _ = make_orchestrator(
        tmp_path / "conflict",
        replay_path=tmp_path / "replay.sqlite3",
        audit_path=tmp_path / "conflict-audit.sqlite3",
        alert_path=tmp_path / "conflict-alerts.sqlite3",
    )
    conflict, _ = process(conflict_orchestrator, conflict_body)
    assert conflict.reason == "request_replay_rejected"

    recovered = ProducerReplayJournal(
        tmp_path / "replay.sqlite3", service_generation_id=NEXT_GENERATION
    )
    recovered.recover_abandoned_generation(abandoned_generation_id=GENERATION, recovered_at=NOW)
    unknown_orchestrator, _, _, _, _, unknown_calls, _ = make_orchestrator(
        tmp_path / "unknown",
        generation=NEXT_GENERATION,
        replay_path=tmp_path / "replay.sqlite3",
        audit_path=tmp_path / "unknown-audit.sqlite3",
        alert_path=tmp_path / "unknown-alerts.sqlite3",
    )
    unknown, _ = process(unknown_orchestrator, body)
    assert unknown.reason == "outcome_unknown"
    assert calls == conflict_calls == unknown_calls == []
    assert alerts.list() == ()


def test_tls_authentication_and_head_failures_never_touch_gates_or_downstream(tmp_path):
    orchestrator, _, audit, alerts, gates, calls, _ = make_orchestrator(tmp_path)

    def reject(self, registry, *, trusted_now):
        raise ProducerTlsTransportError(
            "tls_authentication_failed", status_code=401, reason="authentication_failed"
        )

    orchestrator._transport.accept_authenticated = MethodType(reject, orchestrator._transport)
    with pytest.raises(ProducerOrchestratorError, match="^authentication_rejected$"):
        orchestrator.process_one()
    assert gates.snapshot().accepted_count == 0
    assert calls == [] and alerts.list() == ()
    assert audit.list()[0].event_type == "authentication_rejected"

    second, _, second_audit, _, second_gates, second_calls, _ = make_orchestrator(tmp_path / "head")
    session, connection = session_for(body_for(), [])
    connection.fail_head = True
    with pytest.raises(ProducerOrchestratorError, match="^invalid_request$"):
        second._process_session(session)
    assert second_gates.snapshot().accepted_count == 0
    assert second_calls == []
    assert second_audit.list()[0].reason_code == "invalid_request"


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("producer", "request_rejected"),
        ("source", "request_rejected"),
        ("json", "request_rejected"),
    ],
)
def test_body_and_identity_failures_precede_replay_and_inference(tmp_path, kind, expected):
    updates = {
        "producer": {"producer_id": "wrong-producer"},
        "source": {"source_contract": "cic_registered_event_ref_v1"},
        "json": {},
    }[kind]
    body = b"not json" if kind == "json" else body_for(**updates)
    orchestrator, replay, _, alerts, gates, calls, _ = make_orchestrator(tmp_path)
    result, connection = process(orchestrator, body)
    assert result.reason == expected
    assert calls == [] and alerts.list() == ()
    assert gates.snapshot().accepted_count == 0
    assert gates.snapshot().released_count == 0
    assert connection.body_reads == 1
    assert not (tmp_path / "replay.sqlite3-wal").exists()


def test_admission_precedes_rate_and_concurrency_denial(tmp_path):
    rate, _, _, _, rate_gates, rate_calls, _ = make_orchestrator(tmp_path / "rate")
    for _ in range(2):
        decision = rate_gates.acquire(
            AdmittedProducer(
                REGISTERED_UNSW_PRODUCER_ID,
                FINGERPRINT,
                (REGISTERED_UNSW_SOURCE_CONTRACT,),
            )
        )
        rate_gates.release(decision.lease)
    rate_result, rate_connection = process(rate, body_for())
    assert rate_result.reason == "rate_limited"
    assert rate_connection.body_reads == 1 and rate_calls == []

    busy, _, _, _, busy_gates, busy_calls, _ = make_orchestrator(tmp_path / "busy")
    active = busy_gates.acquire(
        AdmittedProducer(
            REGISTERED_UNSW_PRODUCER_ID,
            FINGERPRINT,
            (REGISTERED_UNSW_SOURCE_CONTRACT,),
        )
    )
    busy_result, busy_connection = process(busy, body_for())
    busy_gates.release(active.lease)
    assert busy_result.reason == "server_busy"
    assert busy_connection.body_reads == 1 and busy_calls == []
    assert busy_gates.snapshot().available_token_count == 0


def test_rejected_admission_does_not_charge_rate_or_acquire_concurrency(tmp_path):
    orchestrator, _, _, _, gates, calls, _ = make_orchestrator(tmp_path)
    result, connection = process(orchestrator, body_for(producer_id="wrong-producer"))
    snapshot = gates.snapshot()

    assert result.reason == "request_rejected"
    assert connection.body_reads == 1
    assert calls == []
    assert snapshot.accepted_count == snapshot.rate_limited_count == 0
    assert snapshot.server_busy_count == snapshot.released_count == 0
    assert snapshot.available_token_count == 2


def test_request_admitted_audit_failure_poisoned_with_zero_inference_and_persistence(
    tmp_path, monkeypatch
):
    orchestrator, replay, audit, alerts, gates, calls, _ = make_orchestrator(tmp_path)
    original = audit.append

    def append(event):
        if event.event_type == "request_admitted":
            raise ProducerSecurityAuditError("audit_write_failed")
        return original(event)

    monkeypatch.setattr(audit, "append", append)
    result, connection = process(orchestrator, body_for())
    assert result.reason == "audit_unavailable"
    assert orchestrator.fatal is True
    assert calls == [] and alerts.list() == ()
    assert gates.snapshot().released_count == 1
    assert connection.closed
    with pytest.raises(ProducerOrchestratorError, match="^service_fatal$"):
        orchestrator.process_one()
    assert replay.service_generation_id == GENERATION


def test_inference_rejection_creates_no_candidate_and_uses_only_random_forest(tmp_path):
    orchestrator, _, _, alerts, _, calls, _ = make_orchestrator(
        tmp_path, plan={1: registered(1, rejected=True)}
    )
    result, _ = process(orchestrator, body_for())
    item = decode_producer_response(result.response_bytes).records[0]
    assert (item.disposition, item.reason) == ("rejected", "inference_rejected")
    assert alerts.list() == ()
    assert calls == [(MEMBER, 1, NetworkModelChoice.RANDOM_FOREST)]


def test_unexpected_predictor_failure_poisoned_before_persistence(tmp_path):
    secret = RuntimeError("submitted /private/model detail")
    orchestrator, _, _, alerts, gates, calls, _ = make_orchestrator(tmp_path, plan={1: secret})
    session, connection = session_for(body_for(), [])
    with pytest.raises(ProducerOrchestratorError, match="^inference_outcome_ambiguous$") as error:
        orchestrator._process_session(session)
    assert "private" not in str(error.value)
    assert orchestrator.fatal and connection.closed
    assert alerts.list() == () and len(calls) == 1
    assert gates.snapshot().released_count == 1


def test_candidate_construction_and_known_preinsert_failure_complete_safely(tmp_path, monkeypatch):
    candidate_failure, _, candidate_audit, alerts, _, _, _ = make_orchestrator(
        tmp_path / "candidate", plan={1: registered(1, "Attack")}
    )
    audit_order = []
    original_append = candidate_audit.append

    def append(event):
        audit_order.append(event.event_type)
        return original_append(event)

    monkeypatch.setattr(candidate_audit, "append", append)
    monkeypatch.setattr(
        orchestration,
        "build_alert_candidate",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            orchestration.AlertCandidateError("alert_candidate_invalid")
        ),
    )
    result, _ = process(candidate_failure, body_for())
    assert result.reason == "internal_error"
    assert not candidate_failure.fatal and alerts.list() == ()
    assert audit_order == ["request_admitted", "internal_failure", "request_completed"]

    repository_failure, _, _, _, _, _, _ = make_orchestrator(
        tmp_path / "repository", plan={1: registered(1, "Attack")}
    )
    monkeypatch.setattr(
        repository_failure._alerts,
        "insert",
        lambda candidate: (_ for _ in ()).throw(AlertPersistenceError("database_unavailable")),
    )
    result, _ = process(repository_failure, body_for())
    assert result.reason == "internal_error"
    assert not repository_failure.fatal


def test_ambiguous_alert_completion_audit_and_replay_failures_poison(tmp_path, monkeypatch):
    repository_failure, _, _, _, _, _, _ = make_orchestrator(
        tmp_path / "repository", plan={1: registered(1, "Attack")}
    )
    monkeypatch.setattr(
        repository_failure._alerts,
        "insert",
        lambda candidate: (_ for _ in ()).throw(AlertPersistenceError("database_write_failed")),
    )
    with pytest.raises(ProducerOrchestratorError, match="^alert_persistence_ambiguous$"):
        process(repository_failure, body_for())
    assert repository_failure.fatal

    committed, _, committed_audit, committed_alerts, _, _, _ = make_orchestrator(
        tmp_path / "committed", plan={1: registered(1, "Attack")}
    )
    original_insert = committed_alerts.insert

    def commit_then_fail(candidate):
        original_insert(candidate)
        raise AlertPersistenceError("database_write_failed")

    monkeypatch.setattr(committed_alerts, "insert", commit_then_fail)
    with pytest.raises(ProducerOrchestratorError, match="^alert_persistence_ambiguous$"):
        process(committed, body_for())
    events = committed_audit.list()
    assert committed.fatal and len(committed_alerts.list()) == 1
    assert {event.event_type for event in events} == {"request_admitted", "internal_failure"}
    assert events[-1].request_id_sha256 is not None
    assert events[-1].body_sha256 is not None

    audit_failure, _, audit, _, _, _, _ = make_orchestrator(tmp_path / "audit")
    original = audit.append

    def append(event):
        if event.event_type == "request_completed":
            raise ProducerSecurityAuditError("audit_write_failed")
        return original(event)

    monkeypatch.setattr(audit, "append", append)
    result, _ = process(audit_failure, body_for())
    assert result.reason == "audit_unavailable"
    assert audit_failure.fatal

    replay_path = tmp_path / "replay" / "replay.sqlite3"
    audit_path = tmp_path / "replay" / "audit.sqlite3"
    alert_path = tmp_path / "replay" / "alerts.sqlite3"
    replay_failure, replay, replay_audit, _, replay_gates, replay_calls, _ = make_orchestrator(
        tmp_path / "replay",
        replay_path=replay_path,
        audit_path=audit_path,
        alert_path=alert_path,
    )
    monkeypatch.setattr(
        replay,
        "complete",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            orchestration.ProducerReplayJournalError("journal_write_failed")
        ),
    )
    replay_body = body_for()
    replay_session, replay_connection = session_for(replay_body, [])
    with pytest.raises(ProducerOrchestratorError, match="^replay_completion_ambiguous$"):
        replay_failure._process_session(replay_session)
    assert replay_failure.fatal
    assert replay_connection.writes == []
    assert {event.event_type for event in replay_audit.list()} == {
        "internal_failure",
        "request_admitted",
        "request_completed",
    }
    assert len(replay_calls) == 1
    assert replay_gates.snapshot().released_count == 1

    reopened, _, _, reopened_alerts, _, reopened_calls, _ = make_orchestrator(
        tmp_path / "reopened",
        generation=NEXT_GENERATION,
        replay_path=replay_path,
        audit_path=audit_path,
        alert_path=alert_path,
    )
    in_progress, _ = process(reopened, replay_body)
    assert in_progress.reason == "request_in_progress"
    assert reopened.recover_abandoned_generation(GENERATION) == 1
    outcome_unknown, _ = process(reopened, replay_body)
    assert outcome_unknown.reason == "outcome_unknown"
    assert reopened_calls == [] and reopened_alerts.list() == ()


def test_ambiguous_replay_claim_audited_before_inference_and_persistence(tmp_path, monkeypatch):
    orchestrator, replay, audit, alerts, gates, calls, _ = make_orchestrator(tmp_path)
    monkeypatch.setattr(
        replay,
        "claim",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            orchestration.ProducerReplayJournalError("database_write_failed")
        ),
    )

    with pytest.raises(ProducerOrchestratorError, match="^replay_claim_ambiguous$"):
        process(orchestrator, body_for())

    assert orchestrator.fatal
    assert [event.event_type for event in audit.list()] == ["internal_failure"]
    assert calls == [] and alerts.list() == ()
    assert gates.snapshot().released_count == 1
    with pytest.raises(ProducerOrchestratorError, match="^service_fatal$"):
        orchestrator.process_one()


@pytest.mark.parametrize("audit_fails", [False, True], ids=["healthy_audit", "failed_audit"])
def test_committed_replay_claim_ambiguity_attempts_request_bound_audit_once(
    tmp_path, monkeypatch, audit_fails
):
    orchestrator, replay, audit, alerts, gates, calls, _ = make_orchestrator(tmp_path)
    original_claim = replay.claim
    original_append = audit.append
    admitted = []
    audit_attempts = []
    insert_calls = []

    def commit_then_fail(record, *, claimed_at):
        admitted.append(record)
        claimed = original_claim(record, claimed_at=claimed_at)
        assert claimed.reason == "request_claimed" and claimed.claim is not None
        raise orchestration.ProducerReplayJournalError("journal_write_failed")

    def append(event):
        audit_attempts.append(event)
        if audit_fails:
            raise ProducerSecurityAuditError("audit_write_failed")
        return original_append(event)

    def insert(candidate):
        insert_calls.append(candidate)
        pytest.fail("ambiguous replay claim reached alert insertion")

    monkeypatch.setattr(replay, "claim", commit_then_fail)
    monkeypatch.setattr(audit, "append", append)
    monkeypatch.setattr(alerts, "insert", insert)
    body = body_for()
    session, connection = session_for(body, [])
    with pytest.raises(ProducerOrchestratorError, match="^replay_claim_ambiguous$") as error:
        orchestrator._process_session(session)

    assert error.value.code == "replay_claim_ambiguous"
    assert error.value.__suppress_context__
    assert orchestrator.fatal
    assert calls == [] and insert_calls == [] and alerts.list() == ()
    assert connection.closed and connection.writes == []
    assert gates.snapshot().released_count == 1
    assert len(admitted) == 1
    record = admitted[0]
    reopened = ProducerReplayJournal(
        tmp_path / "replay.sqlite3", service_generation_id=NEXT_GENERATION
    )
    retry = reopened.claim(record, claimed_at=NOW)
    assert retry.disposition == "in_progress"
    assert retry.claim is None and retry.cached_response is None
    with pytest.raises(ProducerOrchestratorError, match="^service_fatal$"):
        orchestrator.process_one()

    assert len(audit_attempts) == 1
    event = audit_attempts[0]
    assert (event.event_type, event.processing_stage, event.outcome, event.reason_code) == (
        "internal_failure",
        "internal",
        "failed",
        "internal_error",
    )
    assert event.correlation_id == record.correlation_id
    assert event.producer_id == record.producer_id == REGISTERED_UNSW_PRODUCER_ID
    assert event.source_contract_id == record.source_contract == REGISTERED_UNSW_SOURCE_CONTRACT
    assert event.credential_sha256 == record.credential_id == FINGERPRINT
    assert event.request_id_sha256 == hashlib.sha256(record.request_id.encode("ascii")).hexdigest()
    assert event.body_sha256 == record.body_sha256 == hashlib.sha256(body).hexdigest()
    assert audit.list() == (() if audit_fails else (event,))


def test_response_finalization_after_persistence_and_lease_release_failure_poison(
    tmp_path, monkeypatch
):
    response_failure, _, response_audit, alerts, _, _, _ = make_orchestrator(
        tmp_path / "response", plan={1: registered(1, "Attack")}
    )
    monkeypatch.setattr(
        orchestration,
        "serialize_producer_response",
        lambda response: (_ for _ in ()).throw(ProducerAdmissionError("response_invalid")),
    )
    with pytest.raises(ProducerOrchestratorError, match="^response_finalization_ambiguous$"):
        process(response_failure, body_for())
    assert response_failure.fatal and len(alerts.list()) == 1
    assert {event.event_type for event in response_audit.list()} == {
        "request_admitted",
        "internal_failure",
    }

    release_failure, _, _, _, gates, _, _ = make_orchestrator(tmp_path / "release")
    monkeypatch.setattr(
        gates,
        "release",
        lambda lease: (_ for _ in ()).throw(
            orchestration.ProducerExecutionGateError("lease_not_active")
        ),
    )
    with pytest.raises(ProducerOrchestratorError, match="^lease_release_failed$"):
        process(release_failure, body_for())
    assert release_failure.fatal


def test_failure_audit_failure_preserves_original_ambiguity(tmp_path, monkeypatch):
    orchestrator, _, audit, alerts, _, _, _ = make_orchestrator(
        tmp_path, plan={1: registered(1, "Attack")}
    )
    original_insert = alerts.insert
    original_append = audit.append

    def commit_then_fail(candidate):
        original_insert(candidate)
        raise AlertPersistenceError("database_write_failed")

    def fail_failure_audit(event):
        if event.event_type == "internal_failure":
            raise ProducerSecurityAuditError("audit_write_failed")
        return original_append(event)

    monkeypatch.setattr(alerts, "insert", commit_then_fail)
    monkeypatch.setattr(audit, "append", fail_failure_audit)
    with pytest.raises(ProducerOrchestratorError, match="^alert_persistence_ambiguous$") as error:
        process(orchestrator, body_for())
    assert "audit" not in str(error.value)
    assert orchestrator.fatal and len(alerts.list()) == 1


def test_connection_closes_when_replay_completion_and_lease_release_both_fail(
    tmp_path, monkeypatch
):
    orchestrator, replay, _, _, gates, _, _ = make_orchestrator(tmp_path)
    session, connection = session_for(body_for(), [])
    monkeypatch.setattr(
        replay,
        "complete",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            orchestration.ProducerReplayJournalError("journal_write_failed")
        ),
    )
    monkeypatch.setattr(
        gates,
        "release",
        lambda lease: (_ for _ in ()).throw(
            orchestration.ProducerExecutionGateError("lease_not_active")
        ),
    )
    with pytest.raises(ProducerOrchestratorError, match="^lease_release_failed$"):
        orchestrator._process_session(session)
    assert orchestrator.fatal and connection.closed
    assert connection.writes == []


def test_write_failure_after_replay_completion_retries_cached_without_effects(
    tmp_path, monkeypatch
):
    request_id = str(uuid4())
    body = body_for(request_id=request_id)
    replay_path = tmp_path / "replay.sqlite3"
    audit_path = tmp_path / "audit.sqlite3"
    alert_path = tmp_path / "alerts.sqlite3"
    orchestrator, _, _, alerts, gates, calls, _ = make_orchestrator(
        tmp_path,
        plan={1: registered(1, "Attack")},
        replay_path=replay_path,
        audit_path=audit_path,
        alert_path=alert_path,
    )
    session, connection = session_for(body, [])
    connection.fail_write = True
    first = orchestrator._process_session(session)
    assert first.reason == "response_write_failed"
    assert not orchestrator.fatal
    assert len(alerts.list()) == 1

    reopened, _, _, reopened_alerts, reopened_gates, reopened_calls, _ = make_orchestrator(
        tmp_path / "reopened",
        generation=NEXT_GENERATION,
        replay_path=replay_path,
        audit_path=audit_path,
        alert_path=alert_path,
    )
    monkeypatch.setattr(
        reopened_alerts,
        "insert",
        lambda candidate: pytest.fail("cached retry persisted an alert"),
    )
    retry, retry_connection = process(reopened, body)
    assert retry.response_bytes == first.response_bytes
    assert retry_connection.writes == [first.response_bytes]
    assert len(calls) == 1
    assert reopened_calls == []
    assert len(reopened_alerts.list()) == 1
    assert gates.snapshot().released_count == 1
    assert reopened_gates.snapshot().released_count == 1


def test_replay_completion_precedes_response_write(tmp_path, monkeypatch):
    orchestrator, replay, _, _, _, _, _ = make_orchestrator(tmp_path)
    trace: list[str] = []
    session, connection = session_for(body_for(), trace)
    original_complete = replay.complete

    def complete(*args, **kwargs):
        trace.append("complete")
        return original_complete(*args, **kwargs)

    monkeypatch.setattr(replay, "complete", complete)
    orchestrator._process_session(session)

    assert trace[-2:] == ["complete", "write"]


def test_lease_is_released_only_after_response_write_attempt(tmp_path, monkeypatch):
    orchestrator, _, _, _, gates, _, _ = make_orchestrator(tmp_path)
    trace: list[str] = []
    original_release = gates.release
    session, connection = session_for(body_for(), trace)
    original_write = connection.write_response

    def write(capability, response):
        snapshot = gates.snapshot()
        assert snapshot.global_active_count == snapshot.producer_active_count == 1
        return original_write(capability, response)

    def release(lease):
        trace.append("release")
        return original_release(lease)

    monkeypatch.setattr(connection, "write_response", write)
    monkeypatch.setattr(gates, "release", release)
    orchestrator._process_session(session)
    assert trace[-2:] == ["write", "release"]
    assert connection.closed
    assert gates.snapshot().global_active_count == gates.snapshot().producer_active_count == 0


def test_separate_sqlite_connections_have_one_concurrent_duplicate_winner(tmp_path):
    replay_path = tmp_path / "replay.sqlite3"
    audit_path = tmp_path / "audit.sqlite3"
    alert_path = tmp_path / "alerts.sqlite3"
    started = Event()
    release = Event()

    def held_result():
        started.set()
        assert release.wait(2)
        return registered(1)

    first, _, _, alerts, _, first_calls, _ = make_orchestrator(
        tmp_path / "first",
        plan={1: held_result},
        replay_path=replay_path,
        audit_path=audit_path,
        alert_path=alert_path,
    )
    second, _, _, _, _, second_calls, _ = make_orchestrator(
        tmp_path / "second",
        replay_path=replay_path,
        audit_path=audit_path,
        alert_path=alert_path,
    )
    body = body_for()
    with ThreadPoolExecutor(max_workers=2) as executor:
        winner = executor.submit(process, first, body)
        assert started.wait(2)
        duplicate = executor.submit(process, second, body).result(timeout=2)
        release.set()
        completed = winner.result(timeout=2)

    assert duplicate[0].reason == "request_in_progress"
    assert completed[0].reason == "request_completed"
    assert len(first_calls) == 1 and second_calls == []
    assert alerts.list() == ()


def test_reopen_returns_completed_cached_response_without_inference(tmp_path):
    replay_path = tmp_path / "replay.sqlite3"
    audit_path = tmp_path / "audit.sqlite3"
    alert_path = tmp_path / "alerts.sqlite3"
    body = body_for()
    first, _, _, _, _, calls, _ = make_orchestrator(
        tmp_path / "first",
        replay_path=replay_path,
        audit_path=audit_path,
        alert_path=alert_path,
    )
    completed, _ = process(first, body)
    reopened, _, _, _, _, reopened_calls, _ = make_orchestrator(
        tmp_path / "reopened",
        generation=NEXT_GENERATION,
        replay_path=replay_path,
        audit_path=audit_path,
        alert_path=alert_path,
    )
    retry, _ = process(reopened, body)
    assert retry.response_bytes == completed.response_bytes
    assert len(calls) == 1 and reopened_calls == []


def test_processing_timeout_after_inference_is_cached_without_persistence(tmp_path):
    orchestrator, _, _, alerts, _, _, clock = make_orchestrator(tmp_path)

    def slow():
        clock.value += 31.0
        return registered(1)

    orchestrator._inference.infer_registered = MethodType(
        lambda self, **kwargs: slow(), orchestrator._inference
    )
    result, _ = process(orchestrator, body_for())
    assert result.reason == "processing_timeout"
    assert alerts.list() == ()
    assert not orchestrator.fatal


def test_processing_timeout_wins_when_slow_inference_raises_known_rejection(tmp_path):
    orchestrator, _, _, alerts, _, calls, clock = make_orchestrator(
        tmp_path, plan={1: registered(1)}
    )

    def slow_rejection():
        clock.value += 31.0
        raise orchestration.NetworkInferenceError("registered_event_rejected")

    orchestrator._inference.infer_registered = MethodType(
        lambda self, **kwargs: (calls.append(tuple(kwargs.values())), slow_rejection())[1],
        orchestrator._inference,
    )
    result, connection = process(orchestrator, body_for())

    assert result.reason == "processing_timeout"
    assert decoded(connection).records == ()
    assert len(calls) == 1
    assert alerts.list() == ()
    assert not orchestrator.fatal


def test_finalization_timeout_after_persistence_poisoned_and_cannot_process_again(
    tmp_path, monkeypatch
):
    rows = tuple(range(1, 12))
    plan = {row: registered(row, "Attack" if row == rows[-1] else "Normal") for row in rows}
    replay_path = tmp_path / "replay.sqlite3"
    audit_path = tmp_path / "audit.sqlite3"
    alert_path = tmp_path / "alerts.sqlite3"
    orchestrator, _, audit, alerts, _, calls, clock = make_orchestrator(
        tmp_path,
        plan=plan,
        replay_path=replay_path,
        audit_path=audit_path,
        alert_path=alert_path,
    )
    original_infer = orchestrator._inference.infer_registered
    original_append = audit.append

    def infer(**kwargs):
        result = original_infer(**kwargs)
        clock.value += 27
        return result

    def append(event):
        result = original_append(event)
        if event.event_type == "request_completed":
            clock.value += 4
        return result

    monkeypatch.setattr(orchestrator._inference, "infer_registered", infer)
    monkeypatch.setattr(audit, "append", append)
    body = body_for(rows=rows)
    session, connection = session_for(body, [])
    orchestrator._transport.accept_authenticated = MethodType(
        lambda self, registry, *, trusted_now: session,
        orchestrator._transport,
    )
    with pytest.raises(ProducerOrchestratorError, match="^processing_timeout$"):
        orchestrator.process_one()
    assert orchestrator.fatal and len(alerts.list()) == 1
    assert connection.closed and connection.writes == []
    assert {event.event_type for event in audit.list()} == {
        "request_admitted",
        "request_completed",
        "internal_failure",
    }
    with pytest.raises(ProducerOrchestratorError, match="^service_fatal$"):
        orchestrator.process_one()
    assert len(calls) == len(rows)

    restarted, _, _, restarted_alerts, _, restarted_calls, _ = make_orchestrator(
        tmp_path / "restarted",
        generation=NEXT_GENERATION,
        replay_path=replay_path,
        audit_path=audit_path,
        alert_path=alert_path,
    )
    assert restarted.recover_abandoned_generation(GENERATION) == 1
    outcome, _ = process(restarted, body)
    assert outcome.reason == "outcome_unknown"
    assert restarted_calls == [] and len(restarted_alerts.list()) == 1


def test_explicit_recovery_only_and_recovery_audit_failure_poison(tmp_path, monkeypatch):
    path = tmp_path / "replay.sqlite3"
    old, old_replay, _, _, _, _, _ = make_orchestrator(
        tmp_path / "old", replay_path=path, generation=GENERATION
    )
    body = body_for()
    session, connection = session_for(body, [])
    monkeypatch.setattr(
        old._audit,
        "append",
        lambda event: (_ for _ in ()).throw(ProducerSecurityAuditError("audit_write_failed")),
    )
    old._process_session(session)
    assert old.fatal and connection.closed

    restarted, _, audit, _, _, _, _ = make_orchestrator(
        tmp_path / "new", replay_path=path, generation=NEXT_GENERATION
    )
    # Construction/opening alone does not infer abandonment.
    assert old_replay.service_generation_id == GENERATION
    assert restarted.recover_abandoned_generation(GENERATION) == 1
    assert audit.list()[0].event_type == "startup_recovery"

    failing, _, failing_audit, _, _, _, _ = make_orchestrator(
        tmp_path / "failing",
        replay_path=tmp_path / "other-replay.sqlite3",
        generation=NEXT_GENERATION,
    )
    monkeypatch.setattr(
        failing_audit,
        "append",
        lambda event: (_ for _ in ()).throw(ProducerSecurityAuditError("audit_write_failed")),
    )
    assert (
        failing._replay.recover_abandoned_generation(
            abandoned_generation_id=GENERATION, recovered_at=NOW
        )
        == 0
    )
    with pytest.raises(ProducerOrchestratorError, match="^audit_unavailable$"):
        failing.recover_abandoned_generation(GENERATION)
    assert failing.fatal


def test_response_contract_preserves_legacy_bytes_and_bounds_new_fields():
    legacy = (
        b'{"correlation_id":"11111111-1111-4111-8111-111111111111",'
        b'"reason":"request_completed","records":[],"schema_version":'
        b'"producer_ingest_response_v1"}\n'
    )
    assert orchestration.serialize_reason(legacy) == "request_completed"
    enriched_item = orchestration.ProducerRecordDisposition(
        1,
        "created",
        "alert_candidate_created",
        "Attack",
        0.75,
        "alert_candidate_v1:" + "f" * 64,
    )
    with pytest.raises(ProducerAdmissionError, match="^response_invalid$"):
        orchestration.ProducerResponse(
            "producer_ingest_response_v1",
            "11111111-1111-4111-8111-111111111111",
            "request_completed",
            (enriched_item,),
        )
    items = tuple(
        orchestration.ProducerRecordDisposition(
            index,
            "created",
            "alert_candidate_created",
            "Attack",
            0.75,
            "alert_candidate_v1:" + "f" * 64,
        )
        for index in range(1, 257)
    )
    response = orchestration.ProducerResponse(
        "producer_ingest_response_v2",
        "11111111-1111-4111-8111-111111111111",
        "request_completed",
        items,
    )
    enriched = orchestration.serialize_producer_response(response)
    assert len(enriched) < 65_536
    assert len(decode_producer_response(enriched).records) == 256
    exact = legacy + b" " * (65_536 - len(legacy))
    assert len(exact) == 65_536
    assert decode_producer_response(exact).reason == "request_completed"
    with pytest.raises(ProducerAdmissionError, match="^response_invalid$"):
        decode_producer_response(exact + b" ")


@pytest.mark.parametrize(
    "record",
    [
        {
            "record_index": 1,
            "disposition": "rejected",
            "reason": "inference_rejected",
        },
        {
            "record_index": 1,
            "disposition": "not_actionable",
            "reason": "inference_not_actionable",
            "predicted_class": None,
            "attack_probability": None,
            "alert_candidate_id": None,
        },
    ],
)
def test_legacy_response_rejects_v2_record_reason_and_keys(record):
    payload = {
        "schema_version": "producer_ingest_response_v1",
        "correlation_id": "11111111-1111-4111-8111-111111111111",
        "reason": "request_completed",
        "records": [record],
    }
    encoded = json.dumps(payload, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(ProducerAdmissionError, match="^response_invalid$"):
        decode_producer_response(encoded)


@pytest.mark.parametrize("records", [None, (None,), (object(),)])
def test_response_constructor_sanitizes_invalid_record_containers(records):
    with pytest.raises(ProducerAdmissionError, match="^response_invalid$"):
        orchestration.ProducerResponse(
            "producer_ingest_response_v2",
            "11111111-1111-4111-8111-111111111111",
            "request_rejected",
            records,
        )


@pytest.mark.parametrize(
    "payload",
    [
        {
            "schema_version": [],
            "correlation_id": "11111111-1111-4111-8111-111111111111",
            "reason": "request_rejected",
            "records": [],
        },
        {
            "schema_version": "producer_ingest_response_v2",
            "correlation_id": "11111111-1111-4111-8111-111111111111",
            "reason": "request_completed",
            "records": [
                {
                    "record_index": 1,
                    "disposition": "not_actionable",
                    "reason": "inference_not_actionable",
                    "predicted_class": [],
                    "attack_probability": 0.25,
                }
            ],
        },
    ],
)
def test_response_decoder_sanitizes_unhashable_versioned_fields(payload):
    encoded = json.dumps(payload, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(ProducerAdmissionError, match="^response_invalid$"):
        decode_producer_response(encoded)


def test_dependencies_are_exact_and_setup_precedes_listener_open(tmp_path):
    values = make_orchestrator(tmp_path)
    valid = values[0]
    assert valid.fatal is False
    with pytest.raises(ProducerOrchestratorError, match="^orchestrator_configuration_invalid$"):
        ProducerOrchestrator(
            transport=object(),
            certificate_registry=valid._registry,
            execution_gates=valid._gates,
            replay_journal=valid._replay,
            security_audit=valid._audit,
            inference_boundary=valid._inference,
            alert_repository=valid._alerts,
        )

    valid._inference._predictor.audit_provenance["automatic_fallback"] = True
    with pytest.raises(ProducerOrchestratorError, match="^orchestrator_configuration_invalid$"):
        ProducerOrchestrator(
            transport=valid._transport,
            certificate_registry=valid._registry,
            execution_gates=valid._gates,
            replay_journal=valid._replay,
            security_audit=valid._audit,
            inference_boundary=valid._inference,
            alert_repository=valid._alerts,
        )


def test_sanitized_output_has_no_submitted_or_internal_sensitive_values(tmp_path):
    secret = "/private/secret SELECT token 192.0.2.1"
    orchestrator, _, audit, _, _, _, _ = make_orchestrator(tmp_path)
    result, _ = process(orchestrator, secret.encode())
    rendered = f"{result!r} {result.response_bytes!r} {audit.list()!r}"
    assert secret not in rendered
    for fragment in ("/private", "SELECT", "192.0.2.1"):
        assert fragment not in rendered


def test_no_feature_vector_cic_unknown_source_or_model_selection_interface(tmp_path):
    orchestrator, _, _, _, _, _, _ = make_orchestrator(tmp_path)
    assert not hasattr(orchestrator, "infer")
    assert not hasattr(orchestrator, "model")
    cic, connection = process(
        orchestrator,
        body_for(source_contract="cic_registered_event_ref_v1"),
    )
    assert cic.reason == "request_rejected"
    assert decoded(connection).records == ()
    assert "logistic_regression" not in orchestration.__dict__.values()


def test_artifact_hash_constants_are_not_mutated():
    from threatfusion.models.network_inference import (
        APPROVED_MODEL_HASHES,
        APPROVED_PREPROCESSING_HASHES,
    )

    assert APPROVED_MODEL_HASHES["random_forest"]["model"] == (
        "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"
    )
    assert APPROVED_PREPROCESSING_HASHES == {
        "state": "30c955e3931dc010f8b4391a80fc0fbeddd17e14260701c8131d88f95b06ee49",
        "configuration": "70273ec360e0bce88b5ec8311df4b5b8ccbbdbe6c456d8a679528563d477645a",
        "report": "d1688079b9cbcf521a8b9938ea07b540321e11edd70236452720fbd2f1697e4a",
    }
