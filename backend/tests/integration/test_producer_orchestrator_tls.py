"""Bounded real-mTLS integration evidence for the synchronous producer orchestrator."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import ssl
import csv
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Queue
from threading import Thread
from types import MethodType, SimpleNamespace
from uuid import uuid4

import pytest
import yaml

from backend.tests.unit.test_producer_tls_transport import _issue_ca, _issue_certificate
from backend.tests.unit.test_unsw_inference_binding import RAW_NAMES, PredictorSpy, raw_row
import threatfusion.models.network_inference as network_inference
from threatfusion.api.producer_admission import (
    PRODUCER_INGEST_REQUEST_SCHEMA_VERSION,
    REGISTERED_UNSW_PRODUCER_ID,
    REGISTERED_UNSW_PRODUCER_TYPE,
    REGISTERED_UNSW_SOURCE_CONTRACT,
    REGISTERED_UNSW_URI_SAN,
    CertificateRegistry,
    CertificateRegistryRecord,
    decode_producer_response,
)
from threatfusion.api.producer_execution_gates import ProducerExecutionGates
from threatfusion.api.producer_orchestrator import (
    ProducerOrchestrator,
    ProducerOrchestratorError,
)
from threatfusion.api.producer_tls_transport import (
    TRANSPORT_HOST,
    TRANSPORT_HTTP_VERSION,
    TRANSPORT_REQUEST_METHOD,
    TRANSPORT_REQUEST_TARGET,
    ProducerTlsConfiguration,
    ProducerTlsListener,
)
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.producer_replay_journal import (
    ProducerReplayJournal,
    ProducerReplayJournalError,
)
from threatfusion.db.producer_security_audit import (
    ProducerSecurityAuditError,
    ProducerSecurityAuditRepository,
)
from threatfusion.models.network_inference import (
    APPROVED_MODEL_HASHES,
    APPROVED_PREPROCESSING_HASHES,
    NetworkInferenceResult,
    RegisteredUnswInferenceResult,
    UnswNetworkInferenceBoundary,
    default_artifact_directories,
)
from threatfusion.preprocessing.network_behavior_v1 import NetworkBehaviorPreprocessor
from threatfusion.schemas.alert_candidate import derive_source_event_id

NOW = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
MEMBER = "7d851bbeabd27894ce39c8e78835c73341fc946652fb7743b9eff193b55eb511"
GENERATION_ONE = "11111111-1111-4111-8111-111111111111"
GENERATION_TWO = "22222222-2222-4222-8222-222222222222"
PROJECT_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    root = tmp_path_factory.mktemp("producer-orchestrator-mtls")
    ca, ca_key = _issue_ca(root, "integration")
    server = _issue_certificate(
        root, "server", ca, ca_key, purpose="serverAuth", san="DNS:localhost"
    )
    good = _issue_certificate(
        root,
        "good-client",
        ca,
        ca_key,
        purpose="clientAuth",
        san=f"URI:{REGISTERED_UNSW_URI_SAN}",
    )
    unknown = _issue_certificate(
        root,
        "unknown-client",
        ca,
        ca_key,
        purpose="clientAuth",
        san=f"URI:{REGISTERED_UNSW_URI_SAN}",
    )
    yield {"root": root, "ca": ca, "server": server, "good": good, "unknown": unknown}
    shutil.rmtree(root)
    assert not root.exists()


def _fingerprint(certificate: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))
    return hashlib.sha256(der).hexdigest()


def _registry(certificates) -> CertificateRegistry:
    return CertificateRegistry(
        (
            CertificateRegistryRecord(
                REGISTERED_UNSW_PRODUCER_ID,
                REGISTERED_UNSW_PRODUCER_TYPE,
                REGISTERED_UNSW_URI_SAN,
                _fingerprint(certificates["good"][0]),
                True,
                False,
                NOW - timedelta(days=1),
                NOW + timedelta(days=1),
                (REGISTERED_UNSW_SOURCE_CONTRACT,),
            ),
        )
    )


def _client_context(certificates, client: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=certificates["ca"])
    context.load_cert_chain(*certificates[client])
    return context


def _body(
    *,
    rows: tuple[int, ...] = (1,),
    references: tuple[tuple[str, int], ...] | None = None,
    request_id: str | None = None,
    nonce: str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    producer_id: str = REGISTERED_UNSW_PRODUCER_ID,
    member: str = MEMBER,
) -> bytes:
    return json.dumps(
        {
            "schema_version": PRODUCER_INGEST_REQUEST_SCHEMA_VERSION,
            "producer_id": producer_id,
            "request_id": request_id or str(uuid4()),
            "produced_at": "2026-09-13T12:00:00Z",
            "nonce": nonce,
            "source_contract": REGISTERED_UNSW_SOURCE_CONTRACT,
            "records": [
                {"source_member_sha256": selected_member, "row_number": row}
                for selected_member, row in (
                    references if references is not None else tuple((member, row) for row in rows)
                )
            ],
        },
        separators=(",", ":"),
    ).encode("ascii")


def _request_wire(body: bytes) -> bytes:
    head = (
        f"{TRANSPORT_REQUEST_METHOD} {TRANSPORT_REQUEST_TARGET} {TRANSPORT_HTTP_VERSION}\r\n"
        f"Host: {TRANSPORT_HOST}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    return head + body


def _registered(row: int, predicted_class: str) -> RegisteredUnswInferenceResult:
    probability = 0.8 if predicted_class == "Attack" else 0.2
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
            predicted_class=predicted_class,
            status="completed",
            reason="inference_succeeded",
            processed_at=NOW.isoformat(),
            latency_ms=0.0,
        ),
    )


def _controlled_boundary(
    outcomes: dict[int, str], calls: list[tuple[str, int, object]]
) -> UnswNetworkInferenceBoundary:
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
        return _registered(row_number, outcomes[row_number])

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


def _registered_binding_boundary(root: Path, monkeypatch):
    """Create a real registered-source/adapter boundary with a final model spy."""
    project = root / "registered-project"
    project.mkdir()
    metadata = b"No.,Name,Type,Description\n" + b"".join(
        f"{index},{name},type,fixture\n".encode() for index, name in enumerate(RAW_NAMES, 1)
    )
    (project / "NUSW-NB15_features.csv").write_bytes(metadata)
    raw_path = project / "UNSW-NB15_1.csv"
    with raw_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(raw_row())
        writer.writerow(raw_row(dur="malformed"))
    raw_bytes = raw_path.read_bytes()
    manifest = yaml.safe_dump(
        {
            "name": "unsw_nb15",
            "version": "fixture",
            "license_note": "fixture",
            "files": [
                {
                    "path": "NUSW-NB15_features.csv",
                    "role": "raw",
                    "rows": 49,
                    "sha256": hashlib.sha256(metadata).hexdigest(),
                },
                {
                    "path": "UNSW-NB15_1.csv",
                    "role": "raw",
                    "rows": 2,
                    "sha256": hashlib.sha256(raw_bytes).hexdigest(),
                },
            ],
        }
    ).encode()
    manifest_path = project / "data/manifests/unsw_nb15.yaml"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_bytes(manifest)
    spy = PredictorSpy()
    monkeypatch.setattr(
        network_inference, "APPROVED_UNSW_MANIFEST_HASH", hashlib.sha256(manifest).hexdigest()
    )
    monkeypatch.setattr(network_inference, "_preprocessing_snapshot", lambda path: {})
    monkeypatch.setattr(network_inference, "_model_snapshot", lambda path, choice: {})
    monkeypatch.setattr(
        network_inference,
        "_verify_preprocessor",
        lambda snapshot: NetworkBehaviorPreprocessor(1, (0.0,) * 10, (1.0,) * 10, ()),
    )
    monkeypatch.setattr(
        network_inference,
        "_verify_model",
        lambda snapshot, choice: network_inference._LoadedModel(spy, choice.value, "fixture_v1"),
    )
    return (
        UnswNetworkInferenceBoundary(project_root=project),
        spy,
        hashlib.sha256(raw_bytes).hexdigest(),
    )


@dataclass
class _Service:
    orchestrator: ProducerOrchestrator
    listener: ProducerTlsListener
    replay: ProducerReplayJournal
    audit: ProducerSecurityAuditRepository
    alerts: AlertCandidateRepository
    gates: ProducerExecutionGates

    def close(self) -> None:
        self.orchestrator.close()
        assert self.listener._listener is None
        snapshot = self.gates.snapshot()
        assert snapshot.global_active_count == snapshot.producer_active_count == 0


def _make_service(
    root: Path,
    certificates,
    boundary: UnswNetworkInferenceBoundary,
    *,
    generation: str = GENERATION_ONE,
    worker: bool = False,
) -> _Service:
    listener = ProducerTlsListener(
        ProducerTlsConfiguration(
            server_certificate_path=certificates["server"][0],
            server_private_key_path=certificates["server"][1],
            client_ca_path=certificates["ca"],
        )
    )
    replay = ProducerReplayJournal(root / "replay.sqlite3", service_generation_id=generation)
    audit = ProducerSecurityAuditRepository(root / "audit.sqlite3")
    alerts = AlertCandidateRepository(root / "alerts.sqlite3")
    gates = ProducerExecutionGates()
    orchestrator = ProducerOrchestrator(
        transport=listener,
        certificate_registry=_registry(certificates),
        execution_gates=gates,
        replay_journal=replay,
        security_audit=audit,
        inference_boundary=boundary,
        alert_repository=alerts,
        trusted_now=lambda: NOW,
        _test_inference_mode=None if worker else "inline_registered_inference",
    )
    orchestrator.open()
    return _Service(orchestrator, listener, replay, audit, alerts, gates)


@contextmanager
def _runtime(tmp_path: Path):
    root = tmp_path / "runtime"
    root.mkdir()
    try:
        yield root
    finally:
        assert not tuple(root.glob("*.sqlite3-wal"))
        assert not tuple(root.glob("*.sqlite3-shm"))
        shutil.rmtree(root)
        assert not root.exists()


def _exchange(service: _Service, certificates, body: bytes, *, client: str = "good"):
    outcome: Queue[object] = Queue(maxsize=1)

    def process_one() -> None:
        try:
            outcome.put(service.orchestrator.process_one())
        except BaseException as error:
            outcome.put(error)

    thread = Thread(target=process_one, name="producer-orchestrator-integration")
    thread.start()
    chunks: list[bytes] = []
    negotiated = None
    try:
        raw = socket.create_connection(service.listener.address, timeout=2)
        with _client_context(certificates, client).wrap_socket(
            raw, server_hostname="localhost"
        ) as connection:
            negotiated = connection.version()
            connection.settimeout(30)
            connection.sendall(_request_wire(body))
            while True:
                try:
                    chunk = connection.recv(65_536)
                except ssl.SSLError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
    finally:
        thread.join(35)
    assert not thread.is_alive()
    assert negotiated == "TLSv1.3"
    return b"".join(chunks), outcome.get_nowait()


def _response(wire: bytes):
    head, body = wire.split(b"\r\n\r\n", 1)
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    assert f"Content-Length: {len(body)}".encode("ascii") in head.split(b"\r\n")
    assert b"Connection: close" in head.split(b"\r\n")
    return status, body, decode_producer_response(body)


def test_authenticated_mixed_outcomes_use_real_tls_and_attack_only_sqlite(
    tmp_path, certificates, monkeypatch
):
    calls: list[tuple[str, int, object]] = []
    with _runtime(tmp_path) as root:
        service = _make_service(
            root, certificates, _controlled_boundary({1: "Normal", 2: "Attack"}, calls)
        )
        insert_calls = 0
        original_insert = service.alerts.insert

        def insert(candidate):
            nonlocal insert_calls
            insert_calls += 1
            return original_insert(candidate)

        monkeypatch.setattr(service.alerts, "insert", insert)
        try:
            wire, result = _exchange(service, certificates, _body(rows=(1, 2)))
            status, body, response = _response(wire)
            assert status == 200
            assert result.response_bytes == body
            assert [record.predicted_class for record in response.records] == ["Normal", "Attack"]
            assert [record.disposition for record in response.records] == [
                "not_actionable",
                "created",
            ]
            assert response.records[0].alert_candidate_id is None
            assert (
                response.records[1].alert_candidate_id
                == service.alerts.list()[0].alert_candidate_id
            )
            assert len(calls) == 2 and insert_calls == 1 and len(service.alerts.list()) == 1
            assert sorted(event.event_type for event in service.audit.list()) == [
                "request_admitted",
                "request_completed",
            ]
        finally:
            service.close()


def test_completed_retry_after_repository_reopen_is_exactly_cached(
    tmp_path, certificates, monkeypatch
):
    body = _body(request_id=str(uuid4()))
    first_calls: list[tuple[str, int, object]] = []
    retry_calls: list[tuple[str, int, object]] = []
    with _runtime(tmp_path) as root:
        first = _make_service(root, certificates, _controlled_boundary({1: "Attack"}, first_calls))
        insert_calls = 0
        original_insert = first.alerts.insert

        def insert(candidate):
            nonlocal insert_calls
            insert_calls += 1
            return original_insert(candidate)

        monkeypatch.setattr(first.alerts, "insert", insert)
        try:
            first_wire, first_result = _exchange(first, certificates, body)
            assert _response(first_wire)[0] == 200
            assert len(first.alerts.list()) == 1
        finally:
            first.close()

        reopened = _make_service(
            root,
            certificates,
            _controlled_boundary({1: "Attack"}, retry_calls),
            generation=GENERATION_TWO,
        )
        reopened_original_insert = reopened.alerts.insert

        def retry_insert(candidate):
            nonlocal insert_calls
            insert_calls += 1
            return reopened_original_insert(candidate)

        monkeypatch.setattr(reopened.alerts, "insert", retry_insert)
        try:
            retry_wire, retry_result = _exchange(reopened, certificates, body)
            _, retry_body, _ = _response(retry_wire)
            assert retry_body == first_result.response_bytes == retry_result.response_bytes
            assert len(first_calls) == 1 and retry_calls == []
            assert insert_calls == 1 and len(reopened.alerts.list()) == 1
        finally:
            reopened.close()


def test_authentication_admission_and_preinference_audit_rejections_have_zero_effects(
    tmp_path, certificates, monkeypatch
):
    for case in ("authentication", "admission", "audit"):
        root = tmp_path / case
        root.mkdir()
        calls: list[tuple[str, int, object]] = []
        service = _make_service(root, certificates, _controlled_boundary({1: "Attack"}, calls))
        insert_calls = 0
        original_insert = service.alerts.insert

        def insert(candidate):
            nonlocal insert_calls
            insert_calls += 1
            return original_insert(candidate)

        monkeypatch.setattr(service.alerts, "insert", insert)
        if case == "audit":
            original_append = service.audit.append

            def append(event):
                if event.event_type == "request_admitted":
                    raise ProducerSecurityAuditError("audit_write_failed")
                return original_append(event)

            monkeypatch.setattr(service.audit, "append", append)
        try:
            selected_client = "unknown" if case == "authentication" else "good"
            producer = "wrong-producer" if case == "admission" else REGISTERED_UNSW_PRODUCER_ID
            wire, result = _exchange(
                service, certificates, _body(producer_id=producer), client=selected_client
            )
            if case == "authentication":
                assert wire == b""
                assert isinstance(result, ProducerOrchestratorError)
                assert result.code == "authentication_rejected"
            else:
                status, _, response = _response(wire)
                assert response.reason == (
                    "request_rejected" if case == "admission" else "audit_unavailable"
                )
                assert status == (400 if case == "admission" else 503)
            assert calls == [] and insert_calls == 0 and service.alerts.list() == ()
            assert service.gates.snapshot().released_count == (1 if case == "audit" else 0)
        finally:
            service.close()
            assert not tuple(root.glob("*.sqlite3-wal"))
            assert not tuple(root.glob("*.sqlite3-shm"))
            shutil.rmtree(root)
            assert not root.exists()


def test_replay_completion_failure_sends_no_success(tmp_path, certificates, monkeypatch):
    calls: list[tuple[str, int, object]] = []
    with _runtime(tmp_path) as root:
        service = _make_service(root, certificates, _controlled_boundary({1: "Normal"}, calls))
        monkeypatch.setattr(
            service.replay,
            "complete",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                ProducerReplayJournalError("journal_write_failed")
            ),
        )
        try:
            wire, result = _exchange(service, certificates, _body())
            assert wire == b""
            assert isinstance(result, ProducerOrchestratorError)
            assert result.code == "replay_completion_ambiguous"
            assert service.orchestrator.fatal
            assert len(calls) == 1 and service.alerts.list() == ()
            assert service.gates.snapshot().released_count == 1
        finally:
            service.close()


@pytest.mark.parametrize("later_reference", ["invalid_ordinal", "unknown_member", "malformed_row"])
def test_real_registered_binding_rejects_invalid_later_reference_before_prediction(
    tmp_path, certificates, monkeypatch, later_reference
):
    with _runtime(tmp_path) as root:
        boundary, predictor, member = _registered_binding_boundary(root, monkeypatch)
        service = _make_service(root, certificates, boundary)
        insert_calls = 0
        original_insert = service.alerts.insert

        def insert(candidate):
            nonlocal insert_calls
            insert_calls += 1
            return original_insert(candidate)

        monkeypatch.setattr(service.alerts, "insert", insert)
        try:
            second = {
                "invalid_ordinal": (member, 3),
                "unknown_member": ("f" * 64, 1),
                "malformed_row": (member, 2),
            }[later_reference]
            body = _body(references=((member, 1), second))
            wire, result = _exchange(service, certificates, body)
            status, body, response = _response(wire)
            assert status == 200
            assert result.response_bytes == body
            assert [record.disposition for record in response.records] == [
                "rejected",
                "rejected",
            ]
            assert predictor.calls == [] and insert_calls == 0
            assert service.alerts.list() == ()
        finally:
            service.close()


def test_frozen_registered_unsw_smoke_uses_real_tls_orchestrator_path(tmp_path, certificates):
    preprocessing, logistic, forest = default_artifact_directories(PROJECT_ROOT)
    required = [
        PROJECT_ROOT / "data/manifests/unsw_nb15.yaml",
        PROJECT_ROOT / "data/raw/unsw_nb15/official/NUSW-NB15_features.csv",
        PROJECT_ROOT / "data/raw/unsw_nb15/official/UNSW-NB15_1.csv",
        preprocessing / "preprocessor_state.json",
        preprocessing / "preprocessing_config.json",
        preprocessing / "preprocessing_report.json",
        logistic / "logistic_regression.joblib",
        logistic / "model_config.json",
        logistic / "evaluation_report.json",
        forest / "random_forest.joblib",
        forest / "model_config.json",
        forest / "evaluation_report.json",
    ]
    if any(not path.is_file() for path in required):
        pytest.skip("configured frozen artifacts or registered UNSW inputs are unavailable")

    boundary = UnswNetworkInferenceBoundary(project_root=PROJECT_ROOT)
    assert boundary.audit_provenance["preprocessing_hashes"] == APPROVED_PREPROCESSING_HASHES
    assert boundary.audit_provenance["model_hashes"] == APPROVED_MODEL_HASHES
    with _runtime(tmp_path) as root:
        service = _make_service(root, certificates, boundary, worker=True)
        try:
            wire, result = _exchange(service, certificates, _body(member=MEMBER))
            status, body, response = _response(wire)
            assert status == 200
            assert result.response_bytes == body
            assert response.reason == "request_completed"
            assert len(response.records) == 1
            record = response.records[0]
            assert record.predicted_class in {"Normal", "Attack"}
            assert (record.alert_candidate_id is not None) == (record.predicted_class == "Attack")
            assert len(service.alerts.list()) == (1 if record.predicted_class == "Attack" else 0)
            assert service.orchestrator.worker_completed_record_count == 1
            worker_pid = service.orchestrator._worker.last_worker_pid
            assert worker_pid is not None
            with pytest.raises(ProcessLookupError):
                os.kill(worker_pid, 0)
        finally:
            service.close()
