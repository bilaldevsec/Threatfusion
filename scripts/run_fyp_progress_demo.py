"""Run the bounded FYP-II recorded-UNSW demonstration."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import socket
import ssl
import subprocess
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Empty, Queue
from tempfile import TemporaryDirectory
from threading import Thread
from types import MethodType
from uuid import uuid4

import numpy as np

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.api.producer_admission import (  # noqa: E402
    PRODUCER_INGEST_REQUEST_SCHEMA_VERSION,
    REGISTERED_UNSW_PRODUCER_ID,
    REGISTERED_UNSW_PRODUCER_TYPE,
    REGISTERED_UNSW_SOURCE_CONTRACT,
    REGISTERED_UNSW_URI_SAN,
    CertificateRegistry,
    CertificateRegistryRecord,
    ProducerAdmissionError,
    decode_producer_response,
)
from threatfusion.api.producer_execution_gates import ProducerExecutionGates  # noqa: E402
from threatfusion.api.producer_orchestrator import (  # noqa: E402
    ProducerOrchestrator,
    ProducerOrchestratorError,
    ProducerOrchestratorResult,
)
from threatfusion.api.producer_tls_transport import (  # noqa: E402
    TRANSPORT_HOST,
    TRANSPORT_HTTP_VERSION,
    TRANSPORT_REQUEST_METHOD,
    TRANSPORT_REQUEST_TARGET,
    ProducerTlsConfiguration,
    ProducerTlsListener,
)
from threatfusion.db.alert_repository import AlertCandidateRepository  # noqa: E402
from threatfusion.db.producer_replay_journal import ProducerReplayJournal  # noqa: E402
from threatfusion.db.producer_security_audit import (  # noqa: E402
    ProducerSecurityAuditRepository,
)
from threatfusion.models.network_autoencoder import (  # noqa: E402
    SCORING_CONTRACT_VERSION,
    TrustedAutoencoderBundle,
    _load_verified_autoencoder_detector,
    configure_deterministic_cpu_runtime,
)
from threatfusion.models.network_inference import (  # noqa: E402
    APPROVED_MODEL_HASHES,
    APPROVED_PREPROCESSING_HASHES,
    NetworkInferenceError,
    UnswNetworkInferenceBoundary,
    _feature_record,
)

PROJECT_ROOT = SOURCE_ROOT.parents[1]
OUTPUT_DIRECTORY = PROJECT_ROOT / "artifacts/reports/fyp_progress_demo/latest"
OUTPUT_FILENAME = "evidence.json"
MEMBER_SHA256 = "7d851bbeabd27894ce39c8e78835c73341fc946652fb7743b9eff193b55eb511"
V2_ARTIFACT_IDENTITY = "bdb7fc33d5b092566995018b5f83aa66bdb8ce95841d6b8b9021111c9a392a9a"
V2_DIRECTORY = (
    PROJECT_ROOT / "artifacts/models/network_autoencoder/full-benign-autoencoder-2a51c94-v2"
)

# These are independently pinned research/demo expectations. They do not add the
# experimental identity to the product loader's approved registry.
V2_FILE_HASHES = {
    "artifact_manifest.json": "c142d3352b406a689b6317f48ae513540076b02ffb2e0fdef9cd3e6a83da1866",
    "autoencoder_config.json": "51d4d664b5e017c5b039a08dc897d63e81a0b1e140eb1bb16457997ffa0727c2",
    "autoencoder_state.pt": "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23",
    "evaluation_report.json": "0ec77eda4a58e40e1b75087bbc5131f39cad54d553771e174ea303bc506c3bef",
    "network_autoencoder.snapshot.py": (
        "bcd2f8077de6cd9edeb3902aea5cb9a64f089111d7233aa6f94ee0257a1542c9"
    ),
    "network_autoencoder_protocol.snapshot.md": (
        "7ebd76b094f48303e45b40c6ff42bbfdbae1256e24c41a265bed6187466be78e"
    ),
    "source_provenance_manifest.json": (
        "d412f390f0d081170917a2e784046239f3e5b14d9a604e1196d2e3cbd3c527a9"
    ),
    "threshold.json": "79bc7f3def3a4ed745fbc85d9cbf36a04f4fb4384de4db065569f81f60c78e3e",
    "train_network_autoencoder.snapshot.py": (
        "1e85861ced0f341598f697387c2826ffdc31ad41d0516755ddff77850a6f6a54"
    ),
}
V2_TRUSTED_BUNDLE = TrustedAutoencoderBundle(
    scoring_contract_version=SCORING_CONTRACT_VERSION,
    configuration_sha256=V2_FILE_HASHES["autoencoder_config.json"],
    model_state_sha256=V2_FILE_HASHES["autoencoder_state.pt"],
    threshold_sha256=V2_FILE_HASHES["threshold.json"],
    manifest_sha256=V2_FILE_HASHES["artifact_manifest.json"],
    report_sha256=V2_FILE_HASHES["evaluation_report.json"],
)


@dataclass(frozen=True, slots=True)
class DemoExample:
    row_number: int
    known_label: str


DEMO_EXAMPLES = (
    DemoExample(1, "Normal"),
    DemoExample(21, "Attack"),
)


class DemoError(RuntimeError):
    """Sanitized demonstration failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(slots=True)
class _DemoService:
    orchestrator: ProducerOrchestrator
    listener: ProducerTlsListener
    alerts: AlertCandidateRepository
    audit: ProducerSecurityAuditRepository
    gates: ProducerExecutionGates

    def close(self) -> None:
        self.orchestrator.close()
        snapshot = self.gates.snapshot()
        if snapshot.global_active_count != 0 or snapshot.producer_active_count != 0:
            raise DemoError("execution_lease_cleanup_failed")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        raise DemoError("artifact_unavailable") from None
    return digest.hexdigest()


def _verify_v2_files() -> None:
    for filename, expected in V2_FILE_HASHES.items():
        path = V2_DIRECTORY / filename
        if not path.is_file() or path.is_symlink() or _sha256_file(path) != expected:
            raise DemoError("experimental_autoencoder_integrity_failed")


def _run_openssl(arguments: list[str]) -> None:
    try:
        completed = subprocess.run(
            ["openssl", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        raise DemoError("temporary_credential_generation_failed") from None
    if completed.returncode != 0:
        raise DemoError("temporary_credential_generation_failed")


def _issue_ca(root: Path) -> tuple[Path, Path]:
    key = root / "demo-ca.key"
    certificate = root / "demo-ca.pem"
    _run_openssl(
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-days",
            "2",
            "-sha256",
            "-subj",
            "/CN=ThreatFusion ephemeral demonstration CA",
        ]
    )
    key.chmod(0o600)
    certificate.chmod(0o644)
    return certificate, key


def _issue_certificate(
    root: Path,
    name: str,
    ca_certificate: Path,
    ca_key: Path,
    *,
    purpose: str,
    san: str,
) -> tuple[Path, Path]:
    key = root / f"{name}.key"
    request = root / f"{name}.csr"
    certificate = root / f"{name}.pem"
    extension = root / f"{name}.ext"
    extension.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        f"extendedKeyUsage={purpose}\n"
        f"subjectAltName={san}\n",
        encoding="ascii",
    )
    _run_openssl(
        [
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(request),
            "-subj",
            f"/CN={name}",
        ]
    )
    _run_openssl(
        [
            "x509",
            "-req",
            "-in",
            str(request),
            "-CA",
            str(ca_certificate),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(certificate),
            "-days",
            "2",
            "-sha256",
            "-extfile",
            str(extension),
        ]
    )
    key.chmod(0o600)
    certificate.chmod(0o644)
    return certificate, key


def _fingerprint(certificate: Path) -> str:
    try:
        der = ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))
    except (OSError, UnicodeError, ValueError):
        raise DemoError("temporary_credential_invalid") from None
    return hashlib.sha256(der).hexdigest()


@contextmanager
def _temporary_runtime() -> Iterator[Path]:
    retained: Path | None = None
    with TemporaryDirectory(prefix="threatfusion-fyp-demo-") as directory:
        retained = Path(directory)
        retained.chmod(0o700)
        yield retained
    if retained is None or retained.exists():
        raise DemoError("temporary_runtime_cleanup_failed")


def _create_credentials(root: Path) -> dict[str, object]:
    ca, ca_key = _issue_ca(root)
    server = _issue_certificate(
        root,
        "server",
        ca,
        ca_key,
        purpose="serverAuth",
        san="DNS:localhost",
    )
    client = _issue_certificate(
        root,
        "registered-unsw-client",
        ca,
        ca_key,
        purpose="clientAuth",
        san=f"URI:{REGISTERED_UNSW_URI_SAN}",
    )
    return {"ca": ca, "server": server, "client": client}


def _registry(client_certificate: Path, now: datetime) -> CertificateRegistry:
    return CertificateRegistry(
        (
            CertificateRegistryRecord(
                REGISTERED_UNSW_PRODUCER_ID,
                REGISTERED_UNSW_PRODUCER_TYPE,
                REGISTERED_UNSW_URI_SAN,
                _fingerprint(client_certificate),
                True,
                False,
                now - timedelta(days=1),
                now + timedelta(days=1),
                (REGISTERED_UNSW_SOURCE_CONTRACT,),
            ),
        )
    )


def _client_context(credentials: dict[str, object]) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=credentials["ca"])
    context.load_cert_chain(*credentials["client"])
    return context


def _request_body(
    references: tuple[tuple[str, int], ...],
    *,
    producer_id: str = REGISTERED_UNSW_PRODUCER_ID,
) -> bytes:
    produced_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return json.dumps(
        {
            "schema_version": PRODUCER_INGEST_REQUEST_SCHEMA_VERSION,
            "producer_id": producer_id,
            "request_id": str(uuid4()),
            "produced_at": produced_at,
            "nonce": secrets.token_urlsafe(32),
            "source_contract": REGISTERED_UNSW_SOURCE_CONTRACT,
            "records": [
                {"source_member_sha256": member, "row_number": row} for member, row in references
            ],
        },
        separators=(",", ":"),
    ).encode("ascii")


def _request_wire(body: bytes) -> bytes:
    return (
        f"{TRANSPORT_REQUEST_METHOD} {TRANSPORT_REQUEST_TARGET} {TRANSPORT_HTTP_VERSION}\r\n"
        f"Host: {TRANSPORT_HOST}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body


def _exchange(
    service: _DemoService, credentials: dict[str, object], body: bytes
) -> tuple[bytes, ProducerOrchestratorResult, str]:
    outcome: Queue[object] = Queue(maxsize=1)

    def process_one() -> None:
        try:
            outcome.put(service.orchestrator.process_one())
        except BaseException as error:
            outcome.put(error)

    thread = Thread(target=process_one, name="threatfusion-fyp-demo-request")
    thread.start()
    chunks: list[bytes] = []
    negotiated = ""
    client_error: BaseException | None = None
    try:
        with socket.create_connection(service.listener.address, timeout=3) as raw:
            with _client_context(credentials).wrap_socket(
                raw, server_hostname="localhost"
            ) as connection:
                negotiated = connection.version() or ""
                connection.settimeout(45)
                connection.sendall(_request_wire(body))
                while chunk := connection.recv(65_536):
                    chunks.append(chunk)
    except BaseException as error:
        client_error = error
    finally:
        if client_error is not None:
            service.listener.close()
        thread.join(50)
    if thread.is_alive():
        raise DemoError("demo_request_thread_cleanup_failed")
    if client_error is not None:
        if isinstance(client_error, (OSError, ssl.SSLError)):
            raise DemoError("loopback_tls_exchange_failed") from None
        raise client_error
    try:
        result = outcome.get_nowait()
    except Empty:
        raise DemoError("orchestrator_result_missing") from None
    if isinstance(result, BaseException):
        raise DemoError("orchestrator_request_failed") from None
    if type(result) is not ProducerOrchestratorResult:
        raise DemoError("orchestrator_result_invalid")
    if negotiated != "TLSv1.3":
        raise DemoError("tls_version_invalid")
    return b"".join(chunks), result, negotiated


def _decode_wire(wire: bytes) -> tuple[int, bytes, object]:
    try:
        head, body = wire.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        status = int(lines[0].split()[1])
        if f"Content-Length: {len(body)}".encode("ascii") not in lines:
            raise ValueError
        if b"Connection: close" not in lines:
            raise ValueError
        response = decode_producer_response(body)
    except (IndexError, ValueError, ProducerAdmissionError):
        raise DemoError("producer_response_invalid") from None
    return status, body, response


def _instrument_actual_calls(
    boundary: UnswNetworkInferenceBoundary,
    alerts: AlertCandidateRepository,
) -> dict[str, int]:
    counters = {"inference_calls": 0, "alert_insert_calls": 0}
    original_infer = boundary._infer_prepared_registered
    original_insert = alerts.insert

    def counted_infer(self, prepared, *, model):  # noqa: ANN001, ANN202
        counters["inference_calls"] += 1
        return original_infer(prepared, model=model)

    def counted_insert(candidate):  # noqa: ANN001, ANN202
        counters["alert_insert_calls"] += 1
        return original_insert(candidate)

    boundary._infer_prepared_registered = MethodType(counted_infer, boundary)
    alerts.insert = counted_insert
    return counters


def _create_service(
    root: Path,
    credentials: dict[str, object],
    boundary: UnswNetworkInferenceBoundary,
) -> _DemoService:
    listener = ProducerTlsListener(
        ProducerTlsConfiguration(
            server_certificate_path=credentials["server"][0],
            server_private_key_path=credentials["server"][1],
            client_ca_path=credentials["ca"],
        )
    )
    try:
        replay = ProducerReplayJournal(root / "replay.sqlite3", service_generation_id=str(uuid4()))
        audit = ProducerSecurityAuditRepository(root / "audit.sqlite3")
        alerts = AlertCandidateRepository(root / "alerts.sqlite3")
        gates = ProducerExecutionGates()
        now = datetime.now(UTC)
        orchestrator = ProducerOrchestrator(
            transport=listener,
            certificate_registry=_registry(credentials["client"][0], now),
            execution_gates=gates,
            replay_journal=replay,
            security_audit=audit,
            inference_boundary=boundary,
            alert_repository=alerts,
        )
        orchestrator.open()
        return _DemoService(orchestrator, listener, alerts, audit, gates)
    except BaseException:
        listener.close()
        raise


def _git_revision() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        raise DemoError("revision_unavailable") from None
    revision = completed.stdout.strip()
    if completed.returncode != 0 or len(revision) != 40:
        raise DemoError("revision_unavailable")
    return revision


def _prepare_autoencoder_rows(
    boundary: UnswNetworkInferenceBoundary,
) -> tuple[np.ndarray, tuple[str, ...]]:
    member = boundary._registered_source.members_by_sha256.get(MEMBER_SHA256)
    if member is None:
        raise DemoError("registered_demo_member_unavailable")
    transformed: list[np.ndarray] = []
    labels: list[str] = []
    for example in DEMO_EXAMPLES:
        raw = boundary._registered_row(member, example.row_number)
        try:
            numeric_label = int(raw[-1].strip())
        except (IndexError, ValueError):
            raise DemoError("registered_demo_label_invalid") from None
        label = "Attack" if numeric_label == 1 else "Normal" if numeric_label == 0 else ""
        if label != example.known_label:
            raise DemoError("registered_demo_label_mismatch")
        adapted = boundary._adapt_raw(raw)
        if adapted is None:
            raise DemoError("registered_demo_record_rejected")
        request, _ = adapted
        try:
            transformed.append(
                boundary._predictor._preprocessor.transform(_feature_record(request))
            )
        except Exception:
            raise DemoError("registered_demo_transformation_failed") from None
        labels.append(label)
    return np.stack(transformed), tuple(labels)


def _autoencoder_evidence(
    boundary: UnswNetworkInferenceBoundary,
) -> dict[str, object]:
    configure_deterministic_cpu_runtime()
    _verify_v2_files()
    detector = _load_verified_autoencoder_detector(
        V2_DIRECTORY,
        artifact_identity=V2_ARTIFACT_IDENTITY,
        expected=V2_TRUSTED_BUNDLE,
    )
    matrix, labels = _prepare_autoencoder_rows(boundary)
    scores = detector.score(matrix, caller_chunk_size=1)
    records = []
    for example, label, score in zip(DEMO_EXAMPLES, labels, scores, strict=True):
        numeric_score = float(score)
        records.append(
            {
                "row_number": example.row_number,
                "known_label": label,
                "reconstruction_score": numeric_score,
                "threshold": detector.threshold,
                "operator": ">",
                "anomaly": numeric_score > detector.threshold,
            }
        )
    return {
        "status": "completed",
        "scope": "experimental_research_demo_only",
        "artifact_identity": detector.artifact_identity,
        "artifact_files_verified": len(V2_FILE_HASHES),
        "product_registry_approved": False,
        "producer_workflow_integrated": False,
        "fusion_enabled": False,
        "records": records,
    }


def _producer_evidence(
    service: _DemoService,
    credentials: dict[str, object],
    counters: dict[str, int],
) -> dict[str, object]:
    references = tuple((MEMBER_SHA256, item.row_number) for item in DEMO_EXAMPLES)
    body = _request_body(references)
    first_wire, first_result, negotiated = _exchange(service, credentials, body)
    first_status, first_body, first_response = _decode_wire(first_wire)
    if first_status != 200 or first_result.response_bytes != first_body:
        raise DemoError("initial_request_failed")
    alerts_after_first = service.alerts.list()
    counters_after_first = dict(counters)

    retry_wire, retry_result, retry_tls = _exchange(service, credentials, body)
    retry_status, retry_body, retry_response = _decode_wire(retry_wire)
    alerts_after_retry = service.alerts.list()
    counters_after_retry = dict(counters)

    invalid_body = _request_body(references, producer_id="wrong-producer")
    invalid_wire, invalid_result, invalid_tls = _exchange(service, credentials, invalid_body)
    invalid_status, invalid_response_body, invalid_response = _decode_wire(invalid_wire)
    alerts_after_invalid = service.alerts.list()
    counters_after_invalid = dict(counters)

    records = []
    for example, disposition in zip(DEMO_EXAMPLES, first_response.records, strict=True):
        records.append(
            {
                "row_number": example.row_number,
                "known_label": example.known_label,
                "predicted_class": disposition.predicted_class,
                "attack_probability": disposition.attack_probability,
                "disposition": disposition.disposition,
                "alert_candidate_id": disposition.alert_candidate_id,
            }
        )
    audit_types = [event.event_type for event in service.audit.list()]
    return {
        "status": "completed",
        "scope": "recorded_unsw_replay_not_live_traffic_or_accuracy_testing",
        "selection_disclosure": (
            "Rows 1 and 21 were deliberately frozen because they illustrate one RF Normal and "
            "one RF Attack outcome; they are not an unbiased evaluation sample."
        ),
        "tls_version": negotiated,
        "records": records,
        "alerts_after_first": len(alerts_after_first),
        "inference_calls_after_first": counters_after_first["inference_calls"],
        "alert_insert_calls_after_first": counters_after_first["alert_insert_calls"],
        "replay": {
            "tls_version": retry_tls,
            "http_status": retry_status,
            "reason": retry_response.reason,
            "wire_bytes_identical": retry_wire == first_wire,
            "cached_response_bytes_identical": (
                retry_body
                == first_body
                == first_result.response_bytes
                == retry_result.response_bytes
            ),
            "cached_response_length": len(first_body),
            "alerts_after_retry": len(alerts_after_retry),
            "inference_calls_after_retry": counters_after_retry["inference_calls"],
            "alert_insert_calls_after_retry": counters_after_retry["alert_insert_calls"],
        },
        "authenticated_invalid_request": {
            "tls_version": invalid_tls,
            "http_status": invalid_status,
            "reason": invalid_response.reason,
            "orchestrator_reason": invalid_result.reason,
            "response_bound": invalid_result.response_bytes == invalid_response_body,
            "alerts_after_rejection": len(alerts_after_invalid),
            "inference_calls_after_rejection": counters_after_invalid["inference_calls"],
            "alert_insert_calls_after_rejection": counters_after_invalid["alert_insert_calls"],
        },
        "audit_event_types": audit_types,
    }


def _validate_report(report: dict[str, object]) -> None:
    try:
        producer = report["random_forest_producer_demo"]
        replay = producer["replay"]
        rejection = producer["authenticated_invalid_request"]
        records = producer["records"]
        autoencoder = report["experimental_v2_autoencoder_demo"]
        ae_records = autoencoder["records"]
        first_inference = producer["inference_calls_after_first"]
        first_inserts = producer["alert_insert_calls_after_first"]
        first_alerts = producer["alerts_after_first"]
        valid = (
            report["status"] == "completed"
            and producer["status"] == "completed"
            and producer["tls_version"] == "TLSv1.3"
            and len(records) == 2
            and [item["known_label"] for item in records] == ["Normal", "Attack"]
            and [item["predicted_class"] for item in records] == ["Normal", "Attack"]
            and [item["disposition"] for item in records] == ["not_actionable", "created"]
            and records[0]["alert_candidate_id"] is None
            and type(records[1]["alert_candidate_id"]) is str
            and first_inference == 2
            and first_inserts == 1
            and first_alerts == 1
            and replay["http_status"] == 200
            and replay["wire_bytes_identical"] is True
            and replay["cached_response_bytes_identical"] is True
            and replay["alerts_after_retry"] == first_alerts
            and replay["inference_calls_after_retry"] == first_inference
            and replay["alert_insert_calls_after_retry"] == first_inserts
            and rejection["http_status"] == 400
            and rejection["reason"] == "request_rejected"
            and rejection["response_bound"] is True
            and rejection["alerts_after_rejection"] == first_alerts
            and rejection["inference_calls_after_rejection"] == first_inference
            and rejection["alert_insert_calls_after_rejection"] == first_inserts
            and autoencoder["status"] == "completed"
            and autoencoder["artifact_identity"] == V2_ARTIFACT_IDENTITY
            and autoencoder["artifact_files_verified"] == 9
            and autoencoder["product_registry_approved"] is False
            and autoencoder["producer_workflow_integrated"] is False
            and autoencoder["fusion_enabled"] is False
            and len(ae_records) == 2
            and all(
                item["anomaly"] == (item["reconstruction_score"] > item["threshold"])
                and item["operator"] == ">"
                for item in ae_records
            )
        )
    except (KeyError, TypeError):
        raise DemoError("demo_evidence_invalid") from None
    if not valid:
        raise DemoError("demo_assertion_failed")


def _write_report(report: dict[str, object], directory: Path = OUTPUT_DIRECTORY) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / OUTPUT_FILENAME
    temporary = directory / f".{OUTPUT_FILENAME}.tmp"
    try:
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(target)
    except OSError:
        raise DemoError("demo_evidence_write_failed") from None
    return target


def _print_report(report: dict[str, object], output: Path) -> None:
    producer = report["random_forest_producer_demo"]
    replay = producer["replay"]
    invalid = producer["authenticated_invalid_request"]
    autoencoder = report["experimental_v2_autoencoder_demo"]
    print("ThreatFusion FYP-II demonstration: PASS")
    print("Scope: recorded UNSW replay; not live traffic and not accuracy testing")
    print(f"Revision: {report['revision']}")
    print(f"Transport: real loopback {producer['tls_version']} with mutual TLS")
    print("Random Forest registered examples (deliberately selected for illustration):")
    for record in producer["records"]:
        print(
            f"  row {record['row_number']}: known_label={record['known_label']} "
            f"prediction={record['predicted_class']} "
            f"attack_probability={record['attack_probability']:.12f} "
            f"alert={record['disposition']}"
        )
    print(
        "Replay proof: "
        f"cached_bytes_identical={replay['cached_response_bytes_identical']} "
        f"inference_calls={producer['inference_calls_after_first']}->"
        f"{replay['inference_calls_after_retry']} "
        f"alert_insert_calls={producer['alert_insert_calls_after_first']}->"
        f"{replay['alert_insert_calls_after_retry']} "
        f"alert_count={producer['alerts_after_first']}->{replay['alerts_after_retry']}"
    )
    print(
        "Authenticated invalid request: "
        f"HTTP {invalid['http_status']} reason={invalid['reason']} "
        f"inference_calls={invalid['inference_calls_after_rejection']} "
        f"alert_insert_calls={invalid['alert_insert_calls_after_rejection']} "
        f"alert_count={invalid['alerts_after_rejection']}"
    )
    print("Experimental v2 autoencoder (separate; not product-approved or fused):")
    print(f"  artifact_identity={autoencoder['artifact_identity']}")
    for record in autoencoder["records"]:
        print(
            f"  row {record['row_number']}: known_label={record['known_label']} "
            f"score={record['reconstruction_score']:.12f} "
            f"threshold={record['threshold']:.12f} "
            f"score>threshold={record['anomaly']}"
        )
    print("Cleanup: request threads joined, listener closed, leases released, runtime removed")
    print(f"Evidence: {output.relative_to(PROJECT_ROOT)}")


def run_demo() -> dict[str, object]:
    revision = _git_revision()
    boundary = UnswNetworkInferenceBoundary(project_root=PROJECT_ROOT)
    autoencoder = _autoencoder_evidence(boundary)
    producer: dict[str, object]
    with _temporary_runtime() as runtime:
        credentials = _create_credentials(runtime)
        service = _create_service(runtime, credentials, boundary)
        try:
            counters = _instrument_actual_calls(boundary, service.alerts)
            producer = _producer_evidence(service, credentials, counters)
        finally:
            service.close()
        if tuple(runtime.glob("*.sqlite3-wal")) or tuple(runtime.glob("*.sqlite3-shm")):
            raise DemoError("sqlite_cleanup_failed")
    report: dict[str, object] = {
        "schema_version": "threatfusion_fyp_progress_demo_v1",
        "status": "completed",
        "revision": revision,
        "random_forest_artifact_sha256": APPROVED_MODEL_HASHES["random_forest"]["model"],
        "preprocessing_hashes": dict(APPROVED_PREPROCESSING_HASHES),
        "random_forest_producer_demo": producer,
        "experimental_v2_autoencoder_demo": autoencoder,
        "runtime_cleanup_verified": True,
    }
    _validate_report(report)
    return report


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description=(
            "Bounded recorded-UNSW FYP-II demo using real loopback mTLS, frozen RF inference, "
            "replay controls, Attack-only alerts, and a separate experimental v2 AE score."
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    _parser().parse_args(argv)
    try:
        report = run_demo()
        output = _write_report(report)
    except (
        DemoError,
        NetworkInferenceError,
        ProducerAdmissionError,
        ProducerOrchestratorError,
    ) as error:
        reason = getattr(error, "code", "demo_failed")
        print(json.dumps({"status": "failed", "reason": reason}, sort_keys=True))
        return 1
    except Exception:
        print(json.dumps({"status": "failed", "reason": "demo_internal_failure"}, sort_keys=True))
        return 1
    _print_report(report, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
