"""Real TLS and strict staged transport tests using temporary certificates only."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import socket
import ssl
import subprocess
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Queue
from threading import Event, Thread
import time

import pytest

import threatfusion.models.network_inference as inference
from threatfusion.api.producer_admission import (
    PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION,
    REGISTERED_UNSW_PRODUCER_ID,
    REGISTERED_UNSW_PRODUCER_TYPE,
    REGISTERED_UNSW_SOURCE_CONTRACT,
    REGISTERED_UNSW_URI_SAN,
    CertificateRegistry,
    CertificateRegistryRecord,
    ProducerRecordDisposition,
    ProducerResponse,
)
from threatfusion.api.producer_tls_transport import (
    LISTEN_BACKLOG,
    LOOPBACK_BIND_HOST,
    MAX_HEADER_BYTES,
    MAX_HEADER_FIELDS,
    MAX_HEADER_NAME_BYTES,
    MAX_HEADER_VALUE_BYTES,
    MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_BYTES,
    REQUEST_READ_IDLE_SECONDS,
    REQUEST_READ_TOTAL_SECONDS,
    TLS_HANDSHAKE_TOTAL_SECONDS,
    TRANSPORT_HOST,
    TRANSPORT_HTTP_VERSION,
    TRANSPORT_REQUEST_METHOD,
    TRANSPORT_REQUEST_TARGET,
    ProducerTlsConfiguration,
    ProducerTlsListener,
    ProducerTlsTransportError,
    TransportCapability,
    _parse_request_head,
)
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.producer_replay_journal import ProducerReplayJournal
from threatfusion.db.producer_security_audit import ProducerSecurityAuditRepository


@pytest.fixture(autouse=True)
def downstream_spies(monkeypatch):
    calls: list[str] = []

    def forbidden(name):
        def call(*args, **kwargs):
            calls.append(name)
            pytest.fail(f"TLS transport invoked {name}")

        return call

    monkeypatch.setattr(ProducerReplayJournal, "claim", forbidden("replay"))
    monkeypatch.setattr(inference._FrozenNetworkPredictor, "infer", forbidden("predictor"))
    monkeypatch.setattr(AlertCandidateRepository, "insert", forbidden("alert repository"))
    monkeypatch.setattr(ProducerSecurityAuditRepository, "append", forbidden("audit repository"))
    yield
    assert calls == []


def _run(arguments: list[str]) -> None:
    completed = subprocess.run(arguments, capture_output=True, check=False, timeout=10)
    if completed.returncode != 0:
        pytest.fail("ephemeral OpenSSL certificate generation failed")


def _issue_ca(root: Path, name: str) -> tuple[Path, Path]:
    key = root / f"{name}-ca.key"
    certificate = root / f"{name}-ca.pem"
    _run(
        [
            "openssl",
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
            f"/CN={name} ephemeral CA",
        ]
    )
    return certificate, key


def _issue_certificate(
    root: Path,
    name: str,
    ca_certificate: Path,
    ca_key: Path,
    *,
    purpose: str,
    san: str | None,
) -> tuple[Path, Path]:
    key = root / f"{name}.key"
    request = root / f"{name}.csr"
    certificate = root / f"{name}.pem"
    extension = root / f"{name}.ext"
    extension_lines = [
        "basicConstraints=CA:FALSE",
        "keyUsage=digitalSignature,keyEncipherment",
        f"extendedKeyUsage={purpose}",
    ]
    if san is not None:
        extension_lines.append(f"subjectAltName={san}")
    extension.write_text("\n".join(extension_lines) + "\n", encoding="ascii")
    _run(
        [
            "openssl",
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
    _run(
        [
            "openssl",
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
    return certificate, key


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    root = tmp_path_factory.mktemp("producer-tls-certificates")
    ca, ca_key = _issue_ca(root, "trusted")
    other_ca, other_ca_key = _issue_ca(root, "other")
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
    wrong_san = _issue_certificate(
        root,
        "wrong-san-client",
        ca,
        ca_key,
        purpose="clientAuth",
        san="URI:urn:threatfusion:producer:wrong",
    )
    cn_only = _issue_certificate(
        root,
        REGISTERED_UNSW_PRODUCER_ID,
        ca,
        ca_key,
        purpose="clientAuth",
        san=None,
    )
    wrong_ca = _issue_certificate(
        root,
        "wrong-ca-client",
        other_ca,
        other_ca_key,
        purpose="clientAuth",
        san=f"URI:{REGISTERED_UNSW_URI_SAN}",
    )
    wrong_eku = _issue_certificate(
        root,
        "wrong-eku-client",
        ca,
        ca_key,
        purpose="serverAuth",
        san=f"URI:{REGISTERED_UNSW_URI_SAN}",
    )
    yield {
        "root": root,
        "ca": ca,
        "server": server,
        "good": good,
        "unknown": unknown,
        "wrong_san": wrong_san,
        "cn_only": cn_only,
        "wrong_ca": wrong_ca,
        "wrong_eku": wrong_eku,
    }
    shutil.rmtree(root)
    assert not root.exists()


def _fingerprint(certificate: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))
    return hashlib.sha256(der).hexdigest()


def _registry(certificates, **updates) -> CertificateRegistry:
    now = datetime.now(UTC)
    values = {
        "producer_id": REGISTERED_UNSW_PRODUCER_ID,
        "producer_type": REGISTERED_UNSW_PRODUCER_TYPE,
        "uri_san": REGISTERED_UNSW_URI_SAN,
        "certificate_sha256": _fingerprint(certificates["good"][0]),
        "enabled": True,
        "revoked": False,
        "not_before": now - timedelta(hours=1),
        "not_after": now + timedelta(hours=1),
        "allowed_source_contracts": (REGISTERED_UNSW_SOURCE_CONTRACT,),
    }
    values.update(updates)
    return CertificateRegistry((CertificateRegistryRecord(**values),))


def _configuration(certificates, **updates) -> ProducerTlsConfiguration:
    values = {
        "server_certificate_path": certificates["server"][0],
        "server_private_key_path": certificates["server"][1],
        "client_ca_path": certificates["ca"],
    }
    values.update(updates)
    return ProducerTlsConfiguration(**values)


def _client_context(certificates, client="good", *, tls12_only=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=certificates["ca"])
    if tls12_only:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    if client is not None:
        context.load_cert_chain(*certificates[client])
    return context


def _start_accept(listener, registry, action):
    outcome: Queue[object] = Queue()

    def serve():
        try:
            session = listener.accept_authenticated(registry, trusted_now=datetime.now(UTC))
            outcome.put(action(session))
        except BaseException as exc:
            outcome.put(exc)

    thread = Thread(target=serve)
    thread.start()
    return thread, outcome


def _connect(listener, context):
    raw = socket.create_connection(listener.address, timeout=1)
    return context.wrap_socket(raw, server_hostname="localhost")


def _valid_head(content_length=2, extra=()):
    lines = [
        f"{TRANSPORT_REQUEST_METHOD} {TRANSPORT_REQUEST_TARGET} {TRANSPORT_HTTP_VERSION}",
        f"Host: {TRANSPORT_HOST}",
        "Content-Type: application/json",
        f"Content-Length: {content_length}",
        "Connection: close",
        *extra,
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def _response():
    return ProducerResponse(
        PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION,
        "11111111-1111-4111-8111-111111111111",
        "request_completed",
        (ProducerRecordDisposition(1, "created", "alert_candidate_created"),),
    )


def _receive_all(client) -> bytes:
    chunks = []
    while True:
        data = client.recv(65_536)
        if not data:
            return b"".join(chunks)
        chunks.append(data)


def test_valid_connection_negotiates_tls13_and_returns_only_canonical_peer_evidence(
    certificates,
):
    listener = ProducerTlsListener(_configuration(certificates))
    listener.open()

    def inspect(session):
        evidence = session.peer_evidence
        assert evidence.tls_version == "TLSv1.3"
        assert evidence.chain_authenticated is evidence.client_auth_eku is True
        assert evidence.certificate_sha256 == _fingerprint(certificates["good"][0])
        assert evidence.uri_sans == (REGISTERED_UNSW_URI_SAN,)
        assert session.admitted_producer.producer_id == REGISTERED_UNSW_PRODUCER_ID
        assert "CERTIFICATE" not in repr(session)
        session.connection.close(session.capability)
        return "accepted"

    thread, outcome = _start_accept(listener, _registry(certificates), inspect)
    with _connect(listener, _client_context(certificates)) as client:
        assert client.version() == "TLSv1.3"
    thread.join(2)
    listener.close()
    assert not thread.is_alive()
    assert outcome.get_nowait() == "accepted"


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "localhost", "127.0.0.2", "192.0.2.1"])
def test_non_loopback_wildcard_hostname_and_external_bind_rejected_before_socket(
    certificates, monkeypatch, host
):
    calls = 0

    def forbidden(*args, **kwargs):
        nonlocal calls
        calls += 1
        pytest.fail("invalid bind configuration opened a socket")

    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(ProducerTlsTransportError, match="^transport_configuration_invalid$"):
        _configuration(certificates, bind_host=host)
    assert calls == 0


def test_server_context_is_exact_tls13_and_requires_client_certificates(certificates):
    listener = ProducerTlsListener(_configuration(certificates))
    assert listener._context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert listener._context.maximum_version is ssl.TLSVersion.TLSv1_3
    assert listener._context.verify_mode is ssl.CERT_REQUIRED


def test_production_deadline_constants_are_exact():
    assert TLS_HANDSHAKE_TOTAL_SECONDS == 3.0
    assert REQUEST_READ_TOTAL_SECONDS == 5.0
    assert REQUEST_READ_IDLE_SECONDS == 1.0


@pytest.mark.parametrize("mode", ["tls12", "missing", "wrong_ca", "wrong_eku", "plaintext"])
def test_tls12_plaintext_missing_certificate_and_wrong_ca_are_rejected(certificates, mode):
    listener = ProducerTlsListener(_configuration(certificates), _handshake_seconds=0.25)
    listener.open()
    thread, outcome = _start_accept(
        listener,
        _registry(certificates),
        lambda session: session.connection.close(session.capability),
    )
    if mode == "plaintext":
        client = socket.create_connection(listener.address, timeout=1)
        client.sendall(b"plaintext\r\n")
        client.close()
    else:
        selected = (
            None if mode == "missing" else (mode if mode in {"wrong_ca", "wrong_eku"} else "good")
        )
        context = _client_context(certificates, selected, tls12_only=mode == "tls12")
        try:
            with _connect(listener, context) as client:
                client.sendall(b"x")
                client.recv(1)
        except (ssl.SSLError, ConnectionError, TimeoutError):
            pass
    thread.join(2)
    listener.close()
    assert not thread.is_alive()
    error = outcome.get_nowait()
    assert isinstance(error, ProducerTlsTransportError)
    assert "ssl" not in str(error).lower()
    assert str(certificates["root"]) not in str(error)


@pytest.mark.parametrize(
    ("client", "registry_updates", "reason"),
    [
        ("unknown", {}, "authentication_failed"),
        ("wrong_san", {}, "authentication_failed"),
        ("cn_only", {}, "authentication_failed"),
        ("good", {"enabled": False}, "credential_disabled"),
        ("good", {"revoked": True}, "credential_revoked"),
        (
            "good",
            {
                "not_before": datetime.now(UTC) - timedelta(hours=2),
                "not_after": datetime.now(UTC) - timedelta(hours=1),
            },
            "credential_expired",
        ),
        (
            "good",
            {
                "not_before": datetime.now(UTC) + timedelta(hours=1),
                "not_after": datetime.now(UTC) + timedelta(hours=2),
            },
            "credential_not_yet_valid",
        ),
    ],
)
def test_unknown_fingerprint_san_cn_only_disabled_and_revoked_are_rejected(
    certificates, client, registry_updates, reason
):
    listener = ProducerTlsListener(_configuration(certificates))
    listener.open()
    thread, outcome = _start_accept(
        listener,
        _registry(certificates, **registry_updates),
        lambda session: session.connection.close(session.capability),
    )
    try:
        with _connect(listener, _client_context(certificates, client)):
            pass
    except (ssl.SSLError, ConnectionError):
        pass
    thread.join(2)
    listener.close()
    error = outcome.get_nowait()
    assert isinstance(error, ProducerTlsTransportError)
    assert (error.code, error.reason) == ("authentication_rejected", reason)


def test_ephemeral_listener_uses_ipv4_loopback_smallest_backlog_and_no_reuseport(
    certificates, monkeypatch
):
    real_socket = socket.socket
    options = []

    class RecordingSocket:
        def __init__(self):
            self.wrapped = real_socket(socket.AF_INET, socket.SOCK_STREAM)

        def __getattr__(self, name):
            return getattr(self.wrapped, name)

        def setsockopt(self, level, option, value):
            options.append((level, option, value))
            return self.wrapped.setsockopt(level, option, value)

    monkeypatch.setattr(socket, "socket", lambda *args: RecordingSocket())
    listener = ProducerTlsListener(_configuration(certificates))
    listener.open()
    assert listener.address[0] == LOOPBACK_BIND_HOST
    assert listener.address[1] != 0
    assert LISTEN_BACKLOG == 1
    assert all(option != getattr(socket, "SO_REUSEPORT", -1) for _, option, _ in options)
    listener.close()


@pytest.mark.parametrize(
    "line",
    [
        b"GET /v1/producer-events HTTP/1.1",
        b"POST /wrong HTTP/1.1",
        b"POST /v1/producer-events HTTP/1.0",
        b"POST  /v1/producer-events HTTP/1.1",
        b"\xff /v1/producer-events HTTP/1.1",
    ],
)
def test_wrong_method_path_version_and_malformed_request_line(line):
    request = _valid_head().split(b"\r\n", 1)[1]
    with pytest.raises(ProducerTlsTransportError, match="^request_line_invalid$"):
        _parse_request_head(line + b"\r\n" + request)


def test_lf_only_and_oversized_request_line_are_rejected():
    with pytest.raises(ProducerTlsTransportError, match="^request_framing_invalid$"):
        _parse_request_head(_valid_head().replace(b"\r\n", b"\n"))
    oversized = b"P" * 513 + b"\r\n" + _valid_head().split(b"\r\n", 1)[1]
    with pytest.raises(ProducerTlsTransportError, match="^request_line_too_large$"):
        _parse_request_head(oversized)


def _head_with_extensions(count: int, *, name_length=8, value_length=1) -> bytes:
    extras = []
    for index in range(count):
        suffix = f"{index:02d}"
        name = "X" * (name_length - len(suffix)) + suffix
        extras.append(f"{name}: {'v' * value_length}")
    return _valid_head(extra=extras)


def test_header_count_name_and_value_exact_boundaries_and_one_over():
    assert _parse_request_head(_head_with_extensions(MAX_HEADER_FIELDS - 4)).header_count == 32
    with pytest.raises(ProducerTlsTransportError, match="^request_header_count_invalid$"):
        _parse_request_head(_head_with_extensions(MAX_HEADER_FIELDS - 3))
    assert _parse_request_head(_head_with_extensions(1, name_length=MAX_HEADER_NAME_BYTES))
    with pytest.raises(ProducerTlsTransportError, match="^request_header_invalid$"):
        _parse_request_head(_head_with_extensions(1, name_length=MAX_HEADER_NAME_BYTES + 1))
    assert _parse_request_head(_head_with_extensions(1, value_length=MAX_HEADER_VALUE_BYTES))
    with pytest.raises(ProducerTlsTransportError, match="^request_header_invalid$"):
        _parse_request_head(_head_with_extensions(1, value_length=MAX_HEADER_VALUE_BYTES + 1))


def _exact_header_size(size: int) -> bytes:
    extras = [[f"X-Pad-{index:02d}", "v"] for index in range(MAX_HEADER_FIELDS - 4)]
    while True:
        encoded = _valid_head(extra=[f"{name}: {value}" for name, value in extras])
        difference = size - len(encoded)
        if difference <= 0:
            return encoded
        for item in extras:
            capacity = MAX_HEADER_VALUE_BYTES - len(item[1])
            addition = min(capacity, difference)
            item[1] += "x" * addition
            difference -= addition
            if difference == 0:
                break


def test_header_total_size_exact_boundary_and_one_over():
    exact = _exact_header_size(MAX_HEADER_BYTES)
    assert len(exact) == MAX_HEADER_BYTES
    assert _parse_request_head(exact).total_header_bytes == MAX_HEADER_BYTES
    with pytest.raises(ProducerTlsTransportError, match="^request_headers_too_large$"):
        _parse_request_head(exact[:-4] + b"X" + b"\r\n\r\n")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.replace(b"Host: ", b"host: ").replace(
            b"Content-Type:", b"CONTENT-TYPE:"
        ),
    ],
)
def test_header_names_are_case_insensitive(mutation):
    assert _parse_request_head(mutation(_valid_head())).content_length == 2


@pytest.mark.parametrize(
    ("extra", "code"),
    [
        ((f"Host: {TRANSPORT_HOST}",), "duplicate_header"),
        ((" Transfer-Encoding: chunked",), "request_header_invalid"),
        (("Transfer-Encoding: chunked",), "unsupported_header"),
        (("Content-Encoding: gzip",), "unsupported_header"),
        (("Upgrade: websocket",), "unsupported_header"),
        (("Keep-Alive: timeout=5",), "unsupported_header"),
        (("Trailer: Digest",), "unsupported_header"),
    ],
)
def test_duplicate_folded_transfer_compression_upgrade_keepalive_and_trailer_rejected(extra, code):
    with pytest.raises(ProducerTlsTransportError, match=f"^{code}$"):
        _parse_request_head(_valid_head(extra=extra))


def test_missing_required_headers_are_rejected():
    for name in (b"Host", b"Content-Type", b"Content-Length", b"Connection"):
        lines = [line for line in _valid_head().split(b"\r\n") if not line.startswith(name + b":")]
        with pytest.raises(ProducerTlsTransportError, match="^required_header_missing$"):
            _parse_request_head(b"\r\n".join(lines))


@pytest.mark.parametrize(
    "value",
    [b"", b"+1", b"-1", b" 1", b"1 ", b"01", b"1.0", b"18446744073709551616"],
)
def test_missing_malformed_noncanonical_and_overflow_content_length(value):
    request = _valid_head().replace(b"Content-Length: 2", b"Content-Length: " + value)
    expected = "request_too_large" if value.startswith(b"1844") else "content_length_invalid"
    with pytest.raises(ProducerTlsTransportError, match=f"^{expected}$"):
        _parse_request_head(request)


def test_zero_maximum_and_one_over_body_length_policy():
    with pytest.raises(ProducerTlsTransportError, match="^empty_body$"):
        _parse_request_head(_valid_head(0))
    assert _parse_request_head(_valid_head(MAX_REQUEST_BODY_BYTES)).content_length == (
        MAX_REQUEST_BODY_BYTES
    )
    with pytest.raises(ProducerTlsTransportError, match="^request_too_large$"):
        _parse_request_head(_valid_head(MAX_REQUEST_BODY_BYTES + 1))


def test_body_requires_explicit_post_head_capability_and_exact_body(certificates):
    listener = ProducerTlsListener(_configuration(certificates))
    listener.open()

    def consume(session):
        with pytest.raises(ProducerTlsTransportError, match="^connection_capability_invalid$"):
            session.connection.read_body(session.capability)
        assert session.connection.closed
        return "closed"

    thread, outcome = _start_accept(listener, _registry(certificates), consume)
    with _connect(listener, _client_context(certificates)) as client:
        client.sendall(_valid_head() + b"{}")
    thread.join(2)
    listener.close()
    assert outcome.get_nowait() == "closed"


def test_valid_head_body_and_response_are_one_shot_and_content_length_is_exact(certificates):
    listener = ProducerTlsListener(_configuration(certificates))
    listener.open()

    def exchange(session):
        head, head_capability = session.connection.read_request_head(session.capability)
        assert head.content_length == 2
        body, body_capability = session.connection.read_body(head_capability)
        assert body == b"{}"
        session.connection.write_response(body_capability, _response())
        assert session.connection.closed
        return "completed"

    thread, outcome = _start_accept(listener, _registry(certificates), exchange)
    with _connect(listener, _client_context(certificates)) as client:
        client.sendall(_valid_head() + b"{}")
        wire = _receive_all(client)
    thread.join(2)
    listener.close()
    head, body = wire.split(b"\r\n\r\n", 1)
    length = int(
        next(line for line in head.split(b"\r\n") if line.startswith(b"Content-Length:")).split()[1]
    )
    assert length == len(body)
    assert b"Connection: close" in head
    assert outcome.get_nowait() == "completed"


def test_exact_maximum_body_is_read_without_truncation(certificates):
    body = b"x" * MAX_REQUEST_BODY_BYTES
    listener = ProducerTlsListener(_configuration(certificates))
    listener.open()

    def consume(session):
        head, capability = session.connection.read_request_head(session.capability)
        received, capability = session.connection.read_body(capability)
        session.connection.close(capability)
        return head.content_length, len(received), hashlib.sha256(received).digest()

    thread, outcome = _start_accept(listener, _registry(certificates), consume)
    with _connect(listener, _client_context(certificates)) as client:
        client.sendall(_valid_head(len(body)) + body)
        assert client.recv(1) == b""
    thread.join(2)
    listener.close()
    assert not thread.is_alive()
    result = outcome.get_nowait()
    assert not isinstance(result, ProducerTlsTransportError), result.code
    assert result == (
        MAX_REQUEST_BODY_BYTES,
        MAX_REQUEST_BODY_BYTES,
        hashlib.sha256(body).digest(),
    )


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"{", "body_incomplete"),
        (b"{}X", "unexpected_trailing_data"),
        (b"{}GET /", "unexpected_trailing_data"),
    ],
)
def test_premature_eof_extra_bytes_and_pipelining_are_rejected(certificates, body, code):
    listener = ProducerTlsListener(_configuration(certificates))
    listener.open()

    def consume(session):
        _, capability = session.connection.read_request_head(session.capability)
        return session.connection.read_body(capability)

    thread, outcome = _start_accept(listener, _registry(certificates), consume)
    with _connect(listener, _client_context(certificates)) as client:
        client.sendall(_valid_head() + body)
    thread.join(2)
    listener.close()
    error = outcome.get_nowait()
    assert isinstance(error, ProducerTlsTransportError)
    assert error.code == code


def test_handshake_timeout_is_bounded_synchronized_and_closes_socket(certificates):
    listener = ProducerTlsListener(_configuration(certificates), _handshake_seconds=0.05)
    listener.open()
    thread, outcome = _start_accept(listener, _registry(certificates), lambda session: None)
    client = socket.create_connection(listener.address, timeout=1)
    thread.join(1)
    listener.close()
    assert not thread.is_alive()
    error = outcome.get_nowait()
    assert isinstance(error, ProducerTlsTransportError)
    assert error.code == "authentication_timeout"
    assert client.recv(1) == b""
    client.close()


def test_handshake_clock_failure_is_sanitized_and_closes_socket(certificates):
    def failing_clock():
        raise RuntimeError("secret clock detail")

    listener = ProducerTlsListener(_configuration(certificates), monotonic=failing_clock)
    listener.open()
    thread, outcome = _start_accept(listener, _registry(certificates), lambda session: None)
    try:
        with _connect(listener, _client_context(certificates)):
            pass
    except (ssl.SSLError, ConnectionError):
        pass
    thread.join(2)
    listener.close()
    error = outcome.get_nowait()
    assert isinstance(error, ProducerTlsTransportError)
    assert (error.code, error.reason) == ("monotonic_clock_invalid", "internal_failure")
    assert "secret" not in str(error)


def test_idle_body_timeout_is_bounded_and_closes_tls_socket(certificates):
    listener = ProducerTlsListener(_configuration(certificates), _read_idle_seconds=0.05)
    listener.open()
    ready = Event()

    def consume(session):
        _, capability = session.connection.read_request_head(session.capability)
        ready.set()
        return session.connection.read_body(capability)

    thread, outcome = _start_accept(listener, _registry(certificates), consume)
    with _connect(listener, _client_context(certificates)) as client:
        client.sendall(_valid_head(1))
        assert ready.wait(1)
        thread.join(1)
        assert client.recv(1) == b""
    listener.close()
    error = outcome.get_nowait()
    assert isinstance(error, ProducerTlsTransportError)
    assert (error.code, error.reason) == ("request_idle_timeout", "request_timeout")


def test_total_read_timeout_wins_while_each_progress_gap_is_below_idle(certificates):
    listener = ProducerTlsListener(
        _configuration(certificates), _read_total_seconds=0.12, _read_idle_seconds=0.08
    )
    listener.open()
    head_ready = Event()

    def consume(session):
        _, capability = session.connection.read_request_head(session.capability)
        head_ready.set()
        return session.connection.read_body(capability)

    thread, outcome = _start_accept(listener, _registry(certificates), consume)
    with _connect(listener, _client_context(certificates)) as client:
        client.sendall(_valid_head(3))
        assert head_ready.wait(1)
        for value in (b"a", b"b", b"c"):
            time.sleep(0.045)
            try:
                client.sendall(value)
            except OSError:
                break
    thread.join(1)
    listener.close()
    error = outcome.get_nowait()
    assert isinstance(error, ProducerTlsTransportError)
    assert error.code == "request_total_timeout"


def test_response_at_exact_maximum_is_accepted_and_one_over_sends_generic(certificates):
    base = (
        json.dumps(
            {
                "schema_version": PRODUCER_INGEST_RESPONSE_SCHEMA_VERSION,
                "correlation_id": "11111111-1111-4111-8111-111111111111",
                "reason": "request_completed",
                "records": [],
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    exact = base + b" " * (MAX_RESPONSE_BYTES - len(base))
    assert len(exact) == MAX_RESPONSE_BYTES

    for response, expected in ((exact, b"HTTP/1.1 200 OK"), (exact + b" ", b"500 Internal Error")):
        listener = ProducerTlsListener(_configuration(certificates))
        listener.open()

        def write(session):
            _, capability = session.connection.read_request_head(session.capability)
            try:
                session.connection.write_response(capability, response)
            except ProducerTlsTransportError as exc:
                return exc.code
            return "written"

        thread, outcome = _start_accept(listener, _registry(certificates), write)
        with _connect(listener, _client_context(certificates)) as client:
            client.sendall(_valid_head())
            wire = _receive_all(client)
        thread.join(2)
        listener.close()
        assert expected in wire
        result = outcome.get_nowait()
        assert result == ("written" if response is exact else "response_invalid")


def test_response_clock_failure_is_sanitized_and_closes_connection(certificates):
    listener = ProducerTlsListener(_configuration(certificates))
    listener.open()

    def write(session):
        _, capability = session.connection.read_request_head(session.capability)

        def failing_clock():
            raise RuntimeError("secret response clock")

        session.connection._monotonic = failing_clock
        with pytest.raises(ProducerTlsTransportError, match="^monotonic_clock_invalid$"):
            session.connection.write_response(capability, _response())
        return session.connection.closed

    thread, outcome = _start_accept(listener, _registry(certificates), write)
    with _connect(listener, _client_context(certificates)) as client:
        client.sendall(_valid_head())
        assert _receive_all(client) == b""
    thread.join(2)
    listener.close()
    assert outcome.get_nowait() is True


def test_state_transition_stale_foreign_copied_forged_and_post_close_misuse(certificates):
    listener = ProducerTlsListener(_configuration(certificates))
    listener.open()

    def misuse(session):
        with pytest.raises(ProducerTlsTransportError, match="^connection_capability_invalid$"):
            copy.copy(session.capability)
        forged = TransportCapability(
            session.capability.connection_id,
            session.capability.stage,
            "A" * 43,
        )
        with pytest.raises(ProducerTlsTransportError, match="^connection_capability_invalid$"):
            session.connection.read_request_head(forged)
        assert session.connection.closed
        with pytest.raises(ProducerTlsTransportError, match="^connection_capability_invalid$"):
            session.connection.close(session.capability)
        return "closed"

    thread, outcome = _start_accept(listener, _registry(certificates), misuse)
    with _connect(listener, _client_context(certificates)):
        pass
    thread.join(2)
    listener.close()
    assert outcome.get_nowait() == "closed"


@pytest.mark.parametrize("misuse", ["response_before_head", "double_body", "double_response"])
def test_response_and_body_state_transitions_are_one_shot(certificates, misuse):
    listener = ProducerTlsListener(_configuration(certificates))
    listener.open()

    def exercise(session):
        if misuse == "response_before_head":
            with pytest.raises(ProducerTlsTransportError, match="^connection_capability_invalid$"):
                session.connection.write_response(session.capability, _response())
            return session.connection.closed
        _, head_capability = session.connection.read_request_head(session.capability)
        _, body_capability = session.connection.read_body(head_capability)
        if misuse == "double_body":
            with pytest.raises(ProducerTlsTransportError, match="^connection_capability_invalid$"):
                session.connection.read_body(head_capability)
            return session.connection.closed
        session.connection.write_response(body_capability, _response())
        with pytest.raises(ProducerTlsTransportError, match="^connection_capability_invalid$"):
            session.connection.write_response(body_capability, _response())
        return session.connection.closed

    thread, outcome = _start_accept(listener, _registry(certificates), exercise)
    with _connect(listener, _client_context(certificates)) as client:
        if misuse != "response_before_head":
            client.sendall(_valid_head() + b"{}")
        _receive_all(client)
    thread.join(2)
    listener.close()
    assert outcome.get_nowait() is True


def test_foreign_and_stale_capabilities_cannot_cross_connections(certificates):
    listener = ProducerTlsListener(_configuration(certificates))
    listener.open()
    sessions: Queue[object] = Queue()

    def accept_once():
        sessions.put(
            listener.accept_authenticated(_registry(certificates), trusted_now=datetime.now(UTC))
        )

    first_thread = Thread(target=accept_once)
    first_thread.start()
    first_client = _connect(listener, _client_context(certificates))
    first_thread.join(2)
    first = sessions.get_nowait()
    second_thread = Thread(target=accept_once)
    second_thread.start()
    second_client = _connect(listener, _client_context(certificates))
    second_thread.join(2)
    second = sessions.get_nowait()
    with pytest.raises(ProducerTlsTransportError, match="^connection_capability_invalid$"):
        second.connection.read_request_head(first.capability)
    assert second.connection.closed
    first.connection.close(first.capability)
    first_client.close()
    second_client.close()
    listener.close()


def test_configuration_paths_and_errors_are_sanitized(certificates, tmp_path):
    missing = tmp_path / "private/server-secret.key"
    configuration = replace(_configuration(certificates), server_private_key_path=missing)
    with pytest.raises(
        ProducerTlsTransportError, match="^tls_configuration_unavailable$"
    ) as raised:
        ProducerTlsListener(configuration)
    rendered = f"{raised.value!s} {raised.value!r} {raised.value.__dict__}"
    assert str(missing) not in rendered
    assert "private" not in rendered


def test_contracts_are_immutable_and_repr_hides_paths_tokens_and_peer_values(certificates):
    configuration = _configuration(certificates)
    with pytest.raises(FrozenInstanceError):
        configuration.bind_host = "0.0.0.0"
    assert str(certificates["root"]) not in repr(configuration)
    capability = TransportCapability(
        "11111111-1111-4111-8111-111111111111", "authenticated", "A" * 43
    )
    assert "A" * 43 not in repr(capability)


def test_no_reusable_certificate_or_key_exists_beneath_repository_root():
    root = Path(__file__).resolve().parents[3]
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    prohibited_suffixes = (".pem", ".key", ".crt", ".cer", ".p12", ".pfx")
    assert not [name for name in tracked if name.lower().endswith(prohibited_suffixes)]
