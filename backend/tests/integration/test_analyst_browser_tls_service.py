"""Real loopback TLS authorization with separate ephemeral human credentials for browser boundary."""

from __future__ import annotations

import hashlib
import socket
import ssl
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Thread
import time

import pytest

from threatfusion.db.analyst_security_audit import (
    AnalystSecurityAuditError,
    AnalystSecurityAuditRepository,
)
from threatfusion.api.analyst_tls_service import (
    AnalystTlsConfiguration,
    HumanCredential,
    HumanCredentialRegistry,
)
from threatfusion.api import analyst_browser_tls_service as browser_service
from threatfusion.api.analyst_browser_tls_service import AnalystBrowserTlsListener
from threatfusion.api.analyst_view_model import AnalystAlertViewModel, AnalystViewError
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.analyst_state_repository import AnalystStateRepository
from threatfusion.schemas.analyst_state import (
    AnalystAuthorizationRegistry,
    AnalystRegistryEntry,
    AnalystStateError,
)

from backend.tests.unit.test_analyst_view_model import _candidate


def _openssl(*arguments: str) -> None:
    result = subprocess.run(["openssl", *arguments], capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, "ephemeral certificate creation failed"


def _ca(directory: Path, name: str) -> tuple[Path, Path]:
    certificate, key = directory / f"{name}-ca.pem", directory / f"{name}-ca.key"
    _openssl(
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
        f"/CN={name} CA",
    )
    return certificate, key


def _certificate(
    directory: Path, name: str, ca: tuple[Path, Path], *, purpose: str | None, san: str
) -> tuple[Path, Path]:
    certificate, key = directory / f"{name}.pem", directory / f"{name}.key"
    request, extension = directory / f"{name}.csr", directory / f"{name}.ext"
    extension.write_text(
        "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
        + (f"extendedKeyUsage={purpose}\n" if purpose else "")
        + f"subjectAltName={san}\n",
        encoding="ascii",
    )
    _openssl(
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
    )
    _openssl(
        "x509",
        "-req",
        "-in",
        str(request),
        "-CA",
        str(ca[0]),
        "-CAkey",
        str(ca[1]),
        "-days",
        "1",
        "-sha256",
        "-extfile",
        str(extension),
        "-out",
        str(certificate),
    )
    return certificate, key


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    import shutil

    directory = tmp_path_factory.mktemp("analyst-tls-certificates")
    human_ca = _ca(directory, "human")
    producer_ca = _ca(directory, "producer")
    result = {"human_ca": human_ca[0], "producer_ca": producer_ca[0]}
    result["server"] = _certificate(
        directory, "analyst-server", human_ca, purpose="serverAuth", san="DNS:localhost"
    )
    for name, actor in (
        ("viewer", "queue.viewer"),
        ("analyst_a", "analyst_a"),
        ("analyst_b", "analyst.b"),
        ("analyst_a_new", "analyst_a"),
        ("revoked", "revoked.analyst"),
        ("unknown", "unknown.analyst"),
    ):
        result[name] = _certificate(
            directory,
            name,
            human_ca,
            purpose="clientAuth",
            san=f"URI:urn:threatfusion:human:{actor}",
        )
    result["producer"] = _certificate(
        directory,
        "producer",
        producer_ca,
        purpose="clientAuth",
        san="URI:urn:threatfusion:producer:tf-demo-unsw-replay-01",
    )
    result["wrong_san"] = _certificate(
        directory,
        "wrong-san",
        human_ca,
        purpose="clientAuth",
        san="URI:urn:threatfusion:producer:tf-demo-unsw-replay-01",
    )
    result["wrong_eku"] = _certificate(
        directory,
        "wrong-eku",
        human_ca,
        purpose="serverAuth",
        san="URI:urn:threatfusion:human:analyst_a",
    )
    result["no_eku"] = _certificate(
        directory,
        "no-eku",
        human_ca,
        purpose=None,
        san="URI:urn:threatfusion:human:queue.viewer",
    )
    try:
        yield result
    finally:
        shutil.rmtree(directory)


def _fingerprint(certificate: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))
    return hashlib.sha256(der).hexdigest()


def _registry(certs, *, include_new=False, revoked=()) -> HumanCredentialRegistry:
    now = datetime.now(UTC)
    entries = []
    for name, actor in (
        ("viewer", "queue.viewer"),
        ("analyst_a", "analyst_a"),
        ("analyst_b", "analyst.b"),
        ("revoked", "revoked.analyst"),
        ("wrong_san", "analyst_a"),
        ("wrong_eku", "analyst_a"),
    ):
        entries.append(
            HumanCredential(
                actor,
                _fingerprint(certs[name][0]),
                True,
                name == "revoked" or name in revoked,
                now - timedelta(hours=1),
                now + timedelta(hours=1),
            )
        )
    if include_new:
        entries.append(
            HumanCredential(
                "analyst_a",
                _fingerprint(certs["analyst_a_new"][0]),
                True,
                False,
                now - timedelta(hours=1),
                now + timedelta(hours=1),
            )
        )
    return HumanCredentialRegistry(tuple(entries))


def _listener(
    tmp_path,
    certs,
    credentials=None,
    *,
    disabled_actor=False,
    empty_queue=False,
    two_alerts=False,
    candidate=None,
):
    candidate = candidate or _candidate(1)
    alerts = AlertCandidateRepository(tmp_path / "alerts.sqlite3")
    if not empty_queue:
        alerts.insert(candidate)
        if two_alerts:
            alerts.insert(_candidate(2))
    authorization = AnalystAuthorizationRegistry(
        (
            AnalystRegistryEntry("queue.viewer", "viewer"),
            AnalystRegistryEntry("analyst_a", "analyst", enabled=not disabled_actor),
            AnalystRegistryEntry("analyst.b", "analyst"),
            AnalystRegistryEntry("revoked.analyst", "analyst"),
        )
    )
    states = AnalystStateRepository(tmp_path / "states.sqlite3", alerts, authorization)
    audit = AnalystSecurityAuditRepository(tmp_path / "audit.sqlite3")

    view = AnalystAlertViewModel(states)
    conf = AnalystTlsConfiguration(certs["server"][0], certs["server"][1], certs["human_ca"])
    srv = AnalystBrowserTlsListener(
        conf, credentials or _registry(certs), authorization, view, audit
    )
    return srv, audit, view, candidate.alert_candidate_id


def _context(certs, name: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=certs["human_ca"])
    if name is not None:
        ctx.load_cert_chain(certs[name][0], certs[name][1])
    return ctx


def _exchange(listener, certs, identity, request, *, context=None):
    failure = []

    def serve():
        try:
            listener.process_one()
        except BaseException as error:
            failure.append(error)

    worker = Thread(target=serve)
    worker.start()
    try:
        with socket.create_connection(listener.address, timeout=3) as raw:
            with (context or _context(certs, identity)).wrap_socket(
                raw, server_hostname="localhost"
            ) as client:
                client.settimeout(5)
                for part in request if type(request) is tuple else (request,):
                    client.sendall(part)
                chunks = []
                try:
                    while chunk := client.recv(4096):
                        chunks.append(chunk)
                except ssl.SSLEOFError:
                    pass
        response = b"".join(chunks)
    except (OSError, ssl.SSLError):
        response = b""
    worker.join(timeout=8)
    assert not worker.is_alive()
    assert not failure
    if not response:
        return None, b"", b""
    head, body = response.split(b"\r\n\r\n", 1)
    return int(head.split(b" ")[1]), head, body


def _req(port, target="/", extra="", method="GET") -> bytes:
    return f"{method} {target} HTTP/1.1\r\nHost: localhost:{port}\r\n{extra}\r\n".encode("ascii")


def test_browser_tls_authorized_viewer_html_response(tmp_path, certificates):
    srv, audit, view, candidate_id = _listener(tmp_path, certificates)
    srv.open()

    code, head, body = _exchange(srv, certificates, "viewer", _req(srv.address[1]))
    srv.close()

    assert code == 200
    html = body.decode("utf-8")
    assert "<title>ThreatFusion Analyst Dashboard</title>" in html
    assert candidate_id[:16] in html

    head_str = head.decode("ascii")
    assert "Cache-Control: no-store" in head_str
    assert (
        "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
        in head_str
    )
    assert "Content-Length: " in head_str

    records = list(audit.list())
    assert len(records) == 2
    assert records[0].event_type == "request_admitted"
    assert records[1].event_type == "request_completed"


def test_browser_tls_empty_queue(tmp_path, certificates):
    srv, audit, view, _ = _listener(tmp_path, certificates, empty_queue=True)
    srv.open()

    code, head, body = _exchange(srv, certificates, "viewer", _req(srv.address[1]))
    srv.close()

    assert code == 200
    html = body.decode("utf-8")
    assert "empty" in html  # Status: empty


def test_browser_tls_backend_detail_failure(tmp_path, certificates):
    srv, audit, view, _ = _listener(tmp_path, certificates)
    srv.open()

    def _fail(*args, **kwargs):
        raise AnalystViewError("not_found")

    view.get_alert = _fail

    code, head, body = _exchange(srv, certificates, "viewer", _req(srv.address[1]))
    srv.close()

    assert code == 200
    html = body.decode("utf-8")
    assert "Status: <b>unavailable</b>" in html


def test_browser_tls_backend_503_is_audited_as_failure(tmp_path, certificates, monkeypatch):
    srv, audit, view, _ = _listener(tmp_path, certificates)
    srv.open()

    def _fail(*args, **kwargs):
        raise AnalystViewError("unavailable")

    monkeypatch.setattr(view, "list_alerts", _fail)
    code, _, body = _exchange(srv, certificates, "viewer", _req(srv.address[1]))
    srv.close()

    assert code == 503
    assert b"Unavailable" in body
    assert [event.event_type for event in audit.list()] == ["request_admitted", "internal_failure"]


def test_browser_tls_oversized_html_fails_safely(tmp_path, certificates, monkeypatch):
    srv, audit, _, _ = _listener(tmp_path, certificates)
    srv.open()
    marker = "private-rendered-value"
    monkeypatch.setattr(
        browser_service,
        "render_dashboard_html",
        lambda *args, **kwargs: marker + "x" * browser_service.MAX_BROWSER_RESPONSE_BYTES,
    )

    code, head, body = _exchange(srv, certificates, "viewer", _req(srv.address[1]))
    srv.close()

    assert code == 503
    assert marker.encode() not in body
    assert len(body) < browser_service.MAX_BROWSER_RESPONSE_BYTES
    assert f"Content-Length: {len(body)}".encode() in head
    assert [event.event_type for event in audit.list()] == ["request_admitted", "internal_failure"]


def test_browser_tls_queue_links_navigate_to_other_alert(tmp_path, certificates, monkeypatch):
    srv, audit, view, first_id = _listener(tmp_path, certificates, two_alerts=True)
    other_id = _candidate(2).alert_candidate_id
    srv.open()
    original_list = view.list_alerts

    def unsafe_label(*args, **kwargs):
        result = original_list(*args, **kwargs)
        result["items"][0]["detection_evidence"]["model_identity"] = "<script>unsafe</script>"
        return result

    monkeypatch.setattr(view, "list_alerts", unsafe_label)

    code, _, body = _exchange(srv, certificates, "viewer", _req(srv.address[1]))
    assert code == 200
    html = body.decode("utf-8")
    assert f'href="/v1/analyst/alerts/{first_id}"' in html
    link = f"/v1/analyst/alerts/{other_id}"
    assert f'href="{link}"' in html
    assert "&lt;script&gt;unsafe&lt;/script&gt;" in html
    assert "<script>unsafe</script>" not in html

    detail_code, _, detail_body = _exchange(srv, certificates, "viewer", _req(srv.address[1], link))
    srv.close()

    assert detail_code == 200
    assert f"Candidate ID:</b> <code>{other_id}</code>" in detail_body.decode("utf-8")
    assert [event.event_type for event in audit.list()] == [
        "request_admitted",
        "request_completed",
        "request_admitted",
        "request_completed",
    ]


@pytest.mark.parametrize("failure_type", ["authentication", "authorization"])
def test_browser_tls_recheck_audit_type(tmp_path, certificates, monkeypatch, failure_type):
    srv, audit, _, _ = _listener(tmp_path, certificates)
    srv.open()
    if failure_type == "authentication":
        target = srv._credentials
        method = "_actor_for_verified_peer"
        error = browser_service.AnalystTlsError("authentication_failed")
    else:
        target = srv._authorization
        method = "issue_for_trusted_actor"
        error = AnalystStateError("analyst_not_authorized")
    original = getattr(target, method)
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise error
        return original(*args, **kwargs)

    monkeypatch.setattr(target, method, fail_second)
    code, _, body = _exchange(srv, certificates, "viewer", _req(srv.address[1]))
    srv.close()

    assert code == 401
    assert b"Authentication failed" in body
    assert calls == 2
    assert [event.event_type for event in audit.list()] == [
        "request_admitted",
        f"{failure_type}_rejected",
    ]


def test_browser_tls_admission_audit_failure(tmp_path, certificates, monkeypatch):
    srv, audit, view, _ = _listener(tmp_path, certificates)
    srv.open()

    def _fail(*args, **kwargs):
        raise AnalystSecurityAuditError("disk_full")

    monkeypatch.setattr(audit, "append", _fail)

    code, head, body = _exchange(srv, certificates, "viewer", _req(srv.address[1]))
    srv.close()

    assert code == 503


def test_browser_tls_completion_audit_failure(tmp_path, certificates, monkeypatch):
    srv, audit, view, _ = _listener(tmp_path, certificates)
    srv.open()

    original = audit.append

    def _append(ev):
        if ev.event_type == "request_completed":
            raise AnalystSecurityAuditError("disk_full")
        original(ev)

    monkeypatch.setattr(audit, "append", _append)

    code, head, body = _exchange(srv, certificates, "viewer", _req(srv.address[1]))
    srv.close()

    assert code == 503
    html = body.decode("utf-8")
    assert "503 Error" in html


@pytest.mark.parametrize("identity", [None, "producer", "wrong_eku"])
def test_browser_tls_rejects_missing_or_invalid_certificate(tmp_path, certificates, identity):
    srv, audit, view, _ = _listener(tmp_path, certificates)
    srv.open()

    code, head, body = _exchange(srv, certificates, identity, _req(srv.address[1]))
    srv.close()

    assert code is None
    assert head == body == b""
    assert list(audit.list()) == []


def test_browser_tls_rejects_revoked(tmp_path, certificates):
    srv, audit, view, _ = _listener(tmp_path, certificates)
    srv.open()

    code, head, body = _exchange(srv, certificates, "revoked", _req(srv.address[1]))
    srv.close()

    assert code in (None, 401)
    if code == 401:
        assert "Authentication failed" in body.decode("utf-8")

    records = list(audit.list())
    assert len(records) == 1
    assert records[0].event_type == "authentication_rejected"


def test_browser_tls_rejects_untrusted_credentials(tmp_path, certificates):
    srv, audit, view, _ = _listener(tmp_path, certificates)
    srv.open()

    code, head, body = _exchange(srv, certificates, "unknown", _req(srv.address[1]))
    srv.close()

    assert code in (None, 401)
    assert [event.event_type for event in audit.list()] == ["authentication_rejected"]


def test_browser_tls_rejects_wrong_san(tmp_path, certificates):
    srv, audit, _, _ = _listener(tmp_path, certificates)
    srv.open()

    code, _, body = _exchange(srv, certificates, "wrong_san", _req(srv.address[1]))
    srv.close()

    assert code in (None, 401)
    if code == 401:
        assert b"Authentication failed" in body
    assert [event.event_type for event in audit.list()] == ["authentication_rejected"]


def test_browser_tls_rejects_host_origin_framing(tmp_path, certificates):
    srv, audit, view, _ = _listener(tmp_path, certificates)
    srv.open()

    # Bad host
    req = "GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n".encode("ascii")
    code, head, body = _exchange(srv, certificates, "viewer", req)
    assert code == 400

    # Bad origin
    req = f"GET / HTTP/1.1\r\nHost: localhost:{srv.address[1]}\r\nOrigin: https://evil.com\r\n\r\n".encode(
        "ascii"
    )
    code, head, body = _exchange(srv, certificates, "viewer", req)
    assert code == 400

    # Bad framing (content-length in GET)
    req = (
        f"GET / HTTP/1.1\r\nHost: localhost:{srv.address[1]}\r\nContent-Length: 10\r\n\r\n".encode(
            "ascii"
        )
    )
    code, head, body = _exchange(srv, certificates, "viewer", req)
    assert code == 400

    # Duplicate header
    req = f"GET / HTTP/1.1\r\nHost: localhost:{srv.address[1]}\r\nHost: localhost:{srv.address[1]}\r\n\r\n".encode(
        "ascii"
    )
    code, head, body = _exchange(srv, certificates, "viewer", req)
    assert code == 400

    srv.close()


def test_browser_tls_rejects_non_get_request(tmp_path, certificates):
    srv, audit, view, _ = _listener(tmp_path, certificates)
    srv.open()

    code, head, body = _exchange(srv, certificates, "viewer", _req(srv.address[1], method="POST"))
    srv.close()

    assert code == 400


def test_browser_tls_slow_incomplete_request(tmp_path, certificates):
    srv, audit, view, _ = _listener(tmp_path, certificates)
    srv.open()
    original_deadline = browser_service.REQUEST_SECONDS
    browser_service.REQUEST_SECONDS = 0.35
    failures = []

    def serve():
        try:
            srv.process_one()
        except BaseException as error:
            failures.append(error)

    worker = Thread(target=serve)
    worker.start()

    def slow_request():
        yield b"GET / HT"
        time.sleep(0.12)
        yield b"TP/1.1\r\n"
        time.sleep(0.12)
        yield b"Host: localhost"

    try:
        with socket.create_connection(srv.address, timeout=2) as raw:
            with _context(certificates, "viewer").wrap_socket(
                raw, server_hostname="localhost"
            ) as client:
                client.settimeout(2)
                start = time.monotonic()
                for segment in slow_request():
                    client.sendall(segment)
                response = client.recv(4096)
                elapsed = time.monotonic() - start
    finally:
        browser_service.REQUEST_SECONDS = original_deadline
        worker.join(timeout=2)
        srv.close()

    assert response.startswith(b"HTTP/1.1 400 Error\r\n")
    assert 0.30 <= elapsed < 1.0
    assert not worker.is_alive()
    assert failures == []
    assert [event.event_type for event in audit.list()] == ["request_rejected"]


def test_browser_tls_close_interrupts_incomplete_request(tmp_path, certificates):
    srv, audit, _, _ = _listener(tmp_path, certificates)
    srv.open()
    failures = []

    def serve():
        try:
            srv.process_one()
        except BaseException as error:
            failures.append(error)

    worker = Thread(target=serve)
    worker.start()
    with socket.create_connection(srv.address, timeout=2) as raw:
        with _context(certificates, "viewer").wrap_socket(
            raw, server_hostname="localhost"
        ) as client:
            client.sendall(b"GET / HTTP/1.1\r\nHost: localhost")
            start = time.monotonic()
            srv.close()
            worker.join(timeout=1.5)
            elapsed = time.monotonic() - start

    assert elapsed < 1.5
    assert not worker.is_alive()
    assert failures == []
    assert list(audit.list()) == []


def test_browser_factual_explanation_and_failure_isolation(tmp_path, certificates, monkeypatch):
    from backend.tests.unit.test_alert_explanation import approved_candidate
    from threatfusion.api import alert_explanation

    candidate = approved_candidate()
    srv, _, view, candidate_id = _listener(tmp_path, certificates, candidate=candidate)
    viewer = view._repository._authorization.issue_for_trusted_actor("queue.viewer")
    analyst = view._repository._authorization.issue_for_trusted_actor("analyst_a")
    view.transition(
        analyst,
        alert_candidate_id=candidate_id,
        expected_version=0,
        to_state="in_review",
        transition_id="eb636ef4-7a01-4b90-a62b-176a667e62a1",
        rationale="Existing analyst annotation",
    )
    before = view.get_alert(viewer, candidate_id)
    assert before["analyst_state"]["state"] == "in_review"
    assert len(before["analyst_history"]) == 1
    srv.open()
    try:
        target = f"/v1/analyst/alerts/{candidate_id}"
        code, _, body = _exchange(srv, certificates, "viewer", _req(srv.address[1], target))
        assert code == 200
        assert b"Status: available" in body
        assert b"alert_explanation_v1" in body
        assert b"Stored frozen-RF score 0.75" in body
        assert b"Feature attribution: unavailable" in body
        assert candidate_id.encode() in body

        def fail(_):
            raise RuntimeError("private-explanation-secret")

        monkeypatch.setattr(alert_explanation, "generate_explanation", fail)
        code, _, body = _exchange(srv, certificates, "viewer", _req(srv.address[1], target))
        assert code == 200
        assert b"Status: unavailable" in body
        assert b"private-explanation-secret" not in body
        after = view.get_alert(viewer, candidate_id)
        for key in ("detection_evidence", "analyst_state", "analyst_history"):
            assert before[key] == after[key]
        assert after["explanation"]["status"] == "unavailable"
        assert view._repository._alerts.get(candidate_id) == candidate
    finally:
        srv.close()
