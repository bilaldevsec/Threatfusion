"""Real loopback TLS authorization with separate ephemeral human credentials."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import ssl
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread
from uuid import uuid4

import pytest

import threatfusion.api.analyst_tls_service as analyst_transport

from threatfusion.api.analyst_tls_service import (
    ANALYST_HOST,
    AnalystTlsConfiguration,
    AnalystTlsError,
    AnalystTlsListener,
    HumanCredential,
    HumanCredentialRegistry,
    _read_request,
)
from threatfusion.api.analyst_view_model import AnalystAlertViewModel
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.analyst_state_repository import AnalystStateRepository
from threatfusion.schemas.analyst_state import AnalystAuthorizationRegistry, AnalystRegistryEntry

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
        "-CAcreateserial",
        "-out",
        str(certificate),
        "-days",
        "2",
        "-sha256",
        "-extfile",
        str(extension),
    )
    return certificate, key


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    directory = tmp_path_factory.mktemp("analyst-tls-certificates")
    human_ca = _ca(directory, "human")
    producer_ca = _ca(directory, "producer")
    result = {"human_ca": human_ca[0], "producer_ca": producer_ca[0]}
    result["server"] = _certificate(
        directory, "analyst-server", human_ca, purpose="serverAuth", san="DNS:localhost"
    )
    for name, actor in (
        ("viewer", "queue.viewer"),
        ("analyst_a", "analyst.a"),
        ("analyst_b", "analyst.b"),
        ("analyst_a_new", "analyst.a"),
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
        san="URI:urn:threatfusion:human:analyst.a",
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
        ("analyst_a", "analyst.a"),
        ("analyst_b", "analyst.b"),
        ("revoked", "revoked.analyst"),
        ("wrong_san", "analyst.a"),
        ("wrong_eku", "analyst.a"),
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
                "analyst.a",
                _fingerprint(certs["analyst_a_new"][0]),
                True,
                False,
                now - timedelta(hours=1),
                now + timedelta(hours=1),
            )
        )
    return HumanCredentialRegistry(tuple(entries))


def _listener(tmp_path, certs, credentials=None, *, disabled_actor=False):
    candidate = _candidate(1)
    alerts = AlertCandidateRepository(tmp_path / "alerts.sqlite3")
    alerts.insert(candidate)
    authorization = AnalystAuthorizationRegistry(
        (
            AnalystRegistryEntry("queue.viewer", "viewer"),
            AnalystRegistryEntry("analyst.a", "analyst", enabled=not disabled_actor),
            AnalystRegistryEntry("analyst.b", "analyst"),
            AnalystRegistryEntry("revoked.analyst", "analyst"),
        )
    )
    states = AnalystStateRepository(tmp_path / "states.sqlite3", alerts, authorization)
    configuration = AnalystTlsConfiguration(
        certs["server"][0], certs["server"][1], certs["human_ca"]
    )
    listener = AnalystTlsListener(
        configuration, credentials or _registry(certs), authorization, AnalystAlertViewModel(states)
    )
    return listener, candidate, alerts, states


def _context(certs, identity):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cafile=certs["human_ca"])
    if identity is not None:
        context.load_cert_chain(*certs[identity])
    return context


def _request(method, target, payload=None, *, extra_headers=(), raw_body=None):
    if raw_body is not None:
        body = raw_body
    elif payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    else:
        body = b""
    lines = [f"{method} {target} HTTP/1.1", f"Host: {ANALYST_HOST}", "Connection: close"]
    if method == "POST":
        lines += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
    lines += list(extra_headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


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
        return None, None
    head, body = response.split(b"\r\n\r\n", 1)
    return int(head.split(b" ")[1]), json.loads(body)


def _transition(candidate, transition_id, *, rationale="Reviewed"):
    return _request(
        "POST",
        f"/v1/analyst/alerts/{candidate.alert_candidate_id}/transitions",
        {
            "expected_version": 0,
            "to_state": "in_review",
            "transition_id": transition_id,
            "rationale": rationale,
        },
    )


def test_real_tls_viewer_read_analyst_write_and_identity_bound_replay(tmp_path, certificates):
    listener, candidate, alerts, states = _listener(tmp_path, certificates)
    with listener:
        status, page = _exchange(
            listener, certificates, "viewer", _request("GET", "/v1/analyst/alerts?limit=1&offset=0")
        )
        assert status == 200
        assert (
            page["items"][0]["detection_evidence"]["alert_candidate_id"]
            == candidate.alert_candidate_id
        )
        status, detail = _exchange(
            listener,
            certificates,
            "viewer",
            _request("GET", f"/v1/analyst/alerts/{candidate.alert_candidate_id}"),
        )
        assert status == 200 and detail["analyst_history"] == []
        operation = str(uuid4())
        status, denied = _exchange(
            listener, certificates, "viewer", _transition(candidate, operation)
        )
        assert (status, denied) == (403, {"error": "forbidden"})
        before = alerts.get(candidate.alert_candidate_id)
        status, created = _exchange(
            listener, certificates, "analyst_a", _transition(candidate, operation)
        )
        assert status == 200 and created["disposition"] == "created"
        assert created["analyst_transition"]["actor_id"] == "analyst.a"
        status, replay = _exchange(
            listener, certificates, "analyst_a", _transition(candidate, operation)
        )
        assert status == 200 and replay["disposition"] == "existing"
        status, conflict = _exchange(
            listener, certificates, "analyst_b", _transition(candidate, operation)
        )
        assert (status, conflict) == (409, {"error": "conflict"})
        status, stale = _exchange(
            listener, certificates, "analyst_b", _transition(candidate, str(uuid4()))
        )
        assert (status, stale) == (409, {"error": "conflict"})
        assert alerts.get(candidate.alert_candidate_id) == before
        assert (
            states.get_alert(
                states._authorization.issue_for_trusted_actor("queue.viewer"),
                candidate.alert_candidate_id,
            ).analyst_state.version
            == 1
        )


def test_real_tls_rejects_missing_revoked_producer_unknown_and_malformed(tmp_path, certificates):
    listener, candidate, _, states = _listener(tmp_path, certificates)
    read = _request("GET", "/v1/analyst/alerts")
    with listener:
        assert _exchange(listener, certificates, None, read)[0] is None
        assert _exchange(listener, certificates, "producer", read)[0] is None
        assert _exchange(listener, certificates, "wrong_eku", read)[0] is None
        for identity in ("revoked", "unknown", "wrong_san"):
            assert _exchange(listener, certificates, identity, read) in (
                (None, None),
                (401, {"error": "authentication_failed"}),
            ), identity
        for request in (
            _request("GET", "/v1/analyst/alerts", extra_headers=("X-Role: analyst",)),
            _request(
                "POST",
                f"/v1/analyst/alerts/{candidate.alert_candidate_id}/transitions",
                raw_body=b"{}",
            ),
            _request(
                "POST",
                f"/v1/analyst/alerts/{candidate.alert_candidate_id}/transitions",
                raw_body=(
                    b'{"expected_version":0,"to_state":"in_review",'
                    b'"transition_id":"' + str(uuid4()).encode("ascii") + b'",'
                    b'"rationale":"first","rationale":"second"}'
                ),
            ),
            _request("GET", "/v1/producer-events"),
            _request("GET", "/v1/analyst/alerts?limit=101"),
        ):
            status, body = _exchange(listener, certificates, "analyst_a", request)
            assert status == 400 and body == {"error": "request_invalid"}
        forged = _request(
            "POST",
            f"/v1/analyst/alerts/{candidate.alert_candidate_id}/transitions",
            {
                "expected_version": 0,
                "to_state": "in_review",
                "transition_id": str(uuid4()),
                "rationale": "Reviewed",
                "actor_id": "analyst.a",
                "role": "analyst",
            },
        )
        assert _exchange(listener, certificates, "viewer", forged) == (
            400,
            {"error": "request_invalid"},
        )
        assert (
            states.get_alert(
                states._authorization.issue_for_trusted_actor("queue.viewer"),
                candidate.alert_candidate_id,
            ).transitions
            == ()
        )


def test_registry_rejects_disabled_expired_and_reused_fingerprint(certificates):
    now = datetime.now(UTC)
    certificate = HumanCredential(
        "analyst.a",
        _fingerprint(certificates["analyst_a"][0]),
        False,
        False,
        now - timedelta(hours=1),
        now + timedelta(hours=1),
    )
    der = ssl.PEM_cert_to_DER_cert(certificates["analyst_a"][0].read_text(encoding="ascii"))
    decoded = {"subjectAltName": (("URI", "urn:threatfusion:human:analyst.a"),)}
    with pytest.raises(AnalystTlsError, match="^authentication_failed$"):
        HumanCredentialRegistry((certificate,))._actor_for_verified_peer(der, decoded, now)
    for changed in (
        replace(certificate, enabled=True, revoked=True),
        replace(certificate, enabled=True, not_before=now + timedelta(minutes=1)),
        replace(certificate, enabled=True, not_after=now - timedelta(minutes=1)),
    ):
        with pytest.raises(AnalystTlsError, match="^authentication_failed$"):
            HumanCredentialRegistry((changed,))._actor_for_verified_peer(der, decoded, now)
    with pytest.raises(AnalystTlsError, match="^configuration_invalid$"):
        HumanCredentialRegistry((certificate, certificate))


def test_rotation_overlap_then_restart_revokes_old_certificate(tmp_path, certificates):
    old = _request("GET", "/v1/analyst/alerts?limit=1")
    listener, _, _, _ = _listener(tmp_path, certificates, _registry(certificates, include_new=True))
    with listener:
        assert _exchange(listener, certificates, "analyst_a", old)[0] == 200
        assert _exchange(listener, certificates, "analyst_a_new", old)[0] == 200
    listener, _, _, _ = _listener(
        tmp_path, certificates, _registry(certificates, include_new=True, revoked=("analyst_a",))
    )
    with listener:
        assert _exchange(listener, certificates, "analyst_a", old)[0] in (None, 401)
        assert _exchange(listener, certificates, "analyst_a_new", old)[0] == 200


def test_transport_does_not_reflect_storage_exception(tmp_path, certificates, monkeypatch):
    listener, _, _, states = _listener(tmp_path, certificates)

    def broken(*args, **kwargs):
        raise RuntimeError("secret /tmp/alerts.sqlite3 password=example")

    monkeypatch.setattr(states, "list_alerts", broken)
    with listener:
        status, body = _exchange(
            listener, certificates, "viewer", _request("GET", "/v1/analyst/alerts")
        )
    assert (status, body) == (503, {"error": "unavailable"})


def test_fragmented_body_rejects_present_trailing_bytes():
    """Splitting the head from body must not make trailing bytes acceptable."""
    request = _request("POST", "/v1/analyst/alerts/id/transitions", raw_body=b"{}")
    head, body = request.split(b"\r\n\r\n", 1)

    class FragmentedSocket:
        def __init__(self):
            self.chunks = [head + b"\r\n\r\n", body + b"smuggled"]

        def settimeout(self, value):
            pass

        def recv(self, count):
            chunk = self.chunks[0][:count]
            self.chunks[0] = self.chunks[0][count:]
            if not self.chunks[0]:
                self.chunks.pop(0)
            return chunk

        def pending(self):
            return sum(map(len, self.chunks))

    with pytest.raises(AnalystTlsError, match="^request_invalid$"):
        _read_request(FragmentedSocket())


def test_close_prevents_accepted_peer_from_authorizing_after_shutdown(
    tmp_path, certificates, monkeypatch
):
    listener, candidate, _, states = _listener(tmp_path, certificates)
    reached_wrap, resume_wrap = Event(), Event()
    wrap_socket = listener._context.wrap_socket

    def delayed_wrap(*args, **kwargs):
        reached_wrap.set()
        assert resume_wrap.wait(3)
        return wrap_socket(*args, **kwargs)

    monkeypatch.setattr(listener._context, "wrap_socket", delayed_wrap)
    listener.open()
    outcome = []
    client_worker = Thread(
        target=lambda: outcome.append(
            _exchange(listener, certificates, "analyst_a", _transition(candidate, str(uuid4())))
        )
    )
    client_worker.start()
    try:
        assert reached_wrap.wait(3)
        listener.close()
    finally:
        resume_wrap.set()
        client_worker.join(8)
        listener.close()
    assert not client_worker.is_alive()
    viewer = states._authorization.issue_for_trusted_actor("queue.viewer")
    assert states.get_alert(viewer, candidate.alert_candidate_id).transitions == ()


def test_fragmented_tls_transition_with_trailing_bytes_has_zero_effects(tmp_path, certificates):
    listener, candidate, _, states = _listener(tmp_path, certificates)
    head, body = _transition(candidate, str(uuid4())).split(b"\r\n\r\n", 1)
    with listener:
        status, result = _exchange(
            listener, certificates, "analyst_a", (head + b"\r\n\r\n", body + b"extra")
        )
    assert (status, result) == (400, {"error": "request_invalid"})
    viewer = states._authorization.issue_for_trusted_actor("queue.viewer")
    assert states.get_alert(viewer, candidate.alert_candidate_id).transitions == ()


@pytest.mark.parametrize(
    "identity", [None, "producer", "revoked", "unknown", "wrong_san", "wrong_eku"]
)
def test_denied_credentials_cannot_reach_alert_storage_on_any_route(
    tmp_path, certificates, monkeypatch, identity
):
    listener, candidate, alerts, _ = _listener(tmp_path, certificates)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("storage")
        raise AssertionError("unauthorized storage access")

    monkeypatch.setattr(alerts, "list", forbidden)
    monkeypatch.setattr(alerts, "get", forbidden)
    with listener:
        assert listener.address[0] == "127.0.0.1"
        for request in (
            _request("GET", "/v1/analyst/alerts"),
            _request("GET", f"/v1/analyst/alerts/{candidate.alert_candidate_id}"),
            _transition(candidate, str(uuid4())),
        ):
            assert _exchange(listener, certificates, identity, request)[0] in (None, 401)
    assert calls == []


def test_tls12_is_denied_before_storage(tmp_path, certificates, monkeypatch):
    listener, _, alerts, _ = _listener(tmp_path, certificates)
    calls = []
    monkeypatch.setattr(alerts, "list", lambda **kwargs: calls.append("storage"))
    context = _context(certificates, "viewer")
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    with listener:
        assert (
            _exchange(
                listener,
                certificates,
                "viewer",
                _request("GET", "/v1/analyst/alerts"),
                context=context,
            )[0]
            is None
        )
    assert calls == []


def test_exact_registry_validity_boundaries_and_ambiguous_sans(certificates):
    record = _registry(certificates)._records[0]
    der = ssl.PEM_cert_to_DER_cert(certificates["viewer"][0].read_text(encoding="ascii"))
    names = (("URI", "urn:threatfusion:human:queue.viewer"),)
    registry = HumanCredentialRegistry((record,))
    assert (
        registry._actor_for_verified_peer(der, {"subjectAltName": names}, record.not_before)
        == "queue.viewer"
    )
    for timestamp in (record.not_before - timedelta(microseconds=1), record.not_after):
        with pytest.raises(AnalystTlsError, match="^authentication_failed$"):
            registry._actor_for_verified_peer(der, {"subjectAltName": names}, timestamp)
    for sans in ((), names * 2, names + (("URI", "urn:threatfusion:human:analyst.a"),)):
        with pytest.raises(AnalystTlsError, match="^authentication_failed$"):
            registry._actor_for_verified_peer(der, {"subjectAltName": sans}, record.not_before)


def test_close_interrupts_partial_request_and_reopen_cannot_reuse_old_connection(
    tmp_path, certificates, monkeypatch
):
    listener, candidate, _, states = _listener(tmp_path, certificates)
    reading = Event()
    original_read = analyst_transport._read_request

    def read(connection):
        reading.set()
        return original_read(connection)

    monkeypatch.setattr(analyst_transport, "_read_request", read)
    listener.open()
    worker = Thread(target=listener.process_one)
    worker.start()
    try:
        with socket.create_connection(listener.address, timeout=3) as raw:
            with _context(certificates, "analyst_a").wrap_socket(
                raw, server_hostname="localhost"
            ) as client:
                head, _ = _transition(candidate, str(uuid4())).split(b"\r\n\r\n", 1)
                client.sendall(head + b"\r\n\r\n")
                assert reading.wait(2)
                with pytest.raises(AnalystTlsError, match="^listener_busy$"):
                    listener.process_one()
                listener.close()
                worker.join(1)
                assert not worker.is_alive()
        listener.open()
        assert (
            _exchange(listener, certificates, "viewer", _request("GET", "/v1/analyst/alerts"))[0]
            == 200
        )
    finally:
        listener.close()
        worker.join(6)
    viewer = states._authorization.issue_for_trusted_actor("queue.viewer")
    assert states.get_alert(viewer, candidate.alert_candidate_id).transitions == ()


def test_shutdown_waits_for_already_dispatched_transaction(tmp_path, certificates, monkeypatch):
    listener, candidate, _, states = _listener(tmp_path, certificates)
    dispatched, finish, closed = Event(), Event(), Event()
    transition = states.transition

    def delayed_transition(*args, **kwargs):
        dispatched.set()
        assert finish.wait(3)
        return transition(*args, **kwargs)

    monkeypatch.setattr(states, "transition", delayed_transition)
    listener.open()
    client_worker = Thread(
        target=lambda: _exchange(
            listener, certificates, "analyst_a", _transition(candidate, str(uuid4()))
        )
    )
    closer = Thread(target=lambda: (listener.close(), closed.set()))
    client_worker.start()
    try:
        assert dispatched.wait(3)
        closer.start()
        assert not closed.wait(0.05)
    finally:
        finish.set()
        client_worker.join(8)
        if closer.ident is not None:
            closer.join(3)
        listener.close()
    assert closed.is_set() and not client_worker.is_alive()
    viewer = states._authorization.issue_for_trusted_actor("queue.viewer")
    assert states.get_alert(viewer, candidate.alert_candidate_id).analyst_state.version == 1


@pytest.mark.parametrize("stage", ["handshake", "request"])
def test_stalled_connection_terminates_without_storage(tmp_path, certificates, monkeypatch, stage):
    listener, _, alerts, _ = _listener(tmp_path, certificates)
    monkeypatch.setattr(analyst_transport, "HANDSHAKE_SECONDS", 0.1)
    monkeypatch.setattr(analyst_transport, "REQUEST_SECONDS", 0.1)
    calls = []
    monkeypatch.setattr(alerts, "list", lambda **kwargs: calls.append("storage"))
    with listener:
        worker = Thread(target=listener.process_one)
        worker.start()
        with socket.create_connection(listener.address, timeout=3) as raw:
            if stage == "request":
                with _context(certificates, "viewer").wrap_socket(raw, server_hostname="localhost"):
                    worker.join(2)
            else:
                worker.join(2)
        assert not worker.is_alive()
    assert calls == []


def test_credential_expiring_during_read_is_rechecked_before_dispatch(
    tmp_path, certificates, monkeypatch
):
    registry = _registry(certificates)
    original = registry._actor_for_verified_peer
    checks = []

    def verify(der, decoded, now):
        checks.append(now)
        if len(checks) > 1:
            now += timedelta(hours=2)
        return original(der, decoded, now)

    monkeypatch.setattr(registry, "_actor_for_verified_peer", verify)
    listener, candidate, _, states = _listener(tmp_path, certificates, registry)
    with listener:
        assert _exchange(
            listener, certificates, "analyst_a", _transition(candidate, str(uuid4()))
        ) == (401, {"error": "authentication_failed"})
    assert len(checks) == 2
    viewer = states._authorization.issue_for_trusted_actor("queue.viewer")
    assert states.get_alert(viewer, candidate.alert_candidate_id).transitions == ()


def test_openssl_purpose_is_not_an_explicit_eku_extension_policy(tmp_path, certificates):
    """A certificate without EKU still needs explicit operator fingerprint admission."""
    registry = _registry(certificates)
    listener, _, _, _ = _listener(tmp_path, certificates, registry)
    request = _request("GET", "/v1/analyst/alerts")
    with listener:
        assert _exchange(listener, certificates, "no_eku", request)[0] in (None, 401)
    record = replace(
        registry._records[0], certificate_sha256=_fingerprint(certificates["no_eku"][0])
    )
    listener, _, _, _ = _listener(tmp_path, certificates, HumanCredentialRegistry((record,)))
    with listener:
        assert _exchange(listener, certificates, "no_eku", request)[0] == 200


@pytest.mark.parametrize("denial", ["disabled_credential", "disabled_actor", "unknown_actor"])
def test_server_owned_identity_denial_on_all_routes(tmp_path, certificates, monkeypatch, denial):
    registry = _registry(certificates)
    identity = "analyst_a"
    if denial == "disabled_credential":
        registry = HumanCredentialRegistry(
            tuple(
                replace(record, enabled=False) if record.actor_id == "analyst.a" else record
                for record in registry._records
            )
        )
    elif denial == "unknown_actor":
        identity = "unknown"
        registry = HumanCredentialRegistry(
            (
                replace(
                    registry._records[0],
                    actor_id="unknown.analyst",
                    certificate_sha256=_fingerprint(certificates["unknown"][0]),
                ),
            )
        )
    listener, candidate, alerts, _ = _listener(
        tmp_path, certificates, registry, disabled_actor=denial == "disabled_actor"
    )
    calls = []
    monkeypatch.setattr(alerts, "list", lambda **kwargs: calls.append("list"))
    monkeypatch.setattr(alerts, "get", lambda *args: calls.append("get"))
    with listener:
        for request in (
            _request("GET", "/v1/analyst/alerts"),
            _request("GET", f"/v1/analyst/alerts/{candidate.alert_candidate_id}"),
            _transition(candidate, str(uuid4())),
        ):
            assert _exchange(listener, certificates, identity, request)[0] in (None, 401)
    assert calls == []


def test_wire_bounds_and_malformed_commands_have_zero_storage_calls(
    tmp_path, certificates, monkeypatch
):
    listener, candidate, alerts, _ = _listener(tmp_path, certificates)
    calls = []
    monkeypatch.setattr(alerts, "list", lambda **kwargs: calls.append("list"))
    monkeypatch.setattr(alerts, "get", lambda *args: calls.append("get"))
    path = f"/v1/analyst/alerts/{candidate.alert_candidate_id}/transitions"
    with listener:
        for request in (
            _request("POST", path, raw_body=b" " * 2049),
            _request("GET", "/v1/analyst/alerts", extra_headers=("X-Long: " + "a" * 4096,)),
            _request("POST", path, raw_body=b"{}").replace(
                b"Content-Length: 2", b"Content-Length: 02"
            ),
            _request("POST", path, raw_body=b"{}", extra_headers=("Content-Length: 2",)),
            _request("POST", path, raw_body=b"{}", extra_headers=("Transfer-Encoding: chunked",)),
            _request("GET", "/v1/analyst/alerts?limit=1&limit=2"),
            _request("GET", "/v1/analyst/alerts/analyst.a"),
        ):
            assert _exchange(listener, certificates, "analyst_a", request)[0] in (None, 400)
    assert calls == []
