"""Both policy-backed human listeners, real TLS, and controlled generation changes."""

import json
import socket
import ssl
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from uuid import uuid4

import pytest

from backend.tests.integration import test_analyst_tls_service as api
from backend.tests.integration import test_analyst_browser_tls_service as browser
from backend.tests.integration import test_operator_human_credentials as operator
from threatfusion.api.analyst_browser_tls_service import AnalystBrowserTlsListener
from threatfusion.operations import human_credentials as policy
from threatfusion.operations import human_listener_lifecycle as lifecycle
from threatfusion.operations.human_listener_lifecycle import (
    HumanLifecycleError,
    HumanListenerLifecycle,
)

certificates = api.certificates
directory = operator.directory


@pytest.fixture
def setup(tmp_path, certificates, directory):
    fingerprint = operator.enroll(directory, certificates)
    operator.enroll(directory, certificates, "analyst_a", "analyst_a", create=False)
    template, candidate, alerts, states, audit = api._listener(tmp_path, certificates)
    service = HumanListenerLifecycle(
        directory,
        template._configuration,
        template._configuration,
        template._authorization,
        template._view,
        audit,
    )
    try:
        yield service, fingerprint, template, candidate, states, audit
    finally:
        service.shutdown()


def exchange(address, certificates, identity, request):
    chunks = []
    try:
        with socket.create_connection(address, timeout=3) as raw:
            with api._context(certificates, identity).wrap_socket(
                raw, server_hostname="localhost"
            ) as client:
                client.settimeout(5)
                client.sendall(request)
                while chunk := client.recv(4096):
                    chunks.append(chunk)
    except (OSError, ssl.SSLError):
        pass
    raw = b"".join(chunks)
    return (int(raw.split(b" ")[1]), raw.split(b"\r\n\r\n", 1)[1]) if raw else (None, b"")


def reads(service, certificates, identity):
    api_address, browser_address = service.addresses
    return (
        exchange(api_address, certificates, identity, api._request("GET", "/v1/analyst/alerts")),
        exchange(browser_address, certificates, identity, browser._req(browser_address[1])),
    )


def closed(addresses, workers):
    assert all(not worker.is_alive() for worker in workers)
    for address in addresses:
        with socket.socket() as probe:
            probe.settimeout(1)
            assert probe.connect_ex(address) != 0


@pytest.mark.parametrize("revoke", [False, True])
def test_replace_denies_exact_certificate_and_preserves_audit(
    setup, certificates, directory, monkeypatch, revoke
):
    service, fingerprint, template, _, _, audit = setup
    assert service.replace()["generation"] == 1
    assert all(code == 200 for code, _ in reads(service, certificates, "viewer"))
    addresses, workers = service.addresses, tuple(w for w, _, _ in service._workers)
    policy.restrict(directory, fingerprint, revoke=revoke)
    assert service.snapshot()["generation"] == 1
    assert all(code == 200 for code, _ in reads(service, certificates, "viewer"))
    history = audit.list(limit=100)
    assert service.replace()["generation"] == 2
    assert all(not worker.is_alive() for worker in workers)
    # Ephemeral ports could be reused; old objects themselves must be closed.
    assert addresses != ()
    calls = []
    original = template._view.list_alerts
    monkeypatch.setattr(template._view, "list_alerts", lambda *a, **k: calls.append(1))
    denied = reads(service, certificates, "viewer")
    assert all(code in (None, 401) for code, _ in denied)
    assert all(b"alert_candidate_v1:" not in body for _, body in denied)
    assert calls == []
    events = audit.list(limit=100)
    assert events[: len(history)] == history
    assert len(events[len(history) :]) == 2
    for event in events[len(history) :]:
        assert (event.event_type, event.reason_code, event.actor_id, event.credential_sha256) == (
            "authentication_rejected",
            "authentication_failed",
            None,
            fingerprint,
        )
    monkeypatch.setattr(template._view, "list_alerts", original)
    assert all(code == 200 for code, _ in reads(service, certificates, "analyst_a"))
    addresses, workers = service.addresses, tuple(w for w, _, _ in service._workers)
    assert service.shutdown()["state"] == "stopped"
    closed(addresses, workers)


@pytest.mark.parametrize(
    "damage", ["corrupt", "missing", "unsafe", "expired", "unauthorized", "tls", "view", "audit"]
)
def test_invalid_replacement_stops_old_generation(
    setup, certificates, directory, damage, monkeypatch
):
    service, _, template, _, _, audit = setup
    service.replace()
    addresses, workers = service.addresses, tuple(w for w, _, _ in service._workers)
    path = directory / policy.FILENAME
    data = json.loads(path.read_text())
    if damage == "corrupt":
        path.write_text("{")
    elif damage == "missing":
        path.unlink()
    elif damage == "unsafe":
        path.chmod(0o644)
    elif damage in ("expired", "unauthorized"):
        if damage == "expired":
            data["credentials"][0]["not_after"] = (
                datetime.now(UTC) - timedelta(seconds=1)
            ).isoformat()
        else:
            data["credentials"][0]["actor_id"] = "absent.actor"
        path.write_text(json.dumps(data))
    elif damage == "tls":
        args = list(service._arguments)
        args[2] = replace(template._configuration, human_ca_path=directory / "absent")
        service._arguments = tuple(args)
    else:

        def fail(*args, **kwargs):
            raise RuntimeError("secret filesystem detail")

        monkeypatch.setattr(
            template._view if damage == "view" else audit,
            "list_alerts" if damage == "view" else "list",
            fail,
        )
    with pytest.raises(HumanLifecycleError, match="^human_lifecycle_failed$"):
        service.replace()
    assert service.snapshot() == {
        "state": "failed",
        "generation": 1,
        "accepting": False,
        "live_workers": 0,
    }
    closed(addresses, workers)
    # The identical invalid input also fails on a cold start.
    with pytest.raises(HumanLifecycleError):
        service.replace()
    assert not service._listeners


@pytest.mark.parametrize("interrupt", [False, True])
def test_second_open_failure_closes_first(setup, monkeypatch, interrupt):
    service = setup[0]
    opened = []
    original = api.AnalystTlsListener.open

    def capture(listener):
        original(listener)
        opened.append(listener.address)

    def fail(listener):
        raise KeyboardInterrupt if interrupt else RuntimeError("private details")

    monkeypatch.setattr(api.AnalystTlsListener, "open", capture)
    monkeypatch.setattr(AnalystBrowserTlsListener, "open", fail)
    with pytest.raises(KeyboardInterrupt if interrupt else HumanLifecycleError):
        service.replace()
    assert len(opened) == 1
    closed(opened, tuple(w for w, _, _ in service._workers))
    assert not service.snapshot()["accepting"]


def test_context_interruption_closes_pending_handshakes(setup):
    service = setup[0]
    sockets = []
    try:
        with pytest.raises(KeyboardInterrupt):
            with service:
                addresses, workers = service.addresses, tuple(w for w, _, _ in service._workers)
                sockets = [socket.create_connection(address, timeout=2) for address in addresses]
                raise KeyboardInterrupt
        closed(addresses, workers)
        assert service.snapshot()["state"] == "stopped"
    finally:
        for connection in sockets:
            connection.close()


def test_dispatched_transition_drains_and_same_uuid_retries(setup, certificates, monkeypatch):
    service, _, template, candidate, states, audit = setup
    dispatched, finish, stopping = Event(), Event(), Event()
    original = template._view.transition

    def pause(*args, **kwargs):
        dispatched.set()
        assert finish.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(template._view, "transition", pause)
    service.replace()
    addresses, workers = service.addresses, tuple(w for w, _, _ in service._workers)
    request = api._transition(candidate, str(uuid4()))
    client = Thread(target=exchange, args=(addresses[0], certificates, "analyst_a", request))
    original_stop = service._stop_admission

    def stop():
        original_stop()
        stopping.set()

    monkeypatch.setattr(service, "_stop_admission", stop)
    shutdown = Thread(target=service.shutdown)
    try:
        client.start()
        assert dispatched.wait(3)
        shutdown.start()
        assert stopping.wait(3)
        assert shutdown.is_alive()
        assert service.snapshot()["state"] == "stopping"
        assert all(listener._admission_stopped.is_set() for listener in service._listeners)
    finally:
        finish.set()
        client.join(6)
        if shutdown.ident is not None:
            shutdown.join(6)
    assert not shutdown.is_alive()
    closed(addresses, workers)
    monkeypatch.setattr(template._view, "transition", original)
    service.replace()
    code, body = exchange(service.addresses[0], certificates, "analyst_a", request)
    assert code == 200 and json.loads(body)["disposition"] == "existing"
    capability = template._authorization.issue_for_trusted_actor("analyst_a")
    assert len(states.get_alert(capability, candidate.alert_candidate_id).transitions) == 1


def test_partial_worker_start_is_joined(setup, monkeypatch):
    service = setup[0]
    original = Thread.start
    started = []

    def start(worker):
        if started:
            raise RuntimeError("private start failure")
        original(worker)
        started.append(worker)

    monkeypatch.setattr(lifecycle.Thread, "start", start)
    with pytest.raises(HumanLifecycleError):
        service.replace()
    assert len(started) == 1 and not started[0].is_alive()
    assert service.snapshot()["live_workers"] == 0
    assert not service._listeners


def test_interrupt_during_close_finishes_cleanup(setup, monkeypatch):
    service = setup[0]
    service.replace()
    addresses, workers = service.addresses, tuple(w for w, _, _ in service._workers)
    listener = service._listeners[0]
    original = listener.close
    attempts = []

    def close():
        attempts.append(1)
        if len(attempts) == 1:
            raise KeyboardInterrupt
        original()

    monkeypatch.setattr(listener, "close", close)
    with pytest.raises(KeyboardInterrupt):
        service.shutdown()
    assert service.snapshot()["state"] == "stopped"
    closed(addresses, workers)


def test_invalid_state_schema_fails_even_with_empty_queue(setup):
    service, _, template, _, states, _ = setup
    with sqlite3.connect(template._view._repository._alerts._database_path) as connection:
        connection.execute("DELETE FROM alert_candidates")
    with sqlite3.connect(states._database_path) as connection:
        connection.execute("PRAGMA user_version = 999")
    with pytest.raises(HumanLifecycleError):
        service.replace()
    assert not service._listeners


def test_stalled_handshake_does_not_block_replace_or_shutdown(setup, certificates):
    """A client stalling mid-TLS-handshake does not block lifecycle replace or shutdown."""
    import time

    service, _, _, _, _, _ = setup
    service.replace()
    _, browser_address = service.addresses
    workers_before = tuple(w for w, _, _ in service._workers)

    # Raw TCP client connects to browser listener and stalls mid-handshake
    stalled = socket.create_connection(browser_address, timeout=2)
    try:
        time.sleep(0.1)

        start = time.monotonic()
        snapshot = service.replace()
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, f"replace() blocked for {elapsed:.2f}s"
        assert snapshot["state"] == "accepting"
        assert all(not w.is_alive() for w in workers_before)
    finally:
        stalled.close()

    # Now test shutdown with stalled client
    _, browser_address_2 = service.addresses
    workers_2 = tuple(w for w, _, _ in service._workers)
    stalled_2 = socket.create_connection(browser_address_2, timeout=2)
    try:
        time.sleep(0.1)

        start = time.monotonic()
        shutdown_snapshot = service.shutdown()
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, f"shutdown() blocked for {elapsed:.2f}s"
        assert shutdown_snapshot["state"] == "stopped"
        assert all(not w.is_alive() for w in workers_2)
    finally:
        stalled_2.close()
