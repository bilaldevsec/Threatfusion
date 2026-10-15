"""Integration tests for the authenticated read-only analyst dashboard slice."""

from __future__ import annotations

import sys
from contextlib import contextmanager
from threading import Thread

import pytest

from threatfusion.api.analyst_dashboard import (
    AnalystDashboardAuthenticationError,
    AnalystDashboardClient,
    AnalystDashboardUnavailableError,
    DashboardAlertQueue,
    DashboardSnapshot,
    _parse_detail,
    _parse_summary,
    create_dashboard_ssl_context,
    render_dashboard_html,
)
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.analyst_security_audit import AnalystSecurityAuditRepository
from threatfusion.db.analyst_state_repository import AnalystStateRepository
from threatfusion.api.analyst_tls_service import AnalystTlsConfiguration, AnalystTlsListener
from threatfusion.api.analyst_view_model import AnalystAlertViewModel
from threatfusion.schemas.analyst_state import AnalystAuthorizationRegistry, AnalystRegistryEntry

from backend.tests.integration.test_analyst_tls_service import (
    _context,
    _listener,
    _registry,
    certificates,  # noqa: F401
)


@pytest.fixture(scope="module")
def analyst_certs(certificates):  # noqa: F811
    return certificates


@contextmanager
def _serve(listener: AnalystTlsListener, count: int = 1):
    failure: list[BaseException] = []

    def runner() -> None:
        for _ in range(count):
            try:
                listener.process_one()
            except BaseException as exc:
                failure.append(exc)
                break

    worker = Thread(target=runner)
    worker.start()
    try:
        yield
    finally:
        worker.join(timeout=8)
        assert not worker.is_alive()
        assert not failure


def test_authenticated_viewer_can_read_alert_list_and_detail(tmp_path, analyst_certs):
    listener, candidate, alerts, states, audit = _listener(tmp_path, analyst_certs)
    context = _context(analyst_certs, "viewer")

    with listener:
        client = AnalystDashboardClient(listener.address, context)
        with _serve(listener, count=1):
            queue = client.list_alerts(limit=10, offset=0)

        assert not queue.is_empty
        assert queue.total_loaded == 1
        assert queue.items[0].alert_candidate_id == candidate.alert_candidate_id
        assert queue.items[0].decision == "Attack"
        assert queue.items[0].state == "new"
        assert queue.items[0].version == 0

        with _serve(listener, count=1):
            detail = client.get_alert(candidate.alert_candidate_id)

        assert detail is not None
        assert detail.alert_candidate_id == candidate.alert_candidate_id
        assert detail.source_event_id == candidate.source_event_id
        assert detail.model_identity == candidate.model_identity
        assert detail.uncalibrated_model_score == candidate.uncalibrated_model_score
        assert detail.decision_threshold == candidate.decision_threshold
        assert detail.decision == candidate.decision
        assert detail.state == "new"
        assert detail.history == ()

        with _serve(listener, count=2):
            snapshot = client.get_dashboard_snapshot()

        assert snapshot.status == "active"
        assert snapshot.selected is not None
        assert snapshot.selected.alert_candidate_id == candidate.alert_candidate_id

        html_view = render_dashboard_html(snapshot)
        assert "ThreatFusion Analyst Dashboard" in html_view
        assert 'href="/v1/analyst/alerts/' not in html_view
        assert "mTLS Authenticated" in html_view
        assert candidate.alert_candidate_id[:16] in html_view
        assert "Attack" in html_view
        assert "new" in html_view


def test_viewing_dashboard_does_not_mutate_analyst_state(tmp_path, analyst_certs):
    listener, candidate, alerts, states, audit = _listener(tmp_path, analyst_certs)
    context = _context(analyst_certs, "viewer")

    viewer_cap = states._authorization.issue_for_trusted_actor("queue.viewer")
    state_before = states.get_alert(viewer_cap, candidate.alert_candidate_id)
    assert state_before.analyst_state.version == 0
    assert state_before.transitions == ()

    with listener:
        client = AnalystDashboardClient(listener.address, context)
        for _ in range(3):
            with _serve(listener, count=1):
                client.list_alerts()
            with _serve(listener, count=1):
                client.get_alert(candidate.alert_candidate_id)

    state_after = states.get_alert(viewer_cap, candidate.alert_candidate_id)
    assert state_after.analyst_state.version == 0
    assert state_after.analyst_state.state == "new"
    assert state_after.transitions == ()


@pytest.mark.parametrize("identity", ["revoked", "unknown", "wrong_san"])
def test_unauthenticated_or_invalid_credential_fails_without_data_leakage(
    tmp_path, analyst_certs, identity
):
    listener, candidate, alerts, states, audit = _listener(tmp_path, analyst_certs)
    context = _context(analyst_certs, identity)

    with listener:
        client = AnalystDashboardClient(listener.address, context)
        with pytest.raises(AnalystDashboardAuthenticationError) as exc_info:
            with _serve(listener, count=1):
                client.list_alerts()

    error_str = str(exc_info.value)
    assert candidate.alert_candidate_id not in error_str
    assert "sqlite" not in error_str.lower()
    assert "/tmp" not in error_str


def test_empty_queue_state_is_cleanly_represented(tmp_path, analyst_certs):
    alerts = AlertCandidateRepository(tmp_path / "alerts.sqlite3")
    authorization = AnalystAuthorizationRegistry((AnalystRegistryEntry("queue.viewer", "viewer"),))
    states = AnalystStateRepository(tmp_path / "states.sqlite3", alerts, authorization)
    configuration = AnalystTlsConfiguration(
        analyst_certs["server"][0],
        analyst_certs["server"][1],
        analyst_certs["human_ca"],
    )
    audit = AnalystSecurityAuditRepository(tmp_path / "audit.sqlite3")
    listener = AnalystTlsListener(
        configuration,
        _registry(analyst_certs),
        authorization,
        AnalystAlertViewModel(states),
        audit,
    )

    context = _context(analyst_certs, "viewer")

    with listener:
        client = AnalystDashboardClient(listener.address, context)
        with _serve(listener, count=1):
            queue = client.list_alerts()

        assert queue.is_empty
        assert queue.total_loaded == 0
        assert queue.items == ()

        with _serve(listener, count=1):
            snapshot = client.get_dashboard_snapshot()

        assert snapshot.status == "empty"
        assert snapshot.selected is None

        html_view = render_dashboard_html(snapshot)
        assert "No alert candidates in triage queue." in html_view


def test_unavailable_backend_state_is_surfaced_safely(tmp_path, analyst_certs, monkeypatch):
    listener, candidate, alerts, states, audit = _listener(tmp_path, analyst_certs)
    context = _context(analyst_certs, "viewer")

    # 1. Closed listener (connection refused)
    with listener:
        addr = listener.address
    # Now listener is closed
    client = AnalystDashboardClient(addr, context)
    with pytest.raises(AnalystDashboardUnavailableError) as exc_info:
        client.list_alerts()
    assert exc_info.value.code == "service_unavailable"

    # 2. Injected storage failure returning 503
    def broken_list(*args, **kwargs):
        raise RuntimeError("secret database error /private/key")

    monkeypatch.setattr(states, "list_alerts", broken_list)

    with listener:
        client_live = AnalystDashboardClient(listener.address, context)
        with pytest.raises(AnalystDashboardUnavailableError) as exc_info:
            with _serve(listener, count=1):
                client_live.list_alerts()

    assert exc_info.value.code == "service_unavailable"
    assert "secret" not in str(exc_info.value)
    assert "/private" not in str(exc_info.value)


def test_reconciled_identity_and_status_across_stages(tmp_path, analyst_certs):
    listener, candidate, alerts, states, audit = _listener(tmp_path, analyst_certs)
    context = create_dashboard_ssl_context(
        human_ca_path=analyst_certs["human_ca"],
        client_certificate_path=analyst_certs["viewer"][0],
        client_private_key_path=analyst_certs["viewer"][1],
    )

    with listener:
        client = AnalystDashboardClient(listener.address, context)
        with _serve(listener, count=2):
            snapshot = client.get_dashboard_snapshot(candidate.alert_candidate_id)

    assert snapshot.selected is not None
    sel = snapshot.selected
    assert sel.model_identity == candidate.model_identity
    assert sel.model_version == candidate.model_version
    assert sel.decision == "Attack"
    assert sel.state == "new"
    assert sel.version == 0
    assert sel.uncalibrated_model_score == candidate.uncalibrated_model_score
    assert sel.decision_threshold == candidate.decision_threshold
    assert sel.source_event_id == candidate.source_event_id


def test_nonexistent_alert_returns_none(tmp_path, analyst_certs):
    listener, candidate, alerts, states, audit = _listener(tmp_path, analyst_certs)
    context = _context(analyst_certs, "viewer")
    nonexistent_id = "alert_candidate_v1:" + "0" * 64

    with listener:
        client = AnalystDashboardClient(listener.address, context)
        with _serve(listener, count=1):
            detail = client.get_alert(nonexistent_id)

    assert detail is None


def test_authenticated_viewer_reads_transition_history_over_loopback(tmp_path, analyst_certs):
    listener, candidate, alerts, states, audit = _listener(tmp_path, analyst_certs)
    analyst_cap = states._authorization.issue_for_trusted_actor("analyst_a")
    transition_id = "00000000-0000-4000-8000-000000000001"
    states.transition(
        analyst_cap,
        alert_candidate_id=candidate.alert_candidate_id,
        expected_version=0,
        to_state="in_review",
        transition_id=transition_id,
        rationale="Initial triage completed by security analyst",
    )

    context = _context(analyst_certs, "viewer")
    with listener:
        client = AnalystDashboardClient(listener.address, context)
        with _serve(listener, count=1):
            detail = client.get_alert(candidate.alert_candidate_id)

    assert detail is not None
    assert detail.state == "in_review"
    assert detail.version == 1
    assert detail.updated_at is not None
    assert detail.updated_by == "analyst_a"
    assert detail.last_transition_id == transition_id
    assert len(detail.history) == 1
    assert detail.history[0].transition_id == transition_id
    assert detail.history[0].sequence == 1
    assert detail.history[0].from_state == "new"
    assert detail.history[0].to_state == "in_review"
    assert detail.history[0].actor_id == "analyst_a"
    assert detail.history[0].rationale == "Initial triage completed by security analyst"
    assert detail.history[0].transitioned_at is not None

    snapshot = DashboardSnapshot(
        queue=DashboardAlertQueue(items=(), total_loaded=0, limit=10, offset=0),
        selected=detail,
        status="active",
    )
    html_view = render_dashboard_html(snapshot)
    assert "Initial triage completed by security analyst" in html_view
    assert "new &rarr; in_review" in html_view


@pytest.mark.parametrize(
    "raw_response, expected_code",
    [
        (b"", "authentication_rejected"),
        (b"NO_SEPARATOR", "invalid_framing"),
        (
            b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            "invalid_framing",
        ),
        (
            b"HTTP/1.1 20 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            "invalid_framing",
        ),
        (
            b"HTTP/1.1 ABC OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            "invalid_framing",
        ),
        (b"HTTP/1.1 200 OK\r\nBadHeaderNoColon\r\n\r\n{}", "invalid_framing"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", "invalid_framing"),
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}",
            "invalid_framing",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
            "invalid_framing",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: abc\r\n\r\n{}",
            "invalid_framing",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: -5\r\n\r\n{}",
            "invalid_framing",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{}",
            "invalid_framing",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}EXTRA",
            "invalid_framing",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            "invalid_framing",
        ),
        (
            b"HTTP/1.1 200 OK\r\n" + b"X-Pad: " + b"a" * 4096 + b"\r\n\r\n{}",
            "invalid_framing",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{bad:1}",
            "invalid_service_response",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n[1,2]",
            "invalid_payload_format",
        ),
        (
            b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\n"ok"',
            "invalid_payload_format",
        ),
    ],
)
def test_client_rejects_malformed_http_framing(raw_response, expected_code):
    client = AnalystDashboardClient(("127.0.0.1", 1), None)  # type: ignore[arg-type]
    if expected_code == "authentication_rejected":
        with pytest.raises(AnalystDashboardAuthenticationError) as exc_info:
            client._parse_response(raw_response)
        assert exc_info.value.code == expected_code
    else:
        with pytest.raises(AnalystDashboardUnavailableError) as exc_info:
            client._parse_response(raw_response)
        assert exc_info.value.code == expected_code


def test_client_rejects_integer_exceeding_string_conversion_limit():
    limit = sys.get_int_max_str_digits()
    oversized_int_body = ('{"oversized": 1' + "0" * (limit + 50) + "}").encode("utf-8")
    raw_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: "
        + str(len(oversized_int_body)).encode("ascii")
        + b"\r\n\r\n"
        + oversized_int_body
    )
    client = AnalystDashboardClient(("127.0.0.1", 1), None)  # type: ignore[arg-type]
    with pytest.raises(AnalystDashboardUnavailableError) as exc_info:
        client._parse_response(raw_response)
    assert exc_info.value.code == "invalid_service_response"


def _valid_list_payload():
    return {
        "schema_version": "analyst_alert_view_v1",
        "limit": 50,
        "offset": 0,
        "items": [
            {
                "detection_evidence": {
                    "alert_candidate_id": "alert_candidate_v1:" + "a" * 64,
                    "source_event_id": "event-1",
                    "observed_at": "2026-09-24T12:00:00Z",
                    "created_at": "2026-09-24T12:00:01Z",
                    "source_representation_identity": "rep-1",
                    "feature_contract_identity": "contract-1",
                    "model_identity": "rf_classifier",
                    "model_version": "1.0.0",
                    "model_artifact_sha256": "b" * 64,
                    "uncalibrated_model_score": 0.85,
                    "decision_threshold": 0.5,
                    "decision_policy_version": "policy-v1",
                    "decision": "Attack",
                },
                "analyst_state": {
                    "state": "new",
                    "version": 0,
                    "updated_at": None,
                    "updated_by": None,
                    "last_transition_id": None,
                },
            }
        ],
    }


def _valid_detail_payload():
    return {
        "schema_version": "analyst_alert_view_v1",
        "detection_evidence": {
            "alert_candidate_id": "alert_candidate_v1:" + "a" * 64,
            "source_event_id": "event-1",
            "observed_at": "2026-09-24T12:00:00Z",
            "created_at": "2026-09-24T12:00:01Z",
            "source_representation_identity": "rep-1",
            "feature_contract_identity": "contract-1",
            "model_identity": "rf_classifier",
            "model_version": "1.0.0",
            "model_artifact_sha256": "b" * 64,
            "uncalibrated_model_score": 0.85,
            "decision_threshold": 0.5,
            "decision_policy_version": "policy-v1",
            "decision": "Attack",
        },
        "analyst_state": {
            "state": "new",
            "version": 0,
            "updated_at": None,
            "updated_by": None,
            "last_transition_id": None,
        },
        "analyst_history": [
            {
                "transition_id": "00000000-0000-4000-8000-000000000001",
                "sequence": 1,
                "from_state": "new",
                "to_state": "triaged",
                "actor_id": "analyst.1",
                "rationale": "Initial triage confirmed threat",
                "transitioned_at": "2026-09-24T12:05:00Z",
            }
        ],
    }


@pytest.mark.parametrize(
    "mutator, expected_code",
    [
        (lambda p: p.update({"schema_version": "wrong_v2"}), "invalid_schema_version"),
        (lambda p: p.pop("items"), "invalid_payload_format"),
        (lambda p: p.update({"items": "not_a_list"}), "invalid_payload_format"),
        (lambda p: p["items"].append("not_a_dict"), "invalid_payload_format"),
        (lambda p: p["items"][0].pop("detection_evidence"), "invalid_payload_format"),
        (lambda p: p["items"][0].pop("analyst_state"), "invalid_payload_format"),
        (
            lambda p: p["items"][0]["detection_evidence"].pop("alert_candidate_id"),
            "invalid_payload_format",
        ),
        (
            lambda p: p["items"][0]["detection_evidence"].update({"alert_candidate_id": ""}),
            "invalid_payload_format",
        ),
        (
            lambda p: p["items"][0]["detection_evidence"].update({"alert_candidate_id": None}),
            "invalid_payload_format",
        ),
        (
            lambda p: p["items"][0]["detection_evidence"].update(
                {"uncalibrated_model_score": "0.85"}
            ),
            "invalid_payload_format",
        ),
        (
            lambda p: p["items"][0]["detection_evidence"].update(
                {"uncalibrated_model_score": True}
            ),
            "invalid_payload_format",
        ),
        (
            lambda p: p["items"][0]["detection_evidence"].update(
                {"uncalibrated_model_score": float("nan")}
            ),
            "invalid_payload_format",
        ),
        (
            lambda p: p["items"][0]["detection_evidence"].update(
                {"uncalibrated_model_score": float("inf")}
            ),
            "invalid_payload_format",
        ),
        (
            lambda p: p["items"][0]["detection_evidence"].update(
                {"decision_threshold": "not_a_number"}
            ),
            "invalid_payload_format",
        ),
        (
            lambda p: p["items"][0]["analyst_state"].update({"version": "0"}),
            "invalid_payload_format",
        ),
        (
            lambda p: p["items"][0]["analyst_state"].update({"version": -1}),
            "invalid_payload_format",
        ),
        (
            lambda p: p["items"][0]["analyst_state"].update({"version": True}),
            "invalid_payload_format",
        ),
        (
            lambda p: p["items"][0]["analyst_state"].update({"updated_at": 12345}),
            "invalid_payload_format",
        ),
    ],
)
def test_list_alerts_rejects_malformed_payload_structures(mutator, expected_code, monkeypatch):
    payload = _valid_list_payload()
    mutator(payload)
    client = AnalystDashboardClient(("127.0.0.1", 1), None)  # type: ignore[arg-type]
    monkeypatch.setattr(client, "_execute", lambda *a, **kw: payload)

    with pytest.raises(AnalystDashboardUnavailableError) as exc_info:
        client.list_alerts()
    assert exc_info.value.code == expected_code


@pytest.mark.parametrize(
    "mutator, expected_code",
    [
        (lambda p: p.update({"schema_version": "wrong_v2"}), "invalid_schema_version"),
        (lambda p: p.pop("detection_evidence"), "invalid_payload_format"),
        (lambda p: p.pop("analyst_state"), "invalid_payload_format"),
        (lambda p: p.pop("analyst_history"), "invalid_payload_format"),
        (lambda p: p.update({"analyst_history": "not_a_list"}), "invalid_payload_format"),
        (lambda p: p["analyst_history"].append("not_a_dict"), "invalid_payload_format"),
        (lambda p: p["analyst_history"][0].pop("transition_id"), "invalid_payload_format"),
        (
            lambda p: p["analyst_history"][0].update({"sequence": "1"}),
            "invalid_payload_format",
        ),
        (
            lambda p: p["analyst_history"][0].update({"sequence": 0}),
            "invalid_payload_format",
        ),
        (
            lambda p: p["analyst_history"][0].update({"sequence": True}),
            "invalid_payload_format",
        ),
        (
            lambda p: p["analyst_history"][0].update({"actor_id": ""}),
            "invalid_payload_format",
        ),
        (
            lambda p: p["analyst_history"][0].update({"actor_id": None}),
            "invalid_payload_format",
        ),
        (
            lambda p: p["analyst_history"][0].update({"rationale": None}),
            "invalid_payload_format",
        ),
        (
            lambda p: p["analyst_history"][0].update({"transitioned_at": ""}),
            "invalid_payload_format",
        ),
    ],
)
def test_get_alert_rejects_malformed_payload_and_history(mutator, expected_code, monkeypatch):
    payload = _valid_detail_payload()
    mutator(payload)
    client = AnalystDashboardClient(("127.0.0.1", 1), None)  # type: ignore[arg-type]
    monkeypatch.setattr(client, "_execute", lambda *a, **kw: payload)

    with pytest.raises(AnalystDashboardUnavailableError) as exc_info:
        client.get_alert("candidate-1")
    assert exc_info.value.code == expected_code


def test_detail_preserves_none_without_stringification(monkeypatch):
    payload = _valid_detail_payload()
    payload["analyst_state"]["updated_at"] = None
    payload["analyst_state"]["updated_by"] = None
    payload["analyst_state"]["last_transition_id"] = None
    client = AnalystDashboardClient(("127.0.0.1", 1), None)  # type: ignore[arg-type]
    monkeypatch.setattr(client, "_execute", lambda *a, **kw: payload)

    detail = client.get_alert("candidate-1")
    assert detail is not None
    assert detail.updated_at is None
    assert detail.updated_by is None
    assert detail.last_transition_id is None

    payload2 = _valid_detail_payload()
    payload2["analyst_state"]["updated_at"] = "2026-09-24T12:00:00Z"
    payload2["analyst_state"]["updated_by"] = "analyst.1"
    payload2["analyst_state"]["last_transition_id"] = "uuid-1234"
    monkeypatch.setattr(client, "_execute", lambda *a, **kw: payload2)

    detail2 = client.get_alert("candidate-1")
    assert detail2 is not None
    assert detail2.updated_at == "2026-09-24T12:00:00Z"
    assert detail2.updated_by == "analyst.1"
    assert detail2.last_transition_id == "uuid-1234"


def test_responsive_queue_and_detail_keep_full_evidence_and_selectable_link():
    candidate_id = "alert_candidate_v1:" + "a" * 64
    source_id = "unsw_registered_source_event_v1:" + "b" * 64
    detail_payload = _valid_detail_payload()
    detail_payload["detection_evidence"]["alert_candidate_id"] = candidate_id
    detail_payload["detection_evidence"]["source_event_id"] = source_id
    queue_payload = _valid_list_payload()
    queue_payload["items"][0]["detection_evidence"].update(
        alert_candidate_id=candidate_id, source_event_id=source_id
    )
    snapshot = DashboardSnapshot(
        queue=DashboardAlertQueue(
            items=(_parse_summary(queue_payload["items"][0]),),
            total_loaded=1,
            limit=50,
            offset=0,
        ),
        selected=_parse_detail(detail_payload),
        status="active",
    )

    page = render_dashboard_html(snapshot, browser_links=True)
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in page
    assert page.count('class="table-scroll" role="region"') == 2
    assert 'aria-label="Alert triage queue" tabindex="0"' in page
    assert 'aria-label="Analyst transition history" tabindex="0"' in page
    assert ".table-scroll { max-width: 100%; overflow-x: auto; }" in page
    assert ".table-scroll > table { min-width: 640px; }" in page
    assert '<table class="data-table queue-table">' in page
    assert "@media (max-width: 600px)" in page
    assert ".queue-table a { display: inline-block; padding: 0.5rem 0; }" in page
    assert ".queue-table a code { font-size: 1rem; }" in page
    assert "grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr))" in page
    assert ".evidence-grid > div { min-width: 0; overflow-wrap: anywhere; }" in page
    assert f'<a href="/v1/analyst/alerts/{candidate_id}">' in page
    assert "<th>Decision</th>" in page and "<th>State</th>" in page
    assert "<span class='badge badge-decision'>Attack</span>" in page
    assert "<span class='badge badge-state'>new</span>" in page
    assert f"Candidate ID:</b> <code>{candidate_id}</code>" in page
    assert f"Source Event ID:</b> <code>{source_id}</code>" in page
    assert "Created At:</b> 2026-09-24T12:00:01Z" in page


def test_render_dashboard_html_analyst_role_with_csrf_renders_transition_form():
    candidate_id = "alert_candidate_v1:" + "a" * 64
    detail_payload = _valid_detail_payload()
    detail_payload["detection_evidence"]["alert_candidate_id"] = candidate_id
    detail_payload["analyst_state"]["state"] = "new"
    detail_payload["analyst_state"]["version"] = 0
    snapshot = DashboardSnapshot(
        queue=DashboardAlertQueue(
            items=(_parse_summary(detail_payload),),
            total_loaded=1,
            limit=50,
            offset=0,
        ),
        selected=_parse_detail(detail_payload),
        status="active",
    )

    csrf_token = "c" * 64
    transition_request_id = "11111111-2222-4333-8444-555555555555"

    html = render_dashboard_html(
        snapshot,
        browser_links=True,
        actor_role="analyst",
        csrf_token=csrf_token,
        transition_request_id=transition_request_id,
    )

    assert f'action="/v1/analyst/alerts/{candidate_id}/transitions"' in html
    assert '<input type="hidden" name="expected_version" value="0">' in html
    assert (
        f'<input type="hidden" name="transition_request_id" value="{transition_request_id}">'
        in html
    )
    assert f'<input type="hidden" name="csrf_token" value="{csrf_token}">' in html
    assert '<select name="target_state" id="target_state"' in html
    assert '<option value="in_review">in_review</option>' in html
    assert '<input type="text" name="reason"' in html
    assert '<button type="submit" class="btn-submit">Submit Transition</button>' in html
    assert 'Role: <b class="badge badge-role">analyst</b>' in html


def test_render_dashboard_html_viewer_role_renders_readonly_badge():
    candidate_id = "alert_candidate_v1:" + "a" * 64
    detail_payload = _valid_detail_payload()
    detail_payload["detection_evidence"]["alert_candidate_id"] = candidate_id
    detail_payload["analyst_state"]["state"] = "new"
    snapshot = DashboardSnapshot(
        queue=DashboardAlertQueue(
            items=(_parse_summary(detail_payload),),
            total_loaded=1,
            limit=50,
            offset=0,
        ),
        selected=_parse_detail(detail_payload),
        status="active",
    )

    html = render_dashboard_html(
        snapshot,
        browser_links=True,
        actor_role="viewer",
    )

    assert "<form" not in html
    assert "Submit Transition" not in html
    assert "Role: viewer (Read-Only)" in html
    assert 'Role: <b class="badge badge-role">viewer</b>' in html


def test_render_dashboard_html_terminal_state_renders_terminal_badge():
    candidate_id = "alert_candidate_v1:" + "a" * 64
    detail_payload = _valid_detail_payload()
    detail_payload["detection_evidence"]["alert_candidate_id"] = candidate_id
    detail_payload["analyst_state"]["state"] = "closed"
    detail_payload["analyst_state"]["version"] = 2
    snapshot = DashboardSnapshot(
        queue=DashboardAlertQueue(
            items=(_parse_summary(detail_payload),),
            total_loaded=1,
            limit=50,
            offset=0,
        ),
        selected=_parse_detail(detail_payload),
        status="active",
    )

    csrf_token = "c" * 64
    transition_request_id = "11111111-2222-4333-8444-555555555555"

    html = render_dashboard_html(
        snapshot,
        browser_links=True,
        actor_role="analyst",
        csrf_token=csrf_token,
        transition_request_id=transition_request_id,
    )

    assert "<form" not in html
    assert "Submit Transition" not in html
    assert "is a terminal state. No further transitions permitted." in html
