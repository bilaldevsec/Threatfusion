"""HTTP proof for live dual-window correlation and the MISP private-IP guard.

These tests speak to the contract server. They do not call the correlation
engine or the guard helper as the thing under test.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path
import threading
import urllib.error
import urllib.request

import pytest

from scripts.run_misp_and_callback_contract_server import (
    MispAndCallbackContractHandler,
    lookup_canonical_indicator,
)
from threatfusion.api.live_soc_console import score_canonical_flow
from threatfusion.evaluation.study_runner import STUDY_TRIAGE_CASES
from threatfusion.models.drift_and_supply_chain import CANONICAL_14_FEATURES

REPO_ROOT = Path(__file__).resolve().parents[3]
MISP_KEY = "threatfusion_soc_test_misp_key_2026_secure"
_BASE = datetime(2026, 10, 27, 0, 0, tzinfo=UTC)

_BLOCKED = (
    "10.0.0.4",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.0.1",
    "127.0.0.1",
    "::1",
    "169.254.1.1",
    "fe80::1",
    "fc00::1",
    "::ffff:10.1.2.3",
)


def _iso(offset_seconds: float) -> str:
    return (_BASE + timedelta(seconds=offset_seconds)).isoformat()


def _attack_features() -> dict[str, float]:
    """Use a recorded UNSW study vector the frozen forest scores as Attack."""
    for case in STUDY_TRIAGE_CASES:
        if case.source != "recorded_unsw_nb15":
            continue
        features = {name: float(case.raw_features_14[name]) for name in CANONICAL_14_FEATURES}
        scored = score_canonical_flow(features, repo_root=REPO_ROOT)
        if scored["decision"] == "Attack" and scored["evidence_state"] == "verified":
            return features
    raise AssertionError("frozen random forest did not score a recorded study vector as Attack")


def _benign_features() -> dict[str, float]:
    for case in STUDY_TRIAGE_CASES:
        if case.source != "recorded_unsw_nb15":
            continue
        features = {name: float(case.raw_features_14[name]) for name in CANONICAL_14_FEATURES}
        scored = score_canonical_flow(features, repo_root=REPO_ROOT)
        if scored["decision"] == "Benign" and scored["evidence_state"] == "verified":
            return features
    raise AssertionError("frozen random forest did not score a recorded study vector as Benign")


def _provenance(port: str) -> dict[str, object]:
    return {
        "entity_namespace_id": "lab:edge-01",
        "src_entity_id": "198.51.100.27",
        "dst_entity_id": "203.0.113.50",
        "protocol": "tcp",
        "service_or_port": port,
        "clock_synchronized": True,
    }


def _post(base: str, path: str, payload: dict, headers: dict[str, str] | None = None):
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers=request_headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _get(base: str, path: str):
    request = urllib.request.Request(f"{base}{path}", method="GET")
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


@pytest.fixture
def live_http(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    live_db = tmp_path / "live.sqlite3"
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(live_db))
    monkeypatch.setenv("THREATFUSION_MISP_API_KEY", MISP_KEY)
    monkeypatch.delenv("THREATFUSION_INCIDENTS_DB_PATH", raising=False)
    MispAndCallbackContractHandler.misp_api_key = MISP_KEY
    server = ThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()


def _ingest(base: str, features: dict[str, float], when: str, port: str):
    return _post(
        base,
        "/api/v1/live/ingest",
        {
            "features": features,
            "observed_at_utc": when,
            "provenance": _provenance(port),
        },
    )


def test_http_ingest_includes_burst_boundary_and_excludes_the_next_millisecond(
    live_http: str,
) -> None:
    features = _attack_features()
    status, first = _ingest(live_http, features, _iso(0), "80")
    assert status == 200
    assert first["decision"] == "Attack"
    assert first["production_fusion_enabled"] is False
    assert first["correlation"]["correlated_flow_count"] == 0

    status, inside = _ingest(live_http, features, _iso(30.0), "80")
    assert status == 200
    report = inside["correlation"]
    assert report["production_fusion_enabled"] is False
    assert report["burst_window_seconds"] == 30.0
    assert report["campaign_window_seconds"] == 600.0
    assert report["burst_incident_count"] == 1
    assert report["campaign_incident_count"] == 0
    assert report["correlated_flow_count"] == 2
    assert report["max_constituent_count"] == 2
    events = report["timeline"]["events"]
    assert report["timeline"]["event_count"] == 2
    assert {event["window_type"] for event in events} == {"burst_30s"}
    assert {event["observed_at"] for event in events} == {_iso(0), _iso(30.0)}

    status, outside = _ingest(live_http, features, _iso(60.001), "80")
    assert status == 200
    later = outside["correlation"]
    assert later["burst_incident_count"] == 1
    assert later["correlated_flow_count"] == 2
    assert later["incident_count"] == 2


def test_http_burst_gap_of_30_001_seconds_falls_through_to_campaign(live_http: str) -> None:
    """30.001s is outside the burst window and still inside the 600s campaign window."""
    features = _attack_features()
    assert _ingest(live_http, features, _iso(0), "80")[0] == 200
    status, report_body = _ingest(live_http, features, _iso(30.001), "80")
    assert status == 200
    report = report_body["correlation"]
    assert report["burst_incident_count"] == 0
    assert report["campaign_incident_count"] == 1
    assert report["correlated_flow_count"] == 2
    assert {event["window_type"] for event in report["timeline"]["events"]} == {"campaign_600s"}


def test_http_replay_includes_campaign_boundary_and_excludes_the_next_millisecond(
    live_http: str,
) -> None:
    features = _attack_features()
    status, inside = _post(
        live_http,
        "/api/v1/live/replay",
        {
            "flows": [
                {
                    "features": features,
                    "observed_at_utc": _iso(0),
                    "provenance": _provenance("80"),
                },
                {
                    "features": features,
                    "observed_at_utc": _iso(600.0),
                    "provenance": _provenance("443"),
                },
            ]
        },
    )
    assert status == 200
    assert inside["member_count"] == 2
    assert inside["production_fusion_enabled"] is False
    report = inside["correlation"]
    assert report["burst_window_seconds"] == 30.0
    assert report["campaign_window_seconds"] == 600.0
    assert report["burst_incident_count"] == 0
    assert report["campaign_incident_count"] == 1
    assert report["correlated_flow_count"] == 2
    assert {event["window_type"] for event in report["timeline"]["events"]} == {"campaign_600s"}
    assert {event["observed_at"] for event in report["timeline"]["events"]} == {
        _iso(0),
        _iso(600.0),
    }


def test_http_replay_gap_past_600_seconds_does_not_stitch(live_http: str) -> None:
    features = _attack_features()
    status, body = _post(
        live_http,
        "/api/v1/live/replay",
        {
            "flows": [
                {
                    "features": features,
                    "observed_at_utc": _iso(0),
                    "provenance": _provenance("22"),
                },
                {
                    "features": features,
                    "observed_at_utc": _iso(600.001),
                    "provenance": _provenance("8080"),
                },
            ]
        },
    )
    assert status == 200
    report = body["correlation"]
    assert report["campaign_incident_count"] == 0
    assert report["burst_incident_count"] == 0
    assert report["correlated_flow_count"] == 0
    assert report["incident_count"] == 2


def test_http_benign_row_is_not_a_correlation_member_and_benchmark_replay_calls_engine(
    live_http: str,
) -> None:
    attack = _attack_features()
    benign = _benign_features()
    assert _ingest(live_http, attack, _iso(0), "80")[0] == 200
    status, with_benign = _ingest(live_http, benign, _iso(5), "80")
    assert status == 200
    assert with_benign["decision"] == "Benign"
    assert with_benign["correlation"]["correlated_flow_count"] == 0
    assert with_benign["correlation"]["incident_count"] == 1

    status, replayed = _post(live_http, "/api/v1/live/replay", {})
    assert status == 200
    assert replayed["member_count"] == 5
    assert replayed["production_fusion_enabled"] is False
    assert replayed["correlation"]["burst_window_seconds"] == 30.0
    assert replayed["correlation"]["campaign_window_seconds"] == 600.0
    assert replayed["correlation"]["production_fusion_enabled"] is False
    # Recorded study rows have no verified entity key, so the engine leaves them singletons.
    assert replayed["correlation"]["correlated_flow_count"] == 0


def test_http_restitch_replaces_the_smaller_burst(live_http: str) -> None:
    features = _attack_features()
    for offset in (0.0, 10.0, 20.0):
        status, _body = _ingest(live_http, features, _iso(offset), "80")
        assert status == 200
    status, campaigns = _get(live_http, "/api/v1/live/campaigns")
    assert status == 200
    bursts = [row for row in campaigns["incidents"] if row["window_type"] == "burst_30s"]
    assert len(bursts) == 1
    assert bursts[0]["constituent_alert_count"] == 3
    assert campaigns["production_fusion_enabled"] is False


def test_http_invalid_timestamp_is_refused_before_store(live_http: str) -> None:
    status, body = _ingest(live_http, _attack_features(), "not-a-timestamp", "80")
    assert status == 400
    assert body["reason"] == "invalid_observed_at"
    assert body["production_fusion_enabled"] is False
    status, campaigns = _get(live_http, "/api/v1/live/campaigns")
    assert status == 200
    assert campaigns["flow_count"] == 0


def test_http_misp_lookup_refuses_rfc1918_loopback_and_link_local_before_lookup(
    live_http: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    lookups = {"count": 0}

    def _counting_lookup(value: str):
        lookups["count"] += 1
        return lookup_canonical_indicator(value)

    monkeypatch.setattr(
        "scripts.run_misp_and_callback_contract_server.lookup_canonical_indicator",
        _counting_lookup,
    )
    for address in _BLOCKED:
        status, body = _post(
            live_http,
            "/attributes/restSearch",
            {"value": address, "type": "ip-dst"},
            headers={"Authorization": MISP_KEY},
        )
        assert status == 422, address
        assert body["private_ip_guard_triggered"] is True
        assert body["external_lookup_performed"] is False
        assert "response" not in body
        guard_status, guard_body = _post(live_http, "/api/v1/live/misp-guard", {"value": address})
        assert guard_status == 422, address
        assert guard_body["private_ip_guard_triggered"] is True
        assert guard_body["external_lookup_performed"] is False
    assert lookups["count"] == 0

    status, opened = _post(
        live_http,
        "/attributes/restSearch",
        {"value": "198.51.100.27", "type": "ip-dst"},
        headers={"Authorization": MISP_KEY},
    )
    assert status == 200
    assert lookups["count"] == 1
    attributes = opened["response"]["Attribute"]
    assert attributes[0]["event_id"] == "misp_evt_c2_03"
    assert attributes[0]["value"] == "198.51.100.27"

    status, public = _post(
        live_http,
        "/api/v1/live/misp-guard",
        {"value": "8.8.8.8"},
    )
    assert status == 200
    assert public["private_ip_guard_triggered"] is False
    assert public["external_lookup_performed"] is False
