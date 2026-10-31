"""Suricata bridge follower and the live sensor route.

The frozen forest score is stored as its own fact. Alert signatures stay display text.
"""

from __future__ import annotations

import json
from http.server import ThreadingHTTPServer
from pathlib import Path
import threading
import urllib.error
import urllib.request

import pytest

from scripts.follow_suricata_eve import handle_line, remember_alert, sensor_payload
from scripts.run_misp_and_callback_contract_server import MispAndCallbackContractHandler
from threatfusion.api.live_soc_console import (
    CANONICAL_14_FEATURES,
    list_live_campaigns,
    persist_scored_flow,
    purge_bridge_noise_rows,
    record_suricata_bridge_flow,
    replay_live_scenarios,
    run_live_range_scan,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
MISP_KEY = "threatfusion_soc_test_misp_key_2026_secure"


def _flow(src_port: int = 44120, dest_port: int = 80) -> dict[str, object]:
    return {
        "timestamp": "2026-10-30T12:00:00.000000+0000",
        "flow_id": 987654321012345,
        "event_type": "flow",
        "src_ip": "172.29.0.10",
        "src_port": src_port,
        "dest_ip": "172.29.0.20",
        "dest_port": dest_port,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 4,
            "pkts_toclient": 3,
            "bytes_toserver": 240,
            "bytes_toclient": 180,
            "start": "2026-10-30T12:00:00.000000+0000",
            "end": "2026-10-30T12:00:00.200000+0000",
        },
    }


def _alert(signature: str = "ET SCAN Nmap") -> dict[str, object]:
    return {
        "event_type": "alert",
        "src_ip": "172.29.0.10",
        "dest_ip": "172.29.0.20",
        "src_port": 44120,
        "dest_port": 80,
        "proto": "TCP",
        "alert": {"signature": signature, "category": "Attempted Information Leak"},
    }


def test_follower_strips_prefixes_and_keeps_the_signature_as_display_text() -> None:
    cache: dict[tuple[str, str, str, int], str] = {}
    remember_alert(cache, _alert())
    payload = sensor_payload(_flow(), cache)
    assert payload["source_label"] == "suricata_bridge"
    provenance = payload["provenance"]
    assert provenance["entity_namespace_id"] == "lab:range-bridge-01"
    assert provenance["src_entity_id"] == "172.29.0.10"
    assert provenance["dst_entity_id"] == "172.29.0.20"
    assert "attacker:" not in provenance["src_entity_id"]
    assert "victim:" not in provenance["dst_entity_id"]
    observation = payload["sensor_observation"]
    assert observation["signature"] == "ET SCAN Nmap"
    assert observation["proto"] == "tcp"
    assert "technique_id" not in observation
    script = (REPO_ROOT / "scripts" / "follow_suricata_eve.py").read_text(encoding="utf-8")
    assert "threatfusion.advisory" not in script
    assert "chromadb" not in script
    assert "gemini_client" not in script


def test_follower_without_an_alert_leaves_the_signature_empty() -> None:
    payload = sensor_payload(_flow(), {})
    assert payload["sensor_observation"]["signature"] is None


def test_sensor_row_keeps_the_forest_score_and_a_separate_campaign(tmp_path: Path) -> None:
    db = tmp_path / "sensor.sqlite3"
    scenarios = replay_live_scenarios(db, repo_root=REPO_ROOT)
    payload = sensor_payload(_flow(), {})
    stored = record_suricata_bridge_flow(
        db,
        payload["features"],
        repo_root=REPO_ROOT,
        provenance=payload["provenance"],
        sensor_observation=payload["sensor_observation"],
        source_event_id=payload["source_event_id"],
        observed_at_utc=payload["observed_at_utc"],
    )
    assert stored["evidence_state"] == "verified"
    assert stored["reason"] == "frozen_random_forest_scored"
    assert stored["decision"] in {"Attack", "Benign"}
    assert stored["production_fusion_enabled"] is False
    assert stored["source_label"] == "suricata_bridge"
    assert stored["case_title"] is None
    assert stored["campaign_id"].startswith("campaign_suricata_bridge:")
    assert stored["campaign_id"] != scenarios["campaign_id"]
    assert not stored["campaign_id"].startswith("campaign_live_scenarios:")
    observation = stored["sensor_observation"]
    assert observation["suricata_line"].startswith("tcp 172.29.0.10:44120 -> 172.29.0.20:80")
    assert observation["suricata_line"].endswith("flow only, no signature")
    assert observation["forest_line"].startswith(stored["decision"] + ", ")
    assert observation["forest_line"].endswith("frozen_random_forest_scored")
    shown = observation["forest_line"].split(", ")[1]
    assert float(shown) == stored["rf_attack_probability"]
    assert "T1190" not in observation["suricata_line"]
    listed = list_live_campaigns(db)
    assert listed["bridge_flow_count"] == 1
    sensor_rows = [
        flow
        for campaign in listed["campaigns"]
        if campaign["source_label"] == "suricata_bridge"
        for flow in campaign["flows"]
    ]
    assert len(sensor_rows) == 1
    guard = next(
        item for item in sensor_rows[0]["glass_box"]["items"] if item["id"] == "misp_rfc1918_guard"
    )
    assert guard["status"] == "refused"
    assert guard["external_lookup_performed"] is False
    scenario_ids = {
        campaign["campaign_id"]
        for campaign in listed["campaigns"]
        if campaign["source_label"] == "live_scenario_replay"
    }
    sensor_ids = {
        campaign["campaign_id"]
        for campaign in listed["campaigns"]
        if campaign["source_label"] == "suricata_bridge"
    }
    assert scenario_ids.isdisjoint(sensor_ids)
    again = record_suricata_bridge_flow(
        db,
        payload["features"],
        repo_root=REPO_ROOT,
        provenance=payload["provenance"],
        sensor_observation=payload["sensor_observation"],
        source_event_id=payload["source_event_id"],
        observed_at_utc=payload["observed_at_utc"],
    )
    assert again["duplicate"] is True
    assert again["flow_id"] == stored["flow_id"]
    assert list_live_campaigns(db)["bridge_flow_count"] == 1


def test_prefixed_sensor_address_is_refused(tmp_path: Path) -> None:
    payload = sensor_payload(_flow(), {})
    provenance = dict(payload["provenance"])
    provenance["src_entity_id"] = "attacker:172.29.0.10"
    refused = record_suricata_bridge_flow(
        tmp_path / "refused.sqlite3",
        payload["features"],
        repo_root=REPO_ROOT,
        provenance=provenance,
        sensor_observation=payload["sensor_observation"],
        source_event_id=payload["source_event_id"],
    )
    assert refused["evidence_state"] == "unavailable"
    assert refused["reason"] == "prefixed_or_invalid_address"
    assert refused["decision"] == "withheld"


def test_sensor_page_separates_the_three_sources() -> None:
    html = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "frontend" / "js" / "soc_dashboard.js").read_text(encoding="utf-8")
    assert 'id="queueSourceFilter"' in html
    assert "Live sensor, this Docker bridge" in html
    assert "Recorded UNSW study" in html
    assert "Labeled scenario replay" in html
    assert 'id="liveHeroBridgeCount"' in html
    assert 'id="inspectorSensorLine"' in html
    assert 'id="inspectorForestLine"' in html
    assert 'id="inspectorScenarioLabel"' in html
    assert 'id="btnReplayScenarios"' in html
    assert 'id="btnRangeScan"' in html
    assert 'id="liveRangeTopology"' in html
    assert "172.29.0.10" in html
    assert "172.29.0.20" in html
    assert "UNSW-NB15 and CIC byte layers are not interchangeable." in html
    assert "http://" not in html
    assert "https://" not in html
    assert "retrieved candidate technique" in script
    assert "/api/v1/live/sensor" in (
        REPO_ROOT / "scripts" / "run_misp_and_callback_contract_server.py"
    ).read_text(encoding="utf-8")


def _post(base: str, path: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


@pytest.fixture
def live_http(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(tmp_path / "live.sqlite3"))
    monkeypatch.setenv("THREATFUSION_MISP_API_KEY", MISP_KEY)
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


def test_http_sensor_route_stores_the_bridge_row(live_http: str) -> None:
    payload = sensor_payload(_flow(src_port=44121), {})
    status, stored = _post(live_http, "/api/v1/live/sensor", payload)
    assert status == 200
    assert stored["source_label"] == "suricata_bridge"
    assert stored["decision"] in {"Attack", "Benign"}
    assert stored["reason"] == "frozen_random_forest_scored"
    assert stored["production_fusion_enabled"] is False
    assert stored["case_title"] is None
    request = urllib.request.Request(f"{live_http}/api/v1/live/campaigns", method="GET")
    with urllib.request.urlopen(request, timeout=10) as response:
        listed = json.loads(response.read().decode("utf-8"))
    assert listed["bridge_flow_count"] == 1


def _bench_score() -> dict[str, object]:
    return {
        "rf_attack_probability": 0.2,
        "decision": "Benign",
        "evidence_state": "verified",
        "reason": "frozen_random_forest_scored",
        "model_sha256": "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
    }


def test_bridge_noise_is_refused_before_a_row_is_stored(tmp_path: Path) -> None:
    payload = sensor_payload(_flow(), {})
    payload["provenance"]["src_entity_id"] = "224.0.0.251"
    payload["provenance"]["dst_entity_id"] = "ff02::fb"
    payload["provenance"]["service_or_port"] = "5353"
    payload["sensor_observation"]["src_ip"] = "224.0.0.251"
    payload["sensor_observation"]["dst_ip"] = "ff02::fb"
    payload["sensor_observation"]["dst_port"] = 5353
    db = tmp_path / "noise.sqlite3"
    stored = record_suricata_bridge_flow(
        db,
        payload["features"],
        repo_root=REPO_ROOT,
        provenance=payload["provenance"],
        sensor_observation=payload["sensor_observation"],
        source_event_id=payload["source_event_id"],
        observed_at_utc=payload["observed_at_utc"],
    )
    assert stored["reason"] == "bridge_noise_ignored"
    assert stored["evidence_state"] == "unavailable"
    assert not db.exists()


def test_follower_skips_mdns_without_posting(monkeypatch: pytest.MonkeyPatch) -> None:
    posted: list[str] = []

    def _forbid(*_args: object, **_kwargs: object) -> tuple[int, dict[str, object]]:
        posted.append("posted")
        return 500, {}

    monkeypatch.setattr("scripts.follow_suricata_eve.post_sensor", _forbid)
    line = json.dumps(
        {
            "event_type": "flow",
            "src_ip": "172.29.0.1",
            "dest_ip": "224.0.0.251",
            "src_port": 5353,
            "dest_port": 5353,
            "proto": "UDP",
        }
    )
    assert handle_line(line, {}, "http://127.0.0.1:9", 1.0) == "noise"
    assert posted == []


def test_purge_removes_noise_and_keeps_the_lab_pair(tmp_path: Path) -> None:
    db = tmp_path / "queue.sqlite3"
    features = {name: 0.0 for name in CANONICAL_14_FEATURES}
    persist_scored_flow(
        db,
        features,
        _bench_score(),
        source_label="suricata_bridge",
        provenance={
            "entity_namespace_id": "lab:range-bridge-01",
            "src_entity_id": "224.0.0.251",
            "dst_entity_id": "224.0.0.251",
            "flow_protocol": "udp",
            "service_or_port": "5353",
            "clock_synchronized": True,
        },
        sensor_observation_json=json.dumps({"src_ip": "172.29.0.1", "dst_ip": "224.0.0.251"}),
    )
    persist_scored_flow(
        db,
        features,
        _bench_score(),
        source_label="suricata_bridge",
        provenance={
            "entity_namespace_id": "lab:range-bridge-01",
            "src_entity_id": "172.29.0.10",
            "dst_entity_id": "172.29.0.20",
            "flow_protocol": "tcp",
            "service_or_port": "80",
            "clock_synchronized": True,
        },
    )
    assert purge_bridge_noise_rows(db) == 1
    listed = list_live_campaigns(db)
    addresses = {
        (item.get("src_entity_id"), item.get("dst_entity_id"))
        for campaign in listed["campaigns"]
        for item in campaign["flows"]
    }
    assert ("172.29.0.10", "172.29.0.20") in addresses
    assert ("224.0.0.251", "224.0.0.251") not in addresses


def test_range_scan_waits_until_a_new_unicast_row_exists(tmp_path: Path) -> None:
    db = tmp_path / "scan.sqlite3"
    eve = tmp_path / "eve.json"
    features = {name: 0.0 for name in CANONICAL_14_FEATURES}

    def runner() -> None:
        eve.write_text('{"src_ip":"172.29.0.10","dest_ip":"172.29.0.20"}\n', encoding="utf-8")
        persist_scored_flow(
            db,
            features,
            _bench_score(),
            source_label="suricata_bridge",
            provenance={
                "entity_namespace_id": "lab:range-bridge-01",
                "src_entity_id": "172.29.0.10",
                "dst_entity_id": "172.29.0.20",
                "flow_protocol": "tcp",
                "service_or_port": "80",
                "clock_synchronized": True,
            },
        )

    result = run_live_range_scan(db, runner=runner, timeout_seconds=2, eve_path=eve)
    assert result["ingested"] is True
    assert result["reason"] == "range_scan_ingested"
    assert result["eve_seen"] is True


def test_range_scan_does_not_invent_a_row_when_the_runner_fails(tmp_path: Path) -> None:
    db = tmp_path / "down.sqlite3"

    def runner() -> None:
        raise OSError("docker is down")

    result = run_live_range_scan(db, runner=runner, timeout_seconds=1, eve_path=None)
    assert result["reason"] == "range_not_running"
    assert result["ingested"] is False
    assert not db.exists()
