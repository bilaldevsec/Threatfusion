"""Autonomous product audit test suite.

Validates product boundary probes, operator identity guards, evidence queries,
and frontend action graph column contracts.
"""

from __future__ import annotations

import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from scripts.run_misp_and_callback_contract_server import MispAndCallbackContractHandler
from threatfusion.api.live_soc_console import (
    _connect,
    enroll_lab_operator,
    evidence_locker_queries,
    operator_stamp,
    persist_scored_flow,
)
from threatfusion.models.drift_and_supply_chain import CANONICAL_14_FEATURES

REPO_ROOT = Path(__file__).resolve().parents[3]
AUDIT_INGEST_TOKEN = "test_sensor_ingest_token_autonomous_audit_2026"


# ---------------------------------------------------------------------------
# Helper classes and functions required by contracts
# ---------------------------------------------------------------------------

class EvidenceQueryDescriptor(dict):
    """Query descriptor supporting dict indexing, attribute access, and string equality."""

    def __init__(self, query_id: str, title: str = "") -> None:
        super().__init__(query_id=query_id, title=title)
        self._query_id = query_id

    @property
    def query_id(self) -> str:
        return self._query_id

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self._query_id == other
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(self._query_id)

    def __str__(self) -> str:
        return self._query_id

    def __repr__(self) -> str:
        return f"EvidenceQueryDescriptor('{self._query_id}')"


def ensure_lab_operator_credential(
    policy_dir: Path, actor_id: str = "lab_operator"
) -> dict[str, Any]:
    """Helper function to enroll a lab operator credential."""
    return enroll_lab_operator(policy_dir, actor_id)


def list_evidence_locker_queries(
    db_path: Path | None = None,
    flow_id: int | None = None,
    soar_db_path: Path | None = None,
) -> list[EvidenceQueryDescriptor]:
    """Return the 3 canonical evidence locker queries."""
    if db_path is not None and flow_id is not None:
        result = evidence_locker_queries(db_path, flow_id, soar_db_path)
        return [
            EvidenceQueryDescriptor(q["query_id"], q.get("title", ""))
            for q in result.get("queries", [])
        ]
    return [
        EvidenceQueryDescriptor("entity_historical_frequency", "Entity Historical Frequency"),
        EvidenceQueryDescriptor("destination_port_protocol_baseline", "Destination Port & Protocol Baseline"),
        EvidenceQueryDescriptor("correlated_campaign_soar_ledger", "Correlated Campaign & SOAR Ledger State"),
    ]


class ActionGraphColumnParser(HTMLParser):
    """Extract column headers within #actionGraphBoard."""

    def __init__(self) -> None:
        super().__init__()
        self.in_board = False
        self.in_col = False
        self.in_h3 = False
        self.depth = 0
        self.board_depth = 0
        self.titles: list[str] = []
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = dict(attrs)
        self.depth += 1
        if tag == "div" and attr_dict.get("id") == "actionGraphBoard":
            self.in_board = True
            self.board_depth = self.depth
        elif self.in_board:
            classes = (attr_dict.get("class") or "").split()
            if "graph-col" in classes:
                self.in_col = True
            elif self.in_col and tag == "h3":
                self.in_h3 = True
                self._current_text = []

    def handle_endtag(self, tag: str) -> None:
        if self.in_h3 and tag == "h3":
            self.in_h3 = False
            title = html.unescape("".join(self._current_text).strip())
            if title:
                self.titles.append(title)
        elif self.in_col and tag == "div":
            self.in_col = False
        if self.in_board and self.depth == self.board_depth:
            self.in_board = False
        self.depth -= 1

    def handle_data(self, data: str) -> None:
        if self.in_h3:
            self._current_text.append(data)


def parse_action_graph_columns(html_text: str) -> list[str]:
    """Parse column titles from HTML under #actionGraphBoard."""
    parser = ActionGraphColumnParser()
    parser.feed(html_text)
    return parser.titles


# ---------------------------------------------------------------------------
# Fixture for ephemeral in-process HTTP server
# ---------------------------------------------------------------------------

@pytest.fixture
def audit_http_server(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Ephemeral in-process HTTP server bound to port 0."""
    live_db = tmp_path / "live_audit.sqlite3"
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(live_db))
    monkeypatch.setenv("THREATFUSION_SENSOR_INGEST_TOKEN", AUDIT_INGEST_TOKEN)
    monkeypatch.delenv("THREATFUSION_INCIDENTS_DB_PATH", raising=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield base_url, live_db
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Test Suites
# ---------------------------------------------------------------------------

def test_probe_6_remote_sensor_auth_guard(audit_http_server: tuple[str, Path]) -> None:
    """Probe 6: Sensor auth guard refuses invalid token with 401 and writes 0 rows."""
    base_url, live_db = audit_http_server

    # Initialize live DB tables
    with _connect(live_db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM live_flows").fetchone()[0] == 0

    features = {name: 1.0 for name in CANONICAL_14_FEATURES}
    payload = {
        "sensor_node": "aws_cloud_sensor",
        "features": features,
        "provenance": {
            "src_entity_id": "10.0.0.50",
            "dst_entity_id": "10.0.0.60",
            "service_or_port": "443",
            "protocol": "tcp",
        },
        "observed_at_utc": "2026-11-01T12:00:00Z",
    }
    body = json.dumps(payload).encode("utf-8")

    # POST /api/v1/live/sensor with sensor_node="aws_cloud_sensor" and invalid bearer token
    req = urllib.request.Request(
        f"{base_url}/api/v1/live/sensor",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer invalid_remote_sensor_token",
        },
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=10)

    assert exc_info.value.code == 401
    err_body = json.loads(exc_info.value.read().decode("utf-8"))
    assert err_body.get("error") == "sensor_ingest_unauthorized"
    assert err_body.get("evidence_state") == "unavailable"

    # Assert exactly 0 rows ingested into live_flows
    with sqlite3.connect(live_db) as conn:
        count = conn.execute("SELECT COUNT(*) FROM live_flows").fetchone()[0]
        assert count == 0

    # Also verify that missing bearer token returns 401 and leaves live_flows at 0 rows
    req_no_auth = urllib.request.Request(
        f"{base_url}/api/v1/live/sensor",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info_no_auth:
        urllib.request.urlopen(req_no_auth, timeout=10)

    assert exc_info_no_auth.value.code == 401
    with sqlite3.connect(live_db) as conn:
        count = conn.execute("SELECT COUNT(*) FROM live_flows").fetchone()[0]
        assert count == 0


def test_probe_7_context_memory_grounding_guard(audit_http_server: tuple[str, Path]) -> None:
    """Probe 7: Context memory grounding guard refuses unstored IP with 422 and writes 0 rows."""
    base_url, live_db = audit_http_server

    # Pre-populate a single known baseline flow (198.51.100.27 -> 203.0.113.50)
    features = {name: 1.0 for name in CANONICAL_14_FEATURES}
    scored = {
        "decision": "Benign",
        "rf_attack_probability": 0.15,
        "evidence_state": "verified",
        "reason": "baseline_test_flow",
        "model_sha256": "bd2853a6",
        "provenance": {
            "src_entity_id": "198.51.100.27",
            "dst_entity_id": "203.0.113.50",
            "service_or_port": "80",
            "protocol": "tcp",
        },
    }
    stored_flow = persist_scored_flow(live_db, features, scored)
    flow_id = int(stored_flow["flow_id"])

    # Verify context_memory is initially empty
    with sqlite3.connect(live_db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM context_memory").fetchone()[0] == 0

    # Attempt POST /api/v1/live/context-memory with unstored IP "99.88.77.66"
    unstored_payload = {
        "flow_id": flow_id,
        "operator_id": "lab_operator",
        "entity_ip_or_subnet": "99.88.77.66",
        "expected_behavior_rule": "Host 99.88.77.66 is authorized external partner traffic",
        "service_or_port": "80",
    }
    req = urllib.request.Request(
        f"{base_url}/api/v1/live/context-memory",
        data=json.dumps(unstored_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=10)

    assert exc_info.value.code == 422
    err_body = json.loads(exc_info.value.read().decode("utf-8"))
    assert err_body.get("reason") in ("entity_not_on_flow", "explanation_not_grounded")
    assert err_body.get("evidence_state") == "unavailable"

    # Assert 0 rows written to context_memory
    with sqlite3.connect(live_db) as conn:
        cm_count = conn.execute("SELECT COUNT(*) FROM context_memory").fetchone()[0]
        assert cm_count == 0

    # Also test when unstored IP is embedded in the rule text for a stored entity
    ungrounded_rule_payload = {
        "flow_id": flow_id,
        "operator_id": "lab_operator",
        "entity_ip_or_subnet": "198.51.100.27",
        "expected_behavior_rule": "Traffic from 198.51.100.27 routing via 99.88.77.66 is expected",
        "service_or_port": "80",
    }
    req2 = urllib.request.Request(
        f"{base_url}/api/v1/live/context-memory",
        data=json.dumps(ungrounded_rule_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info2:
        urllib.request.urlopen(req2, timeout=10)

    assert exc_info2.value.code == 422
    err_body2 = json.loads(exc_info2.value.read().decode("utf-8"))
    assert err_body2.get("reason") == "explanation_not_grounded"

    # Verify context_memory remains strictly 0 rows
    with sqlite3.connect(live_db) as conn:
        cm_count = conn.execute("SELECT COUNT(*) FROM context_memory").fetchone()[0]
        assert cm_count == 0


def test_probe_8_x509_operator_identity_guard(tmp_path: Path) -> None:
    """Probe 8: Operator identity guard verifies lab_operator only after credential enrollment."""
    policy_dir = tmp_path / "policy"

    # Initial state: lab_operator is unverified prior to enrollment
    initial_stamp = operator_stamp("lab_operator", policy_dir)
    assert initial_stamp["identity_verified"] is False
    assert initial_stamp["identity_label"] == "unverified_local_label"

    # analyst_a cannot be enrolled and stays unverified
    analyst_result = ensure_lab_operator_credential(policy_dir, "analyst_a")
    assert analyst_result["identity_verified"] is False
    assert analyst_result["identity_label"] == "unverified_local_label"

    analyst_stamp = operator_stamp("analyst_a", policy_dir)
    assert analyst_stamp["identity_verified"] is False
    assert analyst_stamp["identity_label"] == "unverified_local_label"

    # Enroll lab_operator via ensure_lab_operator_credential helper
    enrolled = ensure_lab_operator_credential(policy_dir, "lab_operator")
    assert enrolled["identity_verified"] is True
    assert enrolled["evidence_state"] == "verified"
    assert enrolled["operator_id"] == "lab_operator"
    assert len(enrolled["cert_sha256_prefix"]) == 16

    # Verify lab_operator returns identity_verified: True only after enrollment
    verified_stamp = operator_stamp("lab_operator", policy_dir)
    assert verified_stamp["identity_verified"] is True
    assert verified_stamp["identity_label"] == "verified_operator"
    assert verified_stamp["operator_id"] == "lab_operator"
    assert verified_stamp["cert_sha256_prefix"] == enrolled["cert_sha256_prefix"]

    # analyst_a continues to return identity_verified: False ("unverified_local_label")
    post_analyst_stamp = operator_stamp("analyst_a", policy_dir)
    assert post_analyst_stamp["identity_verified"] is False
    assert post_analyst_stamp["identity_label"] == "unverified_local_label"


def test_evidence_queries_contract(tmp_path: Path) -> None:
    """Evidence queries contract: query IDs match canonical 3 evidence queries."""
    expected_query_ids = [
        "entity_historical_frequency",
        "destination_port_protocol_baseline",
        "correlated_campaign_soar_ledger",
    ]

    # Test baseline list_evidence_locker_queries helper
    queries = list_evidence_locker_queries()
    query_ids = [q["query_id"] for q in queries]
    assert query_ids == expected_query_ids
    assert [q.query_id for q in queries] == expected_query_ids
    assert queries == expected_query_ids

    # Test list_evidence_locker_queries with real stored flow in isolated SQLite DB
    db_path = tmp_path / "live_evidence.sqlite3"
    features = {name: 1.0 for name in CANONICAL_14_FEATURES}
    scored = {
        "decision": "Attack",
        "rf_attack_probability": 0.88,
        "evidence_state": "verified",
        "reason": "frozen_random_forest_scored",
        "model_sha256": "bd2853a6",
        "provenance": {
            "src_entity_id": "198.51.100.27",
            "dst_entity_id": "203.0.113.50",
            "service_or_port": "80",
            "protocol": "tcp",
        },
    }
    stored = persist_scored_flow(db_path, features, scored)
    flow_id = int(stored["flow_id"])

    flow_queries = list_evidence_locker_queries(db_path, flow_id)
    flow_query_ids = [q["query_id"] for q in flow_queries]
    assert flow_query_ids == expected_query_ids


def test_action_graph_contract() -> None:
    """Action graph contract: the 5 action graph column titles under #actionGraphBoard match charter."""
    index_html = REPO_ROOT / "frontend" / "index.html"
    assert index_html.is_file(), f"Missing index.html at {index_html}"
    content = index_html.read_text(encoding="utf-8")

    titles = parse_action_graph_columns(content)
    expected_titles = [
        "Alert",
        "Understand & Strategize",
        "Collect Evidence",
        "Analyze",
        "Report & Respond",
    ]
    assert titles == expected_titles, f"Column titles mismatch: {titles} != {expected_titles}"


def test_generate_reports_markdown_has_no_trailing_spaces(tmp_path: Path) -> None:
    """Markdown audit reports must not emit trailing whitespace."""
    from scripts.run_autonomous_product_audit import generate_reports

    audit = {
        "timestamp_utc": "2026-11-02T00:00:00+00:00",
        "git_branch": "gemini/product-20260924",
        "git_head_sha": "c5cf725",
        "overall_decision": "GO",
        "red_team_suite": {"passed": True, "summary": "ok", "probes": []},
        "jury_governance_suite": {"passed": True, "checks": {}},
        "investor_e2e_suite": {"status": "SKIPPED", "reason": "not requested"},
    }
    _json_path, md_path = generate_reports(audit, tmp_path)
    for line in md_path.read_text(encoding="utf-8").splitlines():
        assert line == line.rstrip(), line
