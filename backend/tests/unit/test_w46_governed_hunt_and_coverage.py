"""RFC W46-01 lab hunt runner, coverage heatmap, and timeline grouping."""

from __future__ import annotations

import ast
import json
import os
import re
import socket
import sqlite3
import subprocess
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from threatfusion.evaluation.coverage_heatmap import (
    FROZEN_RF_SHA256,
    STATIC_MITRE_CVE_MAPPING,
    build_coverage_heatmap,
    heatmap_canonical_bytes,
)
from threatfusion.evaluation.lab_hunt_runner import (
    FORBIDDEN_PRODUCTION_DB_NAMES,
    LAB_CLASSIFICATION,
    LabHuntSandboxError,
    LabHuntSchemaError,
    canonical_json,
    canonical_sha256,
    lab_network_sandbox,
    probe_outbound_socket_blocked,
    run_lab_hunt_pack,
    verify_lab_hash_chain,
)
from threatfusion.evaluation.timeline_journal import group_consecutive_timeline_by_actor

REPO_ROOT = Path(__file__).resolve().parents[3]
_RUNNER_PATH = (
    REPO_ROOT / "backend" / "src" / "threatfusion" / "evaluation" / "lab_hunt_runner.py"
)
_HEATMAP_PATH = (
    REPO_ROOT / "backend" / "src" / "threatfusion" / "evaluation" / "coverage_heatmap.py"
)
_FORBIDDEN_IMPORT_TOKENS = (
    "threatfusion.advisory",
    "gemini_client",
    "chromadb",
    "explanation_engine",
    "threatfusion.alerts",
    "threatfusion.soar",
    "network_inference",
)


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            found.append(module)
            found.extend(f"{module}.{alias.name}" for alias in node.names)
    return found


def _fixture() -> dict[str, object]:
    return {
        "schema_version": "lab_hunt_fixture_v1",
        "fixture_id": "replay-local-01",
        "source": "local_replay",
        "records": [
            {
                "record_id": "rec-1",
                "actor": "10.0.0.4",
                "technique_id": "T1046",
                "observed_at": "2026-01-01T00:00:00Z",
                "fields": {"dst_port": 445},
            },
            {
                "record_id": "rec-2",
                "actor": "10.0.0.5",
                "technique_id": "T1190",
                "observed_at": "2026-01-01T00:00:01Z",
                "fields": {"dst_port": 80},
            },
        ],
    }


def _pack() -> dict[str, object]:
    return {
        "schema_version": "lab_hunt_pack_v1",
        "pack_id": "pack-ports",
        "filters": [
            {"step_id": "port-445", "field": "dst_port", "equals": 445},
            {"step_id": "technique", "field": "technique_id", "equals": "T1046"},
        ],
    }


def _live_db(path: Path, rows: list[tuple[object, ...]]) -> None:
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE live_flows (
            flow_id INTEGER PRIMARY KEY,
            decision TEXT,
            evidence_state TEXT,
            production_fusion_enabled INTEGER,
            model_sha256 TEXT,
            case_title TEXT,
            source_label TEXT
        )
        """
    )
    connection.executemany(
        """
        INSERT INTO live_flows (
            flow_id, decision, evidence_state, production_fusion_enabled,
            model_sha256, case_title, source_label
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    connection.commit()
    connection.close()


def test_rt_w46_g9_1_lab_runner_has_no_forbidden_imports() -> None:
    imports = _imports(_RUNNER_PATH)
    for token in _FORBIDDEN_IMPORT_TOKENS + ("sqlite3",):
        assert all(token not in item for item in imports)
    source = _RUNNER_PATH.read_text(encoding="utf-8")
    assert "soar.sqlite3" in source
    assert "alerts.sqlite3" in source
    assert "incidents.sqlite3" in source


def test_rt_w46_g9_2_coverage_helper_stays_outside_advisory() -> None:
    imports = _imports(_HEATMAP_PATH)
    for token in _FORBIDDEN_IMPORT_TOKENS:
        assert all(token not in item for item in imports)
    python = REPO_ROOT / "threatfusion-venv" / "bin" / "python"
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONPATH"] = str(REPO_ROOT / "backend" / "src")
    script = (
        "import sys\n"
        "import threatfusion.evaluation.coverage_heatmap\n"
        "import threatfusion.evaluation.lab_hunt_runner\n"
        "bad = [name for name in sys.modules if any(token in name for token in "
        "('chromadb', 'gemini_client', 'explanation_engine', 'threatfusion.advisory'))]\n"
        "raise SystemExit(1 if bad else 0)\n"
    )
    completed = subprocess.run(
        [str(python), "-c", script],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_rt_w46_d1_hunt_pack_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "one" / "lab_hunt_chain.json"
    second = tmp_path / "two" / "lab_hunt_chain.json"
    left = run_lab_hunt_pack(_fixture(), _pack(), first)
    right = run_lab_hunt_pack(_fixture(), _pack(), second)
    assert left["head_sha256"] == right["head_sha256"]
    assert left["records"] == right["records"]
    assert first.read_bytes() == second.read_bytes()
    assert verify_lab_hash_chain(first) is True


def test_rt_w46_d2_schema_and_lab_classification(tmp_path: Path) -> None:
    chain = tmp_path / "lab_hunt_chain.json"
    result = run_lab_hunt_pack(_fixture(), _pack(), chain)
    assert result["alert_created"] is False
    assert result["production_fusion_enabled"] is False
    assert result["records"]
    assert {row["classification"] for row in result["records"]} == {LAB_CLASSIFICATION}
    assert all(row["alert_created"] is False for row in result["records"])
    assert [row["record_id"] for row in result["records"]] == ["rec-1"]
    live = dict(_fixture())
    live["source"] = "live_production"
    refused = tmp_path / "refused.json"
    with pytest.raises(LabHuntSchemaError):
        run_lab_hunt_pack(live, _pack(), refused)
    assert not refused.exists()


def test_rt_w46_l1_outbound_socket_is_refused(tmp_path: Path) -> None:
    with pytest.raises(LabHuntSandboxError, match="allowed"):
        probe_outbound_socket_blocked()
    with lab_network_sandbox():
        with pytest.raises(LabHuntSandboxError, match="refused"):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("203.0.113.10", 443))
        with pytest.raises(LabHuntSandboxError, match="refused"):
            socket.create_connection(("203.0.113.10", 443), timeout=0.2)
    chain = tmp_path / "lab_hunt_chain.json"
    with pytest.raises(LabHuntSandboxError, match="allowed"):
        run_lab_hunt_pack(_fixture(), _pack(), chain, allow_network=True)
    assert not chain.exists()
    result = run_lab_hunt_pack(_fixture(), _pack(), chain)
    assert result["network_blocked"] is True
    with pytest.raises(LabHuntSandboxError, match="allowed"):
        probe_outbound_socket_blocked()


def test_rt_w46_h1_each_filter_step_uses_canonical_json(tmp_path: Path) -> None:
    assert canonical_json({"b": 1, "a": "x"}) == '{"a":"x","b":1}'
    assert " " not in canonical_json({"b": 1, "a": [2, 3]})
    encoded = canonical_json({"classification": LAB_CLASSIFICATION})
    assert "—" in encoded
    assert "\\u2014" not in encoded
    chain = tmp_path / "lab_hunt_chain.json"
    run_lab_hunt_pack(_fixture(), _pack(), chain)
    document = json.loads(chain.read_text(encoding="utf-8"))
    assert len(document["entries"]) == 2
    previous = "0" * 64
    for entry in document["entries"]:
        payload = {
            key: entry[key]
            for key in (
                "filter",
                "hypotheses_sha256",
                "prev_entry_sha256",
                "sequence_id",
                "surviving_record_ids",
            )
            if key in entry
        }
        assert entry["prev_entry_sha256"] == previous
        assert entry["entry_sha256"] == canonical_sha256(payload)
        assert " " not in canonical_json(payload)
        previous = entry["entry_sha256"]
    assert document["entries"][-1]["hypotheses_sha256"] == canonical_sha256(
        document["hypotheses"]
    )


def test_rt_w46_h2_chain_file_is_separate_from_product_databases(tmp_path: Path) -> None:
    chain = tmp_path / "lab_hunt_chain.json"
    run_lab_hunt_pack(_fixture(), _pack(), chain)
    assert chain.is_file()
    assert (chain.stat().st_mode & 0o777) == 0o600
    assert chain.name not in FORBIDDEN_PRODUCTION_DB_NAMES
    for name in ("soar.sqlite3", "alerts.sqlite3", "incidents.sqlite3"):
        forbidden = tmp_path / name
        with pytest.raises(LabHuntSandboxError):
            run_lab_hunt_pack(_fixture(), _pack(), forbidden)
        assert not forbidden.exists()
    assert list(tmp_path.glob("*.sqlite3")) == []


def test_rt_w46_h3_chain_verification_detects_tamper_and_deletion(tmp_path: Path) -> None:
    chain = tmp_path / "lab_hunt_chain.json"
    run_lab_hunt_pack(_fixture(), _pack(), chain)
    assert verify_lab_hash_chain(chain) is True
    original = chain.read_text(encoding="utf-8")
    document = json.loads(original)
    document["hypotheses"][0]["classification"] = "Attack"
    chain.write_text(canonical_json(document), encoding="utf-8")
    assert verify_lab_hash_chain(chain) is False
    chain.write_text(original, encoding="utf-8")
    os.chmod(chain, 0o600)
    document = json.loads(original)
    document["entries"] = document["entries"][:1]
    chain.write_text(canonical_json(document), encoding="utf-8")
    assert verify_lab_hash_chain(chain) is False
    for name in FORBIDDEN_PRODUCTION_DB_NAMES:
        assert verify_lab_hash_chain(tmp_path / name) is False


def test_rt_w46_e1_heatmap_canonical_json_is_byte_identical(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "live.sqlite3"
    _live_db(
        db_path,
        [
            (
                1,
                "Attack",
                "verified",
                0,
                FROZEN_RF_SHA256,
                "Web exploit replay (scenario label T1190)",
                "live_scenario_replay",
            ),
            (
                2,
                "Benign",
                "verified",
                0,
                FROZEN_RF_SHA256,
                "Benign false alarm",
                "live_scenario_replay",
            ),
            (
                3,
                "Attack",
                "unavailable",
                0,
                FROZEN_RF_SHA256,
                "scenario label T1046",
                "live_scenario_replay",
            ),
        ],
    )
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(db_path))
    monkeypatch.delenv("THREATFUSION_LAB_HUNT_CHAIN", raising=False)
    from scripts.run_misp_and_callback_contract_server import MispAndCallbackContractHandler

    server = ThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        first = _get_bytes(f"{base}/api/v1/live/coverage-heatmap")
        second = _get_bytes(f"{base}/api/v1/live/coverage-heatmap?include_lab=false")
    finally:
        server.shutdown()
        server.server_close()
    assert first[0] == 200
    assert first[1] == second[1]
    payload = json.loads(first[1])
    direct = build_coverage_heatmap(db_path, include_lab=False)
    assert first[1] == heatmap_canonical_bytes(direct)
    assert payload["include_lab"] is False
    assert payload["production_fusion_enabled"] is False
    assert payload["read_only"] is True
    assert len(payload["claimed"]) == 18
    assert [item[0] for item in STATIC_MITRE_CVE_MAPPING] == [item["id"] for item in payload["claimed"]]
    assert all(item["evidence_state"] == "unavailable" for item in payload["claimed"])
    by_id = {cell["id"]: cell for cell in payload["cells"]}
    assert by_id["T1190"]["rf_confirmed_count"] == 1
    assert by_id["T1190"]["evidence_state"] == "verified"
    assert by_id["T1046"]["evidence_state"] == "unavailable"
    assert by_id["T1046"]["rf_confirmed_count"] == 0


def test_rt_w46_e2_heatmap_methods_and_lab_toggle(tmp_path: Path, monkeypatch) -> None:
    chain = tmp_path / "lab_hunt_chain.json"
    run_lab_hunt_pack(_fixture(), _pack(), chain)
    db_path = tmp_path / "empty.sqlite3"
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(db_path))
    monkeypatch.setenv("THREATFUSION_LAB_HUNT_CHAIN", str(chain))
    hidden = build_coverage_heatmap(db_path, include_lab=False, lab_chain_path=chain)
    shown = build_coverage_heatmap(db_path, include_lab=True, lab_chain_path=chain)
    hidden_t1046 = next(cell for cell in hidden["cells"] if cell["id"] == "T1046")
    shown_t1046 = next(cell for cell in shown["cells"] if cell["id"] == "T1046")
    assert hidden_t1046["lab_hypothesis_count"] == 0
    assert hidden_t1046["observed_count"] == 0
    assert shown_t1046["lab_hypothesis_count"] == 1
    assert shown_t1046["rf_confirmed_count"] == 0
    assert shown_t1046["evidence_state"] == "unavailable"
    from scripts.run_misp_and_callback_contract_server import MispAndCallbackContractHandler

    server = ThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}/api/v1/live/coverage-heatmap"
    try:
        for method in ("POST", "PUT", "DELETE"):
            status, body, allow = _method(base, method)
            assert status == 405
            assert allow == "GET"
            parsed = json.loads(body)
            assert parsed["error"] == "method_not_allowed"
            assert parsed["evidence_state"] == "unavailable"
        status, body = _get_bytes(base + "?include_lab=true")
    finally:
        server.shutdown()
        server.server_close()
    assert status == 200
    payload = json.loads(body)
    assert payload["include_lab"] is True
    cell = next(item for item in payload["cells"] if item["id"] == "T1046")
    assert cell["lab_hypothesis_count"] == 1
    assert cell["evidence_state"] == "unavailable"


def test_rt_w46_e3_unverified_cells_stay_unavailable(tmp_path: Path) -> None:
    payload = build_coverage_heatmap(tmp_path / "missing.sqlite3", include_lab=False)
    assert payload["observed_reason"] == "live_store_unavailable"
    assert all(cell["evidence_state"] == "unavailable" for cell in payload["cells"])
    assert all(item["evidence_state"] == "unavailable" for item in payload["observed"])
    wrong_model = tmp_path / "wrong.sqlite3"
    _live_db(
        wrong_model,
        [
            (
                1,
                "Attack",
                "verified",
                0,
                "0" * 64,
                "scenario label T1110",
                "live_scenario_replay",
            )
        ],
    )
    fused = build_coverage_heatmap(wrong_model)
    assert next(cell for cell in fused["cells"] if cell["id"] == "T1110")["evidence_state"] == (
        "unavailable"
    )
    source = _HEATMAP_PATH.read_text(encoding="utf-8")
    assert "mode=ro" in source
    assert "INSERT" not in source
    assert "explanation_engine" not in source
    assert "gemini_client" not in source
    assert "chromadb" not in source


def test_rt_w46_f1_timeline_toggle_groups_consecutive_actors() -> None:
    events = [
        {
            "actor_id": "analyst_a",
            "observed_at": "t1",
            "summary": "one",
            "entry_sha256": "aa",
        },
        {
            "actor_id": "analyst_a",
            "observed_at": "t2",
            "summary": "two",
            "entry_sha256": "bb",
        },
        {
            "actor_id": "analyst_b",
            "observed_at": "t3",
            "summary": "three",
            "entry_sha256": "cc",
        },
        {
            "actor_id": "analyst_a",
            "observed_at": "t4",
            "summary": "four",
            "entry_sha256": "dd",
        },
    ]
    before = json.dumps(events)
    groups = group_consecutive_timeline_by_actor(events)
    assert [group["actor"] for group in groups] == ["analyst_a", "analyst_b", "analyst_a"]
    assert [len(group["events"]) for group in groups] == [2, 1, 1]
    assert json.dumps(events) == before
    assert events[0]["entry_sha256"] == "aa"
    html = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    script = (REPO_ROOT / "frontend" / "js" / "soc_dashboard.js").read_text(encoding="utf-8")
    assert 'id="timelineViewToggle"' in html
    assert 'id="timelineViewJournal"' in html
    assert 'id="timelineViewTable"' in html
    assert html.index('id="timelineViewToggle"') < html.index("Evidence Locker (14-Feat)")
    assert "Observed (RF-Confirmed)" in html
    assert "Claimed (Static Mapping)" in html
    assert "groupConsecutiveTimelineByActor" in script
    assert "setTimelineViewMode" in script
    assert "/api/v1/live/coverage-heatmap?include_lab=false" in script
    render_start = script.index("function renderTimelineGroupedView")
    render_end = script.index("function setTimelineViewMode")
    render_body = script[render_start:render_end]
    assert "forensicDrawer" not in render_body
    assert "data-copy-hash" not in render_body
    start = script.index("const INDEXED_MITRE_COVERAGE")
    end = script.index("function flowContractPassed")
    indexed_ids = re.findall(r"id: '([^']+)'", script[start:end])
    assert indexed_ids == [item[0] for item in STATIC_MITRE_CVE_MAPPING]


def _get_bytes(url: str) -> tuple[int, bytes]:
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.status, response.read()


def _method(url: str, method: str) -> tuple[int, bytes, str | None]:
    request = urllib.request.Request(url, data=b"{}", method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read(), response.headers.get("Allow")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get("Allow")
