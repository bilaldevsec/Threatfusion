"""Regressions for the eight d669be8 zero-defect findings."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import subprocess
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from threatfusion.api.live_soc_console import (
    _flow_endpoint,
    _snapshot_chain_status,
    approve_live_soar,
    assemble_live_workbench,
    build_alert_fatigue_compression_funnel,
    enroll_lab_operator,
    list_live_campaigns,
    persist_scored_flow,
    preview_soar_playbook,
    publish_lab_enrollment,
    score_canonical_flow,
)
from threatfusion.models.drift_and_supply_chain import CANONICAL_14_FEATURES
from threatfusion.operations.human_credentials import FILENAME, active_fingerprint
from threatfusion.soar.playbook_ledger import SoarPlaybookSqliteRepository

ROOT = Path(__file__).resolve().parents[3]


class _Width14Model:
    n_features_in_ = 14

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        return [[0.2, 0.81]]


def _features() -> dict[str, float]:
    return {name: 1.0 for name in CANONICAL_14_FEATURES}


def _attack_flow(db_path: Path) -> int:
    stored = persist_scored_flow(
        db_path,
        _features(),
        score_canonical_flow(
            _features(),
            repo_root=ROOT,
            model=_Width14Model(),
            supply_verified=True,
        ),
    )
    return int(stored["flow_id"])


def _audit_count(path: Path) -> int:
    if not path.is_file():
        return 0
    with sqlite3.connect(path) as conn:
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "soar_audit_events" not in tables:
            return 0
        count = conn.execute("SELECT COUNT(*) FROM soar_audit_events").fetchone()
    return int(count[0]) if count is not None else 0


def _post_json(url: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
    import urllib.error
    import urllib.request

    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-ThreatFusion-Test-Client": "in-process",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            parsed = json.loads(response.read().decode("utf-8"))
            return response.status, parsed if isinstance(parsed, dict) else {}
    except urllib.error.HTTPError as exc:
        parsed = json.loads(exc.read().decode("utf-8"))
        return exc.code, parsed if isinstance(parsed, dict) else {}


def _load_mcp():
    path = ROOT / "scripts" / "threatfusion_mcp_server.py"
    spec = importlib.util.spec_from_file_location("threatfusion_mcp_polish_d669be8", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bare_enroll_cannot_approve_without_a_presented_certificate(
    tmp_path: Path, monkeypatch
) -> None:
    from scripts.run_misp_and_callback_contract_server import MispAndCallbackContractHandler

    live_db = tmp_path / "live.sqlite3"
    soar_db = tmp_path / "soar.sqlite3"
    flow_id = _attack_flow(live_db)
    policy = tmp_path / "operator-policy"
    enrolled = enroll_lab_operator(policy, "lab_operator")
    published = publish_lab_enrollment(enrolled, presented_fingerprint="")
    assert published["identity_verified"] is False
    assert published["evidence_state"] == "unverified_lab_session"
    fingerprint = active_fingerprint(policy, "lab_operator")
    assert fingerprint
    assert (policy / FILENAME).is_file()
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(live_db))
    monkeypatch.setenv("THREATFUSION_OPERATOR_POLICY_DIR", str(policy))
    monkeypatch.setenv("THREATFUSION_SOAR_HMAC_SECRET", "lab-hmac-secret-01")
    previous = MispAndCallbackContractHandler.soar_db_path
    MispAndCallbackContractHandler.soar_db_path = str(soar_db)
    server = ThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        before = _audit_count(soar_db)
        status, body = _post_json(
            f"{base}/api/v1/live/soar/approve",
            {
                "flow_id": flow_id,
                "actor_id": "lab_operator",
                "reason": "Analyst recorded local approval. Containment is not executed.",
            },
        )
        assert status == 403
        assert body["reason"] == "operator_identity_unverified"
        assert body["execution_authorized"] is False
        assert _audit_count(soar_db) == before
    finally:
        MispAndCallbackContractHandler.soar_db_path = previous
        server.shutdown()
        server.server_close()
    approved = approve_live_soar(
        live_db,
        soar_db,
        flow_id=flow_id,
        actor_id="lab_operator",
        reason="Analyst recorded local approval. Containment is not executed.",
        policy_dir=policy,
        presented_fingerprint=fingerprint,
    )
    assert approved["http_status"] == 200
    assert approved["execution_authorized"] is True
    assert _audit_count(soar_db) > 0
    launcher = (ROOT / "scripts" / "run_live_product.sh").read_text(encoding="utf-8")
    seed = launcher.split("from threatfusion.api.live_soc_console import enroll_lab_operator", 1)[1]
    assert 'evidence_state") != "verified"' not in seed
    assert "fingerprint_file.is_file()" in seed


def test_missing_or_empty_ledger_stays_unavailable(tmp_path: Path) -> None:
    missing = tmp_path / "missing.sqlite3"
    assert _snapshot_chain_status(None) == "unavailable"
    assert _snapshot_chain_status(missing) == "unavailable"
    empty = tmp_path / "empty.sqlite3"
    SoarPlaybookSqliteRepository(empty)
    assert _snapshot_chain_status(empty) == "unavailable"
    live_db = tmp_path / "live.sqlite3"
    flow_id = _attack_flow(live_db)
    listed = list_live_campaigns(live_db, soar_db_path=empty)
    assert listed["playbook_hash_chain_status"] == "unavailable"
    workflow = ROOT / "docker" / "n8n" / "workflows" / "threatfusion_live_console_playbook.json"
    funnel = build_alert_fatigue_compression_funnel(live_db)
    brief = assemble_live_workbench(live_db, workflow, funnel, empty)["portable_handoff_brief"]
    assert "Ledger Verification: unavailable" in brief
    assert "Ledger Verification: verified" not in brief
    policy = tmp_path / "operator-policy"
    enroll_lab_operator(policy, "lab_operator")
    fingerprint = active_fingerprint(policy, "lab_operator")
    soar_db = tmp_path / "soar.sqlite3"
    approved = approve_live_soar(
        live_db,
        soar_db,
        flow_id=flow_id,
        actor_id="lab_operator",
        reason="Analyst recorded local approval. Containment is not executed.",
        policy_dir=policy,
        presented_fingerprint=fingerprint,
    )
    assert approved["execution_authorized"] is True
    assert _snapshot_chain_status(soar_db) == "verified"
    verified = assemble_live_workbench(live_db, workflow, funnel, soar_db)["portable_handoff_brief"]
    assert "Ledger Verification: verified" in verified


def test_noise_reduction_stays_below_100_while_one_incident_remains(tmp_path: Path) -> None:
    live_db = tmp_path / "live.sqlite3"
    flow_id = _attack_flow(live_db)
    with sqlite3.connect(live_db) as conn:
        conn.execute(
            "UPDATE live_flows SET burst_count = ?, decision = ? WHERE flow_id = ?",
            (10**9, "Attack", flow_id),
        )
    funnel = build_alert_fatigue_compression_funnel(live_db)
    assert funnel["high_confidence_incidents"] == 1
    assert funnel["raw_telemetry_events"] == 10**9
    assert funnel["noise_reduction_pct"] < 100.0
    assert funnel["noise_reduction_pct"] == 99.9
    with sqlite3.connect(live_db) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET burst_count = ?, decision = ?, rf_attack_probability = ?
            WHERE flow_id = ?
            """,
            (4, "Benign", 0.1, flow_id),
        )
    cleared = build_alert_fatigue_compression_funnel(live_db)
    assert cleared["high_confidence_incidents"] == 0
    assert cleared["noise_reduction_pct"] == 100.0


def test_playbook_uses_remapped_normal_class_not_the_dataset_category(
    tmp_path: Path, monkeypatch
) -> None:
    def _rows(_db_path: Path, *, limit: int, flow_id: int | None = None) -> list[dict[str, object]]:
        del limit, flow_id
        return [
            {
                "flow_id": 7,
                "decision": "Benign",
                "case_title": "quiet",
                "playbook_id": "",
                "src_entity_id": "172.29.0.10",
                "dst_entity_id": "172.29.0.20",
                "rf_attack_probability": 0.2,
                "dnn_attack_probability": 0.002,
                "dnn_class": "DoS",
                "predicted_class": "DoS",
                "unsw_attack_category": "DoS",
                "sensor_observation": {"proto": "tcp", "src_port": 40000, "dst_port": 80},
                "service_or_port": "80",
                "flow_protocol": "tcp",
                "ledger_state": "",
                "prev_entry_sha256": "",
                "audit_chain_verified": 0,
                "callback_recorded": 0,
                "containment_state": "",
                "ae_loss": 0.01,
            }
        ]

    monkeypatch.setattr("threatfusion.api.live_soc_console._flow_rows", _rows)
    preview = preview_soar_playbook(tmp_path / "unused.sqlite3", flow_id=7)
    rendered = str(preview["rendered_python_code"])
    assert "DNN_PREDICTED_CLASS = 'Normal'" in rendered
    assert "DNN_PREDICTED_CLASS = 'DoS'" not in rendered
    assert preview["unsw_attack_category"] == "DoS"
    assert preview["dnn_predicted_class"] == "Normal"


def test_mcp_rejects_forbidden_verbs_smuggled_in_arguments(monkeypatch) -> None:
    del monkeypatch
    mcp = _load_mcp()
    calls = {"count": 0}

    def _list_queue(_arguments: dict[str, object]) -> dict[str, object]:
        calls["count"] += 1
        return {"read_only": True}

    mcp._HANDLERS["threatfusion_list_queue"] = _list_queue
    blocked = mcp.handle_rpc(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "threatfusion_list_queue",
                "arguments": {
                    "action": "threatfusion_approve",
                    "tool": "Isolate",
                    "command": "rollback",
                },
            },
        }
    )
    assert blocked is not None
    assert blocked["error"]["code"] == -32001
    assert calls["count"] == 0


def test_deploy_full_stack_dry_run_prints_the_live_bridge_checks() -> None:
    completed = subprocess.run(
        [
            "bash",
            str(ROOT / "scripts" / "deploy_cloud_range.sh"),
            "--dry-run",
            "--provider",
            "generic",
            "--deploy-full-stack",
            "--victim-host",
            "203.0.113.10",
            "--attacker-host",
            "203.0.113.11",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    assert "HTTP 200" in completed.stdout
    assert "stored_rows > 0" in completed.stdout


def test_dataset_flow_without_proto_or_service_names_the_dataset() -> None:
    label = _flow_endpoint(
        {
            "flow_id": 8,
            "src_entity_id": "",
            "dst_entity_id": "",
            "flow_protocol": "",
            "service_or_port": "",
        },
        "src",
    )
    assert label == "dataset_flow#8 (unsw_dataset)"
    named = _flow_endpoint(
        {
            "flow_id": 9,
            "src_entity_id": "",
            "flow_protocol": "tcp",
            "service_or_port": "80",
        },
        "src",
    )
    assert named == "dataset_flow#9 (tcp/80)"


def test_denied_clipboard_keeps_the_handoff_visible_without_a_pageerror() -> None:
    probe = r"""
const fs = require('fs');
const report = {
  textContent: 'No shift handoff exported yet.',
  attrs: {},
  setAttribute(name, value) { this.attrs[name] = value; }
};
global.window = global;
global.document = {
  readyState: 'loading',
  querySelector() { return null; },
  querySelectorAll() { return []; },
  addEventListener() {},
  getElementById(id) { return id === 'shiftHandoffReport' ? report : null; }
};
global.navigator = {
  clipboard: {
    writeText() {
      const error = new Error('NotAllowedError');
      error.name = 'NotAllowedError';
      return Promise.reject(error);
    }
  }
};
let pageerrors = 0;
process.on('unhandledRejection', () => { pageerrors += 1; });
eval(fs.readFileSync(process.argv[1], 'utf8'));
const api = global.ThreatFusionDashboard;
const brief = 'Incident ID: flow 1\nLedger Verification: unavailable\nSOAR state: execution_authorized=false\n';
api.primePortableHandoffBrief(brief);
api.copyPortableHandoffBrief().then(() => {
  setTimeout(() => {
    if (pageerrors !== 0) process.exit(2);
    if (report.textContent.indexOf('Ledger Verification: unavailable') === -1) process.exit(3);
    if (report.attrs['data-evidence-state'] !== 'unavailable') process.exit(4);
    if (report.hidden === true) process.exit(5);
    if (api.portableHandoffEvidenceState('Ledger Verification: verified') !== 'verified') process.exit(6);
    process.exit(0);
  }, 40);
}).catch((err) => {
  console.error(err);
  process.exit(1);
});
"""
    completed = subprocess.run(
        ["node", "-e", probe, str(ROOT / "frontend" / "js" / "soc_dashboard.js")],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
