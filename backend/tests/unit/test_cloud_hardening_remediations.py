"""Regression tests for final cloud-hardening & P0-P2 war-room remediations."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import subprocess
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from scripts.follow_suricata_eve import remember_alert, sensor_payload
from scripts.run_misp_and_callback_contract_server import MispAndCallbackContractHandler
from threatfusion.advisory.advisory_trace import gate_g9_status
from threatfusion.advisory.telemetry_shield import draft_detection_rule
from threatfusion.api import live_soc_console
from threatfusion.api.live_soc_console import (
    _ATTACK_PROFILE_CANONICAL,
    _finite_feature_vector,
    _flow_rows,
    _flow_triggers_draft,
    _hunt_queue_rows,
    _valid_network,
    approve_live_soar,
    dispatch_approved_callback,
    draft_live_hunter_rule,
    enroll_lab_operator,
    launch_range_vector,
    list_live_campaigns,
    list_recommended_hunting_guides,
    persist_scored_flow,
    rbac_login,
    read_advisory_trace,
    record_suricata_bridge_flow,
    score_canonical_flow,
)
from threatfusion.evaluation import boundary_preflight
from threatfusion.operations.bridge_noise import is_lab_bridge_noise
from threatfusion.operations.human_credentials import active_fingerprint

REPO_ROOT = Path(__file__).resolve().parents[3]


def _canonical_features(*, dst_port: float = 80.0, udp: bool = False) -> dict[str, float]:
    return {
        "duration_ms": 12.0,
        "fwd_packets": 4.0,
        "bwd_packets": 3.0,
        "fwd_bytes": 240.0,
        "bwd_bytes": 180.0,
        "packets_per_second": 500.0,
        "bytes_per_second": 35000.0,
        "fwd_packet_length_mean": 60.0,
        "bwd_packet_length_mean": 60.0,
        "dst_port": dst_port,
        "protocol_tcp": 0.0 if udp else 1.0,
        "protocol_udp": 1.0 if udp else 0.0,
        "protocol_icmp": 0.0,
        "protocol_other": 0.0,
    }


def _http_post_json(
    base: str, path: str, payload: dict[str, object], *, session_token: str | None = None
) -> tuple[int, dict[str, object]]:
    headers = {
        "Content-Type": "application/json",
        "X-ThreatFusion-Test-Client": "in-process",
    }
    if session_token:
        headers["X-ThreatFusion-Session"] = session_token
    req = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


# --- Item 1: /opt/threatfusion self-collision guard ---


def test_item1_opt_threatfusion_self_collision_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opt_root = tmp_path / "opt" / "threatfusion"
    opt_root.mkdir(parents=True)
    protected = boundary_preflight._resolve_default_protected_workspace(opt_root)
    assert protected.resolve() != opt_root.resolve()
    assert not protected.exists()

    monkeypatch.setattr(boundary_preflight, "_DECLARED_ACTIVE_WORKSPACE", opt_root)
    monkeypatch.setattr(boundary_preflight, "CANONICAL_PROTECTED_WORKSPACE", protected)
    monkeypatch.setattr(boundary_preflight, "_module_checkout_root", lambda: opt_root)

    resolved = boundary_preflight.resolve_default_active_workspace()
    assert resolved == opt_root.resolve()

    passed, violations = gate_g9_status(REPO_ROOT)
    assert passed is True
    assert violations == ()


# --- Item 2: Non-overlapping 12s poll & Refresh Queue button ---


def test_item2_polling_livelock_removed_and_refresh_queue_wired() -> None:
    js_path = REPO_ROOT / "frontend" / "js" / "soc_dashboard.js"
    html_path = REPO_ROOT / "frontend" / "index.html"
    js_text = js_path.read_text(encoding="utf-8")
    html_text = html_path.read_text(encoding="utf-8")

    assert "setInterval(refreshLiveCampaigns" not in js_text
    assert "CAMPAIGN_POLL_INTERVAL_MS = 12000" in js_text
    assert "scheduleCampaignPoll" in js_text
    assert 'id="btnRefreshQueue"' in html_text
    assert "http://" not in html_text
    assert "https://" not in html_text

    replay_block = js_text.split("async function replayLiveScenarios()", 1)[1].split(
        "function operatorActorId()", 1
    )[0]
    assert replay_block.count("refreshLiveQueue()") >= 2

    probe = r"""
const fs = require('fs');
const listeners = {};
const calls = [];
const elements = {
  btnRefreshQueue: { addEventListener(ev, fn) { listeners.refresh = fn; } },
  compressionFunnelLine: { textContent: '', setAttribute() {} },
  forensicScopePanel: { innerHTML: '', setAttribute() {} }
};
const scheduled = [];
global.window = global;
global.location = { hash: '' };
global.setTimeout = function (fn, ms) { scheduled.push(ms); return scheduled.length; };
global.clearTimeout = function () {};
global.setInterval = function (fn, ms) {
  if (ms === 3000) throw new Error('unexpected 3000ms interval');
  return 1;
};
global.document = {
  readyState: 'loading',
  body: { classList: { toggle() {} } },
  querySelector() { return null; },
  querySelectorAll() { return []; },
  addEventListener() {},
  getElementById(id) { return elements[id] || null; }
};
global.Headers = class Headers { constructor() {} set() {} };
global.fetch = async (url) => {
  calls.push(String(url));
  return {
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ flows: [], campaigns: [], incidents: [] }),
    json: async () => ({ flows: [], campaigns: [], incidents: [] })
  };
};
eval(fs.readFileSync(process.argv[1], 'utf8'));
(async () => {
  await global.ThreatFusionDashboard.initApp();
  await Promise.resolve();
  if (!listeners.refresh) process.exit(2);
  const before = calls.length;
  listeners.refresh();
  await new Promise(r => setImmediate(r));
  const slice = calls.slice(before);
  if (!slice.includes('/api/v1/live/queue') || !slice.includes('/api/v1/live/campaigns')) {
    process.exit(3);
  }
  if (!scheduled.includes(12000)) process.exit(4);
})();
"""
    completed = subprocess.run(
        ["node", "-e", probe, str(js_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout


# --- Item 3: Turnkey fast cloud deploy + WireServer noise filter ---


def test_item3_deploy_cloud_hardening_and_wireserver_noise_filter() -> None:
    assert is_lab_bridge_noise("168.63.129.16", "172.29.0.20", 12345, 80) is True
    assert is_lab_bridge_noise("172.29.0.20", "168.63.129.16", 80, 12345) is True
    assert is_lab_bridge_noise("172.29.0.20", "169.254.169.254", 44321, 80) is True
    assert is_lab_bridge_noise("172.29.0.10", "172.29.0.20", 44120, 80) is False

    cloud = (REPO_ROOT / "scripts" / "deploy_cloud_range.sh").read_text(encoding="utf-8")
    azure = (REPO_ROOT / "scripts" / "deploy_azure_cyber_range.sh").read_text(encoding="utf-8")

    assert "--exclude='data/raw'" in cloud
    assert "GEMINI_ENABLED=" in cloud
    assert "GEMINI_API_KEY=" in cloud
    assert "THREATFUSION_SENSOR_INGEST_TOKEN=" in cloud
    assert (
        "THREATFUSION_LIVE_CONSOLE_DB=/var/lib/threatfusion/threatfusion-live-console.sqlite3"
        in cloud
    )
    assert "threatfusion-eve-follower.service" in cloud
    assert "/opt/threatfusion-venv/bin/python" in cloud
    assert "scikit-learn==1.9.0" in cloud
    assert "threadpoolctl==3.6.0" in cloud
    assert "time.monotonic() + 90.0" in cloud

    assert "/opt/threatfusion-venv/bin/python" in azure
    assert "/usr/bin/python3" not in azure

    for rel in (
        "scripts/deploy_cloud_range.sh",
        "scripts/deploy_azure_cyber_range.sh",
        "scripts/run_full_range_demo.sh",
        "scripts/run_live_product.sh",
    ):
        checked = subprocess.run(
            ["bash", "-n", str(REPO_ROOT / rel)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert checked.returncode == 0, f"{rel}: {checked.stderr}"


def test_item3_wireserver_ip_rejected_by_sensor_bridge(tmp_path: Path) -> None:
    db = tmp_path / "wireserver.sqlite3"
    res = record_suricata_bridge_flow(
        db,
        _canonical_features(),
        repo_root=REPO_ROOT,
        provenance={
            "entity_namespace_id": "lab:range-bridge-01",
            "src_entity_id": "168.63.129.16",
            "dst_entity_id": "172.29.0.20",
            "protocol": "tcp",
            "service_or_port": "80",
            "clock_synchronized": True,
        },
        sensor_observation={
            "proto": "tcp",
            "src_ip": "168.63.129.16",
            "src_port": 44120,
            "dst_ip": "172.29.0.20",
            "dst_port": 80,
        },
        source_event_id=f"suricata_flow_v1:{'a' * 64}",
        observed_at_utc="2026-11-21T00:00:00Z",
    )
    assert res["reason"] == "bridge_noise_ignored"
    assert not db.exists()


# --- Item 4: Lock range endpoints to soc_approver RBAC ---


def test_item4_range_endpoints_locked_to_soc_approver_rbac(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live_db = tmp_path / "live.sqlite3"
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(live_db))
    monkeypatch.setenv("THREATFUSION_ENV", "lab")
    monkeypatch.setattr("threatfusion.api.live_soc_console._docker_range_scan", lambda: None)
    orig_scan = live_soc_console.run_live_range_scan
    monkeypatch.setattr(
        "threatfusion.api.live_soc_console.run_live_range_scan",
        lambda db_path, **kw: orig_scan(
            db_path,
            timeout_seconds=0.1,
            **{k: v for k, v in kw.items() if k != "timeout_seconds"},
        ),
    )
    monkeypatch.setattr(
        "threatfusion.api.live_soc_console._start_range_vector_probe",
        lambda _vector: {"status": "stubbed"},
    )

    refused_direct = launch_range_vector(
        live_db,
        vector_id="T1046",
        src_ip="172.29.0.10",
        dst_ip="172.29.0.20",
        repo_root=REPO_ROOT,
        actor_id="tier1_analyst",
    )
    assert refused_direct["http_status"] == 403
    assert refused_direct["reason"] == "role_insufficient_for_soar"

    tier1_token = str(
        rbac_login(
            live_db,
            username="suhaib.22k4302@nu.edu.pk",
            access_code="TF-Suhaib-4302!",
        )["session_token"]
    )
    auditor_token = str(
        rbac_login(
            live_db,
            username="hasnain.22k4718@nu.edu.pk",
            access_code="TF-Hasnain-4718!",
        )["session_token"]
    )
    approver_token = str(
        rbac_login(
            live_db,
            username="bilal.21k3551@nu.edu.pk",
            access_code="TF-Bilal-3551!",
        )["session_token"]
    )

    srv = ThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        routes = (
            (
                "/api/range/launch",
                {"vector_id": "T1046", "src_ip": "172.29.0.10", "dst_ip": "172.29.0.20"},
            ),
            (
                "/api/v1/live/range/launch-vector",
                {"vector_id": "T1046", "src_ip": "172.29.0.10", "dst_ip": "172.29.0.20"},
            ),
            ("/api/v1/live/range-scan", {}),
        )
        for route, body in routes:
            st_unauth, _ = _http_post_json(base, route, body)
            assert st_unauth == 401, route

            for token in (tier1_token, auditor_token):
                st_denied, denied_body = _http_post_json(base, route, body, session_token=token)
                assert st_denied == 403, route
                assert denied_body["reason"] == "role_insufficient_for_soar"

            st_ok, ok_body = _http_post_json(base, route, body, session_token=approver_token)
            assert st_ok == 200, (route, ok_body)
    finally:
        srv.shutdown()
        srv.server_close()


# --- Item 5: Plain-HTTP SOAR error UX ---


def test_item5_plain_http_soar_error_ux() -> None:
    js_path = REPO_ROOT / "frontend" / "js" / "soc_dashboard.js"
    probe = r"""
const fs = require('fs');
const banner = { textContent: '', attrs: {}, setAttribute(k, v) { this.attrs[k] = v; }, removeAttribute(k) { delete this.attrs[k]; } };
const toast = { hidden: true, textContent: '', attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } };
const elements = {
  actionStatusBanner: banner,
  socToast: toast,
  campaignQueueStatus: { textContent: '', setAttribute() {} },
  operatorActor: { value: 'lab_operator' }
};
global.window = global;
global.window.clearTimeout = () => {};
global.window.setTimeout = () => 1;
global.document = {
  readyState: 'loading',
  querySelector() { return null; },
  querySelectorAll() { return []; },
  addEventListener() {},
  getElementById(id) { return elements[id] || null; }
};
global.Headers = class Headers { constructor() {} set() {} };
global.fetch = async (url) => {
  if (String(url).includes('/api/v1/live/soar/approve')) {
    return {
      ok: false,
      status: 403,
      text: async () => JSON.stringify({ reason: 'operator_identity_unverified' }),
      json: async () => ({ reason: 'operator_identity_unverified' })
    };
  }
  return { ok: true, status: 200, text: async () => '{}', json: async () => ({}) };
};
eval(fs.readFileSync(process.argv[1], 'utf8'));
const api = global.ThreatFusionDashboard;
const msg1 = api.soarOperatorMessage('operator_not_enrolled', 'fallback');
const msg2 = api.soarOperatorMessage('operator_identity_unverified', 'fallback');
if (!msg1.includes('403') || !msg1.toLowerCase().includes('enroll')) process.exit(2);
if (!msg2.includes('403') || !msg2.toLowerCase().includes('mtls')) process.exit(3);
"""
    completed = subprocess.run(
        ["node", "-e", probe, str(js_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    js_text = js_path.read_text(encoding="utf-8")
    assert "soarOperatorMessage(" in js_text
    assert "operator_not_enrolled" in js_text
    assert "operator_identity_unverified" in js_text


# --- Item 6: Preserve ai_governance_controls & expose model_used ---


def test_item6_campaigns_ai_governance_controls_and_trace_model_used(tmp_path: Path) -> None:
    live_db = tmp_path / "live.sqlite3"
    scored = score_canonical_flow(_canonical_features(dst_port=445.0), repo_root=REPO_ROOT)
    stored = persist_scored_flow(
        live_db,
        _canonical_features(dst_port=445.0),
        scored,
        provenance={
            "entity_namespace_id": "lab:cyber-range",
            "src_entity_id": "172.29.0.10",
            "dst_entity_id": "172.29.0.20",
            "protocol": "tcp",
            "service_or_port": "445",
            "clock_synchronized": True,
        },
        case_title="T1046 Network Service Discovery",
        technique_id="T1046",
    )
    flow_id = int(stored["flow_id"])

    campaigns = list_live_campaigns(live_db)
    flow_obj = campaigns["campaigns"][0]["flows"][0]
    gov = flow_obj["advisory_trace"]["ai_governance_controls"]
    assert isinstance(gov, dict)
    assert "inspectable_evidence" in gov
    assert gov["inspectable_evidence"]["envelope_sha256"]

    trace_local = read_advisory_trace(live_db, flow_id)
    assert trace_local["model_used"] == "local_air_gapped"

    with sqlite3.connect(live_db) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS live_copilot_cache (
                cache_key TEXT PRIMARY KEY,
                provider TEXT,
                model_name TEXT,
                narrative TEXT,
                created_at_utc TEXT
            )
            """)
        conn.execute(
            """
            INSERT INTO live_copilot_cache (
                cache_key, provider, model_name, narrative, created_at_utc
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                f"{flow_id}\nT1046\nT1046\nAttack\nq\ngemma-4-31b-it",
                "gemini",
                "gemma-4-31b-it",
                "Grounded brief for 172.29.0.10 -> 172.29.0.20 T1046.",
                "2026-11-21T00:00:00+00:00",
            ),
        )
        conn.commit()

    trace_cached = read_advisory_trace(live_db, flow_id)
    assert trace_cached["model_used"] == "gemma-4-31b-it"

    js_path = REPO_ROOT / "frontend" / "js" / "soc_dashboard.js"
    probe = r"""
const fs = require('fs');
global.window = global;
global.document = { readyState: 'loading', querySelector() { return null; }, addEventListener() {}, getElementById() { return null; } };
global.Headers = class Headers { constructor() {} set() {} };
global.fetch = async () => ({ ok: false, json: async () => ({}) });
eval(fs.readFileSync(process.argv[1], 'utf8'));
const merged = global.ThreatFusionDashboard.mergePreservedAdvisoryTrace(
  { components: [], completeness_badge: 'COMPLETE' },
  { components: [], ai_governance_controls: { frameworks: ['NIST AI RMF'] }, model_used: 'gemma-4-31b-it' }
);
if (!merged.ai_governance_controls || merged.model_used !== 'gemma-4-31b-it') process.exit(2);
"""
    completed = subprocess.run(
        ["node", "-e", probe, str(js_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


# --- Item 7: copyTextBlock Promise return & toast ---


def test_item7_copy_text_block_returns_promise_and_shows_toast() -> None:
    js_path = REPO_ROOT / "frontend" / "js" / "soc_dashboard.js"
    js_text = js_path.read_text(encoding="utf-8")
    assert js_text.count("navigator.clipboard.writeText(") == 1

    probe = r"""
const fs = require('fs');
const toast = { hidden: true, textContent: '', attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } };
const bodyChildren = [];
let clipMode = 'resolve';
global.window = global;
global.window.clearTimeout = () => {};
global.window.setTimeout = () => 1;
Object.defineProperty(global, 'navigator', {
  value: {
    clipboard: {
      writeText() {
        if (clipMode === 'resolve') return Promise.resolve();
        return Promise.reject(new Error('not allowed'));
      }
    }
  },
  configurable: true,
  writable: true
});
global.document = {
  readyState: 'loading',
  body: { appendChild(el) { bodyChildren.push(el); } },
  createElement() {
    return { value: '', style: {}, setAttribute() {}, select() {}, remove() {} };
  },
  execCommand() { return clipMode === 'reject_with_fallback'; },
  querySelector() { return null; },
  addEventListener() {},
  getElementById(id) { return id === 'socToast' ? toast : null; }
};
global.Headers = class Headers { constructor() {} set() {} };
global.fetch = async () => ({ ok: false, json: async () => ({}) });
eval(fs.readFileSync(process.argv[1], 'utf8'));
(async () => {
  const api = global.ThreatFusionDashboard;
  const p1 = api.copyTextBlock('abc');
  if (!p1 || typeof p1.then !== 'function') process.exit(2);
  if ((await p1) !== true) process.exit(3);
  if (toast.textContent !== 'Copied to clipboard' || toast.hidden !== false) process.exit(4);

  clipMode = 'reject_with_fallback';
  toast.textContent = '';
  const p2 = api.copyTextBlock('def');
  if (!p2 || typeof p2.then !== 'function') process.exit(5);
  if ((await p2) !== true || toast.textContent !== 'Copied to clipboard') process.exit(6);

  clipMode = 'reject_no_fallback';
  const p3 = api.copyTextBlock('ghi');
  if (!p3 || typeof p3.then !== 'function' || (await p3) !== false) process.exit(7);

  const p4 = api.copyTextBlock('');
  if (!p4 || typeof p4.then !== 'function' || (await p4) !== false) process.exit(8);
})();
"""
    completed = subprocess.run(
        ["node", "-e", probe, str(js_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout


# --- Item 8: 4 Hunter edge cases ---


def test_item8_hunter_readonly_escape_technique_override_and_t1498_udp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 8a: non-WAL SQLite DB SHA-256 never mutates across read queries
    ro_db = tmp_path / "nonwal.sqlite3"
    conn = sqlite3.connect(ro_db)
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("""
        CREATE TABLE live_flows (
            flow_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at_utc TEXT NOT NULL,
            features_json TEXT NOT NULL,
            rf_attack_probability REAL,
            decision TEXT NOT NULL,
            evidence_state TEXT NOT NULL,
            reason TEXT NOT NULL,
            model_sha256 TEXT NOT NULL,
            production_fusion_enabled INTEGER NOT NULL,
            case_title TEXT,
            service_or_port TEXT,
            flow_protocol TEXT,
            src_entity_id TEXT,
            dst_entity_id TEXT
        )
        """)
    conn.execute(
        """
        INSERT INTO live_flows (
            observed_at_utc, features_json, rf_attack_probability, decision,
            evidence_state, reason, model_sha256, production_fusion_enabled,
            case_title, service_or_port, flow_protocol, src_entity_id, dst_entity_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "2026-11-21T00:00:00Z",
            json.dumps(_canonical_features(dst_port=53.0, udp=True)),
            0.91,
            "Attack",
            "verified",
            "frozen_random_forest_scored",
            "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
            0,
            "T1498 Network DoS",
            "53",
            "udp",
            "172.29.0.10",
            "172.29.0.20",
        ),
    )
    conn.commit()
    conn.close()

    digest_before = hashlib.sha256(ro_db.read_bytes()).hexdigest()
    assert len(_hunt_queue_rows(ro_db)) == 1
    assert len(_flow_rows(ro_db, limit=10)) == 1
    assert list_recommended_hunting_guides(ro_db)["http_status"] == 200
    draft_t1498 = draft_live_hunter_rule(ro_db, guide_id="hunt-t1498")
    digest_after = hashlib.sha256(ro_db.read_bytes()).hexdigest()
    assert digest_before == digest_after
    assert not ro_db.with_name(f"{ro_db.name}-wal").exists()

    # 8d: T1498 defaults to udp and matches udp/53 (and tcp/53) flows
    assert draft_t1498["grounding"]["proto"] == "udp"
    assert draft_t1498["synthetic_replay"]["events_replayed"] == 1
    assert draft_t1498["synthetic_replay"]["rules_triggered"] == 1
    assert draft_t1498["synthetic_replay"]["verify_status"] == "VERIFIED_AGAINST_LIVE_TELEMETRY"
    assert (
        _flow_triggers_draft(
            {"flow_protocol": "tcp", "service_or_port": "53"},
            draft_t1498["grounding"],
        )
        is True
    )

    # 8d: INV-4 technique preserved
    draft_inv4 = draft_live_hunter_rule(ro_db, guide_id="hunt-inv4")
    assert draft_inv4["grounding"]["technique_id"] == "INV-4"
    assert "INV-4" in draft_inv4["suricata"]
    assert "INV-4" in draft_inv4["sigma_yaml"]
    assert "INV-4" in draft_inv4["spl"]
    assert "INV-4" in draft_inv4["yara_l"]

    # 8b: [:120] slice happens BEFORE escaping backslash so no odd trailing backslash
    draft_slash = draft_detection_rule(
        query="hunt",
        flow_record={"technique_id": "T1046", "vector": "A" * 100 + "\\" * 40},
    )
    match = re.search(r'msg:"([^"]*)";', draft_slash["suricata"])
    assert match is not None
    msg_value = match.group(1)
    trailing_slashes = len(msg_value) - len(msg_value.rstrip("\\"))
    assert trailing_slashes % 2 == 0

    # 8c: HTTP /api/v1/live/hunter/draft-rule honors explicit technique_id
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(ro_db))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        st, body = _http_post_json(
            base,
            "/api/v1/live/hunter/draft-rule",
            {"technique_id": "T1498", "query": "custom query without technique"},
        )
        assert st == 200
        assert body["grounding"]["technique_id"] == "T1498"
        assert "T1498" in body["suricata"]
    finally:
        srv.shutdown()
        srv.server_close()


# --- Item 9: 4 Fuzzing edge cases ---


def test_item9_fuzzing_bool_cidr_icmp_and_tampered_dispatch_409(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 9a: reject bool in _finite_feature_vector
    feats = dict(_canonical_features())
    feats["protocol_tcp"] = True  # type: ignore[assignment]
    vec, reason = _finite_feature_vector(feats)
    assert vec is None
    assert reason == "non_numeric_feature:protocol_tcp"

    # 9b: reject /0 CIDRs in _valid_network
    assert _valid_network("0.0.0.0/0") is False
    assert _valid_network("::/0") is False
    assert _valid_network("10.0.0.0/0") is False
    assert _valid_network("172.29.0.0/24") is True

    # 9c: portless ICMP EVE flow handled cleanly in follow_suricata_eve
    icmp_record = {
        "timestamp": "2026-11-21T00:00:00.000000+0000",
        "flow_id": 123456789,
        "event_type": "flow",
        "src_ip": "172.29.0.10",
        "dest_ip": "172.29.0.20",
        "proto": "ICMP",
        "flow": {
            "pkts_toserver": 2,
            "pkts_toclient": 2,
            "bytes_toserver": 168,
            "bytes_toclient": 168,
            "start": "2026-11-21T00:00:00.000000+0000",
            "end": "2026-11-21T00:00:01.000000+0000",
        },
    }
    cache: dict[tuple[str, str, str, int], str] = {}
    remember_alert(
        cache,
        {
            "event_type": "alert",
            "src_ip": "172.29.0.10",
            "dest_ip": "172.29.0.20",
            "proto": "ICMP",
            "alert": {"signature": "ET ICMP Ping"},
        },
    )
    payload = sensor_payload(icmp_record, cache)
    assert payload["sensor_observation"]["src_port"] == 0
    assert payload["sensor_observation"]["dst_port"] == 0
    assert payload["sensor_observation"]["proto"] == "icmp"
    assert payload["sensor_observation"]["signature"] == "ET ICMP Ping"

    # 9d: return http_status 409 on tampered ledger in dispatch_approved_callback & HTTP route
    live_db = tmp_path / "live.sqlite3"
    soar_db = tmp_path / "soar.sqlite3"
    policy_dir = tmp_path / "policy"
    attack_features = dict(_ATTACK_PROFILE_CANONICAL["T1046"])
    scored = score_canonical_flow(attack_features, repo_root=REPO_ROOT)
    assert scored["decision"] == "Attack"
    flow_id = int(persist_scored_flow(live_db, attack_features, scored)["flow_id"])
    assert enroll_lab_operator(policy_dir, "lab_operator")["identity_verified"] is True
    fp = active_fingerprint(policy_dir, "lab_operator")
    approved = approve_live_soar(
        live_db,
        soar_db,
        flow_id=flow_id,
        actor_id="lab_operator",
        reason="Analyst recorded local approval. Containment is not executed.",
        policy_dir=policy_dir,
        presented_fingerprint=fp,
    )
    assert approved["http_status"] == 200

    with sqlite3.connect(soar_db) as conn:
        conn.execute("DROP TRIGGER IF EXISTS soar_audit_events_append_only_update")
        conn.execute("UPDATE soar_audit_events SET entry_sha256 = ?", ("0" * 64,))
        conn.commit()

    dispatched = dispatch_approved_callback(
        live_db,
        soar_db,
        flow_id=flow_id,
        contract_base_url="http://127.0.0.1:9",
        hmac_secret="lab-hmac-secret-01",
        actor_id="lab_operator",
    )
    assert dispatched["reason"] == "audit_chain_invalid"
    assert dispatched["http_status"] == 409

    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(live_db))
    monkeypatch.setenv("THREATFUSION_SOAR_LEDGER_DB_PATH", str(soar_db))
    monkeypatch.setenv("THREATFUSION_SOAR_HMAC_SECRET", "lab-hmac-secret-01")
    monkeypatch.setenv("THREATFUSION_OPERATOR_POLICY_DIR", str(policy_dir))
    monkeypatch.setenv("THREATFUSION_ENV", "lab")
    token = str(
        rbac_login(
            live_db,
            username="bilal.21k3551@nu.edu.pk",
            access_code="TF-Bilal-3551!",
        )["session_token"]
    )
    srv = ThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        status, body = _http_post_json(
            base,
            "/api/v1/live/soar/dispatch",
            {"flow_id": flow_id},
            session_token=token,
        )
        assert status == 409
        assert body["reason"] == "audit_chain_invalid"
    finally:
        srv.shutdown()
        srv.server_close()
