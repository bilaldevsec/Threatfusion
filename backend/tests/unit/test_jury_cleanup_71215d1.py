"""Regressions for the six remaining jury findings on 71215d1."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from threatfusion.api.live_soc_console import (
    _record_console_callback_receipt,
    approve_live_soar,
    assemble_live_workbench,
    build_alert_fatigue_compression_funnel,
    dispatch_approved_callback,
    enroll_lab_operator,
    persist_scored_flow,
    score_canonical_flow,
)
from threatfusion.models.drift_and_supply_chain import (
    CANONICAL_14_FEATURES,
    DEFAULT_BASELINE_MEANS,
    DEFAULT_BASELINE_STDS,
    evaluate_14_feature_telemetry_drift,
)
from threatfusion.operations.commercial_hardening import ensure_hmac_secret
from threatfusion.operations.human_credentials import active_fingerprint

ROOT = Path(__file__).resolve().parents[3]


class _Width14Model:
    n_features_in_ = 14

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        return [[0.2, 0.81]]


def _features() -> dict[str, float]:
    return {name: 1.0 for name in CANONICAL_14_FEATURES}


def _store_flow(live_db: Path) -> int:
    stored = persist_scored_flow(
        live_db,
        _features(),
        score_canonical_flow(
            _features(),
            repo_root=ROOT,
            model=_Width14Model(),
            supply_verified=True,
        ),
    )
    return int(stored["flow_id"])


def test_invalid_audit_chain_returns_before_the_webhook(tmp_path: Path, monkeypatch) -> None:
    calls = {"count": 0}

    def _refuse_webhook(*_args, **_kwargs):
        calls["count"] += 1
        raise AssertionError("webhook invoked after an invalid audit chain")

    monkeypatch.setattr(
        "threatfusion.api.live_soc_console._dispatch_through_live_n8n",
        _refuse_webhook,
    )
    live_db = tmp_path / "live.sqlite3"
    soar_db = tmp_path / "soar.sqlite3"
    flow_id = _store_flow(live_db)
    policy = tmp_path / "operator-policy"
    assert enroll_lab_operator(policy, "lab_operator")["identity_verified"] is True
    approve_live_soar(
        live_db,
        soar_db,
        flow_id=flow_id,
        actor_id="lab_operator",
        reason="Analyst recorded local approval. Containment is not executed.",
        policy_dir=policy,
        presented_fingerprint=active_fingerprint(policy, "lab_operator"),
    )
    with sqlite3.connect(soar_db) as conn:
        conn.execute("DROP TRIGGER IF EXISTS soar_audit_events_append_only_update")
        conn.execute("UPDATE soar_audit_events SET entry_sha256 = ?", ("0" * 64,))
    result = dispatch_approved_callback(
        live_db,
        soar_db,
        flow_id=flow_id,
        contract_base_url="http://127.0.0.1:9",
        hmac_secret="lab-hmac-secret-01",
        n8n_webhook_url="http://127.0.0.1:9/hook",
        actor_id="lab_operator",
    )
    assert result["reason"] == "audit_chain_invalid"
    assert result["evidence_state"] == "unavailable"
    assert result["callback_recorded"] is False
    assert calls["count"] == 0


def test_console_callback_receipt_stays_unavailable_without_measured_mttr(tmp_path: Path) -> None:
    live_db = tmp_path / "live.sqlite3"
    flow_id = _store_flow(live_db)
    with sqlite3.connect(live_db) as conn:
        conn.row_factory = sqlite3.Row
        flow = conn.execute("SELECT * FROM live_flows WHERE flow_id = ?", (flow_id,)).fetchone()
    assert flow is not None
    result = _record_console_callback_receipt(
        live_db,
        flow,
        SimpleNamespace(playbook_id="pb-console", actor_id="lab_operator"),
        flow_id=flow_id,
        candidate_id=f"live_flow:{flow_id}",
        secret="lab-hmac-secret-01",
    )
    encoded = json.dumps(result)
    assert result["evidence_state"] == "unavailable"
    assert result["callback_verified"] is False
    assert result["mttr_seconds"] == 0.0
    assert result["receipt_covers_stored_bytes"] is False
    assert "0.42" not in encoded
    with sqlite3.connect(live_db) as conn:
        stored = conn.execute(
            "SELECT mttr_seconds FROM live_flows WHERE flow_id = ?",
            (flow_id,),
        ).fetchone()
    assert stored is not None
    assert stored[0] == 0.0


def test_empty_workbench_is_unavailable(tmp_path: Path) -> None:
    missing = tmp_path / "missing.sqlite3"
    workflow = ROOT / "docker" / "n8n" / "workflows" / "threatfusion_live_console_playbook.json"
    funnel = build_alert_fatigue_compression_funnel(missing)
    empty = assemble_live_workbench(missing, workflow, funnel)
    assert empty["evidence_state"] == "unavailable"
    assert empty["evidence_state"] != "verified"
    live_db = tmp_path / "live.sqlite3"
    _store_flow(live_db)
    with sqlite3.connect(live_db) as conn:
        conn.execute("DELETE FROM live_flows")
    cleared = assemble_live_workbench(
        live_db,
        workflow,
        build_alert_fatigue_compression_funnel(live_db),
    )
    assert cleared["evidence_state"] == "unavailable"


def test_psi_requires_two_records_and_a_positive_baseline_std() -> None:
    extreme = {
        name: DEFAULT_BASELINE_MEANS[name] + 3.0 * DEFAULT_BASELINE_STDS[name]
        for name in CANONICAL_14_FEATURES
    }
    single = evaluate_14_feature_telemetry_drift([extreme])
    assert single.record_count == 1
    assert single.drift_status != "severe_out_of_distribution_drift_retraining_review_required"
    assert "severe_out_of_distribution" not in single.drift_status
    zero = {name: 0.0 for name in CANONICAL_14_FEATURES}
    undefined = evaluate_14_feature_telemetry_drift([extreme, extreme], baseline_stds=zero)
    assert undefined.drift_status == "undefined_baseline"
    for metric in undefined.feature_metrics.values():
        assert metric.psi is None
        assert metric.baseline_std == 0.0
        assert metric.drift_category == "undefined_baseline"
        assert metric.baseline_std != pytest.approx(1e-6)


def test_urgent_chip_and_cti_evidence_follow_stored_rows() -> None:
    script = ROOT / "frontend" / "js" / "soc_dashboard.js"
    index = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    css = (ROOT / "frontend" / "css" / "soc_unicorn.css").read_text(encoding="utf-8")
    assert 'data-cvss-source="static_table"' in index
    assert "@media (max-width: 768px)" in index
    assert "@media (max-width: 768px)" in css
    assert "grid-template-columns: minmax(0, 1fr)" in css
    assert "#operatorAuthBadge" in css
    assert "http://" not in index
    assert "https://" not in index
    probe = r"""
const fs = require('fs');
global.window = global;
global.document = {
  readyState: 'loading',
  querySelector() { return null; },
  addEventListener() {},
  getElementById() { return null; }
};
global.Headers = class Headers { constructor() {} set() {} };
global.fetch = async () => ({ ok: false, json: async () => ({}) });
eval(fs.readFileSync(process.argv[1], 'utf8'));
const api = global.ThreatFusionDashboard;
const rows = [
  { decision: 'Attack', sourceLabel: 'suricata_bridge', flowId: 1, id: 'live_flow:1' },
  { decision: 'Attack', sourceLabel: 'incident_store', rowKind: 'soar_approval_receipt', flowId: 1 },
  { decision: 'Benign', sourceLabel: 'suricata_bridge', flowId: 2, id: 'live_flow:2' },
  { decision: 'Attack', schema_version: 'live_soar_callback_v1', id: 'callback_receipt:9' }
];
if (api.countUrgentRfAttackFlows(rows) !== 1) process.exit(2);
const noIp = api.ctiPresentation({
  tactical_ttps: ['T1046'],
  operational_iocs: { ips: ['dataset_flow#8 (/)'] }
});
if (noIp.cvss_source !== 'static_table' || noIp.evidence_state !== 'unavailable') process.exit(3);
const stored = api.ctiPresentation({
  tactical_ttps: ['T1046'],
  operational_iocs: { ips: ['172.29.0.10'] }
});
if (stored.cvss_source !== 'static_table' || stored.evidence_state !== 'verified') process.exit(4);
"""
    completed = subprocess.run(
        ["node", "-e", probe, str(script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_forwarder_heredoc_is_quoted_and_expands_locally() -> None:
    script = ROOT / "scripts" / "deploy_azure_cyber_range.sh"
    text = script.read_text(encoding="utf-8")
    assert "<<'ENV'" in text
    assert "<<ENV\n" not in text
    completed = subprocess.run(
        [
            "bash",
            "-c",
            """
            set -euo pipefail
            eval "$(sed -n '/^render_forwarder_env()/,/^}/p' "$1")"
            render_forwarder_env 'https://console.example/soc' 'tok en' 'hmac secret'
            """,
            "bash",
            str(script),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = completed.stdout
    assert "THREATFUSION_CONSOLE_URL=https://console.example/soc" in rendered
    assert "THREATFUSION_SENSOR_INGEST_TOKEN=tok en" in rendered
    assert "THREATFUSION_SOAR_HMAC_SECRET=hmac secret" in rendered
    assert "TFQ0CONSOLE" not in rendered


def test_ensure_hmac_secret_rejects_symlink_before_chmod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "real-secret"
    target.write_text("kept-secret\n", encoding="utf-8")
    os.chmod(target, 0o644)
    data = tmp_path / "data"
    data.mkdir()
    link = data / ".hmac_secret"
    link.symlink_to(target)
    monkeypatch.setenv("THREATFUSION_SOAR_HMAC_SECRET", "lab-hmac-secret-01")
    with pytest.raises(OSError, match="symlink"):
        ensure_hmac_secret(data)
    assert target.read_text(encoding="utf-8") == "kept-secret\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    monkeypatch.delenv("THREATFUSION_SOAR_HMAC_SECRET", raising=False)
    with pytest.raises(OSError, match="symlink"):
        ensure_hmac_secret(data)
    assert target.read_text(encoding="utf-8") == "kept-secret\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
