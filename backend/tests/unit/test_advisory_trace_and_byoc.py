"""Advisory trace, frozen-authority locks, and provider-agnostic cloud binding."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from threatfusion.advisory.advisory_trace import (
    DISPLAY_ADJUSTED,
    MEASURED_RAW,
    build_advisory_trace,
    module_has_no_write_or_network_calls,
    read_cached_narratives,
)
from threatfusion.evaluation.repo_truth_audit import (
    GATE_G9_STAGE_1_TO_4_MODULES,
    verify_gate_g9_ast_import_graph,
)
from threatfusion.models.drift_and_supply_chain import FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY
from threatfusion.models.multi_signal_risk import evaluate_multi_signal_risk

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "backend" / "src"
_PERSONAL_CLOUD_IDS = (
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "7fb77266-5bb4-4d03-8a91-a744fd38db5c",
)
_FROZEN_DIGESTS = {
    "random_forest": "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
    "logistic_regression": "2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148",
    "autoencoder_v2": "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23",
    "rate_log1p_candidate": "1d02e5bba556cb28709bd0faefce5f29da424a419a2d95332ad27a8995b26f63",
}
_DNN_DIGEST = "614850ad84fc4ab32dc6e6d2318900668d97cad6edba37290ed9fe2b2482df1f"
_NARRATIVE = (
    "[1] EXECUTIVE TRIAGE\n"
    "[2] CORRELATED TELEMETRY\n"
    "[3] MITRE ATT&CK CVE-2024-0001\n"
    "[5] GOVERNED SOAR\n"
    "[E1] [E2] [E3] [E5]"
)


def _flow(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "flow_id": 7,
        "decision": "Attack",
        "rf_attack_probability": 0.91,
        "observed_at_utc": "2026-11-14T12:00:00+00:00",
        "production_fusion_enabled": 0,
        "ae_changes_alert_decision": False,
        "case_title": "T1190 public-facing probe",
        "canonical_features": {"duration_ms": 1.0},
        "ae_loss": 0.042,
        "dnn_class_distribution": {"Normal": 0.2, "Exploits": 0.8},
        "chroma_rag_hits": [
            {"technique_id": "T1190", "cosine_similarity": 0.91, "playbook_id": "pb-t1190"}
        ],
        "cve_ids": ["CVE-2024-0001"],
    }
    record.update(overrides)
    return record


def test_g9_compliance() -> None:
    passed, violations = verify_gate_g9_ast_import_graph(SRC)
    assert passed, violations
    for relative in GATE_G9_STAGE_1_TO_4_MODULES:
        text = (SRC / relative).read_text(encoding="utf-8")
        assert "advisory_trace" not in text
        assert "from threatfusion.advisory" not in text
    trace = build_advisory_trace(_flow(), narrative=_NARRATIVE)
    assert trace["authority"]["gate_g9"] == "PASS"


def test_rf_verdict_invariance() -> None:
    flow = _flow()
    original = flow["decision"]
    trace = build_advisory_trace(flow, narrative=_NARRATIVE)
    assert flow["decision"] == original == "Attack"
    authority = trace["authority"]
    assert authority["frozen_rf_verdict"] == "Attack"
    assert authority["frozen_rf_unchanged"] is True
    assert authority["decision_writes_by_advisory_components"] == 0
    assert authority["summary"] == (
        "Decision writes by advisory components: 0, "
        "Frozen RF verdict: Attack (unchanged), Gate G9: PASS"
    )
    assert "Decision writes: 0 · Frozen RF verdict: Attack (unchanged) · Gate G9: PASS" in (
        trace["authority_bar"]
    )


def test_frozen_digests_preserved() -> None:
    for key, digest in _FROZEN_DIGESTS.items():
        assert FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY[key]["expected_sha256"] == digest
    console = (SRC / "threatfusion/api/live_soc_console.py").read_text(encoding="utf-8")
    assert _DNN_DIGEST in console
    for digest in _FROZEN_DIGESTS.values():
        assert digest in (SRC / "threatfusion/models/drift_and_supply_chain.py").read_text(
            encoding="utf-8"
        )


def test_fusion_flag_locked() -> None:
    source = (SRC / "threatfusion/models/multi_signal_risk.py").read_text(encoding="utf-8")
    assert "production_fusion_enabled=False" in source.replace(" ", "")
    with pytest.raises(ValueError):
        evaluate_multi_signal_risk(production_fusion_enabled=True)
    engine = (SRC / "threatfusion/alerts/correlation_engine.py").read_text(encoding="utf-8")
    assert "production_fusion_enabled = True" not in engine


def test_read_only(tmp_path: Path) -> None:
    source = (SRC / "threatfusion/advisory/advisory_trace.py").read_text(encoding="utf-8")
    assert module_has_no_write_or_network_calls() is True
    for token in ("subprocess", "requests", "socket", "urlopen(", "INSERT ", "DELETE FROM"):
        assert token not in source
    database = tmp_path / "live.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("""
        CREATE TABLE live_copilot_cache (
            cache_key TEXT PRIMARY KEY,
            narrative TEXT,
            created_at_utc TEXT
        )
        """)
    connection.execute(
        "INSERT INTO live_copilot_cache VALUES (?, ?, ?)",
        ("7\nquestion\nlocal", "stored narrative", "2026-11-14T12:00:00+00:00"),
    )
    connection.commit()
    connection.close()
    loaded = read_cached_narratives(database)
    assert loaded[7]["narrative"] == "stored narrative"
    check = sqlite3.connect(database)
    row = check.execute("SELECT narrative FROM live_copilot_cache").fetchone()
    assert row is not None
    assert row[0] == "stored narrative"
    check.close()
    from threatfusion.api.live_soc_console import read_advisory_trace

    missing = read_advisory_trace(tmp_path / "absent.sqlite3", flow_id=4)
    assert missing["http_status"] == 404
    assert missing["decision_writes_by_advisory_components"] == 0
    server = (ROOT / "scripts/run_misp_and_callback_contract_server.py").read_text(encoding="utf-8")
    assert 'path == "/api/v1/live/advisory-trace"' in server


def test_display_adjusted_flagged() -> None:
    flow = _flow(ae_loss=None, ae_display_band="HIGH")
    trace = build_advisory_trace(flow, narrative=_NARRATIVE)
    autoencoder = next(
        item for item in trace["components"] if item["component_id"] == "v2_autoencoder_ranker"
    )
    assert autoencoder["actual_output"] == "HIGH"
    assert autoencoder["measurement_integrity"] == DISPLAY_ADJUSTED
    assert trace["completeness_badge"] == "PARTIAL"
    assert any(DISPLAY_ADJUSTED in gap for gap in trace["completeness_gaps"])


def test_completeness_badge() -> None:
    complete = build_advisory_trace(_flow(), narrative=_NARRATIVE)
    assert complete["completeness_badge"] == "COMPLETE"
    assert complete["completeness_gaps"] == []
    for item in complete["components"]:
        assert item["assigned_scope"]
        assert item["measurement_integrity"] == MEASURED_RAW
        assert item["evidence_ids_read"]
    pending = build_advisory_trace(_flow(), narrative=None)
    assert pending["completeness_badge"] == "PENDING ADVISORY"
    narrative = next(
        item
        for item in pending["components"]
        if item["component_id"] == "grounded_narrative_copilot"
    )
    assert narrative["actual_output"] is None
    partial = build_advisory_trace(_flow(ae_loss=None, canonical_features={}), narrative=_NARRATIVE)
    assert partial["completeness_badge"] == "PARTIAL"
    assert any("missing assigned_scope" in gap for gap in partial["completeness_gaps"])
    assert any("missing actual_output" in gap for gap in partial["completeness_gaps"])


def test_no_hardcoded_personal_cloud_ids() -> None:
    offenders: list[str] = []
    for base in (ROOT / "frontend", ROOT / "backend" / "src", ROOT / "scripts"):
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for needle in _PERSONAL_CLOUD_IDS:
                if needle in text:
                    offenders.append(f"{path}: {needle}")
    assert offenders == []
    cloud = (ROOT / "scripts/deploy_cloud_range.sh").read_text(encoding="utf-8")
    azure = (ROOT / "scripts/deploy_azure_cyber_range.sh").read_text(encoding="utf-8")
    assert "--provider" in cloud
    assert "--provision-range" in cloud
    assert "--deploy-full-stack" in cloud
    assert "--teardown" in cloud
    assert "deploy_cloud_range.sh" in azure
    assert "TF_AZURE_RANGE_IMPL" in azure


def test_cloud_status_reads_operator_state(tmp_path: Path) -> None:
    from threatfusion.api.live_soc_console import azure_portal_status, cloud_range_status

    path = tmp_path / "cloud_state.json"
    path.write_text(
        """
        {
          "provider": "generic",
          "account_id": "operator-account",
          "region": "lab",
          "resource_group": "generic-linux-hosts",
          "victim_public_ip": "203.0.113.20",
          "attacker_public_ip": "203.0.113.10",
          "victim_vm_ip": "172.29.0.20",
          "attacker_vm_ip": "172.29.0.10",
          "ssh_user": "ubuntu",
          "victim_state": "recorded",
          "attacker_state": "recorded",
          "cost_guardrail": "teardown returns spend to 0.00"
        }
        """,
        encoding="utf-8",
    )
    status = cloud_range_status(path)
    assert status["provider_label"] == "Generic"
    assert status["connected"] is True
    assert status["account_id"] == "operator-account"
    assert status["victim_host"]["public_ip"] == "203.0.113.20"
    assert status["ssh_user"] == "ubuntu"
    assert "72f988bf" not in str(status)
    azure = azure_portal_status(path)
    assert azure["terminal_snippet"] == "scripts/deploy_azure_cyber_range.sh --provision-live-azure"
    assert azure["connected"] is False
