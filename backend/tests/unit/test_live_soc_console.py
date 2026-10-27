"""Live console scoring, notes, copilot, drift, and n8n workbench."""

from __future__ import annotations

from pathlib import Path

from threatfusion.api.live_soc_console import (
    add_analyst_note,
    answer_mitre_copilot,
    drift_for_stored_flows,
    list_live_flows,
    persist_scored_flow,
    read_n8n_workbench,
    score_canonical_flow,
)
from threatfusion.models.drift_and_supply_chain import CANONICAL_14_FEATURES, FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY

REPO_ROOT = Path(__file__).resolve().parents[3]


def _features(**overrides: float) -> dict[str, float]:
    values = {name: 1.0 for name in CANONICAL_14_FEATURES}
    values.update(overrides)
    return values


class _Width14Model:
    n_features_in_ = 14

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        return [[0.2, 0.81]]


class _WideModel:
    n_features_in_ = 49

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        raise AssertionError("mismatched feature width must not be scored")


def test_score_uses_injected_forest_and_refuses_width_mismatch() -> None:
    scored = score_canonical_flow(
        _features(),
        repo_root=REPO_ROOT,
        model=_Width14Model(),
        supply_verified=True,
    )
    assert scored["decision"] == "Attack"
    assert scored["rf_attack_probability"] == 0.81
    assert scored["evidence_state"] == "verified"
    assert scored["production_fusion_enabled"] is False
    assert scored["ae_changes_alert_decision"] is False
    assert scored["model_sha256"] == FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY["random_forest"]["expected_sha256"]

    mismatched = score_canonical_flow(
        _features(),
        repo_root=REPO_ROOT,
        model=_WideModel(),
        supply_verified=True,
    )
    assert mismatched["decision"] == "withheld"
    assert mismatched["reason"] == "feature_contract_mismatch"
    assert mismatched["rf_attack_probability"] is None


def test_missing_feature_is_withheld_and_notes_round_trip(tmp_path: Path) -> None:
    incomplete = score_canonical_flow({}, repo_root=REPO_ROOT, supply_verified=True)
    assert incomplete["decision"] == "withheld"
    assert incomplete["reason"].startswith("missing_feature:")
    stored = persist_scored_flow(tmp_path / "live.sqlite3", _features(), incomplete)
    rows = list_live_flows(tmp_path / "live.sqlite3")
    assert rows[0]["flow_id"] == stored["flow_id"]
    assert rows[0]["decision"] == "withheld"
    refused = add_analyst_note(tmp_path / "live.sqlite3", flow_id=stored["flow_id"], author_id="", note_text="x")
    assert refused["evidence_state"] == "unavailable"
    saved = add_analyst_note(
        tmp_path / "live.sqlite3",
        flow_id=stored["flow_id"],
        author_id="analyst_a",
        note_text="Reviewed the withheld score.",
    )
    assert saved["evidence_state"] == "verified"


def test_copilot_refuses_containment_and_drift_reads_rows(tmp_path: Path) -> None:
    refused = answer_mitre_copilot("please isolate the host", tmp_path / "rag.sqlite3")
    assert refused["execution_authorized"] is False
    assert refused["reason"] == "containment_refused"
    assert refused["hits"] == []
    answered = answer_mitre_copilot("command and control beacon", tmp_path / "rag.sqlite3")
    assert answered["execution_authorized"] is False
    assert answered["hits"]
    assert answered["hits"][0]["technique_id"].startswith("T")

    empty = drift_for_stored_flows(tmp_path / "missing.sqlite3")
    assert empty["evidence_state"] == "unavailable"
    persist_scored_flow(
        tmp_path / "live.sqlite3",
        _features(),
        score_canonical_flow(_features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True),
    )
    drift = drift_for_stored_flows(tmp_path / "live.sqlite3")
    assert drift["evidence_state"] == "verified"
    assert drift["changes_model_weights"] is False


def test_workbench_lists_six_nodes_without_dispatch() -> None:
    report = read_n8n_workbench(
        REPO_ROOT / "docker" / "n8n" / "workflows" / "threatfusion_soar_playbook.json"
    )
    assert report["node_count"] == 6
    assert report["execution_authorized"] is False
    assert report["evidence_state"] == "verified"
