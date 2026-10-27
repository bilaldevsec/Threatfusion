"""Live console scoring, notes, copilot, drift, and n8n workbench."""

from __future__ import annotations

from pathlib import Path

import sqlite3

from threatfusion.api.live_soc_console import (
    add_analyst_note,
    answer_mitre_copilot,
    approve_live_soar,
    drift_for_stored_flows,
    list_live_campaigns,
    list_live_flows,
    persist_scored_flow,
    read_n8n_workbench,
    replay_benchmark_attack_burst,
    score_canonical_flow,
)
from threatfusion.models.drift_and_supply_chain import (
    CANONICAL_14_FEATURES,
    FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY,
)

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
    assert (
        scored["model_sha256"]
        == FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY["random_forest"]["expected_sha256"]
    )

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
    refused = add_analyst_note(
        tmp_path / "live.sqlite3", flow_id=stored["flow_id"], author_id="", note_text="x"
    )
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
        score_canonical_flow(
            _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
        ),
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


def test_campaigns_read_stored_flows_and_incident_rows(tmp_path: Path) -> None:
    empty = list_live_campaigns(
        tmp_path / "missing.sqlite3", incidents_db_path=tmp_path / "missing-incidents.sqlite3"
    )
    assert empty["evidence_state"] == "unavailable"
    assert empty["campaigns"] == []
    assert empty["incidents"] == []
    assert empty["production_fusion_enabled"] is False

    replay = replay_benchmark_attack_burst(
        tmp_path / "live.sqlite3",
        repo_root=REPO_ROOT,
        model=_Width14Model(),
        supply_verified=True,
    )
    assert replay["member_count"] == 5
    assert replay["source_label"] == "recorded_unsw_nb15"
    assert replay["fixture_origin"] == "study_triage_cases"
    assert replay["production_fusion_enabled"] is False
    assert replay["execution_authorized"] is False
    assert replay["ae_changes_alert_decision"] is False
    assert {row["rf_attack_probability"] for row in replay["flows"]} == {0.81}
    assert {row["decision"] for row in replay["flows"]} == {"Attack"}

    incidents_db = tmp_path / "incidents.sqlite3"
    with sqlite3.connect(incidents_db) as conn:
        conn.execute("""
            CREATE TABLE incidents (
                incident_id TEXT,
                window_type TEXT,
                constituent_alert_count INTEGER,
                max_probability_score REAL,
                escalated_decision TEXT,
                earliest_observed_at TEXT,
                provenance_status TEXT
            )
            """)
        conn.execute(
            """
            INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "inc_stored_01",
                "30.0s_burst",
                2,
                0.91,
                "Attack",
                "2026-10-27T00:00:00+00:00",
                "verified_entity_bearing",
            ),
        )

    listed = list_live_campaigns(tmp_path / "live.sqlite3", incidents_db_path=incidents_db)
    assert listed["evidence_state"] == "verified"
    assert listed["flow_count"] == 5
    assert listed["incident_count"] == 1
    assert listed["campaigns"][0]["member_count"] == 5
    assert listed["campaigns"][0]["source_label"] == "recorded_unsw_nb15"
    assert listed["incidents"][0]["incident_id"] == "inc_stored_01"
    assert listed["production_fusion_enabled"] is False


def test_soar_approval_writes_linked_hash_and_does_not_execute(tmp_path: Path) -> None:
    live_db = tmp_path / "live.sqlite3"
    soar_db = tmp_path / "soar.sqlite3"
    stored = persist_scored_flow(
        live_db,
        _features(),
        score_canonical_flow(
            _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
        ),
    )
    refused = approve_live_soar(
        live_db, soar_db, flow_id=stored["flow_id"], actor_id="", reason="because"
    )
    assert refused["evidence_state"] == "unavailable"
    assert refused["execution_authorized"] is False
    assert not soar_db.exists()

    approved = approve_live_soar(
        live_db,
        soar_db,
        flow_id=stored["flow_id"],
        actor_id="analyst_a",
        reason="Analyst recorded local approval. Containment is not executed.",
    )
    assert approved["evidence_state"] == "verified"
    assert approved["operator_state"] == "approved_local"
    assert approved["ledger_state"] == "approved"
    assert approved["execution_authorized"] is False
    assert approved["containment_executed"] is False
    assert approved["production_fusion_enabled"] is False
    assert len(approved["entry_sha256"]) == 64
    assert len(approved["prev_entry_sha256"]) == 64
    assert approved["entry_sha256"] != approved["prev_entry_sha256"]

    again = approve_live_soar(
        live_db,
        soar_db,
        flow_id=stored["flow_id"],
        actor_id="analyst_a",
        reason="Analyst recorded local approval. Containment is not executed.",
    )
    assert again["reason"] == "already_approved"
    assert again["entry_sha256"] == approved["entry_sha256"]
    listed = list_live_campaigns(live_db)
    stored_flow = listed["campaigns"][0]["flows"][0]
    assert stored_flow["entry_sha256"] == approved["entry_sha256"]
    assert stored_flow["audit_chain_verified"] == 1
