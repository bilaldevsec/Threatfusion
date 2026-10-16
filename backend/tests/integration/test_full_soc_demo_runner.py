"""Integration test for Turnkey Two-Track Jury & Supervisor Demonstration Runner."""

from __future__ import annotations

import json
from pathlib import Path

from threatfusion.operations.full_soc_demo import (
    DEMO_SCHEMA_VERSION,
    REGISTERED_UNSW_MEMBER_SHA256,
    run_full_soc_demo,
)


def test_full_soc_demo_runner_end_to_end(tmp_path: Path) -> None:
    """Execute run_full_soc_demo(tmp_path) end-to-end and assert all invariants."""
    report = run_full_soc_demo(tmp_path)

    # 1. Top-Level Metadata Invariants
    assert report["schema_version"] == DEMO_SCHEMA_VERSION
    assert report["project_id"] == "AI-FYP-2006"
    assert "ThreatFusion" in report["project_title"]
    assert report["evaluation_checkpoint_commit"] == "6a36dcd9af17bf509977bcf966f2ace72644d5b2"
    assert report["supervisor"] == "Sir Sameer Faisal"
    assert len(report["team_members"]) == 3

    # 2. Track A Invariants
    track_a = report["track_a_unsw_replay"]
    assert track_a["status"] == "completed"
    assert track_a["dataset_member_sha256"] == REGISTERED_UNSW_MEMBER_SHA256
    assert len(track_a["rows_evaluated"]) == 2

    # Row 1: Normal -> No alert
    row_1 = track_a["rows_evaluated"][0]
    assert row_1["row_number"] == 1
    assert row_1["ground_truth"] == "Normal"
    assert row_1["predicted_class"] == "Normal"
    assert row_1["disposition"] == "recorded_without_alert"
    assert row_1["alert_candidate_id"] is None
    assert row_1["attack_probability"] < 0.50

    # Row 21: Attack -> 1 AlertCandidate
    row_21 = track_a["rows_evaluated"][1]
    assert row_21["row_number"] == 21
    assert row_21["ground_truth"] == "Attack"
    assert row_21["predicted_class"] == "Attack"
    assert row_21["disposition"] == "alert_created"
    assert row_21["alert_candidate_id"] is not None
    assert row_21["attack_probability"] >= 0.50

    # Track A Correlation & Enrichment Failure-Closed Invariants
    assert track_a["correlation_disposition"] == "uncorrelatable_missing_entity"
    assert track_a["enrichment_disposition"] == "skipped_unverified_provenance"

    # Track A Section 8 Shield Invariants
    shield = track_a["section_8_counterfactual_shield"]
    assert shield["rf_only_precision_pct"] == 95.266
    assert shield["counterfactual_fused_precision_pct"] == 69.997
    assert shield["false_positive_multiplier"] == 8.8308
    assert shield["marginal_false_positives_per_extra_attack"] == 16.3958
    assert (
        shield["fatigue_protection_verdict"]
        == "fusion_disabled_prevents_1574_false_alarms_8_83x_fp_inflation"
    )

    # 3. Track B Invariants
    track_b = report["track_b_azure_live_spine"]
    assert track_b["status"] == "completed"
    assert track_b["sensor_id"] == "azure-suricata-edge-01"
    assert track_b["source_ip"] == "10.0.0.4"
    assert track_b["destination_ip"] == "10.0.0.5"
    assert track_b["raw_features_extracted"] == 14
    assert track_b["rf_decision"] == "Attack"
    assert track_b["rf_attack_probability"] >= 0.50
    assert track_b["alert_candidate_id"] is not None
    assert track_b["incident_id"] is not None
    assert track_b["threat_intel_status"] == "internal_lab_entity_annotated"
    assert track_b["private_ip_guard_triggered"] is True
    assert track_b["external_lookup_performed"] is False
    assert track_b["lab_annotations"]["10.0.0.4"] == "azure_lab_attacker_vm_slide14"
    assert track_b["lab_annotations"]["10.0.0.5"] == "azure_lab_victim_suricata_vm_slide14"

    # Advisory Explanation
    expl = track_b["advisory_explanation"]
    assert expl["advisory_only_non_authoritative"] is True
    assert expl["groundedness_verified"] is True

    # Reversible SOAR Ledger Invariants
    soar = track_b["soar_playbook"]
    assert soar["final_state"] == "rolled_back"
    assert soar["audit_trail_events"] >= 4

    # Workload Study Invariant (TF-009 Protection)
    summary = track_b["workload_study_summary"]
    assert summary["study_cohort"] == "synthetic_smoke_verification"
    assert summary["tf_009_closure_eligible"] is False
    assert summary["speedup_pct"] > 0.0

    # 4. Artifact File Generation Invariants
    json_path = tmp_path / "full_soc_demo_report.json"
    md_path = tmp_path / "full_soc_demo_report.md"

    assert json_path.exists()
    assert md_path.exists()

    loaded_json = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded_json["schema_version"] == DEMO_SCHEMA_VERSION
    assert loaded_json["project_id"] == "AI-FYP-2006"

    md_text = md_path.read_text(encoding="utf-8")
    assert "ThreatFusion Turnkey SOC Demonstration Report" in md_text
    assert "AI-FYP-2006" in md_text
    assert "16.4:1 benign false alarm penalty" in md_text
    assert "pending_approval" in md_text
    assert "rolled_back" in md_text
