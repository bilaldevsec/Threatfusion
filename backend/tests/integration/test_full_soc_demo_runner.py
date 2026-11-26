"""Integration test for Turnkey Two-Track Jury & Supervisor Demonstration Runner."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from threatfusion.models.network_inference import UnswNetworkInferenceBoundary
from threatfusion.operations.full_soc_demo import (
    DEMO_SCHEMA_VERSION,
    REGISTERED_UNSW_MEMBER_SHA256,
    run_full_soc_demo,
)

_SYNTHETIC_RAW_NAMES = tuple(
    "srcip sport dstip dsport proto state dur sbytes dbytes sttl dttl sloss dloss service "
    "sload dload spkts dpkts swin dwin stcpb dtcpb smeansz dmeansz trans_depth res_bdy_len "
    "sjit djit stime ltime sintpkt dintpkt tcprtt synack ackdat is_sm_ips_ports ct_state_ttl "
    "ct_flw_http_mthd is_ftp_login ct_ftp_cmd ct_srv_src ct_srv_dst ct_dst_ltm ct_src_ltm "
    "ct_src_dport_ltm ct_dst_sport_ltm ct_dst_src_ltm attack_cat label".split()
)


def _synthetic_unsw_row(**updates: str) -> list[str]:
    values = dict.fromkeys(_SYNTHETIC_RAW_NAMES, "0")
    values.update(
        srcip="192.0.2.1",
        dstip="198.51.100.2",
        sport="54322",
        dsport="53",
        proto="udp",
        dur="0.001",
        sbytes="146",
        dbytes="178",
        spkts="2",
        dpkts="2",
        stime="1421928000",
        ltime="1421928001",
        attack_cat="",
        label="0",
    )
    values.update(updates)
    return [values[name] for name in _SYNTHETIC_RAW_NAMES]


def _assert_full_soc_demo_report(report: dict[str, object], out_dir: Path) -> None:
    """Assert end-to-end invariants for both official and synthetic UNSW runs."""
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
    json_path = out_dir / "full_soc_demo_report.json"
    md_path = out_dir / "full_soc_demo_report.md"

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


def test_full_soc_demo_runner_end_to_end(tmp_path: Path) -> None:
    """Execute run_full_soc_demo(tmp_path) end-to-end and assert all invariants."""
    official = Path(__file__).resolve().parents[3] / "data" / "raw" / "unsw_nb15" / "official"
    if any(not (official / f"UNSW-NB15_{number}.csv").is_file() for number in range(1, 5)):
        pytest.skip("raw UNSW-NB15 CSV files not present in this checkout")
    report = run_full_soc_demo(tmp_path)
    _assert_full_soc_demo_report(report, tmp_path)


def test_full_soc_demo_runner_with_synthetic_unsw_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise run_full_soc_demo end-to-end without requiring gitignored raw CSVs."""
    synthetic_csv = tmp_path / "synthetic_UNSW-NB15_1.csv"
    normal_row = _synthetic_unsw_row(
        proto="udp",
        dsport="53",
        dur="0.001",
        spkts="2",
        dpkts="2",
        sbytes="146",
        dbytes="178",
        label="0",
    )
    attack_row = _synthetic_unsw_row(
        proto="udp",
        dsport="53",
        dur="0.00001",
        spkts="2",
        dpkts="0",
        sbytes="114",
        dbytes="0",
        attack_cat="Generic",
        label="1",
    )
    with synthetic_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        for row_num in range(1, 22):
            writer.writerow(attack_row if row_num == 21 else normal_row)

    synthetic_sha256 = hashlib.sha256(synthetic_csv.read_bytes()).hexdigest()

    def _load_synthetic_row(
        _self: UnswNetworkInferenceBoundary, member: object, row_number: int
    ) -> list[str]:
        assert getattr(member, "sha256", None) == REGISTERED_UNSW_MEMBER_SHA256
        payload = synthetic_csv.read_bytes()
        assert hashlib.sha256(payload).hexdigest() == synthetic_sha256
        rows = list(csv.reader(payload.decode("utf-8").splitlines()))
        assert len(rows) == 21
        return rows[row_number - 1]

    monkeypatch.setattr(UnswNetworkInferenceBoundary, "_registered_row", _load_synthetic_row)
    for env_key in (
        "THREATFUSION_MISP_URL",
        "THREATFUSION_N8N_WEBHOOK_URL",
        "THREATFUSION_THEHIVE_URL",
    ):
        monkeypatch.delenv(env_key, raising=False)

    out_dir = tmp_path / "demo_out"
    report = run_full_soc_demo(out_dir)
    _assert_full_soc_demo_report(report, out_dir)
