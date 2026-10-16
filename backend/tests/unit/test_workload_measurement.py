"""Unit tests for Section 13.F Alert-Fatigue Compression & Analyst Workload Measurement Harness."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import tempfile

from threatfusion.evaluation.workload_measurement import (
    AlertFatigueCompressionReport,
    AnalystWorkloadStudyRepository,
    TriageTrialRecord,
    evaluate_alert_fatigue_compression,
)


def test_section_8_counterfactual_fusion_shield_exact_metrics() -> None:
    """Validate exact January UNSW counterfactual numbers under RF-only vs RF+AE OR-fusion."""
    report = evaluate_alert_fatigue_compression(
        raw_flow_count=100000,
        rf_alert_candidate_count=50,
        correlated_incident_count=5,
        uncorrelatable_alert_count=2,
    )
    assert isinstance(report, AlertFatigueCompressionReport)

    shield = report.counterfactual_shield
    # January Population Invariants
    assert shield.population_size == 216568
    assert shield.rf_only_true_positives == 4045
    assert shield.rf_only_false_positives == 201
    assert shield.rf_only_precision_pct == 95.266

    # Counterfactual OR-fusion Invariants
    assert shield.counterfactual_fused_true_positives == 4141  # 4045 + 96
    assert shield.counterfactual_fused_false_positives == 1775  # 201 + 1574
    assert shield.relative_attack_gain_pct == 2.373
    assert shield.false_positive_multiplier == 8.8308
    assert shield.false_positive_inflation_pct == 783.085
    assert shield.counterfactual_fused_precision_pct == 69.997
    assert shield.precision_drop_percentage_points == 25.269
    assert shield.marginal_false_positives_per_extra_attack == 16.3958
    assert (
        shield.fatigue_protection_verdict
        == "fusion_disabled_prevents_1574_false_alarms_8_83x_fp_inflation"
    )

    # Convenience properties
    assert report.rf_only_precision_pct == 95.266
    assert report.counterfactual_fused_precision_pct == 69.997
    assert report.marginal_false_positives_per_extra_attack == 16.3958
    assert (
        report.fatigue_protection_verdict
        == "fusion_disabled_prevents_1574_false_alarms_8_83x_fp_inflation"
    )


def test_queue_compression_calculations() -> None:
    """Validate Layer 1 ingestion and correlation queue reduction ratios."""
    # Scenario: 100,000 raw flows -> 100 alerts -> 8 incidents + 2 uncorrelatable
    report = evaluate_alert_fatigue_compression(
        raw_flow_count=100000,
        rf_alert_candidate_count=100,
        correlated_incident_count=8,
        uncorrelatable_alert_count=2,
    )

    q = report.queue_compression
    assert q.raw_flow_count == 100000
    assert q.rf_alert_candidate_count == 100
    assert q.correlated_incident_count == 8
    assert q.uncorrelatable_alert_count == 2
    assert q.effective_analyst_queue_size == 10
    # 1 - (100 / 100000) = 0.9990
    assert q.flow_to_alert_reduction_ratio == 0.999
    # 1 - (10 / 100) = 0.9000
    assert q.alert_to_incident_consolidation_ratio == 0.9

    d = report.to_dict()
    assert d["schema_version"] == "workload_measurement_v1"
    assert d["queue_compression"]["effective_analyst_queue_size"] == 10


def test_analyst_workload_study_repository_persistence_and_summary() -> None:
    """Validate SQLite persistence, mode 0600 file permissions, and cohort metrics."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "workload_study.sqlite3"
        repo = AnalystWorkloadStudyRepository(db_path)

        # Confirm mode 0600 permissions
        file_mode = db_path.stat().st_mode & 0o777
        assert file_mode == 0o600

        now = datetime.now(UTC).isoformat()
        # Record synthetic verification trials
        for i in range(5):
            repo.record_trial(
                TriageTrialRecord(
                    trial_id=f"syn_base_{i}",
                    study_cohort="synthetic_smoke_verification",
                    participant_id="automated_harness",
                    candidate_id=f"cand_{i}",
                    condition="baseline_raw_alert_only",
                    time_to_first_review_ms=3000,
                    time_to_disposition_ms=12000,
                    expected_disposition="Attack",
                    recorded_disposition="Attack" if i < 4 else "Normal",
                    disposition_correct=i < 4,
                    evidence_panels_viewed=("raw_hex", "argus_csv"),
                    recorded_at_utc=now,
                )
            )
            repo.record_trial(
                TriageTrialRecord(
                    trial_id=f"syn_tf_{i}",
                    study_cohort="synthetic_smoke_verification",
                    participant_id="automated_harness",
                    candidate_id=f"cand_{i}",
                    condition="threatfusion_enriched_advisory_soar",
                    time_to_first_review_ms=1000,
                    time_to_disposition_ms=4000,
                    expected_disposition="Attack",
                    recorded_disposition="Attack",
                    disposition_correct=True,
                    evidence_panels_viewed=("threat_intel", "advisory_debrief", "soar_playbook"),
                    recorded_at_utc=now,
                )
            )

        assert len(repo.list_trials()) == 10
        summary = repo.summarize_study_metrics("synthetic_smoke_verification")
        assert summary.total_trials == 10
        assert summary.baseline_trials == 5
        assert summary.threatfusion_trials == 5
        assert summary.baseline_mean_time_to_disposition_ms == 12000.0
        assert summary.threatfusion_mean_time_to_disposition_ms == 4000.0
        # Speedup: (12000 - 4000) / 12000 * 100 = 66.67%
        assert summary.speedup_pct == 66.67
        assert summary.baseline_accuracy_pct == 80.0
        assert summary.threatfusion_accuracy_pct == 100.0
        assert summary.accuracy_gain_percentage_points == 20.0
        # CRITICAL INVARIANT: Synthetic cohort can NEVER close TF-009!
        assert summary.tf_009_closure_eligible is False
        assert "cannot satisfy TF-009" in summary.notes


def test_tf_009_closure_eligibility_invariant() -> None:
    """Validate that TF-009 closure is eligible ONLY under human study conditions."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "workload_study.sqlite3"
        repo = AnalystWorkloadStudyRepository(db_path)

        now = datetime.now(UTC).isoformat()
        # Record human study with 10 trials (5 baseline, 5 threatfusion)
        for i in range(5):
            repo.record_trial(
                TriageTrialRecord(
                    trial_id=f"human_base_{i}",
                    study_cohort="human_analyst_cohort_study",
                    participant_id=f"analyst_usr_{i}",
                    candidate_id=f"cand_{i}",
                    condition="baseline_raw_alert_only",
                    time_to_first_review_ms=4000,
                    time_to_disposition_ms=15000,
                    expected_disposition="Attack",
                    recorded_disposition="Attack",
                    disposition_correct=True,
                    evidence_panels_viewed=("raw_hex",),
                    recorded_at_utc=now,
                )
            )
            repo.record_trial(
                TriageTrialRecord(
                    trial_id=f"human_tf_{i}",
                    study_cohort="human_analyst_cohort_study",
                    participant_id=f"analyst_usr_{i}",
                    candidate_id=f"cand_{i}",
                    condition="threatfusion_enriched_advisory_soar",
                    time_to_first_review_ms=1200,
                    time_to_disposition_ms=5000,
                    expected_disposition="Attack",
                    recorded_disposition="Attack",
                    disposition_correct=True,
                    evidence_panels_viewed=("advisory_debrief", "soar_playbook"),
                    recorded_at_utc=now,
                )
            )

        summary = repo.summarize_study_metrics("human_analyst_cohort_study")
        assert summary.total_trials == 10
        assert summary.baseline_trials == 5
        assert summary.threatfusion_trials == 5
        assert summary.tf_009_closure_eligible is True
