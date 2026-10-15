"""Unit tests for missing-data aware multi-signal risk policy and RF/AE ablation evaluator."""

from __future__ import annotations

import math

import pytest

from threatfusion.models.multi_signal_risk import (
    CANONICAL_SIGNAL_SLOTS,
    DEFAULT_SIGNAL_WEIGHTS,
    DETECTOR_ABLATION_REPORT_SCHEMA_VERSION,
    DYNAMIC_RISK_ASSESSMENT_SCHEMA_VERSION,
    MultiSignalRiskError,
    SIGNAL_STATUS_AVAILABLE,
    SIGNAL_STATUS_UNAVAILABLE,
    SignalObservation,
    compute_dynamic_risk_score,
    evaluate_detector_ablation,
)


class TestDynamicRiskScore:
    """Test multi-signal risk calculation and missing-data invariant."""

    def test_missing_data_invariance_single_signal(self) -> None:
        """Prove that when supervised_rf=0.90 and 6 optional signals are UNAVAILABLE,

        D == 90.0 (not 27.0), and unavailable_signals lists all 6 with exact reasons.
        """
        reasons = {
            "autoencoder_v2_reconstruction": "experimental_unfused_gate",
            "isolation_forest_outlier": "service_offline",
            "ueba_behavioral_deviation": "source_modality_unsupported",
            "threat_intel_ioc": "misp_enrichment_disabled",
            "payload_entropy": "packet_truncation",
            "periodic_beaconing": "insufficient_flow_window",
        }

        observations = [
            SignalObservation(
                slot="supervised_rf",
                status=SIGNAL_STATUS_AVAILABLE,
                score=0.90,
            )
        ]
        for slot, reason in reasons.items():
            observations.append(
                SignalObservation(
                    slot=slot,
                    status=SIGNAL_STATUS_UNAVAILABLE,
                    reason=reason,
                )
            )

        assessment = compute_dynamic_risk_score(observations)

        assert assessment.schema_version == DYNAMIC_RISK_ASSESSMENT_SCHEMA_VERSION
        # Crucial invariant: D must be 90.0, NOT diluted by the absent 0.70 weight to 27.0!
        assert math.isclose(assessment.dynamic_risk_score, 90.0, abs_tol=1e-3)
        assert assessment.severity_level == "critical"
        assert math.isclose(
            assessment.effective_weight_denominator,
            DEFAULT_SIGNAL_WEIGHTS["supervised_rf"],
            abs_tol=1e-5,
        )

        assert len(assessment.available_signals) == 1
        assert "supervised_rf" in assessment.available_signals
        assert assessment.available_signals["supervised_rf"]["score"] == 0.90
        assert assessment.available_signals["supervised_rf"]["normalized_contribution"] == 90.0

        assert len(assessment.unavailable_signals) == 6
        for slot, expected_reason in reasons.items():
            assert slot in assessment.unavailable_signals
            assert assessment.unavailable_signals[slot]["reason"] == expected_reason
            assert math.isclose(
                assessment.unavailable_signals[slot]["nominal_weight"],
                DEFAULT_SIGNAL_WEIGHTS[slot],
                abs_tol=1e-5,
            )

    def test_multi_signal_partial_availability(self) -> None:
        """Test calculation with multiple available signals and omitted slots."""
        # Provide 2 signals; other 5 will default to UNAVAILABLE (omitted_from_input)
        obs = {
            "supervised_rf": {"status": "AVAILABLE", "score": 0.80},
            "threat_intel_ioc": {"status": "AVAILABLE", "score": 1.00},
        }
        assessment = compute_dynamic_risk_score(obs)

        # Expected:
        # supervised_rf weight: 0.30, threat_intel_ioc weight: 0.15
        # Total effective weight = 0.45
        # Weighted sum = 0.30 * 0.80 + 0.15 * 1.00 = 0.24 + 0.15 = 0.39
        # Dynamic risk score = 100.0 * (0.39 / 0.45) = 86.6667
        assert math.isclose(assessment.dynamic_risk_score, 86.6667, abs_tol=1e-3)
        assert assessment.severity_level == "critical"
        assert math.isclose(assessment.effective_weight_denominator, 0.45, abs_tol=1e-5)
        assert len(assessment.unavailable_signals) == 5

    def test_all_signals_available(self) -> None:
        """Test calculation with all 7 canonical signals available."""
        obs = {slot: 0.50 for slot in CANONICAL_SIGNAL_SLOTS}
        assessment = compute_dynamic_risk_score(obs)
        assert math.isclose(assessment.dynamic_risk_score, 50.0, abs_tol=1e-3)
        assert assessment.severity_level == "medium"
        assert math.isclose(assessment.effective_weight_denominator, 1.0, abs_tol=1e-5)
        assert len(assessment.unavailable_signals) == 0

    def test_severity_levels(self) -> None:
        """Test critical, high, medium, and low severity classifications."""
        assert compute_dynamic_risk_score({"supervised_rf": 0.90}).severity_level == "critical"
        assert compute_dynamic_risk_score({"supervised_rf": 0.70}).severity_level == "high"
        assert compute_dynamic_risk_score({"supervised_rf": 0.50}).severity_level == "medium"
        assert compute_dynamic_risk_score({"supervised_rf": 0.20}).severity_level == "low"

    def test_custom_weights(self) -> None:
        """Test using custom weights."""
        custom = {
            "supervised_rf": 2.0,
            "threat_intel_ioc": 1.0,
        }
        obs = {
            "supervised_rf": 0.60,
            "threat_intel_ioc": 0.90,
        }
        assessment = compute_dynamic_risk_score(obs, custom_weights=custom)
        # Denominator = 3.0, Weighted sum = 2.0*0.60 + 1.0*0.90 = 2.10
        # Score = 100 * (2.1 / 3.0) = 70.0
        assert math.isclose(assessment.dynamic_risk_score, 70.0, abs_tol=1e-3)
        assert assessment.severity_level == "high"

    def test_fail_closed_empty_available_set(self) -> None:
        """All signals unavailable fails closed."""
        obs = [
            SignalObservation(
                slot=slot,
                status=SIGNAL_STATUS_UNAVAILABLE,
                reason="disabled",
            )
            for slot in CANONICAL_SIGNAL_SLOTS
        ]
        with pytest.raises(MultiSignalRiskError) as exc_info:
            compute_dynamic_risk_score(obs)
        assert exc_info.value.code == "empty_available_signal_set"

    def test_fail_closed_score_out_of_bounds(self) -> None:
        """Out of bounds score (< 0.0 or > 1.0) raises error."""
        with pytest.raises(MultiSignalRiskError) as exc_info:
            SignalObservation(slot="supervised_rf", status="AVAILABLE", score=1.2)
        assert exc_info.value.code == "signal_score_out_of_bounds"

        with pytest.raises(MultiSignalRiskError) as exc_info:
            SignalObservation(slot="supervised_rf", status="AVAILABLE", score=-0.1)
        assert exc_info.value.code == "signal_score_out_of_bounds"

    def test_fail_closed_score_nan(self) -> None:
        """NaN or Inf score raises error."""
        with pytest.raises(MultiSignalRiskError) as exc_info:
            SignalObservation(slot="supervised_rf", status="AVAILABLE", score=float("nan"))
        assert exc_info.value.code == "signal_score_nan"

        with pytest.raises(MultiSignalRiskError) as exc_info:
            SignalObservation(slot="supervised_rf", status="AVAILABLE", score=float("inf"))
        assert exc_info.value.code == "signal_score_nan"

    def test_fail_closed_unavailable_missing_reason(self) -> None:
        """Unavailable signal without reason raises error."""
        with pytest.raises(MultiSignalRiskError) as exc_info:
            SignalObservation(slot="supervised_rf", status="UNAVAILABLE", reason="")
        assert exc_info.value.code == "missing_unavailability_reason"

    def test_fail_closed_unavailable_with_score(self) -> None:
        """Unavailable signal with score raises error."""
        with pytest.raises(MultiSignalRiskError) as exc_info:
            SignalObservation(
                slot="supervised_rf", status="UNAVAILABLE", score=0.5, reason="offline"
            )
        assert exc_info.value.code == "unavailable_signal_must_not_have_score"

    def test_fail_closed_unknown_slot(self) -> None:
        """Unknown signal slot raises error."""
        with pytest.raises(MultiSignalRiskError) as exc_info:
            compute_dynamic_risk_score({"unknown_slot_xyz": 0.5})
        assert exc_info.value.code == "unknown_signal_slot"

    def test_fail_closed_invalid_weight(self) -> None:
        """Invalid weight raises error."""
        with pytest.raises(MultiSignalRiskError) as exc_info:
            compute_dynamic_risk_score(
                {"supervised_rf": 0.5}, custom_weights={"supervised_rf": 0.0}
            )
        assert exc_info.value.code == "invalid_signal_weight"

        with pytest.raises(MultiSignalRiskError) as exc_info:
            compute_dynamic_risk_score(
                {"supervised_rf": 0.5},
                custom_weights={"supervised_rf": float("nan")},
            )
        assert exc_info.value.code == "invalid_signal_weight"


class TestDetectorAblation:
    """Test RF vs RF+AE detector ablation metrics and promotion gates."""

    def test_ablation_metrics_computation(self) -> None:
        """Verify precision, recall, f1, pr_auc, and false alert burden."""
        y_true = [1, 1, 1, 1, 0, 0, 0, 0, 0, 0]
        # Baseline: 3 TP, 1 FN, 1 FP, 5 TN
        base_preds = [1, 1, 1, 0, 1, 0, 0, 0, 0, 0]
        # Candidate matches baseline
        cand_preds = [1, 1, 1, 0, 1, 0, 0, 0, 0, 0]

        report = evaluate_detector_ablation(
            y_true=y_true,
            baseline_preds=base_preds,
            candidate_preds=cand_preds,
            baseline_name="frozen_rf",
            candidate_name="cand_rf",
        )

        assert report.schema_version == DETECTOR_ABLATION_REPORT_SCHEMA_VERSION
        assert report.sample_count == 10
        assert report.baseline.tp == 3
        assert report.baseline.fn == 1
        assert report.baseline.fp == 1
        assert report.baseline.tn == 5
        assert math.isclose(report.baseline.precision, 3 / 4, abs_tol=1e-5)
        assert math.isclose(report.baseline.recall, 3 / 4, abs_tol=1e-5)
        # False alert burden per 1000 benign records: 1000 * 1 / 6 = 166.6667
        assert math.isclose(report.baseline.false_alert_burden_per_1000, 166.6667, abs_tol=1e-3)
        assert report.verdict == "approved_baseline"

    def test_ablation_rejection_recall_drop(self) -> None:
        """Candidate that drops recall is rejected as regression."""
        y_true = [1, 1, 1, 1, 0, 0, 0, 0]
        base_preds = [1, 1, 1, 1, 0, 0, 0, 0]  # recall = 1.0
        cand_preds = [1, 1, 1, 0, 0, 0, 0, 0]  # recall = 0.75 (drop!)

        report = evaluate_detector_ablation(
            y_true=y_true,
            baseline_preds=base_preds,
            candidate_preds=cand_preds,
        )

        assert report.verdict == "rejected_regression"
        assert report.delta["recall_delta"] < 0
        assert "Candidate recall regressed" in report.verdict_rationale

    def test_ablation_rejection_inflated_false_positives(self) -> None:
        """Candidate that inflates FP without recall gain is rejected as regression."""
        y_true = [1, 1, 0, 0, 0, 0, 0, 0]
        base_preds = [1, 1, 0, 0, 0, 0, 0, 0]  # recall = 1.0, FP = 0
        cand_preds = [1, 1, 1, 1, 0, 0, 0, 0]  # recall = 1.0, FP = 2 (inflated burden!)

        report = evaluate_detector_ablation(
            y_true=y_true,
            baseline_preds=base_preds,
            candidate_preds=cand_preds,
        )

        assert report.verdict == "rejected_regression"
        assert report.delta["false_alert_burden_delta"] > 0
        assert "without compensating recall gain" in report.verdict_rationale

    def test_ablation_experimental_unfused_retained(self) -> None:
        """Candidate with recall gain but higher false alert burden is retained as unfused."""
        y_true = [1, 1, 1, 1, 0, 0, 0, 0, 0, 0]
        base_preds = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0]  # recall = 0.50, FP = 0
        cand_preds = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]  # recall = 1.00 (+0.50), FP = 1

        report = evaluate_detector_ablation(
            y_true=y_true,
            baseline_preds=base_preds,
            candidate_preds=cand_preds,
            candidate_is_unfused_advisory=True,
        )

        assert report.verdict == "experimental_unfused_retained"
        assert report.delta["recall_delta"] > 0
        assert report.delta["false_alert_burden_delta"] > 0
        assert "retained as experimental unfused advisory signal" in report.verdict_rationale

    def test_ablation_with_continuous_scores(self) -> None:
        """Test PR-AUC calculation with continuous scores."""
        y_true = [1, 1, 0, 0]
        base_preds = [1, 1, 0, 0]
        cand_preds = [1, 1, 0, 0]
        base_scores = [0.9, 0.8, 0.2, 0.1]
        cand_scores = [0.95, 0.85, 0.15, 0.05]

        report = evaluate_detector_ablation(
            y_true=y_true,
            baseline_preds=base_preds,
            candidate_preds=cand_preds,
            baseline_scores=base_scores,
            candidate_scores=cand_scores,
        )

        assert report.baseline.pr_auc == 1.0
        assert report.candidate.pr_auc == 1.0
        assert report.verdict == "approved_baseline"

    def test_ablation_fail_closed_length_mismatch(self) -> None:
        """Mismatched sample lengths fail closed."""
        with pytest.raises(MultiSignalRiskError) as exc_info:
            evaluate_detector_ablation(
                y_true=[1, 0],
                baseline_preds=[1],
                candidate_preds=[1, 0],
            )
        assert exc_info.value.code == "mismatched_sample_lengths"

    def test_ablation_fail_closed_empty_set(self) -> None:
        """Empty evaluation set fails closed."""
        with pytest.raises(MultiSignalRiskError) as exc_info:
            evaluate_detector_ablation(
                y_true=[],
                baseline_preds=[],
                candidate_preds=[],
            )
        assert exc_info.value.code == "empty_evaluation_set"

    def test_ablation_fail_closed_invalid_labels(self) -> None:
        """Invalid non-binary labels fail closed."""
        with pytest.raises(MultiSignalRiskError) as exc_info:
            evaluate_detector_ablation(
                y_true=[1, 2],
                baseline_preds=[1, 0],
                candidate_preds=[1, 0],
            )
        assert exc_info.value.code == "invalid_ground_truth_labels"
