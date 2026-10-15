"""Missing-Data Aware Multi-Signal Risk Policy and RF/AE Ablation Evaluator.

Enforces Phase P5 missing-data invariant: 'Missing evidence is not benign evidence'.
When optional detection signals are unavailable, their weights are removed from the
denominator rather than diluting attack evidence toward 0.0.

Provides rigorous class-aware RF vs. RF+AE ablation evaluation against baseline.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping, Sequence

import numpy as np
from sklearn.metrics import auc, precision_recall_curve

DYNAMIC_RISK_ASSESSMENT_SCHEMA_VERSION = "dynamic_risk_assessment_v1"
DETECTOR_ABLATION_REPORT_SCHEMA_VERSION = "detector_ablation_report_v1"

CANONICAL_SIGNAL_SLOTS: tuple[str, ...] = (
    "supervised_rf",
    "autoencoder_v2_reconstruction",
    "isolation_forest_outlier",
    "ueba_behavioral_deviation",
    "threat_intel_ioc",
    "payload_entropy",
    "periodic_beaconing",
)

DEFAULT_SIGNAL_WEIGHTS: dict[str, float] = {
    "supervised_rf": 0.30,
    "autoencoder_v2_reconstruction": 0.15,
    "isolation_forest_outlier": 0.10,
    "ueba_behavioral_deviation": 0.15,
    "threat_intel_ioc": 0.15,
    "payload_entropy": 0.075,
    "periodic_beaconing": 0.075,
}

SIGNAL_STATUS_AVAILABLE = "AVAILABLE"
SIGNAL_STATUS_UNAVAILABLE = "UNAVAILABLE"
ALLOWED_SIGNAL_STATUSES = frozenset({SIGNAL_STATUS_AVAILABLE, SIGNAL_STATUS_UNAVAILABLE})


class MultiSignalRiskError(RuntimeError):
    """Sanitized boundary error for multi-signal risk and detector ablation."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class SignalObservation:
    """Individual signal observation slot and provenance status."""

    slot: str
    status: str
    score: float | None = None
    reason: str | None = None
    metadata: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.slot not in CANONICAL_SIGNAL_SLOTS:
            raise MultiSignalRiskError("unknown_signal_slot")
        if self.status not in ALLOWED_SIGNAL_STATUSES:
            raise MultiSignalRiskError("invalid_signal_status")
        if self.status == SIGNAL_STATUS_AVAILABLE:
            if self.score is None:
                raise MultiSignalRiskError("available_signal_missing_score")
            try:
                score_val = float(self.score)
            except (TypeError, ValueError):
                raise MultiSignalRiskError("signal_score_out_of_bounds") from None
            if math.isnan(score_val) or math.isinf(score_val):
                raise MultiSignalRiskError("signal_score_nan")
            if not 0.0 <= score_val <= 1.0:
                raise MultiSignalRiskError("signal_score_out_of_bounds")
        else:  # UNAVAILABLE
            if self.score is not None:
                raise MultiSignalRiskError("unavailable_signal_must_not_have_score")
            if not self.reason or not isinstance(self.reason, str) or not self.reason.strip():
                raise MultiSignalRiskError("missing_unavailability_reason")


@dataclass(frozen=True, slots=True)
class DynamicRiskAssessment:
    """Evaluated multi-signal risk score and complete component breakdown."""

    schema_version: str
    dynamic_risk_score: float
    severity_level: str
    effective_weight_denominator: float
    available_signals: dict[str, dict[str, Any]]
    unavailable_signals: dict[str, dict[str, Any]]
    assessed_at_utc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "dynamic_risk_score": self.dynamic_risk_score,
            "severity_level": self.severity_level,
            "effective_weight_denominator": self.effective_weight_denominator,
            "available_signals": self.available_signals,
            "unavailable_signals": self.unavailable_signals,
            "assessed_at_utc": self.assessed_at_utc,
        }


def _validate_weights(custom_weights: Mapping[str, float] | None) -> dict[str, float]:
    weights = dict(DEFAULT_SIGNAL_WEIGHTS)
    if custom_weights is not None:
        if not isinstance(custom_weights, Mapping):
            raise MultiSignalRiskError("invalid_signal_weight")
        for slot, w in custom_weights.items():
            if slot not in CANONICAL_SIGNAL_SLOTS:
                raise MultiSignalRiskError("unknown_signal_slot")
            try:
                w_val = float(w)
            except (TypeError, ValueError):
                raise MultiSignalRiskError("invalid_signal_weight") from None
            if math.isnan(w_val) or math.isinf(w_val) or w_val <= 0.0:
                raise MultiSignalRiskError("invalid_signal_weight")
            weights[slot] = w_val
    return weights


def compute_dynamic_risk_score(
    observations: Sequence[SignalObservation] | Mapping[str, Any],
    *,
    custom_weights: Mapping[str, float] | None = None,
    assessed_at_utc: str | None = None,
) -> DynamicRiskAssessment:
    """Compute missing-data aware dynamic risk score over canonical signal registry.

    Enforces the Missing-Data Invariant:
    D = 100.0 * sum(w_i * s_i for i in A) / sum(w_i for i in A)
    strictly over available set A. Subtracts unavailable weights from denominator
    so an absent signal NEVER dilutes an attack score toward 0.0.
    """
    weights = _validate_weights(custom_weights)

    # Standardize input observations into mapping slot -> SignalObservation
    obs_map: dict[str, SignalObservation] = {}
    if isinstance(observations, Sequence) and not isinstance(observations, (str, bytes)):
        for item in observations:
            if not isinstance(item, SignalObservation):
                raise MultiSignalRiskError("invalid_observation_format")
            if item.slot in obs_map:
                raise MultiSignalRiskError("duplicate_signal_slot")
            obs_map[item.slot] = item
    elif isinstance(observations, Mapping):
        for slot, value in observations.items():
            if slot not in CANONICAL_SIGNAL_SLOTS:
                raise MultiSignalRiskError("unknown_signal_slot")
            if isinstance(value, SignalObservation):
                obs_map[slot] = value
            elif isinstance(value, Mapping):
                status = value.get("status", SIGNAL_STATUS_AVAILABLE)
                score = value.get("score")
                reason = value.get("reason")
                metadata = value.get("metadata")
                obs_map[slot] = SignalObservation(
                    slot=slot,
                    status=status,
                    score=score,
                    reason=reason,
                    metadata=metadata,
                )
            elif isinstance(value, (int, float)):
                obs_map[slot] = SignalObservation(
                    slot=slot,
                    status=SIGNAL_STATUS_AVAILABLE,
                    score=float(value),
                )
            else:
                raise MultiSignalRiskError("invalid_observation_format")
    else:
        raise MultiSignalRiskError("invalid_observation_format")

    # Slots not provided in observations are marked UNAVAILABLE by default
    for slot in CANONICAL_SIGNAL_SLOTS:
        if slot not in obs_map:
            obs_map[slot] = SignalObservation(
                slot=slot,
                status=SIGNAL_STATUS_UNAVAILABLE,
                reason="omitted_from_input",
            )

    available_signals: dict[str, dict[str, Any]] = {}
    unavailable_signals: dict[str, dict[str, Any]] = {}
    weighted_sum = 0.0
    effective_weight_denom = 0.0

    for slot in CANONICAL_SIGNAL_SLOTS:
        obs = obs_map[slot]
        slot_weight = weights[slot]
        if obs.status == SIGNAL_STATUS_AVAILABLE:
            score = float(obs.score)  # type: ignore[arg-type]
            available_signals[slot] = {
                "score": score,
                "weight": slot_weight,
                "metadata": obs.metadata,
            }
            weighted_sum += slot_weight * score
            effective_weight_denom += slot_weight
        else:
            unavailable_signals[slot] = {
                "reason": obs.reason,
                "nominal_weight": slot_weight,
            }

    if effective_weight_denom <= 0.0 or not available_signals:
        raise MultiSignalRiskError("empty_available_signal_set")

    # Compute raw dynamic risk score strictly over available set A
    dynamic_risk_score = 100.0 * (weighted_sum / effective_weight_denom)
    dynamic_risk_score = min(max(dynamic_risk_score, 0.0), 100.0)

    # Calculate per-signal normalized contribution percentage
    for slot, data in available_signals.items():
        data["normalized_contribution"] = round(
            100.0 * (data["weight"] * data["score"]) / effective_weight_denom,
            4,
        )

    # Classify severity
    if dynamic_risk_score >= 85.0:
        severity = "critical"
    elif dynamic_risk_score >= 65.0:
        severity = "high"
    elif dynamic_risk_score >= 40.0:
        severity = "medium"
    else:
        severity = "low"

    timestamp = assessed_at_utc or datetime.now(UTC).isoformat()

    return DynamicRiskAssessment(
        schema_version=DYNAMIC_RISK_ASSESSMENT_SCHEMA_VERSION,
        dynamic_risk_score=round(dynamic_risk_score, 4),
        severity_level=severity,
        effective_weight_denominator=round(effective_weight_denom, 6),
        available_signals=available_signals,
        unavailable_signals=unavailable_signals,
        assessed_at_utc=timestamp,
    )


@dataclass(frozen=True, slots=True)
class DetectorMetrics:
    """Class-aware detection metrics for one detector policy."""

    name: str
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1_score: float
    pr_auc: float
    false_alert_burden_per_1000: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "confusion_matrix": {
                "tp": self.tp,
                "fp": self.fp,
                "tn": self.tn,
                "fn": self.fn,
            },
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "pr_auc": self.pr_auc,
            "false_alert_burden_per_1000": self.false_alert_burden_per_1000,
        }


@dataclass(frozen=True, slots=True)
class DetectorAblationReport:
    """Structured ablation evaluation between baseline and candidate detector."""

    schema_version: str
    evaluated_at_utc: str
    sample_count: int
    baseline: DetectorMetrics
    candidate: DetectorMetrics
    delta: dict[str, float]
    verdict: str
    verdict_rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evaluated_at_utc": self.evaluated_at_utc,
            "sample_count": self.sample_count,
            "baseline": self.baseline.to_dict(),
            "candidate": self.candidate.to_dict(),
            "delta": self.delta,
            "verdict": self.verdict,
            "verdict_rationale": self.verdict_rationale,
        }


def _compute_metrics(
    name: str,
    y_true: np.ndarray,
    preds: np.ndarray,
    scores: np.ndarray | None,
) -> DetectorMetrics:
    tp = int(np.sum((preds == 1) & (y_true == 1)))
    fp = int(np.sum((preds == 1) & (y_true == 0)))
    tn = int(np.sum((preds == 0) & (y_true == 0)))
    fn = int(np.sum((preds == 0) & (y_true == 1)))

    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1_score = (
        float(2.0 * precision * recall / (precision + recall))
        if (precision + recall) > 0.0
        else 0.0
    )

    benign_count = fp + tn
    false_alert_burden = float(1000.0 * fp / benign_count) if benign_count > 0 else 0.0

    # Compute PR-AUC
    eval_scores = scores if scores is not None else preds.astype(np.float64)
    positive_samples = int(np.sum(y_true == 1))
    if positive_samples == 0:
        pr_auc_val = 0.0
    else:
        try:
            p_curve, r_curve, _ = precision_recall_curve(y_true, eval_scores)
            pr_auc_val = float(auc(r_curve, p_curve))
            if math.isnan(pr_auc_val):
                pr_auc_val = 0.0
        except Exception:
            pr_auc_val = 0.0

    return DetectorMetrics(
        name=name,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=round(precision, 6),
        recall=round(recall, 6),
        f1_score=round(f1_score, 6),
        pr_auc=round(pr_auc_val, 6),
        false_alert_burden_per_1000=round(false_alert_burden, 4),
    )


def evaluate_detector_ablation(
    y_true: Sequence[int],
    baseline_preds: Sequence[int],
    candidate_preds: Sequence[int],
    *,
    baseline_scores: Sequence[float] | None = None,
    candidate_scores: Sequence[float] | None = None,
    baseline_name: str = "frozen_random_forest",
    candidate_name: str = "rf_plus_autoencoder_v2",
    candidate_is_unfused_advisory: bool = False,
    evaluated_at_utc: str | None = None,
) -> DetectorAblationReport:
    """Evaluate ablation of a candidate anomaly/fusion policy against frozen baseline.

    Computes class-aware metrics: confusion matrix, precision, recall, f1, pr_auc,
    false-alert burden per 1000 benign records, and explicit promotion gate verdict.
    """
    n = len(y_true)
    if n == 0:
        raise MultiSignalRiskError("empty_evaluation_set")
    if len(baseline_preds) != n or len(candidate_preds) != n:
        raise MultiSignalRiskError("mismatched_sample_lengths")
    if baseline_scores is not None and len(baseline_scores) != n:
        raise MultiSignalRiskError("mismatched_sample_lengths")
    if candidate_scores is not None and len(candidate_scores) != n:
        raise MultiSignalRiskError("mismatched_sample_lengths")

    try:
        y_true_arr = np.asarray(y_true, dtype=np.int64)
        base_arr = np.asarray(baseline_preds, dtype=np.int64)
        cand_arr = np.asarray(candidate_preds, dtype=np.int64)
    except (TypeError, ValueError):
        raise MultiSignalRiskError("invalid_prediction_labels") from None

    # Validate binary label values
    if not np.all((y_true_arr == 0) | (y_true_arr == 1)):
        raise MultiSignalRiskError("invalid_ground_truth_labels")
    if not np.all((base_arr == 0) | (base_arr == 1)) or not np.all(
        (cand_arr == 0) | (cand_arr == 1)
    ):
        raise MultiSignalRiskError("invalid_prediction_labels")

    base_scores_arr: np.ndarray | None = None
    if baseline_scores is not None:
        try:
            base_scores_arr = np.asarray(baseline_scores, dtype=np.float64)
            if np.any(np.isnan(base_scores_arr)) or np.any(np.isinf(base_scores_arr)):
                raise MultiSignalRiskError("invalid_prediction_scores")
            if np.any((base_scores_arr < 0.0) | (base_scores_arr > 1.0)):
                raise MultiSignalRiskError("invalid_prediction_scores")
        except (TypeError, ValueError):
            raise MultiSignalRiskError("invalid_prediction_scores") from None

    cand_scores_arr: np.ndarray | None = None
    if candidate_scores is not None:
        try:
            cand_scores_arr = np.asarray(candidate_scores, dtype=np.float64)
            if np.any(np.isnan(cand_scores_arr)) or np.any(np.isinf(cand_scores_arr)):
                raise MultiSignalRiskError("invalid_prediction_scores")
            if np.any((cand_scores_arr < 0.0) | (cand_scores_arr > 1.0)):
                raise MultiSignalRiskError("invalid_prediction_scores")
        except (TypeError, ValueError):
            raise MultiSignalRiskError("invalid_prediction_scores") from None

    base_metrics = _compute_metrics(baseline_name, y_true_arr, base_arr, base_scores_arr)
    cand_metrics = _compute_metrics(candidate_name, y_true_arr, cand_arr, cand_scores_arr)

    recall_delta = round(cand_metrics.recall - base_metrics.recall, 6)
    precision_delta = round(cand_metrics.precision - base_metrics.precision, 6)
    f1_delta = round(cand_metrics.f1_score - base_metrics.f1_score, 6)
    burden_delta = round(
        cand_metrics.false_alert_burden_per_1000 - base_metrics.false_alert_burden_per_1000,
        4,
    )

    delta = {
        "recall_delta": recall_delta,
        "precision_delta": precision_delta,
        "f1_delta": f1_delta,
        "false_alert_burden_delta": burden_delta,
    }

    # Promotion gate logic
    if recall_delta < -1e-4:
        verdict = "rejected_regression"
        rationale = (
            f"Candidate recall regressed by {abs(recall_delta):.4f} "
            f"({cand_metrics.recall:.4f} vs baseline {base_metrics.recall:.4f})"
        )
    elif burden_delta > 0.0 and recall_delta <= 1e-4:
        verdict = "rejected_regression"
        rationale = (
            f"Candidate increased false-alert burden by {burden_delta:+.2f} per 1000 "
            f"without compensating recall gain"
        )
    elif candidate_is_unfused_advisory or burden_delta > 0.0:
        verdict = "experimental_unfused_retained"
        rationale = (
            f"Candidate provides anomaly/recall evidence ({recall_delta:+.4f}) "
            f"with false-alert burden {cand_metrics.false_alert_burden_per_1000:.2f}/1000; "
            f"retained as experimental unfused advisory signal"
        )
    elif recall_delta >= -1e-4 and burden_delta <= 0.0:
        verdict = "approved_baseline"
        rationale = (
            f"Candidate matches or exceeds baseline without regression "
            f"(recall {cand_metrics.recall:.4f}, burden {cand_metrics.false_alert_burden_per_1000:.2f}/1000)"
        )
    else:
        verdict = "experimental_unfused_retained"
        rationale = "Candidate retained as experimental unfused evidence"

    timestamp = evaluated_at_utc or datetime.now(UTC).isoformat()

    return DetectorAblationReport(
        schema_version=DETECTOR_ABLATION_REPORT_SCHEMA_VERSION,
        evaluated_at_utc=timestamp,
        sample_count=n,
        baseline=base_metrics,
        candidate=cand_metrics,
        delta=delta,
        verdict=verdict,
        verdict_rationale=rationale,
    )
