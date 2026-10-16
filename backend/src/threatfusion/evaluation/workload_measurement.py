"""Section 13.F -- Alert-Fatigue Compression & Analyst Workload Measurement Harness.

Quantifies:
1. Ingestion-to-Incident Queue Compression:
   Measures raw flow filtering and alert-to-incident consolidation ratios.
2. Section 8 Counterfactual Fusion False-Positive Shield:
   Calculates exact analyst false-positive burden under RF-Only (production_fusion_enabled=False)
   vs Counterfactual RF+AE OR-Fusion on the January validation population (216,568 rows).
3. Analyst Workload Study Repository:
   Durable SQLite ledger (mode 0600) for triage timing, decision accuracy, and condition comparison,
   honestly enforcing TF-009 closure eligibility rules (synthetic trials never close TF-009).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sqlite3
import stat
import statistics
from typing import Any

from threatfusion.models.canonical_evaluation import (
    CANONICAL_EVALUATION_PACK_REV2,
)

WORKLOAD_MEASUREMENT_SCHEMA_VERSION = "workload_measurement_v1"


@dataclass(frozen=True, slots=True)
class QueueCompressionMetrics:
    """Ingestion-to-Incident Queue Compression Metrics."""

    raw_flow_count: int
    rf_alert_candidate_count: int
    correlated_incident_count: int
    uncorrelatable_alert_count: int
    effective_analyst_queue_size: int
    flow_to_alert_reduction_ratio: float
    alert_to_incident_consolidation_ratio: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_flow_count": self.raw_flow_count,
            "rf_alert_candidate_count": self.rf_alert_candidate_count,
            "correlated_incident_count": self.correlated_incident_count,
            "uncorrelatable_alert_count": self.uncorrelatable_alert_count,
            "effective_analyst_queue_size": self.effective_analyst_queue_size,
            "flow_to_alert_reduction_ratio": self.flow_to_alert_reduction_ratio,
            "alert_to_incident_consolidation_ratio": self.alert_to_incident_consolidation_ratio,
        }


@dataclass(frozen=True, slots=True)
class CounterfactualFusionShieldMetrics:
    """Section 8 Counterfactual Fusion False-Positive Shield Metrics on January UNSW."""

    population_name: str
    population_size: int
    rf_only_true_positives: int
    rf_only_false_positives: int
    rf_only_precision_pct: float
    counterfactual_fused_true_positives: int
    counterfactual_fused_false_positives: int
    counterfactual_fused_precision_pct: float
    relative_attack_gain_pct: float
    false_positive_multiplier: float
    false_positive_inflation_pct: float
    precision_drop_percentage_points: float
    marginal_false_positives_per_extra_attack: float
    fatigue_protection_verdict: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "population_name": self.population_name,
            "population_size": self.population_size,
            "rf_only_true_positives": self.rf_only_true_positives,
            "rf_only_false_positives": self.rf_only_false_positives,
            "rf_only_precision_pct": self.rf_only_precision_pct,
            "counterfactual_fused_true_positives": self.counterfactual_fused_true_positives,
            "counterfactual_fused_false_positives": self.counterfactual_fused_false_positives,
            "counterfactual_fused_precision_pct": self.counterfactual_fused_precision_pct,
            "relative_attack_gain_pct": self.relative_attack_gain_pct,
            "false_positive_multiplier": self.false_positive_multiplier,
            "false_positive_inflation_pct": self.false_positive_inflation_pct,
            "precision_drop_percentage_points": self.precision_drop_percentage_points,
            "marginal_false_positives_per_extra_attack": (
                self.marginal_false_positives_per_extra_attack
            ),
            "fatigue_protection_verdict": self.fatigue_protection_verdict,
        }


@dataclass(frozen=True, slots=True)
class AlertFatigueCompressionReport:
    """Unified Alert-Fatigue Compression & Counterfactual Protection Report."""

    schema_version: str
    queue_compression: QueueCompressionMetrics
    counterfactual_shield: CounterfactualFusionShieldMetrics
    generated_at_utc: str

    @property
    def flow_to_alert_reduction_ratio(self) -> float:
        return self.queue_compression.flow_to_alert_reduction_ratio

    @property
    def alert_to_incident_consolidation_ratio(self) -> float:
        return self.queue_compression.alert_to_incident_consolidation_ratio

    @property
    def effective_analyst_queue_size(self) -> int:
        return self.queue_compression.effective_analyst_queue_size

    @property
    def rf_only_precision_pct(self) -> float:
        return self.counterfactual_shield.rf_only_precision_pct

    @property
    def counterfactual_fused_precision_pct(self) -> float:
        return self.counterfactual_shield.counterfactual_fused_precision_pct

    @property
    def marginal_false_positives_per_extra_attack(self) -> float:
        return self.counterfactual_shield.marginal_false_positives_per_extra_attack

    @property
    def fatigue_protection_verdict(self) -> str:
        return self.counterfactual_shield.fatigue_protection_verdict

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "queue_compression": self.queue_compression.to_dict(),
            "counterfactual_shield": self.counterfactual_shield.to_dict(),
            "generated_at_utc": self.generated_at_utc,
        }


def evaluate_alert_fatigue_compression(
    *,
    raw_flow_count: int,
    rf_alert_candidate_count: int,
    correlated_incident_count: int,
    uncorrelatable_alert_count: int,
) -> AlertFatigueCompressionReport:
    """Compute exact alert-fatigue compression and Section 8 counterfactual shield metrics."""
    # Layer 1: Ingestion-to-Incident Queue Compression
    if raw_flow_count > 0:
        flow_to_alert_reduction = 1.0 - (rf_alert_candidate_count / raw_flow_count)
    else:
        flow_to_alert_reduction = 0.0

    effective_queue = correlated_incident_count + uncorrelatable_alert_count

    if rf_alert_candidate_count > 0:
        alert_to_inc_consolidation = 1.0 - (effective_queue / rf_alert_candidate_count)
    else:
        alert_to_inc_consolidation = 0.0

    queue_metrics = QueueCompressionMetrics(
        raw_flow_count=raw_flow_count,
        rf_alert_candidate_count=rf_alert_candidate_count,
        correlated_incident_count=correlated_incident_count,
        uncorrelatable_alert_count=uncorrelatable_alert_count,
        effective_analyst_queue_size=effective_queue,
        flow_to_alert_reduction_ratio=round(flow_to_alert_reduction, 6),
        alert_to_incident_consolidation_ratio=round(alert_to_inc_consolidation, 6),
    )

    # Layer 2: Section 8 Counterfactual Shield (January UNSW 216,568 validation population)
    pop_rev2 = CANONICAL_EVALUATION_PACK_REV2
    rf_tp = pop_rev2.frozen_random_forest.tp  # 4045
    rf_fp = pop_rev2.frozen_random_forest.fp  # 201
    rf_prec = pop_rev2.frozen_random_forest.precision_pct  # 95.266

    extra_tp = pop_rev2.section_8_complementarity.ae_only_additional_attacks_january  # 96
    extra_fp = pop_rev2.section_8_complementarity.ae_only_additional_benign_fps_january  # 1574

    fused_tp = rf_tp + extra_tp  # 4141
    fused_fp = rf_fp + extra_fp  # 1775

    rel_attack_gain = round((fused_tp - rf_tp) / rf_tp * 100, 3)  # +2.373%
    fp_mult = round(fused_fp / rf_fp, 4)  # 8.8308
    fp_inflation = round((fused_fp - rf_fp) / rf_fp * 100, 3)  # +783.085%

    fused_prec = round(fused_tp / (fused_tp + fused_fp) * 100, 3)  # 69.997%
    prec_drop = round(rf_prec - fused_prec, 3)  # 25.269 pp drop
    fps_per_extra_attack = round(extra_fp / extra_tp, 4)  # 16.3958

    shield_metrics = CounterfactualFusionShieldMetrics(
        population_name="unsw_nb15_january_validation",
        population_size=pop_rev2.populations.january_validation_total_rows,
        rf_only_true_positives=rf_tp,
        rf_only_false_positives=rf_fp,
        rf_only_precision_pct=rf_prec,
        counterfactual_fused_true_positives=fused_tp,
        counterfactual_fused_false_positives=fused_fp,
        counterfactual_fused_precision_pct=fused_prec,
        relative_attack_gain_pct=rel_attack_gain,
        false_positive_multiplier=fp_mult,
        false_positive_inflation_pct=fp_inflation,
        precision_drop_percentage_points=prec_drop,
        marginal_false_positives_per_extra_attack=fps_per_extra_attack,
        fatigue_protection_verdict="fusion_disabled_prevents_1574_false_alarms_8_83x_fp_inflation",
    )

    return AlertFatigueCompressionReport(
        schema_version=WORKLOAD_MEASUREMENT_SCHEMA_VERSION,
        queue_compression=queue_metrics,
        counterfactual_shield=shield_metrics,
        generated_at_utc=datetime.now(UTC).isoformat(),
    )


@dataclass(frozen=True, slots=True)
class TriageTrialRecord:
    """Individual analyst triage trial measurement."""

    trial_id: str
    study_cohort: str  # "synthetic_smoke_verification" | "human_analyst_cohort_study"
    participant_id: str
    candidate_id: str
    condition: str  # "baseline_raw_alert_only" | "threatfusion_enriched_advisory_soar"
    time_to_first_review_ms: int
    time_to_disposition_ms: int
    expected_disposition: str
    recorded_disposition: str
    disposition_correct: bool
    evidence_panels_viewed: tuple[str, ...]
    recorded_at_utc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "trial_id": self.trial_id,
            "study_cohort": self.study_cohort,
            "participant_id": self.participant_id,
            "candidate_id": self.candidate_id,
            "condition": self.condition,
            "time_to_first_review_ms": self.time_to_first_review_ms,
            "time_to_disposition_ms": self.time_to_disposition_ms,
            "expected_disposition": self.expected_disposition,
            "recorded_disposition": self.recorded_disposition,
            "disposition_correct": self.disposition_correct,
            "evidence_panels_viewed": list(self.evidence_panels_viewed),
            "recorded_at_utc": self.recorded_at_utc,
        }


@dataclass(frozen=True, slots=True)
class WorkloadStudySummary:
    """Statistical summary of analyst triage efficiency and accuracy."""

    study_cohort: str
    total_trials: int
    baseline_trials: int
    threatfusion_trials: int
    baseline_mean_time_to_disposition_ms: float
    baseline_median_time_to_disposition_ms: float
    threatfusion_mean_time_to_disposition_ms: float
    threatfusion_median_time_to_disposition_ms: float
    speedup_pct: float
    baseline_accuracy_pct: float
    threatfusion_accuracy_pct: float
    accuracy_gain_percentage_points: float
    tf_009_closure_eligible: bool
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "study_cohort": self.study_cohort,
            "total_trials": self.total_trials,
            "baseline_trials": self.baseline_trials,
            "threatfusion_trials": self.threatfusion_trials,
            "baseline_mean_time_to_disposition_ms": self.baseline_mean_time_to_disposition_ms,
            "baseline_median_time_to_disposition_ms": self.baseline_median_time_to_disposition_ms,
            "threatfusion_mean_time_to_disposition_ms": self.threatfusion_mean_time_to_disposition_ms,
            "threatfusion_median_time_to_disposition_ms": (
                self.threatfusion_median_time_to_disposition_ms
            ),
            "speedup_pct": self.speedup_pct,
            "baseline_accuracy_pct": self.baseline_accuracy_pct,
            "threatfusion_accuracy_pct": self.threatfusion_accuracy_pct,
            "accuracy_gain_percentage_points": self.accuracy_gain_percentage_points,
            "tf_009_closure_eligible": self.tf_009_closure_eligible,
            "notes": self.notes,
        }


class AnalystWorkloadStudyRepository:
    """SQLite repository enforcing mode 0600 permissions for Section 13.F studies."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS triage_trial_records (
                    trial_id TEXT PRIMARY KEY,
                    study_cohort TEXT NOT NULL,
                    participant_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    condition TEXT NOT NULL,
                    time_to_first_review_ms INTEGER NOT NULL,
                    time_to_disposition_ms INTEGER NOT NULL,
                    expected_disposition TEXT NOT NULL,
                    recorded_disposition TEXT NOT NULL,
                    disposition_correct INTEGER NOT NULL,
                    evidence_panels_viewed TEXT NOT NULL,
                    recorded_at_utc TEXT NOT NULL
                )
                """)
            conn.commit()

        try:
            os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def record_trial(self, trial: TriageTrialRecord) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO triage_trial_records (
                    trial_id, study_cohort, participant_id, candidate_id, condition,
                    time_to_first_review_ms, time_to_disposition_ms, expected_disposition,
                    recorded_disposition, disposition_correct, evidence_panels_viewed,
                    recorded_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    trial.trial_id,
                    trial.study_cohort,
                    trial.participant_id,
                    trial.candidate_id,
                    trial.condition,
                    trial.time_to_first_review_ms,
                    trial.time_to_disposition_ms,
                    trial.expected_disposition,
                    trial.recorded_disposition,
                    1 if trial.disposition_correct else 0,
                    json.dumps(list(trial.evidence_panels_viewed)),
                    trial.recorded_at_utc,
                ),
            )
            conn.commit()

    def list_trials(self, study_cohort: str | None = None) -> list[TriageTrialRecord]:
        with self._get_connection() as conn:
            if study_cohort:
                cursor = conn.execute(
                    "SELECT * FROM triage_trial_records WHERE study_cohort = ? ORDER BY recorded_at_utc ASC",
                    (study_cohort,),
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM triage_trial_records ORDER BY recorded_at_utc ASC"
                )
            return [self._row_to_record(row) for row in cursor.fetchall()]

    def summarize_study_metrics(self, study_cohort: str) -> WorkloadStudySummary:
        trials = self.list_trials(study_cohort=study_cohort)
        if not trials:
            return WorkloadStudySummary(
                study_cohort=study_cohort,
                total_trials=0,
                baseline_trials=0,
                threatfusion_trials=0,
                baseline_mean_time_to_disposition_ms=0.0,
                baseline_median_time_to_disposition_ms=0.0,
                threatfusion_mean_time_to_disposition_ms=0.0,
                threatfusion_median_time_to_disposition_ms=0.0,
                speedup_pct=0.0,
                baseline_accuracy_pct=0.0,
                threatfusion_accuracy_pct=0.0,
                accuracy_gain_percentage_points=0.0,
                tf_009_closure_eligible=False,
                notes="No trials recorded for cohort.",
            )

        baseline_times = [
            t.time_to_disposition_ms for t in trials if t.condition == "baseline_raw_alert_only"
        ]
        tf_times = [
            t.time_to_disposition_ms
            for t in trials
            if t.condition == "threatfusion_enriched_advisory_soar"
        ]

        baseline_correct = [
            t.disposition_correct for t in trials if t.condition == "baseline_raw_alert_only"
        ]
        tf_correct = [
            t.disposition_correct
            for t in trials
            if t.condition == "threatfusion_enriched_advisory_soar"
        ]

        b_mean = statistics.mean(baseline_times) if baseline_times else 0.0
        b_med = statistics.median(baseline_times) if baseline_times else 0.0
        tf_mean = statistics.mean(tf_times) if tf_times else 0.0
        tf_med = statistics.median(tf_times) if tf_times else 0.0

        speedup = round((b_mean - tf_mean) / b_mean * 100, 2) if b_mean > 0 else 0.0

        b_acc = (
            round(sum(baseline_correct) / len(baseline_correct) * 100, 2)
            if baseline_correct
            else 0.0
        )
        tf_acc = round(sum(tf_correct) / len(tf_correct) * 100, 2) if tf_correct else 0.0
        acc_gain = round(tf_acc - b_acc, 2)

        # Scientific discipline invariant: TF-009 requires human study with >= 10 trials
        closure_eligible = (
            study_cohort == "human_analyst_cohort_study"
            and len(trials) >= 10
            and len(baseline_times) >= 5
            and len(tf_times) >= 5
        )

        notes = (
            f"Study cohort '{study_cohort}' evaluated across {len(trials)} trials "
            f"({len(baseline_times)} baseline, {len(tf_times)} ThreatFusion)."
        )
        if not closure_eligible and study_cohort != "human_analyst_cohort_study":
            notes += " Synthetic cohort cannot satisfy TF-009 human validation gate."

        return WorkloadStudySummary(
            study_cohort=study_cohort,
            total_trials=len(trials),
            baseline_trials=len(baseline_times),
            threatfusion_trials=len(tf_times),
            baseline_mean_time_to_disposition_ms=round(b_mean, 2),
            baseline_median_time_to_disposition_ms=round(b_med, 2),
            threatfusion_mean_time_to_disposition_ms=round(tf_mean, 2),
            threatfusion_median_time_to_disposition_ms=round(tf_med, 2),
            speedup_pct=speedup,
            baseline_accuracy_pct=b_acc,
            threatfusion_accuracy_pct=tf_acc,
            accuracy_gain_percentage_points=acc_gain,
            tf_009_closure_eligible=closure_eligible,
            notes=notes,
        )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> TriageTrialRecord:
        panels = tuple(json.loads(row["evidence_panels_viewed"]))
        return TriageTrialRecord(
            trial_id=row["trial_id"],
            study_cohort=row["study_cohort"],
            participant_id=row["participant_id"],
            candidate_id=row["candidate_id"],
            condition=row["condition"],
            time_to_first_review_ms=row["time_to_first_review_ms"],
            time_to_disposition_ms=row["time_to_disposition_ms"],
            expected_disposition=row["expected_disposition"],
            recorded_disposition=row["recorded_disposition"],
            disposition_correct=bool(row["disposition_correct"]),
            evidence_panels_viewed=panels,
            recorded_at_utc=row["recorded_at_utc"],
        )
