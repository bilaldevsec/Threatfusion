"""Canonical Evaluation Pack Rev2 (AI-FYP-2006).

Consolidates the authoritative September 21, 2026 Evaluation Pack Rev2 (6a36dcd9af17bf509977bcf966f2ace72644d5b2)
scientific baseline for FAST-NUCES CS492 FYP-II:
1. Exact populations (Train 865,480 benign-only; January validation 216,568; February benchmark 1,452,844).
2. Frozen Random Forest Reference (full-network-random-forest-6d69c72-v1):
   95.266% precision, 92.818% recall, 94.026% F1, 0.095% FPR on January (216,568 rows).
3. Corrected v2 Single-Record Autoencoder (full-benign-autoencoder-2a51c94-v2):
   Architecture 14->8->3->8->14, threshold 0.118136.
4. Section 8 Complementarity & Why Fusion Is Disabled:
   96 additional attacks vs 1,574 additional false alarms (16.4 FPs per additional attack),
   enforcing production_fusion_enabled = False.
5. January Residual Audit (january-v2-record-concentration-b5e6e5d) & Blocked rate-log1p Candidate.
6. Legacy FYP-I superseded numbers preserved exclusively inside LegacyFyp1SupersededSummary.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from threatfusion.models.jury_traceability import (
    FROZEN_LOGISTIC_EXPECTED_SHA256,
    FROZEN_LOGISTIC_RELATIVE_PATH,
    FROZEN_RF_EXPECTED_SHA256,
    FROZEN_RF_RELATIVE_PATH,
)

CANONICAL_EVALUATION_SCHEMA_VERSION = "canonical_evaluation_pack_v2"
PROJECT_ID = "AI-FYP-2006"
PROJECT_IDENTIFIER = PROJECT_ID
PROJECT_TITLE = (
    "ThreatFusion: Mitigating Alert Fatigue in Security Operations through a Unified "
    "Threat Intelligence and Analytics Interface"
)
INSTITUTION = "FAST-NUCES Karachi (CS492 Final Year Project - FYP-II)"
DEPARTMENT = "Department of Computer Science"
ACADEMIC_COURSE = "CS492 Final Year Project - FYP-II"
SUPERVISOR = "Sir Sameer Faisal"
SUPERVISORS: tuple[str, ...] = ("Sir Sameer Faisal",)
TEAM_MEMBERS: tuple[tuple[str, str], ...] = (
    ("Muhammad Bilal", "21K-3551"),
    ("Muhammad Suhaib Shaikh", "22K-4302"),
    ("Muhammad Hasnain", "22K-4718"),
)
AUTHORS: tuple[dict[str, str], ...] = (
    {"name": "Muhammad Bilal", "roll_number": "21K-3551"},
    {"name": "Muhammad Suhaib Shaikh", "roll_number": "22K-4302"},
    {"name": "Muhammad Hasnain", "roll_number": "22K-4718"},
)
EVALUATION_CHECKPOINT_COMMIT = "6a36dcd9af17bf509977bcf966f2ace72644d5b2"

SPLIT_INVERSION_DISCLOSURE = (
    "The historical FYP-I / early FYP-II exploratory deck figures (89.77% RF, 94.95% DL fusion from "
    "Final Presentation (1).pptx) were generated with inverted train/test partitions relative to the "
    "authoritative evaluation split. Those numbers are strictly superseded by the verified September 21, "
    "2026 Evaluation Pack Rev2 (6a36dcd) baseline."
)

SECTION_8_FUSION_DISABLED_POLICY = (
    "In accordance with Section 8 of the product charter and the September 21, 2026 Evaluation Pack Rev2, "
    "decision-level fusion is strictly disabled in production (production_fusion_enabled = False). On the "
    "January validation set (216,568 rows), enabling autoencoder OR-fusion would catch only 96 additional "
    "attacks while introducing 1,574 additional false alarms (16.3958 benign false positives per additional "
    "attack, inflating false positives from 201 to 1,775 -- an 8.83x multiplier). Product inference and alerts "
    "are exclusively driven by the Frozen Random Forest reference."
)


class CanonicalEvaluationError(RuntimeError):
    """Sanitized boundary error for canonical evaluation pack."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class FusionDisabledError(RuntimeError):
    """Raised when an attempt is made to invoke unverified candidate fusion in production."""

    def __init__(self, code: str = "fusion_disabled_pending_same_split_verification") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DatasetPopulation:
    """Exact population splits from Evaluation Pack Rev2 (6a36dcd)."""

    train_total_rows: int = 865480
    train_benign_rows: int = 847837
    train_attack_rows: int = 17643
    train_notes: str = "benign-only weight training with all-TRAIN preprocessing statistics"
    january_validation_total_rows: int = 216568
    january_validation_attack_rows: int = 4358
    january_validation_benign_rows: int = 212210
    february_benchmark_total_rows: int = 1452844
    february_benchmark_notes: str = "previously inspected; disclosed as non-untouched benchmark"

    def to_dict(self) -> dict[str, Any]:
        return {
            "train_total_rows": self.train_total_rows,
            "train_benign_rows": self.train_benign_rows,
            "train_attack_rows": self.train_attack_rows,
            "train_notes": self.train_notes,
            "january_validation_total_rows": self.january_validation_total_rows,
            "january_validation_attack_rows": self.january_validation_attack_rows,
            "january_validation_benign_rows": self.january_validation_benign_rows,
            "february_benchmark_total_rows": self.february_benchmark_total_rows,
            "february_benchmark_notes": self.february_benchmark_notes,
        }


@dataclass(frozen=True, slots=True)
class FrozenRandomForestMetrics:
    """Frozen Random Forest reference evaluation (full-network-random-forest-6d69c72-v1)."""

    model_version: str = "full-network-random-forest-6d69c72-v1"
    population_rows: int = 216568
    tp: int = 4045
    fp: int = 201
    tn: int = 212009
    fn: int = 313
    precision_pct: float = 95.266
    recall_pct: float = 92.818
    f1_pct: float = 94.026
    fpr_pct: float = 0.095
    demo_row_1_attack_probability: float = 0.00001
    demo_row_21_attack_probability: float = 0.8249883171915375

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "population_rows": self.population_rows,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision_pct": self.precision_pct,
            "recall_pct": self.recall_pct,
            "f1_pct": self.f1_pct,
            "fpr_pct": self.fpr_pct,
            "demo_row_1_attack_probability": self.demo_row_1_attack_probability,
            "demo_row_21_attack_probability": self.demo_row_21_attack_probability,
        }


@dataclass(frozen=True, slots=True)
class AutoencoderEvaluation:
    """Corrected v2 Single-Record Autoencoder (full-benign-autoencoder-2a51c94-v2)."""

    model_version: str = "full-benign-autoencoder-2a51c94-v2"
    architecture: str = "14->8->3->8->14"
    threshold: float = 0.1181361214680695
    january_total_rows: int = 216568
    january_tp: int = 1988
    january_fp: int = 1628
    january_tn: int = 210582
    january_fn: int = 2370
    january_precision_pct: float = 54.978
    january_recall_pct: float = 45.617
    january_f1_pct: float = 49.862
    january_fpr_pct: float = 0.767
    february_total_rows: int = 1452844
    february_tp: int = 248531
    february_fp: int = 25934
    february_tn: int = 1127842
    february_fn: int = 50537
    february_precision_pct: float = 90.551
    february_recall_pct: float = 83.102
    february_f1_pct: float = 86.667
    february_fpr_pct: float = 2.248

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "architecture": self.architecture,
            "threshold": self.threshold,
            "january": {
                "total_rows": self.january_total_rows,
                "tp": self.january_tp,
                "fp": self.january_fp,
                "tn": self.january_tn,
                "fn": self.january_fn,
                "precision_pct": self.january_precision_pct,
                "recall_pct": self.january_recall_pct,
                "f1_pct": self.january_f1_pct,
                "fpr_pct": self.january_fpr_pct,
            },
            "february": {
                "total_rows": self.february_total_rows,
                "tp": self.february_tp,
                "fp": self.february_fp,
                "tn": self.february_tn,
                "fn": self.february_fn,
                "precision_pct": self.february_precision_pct,
                "recall_pct": self.february_recall_pct,
                "f1_pct": self.february_f1_pct,
                "fpr_pct": self.february_fpr_pct,
            },
        }


@dataclass(frozen=True, slots=True)
class Section8Complementarity:
    """Mathematical demonstration of why candidate fusion is strictly disabled."""

    ae_only_additional_attacks_january: int = 96
    ae_only_additional_benign_fps_january: int = 1574
    benign_fps_per_additional_attack: float = 16.395833333333332
    production_fusion_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ae_only_additional_attacks_january": self.ae_only_additional_attacks_january,
            "ae_only_additional_benign_fps_january": self.ae_only_additional_benign_fps_january,
            "benign_fps_per_additional_attack": self.benign_fps_per_additional_attack,
            "production_fusion_enabled": self.production_fusion_enabled,
        }


@dataclass(frozen=True, slots=True)
class JanuaryResidualAudit:
    """January residual audit (january-v2-record-concentration-b5e6e5d)."""

    audit_label: str = "january-v2-record-concentration-b5e6e5d"
    rates_group_pooled_error_pct_ae_only_attacks: float = 93.784
    rates_group_pooled_error_pct_ae_only_benign_fps: float = 38.748
    top_158_benign_fp_whole_record_error_pct: float = 69.938
    top_158_benign_fp_rate_group_error_pct: float = 95.676

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_label": self.audit_label,
            "rates_group_pooled_error_pct_ae_only_attacks": (
                self.rates_group_pooled_error_pct_ae_only_attacks
            ),
            "rates_group_pooled_error_pct_ae_only_benign_fps": (
                self.rates_group_pooled_error_pct_ae_only_benign_fps
            ),
            "top_158_benign_fp_whole_record_error_pct": (
                self.top_158_benign_fp_whole_record_error_pct
            ),
            "top_158_benign_fp_rate_group_error_pct": (self.top_158_benign_fp_rate_group_error_pct),
        }


@dataclass(frozen=True, slots=True)
class BlockedRateLog1pCandidate:
    """Blocked candidate disposition (rate-log1p-autoencoder-b5e6e5d-v1)."""

    candidate_version: str = "rate-log1p-autoencoder-b5e6e5d-v1"
    disposition: str = "BLOCKED_preserve_baseline"
    ae_only_attacks: int = 59
    ae_only_benign_fps: int = 2080
    total_ae_fps: int = 2122
    tp: int = 945
    recall_pct: float = 21.684
    fpr_pct: float = 1.000

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_version": self.candidate_version,
            "disposition": self.disposition,
            "ae_only_attacks": self.ae_only_attacks,
            "ae_only_benign_fps": self.ae_only_benign_fps,
            "total_ae_fps": self.total_ae_fps,
            "tp": self.tp,
            "recall_pct": self.recall_pct,
            "fpr_pct": self.fpr_pct,
        }


@dataclass(frozen=True, slots=True)
class LegacyFyp1SupersededSummary:
    """Preserved historical FYP-I deck figures, explicitly marked as superseded."""

    superseded_by_fyp2_eval_pack_rev2: bool = True
    rf_binary_accuracy_pct: float = 89.77
    rf_binary_f1_pct: float = 91.31
    deck_multimodal_fusion_accuracy_pct: float = 94.95
    deck_multimodal_fusion_f1_pct: float = 96.30
    source_reference: str = (
        "Final Presentation (1).pptx preliminary exploratory run with inverted train/test split"
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "superseded_by_fyp2_eval_pack_rev2": self.superseded_by_fyp2_eval_pack_rev2,
            "rf_binary_accuracy_pct": self.rf_binary_accuracy_pct,
            "rf_binary_f1_pct": self.rf_binary_f1_pct,
            "deck_multimodal_fusion_accuracy_pct": self.deck_multimodal_fusion_accuracy_pct,
            "deck_multimodal_fusion_f1_pct": self.deck_multimodal_fusion_f1_pct,
            "source_reference": self.source_reference,
        }


@dataclass(frozen=True, slots=True)
class ModelEvaluationEntry:
    """Legacy model evaluation entry format for compatibility."""

    model_name: str
    family: str
    phase: str
    objective: str
    disposition_status: str
    binary_accuracy: float | None = None
    binary_f1: float | None = None
    binary_recall: float | None = None
    false_positive_rate: float | None = None
    category_accuracy: float | None = None
    category_macro_f1: float | None = None
    artifact_path: str | None = None
    expected_sha256: str | None = None
    is_preliminary: bool = False
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "family": self.family,
            "phase": self.phase,
            "objective": self.objective,
            "disposition_status": self.disposition_status,
            "binary_accuracy": self.binary_accuracy,
            "binary_f1": self.binary_f1,
            "binary_recall": self.binary_recall,
            "false_positive_rate": self.false_positive_rate,
            "category_accuracy": self.category_accuracy,
            "category_macro_f1": self.category_macro_f1,
            "artifact_path": self.artifact_path,
            "expected_sha256": self.expected_sha256,
            "is_preliminary": self.is_preliminary,
            "notes": self.notes,
        }


FYP_I_MODELS: dict[str, ModelEvaluationEntry] = {
    "random_forest": ModelEvaluationEntry(
        model_name="random_forest",
        family="Random_Forest",
        phase="FYP-II_Verified_Rev2",
        objective="binary_classification",
        disposition_status="FROZEN_PRODUCTION_BASELINE",
        binary_accuracy=0.95266,
        binary_f1=0.94026,
        binary_recall=0.92818,
        false_positive_rate=0.00095,
        artifact_path=FROZEN_RF_RELATIVE_PATH,
        expected_sha256=FROZEN_RF_EXPECTED_SHA256,
        is_preliminary=False,
        notes="Primary production inference detector. Drives alerts and correlation.",
    ),
    "logistic_regression": ModelEvaluationEntry(
        model_name="logistic_regression",
        family="Logistic_Regression",
        phase="FYP-I_Preserved",
        objective="binary_classification",
        disposition_status="PRESERVED_LINEAR_BASELINE",
        artifact_path=FROZEN_LOGISTIC_RELATIVE_PATH,
        expected_sha256=FROZEN_LOGISTIC_EXPECTED_SHA256,
        is_preliminary=False,
        notes="Preserved linear comparison baseline.",
    ),
}

FYP_II_MODELS: dict[str, ModelEvaluationEntry] = {
    "autoencoder_v2": ModelEvaluationEntry(
        model_name="autoencoder_v2",
        family="Autoencoder",
        phase="FYP-II_Verified_Rev2",
        objective="anomaly_detection",
        disposition_status="EXPERIMENTAL_UNFUSED_BASELINE",
        binary_accuracy=0.54978,
        binary_f1=0.49862,
        binary_recall=0.45617,
        false_positive_rate=0.00767,
        is_preliminary=False,
        notes="Experimental unfused anomaly detector. Complementarity audit shows 16.4 FPs/extra attack.",
    ),
}


@dataclass(frozen=True, slots=True)
class CanonicalEvaluationPackRev2:
    """Consolidated Rev2 evaluation pack, populations, and Section 8 governance state."""

    schema_version: str
    project_id: str
    project_identifier: str
    project_title: str
    institution: str
    department: str
    academic_course: str
    supervisor: str
    supervisors: tuple[str, ...]
    team_members: tuple[tuple[str, str], ...]
    authors: tuple[dict[str, str], ...]
    evaluation_checkpoint_commit: str
    populations: DatasetPopulation
    frozen_random_forest: FrozenRandomForestMetrics
    autoencoder_v2: AutoencoderEvaluation
    section_8_complementarity: Section8Complementarity
    january_residual_audit: JanuaryResidualAudit
    blocked_candidate: BlockedRateLog1pCandidate
    legacy_superseded: LegacyFyp1SupersededSummary
    fyp_i_models: dict[str, ModelEvaluationEntry]
    fyp_ii_models: dict[str, ModelEvaluationEntry]
    split_inversion_disclosure: str
    section_8_fusion_disabled_policy: str
    fusion_disabled: bool
    production_detector: str
    generated_at_utc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "project_id": self.project_id,
            "project_identifier": self.project_identifier,
            "project_title": self.project_title,
            "institution": self.institution,
            "department": self.department,
            "academic_course": self.academic_course,
            "supervisor": self.supervisor,
            "supervisors": list(self.supervisors),
            "team_members": [list(tm) for tm in self.team_members],
            "authors": list(self.authors),
            "evaluation_checkpoint_commit": self.evaluation_checkpoint_commit,
            "populations": self.populations.to_dict(),
            "frozen_random_forest": self.frozen_random_forest.to_dict(),
            "autoencoder_v2": self.autoencoder_v2.to_dict(),
            "section_8_complementarity": self.section_8_complementarity.to_dict(),
            "january_residual_audit": self.january_residual_audit.to_dict(),
            "blocked_candidate": self.blocked_candidate.to_dict(),
            "legacy_superseded": self.legacy_superseded.to_dict(),
            "fyp_i_models": {k: v.to_dict() for k, v in self.fyp_i_models.items()},
            "fyp_ii_models": {k: v.to_dict() for k, v in self.fyp_ii_models.items()},
            "split_inversion_disclosure": self.split_inversion_disclosure,
            "section_8_fusion_disabled_policy": self.section_8_fusion_disabled_policy,
            "fusion_disabled": self.fusion_disabled,
            "production_detector": self.production_detector,
            "generated_at_utc": self.generated_at_utc,
        }


def get_canonical_evaluation_pack_rev2(
    *,
    generated_at_utc: str | None = None,
) -> CanonicalEvaluationPackRev2:
    """Return the authoritative Canonical Evaluation Pack Rev2."""
    timestamp = generated_at_utc or datetime.now(UTC).isoformat()
    return CanonicalEvaluationPackRev2(
        schema_version=CANONICAL_EVALUATION_SCHEMA_VERSION,
        project_id=PROJECT_ID,
        project_identifier=PROJECT_IDENTIFIER,
        project_title=PROJECT_TITLE,
        institution=INSTITUTION,
        department=DEPARTMENT,
        academic_course=ACADEMIC_COURSE,
        supervisor=SUPERVISOR,
        supervisors=SUPERVISORS,
        team_members=TEAM_MEMBERS,
        authors=AUTHORS,
        evaluation_checkpoint_commit=EVALUATION_CHECKPOINT_COMMIT,
        populations=DatasetPopulation(),
        frozen_random_forest=FrozenRandomForestMetrics(),
        autoencoder_v2=AutoencoderEvaluation(),
        section_8_complementarity=Section8Complementarity(),
        january_residual_audit=JanuaryResidualAudit(),
        blocked_candidate=BlockedRateLog1pCandidate(),
        legacy_superseded=LegacyFyp1SupersededSummary(),
        fyp_i_models=FYP_I_MODELS,
        fyp_ii_models=FYP_II_MODELS,
        split_inversion_disclosure=SPLIT_INVERSION_DISCLOSURE,
        section_8_fusion_disabled_policy=SECTION_8_FUSION_DISABLED_POLICY,
        fusion_disabled=True,
        production_detector="full-network-random-forest-6d69c72-v1",
        generated_at_utc=timestamp,
    )


CANONICAL_EVALUATION_PACK_REV2 = get_canonical_evaluation_pack_rev2()


def is_fusion_enabled() -> bool:
    """Return True if multi-model fusion is enabled in production. Always returns False."""
    return False


def assert_fusion_disabled_invariant() -> None:
    """Assert that Section 8 fusion_disabled invariant holds.

    Raises FusionDisabledError if candidate fusion is improperly configured as active.
    """
    if is_fusion_enabled():
        raise FusionDisabledError("fusion_disabled_invariant_violated")


def execute_production_inference_guard(requested_mode: str) -> str:
    """Enforce that production inference only routes through approved baseline.

    If requested_mode == 'decision_fusion' or 'candidate_fusion', raises FusionDisabledError.
    """
    if requested_mode in {"decision_fusion", "candidate_fusion", "fused_dl"}:
        raise FusionDisabledError(
            f"mode_{requested_mode}_blocked_pending_corrected_split_verification"
        )
    return "frozen_random_forest_approved"
