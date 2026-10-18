"""Pre-Registered Independent Holdout Evaluation Harness for TF-008 (Milestone #31).

Provides an authoritative, leak-proof independent holdout evaluation protocol:
1. INSPECTED_DEVELOPMENT_DATASET_IDS & INSPECTED_DEVELOPMENT_DATASET_SHA256S:
   Strictly tracks all development-informing splits ("unsw_nb15_train_865480",
   "unsw_nb15_january_216568", "unsw_nb15_february_1452844") and their exact hashes
   that were previously inspected during model selection/tuning. Any evaluation on these
   immediately triggers protocol_violation_inspected_split=True and tf_008_closure_eligible=False.
2. IndependentHoldoutEvaluationReport & evaluate_independent_holdout_dataset:
   Computes exact confusion matrix counts (tp, fp, tn, fn) at frozen 0.5 threshold,
   precision_pct, recall_pct, f1_pct, fpr_pct, accuracy_pct, and deterministic 95%
   bootstrap confidence intervals for precision and recall using random.Random(random_seed).
3. TF-008 Closure Gate Invariant:
   Enforces tf_008_closure_eligible=False whenever is_synthetic_smoke_fixture is True,
   protocol_violation_inspected_split is True, total sample size < 1000, bootstrap_iterations < 200,
   dataset_sha256 is invalid or inspected, or Random Forest model identity is mismatched.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
import math
from pathlib import Path
import random
import re
from typing import Any

INDEPENDENT_HOLDOUT_SCHEMA_VERSION = "independent_holdout_evaluation_report_v1"

INSPECTED_DEVELOPMENT_DATASET_IDS: tuple[str, ...] = (
    "unsw_nb15_train_865480",
    "unsw_nb15_january_216568",
    "unsw_nb15_february_1452844",
)

INSPECTED_DEVELOPMENT_DATASET_SHA256S: tuple[str, ...] = (
    "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",  # UNSW training-set.csv
    "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",  # UNSW testing-set.csv
    "c55f19cceebb6360dc50f44f8a5f246ccefbcf8a6c604ac1ad46e643869cafce",  # NUSW-NB15_features.csv
    "7d851bbeabd27894ce39c8e78835c73341fc946652fb7743b9eff193b55eb511",  # UNSW-NB15_1.csv
    "6130ad02873cc6069ae695cf2844f2e8c2e9a9a1b7532dd82ab8f202757cacf8",  # UNSW-NB15_2.csv
    "ae990a96c3dfcd425ce2801aadb1727a34d5e0ae6d8215dbcdae60dedfaef640",  # UNSW-NB15_3.csv
    "cdf563692d51d405541dd659ddcdad9fa01f001f05fe9fc4b67f00ca12fbc96a",  # UNSW-NB15_4.csv
)

MIN_INDEPENDENT_SAMPLES_FOR_CLOSURE: int = 1000
MIN_BOOTSTRAP_ITERATIONS_FOR_CLOSURE: int = 200
FROZEN_RF_DECISION_THRESHOLD: float = 0.50
AUTHORIZED_RF_MODEL_VERSION: str = "full-network-random-forest-6d69c72-v1"
AUTHORIZED_RF_MODEL_SHA256: str = "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"


@dataclass(frozen=True, slots=True)
class IndependentHoldoutEvaluationReport:
    """Cryptographic and statistical receipt of an independent holdout evaluation run."""

    schema_version: str
    dataset_id: str
    dataset_sha256: str
    dataset_sha256_valid: bool
    rf_model_version: str
    rf_model_sha256: str
    rf_model_identity_valid: bool
    rf_supply_chain_verified: bool
    total_samples: int
    threshold: float
    tp: int
    fp: int
    tn: int
    fn: int
    accuracy_pct: float
    precision_pct: float
    recall_pct: float
    f1_pct: float
    fpr_pct: float
    precision_ci_95: tuple[float, float]
    recall_ci_95: tuple[float, float]
    bootstrap_iterations: int
    random_seed: int
    is_synthetic_smoke_fixture: bool
    protocol_violation_inspected_split: bool
    tf_008_closure_eligible: bool
    closure_eligibility_rationale: str
    evaluated_at_utc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "dataset_id": self.dataset_id,
            "dataset_sha256": self.dataset_sha256,
            "dataset_sha256_valid": self.dataset_sha256_valid,
            "rf_model_version": self.rf_model_version,
            "rf_model_sha256": self.rf_model_sha256,
            "rf_model_identity_valid": self.rf_model_identity_valid,
            "rf_supply_chain_verified": self.rf_supply_chain_verified,
            "total_samples": self.total_samples,
            "threshold": self.threshold,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "accuracy_pct": self.accuracy_pct,
            "precision_pct": self.precision_pct,
            "recall_pct": self.recall_pct,
            "f1_pct": self.f1_pct,
            "fpr_pct": self.fpr_pct,
            "precision_ci_95": list(self.precision_ci_95),
            "recall_ci_95": list(self.recall_ci_95),
            "bootstrap_iterations": self.bootstrap_iterations,
            "random_seed": self.random_seed,
            "is_synthetic_smoke_fixture": self.is_synthetic_smoke_fixture,
            "protocol_violation_inspected_split": self.protocol_violation_inspected_split,
            "tf_008_closure_eligible": self.tf_008_closure_eligible,
            "closure_eligibility_rationale": self.closure_eligibility_rationale,
            "evaluated_at_utc": self.evaluated_at_utc,
        }


def evaluate_independent_holdout_dataset(
    *,
    dataset_id: str,
    dataset_sha256: str,
    y_true: Sequence[int],
    rf_probabilities: Sequence[float],
    is_synthetic_smoke_fixture: bool = True,
    bootstrap_iterations: int = 200,
    random_seed: int = 42,
    rf_model_version: str = AUTHORIZED_RF_MODEL_VERSION,
    rf_model_sha256: str = AUTHORIZED_RF_MODEL_SHA256,
    repo_root: Path | None = None,
) -> IndependentHoldoutEvaluationReport:
    """Pre-registered independent holdout evaluation harness for TF-008.

    Parameters:
        dataset_id: Identifier of the holdout dataset.
        dataset_sha256: SHA-256 digest of the dataset file or manifest (must be valid 64-hex).
        y_true: Ground truth binary labels (0 for Normal, 1 for Attack).
        rf_probabilities: Predicted attack probabilities from frozen Random Forest.
        is_synthetic_smoke_fixture: When True, prevents automated test runs from closing TF-008.
        bootstrap_iterations: Number of bootstrap iterations for 95% confidence intervals (>= 1, closure requires >= 200).
        random_seed: PRNG seed for deterministic bootstrap reproducibility (default 42).
        rf_model_version: Registered version string of the frozen Random Forest.
        rf_model_sha256: Canonical SHA-256 digest of the frozen Random Forest joblib artifact.
        repo_root: Optional repository root to verify live frozen model supply-chain integrity.

    Returns:
        IndependentHoldoutEvaluationReport containing exact confusion counts,
        calibrated performance metrics, and deterministic 95% bootstrap CIs.
    """
    # 1. Validate bootstrap_iterations
    if (
        not isinstance(bootstrap_iterations, int)
        or isinstance(bootstrap_iterations, bool)
        or bootstrap_iterations < 1
    ):
        raise ValueError("bootstrap_iterations must be an integer >= 1")

    # 2. Validate dataset_sha256
    if not isinstance(dataset_sha256, str) or not dataset_sha256.strip():
        raise ValueError("dataset_sha256 must be a non-empty string")

    clean_sha256 = dataset_sha256.strip().lower()
    is_valid_sha256_format = bool(re.fullmatch(r"[0-9a-f]{64}", clean_sha256))
    is_inspected_sha256 = clean_sha256 in INSPECTED_DEVELOPMENT_DATASET_SHA256S
    dataset_sha256_valid = is_valid_sha256_format and not is_inspected_sha256

    # 3. Validate y_true and rf_probabilities lengths and values
    total = len(y_true)
    if total == 0:
        raise ValueError("y_true sequence must not be empty")
    if total != len(rf_probabilities):
        raise ValueError(
            f"Length mismatch: len(y_true)={total} != len(rf_probabilities)={len(rf_probabilities)}"
        )

    for idx, (yt, prob) in enumerate(zip(y_true, rf_probabilities, strict=True)):
        if yt not in (0, 1):
            raise ValueError(f"Invalid label at index {idx}: {yt} must be 0 or 1")
        if not (isinstance(prob, (int, float)) and math.isfinite(prob) and 0.0 <= prob <= 1.0):
            raise ValueError(f"Invalid probability at index {idx}: {prob} must be in [0.0, 1.0]")

    # 4. Check for Protocol Violation: Inspected Development Split (ID or SHA-256)
    is_inspected = (dataset_id in INSPECTED_DEVELOPMENT_DATASET_IDS) or is_inspected_sha256

    # 5. Bind and Validate Frozen RF Model Identity and Supply Chain
    rf_identity_valid = (
        rf_model_version == AUTHORIZED_RF_MODEL_VERSION
        and rf_model_sha256 == AUTHORIZED_RF_MODEL_SHA256
    )

    if repo_root is not None:
        from threatfusion.models.drift_and_supply_chain import verify_frozen_model_supply_chain

        sc_report = verify_frozen_model_supply_chain(Path(repo_root), fail_closed=False)
        rf_supply_chain_verified = bool(sc_report.get("passed") or sc_report.get("verified"))
    else:
        rf_supply_chain_verified = False

    # Compute Confusion Matrix at frozen 0.50 threshold
    threshold = FROZEN_RF_DECISION_THRESHOLD
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for yt, prob in zip(y_true, rf_probabilities, strict=True):
        pred = 1 if prob >= threshold else 0
        if yt == 1 and pred == 1:
            tp += 1
        elif yt == 0 and pred == 1:
            fp += 1
        elif yt == 0 and pred == 0:
            tn += 1
        else:
            fn += 1

    accuracy_pct = round(((tp + tn) / total) * 100.0, 3) if total > 0 else 0.0
    precision_pct = round((tp / (tp + fp)) * 100.0, 3) if (tp + fp) > 0 else 0.0
    recall_pct = round((tp / (tp + fn)) * 100.0, 3) if (tp + fn) > 0 else 0.0
    f1_pct = (
        round((2.0 * precision_pct * recall_pct) / (precision_pct + recall_pct), 3)
        if (precision_pct + recall_pct) > 0
        else 0.0
    )
    fpr_pct = round((fp / (fp + tn)) * 100.0, 3) if (fp + tn) > 0 else 0.0

    # Deterministic 95% Bootstrap Confidence Intervals
    boot_precisions: list[float] = []
    boot_recalls: list[float] = []
    rng = random.Random(random_seed)
    pairs = list(zip(y_true, rf_probabilities, strict=True))

    for _ in range(bootstrap_iterations):
        sample_tp = 0
        sample_fp = 0
        sample_tn = 0
        sample_fn = 0

        for _ in range(total):
            yt_samp, prob_samp = pairs[rng.randrange(total)]
            pred_samp = 1 if prob_samp >= threshold else 0
            if yt_samp == 1 and pred_samp == 1:
                sample_tp += 1
            elif yt_samp == 0 and pred_samp == 1:
                sample_fp += 1
            elif yt_samp == 0 and pred_samp == 0:
                sample_tn += 1
            else:
                sample_fn += 1

        s_prec = (
            (sample_tp / (sample_tp + sample_fp) * 100.0) if (sample_tp + sample_fp) > 0 else 0.0
        )
        s_rec = (
            (sample_tp / (sample_tp + sample_fn) * 100.0) if (sample_tp + sample_fn) > 0 else 0.0
        )
        boot_precisions.append(s_prec)
        boot_recalls.append(s_rec)

    boot_precisions.sort()
    boot_recalls.sort()

    lo_idx = max(0, int(0.025 * (bootstrap_iterations - 1)))
    hi_idx = min(bootstrap_iterations - 1, int(0.975 * (bootstrap_iterations - 1)))

    precision_ci_95 = (round(boot_precisions[lo_idx], 3), round(boot_precisions[hi_idx], 3))
    recall_ci_95 = (round(boot_recalls[lo_idx], 3), round(boot_recalls[hi_idx], 3))

    # Determine TF-008 Closure Eligibility
    # All criteria must hold simultaneously:
    # (a) not is_synthetic_smoke_fixture
    # (b) not protocol_violation_inspected_split
    # (c) total_samples >= 1000
    # (d) bootstrap_iterations >= 200
    # (e) dataset_sha256 is valid 64-hex and not inspected
    # (f) rf_model identity valid and supply-chain verified if repo_root provided
    reasons_ineligible: list[str] = []
    if is_inspected:
        reasons_ineligible.append(
            f"Protocol violation: dataset_id '{dataset_id}' or dataset_sha256 matches "
            "previously inspected development split; TF-008 requires an untouched independent holdout benchmark"
        )
    if is_synthetic_smoke_fixture:
        reasons_ineligible.append(
            "Synthetic smoke fixture: automated integration and smoke test runs cannot close TF-008; "
            "requires formal external holdout evaluation"
        )
    if total < MIN_INDEPENDENT_SAMPLES_FOR_CLOSURE:
        reasons_ineligible.append(
            f"Sample size {total} < {MIN_INDEPENDENT_SAMPLES_FOR_CLOSURE} required for "
            "statistically significant holdout benchmarking"
        )
    if bootstrap_iterations < MIN_BOOTSTRAP_ITERATIONS_FOR_CLOSURE:
        reasons_ineligible.append(
            f"Bootstrap iterations {bootstrap_iterations} < {MIN_BOOTSTRAP_ITERATIONS_FOR_CLOSURE} "
            "pre-registered protocol minimum"
        )
    if not is_valid_sha256_format:
        reasons_ineligible.append(
            "dataset_sha256 is not a valid 64-character hexadecimal SHA-256 digest"
        )
    elif is_inspected_sha256:
        reasons_ineligible.append(
            "dataset_sha256 matches a known inspected development split digest"
        )
    if not rf_identity_valid:
        reasons_ineligible.append(
            f"Random Forest model identity mismatch (version='{rf_model_version}', sha256='{rf_model_sha256}')"
        )
    if repo_root is None:
        reasons_ineligible.append(
            "repo_root was not provided; on-disk frozen model supply-chain verification is mandatory for TF-008 closure"
        )
    elif not rf_supply_chain_verified:
        reasons_ineligible.append(
            "Frozen model supply-chain verification failed on specified repo_root"
        )

    if not reasons_ineligible:
        closure_eligible = True
        rationale = "Candidate meets pre-registered independent holdout evaluation criteria for TF-008 review."
    else:
        closure_eligible = False
        rationale = "; ".join(reasons_ineligible)

    return IndependentHoldoutEvaluationReport(
        schema_version=INDEPENDENT_HOLDOUT_SCHEMA_VERSION,
        dataset_id=dataset_id,
        dataset_sha256=clean_sha256,
        dataset_sha256_valid=dataset_sha256_valid,
        rf_model_version=rf_model_version,
        rf_model_sha256=rf_model_sha256,
        rf_model_identity_valid=rf_identity_valid,
        rf_supply_chain_verified=rf_supply_chain_verified,
        total_samples=total,
        threshold=threshold,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        accuracy_pct=accuracy_pct,
        precision_pct=precision_pct,
        recall_pct=recall_pct,
        f1_pct=f1_pct,
        fpr_pct=fpr_pct,
        precision_ci_95=precision_ci_95,
        recall_ci_95=recall_ci_95,
        bootstrap_iterations=bootstrap_iterations,
        random_seed=random_seed,
        is_synthetic_smoke_fixture=is_synthetic_smoke_fixture,
        protocol_violation_inspected_split=is_inspected,
        tf_008_closure_eligible=closure_eligible,
        closure_eligibility_rationale=rationale,
        evaluated_at_utc=datetime.now(UTC).isoformat(),
    )
