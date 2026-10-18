# Pre-Registered Independent Holdout Evaluation Protocol for TF-008

**Protocol Identifier:** `TF-008-PREREGISTERED-HOLDOUT-PROTOCOL-V1`  
**Schema Version:** `independent_holdout_evaluation_report_v1`  
**Governing Issue:** [TF-008 (`docs/issue_register.md`)](file:///home/muhammad-bilal/projects/threatfusion-gemini/docs/issue_register.md#L28)  
**Status:** Canonical Pre-Registered Protocol Specification (Issue TF-008 remains strictly **OPEN**)  
**Last Updated:** 2026-10-18  

---

## 1. Scientific Context & Disqualification of Inspected Splits

In academic machine learning and security operations evaluation, evaluating a trained detector on previously inspected data introduces subtle selection bias, threshold over-calibration, and optimistic generalization claims.

In the ThreatFusion project:
1. **UNSW-NB15 TRAIN** (`865,480` rows) was used for model fitting.
2. **UNSW-NB15 January Validation** (`216,568` rows) was inspected during baseline calibration, precision-recall optimization, and autoencoder threshold calibration.
3. **UNSW-NB15 February Test** (`1,452,844` rows) was inspected during Milestone #15/16 classical model evaluations and autoencoder overlap residual studies.

Per Protocol 0 and `docs/product_charter.md`, **neither January nor February UNSW splits can be claimed as an untouched independent holdout benchmark**.

### Inspected Development Split Blacklist
The evaluation harness strictly blacklists the following identifiers:
```python
INSPECTED_DEVELOPMENT_DATASET_IDS: tuple[str, ...] = (
    "unsw_nb15_train_865480",
    "unsw_nb15_january_216568",
    "unsw_nb15_february_1452844",
)
```
Any evaluation submitted with a dataset ID matching this blacklist is immediately flagged with:
- `protocol_violation_inspected_split = True`
- `tf_008_closure_eligible = False`

---

## 2. Pre-Registered Holdout Evaluation Protocol Invariants

To satisfy the formal closure requirements for TF-008, any future benchmark run must satisfy all of the following frozen invariants:

### A. Immutable Production Model Authority
- **Authorized Detector:** Frozen 100-tree Random Forest (`network_random_forest_baseline_v1`).
- **Required Artifact Digest:** `bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9`.
- **Decision Threshold:** Strictly frozen at `P(Attack) >= 0.5000`. Zero post-hoc threshold adjustment is permitted.
- **Weights:** Strictly read-only; zero retraining or parameter adjustment.

### B. Statistical Significance & Sample Size
- **Minimum Sample Size:** $N \ge 1,000$ independent, previously uninspected network flow records (`MIN_INDEPENDENT_SAMPLES_FOR_CLOSURE = 1000`).
- **Ground Truth Isolation:** Ground truth labels must be independently authenticated and verified via cryptographic checksum.
- **Bootstrap Confidence Intervals:** Deterministic 95% two-sided bootstrap confidence intervals computed across at least $B = 200$ iterations using standard PRNG (`random.Random(random_seed)`).

### C. Synthetic vs. Production Separation
- Automated CI unit tests, integration tests, and smoke test suites MUST set `is_synthetic_smoke_fixture = True`.
- Automated smoke fixtures are programmatically disqualified from closing TF-008 (`tf_008_closure_eligible = False`).

---

## 3. Cryptographic Evaluation Report Schema

Every evaluation produces an immutable `IndependentHoldoutEvaluationReport` receipt:

| Field | Type | Description |
|---|---|---|
| `schema_version` | `str` | `"independent_holdout_evaluation_report_v1"` |
| `dataset_id` | `str` | Unique benchmark identifier (must not match inspected blacklist) |
| `dataset_sha256` | `str` | Cryptographic SHA-256 digest of the dataset artifact or manifest |
| `dataset_sha256_valid` | `bool` | True iff valid 64-char lowercase hex SHA-256 and not inspected split |
| `rf_model_version` | `str` | Bound frozen Random Forest model version string |
| `rf_model_sha256` | `str` | Canonical SHA-256 digest of the frozen Random Forest joblib |
| `rf_model_identity_valid` | `bool` | True iff version and SHA-256 match authorized baseline |
| `rf_supply_chain_verified` | `bool` | True iff model supply-chain checks pass |
| `total_samples` | `int` | Total evaluated flow records ($N \ge 1,000$ required for closure) |
| `threshold` | `float` | Decision threshold (strictly `0.50`) |
| `tp`, `fp`, `tn`, `fn` | `int` | Exact confusion matrix counts |
| `accuracy_pct` | `float` | Overall test accuracy percentage |
| `precision_pct` | `float` | Precision percentage $TP / (TP + FP) \times 100$ |
| `recall_pct` | `float` | Recall percentage $TP / (TP + FN) \times 100$ |
| `f1_pct` | `float` | Harmonic mean $F_1$ score percentage |
| `fpr_pct` | `float` | False positive rate $FP / (FP + TN) \times 100$ |
| `precision_ci_95` | `(float, float)` | 95% bootstrap confidence interval for precision |
| `recall_ci_95` | `(float, float)` | 95% bootstrap confidence interval for recall |
| `bootstrap_iterations` | `int` | Bootstrap iterations ($\ge 200$ required for closure) |
| `random_seed` | `int` | PRNG seed for deterministic reproducibility |
| `is_synthetic_smoke_fixture` | `bool` | Disqualifies automated smoke fixtures from closure |
| `protocol_violation_inspected_split` | `bool` | Flags previously inspected January/February splits |
| `tf_008_closure_eligible` | `bool` | `True` iff non-inspected, non-synthetic, $N \ge 1,000$, $B \ge 200$, valid 64-hex SHA-256, and valid RF identity |
| `closure_eligibility_rationale` | `str` | Transparent audit justification |
| `evaluated_at_utc` | `str` | ISO 8601 UTC timestamp of evaluation |

---

## 4. Algorithmic Implementation Reference

The canonical implementation resides in `backend/src/threatfusion/evaluation/independent_holdout_protocol.py`:

```python
from threatfusion.evaluation.independent_holdout_protocol import (
    INSPECTED_DEVELOPMENT_DATASET_IDS,
    IndependentHoldoutEvaluationReport,
    evaluate_independent_holdout_dataset,
)

# Example: Evaluating an untouched external holdout dataset
report = evaluate_independent_holdout_dataset(
    dataset_id="cse_cic_ids2018_holdout_subset_v1",
    dataset_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    y_true=holdout_labels,
    rf_probabilities=rf_predictions,
    is_synthetic_smoke_fixture=False,
    bootstrap_iterations=200,
    random_seed=42,
    repo_root=Path("."),
)

assert report.protocol_violation_inspected_split is False
assert report.tf_008_closure_eligible is True
print(f"95% Recall CI: {report.recall_ci_95}")
print(f"95% Precision CI: {report.precision_ci_95}")
```

---

## 5. Governance Disposition for TF-008

The deployment of this pre-registered evaluation protocol provides the **prerequisite scientific harness** to evaluate an untouched external holdout benchmark without leakage or selection bias.

However, in strict compliance with Protocol 0, **TF-008 remains OPEN** until:
1. An authentic, non-synthetic external holdout benchmark dataset (such as an authorized CSE-CIC-IDS2018 subset or enterprise partner capture) is acquired and verified on disk.
2. The benchmark evaluation is executed and achieves verified generalization without inspected-split contamination.
3. The resulting signed evaluation report is reviewed and approved by the supervisor and FYP-II jury.
