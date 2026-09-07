# Fixed Random Forest network baseline

This is one explicitly authorized network-only development experiment. It compares a fixed Random
Forest against the already saved logistic-regression baseline and always-benign reference on the
same grouped UNSW VALIDATION partition. It does not alter preprocessing, split assignments,
February/CIC isolation, host readiness, or global readiness gates.

## Frozen model

The configuration is fixed before viewing Random Forest validation performance:

- 100 trees using Gini impurity;
- maximum depth 16;
- minimum split size 2 and minimum leaf size 5;
- square-root feature sampling;
- bootstrap enabled with `max_samples=None`;
- no class weighting;
- random state 42 and four forest workers;
- no out-of-bag scoring, warm start, or pruning (`ccp_alpha=0.0`).

Internal bootstrap sampling is part of this estimator. It does not remove records from the eligible
dataset: fitting receives all 865,480 TRAIN rows. There is no external resampling, weighting,
hyperparameter search, calibration, threshold tuning, or feature selection. Attack is label 1 and
the fixed decision rule is `P(Attack) >= 0.5`, resolved through the fitted `classes_` array.

## Verified inputs and comparison

The runner calls the logistic baseline's existing preprocessing verifier. It checks the completed
preprocessing report, state and configuration hashes, source/assignment provenance, exact 14-field
order, memory-mapped array hashes/shapes/dtypes, finite values, label mapping, and TRAIN/VALIDATION
class counts. It reloads but never refits the preprocessing state. No raw dataset is opened.

Prior logistic and always-benign metrics are loaded only after verifying that the historical model
configuration and report use the same preprocessing state/configuration/report hashes, transformed
feature order, validation row/class counts, `Normal=0`/`Attack=1` mapping, and inclusive 0.5
threshold. The saved logistic model's size and SHA-256 hash are also checked. A mismatch stops the
comparison rather than mixing experiments.

Evaluation reuses the established metric implementation: confusion counts, attack
precision/recall/F1, false-positive rate, balanced and ordinary accuracy, non-interpolated average
precision, ROC-AUC, and predicted-attack count/percentage. Average precision and ROC-AUC use
continuous Attack scores. No individual score, prediction, or feature row is saved.

## Resource and artifact controls

Before fitting, the runner estimates memory for the mapped matrix, estimator input copy, four
parallel workers, label workspace, fixed overhead, and a conservative tree-storage bound derived
from the frozen depth and leaf size. Available RAM and disk must cover the estimate plus fixed
reserves; the model is never silently reduced. Forest workers remain four while nested numerical
libraries are limited to one thread. Validation prediction runs in deterministic batches of 25,000
rows.

A tiny synthetic smoke precedes the single full fit. The fresh ignored run beneath
`artifacts/models/network_random_forest_baseline/` contains the frozen/effective configuration,
model, source/preprocessing/comparison hashes, dependencies, timings, resource observations,
working-tree provenance, aggregate comparison report, and tree depth/node-count summaries. Reloaded
thresholded predictions must be exactly equal on a bounded validation sample. Parallel tree-score
accumulation may vary at floating-point roundoff scale, so reloaded probabilities use zero relative
tolerance and an absolute tolerance of `1e-15`; the observed maximum difference is recorded.

Run with the repository environment:

```bash
.venv/bin/python scripts/train_network_random_forest_baseline.py --run-id <fresh-run-id>
```

## Interpretation limits

Results are grouped development-validation evidence only. February remains untouched later-period
testing, and CIC remains untouched external evaluation. Exact feature collisions and conflicting
labels remain in the frozen assignment; near-duplicate leakage and capture/session provenance are
unresolved. A validation advantage does not establish future-period or cross-dataset performance.
Host model training remains blocked, and this experiment does not change global readiness.
