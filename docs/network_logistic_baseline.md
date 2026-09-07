# Initial supervised network baseline

This experiment is the first explicitly authorized supervised model over ThreatFusion's verified
UNSW development assignment. It is deliberately limited to one logistic regression and one
always-benign reference. It neither changes global readiness nor authorizes host, deep-learning,
February test, or CIC training/evaluation.

## Why logistic regression comes first

Logistic regression provides a small, deterministic, interpretable probability baseline for the
14-column `network_behavior_v1` transformed interface. It establishes whether the frozen features
carry useful linear signal before introducing model-family or tuning complexity. The paired
always-benign reference exposes the effect of class imbalance: because attacks are rare, a model
that never detects an attack can still report high ordinary accuracy. Attack recall, precision,
F1, balanced accuracy, average precision, ROC-AUC, and false-positive rate must therefore be read
alongside accuracy.

The configuration is frozen before validation performance is viewed:

- L2 regularization, `C=1.0`, `solver="lbfgs"`, `fit_intercept=True`, `class_weight=None`,
  `max_iter=1000`, and `tol=1e-4`;
- Attack is label `1`, Normal is label `0`, and `P(Attack) >= 0.5` predicts Attack;
- no rebalancing, resampling, hyperparameter search, calibration, feature selection, or threshold
  tuning;
- no subsampling and at most four numerical-library threads.

scikit-learn 1.9 deprecates the explicit `penalty` argument. The implementation records the frozen
L2 request and uses that installed version's supported equivalent: its default penalty sentinel
with `l1_ratio=0.0`. All estimator parameters returned by `get_params()` are recorded in the run
configuration.

## Inputs and integrity

The only inputs are the existing memory-mapped TRAIN and VALIDATION arrays in
`data/processed/unsw_network_preprocessing/full-train-only-0141bde-v1/`. Before fitting, the runner
requires a completed preprocessing report; exact contract and transformed feature order; stable
label mapping; TRAIN-only fitted state; exact shapes and class counts; successful prior integrity
checks; and matching SHA-256 hashes for the preprocessing configuration, state, and four arrays.
It reloads the saved preprocessing state only to validate it and never refits or modifies it.

The runner also verifies every matrix value is finite and every label is exactly zero or one. It
records the upstream source-manifest, assignment, preflight, preprocessing-state, feature-order,
and matrix provenance. Missing, partial, corrupt, reordered, or inconsistent evidence fails before
training.

## Evaluation definitions

The logistic model fits once on all assigned TRAIN records. Validation labels are passed only to
aggregate evaluation after fitting. The always-benign reference uses constant zero Attack scores
and therefore predicts no attacks at the inclusive 0.5 threshold.

For each predictor, the sanitized report includes TP, FP, TN, FN, attack precision/recall/F1,
false-positive rate, balanced and ordinary accuracy, predicted-attack count/percentage, average
precision from continuous scores, and ROC-AUC from continuous scores. Average precision is the
non-interpolated ranking summary implemented by scikit-learn; it is not called trapezoidal PR-AUC.

When a denominator is zero, precision, recall, F1, false-positive rate, and ordinary accuracy use
`0.0`. Average precision is `0.0` when there are no positive labels. Balanced accuracy and ROC-AUC
are `null` unless both classes are present.

## Reproducibility and scope

The CLI performs a tiny synthetic smoke fit first, estimates fit memory including mapped inputs,
estimator and solver copies, label working space, and fixed overhead, checks available RAM and
disk, then writes the frozen configuration before the full fit. Model execution is wrapped in a
four-thread limit. A fresh ignored directory under `artifacts/models/network_logistic_baseline/`
stores the joblib model, configuration, timings, convergence details, provenance, and sanitized
aggregate validation report. Individual predictions and feature rows are never saved. The model is
reloaded and its probabilities and thresholded predictions must exactly match on a bounded
validation sample.

Run from the repository root with the locked environment:

```bash
uv sync --locked --dev
.venv/bin/python scripts/train_network_logistic_baseline.py --run-id <fresh-run-id>
```

Run completion and optimizer convergence are separate fields. A convergence warning or iteration
limit is preserved in the report and is never followed by automatic tuning.

## Scientific limitations

Validation is grouped development data, while February remains a later-period test that this phase
does not transform or inspect. CIC remains external evaluation only. Exact feature collisions and
conflicting labels remain in the frozen assignment; near-duplicate leakage is unassessed; and
capture/session provenance remains unresolved. These constraints limit conclusions from validation
performance. Host training remains blocked, and this network-only experiment does not weaken or
change any readiness gate.
