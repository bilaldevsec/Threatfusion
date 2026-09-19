# Benign-only UNSW network autoencoder protocol

## Status, scope, and purpose

This began as the frozen pre-implementation protocol for one bounded UNSW-NB15 autoencoder experiment. It
defines the inputs, model, calibration rule, evaluation, artifacts, resource controls, and failure
behavior before any score is calculated. It does not authorize or perform dependency installation,
did not itself authorize model fitting, tuning, dataset evaluation, artifact replacement, or product
integration. Separate authorization for exactly one corrected v2 baseline was received on 2026-09-15;
the architecture, fit population, hyperparameters, preprocessing, scoring contract, calibration rule,
and resource limits below remain frozen.

The proposed model is a complementary reconstruction-anomaly detector. It is not a replacement for
the frozen logistic-regression or Random Forest classifiers. Reconstruction error is neither an attack
probability nor calibrated confidence. The experiment carries no guaranteed-improvement, zero-day
detection, operational usefulness, or supported cross-source claim.

The directly affected open issues remain visible: TF-006 (near-duplicate and capture/session evidence),
TF-007 (known February/CIC outcomes), TF-010 (unverified complete jury model list), TF-011 (no approved
operational target), TF-012/TF-003/TF-002 (CIC incompatibility and qualification), and TF-008/TF-009
(product integration and reliability). TF-015 records the missing project-local PyTorch prerequisite.
None is resolved or accepted by this protocol.

## Verified preflight evidence

The worktree and index were clean at preflight start. `HEAD` and `origin/main` both resolved to
`255c34286c9f98b995d18dce396be8c106b91f18`.

### Registered source and split identity

Only the four registered headerless raw members, interpreted with the registered 49-field metadata,
are the source of the existing assignment and processed matrices:

| Registered member | Rows | SHA-256 |
|---|---:|---|
| `UNSW-NB15_1.csv` | 700,001 | `7d851bbeabd27894ce39c8e78835c73341fc946652fb7743b9eff193b55eb511` |
| `UNSW-NB15_2.csv` | 700,001 | `6130ad02873cc6069ae695cf2844f2e8c2e9a9a1b7532dd82ab8f202757cacf8` |
| `UNSW-NB15_3.csv` | 700,001 | `ae990a96c3dfcd425ce2801aadb1727a34d5e0ae6d8215dbcdae60dedfaef640` |
| `UNSW-NB15_4.csv` | 440,044 | `cdf563692d51d405541dd659ddcdad9fa01f001f05fe9fc4b67f00ca12fbc96a` |

The source manifest SHA-256 is
`c6794cab5af9de5bf218989461b2ad673d1a14232688edf46aed1c63bc6e60e1`. The published
`UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` are registered files but are not inputs to
this assignment or experiment.

The verified assignment is
`data/interim/unsw_development_split/full-assignment-f10992-v1/` with schema
`unsw_development_split_v1`, seed `threatfusion-unsw-dev-split-v1`, report SHA-256
`6913c1f2ef974d0b969506daf2b091a740fbf0d6b43d231a6f64f30841436857`, archive SHA-256
`154829274f1a2d594086c6a73db6fce7b585ffeba58632dfce08422c1b187dc9`, and preflight-report SHA-256
`f805424dc5f39ca41f7b1935b25938307d2e15c18caa008b3a1ca9250b8ab384`. Its enforced groups combine
exact ordered 49-field source equality and connected closed-interval overlap for the
direction-normalized endpoint-pair/protocol identity. The audit reports zero enforced groups crossing
model splits.

| Disposition | Normal | Attack | Total |
|---|---:|---:|---:|
| TRAIN | 847,837 | 17,643 | 865,480 |
| VALIDATION | 212,210 | 4,358 | 216,568 |
| February TEST | 1,153,776 | 299,068 | 1,452,844 |
| Quarantine | 4,931 | 214 | 5,145 |
| Rejected | unknown | unknown | 10 |

Model weights receive exactly the 847,837 TRAIN rows whose saved label is `Normal=0`. TRAIN attacks
must not reach the optimizer. Selection is an order-preserving `y_train == 0` view over the verified
TRAIN artifacts before deterministic epoch shuffling. It does not create a new split or change an
enforced group. VALIDATION remains the existing January grouped-development partition. February TEST,
CIC, quarantine, rejected records, and the published pre-partitioned CSVs are ineligible for weight
fitting.

### Exact processed inputs

The baseline reuses only the approved processed run
`data/processed/unsw_network_preprocessing/full-train-only-0141bde-v1/`:

| Input | Shape and dtype | SHA-256 | Permitted use |
|---|---|---|---|
| `X_train.npy` | `(865480, 14)`, `float64` | `56563f752bba2c7b01f2fa35c4c6927f90d0c83dd6e06c25c9b23cbf2bd2ca81` | Benign rows only for weight fitting |
| `y_train.npy` | `(865480,)`, `uint8` | `f12ba5c05db37d5c34bf7f22fa62d41535bdeaab58014bdd3975d50c21a24209` | Benign filter and count reconciliation |
| `X_validation.npy` | `(216568, 14)`, `float64` | `573993809be67edf8a6e5e4b4683d9254e9da4188aca97918d0ceac01ee487d6` | January threshold calibration and development assessment |
| `y_validation.npy` | `(216568,)`, `uint8` | `38d87b7c7fbf27a59228a2a84f3f4eca4e026acedc4e4aa3626da28292dd467b` | Calibration filter and development metrics |

The completed preprocessing report, state, and configuration hashes are respectively
`d1688079b9cbcf521a8b9938ea07b540321e11edd70236452720fbd2f1697e4a`,
`30c955e3931dc010f8b4391a80fc0fbeddd17e14260701c8131d88f95b06ee49`, and
`70273ec360e0bce88b5ec8311df4b5b8ccbbdbe6c456d8a679528563d477645a`.
The later runner must verify every named file, hash, shape, dtype, count, completion flag, assignment
binding, and finite-value check before it creates a model run.

### Environment and dependency preflight

The project `.venv` is Python 3.11.16 on Linux x86_64. It contains NumPy 2.4.6, pandas 2.3.3,
Pydantic 2.13.5, scikit-learn 1.9.0, joblib 1.6.0, and threadpoolctl 3.6.0. PyTorch is not importable,
has no installed version, and is not declared by `pyproject.toml` or `uv.lock`. Consequently, no
PyTorch CPU instruction-set behavior, CUDA build, GPU visibility, or accelerator compatibility has
been verified. Packages in any other environment are irrelevant.

The inspected workstation exposed 12 logical CPUs, approximately 15.3 GiB total RAM, 10.7 GiB
available RAM, and 66.9 GiB available workspace storage. These are point-in-time observations, not
capacity guarantees. Before implementation or execution, an exact Python 3.11/Linux x86_64 PyTorch
CPU build must be selected, declared, lock-resolved, installed into this `.venv`, and recorded under
separate authorization. A CPU tensor, autograd, deterministic-operation, save, `weights_only` load,
and reload-inference smoke must pass. The frozen baseline does not use a GPU even if one later exists.

## Approved preprocessing contract

The autoencoder reuses the saved `network_behavior_v1_preprocessing_v1` transformation unchanged. Its
14-column order is:

1. `duration_ms__zscore`
2. `fwd_packets__zscore`
3. `bwd_packets__zscore`
4. `fwd_bytes__zscore`
5. `bwd_bytes__zscore`
6. `packets_per_second__zscore`
7. `bytes_per_second__zscore`
8. `fwd_packet_length_mean__zscore`
9. `bwd_packet_length_mean__zscore`
10. `dst_port__zscore`
11. `protocol=tcp`
12. `protocol=udp`
13. `protocol=icmp`
14. `protocol=other`

The first ten columns use population z-scores whose means and scales were fitted on all 865,480
TRAIN records, including 847,837 Normal and 17,643 Attack records. The four protocol columns use the
fixed contract vocabulary, not a learned vocabulary. No clipping, imputation, log transform, feature
selection, PCA, resampling, or outlier removal is added. Benign-only autoencoder weight fitting must
never be described as benign-only preprocessing.

This choice preserves the approved transform and permits exact record-matched comparison with the
frozen classifiers. Any later proposal to fit statistics on benign TRAIN alone or otherwise change the
transform is a different, explicitly versioned experiment. It must write a fresh state and requirements
identity, must not overwrite this run, and cannot be substituted into this baseline after results are
known.

## Frozen baseline

### Architecture and optimization

The only proposed architecture is a fully connected autoencoder with 305 trainable parameters:

`14 -> Linear(14, 8) -> ReLU -> Linear(8, 3) -> ReLU -> Linear(3, 8) -> ReLU -> Linear(8, 14)`

All linear layers include a bias. The three-unit layer is the explicit bottleneck. The output is linear
because standardized numeric values are unbounded; applying a sigmoid would incorrectly constrain
their reconstruction. The same linear output reconstructs the fixed one-hot columns so that one exact
score formula covers the frozen 14-column interface. There is no dropout, batch normalization,
regularization layer, sequence layer, temporal window, or artificial row sequence.

The frozen fit is:

- device CPU only; model/input dtype `float32`; no automatic mixed precision;
- seed 42 for Python, NumPy, PyTorch, and the data-loader generator;
- deterministic PyTorch algorithms required, four intra-operation threads, one inter-operation
  thread, `DataLoader(num_workers=0, pin_memory=False)`;
- Xavier-uniform hidden-layer weights with ReLU gain, Xavier-uniform output weights with linear gain,
  and all biases zero, initialized only after the seed is set;
- batch size 1,024, deterministic seeded shuffle of benign TRAIN indices each epoch, and no dropped
  final batch;
- mean squared error averaged over samples and all 14 columns;
- Adam with learning rate `0.001`, `betas=(0.9, 0.999)`, `eps=1e-8`, `weight_decay=0`, and
  `amsgrad=False`;
- exactly 30 complete epochs, with the epoch-30 weights saved; no early stopping, scheduler,
  checkpoint choice, retry, continuation, or automatic response to loss;
- no architecture, bottleneck, initialization, optimizer, learning-rate, batch-size, epoch, seed, or
  preprocessing sweep.

No VALIDATION, February, or CIC value influences initialization, gradients, epoch choice, model
selection, or architecture. A non-finite loss, incomplete epoch, timeout, or resource breach fails the
run; it does not trigger a retry with changed settings.

### Resource controls

The implementation must memory-map existing arrays, retain at most one 1,024-row float32 feature
batch, its activations/gradients, bounded counters, and the approximately 6.8 MiB benign-index vector.
It must not materialize a full matrix copy or load raw CSVs. Before fitting, a conservative memory
estimate must fit beneath a 2 GiB peak-RSS ceiling while preserving at least 2 GiB of reported
`MemAvailable`. Execution has a 3,600-second monotonic wall-clock deadline checked between batches and
epochs, a 256 MiB run-artifact budget, a 2 GiB free-space reserve, and no GPU allocation. Peak RSS,
elapsed time, processed rows per epoch, and artifact bytes are recorded. An unavailable resource probe
or failed gate stops before fitting.

These are experiment bounds, not throughput or production claims. They may be revised only through a
new protocol version before observing results, never silently at runtime.

### Reproducibility, serialization, and identity

A fresh ignored directory under `artifacts/models/network_autoencoder/<run-id>/` must be immutable and
must never overwrite an existing run. Before fitting, write a canonical configuration binding the
architecture, optimization, seed, score/threshold policies, resource limits, exact dependency and
platform versions, Git state, all upstream hashes, feature order, counts, and exclusion rules.

Save only the final tensor `state_dict` in `autoencoder_state.pt`; do not pickle a module and do not
save optimizer state for continuation. Load with the exact locked PyTorch runtime,
`weights_only=True`, and `map_location="cpu"` into code-constructed architecture. Hash the exact
weight bytes. Store the selected threshold and its calibration evidence separately in canonical JSON,
then bind its hash into the completed aggregate report.

The model identity is `unsw_network_benign_autoencoder_v1`; the detector identity is
`threatfusion.unsw_network_reconstruction_anomaly` version `v1`; the preprocessing requirements
identity is `unsw_train.network_behavior_v1_preprocessing_v1.14_columns.benign_autoencoder.v1`; and
the score identity is `mean_squared_reconstruction_error_14_v1`. The durable artifact identity is a
SHA-256 over a domain-separated canonical manifest containing those identities, the configuration
hash, weights hash, threshold-artifact hash, and upstream preprocessing/assignment hashes. A run ID is
provenance, not sufficient artifact identity.

Recreate the model and reload the saved state before any calibration. On a fixed, hash-bound bounded
sample, every state tensor, reconstruction, score, and thresholded decision must match the pre-save
result exactly in the same locked CPU environment. Cross-version, cross-platform, and GPU bitwise
reproducibility is not claimed; an exact runtime/platform mismatch blocks use rather than relaxing the
reload gate.

## Anomaly score and threshold calibration

### Historical executed v1 definition

The pre-execution formula was incomplete: it did not say that the transformed float64 input was first
rounded to float32 and that the residual used that rounded value. The completed historical run actually
applied the following operations. For each caller batch, the input array was converted to float32, the
model performed CPU float32 arithmetic and returned a float32 reconstruction, and both float32 operands
were converted to float64 before the residual. NumPy accumulated the ordered 14 squared residuals in
float64 and divided by 14:

`q_ij = float32(x_ij)`

`r_i = float32_model(q_i)`

`s_i_historical_v1 = sum((float64(q_ij) - float64(r_ij))^2, dtype=float64) / 14`.

Thus the historical residual was against `q_i`, rather than the original float64 `x_i`. The model
forward also used the caller's batch shape. Review reproduced bitwise score differences from that
batching. On the original workstation, one fixed synthetic vector scored `0.9457795181243431` as a
singleton and `0.9457795275677049` in a mixed batch; these absolute values are execution evidence for
that runtime, rather than cross-platform constants. A strict threshold tied to the lower score changed
the decision. This correction does not apply a tolerance and does not recalculate any historical score,
metric, threshold, or artifact.

### Reusable v2 per-record scoring definition

The corrected scoring-contract version is `unsw_autoencoder_per_record_scoring_v2`, with score identity
`mean_squared_reconstruction_error_14_float32_input_per_record_v2`. It accepts only a finite transformed
NumPy float64 record in the frozen 14-feature order. Each record is converted elementwise to float32 and
evaluated alone as a shape `(1, 14)` CPU tensor. Model arithmetic and reconstruction remain float32.
The residual operands are `float64(float32(input))` and `float64(float32(reconstruction))`; their 14
squares are summed in fixed feature order with NumPy float64 accumulation and divided by float64 14.
Caller chunking controls iteration only and never changes the model-forward shape. Anomaly remains
exactly `score > threshold`; equality remains WithinThreshold.

This canonical per-record method is bitwise invariant for singleton versus mixed calls, caller chunk
sizes, record position, repeated vectors, and final partial chunks in the pinned runtime. It does not
claim cross-runtime equivalence. Every score must be finite and nonnegative. Larger means more anomalous,
and the value remains reconstruction error rather than attack probability, confidence, severity, or
likelihood.

The sole threshold policy is fixed before scores exist:

1. Finalize, serialize, hash, reload, and verify the epoch-30 model.
2. Score only the 212,210 benign (`Normal=0`) records in the existing January VALIDATION partition.
3. Sort those finite scores nondecreasing as `b[0] ... b[n-1]` and set
   `k = ceil(0.99 * (n - 1))` and `threshold = b[k]`. This is NumPy's empirical quantile with
   `q=0.99` and `method="higher"`.
4. Declare Anomaly exactly when `score > threshold`; equality is within threshold. Do not jitter or
   adjust ties.

The 99th percentile is a transparent development calibration convention, not an approved operational
false-positive target, service objective, or guarantee. No attack label participates in threshold
selection. TRAIN scores, mixed VALIDATION scores, February labels/scores/results, CIC evidence, and
classifier results cannot revise it. If benign VALIDATION scores are missing, non-finite, incorrectly
counted, or cannot be reproduced after reload, threshold calibration fails closed.

Calibration and evaluation are distinct. Because benign VALIDATION records set the threshold, false
positives and thresholded aggregate metrics reported on the full VALIDATION partition are
post-calibration January development evidence, not an independent evaluation. The 4,358 VALIDATION
attacks do not set the threshold, but their results still share the known development partition.

The historical `0.11813611984640647` threshold is bound only to the historical v1 scorer and its
caller-batched calibration execution. It is not a calibrated threshold for v2. No threshold-based v2
detector is approved or usable until a separately authorized run calibrates and evaluates v2 without
overwriting the historical run.

## Corrected reusable bundle and provenance boundary

Threshold-based loading requires a trusted, code-owned approved artifact identity. Hashes declared only
inside a candidate bundle cannot approve it. Before deserializing weights, the loader verifies bounded
same-byte snapshots of the configuration, state dictionary, threshold, manifest, and report against the
trusted registry. It then verifies the v2 scoring-contract and score identities; exact 14-8-3-8-14
architecture and feature order; model-weight hash; configuration, threshold, preprocessing, and manifest
bindings; strict greater-than comparison; and exact Python, PyTorch, platform, machine, libc, byte-order,
CPU/dtype, deterministic, and thread identities required by the pinned execution boundary. Missing,
altered, malformed, unapproved, or mismatched evidence fails with an allowlisted sanitized error before
the state dictionary becomes usable.

The historical artifact identity remains registered as historical evidence, but threshold-based loading
fails explicitly with `historical_threshold_incompatible_with_scoring_contract_v2`. There is no approved
v2 artifact identity because no v2 calibration has been authorized or run.

Review also established that the five historical files did not retain the exact protocol bytes, model
source bytes, or runner source bytes used during execution. Git provenance records a dirty worktree but
cannot reconstruct those uncommitted bytes. Current repository files are not claimed to be the execution
snapshots, and no historical snapshot is fabricated.

Before any future fit begins, the v2 runner writes exact copies of its protocol, model source, and runner
source plus a canonical `unsw_autoencoder_source_provenance_v2` manifest containing filenames, byte
sizes, and SHA-256 digests. The pre-fit configuration binds that manifest, and the completed artifact
manifest binds it again. Missing, mismatched, or altered snapshots fail reusable bundle verification.

## Evaluation and comparison protocol

No evaluation occurs in this documentation task. After separately authorized fitting, the completed
report must first label results on all 216,568 matching January VALIDATION rows as
`development_informed_post_calibration`. It must report TP, FP, TN, FN; Attack precision, recall, and
F1; false-positive rate `FP/(FP+TN)`; balanced accuracy; ordinary accuracy as context; predicted
Anomaly count/rate; non-interpolated average precision; and ROC-AUC. AP and ROC-AUC use the continuous
reconstruction score with higher values positive. Undefined ratios use the existing classical metric
policy; balanced accuracy and ROC-AUC are `null` unless both labels exist, and AP is `0.0` with no
positive labels.

Reload the frozen logistic model
`2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148` and frozen Random Forest
`bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9` only after their complete
configuration, report, artifact, preprocessing, runtime, and feature-order bindings pass. Recompute
their continuous scores and inclusive `P(Attack) >= 0.5` decisions in bounded batches on the exact
same ordered records; do not compare metrics from mismatched populations or row orders.

For Random Forest complementarity, report the following exact 2-by-2 detection overlaps separately by
true label:

- Attack: both detect, autoencoder only (Random Forest misses recovered), Random Forest only, neither;
- Normal: both false-positive, autoencoder-only false-positive (added false positives), Random
  Forest-only false-positive, both correctly unflagged.

Also report the corresponding rates and analogous aggregate comparison against logistic regression.
These counts are descriptive; do not create an OR/AND rule, rank blend, voting scheme, automatic
fusion, or production routing unless complementary value is demonstrated and a new protocol is frozen.

Only after every model, threshold, and artifact is frozen may a separate authorized runner score the
assigned February TEST records. Such results must be labeled `later_period_development_informed`:
February aggregate/model outcomes have already been inspected and can no longer provide independent
evaluation. They must not feed architecture, preprocessing, fitting, epoch selection, threshold, or
model retention. An independent claim requires a genuinely uninspected, preregistered compatible
source under TF-007.

CIC remains excluded from supported inference and from this autoencoder experiment. The registered
CICFlowMeter representation has demonstrated incompatible byte semantics for five predictors. Its
historical classical results are already known and may be referenced only with their existing
qualification; no CIC autoencoder score is to be calculated under this protocol.

## Later integration boundary

Later inference may reuse the trusted UNSW registered-member admission, stable source-event identity,
raw 49-column validation/adaptation, exact `network_behavior_v1` projection, and the approved saved
transformer. It must add the autoencoder as an explicitly selected, separately loaded detector. Random
Forest remains the default frozen classifier path with its current artifacts, probability field,
threshold, detector identity, and failure behavior unchanged. No fallback between detectors is allowed.

The autoencoder result contract must carry its separate model/artifact/score/threshold identities and
fields named `reconstruction_error` and `reconstruction_threshold`, with decisions `Anomaly` or
`WithinThreshold`. It must not populate `attack_probability` or reinterpret `Anomaly` as a supervised
Attack classification.

The current `AlertCandidate v1` is deliberately classifier-specific: it allowlists the two classical
models, requires decision `Attack`, and constrains score and threshold to `[0,1]`. Reconstruction error
must not be forced through that contract. A later additive, versioned anomaly-candidate contract and
repository/table may reuse the existing stable identity encoding, bounded SQLite transaction,
idempotency, privacy, and clean-failure patterns. It must have a distinct detector/model/policy identity
and accept finite nonnegative reconstruction values without changing the v1 schema or frozen Random
Forest insertion path. Joining both candidate types into one analyst queue is a separate integration
decision after complementary value is demonstrated. TF-008 and TF-009 remain open throughout.

## Acceptance and failure behavior

A future implementation is acceptable only when all of these hold:

1. All registered-source, assignment, preprocessing, array, classical-comparison, configuration,
   threshold, and model hashes are verified from bounded same-byte reads before dependent use.
2. Shapes, dtypes, 14-column order, label mapping, exact class counts, completed flags, TRAIN-only
   preprocessing population, and zero enforced-group crossings reconcile. Only 847,837 benign TRAIN
   rows reach optimizer batches; instrumentation proves zero VALIDATION/TEST/CIC optimizer access.
3. The exact locked PyTorch CPU runtime passes compatibility smoke, deterministic mode remains enabled,
   and dependency/platform identities match at reload and inference.
4. Training loss, every reconstruction, every score, and the threshold are finite; scores and threshold
   are nonnegative. Non-finite or count-mismatched calibration cannot emit a decision.
5. The immutable epoch-30 state, artifact identity, threshold policy, and bounded reload sample pass the
   exact same-environment reload checks before completion is reported.
6. Four CPU threads, one loader process, batch size 1,024, 30 epochs, 2 GiB peak RSS, 3,600-second
   deadline, 256 MiB artifact budget, and 2 GiB memory/disk reserves are enforced and measured. Limits
   are never silently relaxed and the model is never silently reduced.
7. Interruptions, corrupt or substituted inputs, unsupported runtime/source, resource-gate failure,
   non-finite computation, serialization/reload mismatch, and threshold failure return allowlisted
   sanitized codes. They never modify upstream state, existing classical artifacts, split assignments,
   preprocessing artifacts, or the frozen Random Forest path; they never produce a completed report or
   actionable candidate.
8. A fresh run retains enough incomplete, sanitized evidence to diagnose failure without raw rows,
   individual predictions, secrets, or unsafe exception text. Existing run directories are never
   overwritten.
9. Weak, null, adverse, or non-complementary results are preserved with their frozen configuration and
   reported. They do not trigger hidden retries, alternative percentiles, architecture changes, model
   suppression, post-hoc subgroup selection, or automatic fusion.

Training and dependency changes required separate explicit user authorization; that authorization was
provided for the single run recorded below. Passing this experiment establishes only bounded
same-source development evidence for one fixed reconstruction detector. It does not close global
readiness, cross-source compatibility, independent evaluation, user-value, TF-008, or TF-009 gates.

## Frozen execution evidence, 2026-09-14

The authorized implementation used `torch==2.10.0+cpu` from the explicit official PyTorch CPU index.
The lock selects the CPython 3.11 manylinux 2.28 x86_64 wheel with SHA-256
`b7cb1ec66cefb90fd7b676eac72cfda3b8d4e4d0cacd7a531963bc2e0a9710ab`. The project environment
verified CPU tensor operations, finite forward/backward gradients, deterministic-algorithm mode,
`weights_only` state loading, and `map_location="cpu"`. It has no CUDA build or available CUDA
device. NumPy 2.4.6, scikit-learn 1.9.0, pandas 2.3.3, and Pydantic 2.13.5 remain unchanged;
torchvision and torchaudio are absent. TF-015 is resolved only for this verified prerequisite.

One bounded synthetic smoke passed before the dataset run. The single full attempt
`full-benign-autoencoder-255c342-v1` then completed without a retry or configuration change. All 30
epochs processed exactly 847,837 benign TRAIN records; 17,643 TRAIN attacks were excluded, the final
batch contained 989 records, and zero VALIDATION/TEST records influenced weights. The approved
preprocessor was reused without refitting and retains its all-865,480-TRAIN statistics. Mean epoch loss
decreased from `0.27916392174650945` in epoch 1 to `0.02140706373753276` in epoch 30; the nonmonotonic
late losses were retained without tuning.

Calibration used all 212,210 benign January VALIDATION scores exactly as declared. The frozen
threshold is `0.11813611984640647`, using `method="higher"`; only a strictly greater reconstruction
error flags Anomaly.

| Evidence | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Balanced accuracy | AP | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| January VALIDATION, post-calibration development | 1,988 | 1,628 | 210,582 | 2,370 | 0.549779 | 0.456173 | 0.498621 | 0.007672 | 0.724250 | 0.348041 | 0.917107 |
| February TEST, development-informed previously inspected benchmark | 248,531 | 25,934 | 1,127,842 | 50,537 | 0.905511 | 0.831018 | 0.866667 | 0.022477 | 0.904270 | 0.828553 | 0.950891 |

On January, the autoencoder and Random Forest both detected 1,892 attacks; autoencoder-only detected
96 RF misses; RF-only detected 2,153; and both missed 217. A hypothetical OR would add 1,574 benign
false positives to RF. On February, both detected 245,729 attacks; autoencoder-only detected 2,802 RF
misses; RF-only detected 45,426; and both missed 5,111. A hypothetical OR would add 22,056 benign
false positives. These tradeoffs do not demonstrate sufficient complementary value to enable fusion;
no fusion path was implemented.

The fit took `176.98475433500016` seconds and the complete runner took `187.99965771900042` seconds.
Peak RSS was 944,115,712 bytes by Linux `resource.getrusage(RUSAGE_SELF).ru_maxrss`, below the 2 GiB
limit. The state contains 305 parameters and is 4,931 bytes. Generated aggregate artifacts are:

| Artifact | SHA-256 |
|---|---|
| `autoencoder_config.json` | `2b904768fc264c7c29965cdd5c93b7535f16737e32fcf84620a09c66ffc5695e` |
| `autoencoder_state.pt` | `c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23` |
| `threshold.json` | `ebe9ef140b89e7e0fc8dc6a74ccb4e1d9a08c7eb25f6460a772c8bae8bfc9fce` |
| `artifact_manifest.json` | `e248bf27def9ad4fe92ccee59e166d6dbeef7bd33dc1da0f2050694ad9e4f3a4` |
| `evaluation_report.json` | `ac6f411f1bb29c825e59129a88f79b8d2b96582a79d4e057e9f0a1fd118fe754` |

The domain-separated artifact identity is
`7d982df4f90fd0d3029beb6962b8afdc853cfa3efbeb7d57f58c14a2f92a896f`. The run stores aggregate
reports only. It reused the verified historical February transformed arrays without reopening raw CSVs;
CIC and Mordor were not accessed. Reconstruction error remains an uncalibrated anomaly score.

Post-stabilization validation passed all 862 backend tests with no skips or failures. Four existing
Mordor date-parsing warnings remain visible. Repository Ruff, individual bounded Black checks for the
model, tests, and runner, and lock consistency all pass. The first full-suite permission request was
canceled; process inspection found no surviving pytest command before the one authorized loopback-capable
rerun. All nine frozen preprocessing/logistic/Random Forest artifact hashes and all five generated
autoencoder artifact hashes still match their recorded values. No training, calibration, scoring, or
evaluation was repeated. The measured tracked execution window from the first dependency-file change
through completed behavioral validation was 1,431 seconds; the fit and runner timings above are the more
specific model measurements. Agent model, reasoning-effort, token-use, and quota snapshots were not
supplied and are recorded as unavailable rather than estimated.

### Bounded scientific-review correction, 2026-09-15

The historical five-file run and all reported outcomes above remain unchanged. The review correction
adds the v2 canonical per-record scorer, explicit dtype/reduction contract, trusted bundle/runtime
verification, and pre-fit exact source snapshots for future runs. The observed historical batching
reproduction and all correction validation are development checks only; no dataset was scored and no
model was trained, fitted, calibrated, tuned, or evaluated. A separately authorized v2 calibration and
evaluation is required before threshold-based reuse. Final validation passed 41 focused autoencoder
tests, 96 other related artifact/loading tests, and one 895-test full backend suite. The full suite had
no failures or skips and emitted the four existing TF-005 Mordor date-parsing warnings. Repository Ruff,
three individually bounded Black checks, `uv lock --check`, and tracked/untracked whitespace and
final-newline checks passed. All five historical autoencoder hashes and all nine frozen preprocessing,
logistic-regression, and Random Forest hashes matched their recorded values.

## Next scientific task

Separate explicit authorization has now been received to freeze and run one new v2
calibration/evaluation experiment in a fresh artifact directory, then add its independently trusted
artifact identity only if every gate passes.

## Corrected v2 execution preflight, 2026-09-15

The authorized run ID is `full-benign-autoencoder-2a51c94-v2`. No calibrated v2 directory existed at
preflight. `HEAD` and `origin/main` were both
`2a51c94b2b3c6cd96b00ff516fee34e262afb96b`; the worktree and index were clean. The five historical AE
and nine frozen preprocessing/logistic/Random Forest artifacts were retained.

CI run `34900883087` skipped six tests because ignored evidence is unavailable on GitHub-hosted runners:
three frozen-model artifact loading/reload tests use `ignored frozen model artifacts are unavailable`;
the registered-schema test uses `ignored registered metadata unavailable`; the public raw inference test
uses `ignored frozen bundles or metadata unavailable`; and the real TLS orchestrator smoke uses
`configured frozen artifacts or registered UNSW inputs are unavailable`. All prerequisites exist on the
workstation. The first five passed locally. The TLS smoke reached its listener but the restricted sandbox
blocked loopback binding; the established loopback-capable rerun passed. No test was weakened.

Input verification reconciled TRAIN as 865,480 rows (847,837 benign and 17,643 Attack), January
VALIDATION as 216,568 rows (212,210 benign and 4,358 Attack), and February TEST as 1,452,844 rows
(1,153,776 benign and 299,068 Attack). The Random Forest hash and all February bindings matched their
frozen expected values. The supported runtime was CPython 3.11.16, PyTorch 2.10.0+cpu, Linux x86_64
with glibc 2.39, deterministic algorithms enabled, four intra-op threads, and one inter-op thread.

A fixed-seed, 50,000-row synthetic canonical-scoring benchmark took 3.6275389800002813 seconds, or
13,783.449406240736 records/second. At that measured rate the 1,669,412 planned January and February
scores require an estimated 121.11714207360458 seconds. The probe observed 10,612,293,632 bytes of
available memory, 70,867,173,376 bytes of free artifact-filesystem space, and 737,697,792 bytes peak RSS.
These observations fit the frozen 2 GiB peak-RSS limit, 2 GiB memory and disk reserves, 256 MiB artifact
budget, and 3,600-second deadline. The completed report must retain below/equal/above threshold counts
and exact saved/reloaded v2 score and decision comparisons across caller chunk sizes 1, 64, and 256.

## Corrected v2 execution evidence, 2026-09-15

The single authorized attempt completed without retry, tuning, or configuration change. Each of 30
epochs processed all 847,837 benign TRAIN rows, excluded all 17,643 TRAIN attacks, and retained the
989-row final batch. The epoch losses and fitted state exactly match the historical run because fitting
was unchanged; only scoring and its bound threshold use v2. The v2 threshold is
`0.1181361214680695`, calibrated from all 212,210 benign January scores by `method="higher"`, with
strict `>` and equality within threshold. It was persisted before February scoring.

| Evidence | TP | FP | TN | FN | Precision | Recall | F1 | FPR | AP | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| January VALIDATION, calibration-informed development | 1,988 | 1,628 | 210,582 | 2,370 | 0.549779 | 0.456173 | 0.498621 | 0.007672 | 0.348040 | 0.917107 |
| February TEST, previously inspected benchmark | 248,531 | 25,934 | 1,127,842 | 50,537 | 0.905511 | 0.831018 | 0.866667 | 0.022477 | 0.828553 | 0.950891 |

January had 212,454 scores below, 498 equal to, and 3,616 above threshold. February had 1,177,028
below, 1,351 equal to, and 274,465 above. On identical January rows, AE-only recovered 96 attacks missed
by RF and added 1,574 false positives; on February it recovered 2,802 and added 22,056. These results do
not authorize fusion. February did not affect fitting, scoring definition, or threshold selection.

The fit took 149.8261376269993 seconds; January calibration/evaluation and RF comparison took
16.269357055 seconds; February verification/evaluation and RF comparison took 108.4592168449999
seconds; total runner time was 275.92863129500074 seconds. Peak RSS was 901,115,904 bytes. The nine
ignored run files occupy 138,129 filesystem bytes (`du -sb`):

| Artifact | SHA-256 |
|---|---|
| `autoencoder_config.json` | `51d4d664b5e017c5b039a08dc897d63e81a0b1e140eb1bb16457997ffa0727c2` |
| `autoencoder_state.pt` | `c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23` |
| `threshold.json` | `79bc7f3def3a4ed745fbc85d9cbf36a04f4fb4384de4db065569f81f60c78e3e` |
| `artifact_manifest.json` | `c142d3352b406a689b6317f48ae513540076b02ffb2e0fdef9cd3e6a83da1866` |
| `evaluation_report.json` | `0ec77eda4a58e40e1b75087bbc5131f39cad54d553771e174ea303bc506c3bef` |
| `source_provenance_manifest.json` | `d412f390f0d081170917a2e784046239f3e5b14d9a604e1196d2e3cbd3c527a9` |
| `network_autoencoder_protocol.snapshot.md` | `7ebd76b094f48303e45b40c6ff42bbfdbae1256e24c41a265bed6187466be78e` |
| `network_autoencoder.snapshot.py` | `bcd2f8077de6cd9edeb3902aea5cb9a64f089111d7233aa6f94ee0257a1542c9` |
| `train_network_autoencoder.snapshot.py` | `1e85861ced0f341598f697387c2826ffdc31ad41d0516755ddff77850a6f6a54` |

The domain-separated artifact identity is
`bdb7fc33d5b092566995018b5f83aa66bdb8ce95841d6b8b9021111c9a392a9a`. Independently calculated
expected hashes passed the existing complete bundle/runtime/threshold/preprocessing/provenance loader.
The report also records exact saved/reloaded v2 scores and decisions for 257 January rows across caller
chunks 1, 64, and 256, including partial final chunks. A separate 17-row synthetic verified-load check
was bitwise identical across chunks. The identity remains experimental and is not in the product-approved
registry; no integration or fusion path changed.

Post-run validation passed all 41 focused autoencoder tests and the one-time 895-test backend suite.
The full suite had no failures or skips and emitted the four existing TF-005 Mordor date-parsing
warnings. Of the six CI availability skips, five passed together locally; the real TLS smoke first
failed with `listener_unavailable` in the restricted sandbox, then passed through the established
loopback-capable path. Repository Ruff, individual Black checks for both changed Python files,
`uv lock --check`, `git diff --check`, and final-newline checks passed. All five historical AE and all
nine frozen preprocessing/logistic/Random Forest hashes matched their repository-recorded identities.

The January result supplies weak complementarity evidence: 96 additional detections cost 1,574 added
false positives. The next development experiment should therefore be a preregistered January-only
residual-contribution audit that measures which fixed feature blocks drive AE-only true and false
positives before authorizing any architecture, loss, or threshold change. It must not use February for
selection and is not launched here.
