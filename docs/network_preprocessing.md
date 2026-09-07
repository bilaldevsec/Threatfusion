# Train-only network preprocessing

The first `network_behavior_v1` preprocessing pipeline consumes only the completed, verified UNSW
assignment. It does not change the assignment, frozen seed, quarantine policy, February test set,
CIC role, or any readiness gate. It fits no predictive model.

## Input and leakage boundary

The command verifies the registered UNSW manifest and every registered file checksum, the complete
preflight report and its hash, the complete assignment report, and the assignment archive hash. It
requires the exact full-run schema/status flags, acceptance checks, ordered raw basenames, frozen
seed, and reconciled split counts. The gzip assignment must contain one strictly increasing global
record ordinal for every registered raw row. Each ordinal is joined to the same stable registered
file/row traversal used to construct the assignment. Missing, extra, duplicated, malformed, or
adapter-inconsistent entries fail the run.

Rejected and quarantined records are never fitted or transformed. February `test` records are read
only far enough to prove source/assignment coverage and count reconciliation; their predictors are
never projected into an output matrix. CIC is not opened. Only `train` updates fitted statistics,
and only `train` and `validation` receive transformed outputs.

## Exact transformation

The eleven input predictors are the exact declared `network_behavior_v1` order:

1. `duration_ms`
2. `fwd_packets`
3. `bwd_packets`
4. `fwd_bytes`
5. `bwd_bytes`
6. `packets_per_second`
7. `bytes_per_second`
8. `fwd_packet_length_mean`
9. `bwd_packet_length_mean`
10. `dst_port`
11. `protocol`

The first ten fields are numeric according to the contract. Each is centered by its TRAIN mean and
divided by its TRAIN population standard deviation. A zero-variance field uses scale one, retaining
a deterministic all-zero transformed column. This conventional float64 z-score interface is a
small baseline compatible with later linear, distance-based, tree, and neural estimators, without
committing to a model family. No log transform, clipping, imputation, feature selection, PCA,
SMOTE, resampling, or outlier removal is performed.

`protocol` uses the contract-defined order `tcp`, `udp`, `icmp`, `other` and expands to four one-hot
columns. The canonical adapters already normalize unsupported source protocol spellings to
`other`; a noncanonical category presented directly to the reusable transformer is rejected. There
are no remaining categorical fields, so there is no data-learned category vocabulary. Numeric NaN
or infinity is rejected before fitting or transformation.

The transformed feature order is the ten numeric names suffixed by `__zscore`, followed by
`protocol=tcp`, `protocol=udp`, `protocol=icmp`, and `protocol=other`. Labels remain in separate
uint8 arrays with the explicit stable mapping `Normal -> 0`, `Attack -> 1`. Metadata, labels,
attack categories, IPs, timestamps, ingestion IDs, filenames, grouping identifiers, and every
other field outside the exact predictor contract cannot enter the projection.

## Bounded artifacts and reload

The implementation streams registered CSV records and gzip assignments, retaining at most one
configured batch plus fixed-size counters and numeric moments. It writes float64 matrices through
NumPy disk-backed `.npy` memmaps and never loads a complete CSV or transformed partition into a
Python list or pandas dataframe. Row order is registered raw-file order and then one-based source
row order, filtered independently for TRAIN and VALIDATION.

Each fresh run beneath `data/processed/unsw_network_preprocessing/<run-id>/` contains:

- `preprocessor_state.json`: fitted TRAIN means/scales, fixed categories, policies, feature order,
  label mapping, output type, and the documented `1e-12` batch-equivalence tolerance;
- `preprocessing_config.json`: transformation/resource configuration, dependency versions, source
  file hashes, manifest hash, preflight hash, assignment report/archive hashes, and frozen seed;
- `X_train.npy`, `y_train.npy`, `X_validation.npy`, and `y_validation.npy`;
- `preprocessing_report.json`: sanitized counts, dimensions, output hashes, runtime, artifact size,
  validation checks, and unresolved limitations.

The JSON state reload validates all static contract fields before constructing the transformer.
Reloaded state is used for the disk-backed standardization pass, so saved-state incompatibility
fails before the run can be reported complete. Existing run directories are never overwritten.

Run a bounded join/projection smoke check first:

```bash
.venv/bin/python scripts/preprocess_unsw_network.py --smoke-records 10000
```

Then use a fresh identifier for the complete TRAIN fit and TRAIN/VALIDATION transformation:

```bash
.venv/bin/python scripts/preprocess_unsw_network.py --run-id <fresh-run-id>
```

The full command deliberately has no option to transform February test or CIC data. The reusable
`NetworkBehaviorPreprocessor.load(...).transform(...)` interface exists for a later separately
authorized evaluation phase.
