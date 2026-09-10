# UNSW-supported network inference boundary

## Scope and decision

ThreatFusion's supported network-inference representation is explicitly
`unsw_nb15.argus.raw_49.transaction_bytes.v1` projected through the exact ordered
`network_behavior_v1` contract. The grouped January TRAIN/VALIDATION assignment and completed
February chronological TEST remain frozen. No new split, fitting, threshold selection, or model
evaluation is part of this boundary.

The fixed Random Forest is the primary detector because it produced stronger results than logistic
regression on the already-known frozen February test (attack F1 0.9651 versus 0.4146). This is a
documented product choice over existing models, not fresh selection evidence or proof of operational
performance. Logistic regression remains available only by explicit selection as a transparent
comparison. A load or prediction failure never switches models automatically.

CIC files, code, reports, and results remain immutable research evidence. CICFlowMeter's registered
representation is not accepted here: the TF-012 study demonstrated incompatible byte accounting and
additional pinned-extractor grouping limitations. CIC exclusion mitigates TF-012 for this product path;
it does not solve cross-source equivalence. Historical CIC results are development-known and are not
valid arbitrary-exporter or universal-generalization evidence.

## Interface and fail-closed behavior

The supported application entry is `UnswNetworkInferenceBoundary(project_root=...)`, followed by
`infer(raw_values)` or `infer_batch(raw_rows)`. Setup is trusted application configuration; the root
is never taken from serialized client input. Each submitted record must be a plain list of exactly
49 plain strings in the registered headerless UNSW raw-column order, with at most 1,024 characters per
field. JSON arrays decode to this shape. Named mappings, additional provenance fields, precomputed
11-value predictors, canonical events, internal requests, subclasses, and duck-typed substitutes are
rejected. There is no source-selection or client-approval parameter. CIC's registered input remains
rejected; this is not a generic source-admission mechanism.

The exact supported call path is:

`UnswNetworkInferenceBoundary.infer[_batch]` → shared `map_unsw_raw_values` reader mapping →
`adapt_unsw_row` → validated concrete `NetworkFlow` → `project_network_behavior` → immutable private
request with internally assigned UNSW provenance → private frozen predictor → existing compatibility,
feature validation, preprocessing, and prediction.

Trusted setup verifies the pinned UNSW manifest hash and validates its `DatasetManifest` schema,
then verifies the registered 49-row feature-metadata hash. Parsing uses the same verified byte snapshots;
neither file is reopened for decoding. These bounded reads reuse the TF-013 regular-file snapshot
checks. This validates the registered representation definition; it does **not** verify submitted rows'
membership in any registered raw dataset file. No full dataset is read by this entry path.

The private request contains only frozen provenance and an immutable tuple of scalar predictors
in this order:

`duration_ms`, `fwd_packets`, `bwd_packets`, `fwd_bytes`, `bwd_bytes`,
`packets_per_second`, `bytes_per_second`, `fwd_packet_length_mean`,
`bwd_packet_length_mean`, `dst_port`, `protocol`.

The pipeline assigns the exact source representation, fitted-source representation, contract
version, and model/preprocessing requirements after successful adaptation. Compatibility is checked
before feature validation, transformation, or prediction. Missing/unknown evidence, CIC provenance,
internal feature version/order changes,
missing/non-numeric/non-finite/negative values, invalid integer/count/byte relationships, an invalid
port, or an unknown canonical protocol category is rejected with a stable reason code.
Raw protocol aliases retain the adapter's existing normalization, including `other` for noncanonical
protocols. Requests/provenance must be the
declared concrete dataclasses, their ordered features must be tuples, and scalar values must be plain
Python numbers/strings (not booleans or coercible/custom objects). Raw packet/byte counts must be finite,
nonnegative integers no larger than 2^53, preventing the shared adapter's historical float-mediated
integer parsing from silently rounding counts. This is a conservative input bound, not a claim that
every integer above 2^53 is inexact; the review retains that bound. Binary labels are checked for exact
integrality and the range [0, 1] before float-mediated adapter parsing, even though they are not predictors.
Duration and numeric epoch `stime` are checked for finite, nonnegative values before float conversion;
a nonzero raw value converting to zero is rejected. Exact zero duration keeps the existing zero-rate
behavior. UTC epoch conversion precedes adaptation and bypasses the generic date parser entirely,
preventing warnings from echoing submitted timestamp text. Numeric epoch semantics are documented in
[`network_training_split_design.md`](network_training_split_design.md#bounded-exploratory-check).
Integers losing precision on float64 conversion and
forest inputs overflowing float32 are rejected before prediction. The raw input includes endpoints,
timestamps and labels because the existing adapter requires them; these, attack categories, reader IDs,
paths, and all other non-allowlisted fields are excluded from predictors and never returned.
Raw rates/means supplied in unused UNSW columns do not replace internally derived rates/means.

The canonical event is local to adaptation and immediately projected; neither it nor the internal request
is returned. Each raw list is snapshotted and adapted before requesting the next iterator item. Later
mutation of the original list cannot change its prepared predictors. Internal request/provenance
dataclasses are frozen, their contents immutable, and their reprs omit fields. The historical feature-level
implementation is now private and retained for focused unit tests, not supported application submission.

Initialization is a trusted, eager setup operation, independent of request submission. It verifies all
nine frozen state/configuration/report/model files before any model deserialization. Each is opened
read-only as a regular file, with leaf symlinks and special files rejected. Reads are bounded at 64 KiB
per JSON file and 8 MiB per model. Hashing and decoding use the same in-memory byte snapshot; replacement
after verification cannot substitute bytes for loading. Parent-directory aliases cannot bypass exact
content hashes. Python and recorded numerical-library versions must match before model deserialization.
Model type, integer class order `[0, 1]`, 14-column width, feature order, source binding, label mapping,
and inclusive Attack threshold 0.5 must agree. Unreadable/missing/truncated/mismatched evidence raises a
sanitized setup error, never a fallback. Artifacts are never fitted or modified. Later on-disk changes
do not alter a running instance; constructing a fresh instance verifies them again.

The output contains only a generated per-attempt correlation UUID, model identity/version, contract
and approved source identity, Attack probability, threshold, predicted class, sanitized status/reason, UTC processing
timestamp, and elapsed milliseconds. Failed inputs return no score/class and never echo feature values
or unknown provenance. Audit provenance exposes hashes and versions without filesystem paths or raw
features.

Single-record inference and streaming batches up to 256 records are supported. At most 257 iterator
items are requested, and the 257th is never adapted. A 257th item or an iterator exception rejects
the whole batch before prediction; no partial-batch success or count summary is returned.
The errors are `batch_size_exceeded` and
`batch_iteration_failed`, with internal exception context suppressed from displayed tracebacks. Invalid
model selection also raises a sanitized batch/call error, including for empty batches. Within an
accepted-size batch, malformed records and transformation/prediction failures remain ordered and each
succeeds or fails independently; received/succeeded/rejected totals reconcile. This is an inference-to-alert
boundary, not yet alert persistence, deduplication, correlation, explanation, or dashboard integration.
Raw type, size, adaptation, and canonical-binding failures return `raw_input_rejected` with no score and
an unapproved source identity. Setup registration errors are `unsw_registration_invalid`. Neither retains
raw exception details in output. No log, report, raw record, or internal approval material is emitted.

## Security and scientific claim boundary

TF-014 binds the supported application entry path to actual UNSW raw adaptation and feature construction.
Serialized clients cannot supply an internal feature vector and provenance assertion to that path.
Source identity records the registered representation whose adapter successfully processed the input;
it is assigned by repository code, not copied from a client field.

This is **adaptation binding, not authentication of remote measurements or dataset membership**.
A client can fabricate raw values or deliberately convert another source to a plausible 49-column row;
schema/adapter validation cannot prove the physical exporter or capture origin. Such conversions have
no compatibility approval. Future deployment must restrict upstream producers to the supported
representation and define transport authentication/admission separately. No API or external transport
exists in this milestone, and no remaining supported feature-vector submission path accepts caller
attestation. TF-014 is resolved for this component integration; external service controls and readiness
remain unverified under TF-008/TF-009.

The mapping fixes column positions; it cannot detect swapping two otherwise valid numeric columns
(for example forward and backward byte values). Reordering that violates a field's validation fails,
but arbitrary reordering cannot honestly be claimed rejected. Unused raw columns are bounded strings,
not a complete semantic validation of all 49 original measurements. They do not become predictors.
Duplicate keys, aliases, path/root overrides and source declarations cannot enter as named payload
fields because mappings are rejected. Root configuration is trusted setup; alternate roots still need
the exact pinned manifest, metadata and artifact bytes. Adapter or predictor substitution requires
trusted same-process code, not serialized input.

Private names and concrete immutable classes prevent ordinary accidental misuse, not malicious Python
code executing inside the process. They are not cryptographic authentication. Trusted application code,
setup configuration, adapters, feature builders, and dependencies remain in the trusted computing base.
No capability token, object-identity credential, HMAC, signing key, or global secret is introduced.

Joblib/pickle loading executes code: hard-coded, reviewed hashes are the trust anchor, not a sandbox or
a guarantee that an intentionally approved malicious pickle is safe. The code, installed dependencies,
hash allowlist, and in-process callers must be trusted. Private estimator state must not be mutated by
callers. No in-process API can isolate itself from malicious code running with the same privileges.

`attack_probability` is an uncalibrated model score, not real-world confidence or an operational attack
likelihood. Float64 scaling happens once; sklearn's existing float32 forest quantization, including
rounding/underflow of sufficiently small values, remains unchanged. Input values already rounded to
zero upstream cannot be reconstructed. Reload probability tolerance remains 1e-15, not bitwise forest
probability reproducibility. The correlation UUID identifies an inference attempt, **not** a stable
ingestion identity, deduplication key, or persistence guarantee. Retrying generates a new UUID.
No ingestion identifier is exposed or invented here. The shared reader's required flow-ID alias uses
a fixed internal submission placeholder, discarded with the canonical event; it is not ingestion
provenance and must never become a persistence key. Stable ingestion identity remains future work.

The synchronous iterator limit bounds records, not time inside arbitrary caller code. Blocking
iterators, service concurrency/admission limits, transport-body limits, process isolation, and
restart/persistence recovery require the future ingestion/service boundary (TF-008/TF-009).
Component fixtures and code review do not establish complete product security or absence of all defects.

The adversarial review reproduced and corrected a hash/reopen race, malformed-object provenance bypass
and leakage, and uncaught malformed-record/iterator failure paths. Core rejection tests now run without
ignored artifacts. Separate integration tests verify reload using the real pinned artifacts when they
are available; those tests explicitly skip when unavailable. No evaluation or fitting was repeated.

## TF-014 adversarial review, 2026-09-10

Two medium-severity defects were demonstrated through the public entry and corrected:

- Raw numeric validation allowed tiny positive or negative duration to round to zero, and fractional
  or underflowing labels to round into accepted binary labels. Five regression cases reached prediction
  before correction; exact preconversion checks now reject them with zero predictor calls.
- Nonnumeric start timestamps could reach pandas' generic parser, emit a warning containing submitted
  timestamp text and an internal source path, and still reach prediction. A sixth failing regression
  now proves rejection without warnings or prediction using the registered numeric-epoch path.

No high-severity supported-entry bypass was demonstrated. Private constructors, copy/pickle round trips,
and internal factory substitutions in tests are not authentication mechanisms. Factory-substitution
tests establish internal consistency checks only; public-path rejection tests and predictor spies
establish the externally observable binding. Exact matrix assertions independently check label and
provenance exclusion. The review also exercises numeric spelling/bounds, zero duration, numeric epochs,
and iterator failure after 256 prepared rows. TF-014 is resolved for application-path adaptation binding;
physical source authenticity, undetectable positional swaps, blocking iterators and service controls
remain explicitly outside that disposition. TF-012 remains open.

Validation after stabilization: 251 focused tests passed, including all 69 binding cases; the complete
suite ran once with 499 passed and four existing TF-005 warnings. Repository-wide Ruff and five
individual Black checks (30-second bounds) passed. All nine frozen artifact hashes still match their
approved values and all nine files remain ignored/untracked. No training or full-data evaluation ran.

## Functional smoke

From the repository root:

```bash
.venv/bin/python scripts/smoke_unsw_network_inference.py
```

The CLI uses one synthetic raw 49-column row, verified registered schema metadata, and the real frozen
artifacts through the supported public path. Its JSON contains only the sanitized output schema.
This demonstrates loading, adaptation, validation, transformation, and prediction wiring; it is not
accuracy, representative-traffic, readiness, or user-value evidence.

Deep learning remains paused until this boundary is validated. Adding another dataset or extractor
requires demonstrated measurement compatibility and a preregistered evaluation protocol before it can
enter the supported path.
