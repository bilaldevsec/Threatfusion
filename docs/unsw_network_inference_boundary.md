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

`UnswNetworkInferenceBoundary` accepts only feature values in this exact order:

`duration_ms`, `fwd_packets`, `bwd_packets`, `fwd_bytes`, `bwd_bytes`,
`packets_per_second`, `bytes_per_second`, `fwd_packet_length_mean`,
`bwd_packet_length_mean`, `dst_port`, `protocol`.

Every request must carry the exact source representation, fitted-source representation, contract
version, and model/preprocessing requirements. Compatibility is checked before feature validation,
transformation, or prediction. Missing/unknown evidence, CIC provenance, version/order changes,
missing/non-numeric/non-finite/negative values, invalid integer/count/byte relationships, an invalid
port, or an unknown protocol is rejected with a stable reason code. Requests/provenance must be the
declared concrete dataclasses, their ordered features must be tuples, and scalar values must be plain
Python numbers/strings (not booleans or coercible/custom objects). `from_mapping` accepts only a plain
11-entry dict. Integers losing precision on float64 conversion and forest inputs overflowing float32
are rejected before prediction. The input type has no fields for
IPs, labels, timestamps, filenames, secrets, or full source rows.

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

The output contains only a generated correlation UUID, model identity/version, contract and approved
source identity, Attack probability, threshold, predicted class, sanitized status/reason, UTC processing
timestamp, and elapsed milliseconds. Failed inputs return no score/class and never echo feature values
or unknown provenance. Audit provenance exposes hashes and versions without filesystem paths or raw
features.

Single-record inference and streaming batches up to 256 records are supported. At most 257 iterator
items are requested. A 257th item or an iterator exception rejects the whole batch before prediction;
no partial-batch success or count summary is returned. The errors are `batch_size_exceeded` and
`batch_iteration_failed`, with internal exception context suppressed from displayed tracebacks. Invalid
model selection also raises a sanitized batch/call error, including for empty batches. Within an
accepted-size batch, malformed records and transformation/prediction failures remain ordered and each succeeds or
fails independently; received/succeeded/rejected totals reconcile. This is an inference-to-alert
boundary, not yet alert persistence, deduplication, correlation, explanation, or dashboard integration.

## Security and scientific claim boundary

Source provenance is a **caller attestation, not source authentication**. Even the exact approved string
cannot prove that measurements came from UNSW/Argus. `approved_unsw()` is a convenience for a trusted
adapter and the explicitly synthetic smoke, not a credential. Do not expose this component directly to
untrusted clients that can label arbitrary measurements as UNSW. A trusted ingestion boundary must
establish representation and derive provenance independently of client claims before product exposure.
Correctly declared CIC inputs are rejected; deliberate relabelling cannot be detected from these 11
numbers alone. TF-014 tracks this remaining integration gate.

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

The synchronous iterator limit bounds records, not time inside arbitrary caller code. Blocking
iterators, service concurrency/admission limits, transport-body limits, process isolation, and
restart/persistence recovery require the future ingestion/service boundary (TF-008/TF-009/TF-014).
Component fixtures and code review do not establish complete product security or absence of all defects.

The adversarial review reproduced and corrected a hash/reopen race, malformed-object provenance bypass
and leakage, and uncaught malformed-record/iterator failure paths. Core rejection tests now run without
ignored artifacts. Separate integration tests verify reload using the real pinned artifacts when they
are available; those tests explicitly skip when unavailable. No evaluation or fitting was repeated.

## Functional smoke

From the repository root:

```bash
.venv/bin/python scripts/smoke_unsw_network_inference.py
```

The CLI uses a synthetic, contract-valid feature-only request and the real frozen artifacts. Its JSON
contains only the sanitized output schema. This demonstrates loading, validation, transformation, and
prediction wiring; it is not accuracy, representative-traffic, readiness, or user-value evidence.

Deep learning remains paused until this boundary is validated. Adding another dataset or extractor
requires demonstrated measurement compatibility and a preregistered evaluation protocol before it can
enter the supported path.
