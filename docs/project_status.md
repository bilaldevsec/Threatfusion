# ThreatFusion current project status

## Snapshot

Status date: 2026-09-10. Branch: `main`. Latest commit:
`344a8546d212f90f63eb643b7bfece6b1d19bc4f`. The working tree contains the preserved `AGENTS.md`
policy update plus the scoped UNSW inference-boundary source, tests, CLI, documentation, and the shared
preprocessing state's snapshot-decoding helper added by the adversarial review; nothing
is staged. Repository evidence and live Git status supersede older snapshots below.

Repository evidence takes precedence over older phase summaries. In particular, the aggregate Phase 0
readiness report still says split assignments are missing, but the later completed full assignment and
preprocessing artifacts supersede that one blocker. The report itself remains historical and must not be
rewritten. Global training/product readiness still does not pass because host training evidence and
integrated product acceptance are absent.

## Implemented and verified

- Manifest-backed readers, strict adapters, bounded validation/profiling, sanitized reports, checksum
  verification, and ignore rules exist for the registered UNSW, CIC, Mordor, and `synthetic_lab` roles.
- A completed full UNSW assignment covers every registered row once. It produced 865,480 TRAIN,
  216,568 VALIDATION, and 1,452,844 February TEST records, plus 5,145 quarantine and 10 rejected
  records. Group/split verification completed; capture provenance and near duplicates remain limitations.
- TRAIN-only preprocessing produced the frozen 14-column output (ten numeric z-scores plus four fixed
  protocol indicators), with 865,480 TRAIN and 216,568 VALIDATION rows. Integrity, finite values,
  assignment reconciliation, TRAIN-only fitting, and state reload were verified.
- Frozen logistic-regression and Random Forest baselines were trained on the full TRAIN matrix and
  evaluated on the same VALIDATION matrix. Their saved artifacts, model/preprocessor binding, metric
  definitions, resource controls, and reload behavior are documented and tested.
- Both saved models were evaluated without refitting on February UNSW and the two registered CIC
  exports. The targeted CIC audit verified the inspected prediction path, hashes, feature order,
  probability mapping, single scaling, rejection alignment, bounded replay, and confusion arithmetic.
- A typed compatibility decision now keys the actual input/fitted-source representations, contract
  version, and model/preprocessing requirements. Same-source verified UNSW use is supported; the
  registered CIC representation is rejected before transformation/inference or run artifact creation.
  Unknown and incomplete evidence fails closed. Historical completion remains separately readable.
- Repository-wide Ruff passes. Four direct-execution CLIs retain their intentional `backend/src`
  bootstrap with import-level `E402` suppressions matching the established script convention; their
  `--help` paths exit without starting data work or creating artifacts.
- An UNSW-specific network inference boundary verifies the exact frozen preprocessing and both model
  bundles before loading, requires the approved Argus representation provenance, defaults explicitly
  to Random Forest, and rejects CIC/unknown representations before transformation. Its feature-only
  input, sanitized result, no-fallback model choice, and 256-record batch accounting have been reviewed
  adversarially. TF-013's hash/reopen race, object-provenance bypass/leakage, and malformed request and
  iterator failures were reproduced and corrected. All nine artifacts are verified as bounded byte
  snapshots before deserialization; runtime versions are checked. The final review validation passed
  113 focused inference/contract/preprocessing tests and one full 430-test suite (four pre-existing
  Mordor warnings, TF-005). Repository-wide Ruff and all four individual Black checks pass. All nine
  frozen artifact hashes remain unchanged and their directories remain ignored. Core rejection tests
  no longer depend on ignored model files. The previous synthetic functional smoke completed through the real frozen Random Forest artifacts;
  it is not accuracy evidence. This is a component boundary, not an integrated demo or readiness claim.

## Implemented with limitations

- `network_behavior_v1` is valid as the frozen input order for the historical UNSW models, but its
  cross-source byte mapping is not a validated common measurement contract. Five byte-dependent CIC
  predictors have incompatible documented semantics; direction/flow policy remains uncertain. See
  [`network_feature_comparability_audit.md`](network_feature_comparability_audit.md) and TF-012. The
  gate prevents unapproved use; it does not improve accuracy or establish compatible measurements.
- CIC metrics are preserved historical research evidence, not proof of compatible external transfer or
  operational usefulness. February and CIC outcomes are known and must be disclosed in future work.
- Host-event schemas, Mordor ingestion/validation, `host_behavior_v1`, and the synthetic fixture exercise
  pipeline behavior only. Mordor is attack/test-only; `synthetic_lab` is not representative training data.
- Feature collisions/conflicting labels are documented. Near-duplicate leakage, capture/session
  provenance, possible CIC row caps, CIC timezone, and historical extractor configuration remain open.
- Provenance is a trusted-adapter attestation, not proof of the measurement source. Direct untrusted
  client access is blocked pending TF-014's ingestion binding. Model scores are not calibrated
  confidence, and request UUIDs are not stable ingestion/deduplication identities. Service-level time,
  concurrency, transport, and restart/recovery limits remain unverified (TF-008/TF-009). See the
  [inference trust boundary](unsw_network_inference_boundary.md#security-and-scientific-claim-boundary).

## Blocked

- Host-model training and host scientific claims are blocked by missing representative benign-host data.
- Global training readiness remains false even though the authorized network baselines completed.
- Deep-learning work remains paused. Validation of the classical UNSW inference boundary does not
  itself authorize or establish requirements for deep-learning work.
- New claims of independent February/CIC evaluation are blocked because those outcomes are known.
- Cross-source compatibility approval is blocked by TF-012 and TF-003.

## Not yet implemented

- A supported end-to-end product path connecting ingestion, validation, inference, alert persistence,
  deduplication/correlation, explanation, and dashboard display.
- Product API/view-model contracts, dashboard behavior, persistence/restart recovery, optional-service
  degradation, and integrated resource/latency evidence.
- Approval-gated allowlisted containment with audit and rollback. No automatic containment is supported.
- A verified jury requirements reference, confirmed target-user/environment decision, operational
  acceptance targets, manual-workflow baseline, or representative-user usefulness study.

## One next implementation task

Implement the trusted UNSW-adapter-to-inference provenance binding (TF-014) before external exposure
or AlertCandidate/persistence work. Provenance must be derived from verified input representation by
the trusted adapter, never accepted as a client's approval assertion. Acceptance fixtures must reject
relabeled/unsupported client input, preserve exact feature order and source binding, and demonstrate
bounded input and sanitized rejection behavior without datasets or model fitting. The security review
does not authorize starting this next task, persistence, dashboard, or deep learning.
