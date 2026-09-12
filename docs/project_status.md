# ThreatFusion current project status

## Snapshot

Status date: 2026-09-12. Branch: `main`. The durable producer replay-journal milestone began from a
clean tree with nothing staged and verified HEAD and `origin/main` at
`2cd5868167ab7fbdf92fdf65cb87d76c7d95562b`. The implementation below remains local and unstaged;
HEAD and `origin/main` remain at that checkpoint.

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
- The TF-013 internal UNSW predictor verifies the exact frozen preprocessing and both model
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
- TF-014 is resolved for trusted UNSW adaptation binding. The supported public boundary now accepts
  only raw 49-column string arrays, verifies pinned manifest/schema snapshots during trusted setup,
  and uses shared reader mapping, the existing UNSW adapter and exact feature projection to construct
  immutable private inference requests. Source identity is assigned internally. The previous public
  feature-request interface is private; the smoke uses the supported raw path. Labels, categories,
  endpoints, IDs and other provenance never enter predictors. A reproduced legacy float-mediated
  integer-rounding defect is rejected by a boundary guard without changing historical adapter behavior.
  New spies prove no model prediction on adaptation/binding failure or aborted/oversized batches;
  snapshots prevent subsequent caller mutation. All 59 new binding cases pass, including real frozen
  bundle wiring when artifacts are available (available in that run). Initial validation: 241 focused
  tests; one complete suite, 489 passed with four existing TF-005 warnings; repository-wide Ruff;
  five individual 30-second-bounded Black checks; clean diff whitespace checks, including the new
  untracked test file and its final newline; unchanged approved hashes and ignored/untracked
  status for all nine frozen artifacts. No datasets or packages downloaded, no dataset regeneration
  or new model/preprocessor fitting, no February/CIC evaluation, and no persistence/API work.
- The subsequent TF-014 adversarial review reproduced and corrected two medium-severity defects:
  raw duration underflow and binary-label rounding could reach prediction, and generic start-time
  parsing could emit submitted timestamp text/internal paths in warnings while predicting. Duration
  and epoch parsing now reject non-finite, negative and nonzero-to-zero conversion; binary labels
  receive exact preconversion validation. Numeric UTC epoch parsing uses the existing adapter's
  datetime input semantics and never enters its generic date fallback. Six new regression cases
  failed before correction and pass afterward with zero model calls and no leaked warnings.
  Final review validation: 69 binding cases; 251 focused tests; one complete suite with 499 passed
  and four existing TF-005 warnings; repository-wide Ruff and five individually bounded Black checks.
  All nine frozen hashes remain approved, with every artifact ignored/untracked. No high-severity
  supported-entry bypass was demonstrated. TF-014 remains resolved for adaptation binding after
  re-review, not remote source authentication or complete service security.
- A registered-offline UNSW path now binds the pinned manifest digest, verified raw-member digest and
  one-based CSV record ordinal to `unsw_registered_source_event_v1`, then creates an immutable
  Attack-only `alert_candidate_v1`. Candidate identity additionally binds detector/model/artifact and
  decision-policy versions using documented length-prefixed SHA-256 encoding; correlation UUID, score
  and time do not alter the ID. Normal, rejected and failed inference is not actionable and is not
  stored. The standard-library SQLite v1 repository provides atomic insertion, idempotent retry,
  same-ID/content-conflict rejection, bounded deterministic listing, schema/integrity checks, bounded
  lock wait and restart retrieval. Stored fields exclude raw rows, feature vectors, endpoints, labels,
  categories, filenames, paths and exception details. Validation passed 266 focused tests and one full
  516-test suite with the four existing TF-005 warnings; repository-wide Ruff and seven individual
  Black checks pass. See [`alert_candidate_persistence.md`](alert_candidate_persistence.md).

## Implemented with limitations

- The first internal TF-008/TF-009 producer-admission boundary implements the exact v1 registered-UNSW
  producer/source allowlist, immutable certificate registry and rotation-overlap checks, uniform
  fail-closed certificate mapping, an exact immutable envelope, bounded exact-length body reads, strict
  UTF-8/JSON decoding, trusted-UTC timestamp windows, request/nonce/reference validation, exact-body and
  nonce digests, and an immutable admission record for the future replay journal. A compact allowlisted
  response serializer has a measured 25,142-byte worst case for 256 records, below its 65,536-byte cap,
  and never truncates. TLS peer evidence remains an assertion from the future directly terminating TLS
  adapter; Python constructors are not credentials. The pure bounded reader makes only sized reads but
  cannot impose wall-clock deadlines on an arbitrary blocking stream. All 63 admission tests and 218
  focused admission/inference/binding/persistence tests pass; the full suite passes with 581 tests and
  the four existing TF-005 warnings. Repository-wide Ruff and both individual bounded Black checks pass.
  Predictor and repository spies remain at zero for every admission test. There is still no listener,
  durable security audit or live-source identity. The planned
  Azure sensor remains disabled until a separate live representation and stable identity contract is
  approved; it must not impersonate registered UNSW membership. See
  [`producer_admission_transport_policy.md`](producer_admission_transport_policy.md).

- The separate standard-library producer replay journal implements exact SQLite schema/constraint/
  index verification, global request-ID and nonce-digest uniqueness, 500 ms busy waits, atomic
  `BEGIN IMMEDIATE` first claims, and hashed unpredictable ownership tokens. Its only states are
  `in_progress`, `completed`, and terminal `outcome_unknown`. Exact in-progress retries cannot acquire
  ownership; exact completed retries receive the original digest-verified bounded sanitized response;
  any identity/evidence mismatch is a uniform replay rejection. Completion requires the exact active
  token and service generation and stores state, response and response digest atomically. Explicit,
  idempotent generation-scoped recovery changes only externally proven-abandoned `in_progress` rows to
  `outcome_unknown`; ordinary connections never infer a crash or alter claims. This assumes one
  externally coordinated service owner and deliberately uses no weak lease. Forty-four replay tests
  and 195 directly related tests pass, including independent-connection races, reopen, locks, rollback,
  corruption/schema drift, response tampering/bounds, zero-call inference/repository spies and ignore
  coverage. The complete suite passes with 625 tests and the four existing TF-005 warnings;
  repository-wide Ruff and all three individual bounded Black checks pass. Stable manifest-derived
  source-event orchestration is not implemented by the journal.

- The internal v1 producer execution gate implements a fixed single-producer configuration, exact
  integer-nanosecond token bucket (six/minute, one token per ten seconds, burst two), and immediate
  global/per-producer concurrency limits of one with queue capacity zero. Certificate/producer
  admission precedes rate charging; rate precedes concurrency; authenticated concurrency rejection
  consumes its token to prevent saturation-probe bypass. An immutable unpredictable lease is required
  for exactly-once release, including context-manager `finally` release; stale, foreign, forged and
  double releases fail closed. Invalid, negative, oversized or backward clock values add no credit.
  State and count-only metrics are bounded without a producer-keyed map. All state is process-local,
  resets on restart and is independent across instances, so the supported design still requires one
  externally coordinated process with exactly one shared gate. This is not durable or multi-process
  enforcement and does not authenticate the supplied `AdmittedProducer`. Thirty-seven deterministic
  gate tests pass without sleeping; predictor, replay-journal and alert-repository spies remain at zero
  for denial and successful acquisition paths. All 232 directly related tests pass. The complete suite
  passes with 662 tests and the four existing TF-005 warnings; repository-wide Ruff and both individual
  bounded Black checks pass.

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
- The supported raw application entry now enforces trusted adaptation (TF-014); it does not
  authenticate remote measurements or prove registered dataset membership. Fabricated raw rows cannot
  be distinguished from authentic measurements by schema validation. Swapping two valid numeric raw
  columns is also undetectable; only violations of the fixed positions' validation can be rejected.
  Unused raw fields receive string/size checks, not complete semantic validation. The existing 2^53
  packet/byte input bound remains conservative, including rejection of some exactly representable
  larger integers. Trusted code, setup and dependencies
  remain in the trusted computing base; private Python classes are not cryptographic credentials.
  Model scores are not calibrated confidence, and request UUIDs are not stable ingestion/deduplication
  identities. Stable identity exists only for registered offline UNSW members and row ordinals; it is
  not a live-sensor identity. External producer admission, service-level time, transport,
  backup/recovery and total storage limits remain unverified (TF-008/TF-009). See the
  [inference trust boundary](unsw_network_inference_boundary.md#security-and-scientific-claim-boundary).

## Blocked

- Host-model training and host scientific claims are blocked by missing representative benign-host data.
- Global training readiness remains false even though the authorized network baselines completed.
- Deep-learning work remains paused. Validation of the classical UNSW inference boundary does not
  itself authorize or establish requirements for deep-learning work.
- New claims of independent February/CIC evaluation are blocked because those outcomes are known.
- Cross-source compatibility approval is blocked by TF-012 and TF-003.

## Not yet implemented

- A supported end-to-end product path connecting the implemented registered-offline inference and
  AlertCandidate persistence boundary to correlation, explanation and dashboard display.
- Stable source-event orchestration, the security-audit sink and directly
  terminating loopback TLS transport with socket-enforced handshake/read/idle timeouts.
- Product API/view-model contracts, dashboard behavior, backup/recovery, optional-service degradation,
  and integrated resource/latency evidence.
- Approval-gated allowlisted containment with audit and rollback. No automatic containment is supported.
- A verified jury requirements reference, confirmed target-user/environment decision, operational
  acceptance targets, manual-workflow baseline, or representative-user usefulness study.

## One next implementation task

Implement and unit-test the bounded sanitized producer security-audit sink.

Resume handoff: the durable three-state request replay journal is implemented and tested on top of the
transport-independent admission record. Process-local rate/concurrency controls are now implemented.
Actual TLS authentication, stable event orchestration, audit durability and the service remain
unimplemented; TF-008/TF-009 stay
open. Nothing is staged, committed or pushed. No dataset/artifact access, package download, training,
fitting, preprocessing, evaluation, listener, AlertCandidate persistence change, dashboard, LLM,
correlation, SOAR or deep-learning work occurred.
