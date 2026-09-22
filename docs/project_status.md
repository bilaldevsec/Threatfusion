# ThreatFusion current project status

## Snapshot

Status date: 2026-09-22. Branch: `main`. The corrected v2 experiment is checkpointed and pushed at
`8aa26ba250e4a63f95d90960ec87e224325b6d2f`; Backend quality run `35438412921` passed. The FYP-II
recorded-data demonstration is checkpointed and pushed at
`f71a5e74186a8975b4ca090b9d1a987384a55da4`. Both autoencoder runs and generated demonstration
evidence are ignored. Existing split, preprocessing, historical autoencoder, and classical-model
artifacts remain unchanged.

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
- The frozen benign-only UNSW autoencoder milestone completed once without retry or tuning. Exact
  `torch==2.10.0+cpu` is locked to the explicit official CPU index; TF-015's prerequisite smoke passes.
  The 14-8-3-8-14 model fitted 30 epochs on exactly 847,837 benign TRAIN rows, while the unchanged
  preprocessor retains statistics from all 865,480 TRAIN rows. The threshold is
  `0.11813611984640647`, calibrated by the frozen higher 99th percentile of 212,210 benign January
  VALIDATION scores with strict `score > threshold`. January post-calibration F1 is 0.498621 with
  FPR 0.007672. Previously inspected February F1 is 0.866667 with FPR 0.022477; this is not independent
  evaluation. Against RF, AE-only detections add 96 attacks/1,574 benign false positives in January and
  2,802 attacks/22,056 benign false positives in February. Fusion remains disabled. The state is 4,931
  bytes, fit time is 176.985 seconds, total runner time is 188.000 seconds, and measured peak RSS is
  944,115,712 bytes. Aggregate artifacts are ignored; CIC and Mordor were not accessed.
- The bounded autoencoder scientific review preserves that run as historical v1 evidence and corrects
  four reusable-boundary defects under TF-016. The historical residual used the float32-converted input,
  rather than the original transformed float64 value stated by the earlier formula. Its caller-batched
  forward was also score-unstable: on the original workstation, one fixed synthetic threshold-tie
  reproduction changed from `0.9457795181243431` alone to `0.9457795275677049` in a mixed batch and
  changed the strict decision. Those absolute values are runtime-specific execution evidence.
  The versioned v2 scorer performs one shape-(1,14) float32 forward per record and fixed float64 residual
  accumulation; exact regressions cover singleton/mixed calls, caller chunks, positions, repetitions,
  final partial chunks, the reproduced tie, and save/reload. The five historical artifact hashes remain
  the historical identities; none was modified or rescored.
- Reusable autoencoder loading now requires a code-owned approved artifact identity and verifies all
  bundle bytes before state deserialization. It binds the scoring contract, architecture, feature order,
  weight identity, configuration, threshold, preprocessing, Python, PyTorch, platform, CPU/dtype/thread
  runtime, report, and future source-snapshot provenance. A self-asserted bundle identity is rejected.
  The historical identity fails threshold loading with the sanitized reason
  `historical_threshold_incompatible_with_scoring_contract_v2`. The new v2 experiment is calibrated and
  verified but remains outside the product-approved registry.
- The historical bundle did not preserve the exact protocol or uncommitted model/runner source bytes used
  for execution. Current files are not substituted for those missing bytes. Before any future fit, the
  v2 runner writes exact protocol/model/runner snapshots and a canonical digest manifest, then binds it
  into the pre-fit configuration and completed artifact manifest. Missing, mismatched, and altered
  provenance regressions fail closed.
- One corrected v2 baseline completed in ignored run
  `full-benign-autoencoder-2a51c94-v2`. It retained the same fixed fit and state, calibrated the v2
  threshold `0.1181361214680695` on 212,210 benign January rows, and evaluated January and the previously
  inspected February benchmark once. Confusion counts match historical v1: January TP/FP/TN/FN are
  1,988/1,628/210,582/2,370 and February counts are 248,531/25,934/1,127,842/50,537. January AP/ROC-AUC
  are 0.348040/0.917107; February AP/ROC-AUC are 0.828553/0.950891. January AE-only detections add 96
  attacks and 1,574 false positives versus RF. Total runner time was 275.929 seconds and peak RSS was
  901,115,904 bytes. Independently calculated hashes passed the complete experimental bundle verifier;
  saved/reloaded v2 scores and decisions were exact across caller chunks. The identity remains
  experimental, and fusion/integration remain disabled.
- Corrected v2 validation passes all 41 focused autoencoder tests and the one-time 895-test backend
  suite with no final failures or skips and four existing TF-005 warnings. Five of the six CI
  availability-gated tests passed together locally; the real TLS smoke first encountered the sandbox's
  loopback restriction and then passed through the loopback-capable path. Ruff, both bounded Black
  checks, lock consistency, whitespace, and final-newline checks pass. All 14 historical/frozen artifact
  hashes remain unchanged.
- The preregistered January-only v2 residual-contribution audit is complete. The first attempt reached
  publication but lost its in-memory aggregates because of a publication field-name defect; no result
  from that attempt is retained or reported. After explicit authorization, exactly one additional
  January scoring pass completed and retained verified aggregate JSON, long-form CSV, an SVG chart, and
  an aggregate-only ignored recovery file. It reproduced all frozen January confusion/overlap counts
  and exact score/residual arithmetic. AE-only attacks were dominated by rate-feature residuals
  (93.78%); AE-only benign false positives were split mainly between rates (38.75%) and byte counts
  (38.44%). This remains calibration-informed descriptive evidence, not causal attribution,
  independent evaluation, fusion evidence, or product approval. The pass recorded 27.30 seconds,
  505,634,816 bytes peak RSS, and no TRAIN, February, or CIC access. The completion review confirmed
  positional label/AE/RF alignment and exact v2 residual arithmetic. It corrected recovery integrity by
  binding and revalidating the exact aggregate payload before retry; a valid retry precedes and bypasses
  all scoring-input access. Ten focused publication, recovery, CLI-failure, alignment, and aggregation
  tests and audit-file Ruff pass. The bounded local Black check reported both files unchanged but
  required timeout termination after emitting that result.
  All reported feature/group percentages are pooled-error fractions, not fractions of records. Feature
  medians support only a limited qualitative common-rate-residual observation for the 96 AE-only attacks;
  the other flagged cohorts are strongly skewed, including forward-byte mean/median squared residuals
  of 141.72/0.00077 for attacks detected by both models. The aggregates cannot quantify per-feature
  outlier concentration, characterize a typical record with group percentages, define a decision rule,
  or justify a specific model experiment.
- TF-016 final validation passes 41 focused autoencoder tests, 96 other related artifact/loading tests,
  and one 895-test complete backend suite. The full suite has no failures or skips and the four existing
  TF-005 Mordor date-parsing warnings. Repository Ruff, three individually bounded Black checks,
  `uv lock --check`, and tracked/untracked whitespace and final-newline checks pass. All five historical
  autoencoder and all nine frozen preprocessing/logistic/Random Forest hashes match their recorded
  values. No dataset or generated artifact was modified or created.
- Post-stabilization validation passes all 862 backend tests with no skips or failures and four existing
  Mordor date-parsing warnings. Repository Ruff, the three individual bounded Black checks, lock
  consistency, documentation whitespace/final-newline checks, and verification of all nine existing
  frozen artifact hashes pass. The canceled permission attempt left no pytest process; only the later
  authorized loopback-capable rerun completed.
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

- The internal `producer_security_audit_event_v2` contract and
  `producer_security_audit_sqlite_v2` repository extend the fixed taxonomy with an exact
  `startup_recovery` event while preserving the existing admission/replay reason codes. Events contain
  only trusted UTC time, a generated UUIDv4, optional server correlation UUID, fixed
  stage/outcome/reason, internally resolved producer
  and source-contract IDs, and optional already-available credential/request/body SHA-256 digests.
  The strict SQLite v2 boundary uses atomic `BEGIN IMMEDIATE` appends, exact schema/index/integrity and
  row validation, equivalent retry by audit-event ID, conflict rejection, 500 ms busy waits, stable
  bounded listing, restart preservation, and a hard 100,000-event cap. A full sink fails closed without
  deleting, overwriting, or wrapping history; orchestration maps unpersistable denial evidence
  to generic `audit_unavailable` and must block any request that would otherwise reach prediction or
  persistence. The repository exposes no update/delete API and never calls replay processing, inference,
  or AlertCandidate persistence. SQLite is not tamper-evident and provides no protection from a
  filesystem owner, compromised process, SQLite administrator, or kernel. Export, retention, rotation,
  backup, and recovery remain production work. Current component validation is included in the final
  focused and full-suite evidence below.

- The internal producer TLS transport directly terminates TLS 1.3 on exactly IPv4 `127.0.0.1`,
  requires a CA-verified client certificate, obtains verified DER and decoded peer metadata, derives
  the DER SHA-256 fingerprint, accepts URI SAN identity only, and submits canonical peer evidence to
  the existing certificate registry. Wildcard, external, hostname-resolved, other-loopback and IPv6
  binds fail before socket creation. The staged one-request API freezes
  `POST /v1/producer-events HTTP/1.1`, four required control headers, exact CRLF/ASCII and bounded
  inert extension headers; rejects duplicate/folded/encoded/upgraded/keep-alive/pipelined input; and
  separates authenticated head validation from explicit bounded body consumption. Rotating internal
  capabilities enforce one legal head/body/response sequence and every success/failure path closes the
  accepted socket. Monotonic socket deadlines are exactly three seconds for handshake and five total/
  one idle for reads; synchronized tests use smaller internal bounds without changing production
  constants. Responses validate the existing bounded producer response and send a small generic fixed
  failure rather than truncate unsafe output. The listener backlog is one because the kernel TCP queue
  cannot honestly be zero; the application adds no queue or serving loop. Certificate/key/CA paths,
  filesystem/OS permissions and Python/OpenSSL remain trusted setup, with no descriptor-level load
  TOCTOU claim. This strict subset is not production-grade HTTP and becomes invalid as an authentication
  claim if TLS terminates elsewhere. All 67 TLS transport tests and 210 directly related admission,
  gate, replay and audit tests pass. The complete suite passes with 795 tests and the four existing
  TF-005 warnings; repository-wide Ruff and both individual bounded Black checks pass.

- The fixed synchronous producer orchestrator now joins directly terminated TLS identity, full
  application admission, rate/concurrency, durable replay claim, durable request audit, registered
  Random Forest inference, Attack-only candidate persistence, completion audit, replay completion,
  bounded response writing and exact lease release in that order. V2 responses bind each disposition to
  predicted class/probability and expose a stable candidate ID only for persisted Attacks while
  preserving legacy v1 bytes. Exact replay retries are byte-identical and make zero predictor or alert
  calls; `in_progress` and terminal `outcome_unknown` remain non-executing; write failure still permits
  the same durably completed cached retry. Ambiguous inference/persistence/response-finalization/replay
  completion and lease-release failures poison the service generation, and explicit abandoned-generation
  recovery is audited. The adversarial review corrected admission/gate ordering, a slow sanitized
  inference rejection that bypassed timeout classification, and unhashable v2 fields that escaped fixed
  response validation. A follow-up invariant review then reproduced and corrected successful response
  writing before durable replay completion. Bounded integration now drives the supported
  `ProducerOrchestrator.process_one` entry through a real IPv4-loopback TLS 1.3 connection with mutual
  certificate authentication and temporary SQLite replay, audit, and alert repositories. Controlled
  Normal/Attack results prove response binding and Attack-only insertion; an exact retry after repository
  reopen returns identical cached response bytes with zero new inference or alert insertion. Real
  authentication/admission rejection and an injected pre-inference audit failure have zero predictor and
  alert-insertion calls, while injected replay-completion failure sends no success bytes. A correction
  review then established six further regressions and fixed them without changing the supported scope:
  all registered identities, ordinals, file digests and adapted immutable rows are now preflighted before
  the first final-predictor call; prepared rows are bound to the boundary that verified them; finalization
  timeout and ambiguous persistence/replay/response failures poison the generation and attempt a
  request-bound failure audit; connection closure survives lease-release failure; and v1/v2 response
  wire keys, reasons and malformed construction fail closed. Real TLS cases cover invalid later ordinal,
  unknown member and malformed later registered row through the actual reader/adapter with zero final
  predictor and alert-insertion calls. Each case joins
  its bounded thread, closes listener/client/accepted sockets, releases any lease, closes per-operation
  SQLite connections, and removes temporary databases and credentials. One available registered
  `UNSW-NB15_1.csv` record also completed the same TLS/orchestrator path through the verified frozen Random
  Forest artifacts; this is functional evidence only, not accuracy evaluation. Final validation passed
  422 focused producer/binding/persistence tests, eight real loopback integration cases, and one complete
  852-test suite with the four existing TF-005 warnings and no skips.
  A bounded closure review then found that ambiguous replay-claim failure still bypassed failure
  auditing. Two new regressions first failed with zero audit attempts after a real temporary SQLite
  claim committed. That path now calls the existing nonrecursive `_raise_ambiguous` helper with the
  validated admission record and authenticated session. A healthy sink persists one request-bound
  `internal_failure` event; a failing sink is attempted once without replacing the sanitized
  `replay_claim_ambiguous` error. Both cases preserve fatal state and durable `in_progress` replay,
  send no response, make zero predictor/alert-insertion calls, and close the connection and release
  the lease. Ordinary replay conflicts and retries retain their existing handling. After this scoped
  correction, all 156 orchestrator/replay/audit tests pass; one full suite passes 854 tests with the
  same four TF-005 warnings and no skips. Repository Ruff and all nine individual bounded Black
  checks pass. The other five findings and replay ordering were not reopened for review.
  Registered preparation and frozen Random Forest prediction now run in a fresh spawned worker process
  for each newly claimed request. The parent enforces exact 30-second per-record and 300-second
  whole-request production limits, with shorter limits allowed only by test configuration. A bounded
  one-way protocol carries preparation, record-start, result and completion messages; strict parent
  validation binds stable order, registered source-event identity, frozen RF identity/artifact,
  timestamps, scores and dispositions. No AlertCandidate is constructed or persisted until the complete
  batch is valid and the exact worker/process group and pipe are cleaned. Crash, hang, silent exit,
  malformed/missing response, child exception and cleanup failure therefore create no partial alert.
  Timeout maps to `processing_timeout`; every other worker failure maps to `internal_error`, without
  exception/path/credential/model-location disclosure. Completed replay remains byte-identical and
  starts no worker. A later fresh request remains usable after a cleaned worker failure. The wrapper
  creates no queue, thread, listener, database connection or temporary file. A serving loop and broader
  operational resource evidence remain absent.
  Final validation passed 16 focused worker tests, 491 related producer/admission/inference/persistence/
  replay/TLS tests, 13 focused FYP demo/viewer tests, and the real IPv4-loopback frozen-RF worker smoke.
  The one permitted complete backend run passed 944 tests with zero failures or skips and the four
  existing TF-005 warnings. Terminal-message review then tightened rejection of output after a valid
  completion; the final focused matrix and real worker smoke passed after that correction, and the full
  suite was not repeated under the exactly-once validation constraint. The recorded demo passed once
  with unchanged predictions, exact replay counts, one invalid request with unchanged effect counts, and
  complete cleanup. Independent verification passed for all 23 immutable preprocessing, RF/logistic and
  historical/corrected autoencoder files.

- A terminating producer serving lifecycle now wraps the unchanged one-request orchestrator. Explicit
  startup opens one directly terminating loopback listener and reports readiness only with exactly two
  fixed non-daemon handlers alive. There is no application queue: the existing shared gate still
  permits one active execution, and the second handler lets an authenticated overlap receive immediate
  `server_busy`. Idle accept polling is distinct from handshake timeout and creates no false
  authentication audit. Shutdown closes admission and joins both handlers under a 310-second ceiling;
  accepted work retains the exact 30-second record and 300-second request deadlines. Clean stopped
  instances reopen and exact completed replay remains byte-identical; fatal generations cannot restart.
  Real mTLS tests cover successive requests, overlap, restart, worker malformed-result failure and
  shortened record timeout, with no remaining listener, handler, lease, worker/process group, partial
  alert or SQLite sidecar. A two-request controlled-inference measurement took 0.360245 seconds
  (5.551781 requests/second): pytest-process high-water RSS was 187,817,984 bytes; sampled descriptors
  were 6 baseline/12 maximum/6 after shutdown; threads were 1 baseline/4 maximum including sampler/1
  after shutdown; active children were zero; and sampled SQLite bytes peaked at 81,920. This short
  harness measurement includes pytest/TLS overhead and is not frozen-RF latency, endurance, an
  operational limit, or production readiness. All 12 new lifecycle/idle-accept cases and the 519-test
  related slice pass. The single post-stabilization full backend run passes all 956 collected tests
  with no failures or skips; repository Ruff, seven individual Black checks, whitespace checks and the
  affected recorded-data demo pass. The demo retained its exact RF predictions/replay/effect counts
  and independently verified all 23 immutable artifacts. TF-008/TF-009 remain open.

- A bounded evaluator-facing FYP-II runner now composes the existing supported components without a
  new service or inference path. It uses one-use credentials and temporary SQLite databases, submits
  frozen registered UNSW rows 1 and 21 over real loopback TLS 1.3/mTLS, displays their known labels
  separately from actual frozen Random Forest predictions, persists only the Attack candidate, proves
  exact completed replay with unchanged inference/insertion/alert counts, and rejects one authenticated
  invalid request before prediction or persistence. The deliberately illustrative rows are not an
  unbiased sample or accuracy evidence. A separate research-only section verifies all nine corrected
  v2 autoencoder files against independently pinned demo hashes and the complete existing bundle loader,
  then reports per-record reconstruction score, calibrated threshold and strict decision. The v2
  identity remains outside the product registry; producer integration and fusion remain disabled. The
  ignored sanitized report is written beneath `artifacts/reports/fyp_progress_demo/latest/`; temporary
  credentials, listener, request threads, leases and databases are cleaned on exit. See
  [`fyp_progress_demo.md`](fyp_progress_demo.md).
- Two final complete real-loopback rehearsals passed with identical predictions, scores, decisions,
  zero-additional-effect replay/rejection counts and byte-identical sanitized evidence; the timed run
  completed in 31.50 seconds. All six
  focused demo contract/cleanup tests pass with no warnings. Repository Ruff, bounded Black checks for
  both changed Python files, whitespace/final-newline checks, and independent hashes for all five
  historical AE files, all nine corrected v2 AE files, and all nine frozen preprocessing/LR/RF files
  pass. The full backend suite was not repeated because Milestone B changes only an isolated script,
  its new focused tests, and documentation; no production Python or shared component changed. Review
  additionally verified nonzero sanitized CLI failure and corrected service/listener cleanup when setup
  or client exchange fails before ordinary request completion.

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
- New claims of independent February/CIC evaluation are blocked because those outcomes are known.
- Cross-source compatibility approval is blocked by TF-012 and TF-003.

## Not yet implemented

- A supported end-to-end product path connecting the implemented registered-offline inference and
  AlertCandidate persistence boundary to correlation, explanation and dashboard display.
- A daemon/CLI, signal handling, service-manager integration, endurance evidence and frozen operational
  resource/capacity targets around the terminating in-process serving lifecycle.
- Product API/view-model contracts, dashboard behavior, backup/recovery, optional-service degradation,
  and representative frozen-RF/operational resource and latency evidence.
- An approved v2 autoencoder detector plus versioned result/persistence contract. The experimental v2
  threshold is calibrated and its bundle verifies, but its identity is not product-approved. The research
  runner does not change the frozen Random Forest application path and does not authorize fusion.
- Approval-gated allowlisted containment with audit and rollback. No automatic containment is supported.
- A verified jury requirements reference, confirmed target-user/environment decision, operational
  acceptance targets, manual-workflow baseline, or representative-user usefulness study.

## Latest scientific task

The final January-only record-concentration diagnostic is complete under its frozen protocol. One
authorized pass completed without retry and retained aggregate JSON, two CSVs, one SVG, and bound
aggregate-only recovery evidence. All cohort, score, residual, loading, row-alignment, and access gates
reconciled. Rates are the unique dominant group in 85/96 AE-only attacks with a 94.26% median record
share; their top 10% contribute 41.61% of attack rate error. For 1,574 AE-only benign false positives,
the rate median is only 0.42%, rates dominate 274 records, and the top 10% contribute 95.68% of benign
rate error. Full results and limitations are in
[`network_autoencoder_residual_audit.md`](network_autoencoder_residual_audit.md).

Decision A supports, but does not execute, one fixed hypothesis: apply `log1p` only to the two raw rate
features before the existing TRAIN-only z-score fit, with architecture and all other controls unchanged.
The preregistered acceptance criteria and population roles are recorded in the audit document. January
informed calibration and this intervention; February has already been inspected; TF-006 and TF-007
remain open. The corrected v2 baseline, all classical models, and the working demonstration remain
preserved and unchanged.

Resume handoff: outcome is Decision A; evidence is the ignored aggregate report and diagnostics; changed
files are the existing audit runner, its focused tests, this status, the audit document, and the issue
register. No training, fitting, calibration, February/CIC/TRAIN access, model/dependency/threshold,
fusion, worker, or demo change occurred. Next action: seek explicit authorization only if the owner
wants to execute the single frozen rate-tail-compression experiment.

## Two-rate log1p experiment outcome, 2026-09-19

The separately authorized single experiment is complete under the frozen
[`protocol`](network_rate_log1p_autoencoder_protocol.md). Exact raw-derived rate pairs were admitted for
865,480 TRAIN and 216,568 January rows; no February feature or label was retained. The experiment ran
under a Landlock ABI 8 allowlist that denied real UNSW raw, February matrix/label, and CIC paths before
fitting. Candidate preprocessing used all TRAIN rows; AE weights used only 847,837 benign TRAIN rows for
exactly 30 epochs. Baseline inputs and the frozen RF remained separate and unchanged.

The candidate threshold is `0.08645885557604867`. January TP/FP/TN/FN are
945/2,122/210,088/3,413; precision/recall/F1 are 0.308119/0.216843/0.254545. It recovered 59 attacks
missed by RF and added 2,080 benign false positives. All four frozen gates failed, overall recall fell
by 0.239330, and attacks detected by both models fell by 1,006. Disposition: **FAIL — preserve the
corrected v2 baseline**. Total experiment time was 559.896 seconds, peak RSS 872,030,208 bytes, and
bound candidate evidence was below the 256 MiB limit. The ignored candidate identity is
`910d2977c93285f54c33408268bb316c5a8f9093042927a77de5ba6fe5fb36f4`; it is not product-approved or
registered. No February/CIC evaluation, fusion, dependency change, demo change, or issue closure
occurred. TF-006 and TF-007 remain open.

Resume handoff: the experiment and completion envelope are preserved, all gates failed, and the
baseline remains authoritative. Changed tracked files add the frozen protocol, isolated experiment and
finalization runners, candidate implementation, focused tests, and these status records while preserving
the five prior diagnostic modifications. Next action: retain the failed candidate as development
evidence and return to the existing project roadmap without another experiment or diagnostic audit.

### Rate-log1p completion-review correction, 2026-09-20

The numerical candidate report and its failed gates remain preserved, but the experiment is not a
protocol-valid completed result. The preparation process adapted all globally assigned rows and its own
report records 1,452,844 TEST rows seen before TEST outputs were discarded. Landlock protected only the
later fit process. Preparation deadline/RSS and pre-fit total-artifact limits were not hard enforced;
execution peak RSS was checked after computation; and the CLI generic-error fallback was not strictly
allowlisted. Although observed use stayed within every numerical bound, these defects violate the
frozen isolation and enforcement requirements.

February access during preparation does not prove that February rows entered optimizer batches. The
retained accounting reports exactly 847,837 benign TRAIN rows in each epoch. The access-boundary breach
alone is sufficient to block the result.

The superseding disposition is **BLOCKED — preserve the corrected v2 baseline**. The 945/2,122/210,088/
3,413 candidate confusion counts and four failed gates are retained only as protocol-invalid development
evidence. No new fit, preparation pass, scoring pass, or audit is authorized. TF-006 and TF-007 remain
open and no issue disposition changes.

The tracked historical CLI now rejects `prepare` and `run` with the sanitized code
`experiment_closed_blocked_no_reuse`; report-only rendering remains available. The runner is unsuitable
for reuse until the documented preparation-access and resource-enforcement defects are corrected under
new authorization. This closure guard does not modify the original ignored runner snapshot or report.

Resume handoff: existing candidate artifacts and exact execution snapshots are preserved and bound by
the corrected completion manifest; no process is running. The concrete blocker is the already-consumed
one attempt's February-accessing preparation plus nonconforming hard-limit enforcement. Next action:
retain the blocked result and continue the pre-existing product roadmap without retrying this experiment.

### Offline FYP evidence viewer, 2026-09-20

A read-only generator renders retained sanitized FYP demonstration, frozen RF and corrected v2 AE
reports, January residual aggregate/recovery binding, and protocol-invalid rate-log1p evidence into one
ignored self-contained HTML file. It does not run models or open data. Required evidence missing,
malformed, incomplete, v2-binding-mismatched, or recovery-binding-mismatched fails publication with a
sanitized nonzero error. The page distinguishes saved replay from live processing, known labels from
predictions, January from previously inspected February, RF estimates from guaranteed confidence,
disabled fusion, pooled residual fractions from per-record statistics, and the candidate's **BLOCKED —
preserve baseline** disposition. See [`fyp_evidence_viewer.md`](fyp_evidence_viewer.md). This does not
close TF-006, TF-007, TF-008, TF-009, TF-010, TF-011, or TF-012 and does not establish dashboard/product
acceptance.
