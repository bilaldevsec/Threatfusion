# ThreatFusion current project status

## Snapshot

The following baseline snapshot is dated 2026-09-24 on `main`; later Gemini-branch milestones appear
below. The corrected v2 experiment is checkpointed and pushed at
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

- The independent human-authentication review reproduced and corrected two defects: an accepted peer
  could dispatch a transition after listener close, and a fragmented body could hide present trailing
  bytes. The listener now synchronizes close with dispatch, interrupts undispatched connections,
  rejects concurrent handlers and excess body bytes, and rechecks credential validity before each
  repository operation. All 128 affected analyst/producer transport and repository tests run during
  this review pass, including 26 analyst boundary cases. The previous implementation's full-suite
  and recorded-demo results below are prior evidence, not reruns in this review. These isolated
  listener corrections did not change shared repositories, producer behavior or model code, so no
  additional local full-suite/demo run was required. See the findings and exact revocation semantics
  in [`analyst_authentication_transport.md`](analyst_authentication_transport.md). TF-008/TF-009 remain
  open for operational provisioning, browser/session safety, security auditing and endurance.

- A separate human mTLS loopback listener now verifies the actual client TLS certificate with a
  dedicated human CA and exact DER fingerprint/SAN allowlist, then maps the server-owned actor ID to
  the existing viewer/analyst capability registry. It exposes bounded alert list/detail reads and
  analyst transitions through the existing `analyst_alert_view_v1` contract. Producer credentials and
  routes remain separate. Real-loopback tests cover distinct human identities, missing/producer-only,
  revoked, unknown and wrong-SAN credentials, viewer write denial, forged/malformed requests, exact
  and cross-identity replay, rotation/revocation after restart, and sanitized storage failure. The
  exact trust path and limitations are in
  [`analyst_authentication_transport.md`](analyst_authentication_transport.md). This is a terminating
  local demonstration listener, not a browser-ready dashboard, daemon or operational authentication
  deployment. The focused analyst/producer transport slice and one complete backend suite pass, with
  the four existing TF-005 date-parsing warnings; repository Ruff, changed-file Black checks and
  `git diff --check` pass. The existing recorded-data demo also passes with its unchanged RF decisions,
  replay counts, alert count and cleanup evidence; its selected examples remain illustrative, not
  independent evaluation. TF-008/TF-009 remain open.

- On 2026-09-24, inspection found no authenticated analyst identity path: the direct TLS listener and
  certificate registry admit only registered producer replay to the fixed ingestion route; the local
  analyst registry assumes an identity was already authenticated upstream. No analyst network endpoint
  was exposed. Internal `analyst_alert_view_v1` formatting now provides bounded ordered list, single
  detail and transition results with explicit immutable detection evidence versus analyst state and
  rationale history. It uses the existing capability-checked repository, frozen transition/UUIDv4
  rules and fixed sanitized errors. Focused tests cover unauthorized and wrong-capability calls,
  viewer reads, analyst transitions, replay/stale/concurrent commands, ordering/bounds, restart and
  response sanitization. All 16 focused analyst tests and the one full backend suite pass (four existing
  TF-005 date-parsing warnings); repository Ruff, both changed-file Black checks and `git diff --check`
  pass. TF-008/TF-009 remain open; real analyst transport integration is blocked by the missing user
  authentication and server-owned identity-to-capability mapping.

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

- The bounded correlation review found no defensible relationship key in retained
  `alert_candidate_v1` evidence: endpoints, hosts, accounts, sessions and flow identity are absent;
  observation time alone cannot establish a relationship; and `correlation_id` is only an inference
  attempt. The frozen rule therefore performs no distinct-alert grouping, has no time window and emits
  no incident identity. Equal candidate IDs remain alert-persistence retries, not correlated incidents.
  A separate `analyst_state_sqlite_v1` repository now supplies the independently useful per-alert
  workflow `new → in_review → {closed | escalated}`. Registry-bound process-local capabilities allow
  configured viewers to read and configured analysts to transition; the registry relies on upstream
  authentication and is not a public credential boundary. Optimistic versions and UUIDv4 operation IDs
  make exact retry idempotent and reject conflicts, stale/reordered commands and concurrent losers.
  Required bounded rationale events are append-only and separate from immutable detection evidence.
  Bounded candidate-ordered list and detail reads validate current state against the complete two-event
  maximum history. SQLite transactions prevent partial state/history writes, and schema-checked reopen
  preserves committed workflow state. Twelve focused tests cover duplicate replay before and after a
  later transition, ordering, competing and identical concurrency, invalid/terminal transitions,
  authorization, missing candidates, rollback and restart. The complete backend suite passes all 968
  tests with the four existing TF-005 warnings; the 14 real-loopback producer integrations and existing
  recorded-data demo also pass unchanged. See
  [`alert_correlation_analyst_state.md`](alert_correlation_analyst_state.md). TF-008/TF-009 remain open:
  there is no correlation, authenticated external analyst API, dashboard, backup/recovery or endurance
  evidence.

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

- A supported end-to-end product path connecting registered-offline inference and AlertCandidate
  persistence through the new separate analyst listener to explanation and dashboard display. Distinct-alert
  correlation additionally remains blocked pending a reviewed retained relationship key and window.
- A daemon/CLI, signal handling, service-manager integration, endurance evidence and frozen operational
  resource/capacity targets around the terminating in-process serving lifecycle.
- Browser/session integration, dashboard behavior, backup/recovery, optional-service degradation,
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

- The internal `analyst_security_audit_event_v1` contract and `analyst_security_audit_sqlite_v1` repository provide bounded local security-audit persistence for the analyst boundary, integrated into `AnalystTlsListener`. State mutations and audit events use two independent SQLite transaction boundaries without distributed transactions. Pre-commit audit failures abort with 503; post-commit audit failures return 503 while same-UUIDv4 retry prevents state duplication, leaving an audit gap for the initial failed completion write. Authentication-rejection audit logging is best-effort returning 401, idle TLS disconnects/timeouts emit no false audit events, and routes record fixed templates or omit unknown paths. (Added 2026-09-25; TF-008 and TF-009 remain open pending dashboard, operational provisioning, backup/recovery, and endurance proofs).
- The authenticated read-only analyst dashboard slice (`threatfusion.api.analyst_dashboard`) connects a human analyst with verified mTLS credentials to `AnalystTlsListener` over mutual TLS 1.3 loopback transport, retrieving real persisted alerts and detail without state mutation. Empty queue and unavailable backend states are cleanly distinguished without data leakage, and a sanitized HTML presentation is rendered via `render_dashboard_html`. (Added 2026-09-26; TF-008 and TF-009 remain open pending browser session/origin integration, operational provisioning, and endurance proofs).
- A distinct browser-facing read-only analyst boundary (`AnalystBrowserTlsListener`) exposes the triage queue and selectable alert detail view directly to browsers as HTML. It verifies the per-human identity from the mTLS certificate SAN, reusing the existing `HumanCredentialRegistry` and `AnalystSecurityAuditRepository` without trusting HTTP headers. The bounded listener interrupts incomplete requests on close, reports backend failures truthfully in audit, and limits UTF-8 HTML bodies to 131,072 bytes with a sanitized 503 on overflow. The final focused browser, analyst-listener, dashboard, and audit run passed 179 tests; affected-file Ruff, Black, and `git diff HEAD --check` passed. (Repaired 2026-09-26; TF-008 and TF-009 remain open pending an explicit write authentication/CSRF design, credential provisioning, and endurance proofs).
- The one-input registered browser path (`scripts/run_registered_browser_path.py`) reuses the existing UNSW producer orchestrator, frozen RF worker, Attack-only SQLite repository, analyst state/view model, and separate human mTLS browser listener. Registered member `7d851bbe…b55eb511` row 21 produced one HTTP 200 `created` Attack alert. A reopened repository, analyst view, and automated real-TLS browser queue/detail all reconciled candidate `alert_candidate_v1:4c785c6418ff70c92a635785f5954355b6222f324d1314565b624affe771a8f7`, model decision `Attack`, and implicit state `new` version 0. Queue and detail returned 200; an injected view-model failure visibly returned sanitized 503 with an `internal_failure` audit event and no state change. The standalone command completed, the focused producer/persistence/analyst/browser/demo suite passed 198 tests, affected-file Ruff and Black passed, and `git diff HEAD --check` passed. This is an automated real-TLS client test, not a human browser session, live telemetry, independent accuracy evidence, explanation, or full charter acceptance. See [`registered_browser_path.md`](registered_browser_path.md). (Added 2026-09-26; TF-008 and TF-009 remain open).

### 2026-09-27 — TF-008 factual retained-evidence explanation

Starting checkpoint: `6d44a42ffc494932c079698e342991b33a6fbd85`, branch
`gemini/product-20260924`, initially clean Gemini working copy. Added
`alert_explanation_v1` to authorized detail results and the read-only HTML page.
The contract is documented in `alert_correlation_analyst_state.md`: candidate and
canonical displayed-evidence digest binding, registry-matched frozen RF identity,
and a deterministic stored-score/threshold summary. No artifact is loaded or
rescored. Attribution, causality and source endpoints explicitly remain unavailable.
This checks retained identity, not original measurement provenance or fresh artifact
integrity. Optional generation failures and mismatched results preserve readable
model evidence, analyst state and history.

Acceptance: available summary for consistent approved RF evidence; unavailable for
unsupported identity/policy/score, wrong version, changed evidence or modified text;
authenticated real-TLS detail remains HTTP 200 after injected generation failure,
with the persisted candidate and existing `in_review` state/history unchanged.
Tests use synthetic persisted evidence fixtures and temporary human TLS certificates.
This is automated browser-listener evidence, not a manual browser demonstration or
another producer/model inference run. Frozen RF and separate experimental AE,
artifacts and datasets were untouched. TF-008 and TF-009 remain open.

Validation command (no inference or dataset tests):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/unit/test_alert_explanation.py backend/tests/unit/test_analyst_view_model.py backend/tests/unit/test_analyst_state.py backend/tests/unit/test_analyst_security_audit.py backend/tests/integration/test_analyst_browser_tls_service.py backend/tests/integration/test_analyst_dashboard.py backend/tests/integration/test_analyst_tls_service.py
```

Initial focused result: `205 passed in 29.71s`. After strengthening existing-state/history isolation, final result: `205 passed in 31.94s`.
Repository Ruff: `All checks passed!`. Black on the five changed Python files:
`5 files would be left unchanged.` `git diff HEAD --check`: exit 0, no output.
No staging, commit or push. Recommended next action: perform and record a manual
authenticated browser queue/detail demonstration of the registered-input path and
factual explanation.

### 2026-09-27 — Bounded manual browser demonstration preparation

Started on clean `gemini/product-20260924` at
`6b3f2c1347e5e1b861aa37d7eea862c04e790fb5`, Gemini copy only; push URL remains
`no-push://requires-explicit-review`. `scripts/launch_browser_demo.py` adds a
30–1800 second inspection window (default 900) to the existing registered one-row
producer/RF/persistence/browser runner. It requires available factual explanation
before inspection, exports one disposable viewer PKCS#12 bundle, and launches an
isolated Firefox profile. Installed Snap Firefox is invoked directly to avoid the
Ubuntu migration wrapper; its private runtime lives under ignored reports rather
than Snap-inaccessible `/tmp`. No system trust or normal profile is modified.

Acceptance evidence: launcher tests use real human-mTLS detail requests and an inert
browser substitute, cover expiry, interrupt, browser launch failure, process reaping,
profile/runtime deletion, private bundle permissions, SIGTERM handler restoration,
and invalid lifetime bounds. The registered-input integration test exercises the new
inspection hook after real producer/RF/persistence/browser checks and asserts factual
explanation availability. Initial focused result: `7 passed in 19.05s`. Final command:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/integration/test_browser_demo_launcher.py backend/tests/integration/test_registered_browser_path.py backend/tests/integration/test_analyst_browser_tls_service.py backend/tests/integration/test_analyst_dashboard.py backend/tests/unit/test_alert_explanation.py backend/tests/unit/test_analyst_security_audit.py
```

Raw final result: `159 passed in 37.41s`. Ruff: `All checks passed!`. Black on the
five affected Python files: `5 files would be left unchanged.` `git diff HEAD --check`:
exit 0, no output. The tests performed only the existing bounded registered-row RF
inference; no training, dataset/artifact changes, AE scoring, packages or deployments.

Exact setup/navigation/shutdown and expected candidate/explanation are in
`registered_browser_path.md`. No GUI browser was launched by this development session;
Firefox/Snap trust import, client-certificate selection, navigation and actual browser
shutdown remain pending human observations. SIGKILL/power-loss cleanup and escaped
browser descendants are not guaranteed. TF-008/TF-009 remain open. Changes are unstaged
and uncommitted. Recommended next action: run the documented launcher and supply the
manual certificate, queue/detail, explanation and shutdown observations.

### 2026-09-27 — Failed Firefox trial: bounded handshake repair

Resumed existing uncommitted launcher work at unchanged HEAD
`6b3f2c1347e5e1b861aa37d7eea862c04e790fb5` on `gemini/product-20260924`.
User reported correct temporary profile, CA/viewer import and viewer selection at
localhost:46087, then Firefox timeout during a 1800-second run. This is a failed/pending
manual demonstration. At diagnosis the port had no listener and no demo runtime
SQLite files remained. Exact historical chooser timing and request bytes are unknown.

Before production edits, a real TLS 1.3 test withheld the client certificate/Finished
flight for 3.3 seconds and received no HTTP response under the inherited 3-second
handshake timeout: `1 failed, 21 deselected in 11.06s` (expected 200, received empty
bytes). An immediate-certificate control using the same representative Firefox-style
headers passed: `1 passed, 22 deselected in 6.99s`. This isolates a reproducible
handshake-budget defect; it does not prove the exact unrecorded Firefox exchange.
No evidence demonstrated malformed framing or premature launcher shutdown in that trial.

Small repair: only the browser listener uses `BROWSER_HANDSHAKE_SECONDS = 60.0`.
The analyst API keeps 3 seconds; browser HTTP reads keep 5 seconds. The handshake
budget remains finite and independent of the launcher lifetime. Tests verify delayed
certificate success, accelerated expiry without view dispatch/audit completion, and
close interrupting a pending handshake under the full 60-second setting. Existing
launcher expiry/signal/cleanup and browser authentication/framing tests also pass.

Validation (no inference, training, GUI or manual retry):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/integration/test_analyst_browser_tls_service.py backend/tests/integration/test_browser_demo_launcher.py backend/tests/integration/test_analyst_tls_service.py backend/tests/integration/test_analyst_dashboard.py backend/tests/unit/test_analyst_security_audit.py backend/tests/unit/test_alert_explanation.py
```

Raw result: `199 passed in 39.30s`. Repository Ruff: `All checks passed!`. Black
checks including preserved uncommitted launcher files: `7 files would be left unchanged.`
`git diff HEAD --check`: exit 0, no output. This repair changes browser listener,
browser TLS tests, runbook, status and issue register; preceding launcher work is
preserved unstaged/uncommitted. TF-008 and TF-009 remain open. A stalled unauthenticated
connection can occupy the serial listener for up to 60 seconds; no concurrency or
endurance claim is made. Recommended next action: review this repair and evidence
before authorizing another manual Firefox attempt.

### 2026-09-27 — User-observed Firefox path; detail wrapping repair

The user reported a successful manual Firefox run on localhost:33991: the correct
viewer mTLS identity opened a queue containing one `Attack` alert in `new`; the
selectable link opened the full candidate detail URL; factual explanation appeared
as available with its stated limits. Ctrl+C printed
`{"status":"stopped","manual_result":"pending_user_observations"}`. That fixed
launcher string records shutdown, while the user's report records the browser result.
Read-only checks showed no listener on port 33991 and no profile at
`artifacts/reports/browser-manual-demo/threatfusion-fyp-demo-_4va309l/firefox-profile`.
No deletion was needed.

The user-provided screenshot showed Candidate ID, Source Event ID and Created At
text overlapping. The detail renderer's 300px minimum grid track and unbroken IDs
allowed content to overflow adjacent cells. A two-rule CSS repair allows tracks to
shrink with the panel and wraps long values inside their own cells, preserving full
escaped IDs and the queue link. A focused renderer regression asserts the responsive
CSS contract, the full ID fields and selectable full-ID link. Dashboard and browser
listener tests: `88 passed in 21.00s`. At that checkpoint, the corrected layout
still awaited a Firefox recheck at desktop and narrow widths. This user-observed
browser path does not by itself establish full product acceptance, operational
credential provisioning, endurance, or distinct-alert correlation. TF-008 and
TF-009 remain open. Changes remain unstaged and uncommitted.

Repository Ruff: `All checks passed!`. Black on the two changed Python files:
`2 files would be left unchanged.` `git diff HEAD --check`: exit 0, no output.
Recommended next action: visually verify the corrected detail panel at desktop
and narrow widths in an isolated authenticated Firefox session.

### 2026-09-27 — Failed 390×844 Firefox check; responsive queue repair

The user confirmed that the authenticated desktop queue/detail still works and
long candidate/source IDs no longer overlap. In a reloaded 390×844 Firefox
Responsive Design viewport, the entire desktop page was scaled down and queue
and detail text became unreadably small. **Mobile visual acceptance failed at
this checkpoint**; no repaired-layout screenshot was available then. The later
owner observation below supersedes this status without erasing the failure.

The renderer had no device viewport declaration, and its seven-column queue and
five-column history could impose wide intrinsic page widths. It now declares
`width=device-width, initial-scale=1`, keeps both tables inside labeled,
keyboard-focusable horizontal scroll regions, and enlarges the queue link text
and tap area at widths up to 600px. The alert link is in the first queue column;
remaining columns stay available by scrolling inside the region. Full candidate
and source IDs, all evidence, escaping, read-only behavior and desktop table
layout remain intact. The existing detail wrapping fix is preserved.

A focused renderer regression checks the viewport declaration, bounded table
regions, mobile link rule, full IDs, decision/state and selectable queue link.
Automated tests cannot certify Firefox's final mobile pixels. TF-008 and TF-009
remain open. No new manual browser run or screenshot was performed in this turn.
Focused dashboard/browser tests: `88 passed in 29.77s`. Repository Ruff:
`All checks passed!`. Black on the two affected Python files:
`2 files would be left unchanged.` `git diff HEAD --check`: exit 0, no output.
All work remained unstaged and uncommitted. At this checkpoint, the next action
was to capture a new 390×844 Firefox screenshot; the later owner observation
below records that visual result.

### 2026-09-27 — Owner screenshots supersede failed mobile visual check

The owner reports that the latest Firefox screenshots show the repaired desktop
layout and a readable 390×844 Responsive Design view. The queue link is visible;
horizontal scrolling exposes score, decision and state; full detail IDs and the
factual explanation are readable without overlap. This supersedes the earlier
failed mobile scaling observation, which remains recorded above. These are
owner-reported visual observations, not an accessibility audit, endurance result,
or proof of full product acceptance.

The latest screenshot report supplies no final launcher output or runtime path,
so cleanup for that run remains **unverified**. The earlier read-only port/profile
check applies only to the prior localhost:33991 run. Frozen RF and separate AE
constraints, the missing defensible distinct-alert correlation key, operational
browser credential provisioning, and broader TF-009 reliability work remain
open. TF-008 and TF-009 stay open. This documentation update changed no code,
tests, model or artifacts and ran no tests.

### 2026-09-27 — Distinct-alert relationship evidence gate

At clean `gemini/product-20260924` HEAD
`81906f4059bab85717bf84a75ffaad8b0c7cb9a1`, a source-to-view audit
reconfirmed that registered member digest plus row ordinal becomes one opaque
`source_event_id`, while the row's numeric UTC start time becomes `observed_at`.
The transient adapted flow contains endpoints, ports, flow ID and end time, but
these are not retained in the Attack-only candidate or analyst view. The alert
repository preserves candidate/source identities, observation and local creation
times, model evidence and an inference-attempt UUID; the view omits that UUID.
Producer request/replay IDs and times remain in their own boundary. Equal
candidate IDs with compatible evidence are one alert's retry, not correlation.
No retained value identifies a shared entity across different source rows.

No distinct-alert grouping or time window is justified, so no code or tests were
changed and no model/data path was run. The exact missing evidence is a validated,
scoped observed-entity identifier with source-appropriate issuance and mapping provenance,
role, lifetime and missing/conflict rules, bound immutably to each source event and
alert. Any bounded window also needs reviewed observation-clock quality and an
explicit duration. The current offline UNSW replay has no such asset namespace;
raw addresses cannot be silently promoted into a stable host or incident key.
The detailed chain, counterexamples and future acceptance gate are in
[`alert_correlation_analyst_state.md`](alert_correlation_analyst_state.md).
TF-008 remains open; TF-009's operational evidence gaps are unchanged. Frozen RF,
experimental unfused AE, blocked rate-log1p candidate and artifacts are untouched.

### 2026-09-27 — Registered UNSW identity provenance check

At clean `gemini/product-20260924` HEAD
`9b1c4783b4c1ed9cc954303577addfecb65e5372`, the manifest, official source
description, feature metadata, raw reader, adapter, registered inference reader,
producer and alert contracts were checked for an observed-entity identity. The
manifest verifies file bytes and row counts, not capture/sensor or asset scope.
The raw files have no native ID: the reader's `flow_id` is a filename/ordinal
bookkeeping value. `srcip`/`dstip` are row endpoint fields; neither the official
page nor registered contract verifies address ownership, reuse/NAT/alias lifetime
or initiator role. The adapter constructs end time from numeric `stime` plus
`dur` without validating `ltime`; UTC parsing does not verify capture-clock
timezone, synchronization, precision or error bound. Addresses, flow ID and end
time are not retained by the alert. See the source-provenance check in
[`alert_correlation_analyst_state.md`](alert_correlation_analyst_state.md).

No stable observed entity within a defined capture namespace is proven, so no
entity field, correlation rule or window was added. The missing evidence is a
reviewed capture/sensor namespace, authenticated address-to-asset mapping or
source-issued stable asset ID with role and validity interval, a privacy/retention
policy, and capture-clock quality. TF-008 and TF-009 remain open. An independent
next product milestone is bounded operational browser credential provisioning
and revocation evidence; it does not depend on alert correlation. No model,
dataset or artifact path changed.

### 2026-09-28 — Local operator human enrollment and restriction

Started clean on `gemini/product-20260924` at
`a6158cda69de1427d9cab30f5c96345c66fc0d16`. The new standard-library
`threatfusion.operations.human_credentials` module enrolls a pre-issued public
certificate into versioned operator-owned metadata and disables/revokes its exact
DER SHA-256 fingerprint. It validates the CA chain/client purpose, explicit
clientAuth-only EKU, CA:FALSE, exact human URI SAN and certificate validity.
The loader reuses immutable HumanCredentialRegistry and the separate authorization
registry; the construction adapter supports both existing listeners without a
fallback, daemon, issuance or hot reload. See the
[operator runbook](human_credential_operator_runbook.md).

Acceptance evidence: valid enrollment and exact mapping; invalid certificate/SAN/
purpose, duplicate/conflicting/malformed metadata, validity/UTC/capacity and unsafe
file/path rejection; private atomic replacement and failure preservation; lock
contention and unrelated-file protection; both real loopback mTLS listeners retain
the old policy across disk changes/reopen and deny restricted certificates after
reconstruction while another actor reads. Audit history remains intact and new
credential denials have authentication_rejected/authentication_failed classification.
Expiry/future enrollment bounds use injected decoded dates; real TLS certificates
are disposable test fixtures, not operational issuance evidence.

Validation commands and observed results:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/integration/test_operator_human_credentials.py backend/tests/integration/test_analyst_tls_service.py backend/tests/integration/test_analyst_browser_tls_service.py backend/tests/unit/test_analyst_security_audit.py backend/tests/unit/test_analyst_state.py
```

Sandbox: `85 failed, 82 passed in 30.87s`, exit 1 (root ownership remapped to
65534 and loopback unavailable). A diagnostic `-xq --tb=short` run of only
`test_operator_human_credentials.py` stopped at the ownership rejection:
`1 failed in 8.31s`, exit 1. The exact combined command outside the sandbox:
`4 failed, 163 passed in 36.25s`, exit 1. All 134 existing tests passed; four new
assertions incorrectly required an HTTP 401 where the established contract also
permits TLS close. Those assertions were corrected while retaining audit checks.
After final UTC/capacity/lock review, only the new test file was rerun:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/integration/test_operator_human_credentials.py
threatfusion-venv/bin/ruff check .
threatfusion-venv/bin/black --check backend/src/threatfusion/operations/human_credentials.py
threatfusion-venv/bin/black --check backend/tests/integration/test_operator_human_credentials.py
git diff HEAD --check
```

Final operator tests: `38 passed in 12.40s`, exit 0. Repository Ruff passes,
exit 0 (initial fixture import warnings F811/E402 fixed). Individual Black checks
pass, exit 0. Multi-file Black format/check invocations stalled and were interrupted
(exit 130); individual file formatting/checks completed. Whitespace check passes,
exit 0. No full suite or model inference ran. Changes are uncommitted for review.

Self-review retained strict ownership checks despite the sandbox incompatibility,
checked both UTC bounds explicitly, verified no role fields or private material
enter policy, and inspected all changed/new source, tests and documentation.
No independent security review is claimed. CA issuance, secure delivery, recovery,
live reload, endurance, operator-action audit history and policy archival remain
outside this phase; the 64-record cap includes retained disabled/revoked records.
TF-008 and TF-009 remain open, as do unrelated scientific/product evidence gaps.
Frozen RF, experimental unfused AE and blocked rate-log1p remain untouched.
Recommended next action: review this uncommitted enrollment/revocation phase.


### 2026-09-28 — Credential gate completed; controlled human listener lifecycle

Workspace verified as `/home/muhammad-bilal/projects/threatfusion-gemini`, branch
`gemini/product-20260924`, HEAD `a6158cda69de1427d9cab30f5c96345c66fc0d16`,
push URL `no-push://requires-explicit-review`. The initial six changed/untracked
credential-phase files were preserved. The previously corrected combined gate was
run before implementation: **172 passed in 38.81s, exit 0**. This completes that
gate; earlier failed runs above remain historical failures.

Acceptance criteria were fixed before editing: both policy-backed listeners validate
before opening; replacement stops both admission paths and joins every old worker
before constructing replacements; failures leave no accepting generation; disk saves
are distinct from active policy; denial causes no protected view calls; audit history
and exact same-UUID transition retry survive replacement.

The new `operations.human_listener_lifecycle.HumanListenerLifecycle` uses explicit
TLS configurations, authorization, view and audit dependencies. The dependency chain
is retained alert repository -> authorization-bound analyst state repository ->
`AnalystAlertViewModel`, plus the separate audit repository. The existing registered
browser composition generates demo credentials and invokes inference, so it was not
reused or run. The producer's fixed-worker lifecycle pattern informed ownership;
producer implementation is unchanged. This is a local Python lifecycle entry point,
not a generic server, deployment CLI, or service-manager configuration.

Each replacement stops admission on both listeners before waiting on either's
in-flight operation, closes sockets and joins its two owned process_one workers.
Only then does it load both listeners through `human_credentials.construct_listener`
under a shared policy-directory lock. Repository schema validation and bounded read
probes precede opening. Both opens and both worker starts must succeed before workers
are released. Failure cleans up without restoring the old credential snapshot.
An all-restricted policy has no eligible actor and leaves the service failed/closed.
The runbook distinguishes metadata saved, old generation stopped, policy loaded and
new listeners accepting; generations are process-local counters, not disk revisions.

Exact validation commands:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/integration/test_operator_human_credentials.py backend/tests/integration/test_analyst_tls_service.py backend/tests/integration/test_analyst_browser_tls_service.py backend/tests/unit/test_analyst_security_audit.py backend/tests/unit/test_analyst_state.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/integration/test_human_listener_lifecycle.py
threatfusion-venv/bin/ruff check .
threatfusion-venv/bin/black --check backend/src/threatfusion/operations/human_credentials.py
threatfusion-venv/bin/black --check backend/src/threatfusion/operations/human_listener_lifecycle.py
threatfusion-venv/bin/black --check backend/tests/integration/test_operator_human_credentials.py
threatfusion-venv/bin/black --check backend/tests/integration/test_human_listener_lifecycle.py
threatfusion-venv/bin/black --check backend/src/threatfusion/api/analyst_tls_service.py
threatfusion-venv/bin/black --check backend/src/threatfusion/api/analyst_browser_tls_service.py
git diff HEAD --check
```

The first new lifecycle test invocation failed at setup: **14 errors in 7.96s,
exit 1**, at the strict policy ancestor-ownership check under the sandbox. The
explicitly authorized outside-sandbox run then passed **14 passed in 12.46s,
exit 0**. Expanded final lifecycle tests passed **17 passed in 13.32s, exit 0**.
They exercise real loopback TLS with disposable certificates, both enrolled actors,
unchanged old generations after disk restriction, exact disable/revoke replacement,
zero protected view access on denial, retained audit classification/history, invalid
policy and dependencies on replacement and cold startup, second-open failure,
partial worker startup, context/interrupted-close cleanup, schema rejection with an
empty queue, and dispatched transition drain followed by `existing` UUIDv4 replay.
No failing sandbox run is counted as passing evidence.

After listener edits, the exact combined gate was repeated: **172 passed in 38.49s,
exit 0**. Ruff: `All checks passed!`, exit 0. Six individual Black checks each
reported `1 file would be left unchanged.`, exit 0. Whitespace check: no output,
exit 0. An earlier multi-file `black --workers 1` format invocation stalled and was
interrupted (exit 130), so its chained tests did not run; individual formatting/checks
and the independent pytest commands above completed. No full backend suite, model
inference, evaluation, fitting, package/dataset download, deployment, staging, commit
or push was performed. Original protected workspace, models and datasets were untouched.

CA issuance, secure certificate/private-key delivery to Firefox, operator-action
journaling, backup/recovery, endurance and service-manager deployment remain open.
There is no claimed deadline for a stalled trusted repository/filesystem, no general
signal handler or crash/SIGKILL recovery, and no independent security review in this
milestone. TF-008 and TF-009 remain open. All changes remain unstaged/uncommitted.
Recommended next action: review the complete credential/lifecycle diff against the
admission, startup rollback and shutdown ownership contract before any deployment.

### 2026-10-14 — Operator credential action journaling and bounded handshake drain

Workspace verified as `/home/muhammad-bilal/projects/threatfusion-gemini`, branch
`gemini/product-20260924`, HEAD `c7d42b7`, push URL `no-push://requires-explicit-review`.

Acceptance criteria addressed:
1. **Append-Only Operator Credential Action Journal:** Maintained under directory lock
   and descriptor-relative ancestor checks (`0700`, owner `0` or `os.geteuid()`, no symlinks)
   as `journal.jsonl` (mode 0600, schema `operator_human_credential_journal_v1`, capped at
   64 records and 64 KiB) inside the private policy metadata directory.
   Deterministic JSONL records for successful `init`, `enroll`, `disable`, and `revoke`
   actions track monotonic 1-based sequence numbers (`seq`), UTC ISO timestamps
   (`recorded_at_utc`), action types, actor ID (when applicable), fingerprint (when applicable),
   resulting status (`initialized`|`active`|`disabled`|`revoked`), total record count, and
   active record count. Raw PEM bytes, private keys, and secrets are never recorded.
   Symlinks, non-0600 permissions, file size/record count overflows, non-monotonic sequence
   numbers, and corrupted entries fail closed with `CredentialPolicyError`. Validated via
   `read_journal(policy_dir)`.
2. **Bounded Listener Drain on Stalled TLS Handshake:** In both
   `AnalystBrowserTlsListener` and `AnalystTlsListener`, `process_one()` assigns `self._active = connection`
   under lock before calling `connection.do_handshake()`. On `close()`, the active connection is safely
   interrupted via `shutdown(socket.SHUT_RDWR)` followed by `close()`. This ensures that a client stalling
   mid-TLS-handshake does not block caller-owned worker threads during `HumanListenerLifecycle.replace()`
   or `shutdown()`, guaranteeing worker joining within < 5.0 seconds (verified in
   `test_stalled_handshake_does_not_block_replace_or_shutdown`) rather than blocking for the 60.0-second
   browser handshake timeout. Requests already admitted into the protected dispatch section continue to
   drain cleanly before close completes.

Exact validation commands and results:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/integration/test_operator_human_credentials.py backend/tests/integration/test_human_listener_lifecycle.py backend/tests/integration/test_analyst_tls_service.py backend/tests/integration/test_analyst_browser_tls_service.py backend/tests/unit/test_analyst_security_audit.py backend/tests/unit/test_analyst_state.py
threatfusion-venv/bin/ruff check .
threatfusion-venv/bin/black --check backend/src/threatfusion/operations/human_credentials.py
threatfusion-venv/bin/black --check backend/src/threatfusion/api/analyst_browser_tls_service.py
threatfusion-venv/bin/black --check backend/src/threatfusion/api/analyst_tls_service.py
threatfusion-venv/bin/black --check backend/tests/integration/test_operator_human_credentials.py
threatfusion-venv/bin/black --check backend/tests/integration/test_human_listener_lifecycle.py
git diff HEAD --check
```

Combined suite: **199 passed in 35.36s, exit 0**.
Ruff: `All checks passed!`, exit 0.
Individual Black checks: all 5 touched files unchanged, exit 0.
`git diff HEAD --check`: clean (0 errors), exit 0.

CA issuance, secure certificate/private-key delivery to Firefox, backup/recovery,
endurance, service-manager deployment, and the defensible distinct-alert correlation key
remain open. TF-008 and TF-009 remain open. All changes remain unstaged/uncommitted for review.
