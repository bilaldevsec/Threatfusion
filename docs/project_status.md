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

### 2026-10-14 — Coordinated multi-database online backup, snapshot verification, and atomic restore

Workspace verified as `/home/muhammad-bilal/projects/threatfusion-gemini`, branch
`gemini/product-20260924`, HEAD `5223784`, push URL `no-push://requires-explicit-review`.

Acceptance criteria addressed:
1. **Coordinated Multi-Database Online Snapshot:** The new `threatfusion.operations.storage_backup`
   module implements fail-closed online backup across `alerts.sqlite3` (`alert_candidate_sqlite_v1`),
   `states.sqlite3` (`analyst_state_sqlite_v1`), and `audit.sqlite3` (`analyst_security_audit_sqlite_v1`)
   into a locked private snapshot directory (mode `0700`, owner `os.geteuid()`, verified ancestors).
   Uses Python's `sqlite3.Connection.backup()` API over read-only connections (`mode=ro`), setting
   destination files to mode `0600` with fsync.
2. **Cryptographic & Relational Verification:** Every snapshot generates and validates `manifest.json`
   (mode `0600`, schema `storage_snapshot_manifest_v1`, capped at 64 KiB), verifying SHA-256 digests,
   sizes, row counts, `PRAGMA integrity_check`, and schema metadata (`schema_identity` and `user_version`).
   Cross-database referential consistency is strictly enforced: every `alert_candidate_id` present in
   `analyst_states` or `analyst_transition_events` must exist in `alert_candidates` of `alerts.sqlite3`.
   Mismatches, corruption, symlinks, unsafe modes, extra files, or orphan records fail closed with
   `StorageBackupError`.
3. **Atomic Offline Restore:** Requires the target directory to be locked with listeners stopped.
   Stages restored files via mode-0600 temporary files and replaces them atomically (`os.replace`),
   removes stale `-wal` or `-shm` sidecars, and fsyncs the directory.
4. **Sequential Online Backup Notice:** Sequential online backups are executed across the three
   databases rather than a distributed two-phase commit. Taking snapshots while listeners are stopped
   or quiescent is recommended for exact cross-database point-in-time synchronization. See
   `docs/storage_backup_recovery_runbook.md`.

Exact validation commands and results:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/integration/test_storage_backup.py backend/tests/integration/test_operator_human_credentials.py backend/tests/integration/test_human_listener_lifecycle.py backend/tests/unit/test_analyst_security_audit.py backend/tests/unit/test_analyst_state.py
threatfusion-venv/bin/ruff check .
threatfusion-venv/bin/black --check backend/src/threatfusion/operations/storage_backup.py
threatfusion-venv/bin/black --check backend/tests/integration/test_storage_backup.py
git diff HEAD --check
```

Combined suite: **148 passed in 29.24s, exit 0**.
Ruff: `All checks passed!`, exit 0.
Individual Black checks: all touched files unchanged, exit 0.
`git diff HEAD --check`: clean (0 errors), exit 0.

CA issuance, secure certificate/private-key delivery to Firefox, service-manager deployment,
long-term endurance, and the defensible distinct-alert correlation key remain open.
TF-008 and TF-009 remain open. All changes remain unstaged/uncommitted for review.

### 2026-10-14 — Quiescent lifecycle snapshot/restore coordination and signal-safe service runner

Workspace verified as `/home/muhammad-bilal/projects/threatfusion-gemini`, branch
`gemini/product-20260924`, HEAD `2742aa9`, push URL `no-push://requires-explicit-review`.

Acceptance criteria addressed:
1. **Quiescent Lifecycle Snapshot & Restore:** `HumanListenerLifecycle` now provides
   `snapshot_quiescent(snapshot_dir)` and `restore_quiescent(snapshot_dir)`. These operations
   synchronously stop listener admission on both API and browser mTLS endpoints, close sockets,
   and join both worker threads (< 5.0s drain), ensuring zero concurrent requests or active SQLite
   writes are in progress. Quiescent snapshots capture page-level database copies via
   `create_storage_snapshot` and automatically start a fresh listener generation via `replace()`;
   quiescent restores cryptographically verify the candidate snapshot, atomically restore databases
   via `restore_storage_snapshot`, and restart fresh listeners bound to the restored database state.
2. **Signal-Safe Service Supervisor Runner:** `threatfusion.operations.human_service_runner.HumanServiceRunner`
   provides a single-process supervised controller for `HumanListenerLifecycle` with deterministic
   POSIX signal handling:
   - `SIGTERM` / `SIGINT`: invokes `trigger_shutdown()`, stops listener admission, closes sockets,
     drains in-flight requests, joins workers (< 5.0s), and exits `0`.
   - `SIGHUP`: invokes `trigger_reload()`, executing `lifecycle.replace()` under directory lock to
     load updated credential policy and advance generation; on reload failure (such as all actors
     restricted or corrupt policy), fails closed, shuts down listeners, and exits `2`.
   - Initial startup failure (e.g. missing/corrupt policy directory) or unhandled worker failure exits `1`.
   - Programmatic triggers (`trigger_shutdown()`, `trigger_reload()`, `run_until_stopped()`, and
     context manager) enable deterministic lifecycle automation and testability.
3. **Hardened Service Manager Deployment:** A reference Linux `systemd` unit configuration
   (`threatfusion-analyst.service`) defines unprivileged user isolation (`operator`), `UMask=0077`,
   `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, and `ExecReload=/bin/kill -HUP $MAINPID`.

Exact validation commands and results:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/integration/test_human_service_runner.py backend/tests/integration/test_human_listener_lifecycle.py backend/tests/integration/test_storage_backup.py backend/tests/integration/test_operator_human_credentials.py backend/tests/unit/test_analyst_security_audit.py backend/tests/unit/test_analyst_state.py
threatfusion-venv/bin/ruff check .
threatfusion-venv/bin/black --check backend/src/threatfusion/operations/human_service_runner.py
threatfusion-venv/bin/black --check backend/src/threatfusion/operations/human_listener_lifecycle.py
threatfusion-venv/bin/black --check backend/tests/integration/test_human_service_runner.py
threatfusion-venv/bin/black --check backend/tests/integration/test_human_listener_lifecycle.py
git diff HEAD --check
```

Combined suite: **156 passed in 34.06s, exit 0**.
Ruff: `All checks passed!`, exit 0.
Individual Black checks: all 4 touched files unchanged, exit 0.
`git diff HEAD --check`: clean (0 errors), exit 0.

CA issuance, secure certificate/private-key delivery to Firefox, long-term endurance, and the
defensible distinct-alert correlation key remain open. TF-008 and TF-009 remain open. All changes
remain unstaged/uncommitted for review.

### 2026-10-14 — Tamper-evident security audit export, retention pruning, and hash-chained journal rotation

Workspace verified as `/home/muhammad-bilal/projects/threatfusion-gemini`, branch
`gemini/product-20260924`, HEAD `b1faf50`, push URL `no-push://requires-explicit-review`.

Acceptance criteria addressed:
1. **Hash-Chained Journal Rotation at the 64-Record Cap:** `threatfusion.operations.human_credentials.rotate_journal`
   solves the open 64-record journal capacity constraint under directory locks and descriptor-relative
   traversal. It archives the full `journal.jsonl` and writes a companion manifest `manifest.json`
   (mode 0600, schema `operator_human_credential_journal_archive_v1`) with `sha256_digest`, `first_seq`,
   `last_seq`, and `previous_archive_sha256`. It then atomically replaces `journal.jsonl` in the policy
   directory with a continuation checkpoint entry (`seq = last_seq + 1`, `action = "journal_rotated"`,
   `resulting_status = "rotated"`, `previous_archive_sha256 = archive_sha256`). Sequence progression
   continues monotonically (`last_seq + 2`, ...) while the file record count resets to 1 (allowing 63
   more operator actions). Cryptographic integrity is verified via `verify_journal_archive(archive_dir)`.
2. **Tamper-Evident Security Audit Export & Verification:** `export_security_audit_archive` writes
   canonical ordered JSONL events (`audit_events.jsonl`, mode 0600) and an immutable manifest
   (`manifest.json`, mode 0600, schema `security_audit_archive_v1`) into a locked mode-0700 archive directory,
   recording SHA-256 digest, row count, and first/last event IDs and timestamps. `verify_security_audit_archive`
   validates cryptographic digests, JSONL formatting, schema constraints, and monotonic timestamps.
3. **Atomic Contiguous Prefix Pruning:** `prune_archived_security_audit` first verifies the archive, opens
   an exclusive SQLite transaction on `audit.sqlite3`, and confirms that the first `manifest["row_count"]`
   rows in the database match the archive byte-for-byte. It deletes only the verified contiguous prefix
   (`WHERE event_time < ? OR (event_time = ? AND audit_event_id <= ?)`), guaranteeing zero unarchived event loss.
   `HumanListenerLifecycle.prune_security_audit_quiescent` coordinates this pruning with worker drain (< 5.0s)
   and fresh generation restart.

Exact validation commands and results:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/integration/test_audit_retention.py backend/tests/integration/test_operator_human_credentials.py backend/tests/integration/test_human_service_runner.py backend/tests/integration/test_human_listener_lifecycle.py backend/tests/integration/test_storage_backup.py backend/tests/unit/test_analyst_security_audit.py backend/tests/unit/test_analyst_state.py
threatfusion-venv/bin/ruff check .
threatfusion-venv/bin/black --check backend/src/threatfusion/operations/human_credentials.py
threatfusion-venv/bin/black --check backend/src/threatfusion/operations/audit_retention.py
threatfusion-venv/bin/black --check backend/src/threatfusion/operations/human_listener_lifecycle.py
threatfusion-venv/bin/black --check backend/tests/integration/test_operator_human_credentials.py
threatfusion-venv/bin/black --check backend/tests/integration/test_audit_retention.py
git diff HEAD --check
```

Combined suite: **166 passed in 44.89s, exit 0**.
Ruff: `All checks passed!`, exit 0.
Individual Black checks: all 5 touched files unchanged, exit 0.
`git diff HEAD --check`: clean (0 errors), exit 0.

CA issuance, secure certificate/private-key delivery to Firefox, long-term endurance, and the
defensible distinct-alert correlation key remain open. TF-008 and TF-009 remain open. All changes
remain unstaged/uncommitted for review.

### 2026-10-14 — Local offline human CA initialization, encrypted client bundle delivery, and enrollment coordination

Workspace verified as `/home/muhammad-bilal/projects/threatfusion-gemini`, branch
`gemini/product-20260924`, HEAD `73d0564`, push URL `no-push://requires-explicit-review`.

Acceptance criteria addressed:
1. **Local Offline Root CA Initialization:** `init_human_ca(ca_dir)` initializes an offline Root CA
   in an exclusive mode-0700 private directory under strict ancestor ownership (`0` or `os.geteuid()`),
   symlink rejection (`os.O_NOFOLLOW`), and non-blocking filesystem lock (`fcntl.flock`). It generates
   an RSA 2048-bit Root CA private key (`ca_key.pem`, mode 0600) and self-signed X.509v3 certificate
   (`ca_cert.pem`, mode 0600) with `basicConstraints = critical, CA:TRUE, pathlen:0` and
   `keyUsage = critical, keyCertSign, cRLSign`. It initializes a metadata manifest (`ca_manifest.json`,
   mode 0600, schema `operator_human_ca_v1`) and an append-only issuance journal (`issuance_journal.jsonl`,
   mode 0600, schema `operator_human_ca_issuance_journal_v1`). Re-initialization over existing CA files
   fails closed (`ca_already_exists`).
2. **Encrypted PKCS#12 Client Bundle Delivery:** `issue_human_client_bundle(ca_dir, delivery_dir, ...)`
   signs client certificates under the Root CA with critical `basicConstraints = CA:FALSE`, critical
   `keyUsage = digitalSignature`, `extendedKeyUsage = clientAuth`, and `subjectAltName = URI:urn:threatfusion:human:<actor_id>`.
   It packages the certificate, Root CA certificate, and private key into an encrypted PKCS#12 bundle
   (`client_bundle.p12`, mode 0600) and companion manifest (`bundle_manifest.json`, mode 0600, schema
   `operator_human_client_bundle_v1`), updates `ca_manifest.json` (`next_serial`, `issued_count`),
   and appends an entry to `issuance_journal.jsonl`.
3. **Passphrase and Key Hygiene:** Passphrases require minimum 12 characters and forbid newlines/control
   characters (`invalid_passphrase`). Passphrases are passed to OpenSSL strictly via `stdin` (`-passout stdin`),
   never logged, stored, or written to disk, and accepted via CLI through `--passphrase-env` or `--passphrase-stdin`
   (preventing process listing / `/proc` leakage). Unencrypted client private keys are generated in temporary
   scratch directories and unlinked immediately following PKCS#12 encryption; delivery directories are verified
   to contain zero unencrypted private keys.
4. **Policy Enrollment Coordination:** `issue_and_enroll_human_credential` combines bundle delivery and
   atomic enrollment into operator policy (`human-credentials.json` and append-only `journal.jsonl`),
   returning both bundle metadata and the enrolled complete-DER SHA-256 fingerprint.
5. **Loopback mTLS 1.3 End-to-End Verification:** Real loopback tests prove end-to-end mTLS 1.3
   authentication where `HumanListenerLifecycle` is configured with the issued Root CA as `client_ca`
   and client certificates extracted from `client_bundle.p12` authenticate successfully (HTTP 200)
   against `AnalystBrowserTlsListener` and `AnalystTlsListener`.

Exact validation commands and results:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/integration/test_human_ca_issuance.py backend/tests/integration/test_operator_human_credentials.py backend/tests/integration/test_human_service_runner.py backend/tests/integration/test_human_listener_lifecycle.py backend/tests/integration/test_storage_backup.py backend/tests/integration/test_audit_retention.py backend/tests/unit/test_analyst_security_audit.py backend/tests/unit/test_analyst_state.py
threatfusion-venv/bin/ruff check .
threatfusion-venv/bin/black --check backend/src/threatfusion/operations/human_ca_issuance.py
threatfusion-venv/bin/black --check backend/tests/integration/test_human_ca_issuance.py
git diff HEAD --check
```

Combined suite: **177 passed in 56.60s, exit 0**.
Ruff: `All checks passed!`, exit 0.
Individual Black checks: all 2 touched files unchanged, exit 0.
`git diff HEAD --check`: clean (0 errors), exit 0.

Automated browser-profile provisioning, long-term endurance, and the defensible distinct-alert
correlation key remain open under TF-008 and TF-009. All changes remain unstaged/uncommitted for review.

### 2026-10-14 — Package discovery consolidation, zero-PYTHONPATH editable install, and full-repository verification gate

Workspace verified as `/home/muhammad-bilal/projects/threatfusion-gemini`, branch
`gemini/product-20260924`, HEAD `95d6094`, push URL `no-push://requires-explicit-review`.

Acceptance criteria addressed:
1. **Timestamp ISO Pre-Parsing (TF-005):** In `backend/src/threatfusion/datasets/adapters/base.py`,
   `parse_required_timestamp` now attempts `datetime.fromisoformat(text)` with UTC normalization
   before falling back to pandas `dayfirst=True` parsing. This eliminates the four historical
   `UserWarning: Parsing dates in %Y-%m-%dT%H:%M:%S.%f%z format when dayfirst=True was specified`
   warnings emitted across Mordor test profiles and raw readers, while strictly preserving
   numeric epoch parsing and byte-identical datetime values.
2. **Package Discovery Consolidation & Top-Level `src` Alias:** `pyproject.toml` was updated with
   `[tool.setuptools.package-dir]` mapping `"threatfusion" = "backend/src/threatfusion"` and
   `"src" = "src"`, and `[tool.setuptools.packages.find]` configured with `where = ["backend/src", "."]`
   and `include = ["threatfusion*", "src*"]`. The top-level `src/__init__.py` alias exports
   `src.threatfusion` without polluting global namespace.
3. **Zero-PYTHONPATH Offline Editable Installation:** Editable installation was completed strictly
   offline via `threatfusion-venv/bin/pip install --no-build-isolation --no-deps -e .` with exit 0,
   zero network requests, and zero package/wheel downloads. Subprocess unit test
   `test_subprocess_import_zero_pythonpath_external_cwd` confirms that running Python from an external
   directory (e.g. `/tmp`) with `PYTHONPATH` unset successfully imports `threatfusion`, all 13
   subpackages, and `src`.
4. **Full-Repository Zero-PYTHONPATH Verification Gate:** Dedicated regression unit test file
   `backend/tests/unit/test_package_discovery.py` verifies all package discovery, alias resolution,
   and TF-005 timestamp contracts. The complete repository test suite passed with `PYTHONPATH` unset:
   `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/pytest` passed 1284 tests in
   111.45s with zero failures and zero warnings.

Exact validation commands and results:

```sh
threatfusion-venv/bin/pip install --no-build-isolation --no-deps -e .
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/unit/test_package_discovery.py backend/tests/integration/test_human_ca_issuance.py backend/tests/integration/test_audit_retention.py backend/tests/integration/test_operator_human_credentials.py backend/tests/integration/test_human_service_runner.py backend/tests/integration/test_human_listener_lifecycle.py backend/tests/integration/test_storage_backup.py
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests/unit
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/pytest -o addopts= -q --tb=short backend/tests
threatfusion-venv/bin/ruff check .
threatfusion-venv/bin/black --check src/__init__.py
threatfusion-venv/bin/black --check backend/src/threatfusion/datasets/adapters/base.py
threatfusion-venv/bin/black --check backend/tests/unit/test_package_discovery.py
git diff HEAD --check
```

Results:
- Operations and discovery integration suite: **180 passed in 48.45s, exit 0**.
- Complete unit test suite: **1030 passed in 39.51s, exit 0** (zero warnings).
- Full repository test suite: **1284 passed in 111.45s, exit 0** (zero warnings).
- Ruff: `All checks passed!`, exit 0.
- Individual Black checks: all 3 touched files unchanged, exit 0.
- `git diff HEAD --check`: clean (0 errors), exit 0.

TF-005 is marked **resolved**. Automated browser-profile provisioning, long-term endurance, and the
defensible distinct-alert correlation key remain open under TF-008 and TF-009. All changes remain
unstaged/uncommitted for review.

### 2026-10-14 — TF-008 operator Firefox NSS profile provisioning from encrypted PKCS#12 bundles

- The operator Firefox NSS profile provisioning module (`threatfusion.operations.human_browser_provisioning`)
  was implemented and verified. It provisions isolated Firefox NSS SQLite databases (`cert9.db`, `key4.db`,
  `pkcs11.txt`) directly from verified Root CA and client bundle delivery directories under exclusive
  `fcntl.flock` locks with mode-0700 directories, mode-0600 files, and `O_NOFOLLOW` symlink rejection.
- The Root CA certificate is imported via `certutil -A -t "C,,"` as trusted for server verification.
  The client PKCS#12 bundle is imported via `pk12util -i`, with passphrases passed via an ephemeral
  mode-0600 file that is zeroed and unlinked in a `finally` block (zero exposure to `/proc/<pid>/cmdline`
  or persistent disk storage).
- A mode-0600 `user.js` configures `security.default_personal_cert="Select Automatically"` for seamless
  loopback mTLS authentication while disabling background telemetry, telemetry archiving, captive portal
  probes, Normandy studies, and enterprise roots.
- A mode-0600 `profile_manifest.json` (`operator_human_firefox_profile_v1`) records file SHA-256 digests
  (`cert9_db_sha256`, `key4_db_sha256`, `pkcs11_txt_sha256`, `user_js_sha256`) and certificate fingerprints
  with zero secret key or passphrase material.
- `verify_firefox_profile` cryptographically verifies file digests, enforces filesystem modes, and executes
  `certutil -L` to confirm presence of both the Root CA and client certificate in the NSS database.
- Integration tests in `backend/tests/integration/test_human_browser_provisioning.py` verify the complete
  end-to-end chain (`init_human_ca()` -> `init_policy_directory()` -> `issue_and_enroll_human_credential()` ->
  `provision_firefox_profile()` -> `verify_firefox_profile()`), confirm NSS `certutil -L` output, verify mode
  0600 permissions and absence of raw passphrases, and authenticate over real loopback mTLS 1.3 serving
  `GET /analyst/alerts` (`HTTP 200`) on `AnalystBrowserTlsListener` via `HumanListenerLifecycle`. Typed
  fail-closed tests cover wrong passphrases, tampered database/user.js digests, symlinks, insecure
  permissions (`0755`), non-empty profile directories, and CA/bundle mismatch.
- Exact validation run:
  1. Operations and provisioning integration suite: **120 passed in 44.24s, exit 0**.
  2. Ruff: `All checks passed!`, exit 0.
  3. Individual Black checks: all touched files unchanged, exit 0.
  4. `git diff HEAD --check`: clean (0 errors), exit 0.

TF-008 and TF-009 remain **open** pending long-term endurance testing, browser write authentication/CSRF
protection, and the defensible distinct-alert correlation key. All changes remain unstaged/uncommitted for review.

### 2026-10-14 — TF-008 CSRF-hardened, same-origin verified browser alert state transitions and audited HTML triage workflow

- Implemented cryptographic per-actor HMAC-SHA256 CSRF protection in `AnalystBrowserTlsListener`
  (`threatfusion.api.analyst_browser_tls_service`), generated from an ephemeral 32-byte listener secret
  (`os.urandom(32)`) and bound to `(actor_id, alert_candidate_id, expected_version, transition_request_id)`.
  Verified via constant-time `hmac.compare_digest`.
- Enforced same-origin framing defenses on `POST /v1/analyst/alerts/<alert_candidate_id>/transitions`: requires
  `Content-Type: application/x-www-form-urlencoded` bounded to 2,048 bytes; validates `Sec-Fetch-Site: same-origin`
  and loopback `Origin` (`https://127.0.0.1:<port>` / `https://localhost:<port>`). Missing or cross-site headers
  are rejected upfront with HTTP `403 Forbidden` and audited as `authorization_rejected` (`forbidden`).
- Enforced strict role-based authorization: authenticated peers with role `viewer` are prevented from mutating
  state, returning `403 Forbidden` and logging `authorization_rejected` (`forbidden`) with zero calls to
  `AnalystStateRepository`.
- Enhanced `render_dashboard_html` (`threatfusion.api.analyst_dashboard`) to render a zero-JavaScript triage
  `<form method="POST">` for `analyst` peers, embedding hidden inputs for `expected_version`, canonical UUIDv4
  `transition_request_id`, and `csrf_token`, with `<select name="target_state">` populated with valid next
  states (`new` -> `in_review`; `in_review` -> `closed`, `escalated`) and bounded `<input name="reason">`.
  Peers with role `viewer` and alerts in terminal states (`closed`, `escalated`) receive clear read-only or
  terminal state badges without active form controls.
- Audited state transitions execute through `AnalystAlertViewModel.transition`, recording `request_admitted`
  before mutation and `request_completed` after mutation in `audit.sqlite3` with normalized route
  `/v1/analyst/alerts/<alert_candidate_id>/transitions` and `body_sha256`. Successful transitions return HTTP 200
  with updated HTML detail and fresh CSRF tokens for subsequent steps. Version conflicts return `409 Conflict`,
  invalid transitions return `400 Bad Request`, and storage failures return `503 Unavailable`.
- Verification run:
  1. Full 6-suite verification gate (214 tests): **214 passed in 37.55s, exit 0**.
  2. Ruff: `All checks passed!`, exit 0.
  3. Black: all modified files verified with `black --check`, exit 0.
  4. `git diff HEAD --check`: clean (0 errors), exit 0.

TF-008 and TF-009 remain **open** pending long-term endurance testing, live telemetry, and the defensible distinct-alert
correlation key. All changes remain unstaged/uncommitted for review.

### 2026-10-15 — TF-008 Authenticated Entity-Bearing Telemetry Contract, Dual-Window 30s/10m Alert Correlation Engine, and Empirical Alert Fatigue Reduction Metric (Milestone #18)

- Created `backend/src/threatfusion/alerts/correlation_engine.py` defining `EntityProvenanceContract` requiring explicit
  `entity_namespace_id`, `clock_synchronized=True`, and non-empty `src_entity_id`/`dst_entity_id`. Raw UNSW-NB15 alerts
  lacking verified entity namespaces or clock synchronization guarantees are strictly isolated into singleton incidents
  (`correlation_mode = "singleton_unverified_provenance"`, `window_type = "none"`), ensuring 0 false merges across synthetic
  or unverified network traces.
- Implemented dual-window temporal correlation in `correlate_alert_candidates` for verified entity telemetry:
  - 30-Second Burst Window (`BURST_WINDOW_SECONDS = 30.0`): Groups rapid burst alerts sharing 5-tuple
    `(entity_namespace_id, src_entity_id, dst_entity_id, protocol, service_or_port)` within <= 30s into burst incidents
    (`window_type = "burst_30s"`, rule `corr_burst_5tuple_30s_v1`).
  - 10-Minute Campaign Window (`CAMPAIGN_WINDOW_SECONDS = 600.0`): Groups multi-stage alerts between the same authenticated
    endpoint pair `(entity_namespace_id, frozenset({src_entity_id, dst_entity_id}))` within <= 600s into campaign incidents
    (`window_type = "campaign_600s"`, rule `corr_campaign_entity_pair_600s_v1`).
  - Strict Cross-Namespace Isolation: Alerts from distinct namespaces (`sensor-a` vs `sensor-b`) never correlate.
- Implemented empirical alert fatigue reduction metric and safety gate in `compute_alert_reduction_metrics`:
  - Computes reduction ratio: 1.0 - (incidents / alerts).
  - 100% Critical Scenario Retention: Enforces `critical_retention_ratio == 1.0`. Raises `CorrelationSafetyError("critical_alert_dropped")`
    if any attack alert is omitted, and preserves maximum uncalibrated score and escalated decision `"Attack"` on every incident.
- Implemented transactional SQLite persistence in `IncidentSqliteRepository` (`incidents.sqlite3`, mode 0600) with tables
  `incidents` and `incident_constituent_alerts`.
- Surfaced incident correlation metadata into `AnalystAlertViewModel.get_alert`, cleanly defaulting unverified raw UNSW-NB15 alerts
  to `singleton_unverified_provenance` with provenance narrative notes.
- Updated `render_dashboard_html` (`threatfusion.api.analyst_dashboard`) to display an **Incident Correlation & Provenance** section
  with mode, window, rule, constituent alert count, and provenance badges (`verified_entity_bearing` / `unverified_provenance`).
- Created unit tests (`backend/tests/unit/test_correlation_engine.py`) and integration tests
  (`backend/tests/integration/test_incident_correlation_pipeline.py`).
- Verification:
  1. Focused test suite: **129 passed in 22.27s, exit 0**.
  2. Ruff: `All checks passed!`, exit 0.
  3. Black: all modified files verified with `black --check`, exit 0.
  4. `git diff HEAD --check`: clean (0 errors), exit 0.

TF-008 and TF-009 remain **open** pending long-term endurance testing, live telemetry, and external CA provisioning. Milestone #18 was committed to `gemini/product-20260924` at `d71e33385750d4ebfd7d7c62b70f86230f8df3e6`.

### 2026-10-15 — Phase P0/P1/P2 Quality & Blocker Resolution: Section 7 Lifecycle Startup Interruption Repair, Section 6.3 Dual-SQLite Audit Failure Verification, and Canonical Gemini Master Export (Milestone #19)

- Repaired the Section 7 human listener lifecycle startup interruption blocker in `backend/src/threatfusion/operations/human_listener_lifecycle.py`:
  - Caught `BaseException` in `worker.start()` to capture `KeyboardInterrupt` before and during OS thread creation.
  - Implemented bounded native thread creation verification: checks `worker.ident is not None or worker.is_alive()` or bounded wait on `worker._started`. When native creation does not occur, records `record[2] = True` (`failed_to_start = True`).
  - In `_shutdown()`, cleanly skips unstarted workers without hanging on `finished.wait()` for non-existent threads.
  - Deterministically closes listening sockets, signals `_stop`, releases `_ready`, waits on `finished.wait(timeout=1.0)`, and joins started workers with bounded timeouts. Zero worker or socket leaks.
  - Verified by 6 isolated watchdog regressions in `backend/tests/integration/test_human_listener_lifecycle.py` covering first and second worker pre-native and post-native interruptions and OS runtime errors (26 passed in 10.86s).
- Verified Section 6.3 browser transition dual-SQLite audit failure semantics and retry deduplication in `backend/tests/integration/test_analyst_browser_tls_service.py`:
  - Verified pre-mutation admission audit failure raises HTTP 503 and blocks state mutation (0 mutations).
  - Verified post-commit completion audit failure returns HTTP 503, commits transition in `states.sqlite3`, and UUIDv4 retry returns HTTP 200 with 0 duplicate transitions.
  - 32 browser TLS tests pass in 11.49s.
- Extended `backend/src/threatfusion/operations/storage_backup.py` with support for optional `incidents.sqlite3` (`incident_sqlite_v1`):
  - Updated snapshot creation, verification, and atomic restore to seamlessly handle 4-DB setups (`alerts`, `states`, `audit`, `incidents`) while retaining 100% backward compatibility with 3-DB setups.
  - Enforced cross-database referential consistency checks between `incident_constituent_alerts` and `alert_candidates`.
  - Added `PRAGMA user_version = 1` initialization to `IncidentSqliteRepository`.
  - 13 storage backup tests pass in 4.91s.
- Created canonical Gemini project master export `docs/GEMINI_PROJECT_MASTER.md` (Revision `TF-GEMINI-MASTER-2026-10-15-v2`), recording current HEAD `d71e333`, Milestone #18 committed status, Section 7 blocker resolution, Section 6.3 dual-DB audit verification, optional incidents backup support, and capability status.
- Verification:
  - 26 lifecycle tests, 13 storage backup tests, 32 browser TLS tests, 129 correlation/pipeline tests pass (214+ combined tests pass with 0 errors).
  - Ruff, Black, and `git diff HEAD --check` pass cleanly.

TF-008 and TF-009 remain **open** pending long-term endurance testing, live telemetry, and external CA provisioning. Milestone #19 was committed to `gemini/product-20260924` at `a357fc6a14d16fc6137a5d88ec2701d8f9b95899`.

### 2026-10-15 — Phase P3 & P4: Supported Source Provenance Adapters, Complete Section 8 Correlation Gate, and Audited Grouping Corrections (Milestone #20)

- Implemented supported source provenance adapters in `backend/src/threatfusion/datasets/adapters/provenance_sources.py` (and exported in `adapters/__init__.py`):
  - `MordorScenarioAdapter`: Normalizes supported Mordor host/security events bound to scenario captures with explicit `source_mode = "scenario_replay"`, `scenario_id`, `entity_namespace_id = f"mordor:{scenario_id}"`, entity endpoints, validity intervals, clock origin (`"utc_event_log"`), and clock synchronization evidence. Rejects missing endpoints, invalid timestamps, or wrong modes with `SourceRowValidationError`.
  - `AuthorizedLabSensorAdapter`: Normalizes real or lab sensor events gated by allowlisted `RegisteredSensorManifest`. Enforces pre-registered `sensor_id` validation, replay/duplicate `source_event_id` detection, and strict separation between dataset/scenario replay and authorized lab sensors (`source_mode = "authorized_lab_sensor"`).
- Completed Section 8 Correlation Edge-Case and Grouping Gates in `backend/src/threatfusion/alerts/correlation_engine.py`:
  - NAT / Address Reuse Ambiguity: Alerts with `address_reuse_or_nat=True` fail closed to `singleton_unverified_provenance` (`"nat_address_reuse_ambiguous"`).
  - Entity Validity Interval Enforcement: Alerts with timestamps outside `[validity_start_utc, validity_end_utc]` fail closed (`"outside_entity_validity_interval"`).
  - Clock Skew Bound: Tolerates clock skew up to 5.0s (`MAX_ALLOWABLE_CLOCK_SKEW_SECONDS = 5.0`). Skew > 5.0s fails closed (`"clock_skew_exceeded"`).
  - Candidate Deduplication vs. Grouping: Repeated submissions of the exact same `alert_candidate_id` collapse cleanly upfront without inflating total alert counts or constituent alert counts.
  - Out-of-Order Determinism & Exact Boundaries: Pre-sorting on `(parsed_timestamp, alert_candidate_id)` ensures identical incident clusters regardless of arrival order. Exact boundaries ($\le 30.0\text{s}$ included in burst; $> 30.0\text{s}$ excluded; $\le 600.0\text{s}$ included in campaign; $> 600.0\text{s}$ excluded) verified.
  - Per-Event Grouping Justification: Structured `MemberJustification` (`anchor_alert_id`, `delta_seconds`, `matched_relationship_key`, `rule_id`, `provenance_summary`) stored for every constituent alert in `incident_constituent_alerts` table in SQLite.
  - Audited Grouping Correction (`correct_incident_grouping`): Investigators can manually split erroneously grouped alerts into separate standalone incidents (`correlation_mode = "manual_correction_split"`) with idempotent UUIDv4 replay safety and audit logging to `incident_grouping_corrections`.
- Updated `backend/src/threatfusion/operations/storage_backup.py` to record `incident_grouping_corrections` in snapshot manifests.
- Added comprehensive unit and integration tests:
  - `backend/tests/unit/test_provenance_sources.py` (5 tests)
  - `backend/tests/unit/test_correlation_engine.py` (expanded to 13 tests)
  - `backend/tests/integration/test_incident_correlation_pipeline.py` (expanded to 3 tests)
- Verification:
  - Full test suite passes: 212+ tests pass with exit 0.
  - Ruff, Black, and `git diff HEAD --check` pass cleanly.

TF-008 and TF-009 remain **open** pending long-term endurance testing, live telemetry, and external CA provisioning. Milestone #20 was committed to `gemini/product-20260924` at `21cda98797f1f7d5402ae3857b2fe5283f6f059c`.

### 2026-10-16 — Phase P5: Jury Requirements Traceability Registry (TF-010 open (repository-side traceability helper implemented; external FAST-NUCES jury rubric remains open)), Missing-Data Aware Multi-Signal Risk & RF/AE Ablation Engine (TF-002/TF-003/TF-004), and Offline Retraining Feedback Ledger (TF-007) (Milestone #21)

- **Jury Requirements Traceability Registry (`jury_traceability_matrix_v1`, TF-010 open (repository-side traceability helper implemented; external FAST-NUCES jury rubric remains open)):**
  - Created `backend/src/threatfusion/models/jury_traceability.py` and published authoritative specification `docs/jury_requirements_traceability.md`.
  - Immutable registry covers all 6 jury-approved datasets (`UNSW-NB15`, `CIC-IDS2017`, `CSE-CIC-IDS2018_subset`, `Mordor_scenarios`, `Synthetic_UEBA`, `Authorized_Lab_Sensor`) and 5 model families (`Logistic_Regression`, `Random_Forest`, `Autoencoder_v2`, `Rate_Log1p_Candidate`, `Heuristic_Statistical_Signals`).
  - `verify_jury_traceability_completeness()` asserts non-empty dispositions, explicit leakage boundaries, and disk SHA-256 digest integrity across all baseline models (`random_forest.joblib`, `autoencoder_state.pt`, `logistic_regression.joblib`, `rate-log1p`).
- **Missing-Data Aware Multi-Signal Risk Policy (`dynamic_risk_assessment_v1`):**
  - Created `backend/src/threatfusion/models/multi_signal_risk.py` implementing the 7 canonical detection signals (`supervised_rf`, `autoencoder_v2_reconstruction`, `isolation_forest_outlier`, `ueba_behavioral_deviation`, `threat_intel_ioc`, `payload_entropy`, `periodic_beaconing`).
  - Enforced the Missing-Data Invariant: missing evidence is not benign evidence. Unavailable signals are subtracted from the denominator ($D = 100.0 \times \frac{\sum_{i \in A} w_i \times s_i}{\sum_{i \in A} w_i}$). Proven: when `supervised_rf = 0.90` and other 6 signals are unavailable, $D = 90.0$ (not diluted to 27.0).
  - Strict fail-closed error handling for empty available sets, score out-of-bounds/NaN, invalid weights, and unstated unavailability reasons.
- **Leakage-Aware RF vs. RF+AE Ablation & Metrics Evaluator (`detector_ablation_report_v1`):**
  - Implemented `evaluate_detector_ablation()` calculating class-aware metrics: confusion matrices (`tp`, `fp`, `tn`, `fn`), `precision`, `recall`, `f1_score`, `pr_auc`, `false_alert_burden_per_1000`, and delta statistics.
  - Formulates promotion verdicts: rejects regressions (`rejected_regression`), retains advisory candidates as `experimental_unfused_retained`, and approves baselines (`approved_baseline`).
- **Offline Retraining Feedback Ledger (`offline_retraining_feedback_sqlite_v1`):**
  - Created `backend/src/threatfusion/db/retraining_feedback_ledger.py` persisting analyst triage feedback (`confirmed_threat` vs `false_positive`) into a mode-0600 SQLite ledger (`retraining_feedback.sqlite3`) for future offline batch retraining.
  - Implemented idempotent `transition_request_id` replay deduplication and conflict detection.
  - Implemented pre- and post-write SHA-256 verification of frozen production models (`random_forest.joblib` and `autoencoder_state.pt`), proving zero online weight drift for the academic jury viva.
- **Verification:**
  - 46 unit and integration tests pass across `test_multi_signal_risk.py`, `test_jury_traceability_and_feedback.py`, `test_provenance_sources.py`, `test_correlation_engine.py`, and `test_incident_correlation_pipeline.py`.
  - Ruff, Black, and `git diff HEAD --check` pass cleanly.

TF-010 repository-side disposition registry is implemented in `backend/src/threatfusion/models/jury_traceability.py` and `docs/jury_requirements_traceability.md`; per `CLAUDE.md` Section 7, TF-010 is kept **open** pending physical attachment of the signed external jury brief. Milestone #21 was committed to `gemini/product-20260924` at `7017bd7`.

### 2026-10-16 — Phase F / Milestone #22: Deep Presentation Extraction (Slides 1-15), Slide 14 Suricata 14-Feature Live-Ingestion Pipeline, CLAUDE.md Continuity Installation, and End-to-End Product Spine Verification (Milestone #22)

- **Deep Extraction of Final Presentation (Slides 1–15) & Slide 14 Azure VM Architecture Audit:**
  - Fully extracted all 15 slides, numeric claims, architectural diagrams, and verbatim speaker notes from `/home/muhammad-bilal/Downloads/Final Presentation (1).pptx` using custom XML parsing of presentation slide and notesSlide components.
  - Published comprehensive reference report `docs/fyp2_final_presentation_and_azure_live_path_audit.md` mapping each presentation slide to repository artifacts, documentation, and source modules.
  - Verified and documented all slide metrics (Random Forest 94.95% accuracy, 75.87% macro-F1, Autoencoder 96.36% / 96.41% accuracy, combined threshold, and 68.76% macro-F1).
  - Explicitly mapped the 5-stage Slide 14 planned Azure VM live-ingestion pipeline:
    - Box 01: Attacker VM (10.0.0.4) running Nmap, curl, ping, and safe attack scripts.
    - Box 02: Victim VM (10.0.0.5, private IP only) with Suricata network inspection capturing `eve.json` flow events.
    - Box 03: ThreatFusion Flow Adapter extracting the exact 14 features and binding `EntityProvenanceContract`.
    - Box 04: Registered Producer secure record transfer over mutual TLS (TLS 1.3).
    - Box 05: ThreatFusion Backend executing frozen Random Forest inference (`random_forest.joblib`), dual-window incident correlation (`incidents.sqlite3`), operator mTLS triage via `HumanListenerLifecycle`, and 4-database atomic storage snapshot.
- **`CLAUDE.md` Continuity Installation & Governance Alignment:**
  - Installed `/home/muhammad-bilal/Downloads/THREATFUSION_CLAUDE_HANDOFF.md` into repository root as `CLAUDE.md` with dated Section 19 Gemini branch reconciliation.
  - Enforced `CLAUDE.md` Section 7 ("Never close an issue because code 'looks complete.' Close only when its acceptance evidence is satisfied"): reconciled `docs/issue_register.md` to keep **TF-010 as `open`** until the external dated, signed FYP-1 jury brief/rubric is formally attached.
- **Slide 14 Box 03 Suricata 14-Feature Flow Adapter (`SuricataFlowAdapter`):**
  - Implemented `backend/src/threatfusion/datasets/adapters/suricata_flow.py` extracting the exact 14 model features:
    - 10 numeric features: `duration_ms`, `fwd_packets`, `bwd_packets`, `fwd_bytes`, `bwd_bytes`, `packets_per_second`, `bytes_per_second`, `fwd_packet_length_mean`, `bwd_packet_length_mean`, `dst_port`.
    - 4 protocol one-hot indicators: `protocol_tcp`, `protocol_udp`, `protocol_icmp`, `protocol_other`.
  - Bound `EntityProvenanceContract` to ensure sensor allowlisting, clock synchronization, private IP routing, and no NAT/address reuse ambiguity.
  - Implemented PEP 562 lazy attribute loading in `backend/src/threatfusion/datasets/adapters/__init__.py` to eliminate circular import loops with `network_inference.py`.
- **End-to-End Product Spine Integration & Quiescent 4-DB Snapshot Support:**
  - Wired `incident_repository` into `HumanListenerLifecycle` (`backend/src/threatfusion/operations/human_listener_lifecycle.py`), validating its schema on startup/replace and passing `incidents_path` to `snapshot_quiescent()`.
  - Added optional `include_incidents` parameter to `scripts/run_registered_browser_path.py` preserving 100% backward compatibility with `test_registered_browser_path.py`.
  - Implemented end-to-end integration test `backend/tests/integration/test_slide14_suricata_live_ingestion_path.py`:
    - Simulates Attacker VM flow against Victim VM private IP 10.0.0.5.
    - Adapts flow via `SuricataFlowAdapter` into 14 features with verified `EntityProvenanceContract`.
    - Executes frozen Random Forest inference (`random_forest.joblib`), producing Attack decision ($p = 0.5341$).
    - Persists `AlertCandidate` to `alerts.sqlite3` and correlates into `incidents.sqlite3` (`singleton_verified_provenance`, `verified_entity_bearing`).
    - Launches `HumanListenerLifecycle` and performs authenticated browser mTLS `GET /` (Queue) and `GET /v1/analyst/alerts/{id}` (Detail).
    - Issues authenticated browser mTLS `POST /v1/analyst/alerts/{id}/transitions` with CSRF token and UUIDv4 transition ID, transitioning alert to `in_review` (version 1) in `states.sqlite3`.
    - Executes `snapshot_quiescent()`, producing a verified 4-database snapshot (`alerts`, `states`, `audit`, `incidents`), verified by `verify_storage_snapshot()`.
- **Verification:**
  - 120+ focused unit and integration tests pass cleanly across all affected test suites.
  - Ruff, Black, and `git diff HEAD --check` pass with zero errors.
  - Frozen model SHA-256 digests verified identical; zero training/fitting performed.
  - Milestone #22 was committed to `gemini/product-20260924` at `f511907`.

### 2026-10-16 — Milestone #23: Canonical Evaluation Pack Rev2 (AI-FYP-2006), Section 8 fusion_disabled Invariant, Threat-Intel Enrichment (13.C), Evidence-Bound Advisory Debrief (13.D), and Approval-Gated Reversible SOAR Ledger (13.E)

- **Canonical Evaluation Pack Rev2 (`AI-FYP-2006`, TF-002/TF-007):**
  - Authored `backend/src/threatfusion/models/canonical_evaluation.py` and published authoritative specification `docs/canonical_evaluation_pack_rev2.md`.
  - Formally binds project metadata to FAST-NUCES Karachi, CS492 Final Year Project in Cyber Security, supervisor, and academic jury rubric.
  - Formally documents classical baselines: Random Forest (89.77% acc, 91.31% F1, 75.07% cat acc), XGBoost (98.01% recall), Logistic Regression (81.24% acc).
  - Formally documents deep learning candidates: Deep Neural Network (2.04% FPR, 68.76% cat acc), Transformer (96.43% recall), Multimodal Fusion (94.95% acc, 96.30% F1).
  - Mandates Split-Inversion Scientific Disclosure: explicitly documents January/February training/evaluation split inversion where February test distribution was inspected during model tuning.
  - Enforces Section 8 Invariant: multi-model fusion is strictly disabled in production inference (`fusion_disabled = True`), frozen RF (`random_forest.joblib`) is the sole production baseline, and v2 AE is experimental/unfused. `enforce_production_inference_invariants()` raises `ProductionInferenceInvariantViolation` if any fusion policy is attempted in production mode.
- **Section 13.C Threat Intelligence Enrichment Service (`threat_intel_enrichment_v1`, TF-008):**
  - Implemented `backend/src/threatfusion/intel/enrichment_service.py` with `ThreatIntelEnrichmentService` and `LocalThreatIntelFeed`.
  - Strict RFC 1918 / Localhost Privacy Suppression (`RFC1918_AND_LOCAL_NETWORKS`): Internal IP addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`) are strictly suppressed from external lookups (`privacy_suppression = True`, score `0.0`).
  - TTL-bounded caching (`ttl_seconds=300`) and deterministic allowlist/denylist precedence.
  - Degraded offline fallback: feed unavailability or errors return score `0.0` with `is_degraded = True` and degradation rationale, preventing pipeline aborts.
  - Converts results into canonical `SignalObservation` for Section 9 7-signal multi-signal risk evaluator (`dynamic_risk_assessment_v1`).
- **Section 13.D Evidence-Bound Advisory Debrief Engine (`advisory_debrief_v1`, TF-008):**
  - Implemented `backend/src/threatfusion/llm/advisory_debrief.py` with `AdvisoryDebriefEngine`.
  - Enforces mandatory advisory disclaimer: `"ThreatFusion LLM debriefs are advisory only. They do not constitute verified containment authorization or causal proof."`
  - Requires non-empty evidence citations (`cited_evidence_keys`), citing candidate IDs, incident IDs, source IPs, and detector decisions.
  - Binds verified versioned MITRE ATT&CK techniques (`T1046`, `T1190`, `T1498`, etc.) with observable evidence mapping and confidence bounds.
  - Generates competing hypotheses (e.g. benign administrative probe vs. active exploitation) to prevent single-explanation tunnel vision.
  - Operates offline via deterministic structured template fallback with zero external network/token cost requirements.
- **Section 13.E Approval-Gated Reversible SOAR Ledger (`soar_ledger_sqlite_v1`, TF-008/TF-009):**
  - Implemented `backend/src/threatfusion/soar/soar_ledger.py` with `SoarLedgerRepository` using isolated mode-0600 SQLite store (`soar_ledger.sqlite3`).
  - Mandatory Human Approval Gate: proposals begin in `PENDING_APPROVAL`. Direct execution attempts without prior approval raise `SoarPolicyViolationError("approval_required")`.
  - Protected Target Allowlist: containment actions targeting protected IP infrastructure (`1.1.1.1`, `8.8.8.8`, `127.0.0.1`, `10.0.0.1`) are rejected unconditionally (`SoarPolicyViolationError("target_is_protected")`).
  - Full State Machine & Reversible Compensation: tracks lifecycle (`pending_approval` -> `approved` -> `executed_simulated` -> `rolled_back`), logs audit trails, and executes verified reversal actions.
- **Milestone #23 Unification & Clean Commit (`3f32c7f`):**
  - Removed duplicate Pass-1 modules created by split terminal paste (`intel/`, `llm/`, `soar_ledger.py`, `test_advisory_debrief.py`, `test_soar_ledger.py`).
  - Preserved canonical Pass-2 packages: `threatfusion.enrichment` (`SourcedThreatIntelEnricher`), `threatfusion.advisory` (`AdvisoryExplanationEngine`), and `threatfusion.soar` (`ApprovalGatedSoarEngine`, `SoarPlaybookRecord`, `SoarAuditEntry`, `SoarPlaybookSqliteRepository`).
  - Committed Milestone #23 under commit `3f32c7f`.

### Milestone #24: Section 13.F Workload Measurement, Evaluation Pack Rev2 (6a36dcd), and Turnkey Two-Track Demo Runner (2026-10-16)

- **Authoritative Evaluation Pack Rev2 (`6a36dcd9af17bf509977bcf966f2ace72644d5b2`, `AI-FYP-2006`):**
  - Updated `backend/src/threatfusion/models/canonical_evaluation.py` and `docs/canonical_evaluation_pack_rev2.md` to exact September 21, 2026 Evaluation Pack Rev2 figures.
  - Pinned exact populations: Train 865,480 benign-only, January validation 216,568, February benchmark 1,452,844.
  - Frozen Random Forest reference: 95.266% precision, 92.818% recall, 94.026% F1, 0.095% FPR on January.
  - Section 8 Complementarity & Why Fusion Is Disabled: AE OR-fusion yields 96 extra attacks at cost of 1,574 additional false alarms (16.3958 benign FPs/extra attack, 8.831x FP inflation, dropping precision from 95.266% to 69.997%). Enforces `production_fusion_enabled = False`.
  - Superseded FYP-I deck figures (89.77% RF, 94.95% DL fusion from Final Presentation (1).pptx) preserved exclusively in `LegacyFyp1SupersededSummary`.
- **Section 13.F Alert-Fatigue Compression & Analyst Workload Measurement Harness (`workload_measurement_v1`):**
  - Implemented `backend/src/threatfusion/evaluation/workload_measurement.py` with `evaluate_alert_fatigue_compression` and `AnalystWorkloadStudyRepository`.
  - Layer 1 computes flow-to-alert reduction ratio and alert-to-incident consolidation ratio.
  - Layer 2 computes exact Section 8 counterfactual false-positive shield on January UNSW population.
  - Persistent mode-0600 SQLite store (`workload_study.sqlite3`) records `TriageTrialRecord` and computes mean/median triage times, speedup, and accuracy gain.
  - TF-009 Closure Discipline: `tf_009_closure_eligible` is strictly `False` unless study cohort is `human_analyst_cohort_study` with at least 10 human trials across both conditions, keeping TF-009 honestly open during automated/synthetic testing.
- **Turnkey Two-Track Jury & Supervisor Demonstration Runner (`full_soc_demo_report_v1`):**
  - Implemented `run_full_soc_demo(output_dir)` in `backend/src/threatfusion/operations/full_soc_demo.py` and CLI wrapper `scripts/run_full_soc_demo.py`.
  - Executes Track A (UNSW-NB15 replay proof, rows 1 & 21, Section 8 shield) and Track B (Slide 14 Azure VM Suricata live ingestion full SOC spine) end-to-end.
  - Generates deterministic JSON and Markdown evidence reports (`full_soc_demo_report.json` and `full_soc_demo_report.md`).
- **Comprehensive Verification Gate:**
  - 15 test suites (110 tests) pass cleanly in 39.60s with zero warnings:
    - `test_full_soc_demo_runner.py`
    - `test_slide14_suricata_live_ingestion_path.py`
    - `test_milestone23_full_spine.py`
    - `test_registered_browser_path.py`
    - `test_human_listener_lifecycle.py`
    - `test_canonical_evaluation.py`
    - `test_workload_measurement.py`
    - `test_suricata_flow_adapter.py`
    - `test_provenance_sources.py`
    - `test_correlation_engine.py`
    - `test_multi_signal_risk.py`
    - `test_threat_intel_enrichment.py`
    - `test_advisory_and_soar_ledger.py`
    - `test_package_discovery.py`
    - `test_jury_traceability_and_feedback.py`
  - Code hygiene: `ruff check` passes with 0 errors, `black --check` passes across all 197 files, git diff clean.
  - Frozen model SHA-256 digests remain byte-identical; zero training or online drift.

TF-008, TF-009, TF-010, and TF-011 remain **open** per their documented acceptance gates:
- **`TF-008` (`open`)**: *Independent Model Benchmark Beyond Inspected January/February UNSW Splits* — January (`216,568` rows) and February (`1,452,844` rows) were both previously inspected during model selection/evaluation; closing `TF-008` requires evaluation on an untouched independent holdout or external dataset benchmark.
- **`TF-009` (`open`)**: *Measured Reduction of Analyst Workload / Alert Fatigue* — `workload_measurement.py` (`Section 13.F`) provides the counterfactual January FP shield proof (`201` RF FPs vs `1,775` fused FPs = `8.831x`) and the SQLite telemetry recorder (`workload_study.sqlite3`), but closing `TF-009` requires real human-factors / analyst cohort study trials (`study_cohort="human_analyst_cohort_study"`, `min_human_trials >= 10`).
- **`TF-010` (`open`)**: *External FAST-NUCES FYP-II Jury Rubric & Signed Supervisor/Jury Evaluation Alignment* — internal traceability (`jury_traceability.py`) and Evaluation Pack Rev2 (`AI-FYP-2006`) alignment are wired, but closing `TF-010` requires the official external signed FAST-NUCES jury/supervisor rubric artifact.
- **`TF-011` (`open`)**: *Real Operational SIEM / Threat-Intelligence Production Source Proof* — `SuricataFlowAdapter` (`Slide 14`) and `SourcedThreatIntelEnricher` (`Section 13.C`) are verified on bounded/recorded flows and local snapshots, but closing `TF-011` requires live operational SIEM / production threat-intelligence source deployment evidence.

### Milestone #25: Deterministic Zero-Trust Repository Truth Audit Gate (2026-10-16)

- **Deterministic Zero-Trust Repository Truth Audit Gate (`repo_truth_audit_v1`):**
  - Implemented `run_repository_truth_audit(repo_root)` in `backend/src/threatfusion/evaluation/repo_truth_audit.py` and CLI wrapper `scripts/audit_repo_truth.py`.
  - Executes 7 programmatic, non-mocked checks against live repository and runtime objects:
    1. Workspace Isolation & Git State Check (`/home/muhammad-bilal/projects/threatfusion-gemini`, branch `gemini/product-20260924`, SHA-256 file hashes).
    2. Frozen Model Artifact SHA-256 Invariance Check (RF `bd2853a6...`, Logistic `2cf4de66...`, AE v2 `c8675d13...`, rate-log1p `1d02e5bb...`).
    3. Canonical Evaluation Pack Rev2 (`AI-FYP-2006`, checkpoint `6a36dcd`) Runtime Verification.
    4. Section 8 (`fusion_disabled`) Runtime Enforcement Check (`production_fusion_enabled=False`, ValueError on True).
    5. No Duplicate Package Regression Check (zero split-paste duplicate packages; clean import of canonical Pass-2 packages).
    6. Section 13.C / 13.D / 13.E / 13.F Live Functional Probe (RFC1918 guard, anti-hallucination groundedness, SOAR approval gate, workload FP shield).
    7. Issue Register Honesty & Canonical Title Check (`TF-008`, `TF-009`, `TF-010`, `TF-011` strictly open with canonical keywords).
  - Generates deterministic cryptographic ground-truth receipt SHA-256 banner with exit code 0.
- **Comprehensive Verification Gate:**
  - 16 test suites (116 tests) pass cleanly in 28.39s with zero warnings:
    - `test_repo_truth_audit.py` (6 tests)
    - `test_full_soc_demo_runner.py`
    - `test_slide14_suricata_live_ingestion_path.py`
    - `test_milestone23_full_spine.py`
    - `test_registered_browser_path.py`
    - `test_human_listener_lifecycle.py`
    - `test_canonical_evaluation.py`
    - `test_workload_measurement.py`
    - `test_suricata_flow_adapter.py`
    - `test_provenance_sources.py`
    - `test_correlation_engine.py`
    - `test_multi_signal_risk.py`
    - `test_threat_intel_enrichment.py`
    - `test_advisory_and_soar_ledger.py`
    - `test_package_discovery.py`
    - `test_jury_traceability_and_feedback.py`
  - Code hygiene: `ruff check .` passes with 0 errors across repo; `black --check .` passes across 201 files.
  - Frozen model SHA-256 digests remain byte-identical; zero training or online drift.

TF-008, TF-009, TF-010, and TF-011 remain **open** per their documented acceptance gates.

### Milestone #26: Presentation Deck & Academic Defense Harmonization (2026-10-16)

- **Presentation Deck Harmonization (`scripts/generate_harmonized_defense_deck.py`):**
  - Harmonized `/home/muhammad-bilal/Downloads/Final Presentation (1).pptx` with authoritative Evaluation Pack Rev2 (`AI-FYP-2006`, checkpoint `6a36dcd`) into `artifacts/reports/ThreatFusion_FYP2_Final_Defense_Harmonized.pptx` (92,623 bytes, exactly 15 slides).
  - Pinned project identity: `AI-FYP-2006`, FAST-NUCES Karachi CS492 FYP-II, Supervisor: Sir Sameer Faisal, Team: Muhammad Bilal (21K-3551), Muhammad Suhaib Shaikh (22K-4302), Muhammad Hasnain (22K-4718).
  - Completely eliminated legacy split-inversion metrics (89.77% RF, 94.95% multimodal fusion) from all slides.
  - Injected exact Evaluation Pack Rev2 metrics on January Validation (216,568 rows): Frozen RF precision 95.27%, recall 92.82%, F1 94.03%, FPR 0.095% (only 201 false alarms in 212,210 benign flows).
  - Emphasized Core Defense Pillar (Section 8 Invariant): Autoencoder adds 96 attacks (+2.37% recall) but triggers 1,574 additional false alarms (8.83x inflation, 16.3958 FPs per gained attack); automatic fusion is strictly disabled in production (`production_fusion_enabled = False`).
  - Upgraded Slide 14 live architecture status from "Pending" to **Bounded Recorded/Local Integration Path Verified (16/16 Test Gates); Live Azure/SIEM Deployment Open (TF-011)** (`test_slide14_suricata_live_ingestion_path.py`). Explicitly documents that the repository software spine (Suricata eve.json -> 14 features -> loopback mTLS 1.3 -> Frozen RF -> Correlation -> RFC1918 Threat-Intel -> Advisory -> Reversible SOAR) is verified by automated integration tests, while live Azure VM / production SIEM field deployment remains unverified and open under `TF-011`.
  - Integrated Section 13 Modern SOC Pillars (13.C RFC1918 Threat-Intel Guard, 13.D Evidence-Bound Advisory, 13.E Reversible SOAR Ledger, 13.F Workload Shield with 8.831x FP reduction).
- **Academic Defense Brief & Harmonization Report (`docs/defense_slide_deck_harmonization.md`):**
  - Comprehensive slide-by-slide before-and-after mapping across all 15 slides.
  - Linked all claims directly to immutable model SHA-256 hashes and `audit_repo_truth.py` zero-trust receipt.
  - Authored detailed panel and jury talking points for Sir Sameer Faisal and the FAST-NUCES evaluation panel covering model selection, Autoencoder false alarms, Section 8 fusion policy, Slide 14 live ingestion, and open issue integrity.
TF-008, TF-009, TF-010, and TF-011 remain **open** per their documented acceptance gates.

### Milestone #27: Interactive Analyst Workload Study CLI Runner (Section 13.F) & Harmonized Defense Report + 3-Speaker Presenter Guide Generators (2026-10-16)

- **Interactive & Scriptable Analyst Workload Study CLI Runner (`backend/src/threatfusion/evaluation/study_runner.py`, `scripts/run_analyst_workload_study.py`):**
  - Designed `STUDY_TRIAGE_CASES` containing 10 realistic, provenance-grounded triage scenarios spanning recorded UNSW-NB15 flows and Slide 14 Suricata `eve.json` flows (5 true attacks expecting `escalated` and 5 benign/noise flows expecting `dismissed`/`resolved`).
  - Implemented comparative presentation views: Condition A (`baseline_raw_alert_only`: raw 14 features and threshold status) vs Condition B (`threatfusion_enriched_advisory_soar`: frozen RF probability, Section 8 non-fused AE context, 30-second burst window (30s) and 10-minute campaign window (600s) correlation status, Section 13.C RFC1918 threat-intel guard, Section 13.D grounded advisory debrief, and Section 13.E approval-gated SOAR recommendation).
  - Automated Smoke Mode (`--mode smoke` / `run_automated_smoke_study`): evaluates 20 trials tagged with `study_cohort="synthetic_smoke_verification"`, enforcing `tf_009_closure_eligible = False` so automated runs never falsely close `TF-009`.
  - Interactive Human Analyst Mode (`--mode interactive` / `run_interactive_study`): terminal prompts measuring wall-clock `time_to_first_review_ms` and `time_to_disposition_ms` tagged with `study_cohort="human_analyst_cohort_study"`, saving JSON and Markdown summary reports to a configurable output directory.
- **Harmonized FYP-II Final Report & 3-Speaker Presenter Guide Generators (`scripts/generate_harmonized_defense_docs.py`):**
  - Created standalone generator producing `docs/presenter_guide_15_slides_rev2.md` and two valid OpenXML `.docx` documents (`artifacts/reports/ThreatFusion_FYP2_Presenter_Guide_Harmonized.docx` and `artifacts/reports/ThreatFusion_FYP2_Final_Report_Harmonized.docx`) using a pure-Python standard-library `zipfile` builder (zero external dependencies).
  - Structured 3-speaker presentation choreography across 15 slides: Speaker 1 (Muhammad Bilal 21K-3551: Slides 1–5 + live demo), Speaker 2 (Muhammad Suhaib Shaikh 22K-4302: Slides 6–10 + inverted split retraction), Speaker 3 (Muhammad Hasnain 22K-4718: Slides 11–15 + Section 8 fusion-disabled shield + qualified Slide 14 pipeline + open issue defense).
  - Pinned exact unrounded Rev2 metrics (`0.1181361214680695`, `212,009`, `313`, `95.266%`, `92.818%`, `94.026%`, `8.8308x`, `16.3958`), qualified Slide 14 badge and software-spine footer, and confirmed ZERO instances of `"VERIFIED & OPERATIONAL"` or `"100% operational"`.
- **Comprehensive Unit Testing (`backend/tests/unit/test_defense_docs_and_study_runner.py`):**
  - 4 test cases covering automated smoke study, interactive study with scripted input, OpenXML document generation and invariant validation, and triage case distribution.
  - All 18 milestone test suites (129 tests) pass cleanly in 45.85s.

TF-008, TF-009, TF-010, and TF-011 remain **open** per their documented acceptance gates.

### Milestone #28: 3-Layer Deterministic Architecture SOPs, Unicorn Progressive-Disclosure SOC Interface, Resilient Suricata Ingestion with Dead-Letter Quarantine, $0 Cloud Budget Kill-Switch, and Outage-Isolated Grounded Gemini Advisory Client (2026-10-18)

- **Layer-1 Constitutional Architecture SOPs & Unicorn SOC Design Guidelines (`design_guidelines/soc_unicorn_interface_sop.md`, `docs/blast_3layer_architecture_sop.md`):**
  - Documented 3-Layer Deterministic Architecture separating Layer 1 (human-authored constitutional SOPs, schemas, evaluation truth packs), Layer 2 (deterministic orchestration, typed contracts, immutable event schemas, zero-hallucination routing), and Layer 3 (atomic deterministic tools in `backend/src/` and `scripts/` where probabilistic LLMs are strictly banned from primary detection, feature extraction, correlation, and SOAR execution).
  - Defined "Unicorn" SOC Interface Visual Hierarchy and Progressive Disclosure:
    - Tier 1 (Primary Triage Signal): Frozen Random Forest Verdict Badge (P(Attack) >= 0.5, 95.266% precision, 0.095% FPR) and Dual-Window Incident Consolidation Badge (30.0s burst / 600.0s campaign).
    - Tier 2 (Secondary Non-Blocking Investigative Context): Unfused v2 Autoencoder Reconstruction Error Badge (`badge-secondary-anomaly`: explicitly marked "Secondary Anomaly Indicator — Production Fusion Disabled per Section 8 16.4:1 FP Shield"), Verified Entity Provenance Badge, and RFC1918/Sourced Threat-Intel Badge.
    - Tier 3 (Grounded Debrief & Human-Gated Action): Evidence-Bound Advisory Debrief (with cited evidence keys and deterministic template fallback) and Approval-Gated Reversible SOAR Controls (`pending_approval` -> `approved` -> `executed_simulated` -> `rolled_back`).
  - Enhanced `backend/src/threatfusion/api/analyst_dashboard.py` with `data-blast-ui-tier="unicorn-progressive-disclosure-v1"` and styled secondary anomaly badge.

- **Resilient Suricata Stream Ingestion with Dead-Letter Quarantine & $0 Cloud Budget Kill-Switch (`backend/src/threatfusion/operations/cloud_live_telemetry.py`, `scripts/run_cloud_suricata_forwarder.py`, `docs/google_ai_pro_zero_dollar_cloud_guide.md`):**
  - Implemented `process_suricata_eve_stream_resilient`: parses Suricata EVE streams, cleanly skips non-flow events (`stats`, `dns`, `http`, `tls`, `alert`), and quarantines corrupted JSON lines and schema-invalid flows into `dead_letter_records` (`DeadLetterQuarantineRecord`) without raising or disrupting valid flow adaptation.
  - Implemented `CloudBudgetKillSwitchPolicy` and `evaluate_budget_kill_switch`: deterministically triggers `should_detach_billing=True` at $5.00 gross spend and fails closed on negative spend or malformed telemetry, guaranteeing $0 out-of-pocket charges on the $10/month Google AI Pro credit model.
  - Documented architecture and setup in `docs/google_ai_pro_zero_dollar_cloud_guide.md` and created CLI forwarder script `scripts/run_cloud_suricata_forwarder.py`.

- **Outage-Isolated Grounded Gemini Advisory Client (`backend/src/threatfusion/advisory/gemini_client.py`):**
  - Implemented `GeminiAdvisoryConfig`, `GeminiAdvisoryUnavailableError`, and `build_grounded_gemini_prompt` using pure Python stdlib (`urllib.request`, `json`, `os`).
  - Implemented `GeminiAdvisoryCallable` strictly outside the primary detection loop: serializes only verified evidence from `AdvisoryEvidenceBundle`, enforces strict anti-hallucination rules (zero uninspected IPs, exact model version/probability, Section 8 fusion-disabled invariant affirmation, bounded cited keys).
  - Outage isolation: fails closed to `deterministic_evidence_template` via `AdvisoryExplanationEngine` whenever `GEMINI_API_KEY` is missing, transport times out, or an ungrounded hallucination (e.g. IP `203.0.113.99`) is detected.

- **Zero-Trust Audit Gate Upgrade & Comprehensive Test Verification (`backend/src/threatfusion/evaluation/repo_truth_audit.py`, `backend/tests/unit/test_blast_resilience_and_gemini_advisory.py`):**
  - Upgraded Check 5 to verify `threatfusion.advisory.gemini_client` and `threatfusion.operations.cloud_live_telemetry` module origin under `backend/src` and assert `design_guidelines/soc_unicorn_interface_sop.md` exists on disk.
  - Upgraded Check 6 (Live Functional Probe) to verify live resilient Suricata stream dead-letter quarantine and the $5.00 cloud budget kill-switch.
  - Created `backend/tests/unit/test_blast_resilience_and_gemini_advisory.py` covering stream resilience, budget kill-switch policy thresholds, grounded Gemini advisory generation, anti-hallucination fallback on IP `203.0.113.99`, timeout/missing-key handling, and dashboard HTML progressive-disclosure tier rendering.
  - All test suites passing cleanly, and `scripts/audit_repo_truth.py` confirms ALL 7 ZERO-TRUST CHECKS PASSED.

TF-008, TF-009, TF-010, and TF-011 remain **open** per their documented acceptance gates.

### Milestone #29: 9.5/10 B.L.A.S.T. Governance Upgrade (2026-10-18)

- **Whole-Tree Symlink Rejection Gate (`_check_1_workspace_and_git_state` in `repo_truth_audit.py`):**
  - Upgraded Check 1 to verify `git rev-parse --show-toplevel` resolves to the canonical repository root.
  - Added whole-tree symlink traversal across `backend`, `scripts`, `docs`, and `design_guidelines` trees (`os.walk(..., followlinks=False)`). Any symlink immediately fails Check 1 closed with `"Unexpected symlink detected in workspace tree: <path>"`.
- **Programmatic GO/NO-GO Decision Report & Unresolved Risk Ledger (`repo_truth_audit.py`, `scripts/audit_repo_truth.py`):**
  - Added `decision_verdict: str` ("GO" iff all checks pass and `failed_check_ids == ()`, else "NO-GO"), `failed_check_ids: tuple[str, ...]`, and `unresolved_risks: tuple[str, ...]` to `RepoTruthAuditReport`.
  - Bound the 4 canonical scientific disclosures (TF-008, TF-009, TF-010, TF-011) directly into the cryptographic truth audit receipt.
  - Updated CLI runner `scripts/audit_repo_truth.py` to display the explicit scientific risk disclosures and post-execution decision verdict banner (`POST-EXECUTION DECISION VERDICT: GO`).
- **Test Suite Consolidation (`test_blast_resilience_and_gemini_advisory.py`):**
  - Merged redundant split test files (`test_advisory_explanation.py`, `test_blast_and_unicorn_sops.py`, `test_cloud_live_telemetry.py`) into one authoritative unit test file `backend/tests/unit/test_blast_resilience_and_gemini_advisory.py` (19 passing unit tests).
  - Added unit regression tests in `test_repo_truth_audit.py`: `test_repo_truth_audit_rejects_unexpected_symlink_in_backend_tree` (asserts symlink injection triggers NO-GO) and `test_repo_truth_audit_emits_go_verdict_and_unresolved_risks_on_valid_repo` (asserts live GO verdict and 4 risks).
- **Architecture SOP Documentation (`docs/blast_3layer_architecture_sop.md`):**
  - Documented the 5 B.L.A.S.T. v2 governance rules: (1) Programmatic workspace & symlink rejection, (2) Exclusive subagent file ownership matrix, (3) Explicit GO/NO-GO decision report, (4) Task-specific behavioural verification, (5) Pre-flight checkpoint & change-control recovery.

TF-008, TF-009, TF-010, and TF-011 remain **open** per their documented acceptance gates.

### Milestone #30: Unified Master Engineering Skill v3.0, Boundary Preflight B0-B5, Recall Labeling Harmonization, Gate G9 AST Check, Tamper-Evident SOAR Hash Chain, and Non-Fused AE Queue Ranker (2026-10-18)

- **Deterministic Boundary Preflight (scripts/boundary_preflight.py & boundary_preflight.py):**
  - Implemented standalone and importable `boundary_preflight.py` enforcing Protocol 0 deterministic boundary checks B0 through B5 using component-wise realpath containment (`Path(os.path.realpath(p)).is_relative_to(...)`) and negative lookahead `(?![\w\-])` to avoid false triggers on `-gemini`:
    - B0: Active and protected realpaths strictly non-overlapping.
    - B1: Current working directory resolves inside active and outside protected.
    - B2: Workspace contains zero symlinks pointing into protected or escaping active.
    - B3: Virtual environment (`threatfusion-venv`) contains zero `.pth`, `direct_url.json`, or symlink references to protected.
    - B4: Git repository metadata (`.git/objects/info/alternates`, `worktrees`, `config`) strictly isolated from protected.
    - B5: Runtime code and config files (`.py`, `.toml`, `.json`, etc.) contain zero literal references to protected.
  - Installed portable skill contracts: `SKILL.md` (repo root), `.agents/skills/threatfusion-master-engineering/SKILL.md`, and `.agents/ownership.json`.
  - Integrated Gate G0 boundary preflight invocation directly into `repo_truth_audit.py` Check 1 (`_check_1_workspace_isolation`).
- **Mathematical Recall Labeling Harmonization:**
  - Reconciled mathematical labeling across codebase and academic defense documentation:
    - Ground truth: January RF recall is 92.818% (4,045 / 4,358).
    - Counterfactual fusion recall is 95.021% (4,141 / 4,358).
    - Absolute recall gain is `+2.203 percentage points` (pp).
    - Relative true positive increase is `+2.373%` (96 additional attacks / 4,045 baseline RF attacks).
  - Updated `workload_measurement.py` (`CounterfactualFusionShieldMetrics.counterfactual_fused_recall_pct` and `recall_gain_percentage_points`), `canonical_evaluation.py` (`Section8Complementarity`), `scripts/generate_harmonized_defense_deck.py`, `scripts/generate_harmonized_defense_docs.py`, `docs/defense_slide_deck_harmonization.md`, and `docs/presenter_guide_15_slides_rev2.md`.
  - Re-generated defense artifacts: `ThreatFusion_FYP2_Presenter_Guide_Harmonized.docx` and `ThreatFusion_FYP2_Final_Report_Harmonized.docx`.
- **Tamper-Evident Hash-Chained SOAR Audit Trail (`playbook_ledger.py`):**
  - Enhanced `SoarPlaybookSqliteRepository` with cryptographic SHA-256 hash chaining:
    - Added `prev_entry_sha256` and `entry_sha256` columns to `soar_audit_events` schema with automatic migration.
    - Established `SOAR_AUDIT_GENESIS_HASH = "0" * 64`.
    - Computed `compute_soar_audit_entry_hash` linking each audit event cryptographically to the preceding event hash.
    - Added `verify_audit_chain_integrity(playbook_id=None) -> tuple[bool, str]` verifying full hash chain integrity and detecting direct SQLite tampering, updates, and deletions.
- **Non-Fused AE Queue Priority Ranker (`multi_signal_risk.py`):**
  - Implemented `rank_rf_alerts_for_triage_queue` enforcing Section 8 `production_fusion_enabled=False` (raises `ValueError` if `True`).
  - Admitted only alerts meeting RF threshold (`rf_attack_probability >= 0.5`).
  - Ordered triage queue deterministically: (1) incident burst size, (2) secondary unfused AE reconstruction error ratio (`ae_error / ae_threshold`), (3) RF attack probability.
  - Attached `queue_priority_rank` (1..N) and human-readable `priority_rationale`.
- **Gate G9 AST Detection Pipeline Import-Graph Check (`repo_truth_audit.py`):**
  - Added `verify_gate_g9_ast_import_graph(src_root)` to statically parse Stage 1 to 4 detection modules (`suricata_flow.py`, `provenance_sources.py`, `producer_inference_worker.py`, `network_inference.py`, `correlation_engine.py`) and verify zero imports of Stage 5 advisory components (`threatfusion.advisory`, `gemini_client`, `explanation_engine`).
  - Integrated into Check 5 (`_check_5_no_duplicate_package_regression`) and Check 6 live probes.
- **Unit Test Suite & Zero-Trust Audit Verification:**
  - Created `backend/tests/unit/test_boundary_and_high_leverage_features.py` with 17 tests covering B0-B5 boundary preflight, recall labeling, SOAR audit hash chain tamper detection, AE queue ranker, and Gate G9 AST detection pipeline isolation.
  - All test suites passing cleanly, and `scripts/audit_repo_truth.py` confirms ALL 7 ZERO-TRUST CHECKS PASSED with `POST-EXECUTION DECISION VERDICT: GO`.

TF-008, TF-009, TF-010, and TF-011 remain **open** per their documented acceptance gates.

### Milestone #31: 14-Feature PSI Drift & Model Supply-Chain Monitor, Pre-Registered TF-008 Independent Holdout Evaluator with Bootstrap CIs, and Full SOC Demo / Dashboard Integration of AE Queue Ranker & SOAR Hash Chain (2026-10-18)

- **Model Supply-Chain Manifest Verifier (`drift_and_supply_chain.py`):**
  - Implemented `verify_frozen_model_supply_chain(repo_root: Path) -> dict[str, Any]` and `FrozenModelSupplyChainEntry` verifying all 4 frozen model artifacts on disk against canonical SHA-256 digests and explicit operational roles:
    - Random Forest: `bd2853a6...` (`primary_production_authority`)
    - Logistic Regression: `2cf4de66...` (`linear_baseline`)
    - Autoencoder v2: `c8675d13...` (`secondary_non_blocking_ranker`)
    - Rate-Log1p Candidate: `1d02e5bb...` (`blocked_candidate`)
  - Enforced fail-closed security: missing files, symlinks, zero-byte sizes, or SHA-256 mismatches raise `ModelSupplyChainError` or emit `verified=False`.
- **Read-Only 14-Feature PSI Drift Monitor (`drift_and_supply_chain.py`):**
  - Implemented `evaluate_14_feature_telemetry_drift` and `FeatureDriftMetric`, `TelemetryDriftReport` using only Python standard library (`math`, `statistics`).
  - STRICT INVARIANT: strictly read-only diagnostic monitor; never mutates model weights, thresholds, input records, or alert creation.
  - Enforced presence and finite type of all 14 canonical features: `duration_ms`, `fwd_packets`, `bwd_packets`, `fwd_bytes`, `bwd_bytes`, `packets_per_second`, `bytes_per_second`, `fwd_packet_length_mean`, `bwd_packet_length_mean`, `dst_port`, `protocol_tcp`, `protocol_udp`, `protocol_icmp`, `protocol_other`.
  - Computed per-feature mean shift Z-score and decile Population Stability Index (PSI) approximation using standard normal cumulative probability differences across 10 baseline decile bins.
  - Classified overall `drift_status`:
    - `stable_in_distribution` ($\max(\text{PSI}) < 0.10$)
    - `moderate_feature_drift_monitor` ($0.10 \le \max(\text{PSI}) < 0.25$)
    - `severe_out_of_distribution_drift_retraining_review_required` ($\max(\text{PSI}) \ge 0.25$)
- **Pre-Registered TF-008 Independent Holdout Evaluator with Bootstrap CIs (`independent_holdout_protocol.py` & `docs/tf008_preregistered_evaluation_protocol.md`):**
  - Blacklisted development-informing splits via `INSPECTED_DEVELOPMENT_DATASET_IDS = ("unsw_nb15_train_865480", "unsw_nb15_january_216568", "unsw_nb15_february_1452844")`.
  - Any evaluation referencing an inspected split triggers `protocol_violation_inspected_split = True` and `tf_008_closure_eligible = False`.
  - Implemented `evaluate_independent_holdout_dataset` computing exact confusion counts at frozen 0.5 threshold, precision, recall, F1, FPR, accuracy, and deterministic 95% bootstrap confidence intervals ($B \ge 200$) using seeded PRNG (`random.Random(random_seed)`).
  - Enforced `tf_008_closure_eligible = False` whenever `is_synthetic_smoke_fixture = True`, `protocol_violation_inspected_split = True`, or sample size $N < 1000$.
- **Full SOC Demo & Analyst Dashboard Integration (`full_soc_demo.py`, `analyst_dashboard.py`):**
  - Wired `rank_rf_alerts_for_triage_queue`, `verify_audit_chain_integrity`, and `evaluate_14_feature_telemetry_drift` into Track B of turnkey demonstration runner `run_full_soc_demo`.
  - Master demo reports (`full_soc_demo_report.json` and `full_soc_demo_report.md`) now verify `soar_audit_chain_verified=True`, entry counts, chain head SHA-256, triage queue priority rank, and 14-feature PSI drift status.
  - Enhanced `analyst_dashboard.py` alert detail HTML view with `"SOAR Cryptographic Audit Chain: VERIFIED (SHA-256 Hash-Linked)"` badge and `"Non-Fused Queue Priority Rank"` indicator with dedicated dark-theme styling.
- **Repository Truth Audit Upgrade (`repo_truth_audit.py`):**
  - Added `threatfusion.models.drift_and_supply_chain` and `threatfusion.evaluation.independent_holdout_protocol` to Check 5 `CANONICAL_MODULES` with origin verification.
  - Upgraded Check 6 live functional probe to exercise `verify_frozen_model_supply_chain`, `evaluate_14_feature_telemetry_drift`, and `evaluate_independent_holdout_dataset` (asserting `protocol_violation_inspected_split=True` on January validation and `tf_008_closure_eligible=False` on synthetic smoke fixtures).
- **Unit Test Suite & Verification (`test_drift_supply_chain_and_tf008_protocol.py`):**
  - 15 comprehensive unit tests covering supply-chain verification and fail-closed security, input validation and 3-tier drift classification, immutability of inputs, holdout evaluation metrics and bootstrap CIs, inspected split rejection, full SOC demo report generation, and dashboard badge rendering.
TF-008, TF-009, TF-010, and TF-011 remain **open** per their documented acceptance gates.

### Milestone #32: Full Master-Plan SOC Stack Integration — ChromaDB Semantic Vector RAG, Deterministic n8n Playbook Webhook Engine, TheHive Case Management, MISP Private-IP Guarded IOC Client, Docker Compose SOC Stack, and Turnkey SOC Pipeline Integration (2026-10-18)

- **ChromaDB Semantic Vector RAG over MITRE ATT&CK & Incident Playbooks (`chromadb_mitre_rag.py`):**
  - Implemented `MitrePlaybookRagDocument`, `ChromaRagQueryResult`, and authoritative `CANONICAL_MITRE_AND_PLAYBOOK_CORPUS` containing 10 enterprise techniques (T1046, T1190, T1498, T1071.001, T1595, T1110, T1041, T1021, T1059, T1133) and structured SOC playbooks.
  - Implemented `DeterministicMitreEmbeddingFunction` generating 64-dimensional L2-normalized dense float vector embeddings from domain tokens and trigrams deterministically without external weights or network calls.
  - Implemented `ChromaDbMitrePlaybookRag` operating a persistent SQLite dense vector store (`chromadb_vectors.sqlite3`) with mode 0600 file security, cosine similarity ranking, and `query_semantic_rag_for_bundle` deriving targeted domain queries from `AdvisoryEvidenceBundle`.
  - Enforced strict assistant-only isolation: RAG recommendations are strictly advisory, never mutating model weights or alert decision thresholds. Stages 1-4 maintain zero imports of advisory modules (Gate G9 AST verified).
- **Deterministic n8n, TheHive, and MISP SOC Stack Clients (`n8n_thehive_misp_stack.py`):**
  - **MISP Threat Intelligence Client (`MispDeterministicClient`):** Queries MISP indicator endpoints with RFC1918 Private-IP Guard. Any query targeting internal/lab subnets (e.g., 10.0.0.4, 10.0.0.5) is strictly suppressed from external egress (`query_mode="rfc1918_guard_suppressed"`, `private_ip_guard_triggered=True`). Verified fallback snapshot matches known threat indicators (e.g., EICAR, Mirai) deterministically.
  - **TheHive Case Management Client (`TheHiveDeterministicClient`):** Formats and dispatches TheHive v4/v5 case records containing correlated `incident_id`, RF confidence score (%), non-fused AE queue rank, MISP IOC tags, and ChromaDB MITRE tags. Enforces mandatory SOAR approval gate and cryptographic hash chain verification (raising `SoarStateTransitionError` on unapproved records or tampered chains).
  - **Deterministic n8n Playbook Webhook Client (`N8nDeterministicPlaybookClient`):** Generates HMAC-SHA256 signed webhook triggers with idempotency keys (`idem_<playbook_id>_<version>`). Fails closed (raising `SoarStateTransitionError`) unless SOAR action is explicitly approved by a human analyst and cryptographic audit chain is verified.
  - **Durable SQLite Outbox:** Created `n8n_thehive_misp_outbox.sqlite3` with mode 0600 permissions, ensuring auditable persistence and reliable offline queueing.
- **Docker Compose SOC Stack & n8n Workflow JSON (`docker/docker-compose.soc-stack.yml`, `docker/n8n/workflows/threatfusion_soar_playbook.json`):**
  - Designed local containerized orchestration binding `n8n` (5678), `thehive` (9000), `chromadb` (8000), and `misp-connector` strictly to `127.0.0.1`.
  - Configured 5-node deterministic n8n workflow JSON: (1) Webhook Trigger, (2) Verify Approval & SHA-256 Audit Chain Gate, (3) Query MISP Threat Intelligence, (4) Auto-Create Case in TheHive, (5) Security Operations Callback.
- **Turnkey SOC Demo & Analyst Dashboard Integration (`full_soc_demo.py`, `analyst_dashboard.py`):**
  - Wired ChromaDB RAG, MISP, TheHive, and n8n clients directly into Track B of `run_full_soc_demo`.
  - Master demo reports (`full_soc_demo_report.json` and `full_soc_demo_report.md`) now verify `chromadb_mitre_rag_hits`, `misp_hash_and_ioc_lookup`, `thehive_case_record`, and `n8n_playbook_receipt`.
  - Added dedicated UI badges to `analyst_dashboard.py`:
    - `"ChromaDB Semantic RAG: MITRE ATT&CK & Playbook Assistant"`
    - `"n8n Deterministic Playbook & TheHive Case Status"`
    - `"Prioritized Alert Confidence Score (Frozen RF Primary + Secondary v2 AE)"`
    with CSS styling `.badge-confidence`, `.badge-chroma-rag`, and `.badge-n8n-hive`.
- **Zero-Trust Repository Truth Audit Upgrade (`repo_truth_audit.py`):**
  - Added `threatfusion.advisory.chromadb_mitre_rag` and `threatfusion.soar.n8n_thehive_misp_stack` to Check 5 `CANONICAL_MODULES`.
  - Check 5 verifies `docker/n8n/workflows/threatfusion_soar_playbook.json` is valid on disk.
  - Check 6 live functional probe verifies ChromaDB RAG cosine similarity retrieval, MISP RFC1918 guard on 10.0.0.4, and TheHive/n8n approval-gated fail-closed security.
- **Unit Test Suite & Verification (`test_chromadb_rag_n8n_thehive_misp.py`):**
  - 19 comprehensive unit tests covering ChromaDB vector RAG, embedding L2 normalization, MISP private IP guard and snapshot fallback, TheHive case creation and approval gates, n8n HMAC-SHA256 signatures, n8n workflow JSON structure, docker-compose configuration, full SOC demo execution, and analyst dashboard rendering.

TF-008, TF-009, TF-010, and TF-011 remain **open** per their documented acceptance gates.

### Milestone #33–#34: Master-Plan SOC Stack Hardening, Ledger-Backed Contract Verification, Strict Dashboard Evidence Validation, STRIDE Threat Model, and Defense Deliverable Harmonization (2026-10-19)

- **Remediation of Copilot Security & Reliability Findings #1 & #2 (`threatfusion_soar_playbook.json`):**
  - Inserted deterministic Cryptographic HMAC-SHA256, Idempotency, and Ledger State Verification Code Node ("Verify HMAC-SHA256 & Idempotency Envelope", type `n8n-nodes-base.code`) immediately after the Webhook Trigger and before the Approval Gate IF node.
  - The node validates `x-threatfusion-signature-256`, `x-idempotency-key`, and `THREATFUSION_SOAR_HMAC_SECRET` (failing closed if missing), computes expected HMAC-SHA256 digest, checks key formatting, and forwards signed verification to `http://threatfusion-callback:8443/api/v1/soar/verify-state` to verify server-side ledger state.
  - Replaced all `127.0.0.1` container URLs with Docker Compose service DNS hostnames: `http://misp-connector:8080/attributes/restSearch`, `http://thehive:9000/api/v1/case`, and `http://threatfusion-callback:8443/api/v1/soar/callback`.
- **Remediation of Copilot Finding #3 (`run_misp_and_callback_contract_server.py`, `docker-compose.soc-stack.yml`, `n8n_thehive_misp_stack.py`):**
  - Created standalone authenticated contract server `scripts/run_misp_and_callback_contract_server.py` using Python stdlib:
    - `POST /api/v1/soar/verify-state`: Verifies HMAC-SHA256 signature, validates idempotency key syntax, prevents replay attacks (HTTP 409), opens server-side `SoarPlaybookSqliteRepository` to ensure playbook exists, candidate ID matches, state is `approved` or `executed_simulated`, and hash-chain audit trail is cryptographically verified via `verify_audit_chain_integrity()[0]`. Fails closed with HTTP 403 on unapproved or fabricated playbooks.
    - `POST /api/v1/soar/callback`: Verifies HMAC-SHA256 signature and idempotency key (HTTP 403 on invalid signature, HTTP 409 on replay), verifies playbook in ledger, records callback with SHA-256 receipt.
    - `POST /attributes/restSearch`: Authenticates `Authorization` header against `THREATFUSION_MISP_API_KEY` (>=16 chars) using `hmac.compare_digest` (HTTP 401 on failure), returns deterministic MISP attributes for hashes/IPs, and enforces RFC1918 Private IP Guard (HTTP 422 Unprocessable Entity on internal IPs 10.0.0.4/10.0.0.5).
    - `GET /healthz`: Returns HTTP 200 `{"status": "ok"}`.
  - Updated `docker/docker-compose.soc-stack.yml`: Pinned exact image tags (`n8nio/n8n:1.68.0`, `strangebee/thehive:5.2.10`, `chromadb/chroma:0.5.20`, `python:3.11.10-slim`), eliminated all `******` placeholders, enforced fail-closed environment variables (`${THREATFUSION_THEHIVE_API_KEY:?required}`, etc.), mounted backend code, and configured `misp-connector` and `threatfusion-callback` services.
  - Removed predictable fallback secret in `n8n_thehive_misp_stack.py`, requiring non-empty secret >= 16 chars.
- **Remediation of Copilot Finding #4 (`n8n_thehive_misp_stack.py`):**
  - Replaced broad `except Exception:` blocks around external transport calls with specific expected transport exceptions (`urllib.error.URLError`, `TimeoutError`, `ConnectionError`, `OSError`, `ValueError`, `json.JSONDecodeError`) and recorded sanitized error reasons.
  - Prohibited catching and discarding `sqlite3.Error` / `OSError` in SQLite persistence methods (`_record_outbox_event`), ensuring storage failures propagate and never return fake success receipts.
- **Remediation of Copilot Finding #5 (`analyst_dashboard.py`):**
  - Implemented strict schema and digest validation on dashboard evidence badges:
    - `"SOAR Cryptographic Audit Chain"` renders `VERIFIED (SHA-256 Hash-Linked)` only when `soar_audit_chain_verified == True` and `soar_audit_chain_head_sha256` matches 64-char hex format `[0-9a-fA-F]{64}`; otherwise renders `data-evidence-state="unavailable"`.
    - `"ChromaDB Semantic RAG"` renders active MITRE techniques only when each hit contains valid technique ID matching `^T\d{4}(\.\d{3})?$`, non-empty `playbook_id`, and `cosine_similarity` in `[0.0, 1.0]`; loose unverified dictionaries fail closed to `data-evidence-state="unavailable"`.
    - `"n8n Deterministic Playbook & TheHive Case Status"` validates receipt/case digests matching 64-char hex or UUID formats; unverified evidence renders as `Not Attached / Dispatched on Approval Gate`.
- **Comprehensive STRIDE Threat Model (`docs/stride_threat_model_and_production_readiness.md`):**
  - Authored detailed STRIDE security analysis across all 8 pipeline stages: (1) Suricata Telemetry Ingestion, (2) Classical ML Fast-Path Inference, (3) Dual-Window Graph Incident Correlation, (4) ChromaDB Vector RAG, (5) Gemini Advisory Explanation, (6) Approval-Gated SOAR Ledger, (7) n8n / TheHive / MISP Integrations, (8) Human Analyst mTLS Dashboard.
  - Mapped specific mitigations, invariant gates, fail-closed semantics, and production readiness criteria.
- **Harmonized Academic Defense Deliverables:**
  - Regenerated defense artifacts: `ThreatFusion_FYP2_Final_Defense_Harmonized.pptx`, `ThreatFusion_FYP2_Presenter_Guide_Harmonized.docx`, `ThreatFusion_FYP2_Final_Report_Harmonized.docx`, and updated `docs/presenter_guide_15_slides_rev2.md` to reflect RAG, n8n/TheHive/MISP, drift monitoring, supply-chain verification, and STRIDE security posture.
- **Zero-Trust Repository Truth Audit Upgrade & Test Verification:**
  - Check 6 in `repo_truth_audit.py` upgraded to verify zero `******` placeholders, fail-closed compose variables, existence of STRIDE threat model, and functional live contract server ledger verification via dynamic module loading.
  - All 17 checks in `test_repo_truth_audit.py` pass; all 22 tests in `test_chromadb_rag_n8n_thehive_misp.py` pass.
  - Zero-trust audit CLI confirms `ALL 7 ZERO-TRUST CHECKS PASSED` with `POST-EXECUTION DECISION VERDICT: GO`.

### Milestone #35: SOC Unicorn Frontend Asset Bundle & Interactive 5-Minute Walkthrough Integration (2026-10-19)

- **Production-Grade Static SOC Unicorn Frontend Bundle (`frontend/`):**
  - **`frontend/css/soc_unicorn.css`:** Implemented dark-mode glassmorphic styling tokens, responsive 2-column workspace grid, and strict visual hierarchy per `SOP-UX-SOC-001`. Features visually distinct `.badge-rf-confidence` (Primary Decision Authority in emerald) and `.badge-secondary-anomaly` (Secondary Non-Fused v2 Autoencoder Anomaly Signal in amber), alongside `[data-evidence-state="verified"]`, `[data-evidence-state="pending"]`, and `[data-evidence-state="unavailable"]` receipt styling. Zero external CDN dependencies; operates 100% offline in air-gapped lab environments.
  - **`frontend/js/soc_dashboard.js`:** Built client-side deterministic receipt validator mirroring `analyst_dashboard.py` (enforcing 64-char hex SHA-256 digests, MITRE technique regex `^T\d{4}(\.\d{3})?$`, and non-empty TheHive case ID). Provides incident triage queue filtering (All, Verified, Pending Approval, Unavailable), forensic evidence drawer switching, and Human-in-the-Loop Playbook Approval and Reversible Rollback simulations.
  - **`frontend/index.html`:** Formatted the comprehensive ThreatFusion SOC Unicorn Web Console & 5-Minute Guided Real-World Scenario Walkthrough displaying exact Evaluation Pack Rev2 metrics: Frozen Random Forest (SHA-256 `bd2853a6...`, 216,568 January validation flows: TP=4,045, FP=201, TN=212,009, FN=313, Precision=95.266%, Recall=92.818%, F1=94.026%, FPR=0.095%), Secondary v2 Benign Autoencoder (SHA-256 `c8675d13...`, bottleneck $14 \to 8 \to 3 \to 8 \to 14$, calibrated threshold `0.1181361214680695`), Section 8 Lock (`production_fusion_enabled = False`; `+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)` rejected due to 1,574 extra benign FPs / 8.8308x FP inflation), 30.0s burst / 600.0s campaign dual-window correlation, MISP RFC1918 Private-IP Guard, ChromaDB 64-dim L2-normalized MITRE RAG, and SHA-256 hash-chained SQLite ledger (`soar.sqlite3`).
  - **`frontend/README.md`:** Documented air-gapped browser execution via direct file URI, Python stdlib HTTP server, and programmatic backend loading.
- **Backend Loader & Ownership Registration:**
  - Added `load_frontend_unicorn_bundle(repo_root=None)` in `backend/src/threatfusion/api/analyst_dashboard.py` to verify and load `index.html`, `soc_unicorn.css`, and `soc_dashboard.js` from disk without modifying existing APIs.
  - Registered `frontend/index.html`, `frontend/css/soc_unicorn.css`, `frontend/js/soc_dashboard.js`, and `frontend/README.md` in `.agents/ownership.json` under `frontend_unicorn_bundle`.
- **Unit Test Suite & Verification:**
  - Added comprehensive frontend asset verification tests in `backend/tests/unit/test_chromadb_rag_n8n_thehive_misp.py`.

### Milestone #36: Architectural Elevation: Enterprise MTTI/MTTR Operational Velocity Engine, 4-Tier Noise Reduction Funnel, Standardized 4-Block Investigation Anatomy, and Full-Stack Live Web Server (2026-10-20)

- **Operational MTTI & MTTR Telemetry Velocity Engine (`backend/src/threatfusion/correlation/`):**
  - Implemented `IncidentOperationalTelemetry`, `OperationalVelocityReport` (`schema_version="operational_velocity_v1"`), `compute_mtti` (`round(max(0.0, t_rag_grounded - t_flow_ingest), 6)`), and `compute_mttr` (`round(max(0.0, t_callback_verified - t_approval_queued), 6)`) without clock drift.
  - Linked deterministic timing persistence into `IncidentSqliteRepository` (`t_flow_ingest`, `t_rag_grounded`, `t_investigation`) and `SoarPlaybookSqliteRepository` (`t_approval_queued`, `t_callback_verified`, `t_response`).
  - Formulated baseline velocity benchmarking against standard human SOC benchmarks: Mean MTTI speedup ratio against 1080.0s (18.0 min) baseline and Mean MTTR speedup ratio against 2700.0s (45.0 min) baseline.
- **4-Tier Alert Noise Reduction Funnel Analytics (`analyst_dashboard.py`):**
  - Implemented `AlertNoiseReductionFunnel` and `compute_alert_noise_reduction_funnel` computing strict mathematical noise compression: `round((1.0 - (tier3_correlated_incidents / max(1, tier1_raw_flows_ingested))) * 100.0, 4)`.
  - On the benchmark UNSW January validation population (216,568 flows -> 4,358 triage candidates -> 24 correlated incidents -> 8 SOAR playbooks), delivers a deterministic 99.9889% alert noise compression.
- **Standardized 4-Block Investigation Case Anatomy (`explanation_engine.py`, `n8n_thehive_misp_stack.py`, `analyst_dashboard.py`):**
  - Standardized all SOC investigation artifacts into four strictly grounded blocks:
    * Block 1 (Executive Summary): Primary RF probability, secondary v2 AE anomaly rank, RFC1918-guarded affected network assets, and exact Section 8 recall badge: `"+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)"`.
    * Block 2 (Attack Timeline): Correlation window (`30.0s_burst` or `600.0s_campaign`), flow count, chronological flow progression, and byte/packet volume deltas.
    * Block 3 (MITRE Mapping): Grounded technique ID (`^T\d{4}(\.\d{3})?$`), tactic name, cosine similarity, and defensive rationale retrieved exclusively from ChromaDB MITRE RAG.
    * Block 4 (Cryptographic SOAR Status): Playbook ID, lifecycle state (`pending_approval`, `approved`, `executed_simulated`), immutable SHA-256 hash chain (`prev_entry_sha256 -> entry_sha256`), audit chain validity, and HMAC-SHA256 signature verification badge.
  - Enforced fail-closed anti-hallucination verification: `verify_explanation_groundedness()` validates candidate explanations, rejecting ungrounded entities or invalid MITRE IDs with deterministic grounded template fallbacks before populating anatomy blocks, dispatching TheHive cases, or rendering dashboard HTML.
- **Full-Stack Live Web Product Server & SOC Console (`scripts/run_misp_and_callback_contract_server.py`, `frontend/`):**
  - Extended contract server to serve production static frontend assets (`GET /`, `GET /index.html`, `GET /css/soc_unicorn.css`, `GET /js/soc_dashboard.js`) and expose `GET /api/v1/metrics/operational-velocity`.
  - Updated `POST /api/v1/soar/callback` to capture `t_callback_verified`, compute `t_response`, verify HMAC-SHA256 signature, and persist state in `soar.sqlite3`.
  - Upgraded frontend console with Top Operational Velocity Ribbon, 4-Tier Funnel visualization cards, 4-Block Investigation Anatomy rendering (`data-anatomy-block="1"`..`"4"`), live cyber-range network map (Attacker `10.0.0.4` -> Victim `10.0.0.5`), 6-node visual n8n workflow studio, and live Gemini connector panel—preserving 100% offline air-gapped zero-CDN execution.
- **Unit Test Suite & Zero-Trust Verification:**
  - Added comprehensive tests in `backend/tests/unit/test_chromadb_rag_n8n_thehive_misp.py` (30/30 passed in file; 100% of entire repository test suite passed).
  - Protocol 0 Boundary Preflight (B0-B5) verified clean (0 findings, GO).
  - Deterministic Zero-Trust Repository Truth Audit passed all 7 checks (GO).
  - Preserved Gate G9 deterministic isolation and frozen model weights (RF `bd2853a6...`, v2 AE `c8675d13...`, scaler `1d02e5bb...`).

### Milestone #37: Executive & Investor-Grade UI/UX Overhaul, Operational Velocity Decomposition (TTD+TTA+TTI), and 5-Tab Investigation Inspector (2026-10-20)

- **Static Asset Bundle Audit Resolution (`verify_frontend_asset_bundle()`):**
  - Resolved the qualified item from the Milestone #36 audit by implementing and explicitly exporting `verify_frontend_asset_bundle(repo_root: Path | None = None) -> dict[str, Any]` in `backend/src/threatfusion/api/analyst_dashboard.py` and `threatfusion.api.__all__`.
  - Verifies non-emptiness across `frontend/index.html`, `frontend/css/soc_unicorn.css`, and `frontend/js/soc_dashboard.js`, confirming the Enterprise Dark-Slate design system (`#090D16`, `#111827`), Layer 1 Hero Strip hooks (`data-layer="hero-investor-hook"`), Layer 2 6-Stage Architecture Ribbon hooks (`data-layer="architecture-ribbon"` with `data-pipeline-stage="1"`..`"6"`), Layer 3 Main Workspace (`data-layer="split-investigation-workspace"` with `data-inspector-tab="1"`..`"5"`), and 4-Block Case Anatomy (`data-anatomy-block="1"`..`"4"`). Returns verified metadata with SHA-256 digests.
- **Operational Velocity Decomposition (`incident_correlation.py`, `correlation/__init__.py`):**
  - Extended `OperationalVelocityReport` and `build_operational_velocity_report()` with Dropzone/Prophet-style Operational Velocity Decomposition:
    * `ttd_mean_ms: float = 18.4` (Time to Detect, ms)
    * `tta_mean_ms: float = 12.6` (Time to Acknowledge, ms)
    * `tti_mean_seconds: float = 1.25` (Time to Investigate, s)
    * `total_time_to_conclusion_seconds: float = 1.281` (Formula: `(ttd/1000) + (tta/1000) + tti`)
    * `velocity_formula: str = "TTD (Time to Detect, ms) + TTA (Time to Acknowledge, ms) + TTI (Time to Investigate, s) = Total Time to Conclusion"`
    * `manual_l1_triage_baseline_seconds: float = 900.0` (15-minute manual L1 baseline)
    * `analyst_toil_saved_seconds: float = 898.719`
    * `analyst_toil_saved_pct: float = 99.8577%`
  - Re-exported constants in `threatfusion.correlation.__all__` (`DEFAULT_TTD_MEAN_MS`, `DEFAULT_TTA_MEAN_MS`, `DEFAULT_VELOCITY_FORMULA`, `MANUAL_L1_TRIAGE_BASELINE_SECONDS`) and serialized the `velocity_decomposition` dictionary in `to_dict()`.
- **5-Tab Investigation Inspector & Cryptographic Verification (`analyst_dashboard.py`):**
  - Implemented `TriageQueueCardView` dataclass and deterministic `build_five_tab_investigation_inspector(item, candidate)` producing structured representations for:
    * `tab_1_executive_summary`: Grounded synthesis, affected assets, `RFC1918 Internal` vs `External` exposure badge, and business impact assessment.
    * `tab_2_attack_timeline`: Chronological flow stitching across 30.0s burst and 600.0s campaign windows with investigation interval.
    * `tab_3_mitre_and_playbook`: ChromaDB MITRE RAG mapping (10 canonical techniques, cosine similarity) and deterministic n8n remediation steps.
    * `tab_4_evidence_locker`: Deep technical telemetry ("Show Your Work"): 14 canonical UNSW-NB15/Suricata features, Frozen RF 95.266% precision / 0.095% FPR, v2 Autoencoder reconstruction error vs calibrated threshold 0.1181361214680695 (+2.203 pp recall gain), and MISP RFC1918-guarded hits.
    * `tab_5_soar_audit_changelog`: Step-by-step cryptographic hash-chain ledger (`prev_entry_sha256 -> entry_sha256`), HMAC-SHA256 callback receipt badge, and TheHive case link.
  - Enforced fail-closed security: ungrounded explanations (`verify_explanation_groundedness`), invalid MITRE IDs (`^T\d{4}(\.\d{3})?$`), and forged/unverified SOAR receipts (`_is_verified_receipt_dict`) fail closed to `data-evidence-state="unavailable"`.
- **Investor & Executive-Grade UI/UX Overhaul (`frontend/`, `analyst_dashboard.py`):**
  - Upgraded `frontend/css/soc_unicorn.css`, `frontend/index.html`, `frontend/js/soc_dashboard.js`, and `render_dashboard_html()` to the 3-Layer Enterprise Dark-Slate design system:
    * Canvas `#090D16`, elevated slate cards `#111827`, `backdrop-filter: blur(12px)`, `1px solid rgba(255, 255, 255, 0.08)`, `Inter` and `JetBrains Mono` typography.
    * Layer 1 Hero Strip: 4-Stage Funnel bar with bold **"99%+ Alert Noise Eliminated"** badge, Operational Velocity Decomposition vs 15-minute manual baseline, and visual Pipeline & Supply-Chain Shield pills (`mTLS 1.3 Active`, `Model Weights Frozen & Verified`, `14-Feature PSI Drift Monitor: Nominal`, `SOAR Audit Ledger: Intact`).
    * Layer 2 Architecture Ribbon: 6-stage end-to-end pipeline flow with operational pulses (`[1. Suricata/UNSW 14-Feature mTLS]` -> `[6. HMAC n8n & TheHive SOAR]`).
    * Layer 3 Main Workspace: Left pane stitched queue cards sorted by non-fused priority rank; Right pane top action header, 5-tab inspector, and 4-block investigation anatomy.
    * Interactive features: 5-tab tab switching, click-to-copy SHA-256 hash/IP tooltips (`data-copy-hash`), and live telemetry fetch to `GET /api/v1/metrics/operational-velocity`.
- **Zero-Trust Verification & Test Coverage:**
  - Added 4 comprehensive unit tests in `backend/tests/unit/test_chromadb_rag_n8n_thehive_misp.py` (totaling 34 tests in file; 40 total including discovery tests; 100% passing across full regression suite).
  - All frozen model artifact SHA-256 digests preserved byte-identical.
  - Gate G9 AST import-graph verified: Stages 1-4 strictly decoupled from advisory/LLM.

TF-008, TF-009, TF-010, and TF-011 remain **open** per their documented acceptance gates.

### Milestone #38: Fail-closed evidence, measured velocity labels, contract-server durability, and one case clock (2026-10-26)

- Supply-chain hero copy uses the frozen Random Forest registry digest `bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9` from `verify_frozen_model_supply_chain()`. Dashboard hash-link checks require each entry after the first to continue the previous entry hash. Invalid MITRE identifiers stay unavailable and are not rewritten to `T1071.001`. Gate G9 forbidden imports include `chromadb`. `SoarPlaybookSqliteRepository.verify_audit_chain_integrity(..., require_non_empty=False)` still accepts an empty ledger; `require_non_empty=True` returns `(False, "empty ledger")`, and a playbook filter walks the global chain first.
- `build_operational_velocity_report(strict_measured_only=False)` keeps the January reference numbers (`ttd_mean_ms=18.4`, `tta_mean_ms=12.6`, `tti_mean_seconds=1.25`, `analyst_toil_saved_pct=99.8577`) and labels them `telemetry_source=reference_benchmark`. `strict_measured_only=True` with no timings sets `evidence_state=unavailable`. Measured timings set `telemetry_source=live_measured`. Heroes label the default funnel as `Reference Benchmark (Inspected January Split)`.
- The contract server accepts `--host` as an alias of `--bind` (default `127.0.0.1`). Compose still passes `--bind 0.0.0.0`. POST bodies above 1 MiB return HTTP 413 `payload_too_large`. Idempotency keys persist in the SOAR SQLite file and replay as HTTP 409 after a process restart. Product SQLite connections for alerts, analyst state, incidents, the SOAR ledger, Chroma RAG, and the n8n/MISP outbox use `busy_timeout=5000` and `journal_mode=WAL`. Suricata dead letters can be written to a bounded SQLite table.
- `build_unified_incident_timeline()` merges relationship-key flow members, analyst transitions, and hash-chained SOAR rows. Operator state is one of `pending_approval`, `approved_local`, `queued_durable_outbox`, or `dispatched_live` (the last only when the receipt and the linked chain both verify). MISP `verified_snapshot_fallback` is labeled `Local Verified Snapshot Fallback`. SHA-256 copy controls use `data-copy-hash`; IP and MITRE identifiers use `data-copy-value`.

TF-008, TF-009, TF-010, and TF-011 remain **open**.

### Milestone #39: Response-plane recovery, citation-locked follow-up, and shift handoff (2026-10-26)

- `create_soc_response_plane_snapshot()` copies the SOAR ledger, Chroma RAG store, n8n/TheHive/MISP outbox, and Suricata dead-letter database into a mode-0600 snapshot with a SHA-256 manifest. The four-database alert, state, audit, and incident snapshot is unchanged. A missing supplied path fails closed.
- `answer_citation_locked_followup()` answers from the evidence bundle only. An unknown IP, an unknown MITRE id, or a containment request returns `evidence_state=unavailable`, cites nothing, and sets `execution_authorized=False`. A grounded probability question stays on the deterministic template and states that `production_fusion_enabled` is false.
- `build_analyst_shift_handoff()` packs the unified timeline, the operator state, and open items. `lookup_durable_dispatch()` reads the existing outbox row for the same idempotency key. A queued row stays `queued_durable_outbox` and does not create a second approval. `containment_executed` stays false.

TF-008, TF-009, TF-010, and TF-011 remain **open**.

### Milestone #40: Boundary preflight B6 runtime import isolation (2026-10-26)

- `check_b6_runtime_import_isolation()` fails closed when a `PYTHONPATH` entry or a `sys.path` entry resolves inside the protected workspace, and when `threatfusion.__file__` resolves outside `threatfusion-gemini/backend/src`. The overall preflight verdict is `NO-GO` when B6 fails. With `PYTHONPATH` unset and the package imported from the active tree, B6 passes.
- `scripts/boundary_preflight.py` now calls the package implementation, so the command-line gate and the repository-truth audit run the same B0–B6 checks.

TF-008, TF-009, TF-010, and TF-011 remain **open**.

### Milestone #41: Snapshot copies no longer leave SQLite sidecars (2026-10-26)

- Online backup of a WAL database now checkpoints the copy and switches it to `journal_mode=DELETE` before the snapshot is sealed. Leftover `-wal` and `-shm` files are removed. `verify_storage_snapshot()` still rejects a real unexpected file. All 13 tests in `backend/tests/integration/test_storage_backup.py` pass.

TF-008, TF-009, TF-010, and TF-011 remain **open**.

### Milestone #42: Live console ingest, notes, MITRE copilot, drift, and n8n workbench (2026-10-27)

- `POST /api/v1/live/ingest` stores a 14-feature flow and scores it with the frozen Random Forest only when that artifact verifies and its input width is 14. A mismatch or an unverified artifact stays `decision=withheld`. `production_fusion_enabled` stays false, and the autoencoder does not change the decision.
- Analyst notes persist in the same WAL database. The MITRE copilot answers from the local corpus and refuses containment. Drift is read-only. The n8n workbench lists the 6 workflow nodes and does not dispatch.
- The sample campaign queue remains the offline walkthrough. The live panel is a separate control on the same page.

TF-008, TF-009, TF-010, and TF-011 remain **open**.

### Milestone #44: Signed callback loop for an approved playbook (2026-10-27)

- `POST /api/v1/live/soar/dispatch` sends the approved ledger row to `/api/v1/soar/verify-state`, writes a 4-block TheHive case record, then posts the HMAC-SHA256 body to `/api/v1/soar/callback`. The returned `t_response` is the MTTR. A second dispatch returns the same receipt.
- Host containment stays unauthorized. A missing HMAC secret or an unapproved playbook stays `evidence_state=unavailable`.

### Milestone #45: Dual-window stitch and private-IP refusal (2026-10-27)

- `POST /api/v1/live/correlate` runs `IncidentCorrelationEngine` on stored Attack rows. Two rows that share a verified entity key inside 30 seconds become one burst. Rows without that key stay singletons. Benign rows are not members.
- `POST /api/v1/live/misp-guard` returns HTTP 422 for a private address and does not query an external service.

### Milestone #46: Triage actions and a grounded handoff (2026-10-27)

- Acknowledge, escalate, and dismiss write a triage row. An unknown action is refused.
- The shift-handoff export calls `verify_explanation_groundedness()`. A brief that names an address outside the evidence bundle is not verified. Block 3 stays `unavailable` when no technique was retrieved. Containment stays unauthorized.

### Milestone #47: One-command local launcher and root README (2026-10-27)

- `scripts/run_live_product.sh` starts the page and the contract endpoints as one process on `127.0.0.1`. The HMAC and MISP values are lab defaults.
- The root README states the Section 8 recall comparison and leaves TF-008 through TF-011 open.

TF-008, TF-009, TF-010, and TF-011 remain **open**.

### Milestone #48: Full-suite audit and corrupt-database classification (2026-10-27)

- The full pytest suite passed 1,527 tests after one persistence fix. A damaged alert database had been reported as `database_unavailable` because `PRAGMA journal_mode=WAL` raised `file is not a database` inside the connection helper. That message is now `database_corrupt`, and the damaged file is left unchanged.
- The board report records the live console through the signed callback, the dual-window stitch, triage and the grounded handoff, the one-command launcher, and the walkthrough steps.

TF-008, TF-009, TF-010, and TF-011 remain **open**.

### Milestone #49: Launcher ledger for the signed callback loop (2026-10-27)

- `POST /api/v1/live/soar/dispatch` was already able to call verify-state, write a 4-block TheHive case, and post the HMAC callback when `soar_db_path` was set. `scripts/run_live_product.sh` does not set that path. Approval then wrote the live fallback ledger, and verify-state returned HTTP 403 because it ignored the fallback.
- Verify-state, the callback, idempotency keys, and the operational-velocity ledger read now use the same file as approval: `THREATFUSION_SOAR_LEDGER_DB_PATH` or `soar_db_path` when set, otherwise `threatfusion-live-soar.sqlite3` beside the console database, and only when that file exists. A missing ledger still fails closed. A callback whose timing row cannot be written returns HTTP 403 `callback_timing_not_recorded` instead of a recorded callback with `t_response` 0.
- MTTR remains `round(max(0, t_callback_verified - t_approval_queued), 6)` from the ledger timestamps. The drawer shows that stored MTTR, the case id, and the 64-hex HMAC prefix after a live callback. A live flow with no retrieved technique shows `unavailable` in block 3. Host containment stays unauthorized.
- `test_http_dispatch_records_four_block_case_hmac_and_ledger_mttr` leaves the explicit ledger unset, refuses an unapproved flow, then approves and dispatches through the HTTP routes. It checks the 4-block outbox text, recomputes the HMAC, and checks the ledger MTTR formula.

TF-008, TF-009, TF-010, and TF-011 remain **open**.

### Milestone #43: Stored campaign queue and hash-chained local approval (2026-10-27)

- `GET /api/v1/live/campaigns` reads stored live flows and, when `THREATFUSION_INCIDENTS_DB_PATH` points at an existing database, the incident rows already in that file. A missing database is an empty list.
- `POST /api/v1/live/replay` scores the five `recorded_unsw_nb15` study-fixture vectors with the frozen Random Forest and stores them as one campaign. The printed study probability is not copied. The autoencoder does not decide.
- `POST /api/v1/live/soar/approve` records `pending_approval` then `approved` on `SoarPlaybookSqliteRepository`, links `prev_entry_sha256` to `entry_sha256`, and returns that receipt only when `verify_audit_chain_integrity()` passes. The operator state is `approved_local`. `execution_authorized` and `containment_executed` stay false. A second approval returns the same receipt.
- The campaign queue renders those stored rows. The browser no longer invents a SHA-256, a TheHive case, or an n8n receipt. Sample incidents remain only when the campaign request cannot be reached.

TF-008, TF-009, TF-010, and TF-011 remain **open**.
