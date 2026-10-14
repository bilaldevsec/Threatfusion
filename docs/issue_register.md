# ThreatFusion prioritized remediation register

## Use and dispositions

This register tracks evidence-backed defects, blockers, uncertainties, and acceptance gaps. It is read
with the [`product charter`](product_charter.md) and [`current status`](project_status.md). Priority is
execution order: P0 before relying on the affected path, P1 before the relevant scientific/product
claim, and P2 as scoped follow-up. Severity is impact: critical can invalidate a central claim or block
the core demo; high blocks a material claim or lane; medium is bounded but unresolved.

Statuses are `open`, `investigating`, `resolved`, or `accepted limitation`. “Accepted limitation”
requires an explicit, dated owner decision and a documented claim boundary. No issue below is accepted
by default.

| ID | Priority / severity | Type and evidence | Affected scope | Next action | Closure test | Status |
|---|---|---|---|---|---|---|
| TF-016 | P0 / high | **Resolved 2026-09-15: autoencoder scientific-review corrections.** The historical v1 scorer used caller-batched float32 forwards and residuals against the float32-converted input, while the written formula implied the original float64 input. Canonical per-record v2 scoring corrects the batching defect without altering historical evidence. The reusable loader enforces trusted identity, complete bundle/runtime bindings, and exact source snapshots. One separately authorized corrected v2 baseline now supplies calibrated same-source development evidence under its distinct score and threshold identities. See [`network_autoencoder_protocol.md`](network_autoencoder_protocol.md#corrected-v2-execution-evidence-2026-09-15). | Autoencoder score meaning, repeatability, threshold reuse, bundle loading, future run provenance | Preserve both immutable runs and their distinct contracts. The historical threshold remains incompatible with v2. The verified v2 identity remains experimental and outside the product-approved registry; fusion and integration remain unauthorized. | Exact invariance and saved/reloaded decision checks pass across caller chunks. The v2 run fitted only 847,837 benign TRAIN rows, persisted its January-calibrated threshold before February, retained threshold counts and RF overlap, and passed complete bundle/provenance verification using independently calculated hashes. All 14 historical/frozen hashes remain unchanged. | resolved |
| TF-013 | P0 / high | **CORRECTION REQUIRED, corrected 2026-09-10: inference-boundary security/failure defects.** The adversarial review reproduced artifact hash/reopen TOCTOU, duck-typed provenance approval with untrusted output, malformed numeric/request exceptions, and unsanitized iterator failures. See [boundary security](unsw_network_inference_boundary.md#security-and-scientific-claim-boundary). | Frozen bundle loading, request validation, bounded batch accounting, sanitized failures | Preserve same-byte bounded loading, concrete input types, numeric range checks, and whole-batch iterator aborts. No fallback or model change. The adapter-binding gap identified in this review was handled separately in TF-014 below; remote source authenticity remains outside these component fixes. | Ten initially failing regression cases now pass; 113 focused tests and one full 430-test suite pass (four existing TF-005 warnings); Ruff and four individual Black checks pass. Nine frozen hashes remain unchanged/ignored. Core security tests run without ignored artifacts. | resolved |
| TF-014 | P0 / high | **Resolved after adversarial corrections, 2026-09-10: trusted UNSW adaptation binding.** The public raw-array path constructs source identity and immutable predictors internally. Review demonstrated two medium-severity defects: duration underflow/binary-label rounding reached prediction, and generic date parsing leaked submitted timestamps and internal paths through warnings while predicting. Exact preconversion checks and numeric UTC epoch parsing correct these failures. See [review evidence](unsw_network_inference_boundary.md#tf-014-adversarial-review-2026-09-10). | Supported UNSW raw application entry; no external API implemented | Preserve the corrected path. Define producer admission/authentication and bounded transport policy under TF-008/TF-009 before exposure. Physical source origin, valid positional swaps, blocking iterators and recovery remain unresolved; no limitation is marked accepted. | Six newly failing regressions pass after correction, with zero prediction calls and no timestamp warnings. All 69 binding cases and 251 focused tests pass; the complete suite ran once: 499 passed, four existing TF-005 warnings. Ruff and five bounded individual Black checks pass. All nine approved artifact hashes remain unchanged and files ignored/untracked. No supported public feature-vector attestation bypass was demonstrated; this disposition does not authenticate raw measurements or dataset membership. | resolved |
| TF-001 | P0 / critical | **Compatibility-enforcement defect.** The CIC path previously treated matching field shape/unit/formulas and `completed=true` as semantic approval despite the byte mismatch. See [`network_feature_comparability_audit.md`](network_feature_comparability_audit.md). The gate was validated by 74 focused tests and the completed 363-test suite; repository-wide Ruff also passes. | `network_behavior_v1` approval, CIC evaluator, historical report consumption | Preserve the typed fail-closed compatibility decision before transformation/inference, historical evidence, and same-source UNSW use. | Focused and full tests prove exact CIC rejection precedes transformation/artifacts; unknown/missing/mismatched evidence fails; UNSW is allowed; legacy completion remains readable without approval. | resolved |
| TF-012 | P0 / critical | **Underlying measurement mismatch.** Five byte-dependent predictors map UNSW/Argus transaction bytes to CICFlowMeter transport-payload bytes. The bounded same-PCAP study confirmed that the pinned extractors also differ in flow termination and ICMP support; it found an Argus UDT accounting defect that is excluded from comparison. The compatibility gate and UNSW-only inference boundary prevent approved cross-source use but do not make measurements compatible or improve accuracy. See the [comparability audit](network_feature_comparability_audit.md) and [inference boundary](unsw_network_inference_boundary.md). | Cross-source feature contract, future compatible evaluation/model evidence | Preserve source-specific product operation. Before adding any source, define and validate a reviewed common byte-layer and flow-termination contract, then preregister independent evaluation. | All five fields and flow membership have supported-equivalence evidence under pinned and historically applicable representations/settings, or every supported product path remains explicitly source-specific. New independent evaluation remains required. | open |
| TF-002 | P0 / high | **Scientific qualification gap.** CIC execution was pipeline-correct, but the current result depends on the incompatible/unverified mapping. CIC outcomes are already known. See the [evaluation protocol](network_classical_evaluation_protocol.md) and TF-012. | Reports, dashboard claims, presentations, comparisons | Propagate a concise compatibility qualification and development-exposure marker to every result surface before reuse. | No surface calls CIC a validated compatible external test; every displayed/exported result binds the qualification and exposure state without changing historical metrics. | open |
| TF-003 | P1 / high | **Unresolved comparability evidence.** Historical Argus/CICFlowMeter revisions, byte layer details, direction assignment, flow termination/timeouts, capture loss/retransmission treatment, and configuration are incompletely established. See the [comparability audit](network_feature_comparability_audit.md). | Directional counts/means, duration, rates, destination port, cross-source interpretation | Obtain authoritative historical configuration or run a separately approved, small, pre-registered same-PCAP parity study; do not launch a large extraction study automatically. | Version/configuration is bound and parity cases cover SYN-led/midstream, idle/FIN/RST, retransmission, header-only, zero-duration, TCP/UDP/ICMP behavior with explicit per-field dispositions. | open |
| TF-004 | P1 / critical | **Training blocker.** No representative benign host training corpus exists; `synthetic_lab` has 42 fixture events and Mordor is attack/test-only. See [`phase_0p_synthetic_training_readiness.md`](phase_0p_synthetic_training_readiness.md). | Host model lane, host scientific claims, global training readiness | Define and obtain explicit authorization for a representative benign-host evidence plan, then register and validate it without repurposing fixtures or attack data. | Manifest-backed corpus meets predeclared coverage/leakage/quality gates and has verified split assignments; an updated readiness report passes for the host lane. | open |
| TF-005 | P2 / medium | **Scoped warning, not yet a proven defect.** Existing pandas date-parsing warnings arise on fixture/Mordor ISO timestamps through the generic `dayfirst=True` path; UNSW epoch parsing is separate. See “Bounded exploratory check” in [`network_training_split_design.md`](network_training_split_design.md). | Generic timestamp parsing, Mordor/fixture diagnostics | Trace the exact warning path with focused fixtures and decide whether explicit format parsing or a documented warning policy is warranted. | Focused tests establish unchanged expected timestamps and either eliminate the warning through evidence-based parsing or document why it is harmless and bounded. | open |
| TF-006 | P1 / high | **Known limitation/evidence gap.** Exact feature collisions and conflicting labels exist; near-duplicate leakage and capture/session provenance remain unresolved. See the [split design](network_training_split_design.md) and [February protocol](network_classical_evaluation_protocol.md). | UNSW validation/test interpretation and all model generalization claims | Specify bounded, label-independent provenance and near-duplicate diagnostics before further model comparison; do not tune a threshold using known test outcomes. | Predeclared diagnostics quantify cross-split capture/group and near-duplicate risk, demonstrate no prohibited leakage under a reviewed rule, or retain an explicit unresolved limitation. | open |
| TF-007 | P1 / high | **Evaluation exposure.** February UNSW and CIC outcomes are known and can influence future decisions. See [`network_classical_evaluation_protocol.md`](network_classical_evaluation_protocol.md). | Future features, models, thresholds, claims of independent evaluation | Record exposure in every future experiment and reserve a genuinely uninspected, independently verified evaluation source before development informed by these outcomes. | Future experiment protocol is frozen before access and proves source/label integrity, semantic compatibility, non-overlap, and no prior outcome inspection. | open |
| TF-008 | P0 / critical | **Demo/acceptance gap; one registered UNSW input now reaches a persisted RF Attack alert and the read-only browser queue/detail through automated real TLS.** The [one-input path](registered_browser_path.md) reuses the bounded [producer protocol](producer_admission_transport_policy.md), [analyst-state contract](alert_correlation_analyst_state.md), and separate [human browser boundary](analyst_authentication_transport.md); candidate ID, decision, and `new` state reconcile across them. An injected view failure displays sanitized 503. Retained alerts have no defensible distinct-alert relationship key. A bounded factual explanation now displays retained frozen-RF decision evidence with unavailable attribution/causality/source details. A user-reported Firefox session verified mTLS queue, linked detail and factual explanation; the earlier failed 390×844 scaling check remains historical, and newer owner screenshots show readable desktop and 390×844 layouts, usable queue link and horizontal access to score/decision/state, and legible detail IDs and explanation without overlap. Local public-certificate enrollment, restart-based disable/revoke, and append-only operator action journaling are implemented; CA issuance, secure browser delivery and full charter acceptance remain absent; Azure remains disabled. | Core product, demo readiness, usefulness claims | Review the local credential slice, define secure browser delivery and capture cleanup evidence for a bounded run; retain the separate relationship-key requirement before proposing correlation. | One authenticated supported input reaches the dashboard with reconciled identity/status; authentication/admission failures have zero predictor/repository calls; failures are visible; optional services can be off; replay/duplicates are idempotent; bounded resource evidence is recorded. | open |
| TF-009 | P1 / high | **Reliability evidence gap; bounded serving cleanup/restart and analyst-state transaction/reopen behavior implemented through 2026-09-23.** Serving regressions cover startup/readiness, graceful drain, overlap, replay, worker failure/timeout and resource cleanup. Analyst-state regressions cover atomic state/history writes, exact replay, concurrent version conflicts, rollback and schema-checked restart persistence. Coordinated cross-database snapshot backup, verification, and atomic restore are implemented (2026-10-14). This does not establish endurance, frozen operational limits, service-manager/signal behavior, audit export/retention/rotation, or optional-service outages. | Core workflow, demo reliability, deployment claims | Preserve terminating isolation and atomic state history; add the remaining operational resource, service-entry, backup/recovery and degradation evidence under separately bounded milestones. | The charter's malformed/partial-input, mismatch, offline-service, restart/replay, idempotency, interruption, timeout, concurrency/rate/body/queue, database backup/recovery and measured-resource cases pass end to end. | open |
| TF-010 | P1 / high | **Requirements traceability gap.** No repository source enumerates the exact jury-approved dataset and base-model families. Existing logistic regression and Random Forest must be preserved, but completeness/jury approval is unverified. | Scope control, jury compliance, roadmap | Add or reference the dated authoritative jury brief/rubric and reconcile it with the charter without rewriting history. | A reviewed repository reference lists exact required datasets/families; UNSW and all listed families have dispositions and no silent substitutions. | open |
| TF-011 | P1 / high | **User-value evidence gap.** Target operator, baseline workflow, task success criteria, and operational false-positive/detection targets are not validated. See [charter user-value evidence](product_charter.md#f-user-value-evidence). | Product usefulness, demo narrative, acceptance targets | Confirm the target operator and design a separately authorized reviewer/user study plus product-owner target-setting decision. Do not contact participants under this issue alone. | Dated decisions define operator/environment and operational targets; approved study evidence compares the same tasks with/without ThreatFusion and reports limitations. | open |
| TF-015 | P1 / high | **Resolved 2026-09-14: autoencoder implementation prerequisite.** The project declares and locks `torch==2.10.0+cpu` to the explicit official PyTorch CPU index. The CPython 3.11 manylinux x86_64 wheel hash and exact runtime are recorded in [`network_autoencoder_protocol.md`](network_autoencoder_protocol.md). | Benign-only UNSW autoencoder implementation, serialization and reproducibility | Preserve the package-specific explicit CPU index, exact lock, CPU-only execution, dependency identity checks, and safe state-dictionary load. Any upgrade or accelerator change requires a new compatibility/reproducibility review. | Project `.venv` import reports `2.10.0+cpu`, CUDA build/availability are absent, CPU tensor and finite forward/backward checks pass, deterministic algorithms are enabled, and state-dictionary `weights_only` CPU reload is verified. NumPy/scikit-learn/pandas/Pydantic remain at their frozen versions; torchvision/torchaudio are absent. | resolved |

### TF-008 / TF-009 human authentication follow-up, 2026-09-24

Independent review reproduced a high-severity shutdown/admission race and a medium-severity
segmentation-dependent trailing-body acceptance defect. Both are corrected with originally failing
regressions, real TLS no-mutation checks, lifecycle synchronization and exact bounded body reads.
The 128-test affected analyst/producer transport/repository slice passes in this review. Revocation
requires closing and joining the old listener worker and constructing a replacement listener with
the updated registry; a file edit or reopening the same object does not revoke a credential.
OpenSSL purpose validation does not independently require an explicit EKU extension, so credential
issuance policy and dedicated CA provisioning remain trusted operator responsibilities. These are
documented open operational requirements, not accepted limitations or completed product gates.

Both remain **open**. A separate terminating loopback TLS 1.3 listener now verifies a human client
certificate on the actual connection against a dedicated human CA, then enforces exact DER
fingerprint, URI SAN, validity, revocation and enabled allowlist before issuing the existing
server-owned viewer/analyst capability. Bounded list/detail and transition routes retain the
internal view-model schema and frozen state/idempotency contract. Real-loopback tests use distinct
human, revoked, unknown and producer credentials and exercise authorization and denial. See
[`analyst_authentication_transport.md`](analyst_authentication_transport.md). This closes the
specific missing human identity binding from the internal-view checkpoint. It does not meet either
issue's complete acceptance criteria: no browser/dashboard path, explanation, end-to-end display,
operational credential provisioning, audit/backup/recovery, service lifecycle or endurance proof.

### TF-008 / TF-009 analyst boundary disposition, 2026-09-24

Both issues remain **open**. The internal `analyst_alert_view_v1` formatter prepares bounded,
candidate-ordered list/detail and state-transition responses with capability checks and sanitized
errors. Inspection found no trustworthy network path from a user credential to a server-owned analyst
identity: the existing mTLS registry admits producer replay only, and the analyst registry's
`issue_for_trusted_actor` method assumes authentication was already completed. A producer certificate,
request header, body actor ID or claimed role cannot grant viewer/analyst access. The network endpoint
and real analyst transport test are blocked until an independent user-authentication and identity
mapping contract is implemented and verified. No dashboard, correlation, recovery/endurance or
end-to-end acceptance criterion was completed.

### TF-008 / TF-009 scoped closure follow-up, 2026-09-14

The bounded closure review qualified the six-findings-closed statement above: finding 3 still lacked
request-bound failure auditing when a replay claim committed and then failed before returning. The
claim-error path now uses the existing nonrecursive `_raise_ambiguous` helper with the validated record
and session. Two new real-temporary-SQLite regressions failed before this correction with zero audit
attempts and pass afterward. A healthy sink persists the allowlisted, request-bound `internal_failure`
event; a failing sink is attempted exactly once while preserving sanitized `replay_claim_ambiguous`,
fatal state, unresolved `in_progress` replay, no response or downstream effects, and connection/lease
cleanup. Ordinary replay conflicts and retries retain their prior behavior. Finding 3 is now corrected;
the other five findings and replay ordering were not reopened for review.

The 422-focused/852-full counts above describe the preceding milestone. This correction passes the
156-test orchestrator/replay/audit slice and one post-stabilization full suite: 854 passed, four existing
TF-005 warnings, no skips. Repository Ruff, nine individual bounded Black checks, and whitespace checks
pass; all nine frozen hashes are unchanged and temporary test resources are removed. TF-008 and TF-009
remain **open** for their existing operational and product acceptance requirements. No limitation is
accepted or charter requirement waived by this correction.

### TF-008 / TF-009 bounded FYP demonstration, 2026-09-19

The local evaluator runner reuses the synchronous one-request orchestrator and real IPv4-loopback TLS
1.3/mTLS transport with ephemeral credentials and isolated SQLite repositories. Two deliberately
selected registered UNSW records exercise the real frozen Random Forest, one Normal disposition and one
Attack-only candidate insertion. An exact completed retry returns byte-identical cached response bytes
with unchanged inference, insertion and alert counts. A separate authenticated invalid request is
rejected before prediction and persistence. A research-only section verifies and scores the same two
compatible records with the corrected v2 autoencoder while keeping it outside the product registry,
producer workflow and fusion. The runner saves an ignored sanitized report and cleans its listener,
threads, leases, credentials and databases. See [`fyp_progress_demo.md`](fyp_progress_demo.md).

This is repeatable recorded-data demonstration evidence, not live ingestion, accuracy evidence, a
long-running service, worker isolation, dashboard acceptance, backup/recovery, or operational readiness.
TF-008 and TF-009 therefore remain **open** with their existing closure tests unchanged.

### Offline evidence-viewer follow-up, 2026-09-20

The ignored self-contained FYP evidence viewer presents retained sanitized demonstration and aggregate
research evidence offline; it does not add a dashboard API/view model, serving worker, live source,
correlation, explanation, backup/recovery, or operational measurement. It therefore does not change
the **open** dispositions or closure criteria for TF-008/TF-009. Its required-evidence verification is
presentation integrity only, not product acceptance evidence.

Two final complete rehearsals passed with byte-identical sanitized evidence; the timed run took 31.50
seconds. Six focused demo contract/cleanup tests, repository Ruff, bounded Black,
whitespace/final-newline and all 23 relevant immutable-artifact hash checks pass. The full backend suite
was not repeated because the implementation is isolated to a new script, new focused tests and
documentation; no production Python or existing shared component changed. The checkpoint review also
verified nonzero sanitized CLI failure and corrected service/listener cleanup for setup and client-side
exchange failures.

### TF-016 January residual-contribution follow-up, 2026-09-19

The preregistered January-only audit is complete without changing TF-016's resolved disposition. The
first attempt completed scoring/aggregation and reached publication, but the publication field-name
defect lost the in-memory aggregates; no result from that attempt is retained. After explicit owner
authorization, exactly one additional January pass retained verified aggregate JSON, CSV, an SVG chart,
and an ignored aggregate-only recovery file. The report reproduces all frozen January confusion and
overlap counts and reconciles every residual sum to the v2 score exactly. Its cohort attribution is
descriptive, calibration-informed development evidence only. No TRAIN, February, CIC, training,
fitting, calibration, threshold/model, fusion, dependency, or demo work occurred. TF-006 and TF-007
remain open and no limitation or product approval is inferred from this audit.

The bounded completion review confirmed row-order alignment and exact v2 residual arithmetic and found
one recovery-integrity defect: structural checks alone did not bind recovered numeric aggregates to the
verified in-memory result. Recovery now includes a canonical aggregate SHA-256 and revalidates the
frozen contract and reconciliation evidence before publication; valid recovery is selected before any
scoring inputs can be opened. CLI failure regressions verify nonzero sanitized failure. The percentages
are explicitly pooled squared-residual fractions, not record fractions. Large mean/median gaps show
strong skew in the flagged cohorts, but the retained aggregates cannot quantify which or how many rows
dominate each feature, describe typical per-record group shares, create a decision rule, or select a
specific model experiment. This does not change TF-016's resolved status or close TF-006/TF-007.

### TF-016 final record-concentration diagnostic, 2026-09-19

One frozen January-only follow-up pass completed without retry and retained aggregate-only per-record
group-share quantiles, explicit dominance/tie/zero counts, score and group-error quantiles, and
ceiling-rounded top-1%/5%/10% concentrations for all four cohorts. It preserves exact v2 scoring,
RF/AE row alignment, frozen overlap counts, trusted loaders, and recovery-before-publication. Rates are
widespread among AE-only attacks (unique dominant in 85/96; median share 94.26%) but concentrated in a
minority of AE-only benign false positives (dominant in 274/1,574; median share 0.42%; top 10% supply
95.68% of rate error). This supports Decision A only as a development hypothesis: one future fixed
`log1p` transform of the two raw rate features before TRAIN-only z-scoring, with the baseline and all
other controls preserved. No experiment was executed. TF-016 remains resolved; TF-006 and TF-007 remain
open, and no causal, independent-validation, fusion, product, or operational claim is added.

### TF-016 two-rate log1p experiment disposition, 2026-09-19

The one authorized January-only experiment tested the single preregistered `log1p` intervention on the
two raw-derived rate features. A Landlock allowlist denied raw UNSW, February matrix/label, and CIC paths
to the experiment process. Preprocessing statistics used all 865,480 TRAIN rows, weights used only
847,837 benign TRAIN rows, and all baseline architecture, optimizer, seed, epoch, scoring, calibration,
and RF controls were preserved. Candidate TP/FP/TN/FN were 945/2,122/210,088/3,413; AE-only A/B were
59/2,080. All four preregistered gates failed, including ratio 0.0283654, and both overall recall and
both-detected attacks deteriorated materially. The candidate is retained as ignored development
evidence with disposition **FAIL — preserve baseline**. This does not reopen or close TF-016 and does
not change the open TF-006/TF-007 limitations.

#### Completion-review correction, 2026-09-20

The numerical rate-log1p result is preserved but is not protocol-valid. Its preparation path adapted all
registered rows and recorded 1,452,844 TEST rows seen before discarding their outputs; Landlock covered
only the later fit process. Required preparation deadline/RSS and pre-fit artifact-budget enforcement
were also absent, execution RSS was checked only afterward, and generic CLI failure codes were not
strictly allowlisted. The superseding disposition is **BLOCKED — preserve baseline**. No retry is
authorized. February access does not by itself prove TEST rows entered optimizer batches; retained fit
accounting still reports only the 847,837 benign TRAIN rows per epoch. The historical CLI rejects new
preparation and execution, while original snapshots and reports remain immutable. TF-016 remains
resolved for its earlier scorer correction, and TF-006/TF-007 remain open.

### TF-008 / TF-009 structured analyst security audit milestone, 2026-09-25

The structured analyst security audit (`analyst_security_audit_sqlite_v1`) was implemented and integrated into the `AnalystTlsListener`. State mutations (`states.sqlite3`) and security audit records (`audit.sqlite3`) operate under two independent SQLite transaction boundaries without distributed transactions. Authenticated request admissions, authorization failures, and transitions are recorded with pre-commit safety: an audit write failure before state mutation aborts the request with 503. A post-commit audit write failure returns 503 unavailable; a subsequent same-UUIDv4 retry prevents state duplication via idempotent replay (`existing`), but the initial request's missing completion audit event is not retroactively created, leaving an audit gap for the initial failed write. Authentication-rejection audit logging is best-effort and returns 401 without leaking internal storage failures. Valid TLS connections that close or time out before sending HTTP request bytes do not emit false audit events. Audit routes record fixed recognized templates or omit the route, preventing unvalidated URL paths from entering audit storage.

Both TF-008 and TF-009 remain **open** pending remaining operational and product requirements (browser/dashboard path, explanation, operational credential provisioning, backup/recovery, service lifecycle, and endurance proofs).

### TF-008 read-only analyst dashboard slice milestone, 2026-09-26

The authenticated read-only analyst dashboard slice (`threatfusion.api.analyst_dashboard`) was implemented and validated with integration tests (`test_analyst_dashboard.py`). A human analyst with verified mTLS credentials can query the real persisted triage queue and individual alert detail without state mutation. Tests prove:
- Authenticated viewer read-only access to alert list and detail with complete detection evidence (model score, threshold, decision).
- Invariance of analyst state during dashboard viewing (zero state version increments or transitions).
- Rejection of unauthenticated, revoked, or unknown credentials without data leakage.
- Clean distinction between empty triage queue and unavailable backend states.
- Reconciled identity and model decision attributes across extraction, persistence, and dashboard representation.

At the time of this dashboard-client slice, direct browser-to-listener access was absent. The separate read-only browser boundary below now serves HTML; operational client-certificate provisioning, future write authentication/CSRF design, explanation, and endurance validation remain open under TF-008 and TF-009.

### TF-008 browser-facing read-only analyst boundary, 2026-09-26

A distinct browser-facing listener (`AnalystBrowserTlsListener`) was implemented, exposing the read-only analyst queue and alert detail view via an actual local HTTPS endpoint. This boundary serves HTML to a browser while maintaining the strict per-human identity rules of the transport contract:
- The server demands a client certificate during the TLS 1.3 handshake and derives the user's actor identity strictly from the verified certificate SAN and the internal `HumanCredentialRegistry`. Browser HTTP headers (e.g. User-Agent) are ignored for authorization.
- The browser boundary directly executes `AnalystAlertViewModel` list and detail lookups without state mutation or session cookies, reusing the structured `AnalystSecurityAuditRepository` for admission and authentication events.
- Response boundaries preserve safety properties: invalid paths return 404, authorization/revocation failures return 401 without leakage, and valid responses include `Cache-Control: no-store` and strict Content-Security-Policy headers.
- The repair review verified shutdown of incomplete TLS requests, accurate failure and second-check authorization audit events, a 131,072-byte UTF-8 HTML body limit with sanitized 503 on overflow, and selectable full-ID queue links. Segmented real-TLS deadline and certificate-rejection regressions cover these boundaries. The final browser, analyst-listener, dashboard, and audit run passed 179 tests; affected-file Ruff, Black, and `git diff HEAD --check` passed.

This milestone is strictly read-only. Future write authentication and CSRF protection need an explicit design. TF-008 and TF-009 remain **open** pending transition safety, explanation, operational credential provisioning, backup/recovery, service lifecycle, and endurance proofs.

### TF-008 one registered input to browser display, 2026-09-26

The [bounded local runner](registered_browser_path.md) sent only registered UNSW-NB15 member
`7d851bbe…b55eb511` row 21 through the existing producer TLS/orchestrator and frozen RF worker.
Its HTTP 200 `created` Attack response identified candidate
`alert_candidate_v1:4c785c6418ff70c92a635785f5954355b6222f324d1314565b624affe771a8f7`.
A reopened alert SQLite repository, analyst view, and two authenticated browser TLS requests agreed
on that ID, decision `Attack`, and state `new` version 0. Queue and detail returned 200. A deliberately
injected view failure returned a visible sanitized 503 and `internal_failure` audit event without
changing the alert or analyst state. The standalone invocation completed; 198 focused tests passed,
with affected-file Ruff, Black, and `git diff HEAD --check` passing. The browser was exercised by an
automated TLS client; no human browser demonstration was performed. TF-008 and TF-009 remain **open**
for explanation, operational credential provisioning, full product acceptance and reliability gates.


### TF-008 / TF-009 bounded manual-browser launcher, 2026-09-27

The [manual runbook](registered_browser_path.md#bounded-manual-inspection-launcher-2026-09-27)
now provides a controlled inspection window on the existing registered-row producer,
frozen RF, persistence, factual explanation and read-only human-mTLS browser path.
A disposable Firefox profile and separate temporary human credentials keep trust local
to that profile. Expiry, SIGINT/SIGTERM and launch failure unwind listener/process/runtime
cleanup. Automated tests use real TLS with an inert browser-process substitute; a real
Firefox/Snap profile/import/navigation/shutdown observation is still required. This is
not operational credential provisioning or daemon/endurance evidence. TF-008 and TF-009
remain **open**; no manual browser pass or accepted limitation is recorded.

### TF-008 / TF-009 failed manual trial and bounded handshake repair, 2026-09-27

The user reported correct profile/CA/viewer setup followed by Firefox timeout at
localhost:46087 during a 1800-second demo. Manual acceptance remains **failed/pending**.
A delayed real-TLS certificate-flight test reproduced closure at the inherited
3-second handshake deadline; an immediate control with identical browser-style
headers passed. The original trial has no retained timing/trace, so that historical
cause is not asserted as proven. The browser-only handshake budget is now fixed at
60 seconds, with expiry/no-dispatch and close interruption regressions. HTTP and
analyst API deadlines and mTLS verification are unchanged. TF-008 and TF-009 remain
**open**. Review this repair before another manual trial; see the runbook evidence.

### TF-008 / TF-009 user-observed Firefox path and detail-layout follow-up, 2026-09-27

The user reported that the next real Firefox run on localhost:33991 succeeded:
viewer mTLS showed one Attack alert in `new`, its queue link opened the full
candidate detail, and factual explanation was available with stated limitations.
Ctrl+C produced `{"status":"stopped","manual_result":"pending_user_observations"}`;
that fixed message describes launcher shutdown and does not override the user's
observations. Read-only checks found no listener on 33991 and no reported temporary
Firefox profile. A screenshot also showed Candidate ID, Source Event ID and Created At
text overlapping in the detail panel. The renderer now wraps long field values and
allows its grid to shrink below 300px; a focused HTML/CSS contract test protects
full IDs and the queue link. At that checkpoint, the corrected layout still needed
a visual desktop and narrow-width recheck. This session does not establish full
charter acceptance, operational provisioning, distinct-alert correlation or endurance. TF-008 and
TF-009 remain **open**.

### TF-008 / TF-009 failed mobile viewport check, 2026-09-27

User-observed desktop Firefox evidence confirms the long-ID overlap is fixed and
queue/detail navigation still works. A reloaded 390×844 Responsive Design view
then scaled the seven-column desktop page down until queue/detail text was
unreadably small. Mobile acceptance was **failed at this checkpoint**, pending a
new screenshot; the later owner observation below supersedes that status. The
rendered HTML lacked a viewport meta declaration, and both data tables could
force a wide intrinsic page. The focused repair adds the device viewport and
scrollable, labeled, keyboard-focusable table regions; all columns, full IDs,
queue link and detail evidence remain in the document. Automated markup, TLS
and quality checks do not prove the final Firefox pixels. TF-008 and TF-009
remain **open**; product acceptance and operational reliability are unchanged.

### TF-008 / TF-009 superseding Firefox visual observation, 2026-09-27

The owner reports new Firefox screenshots showing readable desktop and 390×844
Responsive Design layouts after the viewport/table repair. The queue alert link
is visible and usable; horizontal scroll exposes score, decision and state;
full detail IDs and factual explanation are readable without overlap. The earlier
failed mobile scaling check remains historical evidence. Screenshots establish
only these visual observations, not accessibility, endurance or full product
acceptance. No final launcher output or latest runtime path was supplied, so
cleanup for this run remains unverified; the previous 33991 cleanup check does
not establish cleanup here. Operational browser credential provisioning and the
defensible distinct-alert correlation key remain unresolved. TF-008 and TF-009
remain **open**.

### TF-008 distinct-alert relationship evidence gate, 2026-09-27

The registered producer's member digest and row ordinal identify one verified
source row. `source_event_id` binds that row; `alert_candidate_id` adds detector,
model, artifact and policy identities. A compatible same-candidate replay is
idempotency, not a relationship between different alerts. The row's UTC start
time reaches `observed_at`, but its transient endpoint, port, flow ID and end
time do not reach the persisted candidate or analyst view. Request/replay IDs,
inference-attempt UUID, creation time, model and score cannot establish a shared
host, session or incident. No distinct-alert rule or bounded window is justified.

The missing field is a validated, scoped observed-entity identifier with
source/issuer and mapping provenance, role, lifetime and missing/conflict
semantics, immutably bound to source observation and alert. A future window also
requires verified observation-clock origin, precision and error bound before its
duration is chosen. Raw offline UNSW addresses do not establish an authenticated
asset namespace. The [correlation contract](alert_correlation_analyst_state.md)
records counterexamples and future acceptance criteria. No grouping code or
tests changed; TF-008 remains **open**, and TF-009's disposition is unchanged.

### TF-008 registered-source identity provenance check, 2026-09-27

The manifest's raw-member digest and row ordinal, and the reader-injected
`flow_id`, identify a reproducible CSV row, not a host or capture-scoped asset.
The official source describes UNSW lab traffic, packet capture and Argus/Bro
feature creation, but no verified address-assignment domain, NAT/alias/reuse
lifetime, sensor/capture-segment identity, privacy/retention treatment or
capture-clock quality accompanies these rows. Record source/destination fields
do not establish initiator or attacker roles. The adapter derives end time from
`stime + dur` and does not compare `ltime`; only start time reaches the alert.
No observed-entity field or time window is justified. TF-008 remains **open**;
TF-009 is unchanged. Operational browser credential provisioning/revocation is
the next independent bounded product milestone, without a correlation claim.

### TF-008 / TF-009 local operator credential slice, 2026-09-28

Both remain **open**. The [operator runbook](human_credential_operator_runbook.md)
now supplies public-certificate enrollment, exact-fingerprint disable/revoke,
strict private metadata loading and a construction adapter for both human mTLS
listeners. Real TLS tests prove restriction after reconstruction, unchanged access
for another actor, preserved audit history and authentication-rejection taxonomy.
A disk edit or reopening the same listener retains its old registry. No role can
be supplied through enrollment metadata, a certificate or an HTTP request.

Final new slice: 38 passing tests; the prior combined run passed all 134 existing
listener/audit/authorization tests and exposed four new overly strict response
assertions, corrected to match the existing 401-or-close contract. Ruff, individual
Black checks and whitespace checks pass; detailed failed/sandbox and final commands
are retained in project_status.md. This narrows the prior missing operational
provisioning statement to the capability actually delivered. CA issuance, secure
browser delivery, recovery, live reload, endurance, operator-action journaling and
archival at the 64-record limit remain unimplemented/unproven. No limitation is
accepted, no product gate is waived, and distinct-alert correlation is unchanged.

### TF-008 / TF-009 controlled human lifecycle, 2026-09-28

Both issues remain **open**. The corrected credential combined gate now passes
172 tests (exit 0), superseding the prior incomplete gate without erasing its failures.
The explicitly injected `HumanListenerLifecycle` constructs both human listeners via
operator policy under one shared directory lock. Replacement stops admission on both,
closes sockets and joins old workers before loading policy; validation precedes opening,
and partial startup closes the candidate generation without restoring old credentials.
Real-loopback tests prove persisted disable/revoke leaves an old generation unchanged,
replacement denies the exact fingerprint without protected view access while another
actor reads, audit history/classification survives, and a dispatched transition retains
same-UUIDv4 retry behavior. Startup/dependency failure and interruption cleanup are
covered; no operational credentials or models were used.

CA issuance, secure certificate/private-key delivery to Firefox, operator-action
journaling, backup/recovery, endurance, and service-manager deployment remain open.
The caller must own all lifecycle workers, keep the policy directory in place, and
use finally/context cleanup. Stalled trusted storage has no claimed shutdown deadline.
No limitation is marked accepted. Next action: review the complete uncommitted
credential and lifecycle diff against the documented admission/cleanup contract.

### TF-008 / TF-009 operator credential journaling and bounded handshake drain, 2026-10-14

Both issues remain **open**. An append-only audit journal (`journal.jsonl`, mode 0600,
schema `operator_human_credential_journal_v1`, capped at 64 records and 64 KiB) is
now maintained in the private policy directory under directory lock and strict
descriptor-relative ancestor checks. Every successful `init`, `enroll`, `disable`, and
`revoke` action appends a deterministic entry with monotonic 1-based sequence number (`seq`),
UTC ISO timestamp (`recorded_at_utc`), action type, actor ID, fingerprint, resulting status,
and active/total counts. No raw PEM bytes or secret material are ever recorded. Symlinks,
unsafe permissions/ownership, non-monotonic sequence numbers, corrupted entries, and capacity
overflows fail closed with `CredentialPolicyError`. The `read_journal` helper reads and validates
journal integrity under the directory lock.

In both `AnalystBrowserTlsListener` and `AnalystTlsListener`, `process_one()` assigns
`self._active` to the accepted connection under lock before `connection.do_handshake()`.
When `close()` is invoked (such as during `HumanListenerLifecycle.replace()` or `shutdown()`),
it safely calls `shutdown(socket.SHUT_RDWR)` and `close()` on the active connection,
promptly interrupting stalled TLS handshakes so caller-owned workers join in < 5.0 seconds
(verified by `test_stalled_handshake_does_not_block_replace_or_shutdown`) rather than blocking
for the full 60.0-second browser handshake timeout. Any request already admitted into the
protected dispatch section finishes cleanly before `close()` returns.

The expanded gate passes 199 tests (exit 0). CA issuance, secure Firefox credential delivery,
backup/recovery, endurance, service-manager deployment, and the defensible distinct-alert
correlation key remain open under TF-008 and TF-009.

### TF-009 coordinated multi-database online backup and atomic restore, 2026-10-14

Both TF-008 and TF-009 remain **open**. Fail-closed, descriptor-relative online snapshot
creation, cryptographic verification, and atomic offline restore are now implemented in
`threatfusion.operations.storage_backup` across ThreatFusion's three SQLite databases:
`alerts.sqlite3` (`alert_candidate_sqlite_v1`), `states.sqlite3` (`analyst_state_sqlite_v1`),
and `audit.sqlite3` (`analyst_security_audit_sqlite_v1`).

The implementation enforces mode `0700` directory permissions, mode `0600` file permissions,
strict ancestor ownership/permission verification (`0` or `os.geteuid()`, no group/world write),
symlink rejection (`os.O_NOFOLLOW`), and filesystem locks (`fcntl.flock(fd, LOCK_EX | LOCK_NB)`).
Snapshots use Python's `sqlite3.Connection.backup()` API over read-only connections (`mode=ro`)
for page-level database consistency. Every snapshot generates a SHA-256 manifest
(`manifest.json`, schema `storage_snapshot_manifest_v1`, capped at 64 KiB), runs
`PRAGMA integrity_check` on all three databases, verifies schema identities and versions, and
enforces cross-database referential consistency (verifying that every `alert_candidate_id` present
in `states.sqlite3` exists in `alerts.sqlite3`). Offline atomic restore stages databases via mode-0600
temporary files and replaces them atomically (`os.replace`), cleans up stale `-wal`/`-shm` sidecars,
and fsyncs the target directory.

Because the three databases reside in separate SQLite files without distributed two-phase commit,
snapshots execute sequential online backups across the databases. Coordinated quiescent or stopped-listener
snapshots are therefore recommended for exact point-in-time alignment.

The expanded gate passes 148 tests (exit 0). CA issuance, secure Firefox credential delivery,
daemon service-manager deployment, long-term endurance, and the defensible distinct-alert
correlation key remain open under TF-008 and TF-009.

### TF-009 quiescent lifecycle coordination and signal-safe service runner, 2026-10-14

Both TF-008 and TF-009 remain **open**. Bounded quiescent storage coordination and a signal-safe
service supervisor runner are now implemented in `threatfusion.operations.human_listener_lifecycle`
and `threatfusion.operations.human_service_runner`:

1. **Quiescent Snapshot and Restore Coordination:** `HumanListenerLifecycle` now provides
   `snapshot_quiescent(snapshot_dir)` and `restore_quiescent(snapshot_dir)`. These operations stop
   listener admission, close active sockets, and join both worker threads (< 5.0s drain), ensuring
   zero concurrent requests or active SQLite transactions during backup or restore. Quiescent
   snapshots capture page-level database copies via `create_storage_snapshot` and automatically
   resume a fresh generation (`replace()`); quiescent restores verify the candidate snapshot,
   atomically restore databases via `restore_storage_snapshot`, and restart a fresh generation
   bound to the restored database state.
2. **Signal-Safe Service Runner:** `HumanServiceRunner` wraps `HumanListenerLifecycle` in a
   supervised single-process controller with deterministic POSIX signal handling:
   - `SIGTERM` / `SIGINT`: clean stop drain, closes listeners, joins workers, exits `0`.
   - `SIGHUP`: triggers generation replacement (`replace()`) under directory lock to load updated
     credential policy; on reload failure (such as all actors restricted or corrupt policy), fails
     closed, shuts down listeners, and exits `2`.
   - Initial startup failure or unhandled worker crash exits `1`.
   - Programmatic triggers (`trigger_shutdown()`, `trigger_reload()`, `run_until_stopped()`, and
     context manager) enable deterministic lifecycle automation and testing.
3. **Hardened Service Manager Deployment:** A reference Linux `systemd` unit configuration
   (`threatfusion-analyst.service`) defines unprivileged user isolation (`operator`), `UMask=0077`,
   `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, and `ExecReload=/bin/kill -HUP $MAINPID`.

CA issuance, secure Firefox credential delivery, long-term endurance, and the defensible
distinct-alert correlation key remain open under TF-008 and TF-009.

### TF-008 / TF-009 tamper-evident security audit export, retention pruning, and hash-chained journal rotation, 2026-10-14

Both TF-008 and TF-009 remain **open**. Long-term maintenance mechanisms for bounded SQLite audit
history and credential policy journaling are now implemented in `threatfusion.operations.audit_retention`
and `threatfusion.operations.human_credentials`:

1. **Hash-Chained Journal Rotation at the 64-Record Cap:** `rotate_journal(policy_dir, archive_dir)`
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

CA issuance, secure Firefox credential delivery, long-term endurance, and the defensible
distinct-alert correlation key remain open under TF-008 and TF-009.

### TF-008 local offline human CA initialization, encrypted client bundle delivery, and enrollment coordination, 2026-10-14

Both TF-008 and TF-009 remain **open**. Local offline Root CA issuance, encrypted client bundle
packaging, and enrollment coordination are now implemented in `threatfusion.operations.human_ca_issuance`:

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

Automated browser-profile provisioning, long-term endurance, and the defensible distinct-alert
correlation key remain open under TF-008 and TF-009.
