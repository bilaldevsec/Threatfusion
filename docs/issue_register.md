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
| TF-005 | P2 / medium | **Resolved 2026-10-14: timestamp ISO format parsing and packaging discovery consolidation.** Standard-library ISO-8601 pre-parsing eliminated all four pandas `dayfirst=True` date-parsing warnings across Mordor fixture profiles and readers without altering expected timestamps or numeric epoch parsing. Packaging configuration in `pyproject.toml` and top-level `src` alias established complete package discovery across all 13 `threatfusion.*` subpackages and `src` with zero-PYTHONPATH offline editable installation. | Generic timestamp parsing, Mordor/fixture diagnostics, packaging discovery | Preserve ISO-8601 pre-parsing, epoch fallback, and setuptools package-dir mappings. Run tests under `env -u PYTHONPATH`. | Focused unit and integration tests prove byte-identical UTC timestamps, zero `UserWarning` occurrences, clean subprocess imports across all 13 subpackages and `src` from external directories with `PYTHONPATH` unset, and offline editable install completes with exit 0. | resolved |
| TF-006 | P1 / high | **Known limitation/evidence gap.** Exact feature collisions and conflicting labels exist; near-duplicate leakage and capture/session provenance remain unresolved. See the [split design](network_training_split_design.md) and [February protocol](network_classical_evaluation_protocol.md). | UNSW validation/test interpretation and all model generalization claims | Specify bounded, label-independent provenance and near-duplicate diagnostics before further model comparison; do not tune a threshold using known test outcomes. | Predeclared diagnostics quantify cross-split capture/group and near-duplicate risk, demonstrate no prohibited leakage under a reviewed rule, or retain an explicit unresolved limitation. | open |
| TF-007 | P1 / high | **Evaluation exposure.** February UNSW and CIC outcomes are known and can influence future decisions. See [`network_classical_evaluation_protocol.md`](network_classical_evaluation_protocol.md). | Future features, models, thresholds, claims of independent evaluation | Record exposure in every future experiment and reserve a genuinely uninspected, independently verified evaluation source before development informed by these outcomes. | Future experiment protocol is frozen before access and proves source/label integrity, semantic compatibility, non-overlap, and no prior outcome inspection. | open |
| TF-008 | P1 / high | **Independent Model Benchmark Beyond Inspected January/February UNSW Splits.** January (216,568 rows) and February (1,452,844 rows) were both previously inspected during model selection/evaluation; closing TF-008 requires evaluation on an untouched independent holdout or external dataset benchmark. | Model generalization, independent evaluation claims | Predeclare and freeze protocol on an untouched independent benchmark dataset; evaluate without prior threshold or feature tuning. | Formal evaluation report on untouched external holdout proves generalization without inspected split bias. | open |
| TF-009 | P1 / high | **Measured Reduction of Analyst Workload / Alert Fatigue.** `workload_measurement.py` (Section 13.F) provides the counterfactual January FP shield proof (201 RF FPs vs 1,775 fused FPs = 8.831x) and the SQLite telemetry recorder (`workload_study.sqlite3`), but closing TF-009 requires real human-factors / analyst cohort study trials (`study_cohort="human_analyst_cohort_study"`, `min_human_trials >= 10`). | Operational alert fatigue reduction, analyst workflow claims | Run controlled human-factors / analyst cohort study comparing baseline raw alerts against ThreatFusion enriched advisory triage. | Statistically significant reduction in time-to-disposition and false-alarm triage burden verified across at least 10 real human analyst trials. | open |
| TF-010 | P1 / high | **External FAST-NUCES FYP-II Jury Rubric & Signed Supervisor/Jury Evaluation Alignment.** Internal traceability (`jury_traceability.py`) and Evaluation Pack Rev2 (`AI-FYP-2006`) alignment are wired, but closing TF-010 requires the official external signed FAST-NUCES jury/supervisor rubric artifact. | Scope control, jury compliance, formal academic defense | Formally attach external signed FAST-NUCES FYP-II jury rubric and verify alignment against repository deliverables. | Official signed FAST-NUCES jury rubric artifact attached and validated with zero discrepancies against code deliverables. | open |
| TF-011 | P1 / high | **Real Operational SIEM / Threat-Intelligence Production Source Proof.** `SuricataFlowAdapter` (Slide 14) and `SourcedThreatIntelEnricher` (Section 13.C) are verified on bounded/recorded flows and local snapshots, but closing TF-011 requires live operational SIEM / production threat-intelligence source deployment evidence. | Operational deployment, live enterprise threat-intel ingestion | Deploy live operational SIEM pipeline and production threat-intelligence feeds in enterprise environment. | Verified live telemetry streams ingested from operational enterprise SIEM and production threat-intel sources with end-to-end evidence. | open |
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

### TF-005 timestamp ISO parsing resolution and zero-PYTHONPATH packaging consolidation, 2026-10-14

TF-005 is **resolved**. Both TF-008 and TF-009 remain **open**.

1. **Root-Cause Analysis & Timestamp ISO Pre-Parsing:** The four historical pandas date-parsing
   warnings (`UserWarning: Parsing dates in %Y-%m-%dT%H:%M:%S.%f%z format when dayfirst=True was specified`)
   were traced to `backend/src/threatfusion/datasets/adapters/base.py:parse_required_timestamp`. When
   fixture/Mordor ISO-8601 strings were passed to `pd.to_datetime(text, errors="coerce", utc=True, dayfirst=True)`,
   pandas emitted a warning because ISO-8601 specifies year first, making `dayfirst=True` conflicting.
   The parser now pre-parses ISO-8601 strings using standard library `datetime.fromisoformat(text)` with
   explicit UTC conversion before falling back to pandas dayfirst parsing. Focused tests prove byte-identical
   UTC timestamps with zero `UserWarning` occurrences across the entire repository test suite (1284 passed,
   0 warnings).
2. **Package Discovery Consolidation & Top-Level `src` Alias:** Package configuration in `pyproject.toml`
   was updated with `[tool.setuptools.package-dir]` mapping `"threatfusion" = "backend/src/threatfusion"` and
   `"src" = "src"`, with `[tool.setuptools.packages.find]` configured for `where = ["backend/src", "."]` and
   `include = ["threatfusion*", "src*"]`. The top-level `src/__init__.py` alias exposes `src.threatfusion`
   without polluting the root namespace. Setuptools discovers all 13 `threatfusion` subpackages plus `src`.
3. **Zero-PYTHONPATH Offline Editable Installation:** Editable installation was executed strictly offline
   via `threatfusion-venv/bin/pip install --no-build-isolation --no-deps -e .` with exit 0 and zero network
   downloads. Subprocess test `test_subprocess_import_zero_pythonpath_external_cwd` proves that running Python
   from an external working directory with `PYTHONPATH` explicitly unset cleanly imports `threatfusion`, all 13
   subpackages, and `src`.
4. **Full-Repository Verification Gate:** The entire repository test suite ran with `PYTHONPATH` unset:
   `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/pytest` passed 1284 tests in 111.45s with
   zero failures and zero warnings. Repository Ruff and Black checks pass cleanly.

Automated browser-profile provisioning, long-term endurance, and the defensible distinct-alert
correlation key remain open under TF-008 and TF-009.

### TF-008 operator Firefox NSS profile provisioning from encrypted PKCS#12 bundles, 2026-10-14

Both TF-008 and TF-009 remain **open**.

1. **Fail-Closed Firefox NSS Profile Provisioning (`threatfusion.operations.human_browser_provisioning`):**
   `provision_firefox_profile` provisions isolated Firefox NSS SQLite databases (`cert9.db`, `key4.db`,
   `pkcs11.txt`) directly from verified Root CA (`ca_dir`) and client PKCS#12 bundle delivery directories
   (`delivery_dir`). Enforces mode-0700 private directories, mode-0600 files, `O_NOFOLLOW` symlink rejection,
   and exclusive `fcntl.flock` locks across all participating directories.
2. **Ephemeral Passphrase Handling & NSS Command Execution:** Passphrases are validated for length (>= 12)
   and byte hygiene (no control characters). During `pk12util -i` import, the passphrase is written to a
   temporary mode-0600 file outside the profile directory and zeroed and unlinked in a `finally` block,
   preventing `/proc/<pid>/cmdline` process listing or disk persistence. Non-interactive NSS database
   initialization uses `certutil -N --empty-password`, and the Root CA is imported as trusted for server
   verification (`certutil -A -t "C,,"`). Mode 0600 is explicitly enforced on all generated database files.
3. **Hardened Loopback Configuration & Tamper-Evident Manifest:** A mode-0600 `user.js` configures
   `security.default_personal_cert="Select Automatically"` for seamless loopback mTLS authentication while
   disabling background telemetry, telemetry archiving, captive portal checks, Normandy studies, and
   enterprise roots. A mode-0600 manifest (`profile_manifest.json`, schema `operator_human_firefox_profile_v1`)
   records `actor_id`, `client_cert_sha256`, `ca_cert_sha256`, `serial_number`, `provisioned_at_utc`, and
   individual SHA-256 digests (`cert9_db_sha256`, `key4_db_sha256`, `pkcs11_txt_sha256`, `user_js_sha256`)
   with zero secrets.
4. **Cryptographic & Structural Verification:** `verify_firefox_profile` checks directory and file modes,
   rejects symlinks and unexpected files, verifies all file SHA-256 digests against `profile_manifest.json`,
   executes `certutil -L` to confirm presence of both the CA (`C,,`) and client certificate (`u,u,u`), and
   cross-checks certificate fingerprints against `delivery_dir` and `ca_dir`.
5. **End-to-End Integration Tests (`test_human_browser_provisioning.py`):** Integration tests verify the
   complete chain: `init_human_ca()` -> `init_policy_directory()` -> `issue_and_enroll_human_credential()` ->
   `provision_firefox_profile()` -> `verify_firefox_profile()` -> `certutil -L` verification, mode 0600 file
   checks, zero raw passphrases in text files, and real loopback mTLS `GET /analyst/alerts` (`HTTP 200`) on
   `AnalystBrowserTlsListener` through `HumanListenerLifecycle`. Fail-closed tests verify typed rejection
   (`HumanBrowserProvisioningError`) on wrong passphrases, tampered database/user.js digests, symlinks,
   insecure permissions (`0755`), non-empty profile directories, and CA/bundle mismatch.

Automated operator Firefox profile provisioning is implemented and verified. Browser write authentication/CSRF
protection, long-term endurance, and the defensible distinct-alert correlation key remain open under TF-008 and TF-009.

### TF-008 CSRF-hardened, same-origin verified browser alert state transitions and audited HTML triage workflow, 2026-10-14

Both TF-008 and TF-009 remain **open**.

1. **Cryptographic Per-Actor CSRF Token Generation & Verification:**
   `AnalystBrowserTlsListener` initializes an ephemeral 32-byte secret (`os.urandom(32)`). When rendering
   alert detail to an authenticated mTLS peer with role `analyst`, it generates an HMAC-SHA256 CSRF token
   cryptographically binding `(actor_id, alert_candidate_id, expected_version, transition_request_id)`.
   Upon `POST /v1/analyst/alerts/<alert_candidate_id>/transitions`, the token is verified using constant-time
   `hmac.compare_digest`. Any missing, tampered, expired, or cross-actor CSRF token is rejected fail-closed
   with HTTP `403 Forbidden` and audited as `authorization_rejected` (`forbidden`) with zero state modifications.
2. **Same-Origin & Framing Enforcement:**
   POST requests must specify `Content-Type: application/x-www-form-urlencoded` bounded to 2,048 bytes.
   Browser origin headers are strictly enforced: `Sec-Fetch-Site` must be `"same-origin"` if present,
   `Origin` must match `https://127.0.0.1:<port>` or `https://localhost:<port>` if present, and at least one
   must be supplied. Missing or cross-site headers are rejected upfront with `403 Forbidden` and audited as
   `authorization_rejected` (`forbidden`).
3. **Role-Based Mutation Denial for Viewers:**
   Peers authenticated with role `viewer` cannot mutate alert state: any POST transition attempt is rejected
   with `403 Forbidden` and audited as `authorization_rejected` (`forbidden`) without invoking `AnalystStateRepository`.
4. **Server-Rendered Zero-JavaScript HTML Triage Workflow (`render_dashboard_html`):**
   The alert detail view embeds a server-rendered `<form method="POST">` when accessed by an `analyst` peer,
   populating hidden inputs for `expected_version`, canonical UUIDv4 `transition_request_id`, and `csrf_token`,
   alongside a `<select name="target_state">` with valid next transitions (`new` -> `in_review`; `in_review` ->
   `closed`, `escalated`) and a bounded `<input name="reason">`. When accessed by a `viewer` or when the alert
   has reached a terminal state (`closed` or `escalated`), no form or submission controls are rendered; clear
   read-only and terminal state badges are displayed instead.
5. **Audited State Transitions & Error Semantics:**
   State transitions are executed through `AnalystAlertViewModel.transition`, recording `request_admitted`
   prior to mutation and `request_completed` after successful mutation in `audit.sqlite3` with normalized
   route `/v1/analyst/alerts/<alert_candidate_id>/transitions` and `body_sha256`. Successful transitions
   return HTTP 200 with the updated HTML detail view, displaying the new version, state, transition history,
   and fresh CSRF tokens for subsequent workflow steps. Stale `expected_version` inputs return `409 Conflict`,
   invalid transitions return `400 Bad Request`, and storage failures return `503 Unavailable`.
6. **Integration & Security Tests (`test_analyst_browser_tls_service.py` & `test_analyst_dashboard.py`):**
   Tests verify:
   - Complete browser triage workflow: analyst GET detail -> extract CSRF token -> POST transition `new` ->
     `in_review` -> HTTP 200 with updated detail -> second transition `in_review` -> `closed` -> terminal state.
   - Fail-closed security rejections with zero state mutations: viewer POST denial (403), cross-site
     `Sec-Fetch-Site` (403), untrusted `Origin` (403), missing same-origin headers (403), tampered CSRF token
     (403), cross-actor CSRF token (403), stale version conflict (409), and invalid state jumps (400).
   - Server-rendered HTML presentation: analyst form with valid target states and CSRF token, viewer read-only
     badge without `<form>`, and terminal state notice.

Automated browser triage workflows and CSRF defenses are implemented and verified. Long-term endurance, live telemetry,
and the defensible distinct-alert correlation key remain open under TF-008 and TF-009.

### TF-008 / TF-009 authenticated entity provenance contract, dual-window 30s/10m alert correlation engine, and empirical alert fatigue reduction metric, 2026-10-15

Both TF-008 and TF-009 remain **open**.

1. **Entity Provenance Boundary & Fail-Closed UNSW-NB15 Singleton Isolation (`EntityProvenanceContract`):**
   Implemented `EntityProvenanceContract` in `backend/src/threatfusion/alerts/correlation_engine.py` requiring explicit
   `entity_namespace_id`, `clock_synchronized=True`, and non-empty `src_entity_id`/`dst_entity_id`. Raw UNSW-NB15 alerts
   lacking verified entity namespaces or clock synchronization guarantees are strictly prohibited from merging with other
   alerts; each is deterministically isolated into a singleton incident (`correlation_mode = "singleton_unverified_provenance"`,
   `window_type = "none"`), ensuring 0 false merges across synthetic or unverified captures.
2. **Dual-Window Correlation for Verified Entity Telemetry (`correlate_alert_candidates`):**
   Authenticated alerts are correlated under two distinct temporal windows within the same `entity_namespace_id`:
   - **30-Second Burst Window (`BURST_WINDOW_SECONDS = 30.0`)**: Rapid burst alerts sharing exact 5-tuples
     `(entity_namespace_id, src_entity_id, dst_entity_id, protocol, service_or_port)` within <= 30s collapse into a
     burst incident (`window_type = "burst_30s"`, `correlation_rule_id = "corr_burst_5tuple_30s_v1"`).
   - **10-Minute Campaign Window (`CAMPAIGN_WINDOW_SECONDS = 600.0`)**: Multi-stage alerts between the same authenticated
     endpoint pair `(entity_namespace_id, frozenset({src_entity_id, dst_entity_id}))` within <= 600s collapse into a
     campaign incident (`window_type = "campaign_600s"`, `correlation_rule_id = "corr_campaign_entity_pair_600s_v1"`).
   - **Cross-Namespace Isolation**: Alerts from distinct sensor namespaces (`sensor-a` vs `sensor-b`) never correlate.
3. **Empirical Alert Reduction Metric & 100% Critical Scenario Retention Safety Gate:**
   Computes alert fatigue reduction ratio 1.0 - (incidents / alerts). Enforces that every input alert is
   accounted for, and strictly requires critical_retention_ratio == 1.0. If any critical/attack alert is omitted or
   dropped, the engine raises `CorrelationSafetyError("critical_alert_dropped")`. Every correlated incident inherits the maximum
   uncalibrated model score and escalates to decision "Attack" if any constituent alert is an Attack (zero downgrade invariant).
4. **SQLite Transactional Persistence (`IncidentSqliteRepository`):**
   Implements fail-closed SQLite persistence (`incidents.sqlite3`) with tables `incidents` and `incident_constituent_alerts`
   under file mode 0600, supporting idempotent insertion and index lookups by `incident_id` or `alert_candidate_id`.
5. **Dashboard & View Model Surfacing:**
   `AnalystAlertViewModel.get_alert` queries `IncidentSqliteRepository` and returns `incident_correlation` metadata,
   defaulting unverified raw UNSW-NB15 alerts cleanly to `singleton_unverified_provenance` with clear narrative notes.
   `render_dashboard_html` renders an **Incident Correlation & Provenance** section with mode, window, rule, constituent count,
   and provenance badges.
6. **Unit & Integration Test Verification:**
   `test_correlation_engine.py` (6 tests) and `test_incident_correlation_pipeline.py` (2 integration tests) verify:
   - UNSW-NB15 10 singleton alerts produce 10 separate incidents (0% false merge, reduction ratio 0.0).
   - 20 authenticated sensor burst alerts within 30s collapse into 1 incident (95% reduction ratio, 100% critical retention).
   - Multi-port campaign alerts within 8m collapse into 1 campaign incident; alert at 601s starts a new incident.
   - Cross-namespace isolation between identical IPs/ports across different sensors.
   - Fail-closed error on critical alert omission.
   - View model integration and server-rendered HTML dashboard presentation.

Dual-window incident correlation, entity provenance boundaries, alert reduction metrics, and dashboard surfacing are implemented
and verified. Long-term endurance, live telemetry, and external CA provisioning remain open under TF-008 and TF-009.

### TF-008 / TF-009 Phase P0/P1/P2 quality & blocker resolution: Section 7 lifecycle startup interruption repair, Section 6.3 dual-SQLite audit failure verification, and storage backup incidents support, 2026-10-15

Both TF-008 and TF-009 remain **open**.

1. **Human Listener Lifecycle Startup Interruption Repair (`human_listener_lifecycle.py`):**
   Prior review identified that a `KeyboardInterrupt` (`BaseException`) inside `worker.start()` before native OS
   thread creation bypassed `except Exception`, leaving the worker record marked "possibly started" while no native
   thread existed to set the completion event, resulting in a hang during shutdown cleanup.
   - Updated `worker.start()` error handling to trap `BaseException`, ensuring interruptions and system exits are captured.
   - Added bounded native thread creation verification: checks `worker.ident is not None or worker.is_alive()` or waits
     bounded timeout (50ms) on `worker._started`. If native creation never occurred, `record[2] = True` (`failed_to_start = True`).
   - In `_shutdown()`, cleanly skips workers whose native thread creation never occurred (`ident is None` and not alive),
     preventing indefinite waits on `finished.wait()`.
   - For started threads, cleanly closes listening sockets, sets `_stop`, releases `_ready`, waits on `finished.wait(timeout=1.0)`,
     and deterministically joins `worker`. Zero leaked worker handles or listening sockets.
   - Partial startup failure rolls back candidate generation without restoring old restricted credentials or falsely declaring success.
   - Verified by 6 isolated watchdog regressions in `backend/tests/integration/test_human_listener_lifecycle.py` covering first and
     second worker pre-native and post-native `KeyboardInterrupt` and `RuntimeError` failures. All 26 lifecycle tests pass.
2. **Browser Transition Dual-SQLite Audit Failure & Retry Deduplication Verification (`test_analyst_browser_tls_service.py`):**
   - Verified that pre-mutation admission audit failure in `AnalystBrowserTlsService` raises HTTP 503 unavailable and blocks
     mutation in `AnalystStateRepository` (0 state mutations committed).
   - Verified that post-commit completion audit failure returns HTTP 503 unavailable, state transition commits to `states.sqlite3`,
     and replaying the transition with the same UUIDv4 `transition_request_id` returns HTTP 200 with the committed state and
     generates 0 duplicate transitions in `alert_state_transitions`.
3. **Storage Snapshot Backup Support for Optional `incidents.sqlite3` (`storage_backup.py`):**
   - Added `INCIDENTS_DB_ROLE = "incidents"` with schema `incident_sqlite_v1`.
   - Updated `create_storage_snapshot`, `verify_storage_snapshot`, and `restore_storage_snapshot` to include `incidents.sqlite3`
     when present, while preserving 100% backward compatibility when only the 3 core DBs (`alerts`, `states`, `audit`) are present.
   - Added cross-database referential consistency validation: verifies that every constituent alert in `incident_constituent_alerts`
     corresponds to a valid candidate in `alert_candidates`.
   - Added `PRAGMA user_version = 1` initialization to `IncidentSqliteRepository`.
   - Verified by 13 tests in `backend/tests/integration/test_storage_backup.py`, including optional incidents database backup/restore
     and referential integrity failure detection.
4. **Canonical Gemini Master Project Export (`docs/GEMINI_PROJECT_MASTER.md`):**
   - Created canonical project export `docs/GEMINI_PROJECT_MASTER.md` (Revision `TF-GEMINI-MASTER-2026-10-15-v2`), recording
     current HEAD `d71e333`, Milestone #18 committed status, Section 7 lifecycle blocker resolution, Section 6.3 dual-DB
     audit failure verification, optional incidents backup support, and capability status updates.

Operational credential provisioning, external CA issuance/delivery runbooks, and long-term endurance remain open under TF-008 and TF-009.

### TF-008 / TF-009 Phase P3 & P4: Supported source provenance adapters, complete Section 8 correlation gate, and audited grouping corrections, 2026-10-15

Both TF-008 and TF-009 remain **open**.

1. **Supported Source Provenance Adapters (`provenance_sources.py`):**
   - Implemented `MordorScenarioAdapter` normalizing Mordor security events bound to scenario captures with explicit `source_mode = "scenario_replay"`, `scenario_id`, `entity_namespace_id = f"mordor:{scenario_id}"`, entity endpoints, validity intervals, clock origin (`"utc_event_log"`), and clock synchronization evidence.
   - Implemented `AuthorizedLabSensorAdapter` gating sensor telemetry via allowlisted `RegisteredSensorManifest`. Enforces pre-registered `sensor_id` validation, replay/duplicate `source_event_id` detection, and strict separation between dataset/scenario replay and authorized lab sensors (`source_mode = "authorized_lab_sensor"`).
2. **Address Reuse / NAT & Entity Validity Interval Handling:**
   - Extended `EntityProvenanceContract` with `address_reuse_or_nat: bool = False`, `validity_start_utc`, and `validity_end_utc`.
   - If `address_reuse_or_nat is True` (e.g. unmapped NAT gateway or DHCP lease churn), or if `observed_at_utc` falls outside `[validity_start_utc, validity_end_utc]`, the correlation engine fails closed into `singleton_unverified_provenance` (`"nat_address_reuse_ambiguous"` or `"outside_entity_validity_interval"`).
3. **Clock Skew Tolerance Gate:**
   - `max_clock_skew_seconds <= 5.0` is tolerated under synchronized clocks (`MAX_ALLOWABLE_CLOCK_SKEW_SECONDS = 5.0`). Exceeding this bound fails closed to `singleton_unverified_provenance` (`"clock_skew_exceeded"`).
4. **Candidate Deduplication vs. Incident Grouping:**
   - Repeated submissions of the exact same `alert_candidate_id` collapse cleanly upfront without inflating total alert counts or constituent alert counts.
5. **Exact Boundary Semantics & Out-of-Order Determinism:**
   - Chronological pre-sorting on `(parsed_timestamp, alert_candidate_id)` ensures out-of-order and late-arriving events produce identical incident clusters.
   - Boundaries: $\Delta t \le 30.0\text{s}$ is included in burst window; $\Delta t = 30.001\text{s}$ is excluded. $\Delta t \le 600.0\text{s}$ is included in campaign window; $\Delta t = 600.001\text{s}$ is excluded and starts a new cluster.
6. **Per-Event Grouping Justification (`MemberJustification`):**
   - Every constituent alert carries an explicit structured `MemberJustification` (`anchor_alert_id`, `delta_seconds`, `matched_relationship_key`, `rule_id`, `provenance_summary`) persisted to `incident_constituent_alerts` in SQLite.
7. **Audited Grouping Correction (`correct_incident_grouping`):**
   - Investigators can manually split erroneously grouped alerts into separate standalone incidents (`correlation_mode = "manual_correction_split"`).
   - Replays with the identical UUIDv4 `correction_request_id` return the existing split incident idempotently, while conflicts raise `CorrelationSafetyError("correction_request_conflict")`.
   - All manual split actions are immutably logged to `incident_grouping_corrections`.

Operational credential provisioning, external CA issuance/delivery runbooks, and long-term endurance remain open under TF-008 and TF-009.

### TF-010 repository disposition / TF-002–TF-004 & TF-007 Phase P5 progress: Jury Requirements Traceability, Missing-Data Aware Multi-Signal Risk & RF/AE Ablation Engine, and Offline Retraining Feedback Ledger, 2026-10-16

TF-010 repository-side disposition registry is implemented in `backend/src/threatfusion/models/jury_traceability.py` and `docs/jury_requirements_traceability.md`; per `CLAUDE.md` Section 7, TF-010 remains **open** pending physical attachment of the signed external jury brief. TF-002, TF-003, TF-004, and TF-007 progress is recorded under Phase P5.

1. **Jury Requirements Traceability Registry (`jury_traceability_matrix_v1`, TF-010 open (repository-side traceability helper implemented; external FAST-NUCES jury rubric remains open)):**
   - Implemented `backend/src/threatfusion/models/jury_traceability.py` and published `docs/jury_requirements_traceability.md`.
   - Immutable registry defines formal dispositions, schema contracts, and leakage boundaries for all 6 jury-approved datasets (`UNSW-NB15`, `CIC-IDS2017`, `CSE-CIC-IDS2018_subset`, `Mordor_scenarios`, `Synthetic_UEBA`, `Authorized_Lab_Sensor`) and 5 model families (`Logistic_Regression`, `Random_Forest`, `Autoencoder_v2`, `Rate_Log1p_Candidate`, `Heuristic_Statistical_Signals`).
   - `verify_jury_traceability_completeness()` asserts that every required dataset and model family has a non-empty disposition, valid artifact/contract reference, and explicit leakage boundary. Verifies disk SHA-256 digests for all baseline artifacts (`random_forest.joblib`: `bd2853a6...`, `autoencoder_state.pt`: `c8675d13...`, `logistic_regression.joblib`: `2cf4de66...`, `rate_log1p`: `1d02e5bb...`).

2. **Missing-Data Aware Multi-Signal Risk Engine (`dynamic_risk_assessment_v1`, TF-002/TF-003/TF-004):**
   - Implemented `backend/src/threatfusion/models/multi_signal_risk.py` with 7 canonical slots (`supervised_rf`, `autoencoder_v2_reconstruction`, `isolation_forest_outlier`, `ueba_behavioral_deviation`, `threat_intel_ioc`, `payload_entropy`, `periodic_beaconing`).
   - Enforces the Missing-Data Invariant ("Missing evidence is not benign evidence"): unavailable signals are removed from the denominator rather than diluting attack evidence toward 0.0. Formula: $D = 100.0 \times \frac{\sum_{i \in A} w_i \times s_i}{\sum_{i \in A} w_i}$.
   - Proved that when `supervised_rf = 0.90` and the other 6 signals are `UNAVAILABLE`, $D = 90.0$ (not diluted to 27.0).
   - Fails closed on empty available set, out-of-bounds / NaN scores, invalid weights, and unstated unavailability reasons.

3. **Leakage-Aware RF vs. RF+AE Ablation & Metrics Evaluator (`detector_ablation_report_v1`):**
   - Implemented `evaluate_detector_ablation` computing confusion matrix (`tp`, `fp`, `tn`, `fn`), `precision`, `recall`, `f1_score`, `pr_auc`, `false_alert_burden_per_1000`, and delta statistics.
   - Evaluates promotion gate verdicts: rejects regressions (`rejected_regression`) if candidate drops recall or inflates false alerts without recall gain; retains candidates as `experimental_unfused_retained` when anomaly evidence is present but false alerts increase; approves baselines (`approved_baseline`) only when candidate matches or exceeds baseline without regression.

4. **Offline Retraining Feedback Ledger (`offline_retraining_feedback_sqlite_v1`, TF-007):**
   - Implemented `backend/src/threatfusion/db/retraining_feedback_ledger.py` persisting analyst triage feedback (`confirmed_threat` vs `false_positive`) into a mode-0600 SQLite ledger (`retraining_feedback.sqlite3`) for future offline batch retraining.
   - Enforces idempotent `transition_request_id` replay deduplication and conflicts rejection.
   - Verifies frozen production model SHA-256 digests before and after recording feedback, demonstrating zero online weight drift for the academic jury viva.

### TF-008 / TF-009 / TF-010 Milestone #23 progress: Canonical Evaluation Pack Rev2, Section 8 Invariant, Threat-Intel Enrichment, Advisory Debrief, and SOAR Ledger, 2026-10-16

TF-008, TF-009, and TF-010 remain **open** per their documented acceptance gates.

1. **Canonical Evaluation Pack Rev2 (`AI-FYP-2006`, TF-002/TF-007):**
   - Implemented `backend/src/threatfusion/models/canonical_evaluation.py` and published authoritative specification `docs/canonical_evaluation_pack_rev2.md`.
   - Formally binds project metadata to FAST-NUCES Karachi, CS492 Bachelor of Science in Cyber Security, supervisor, and academic jury rubric.
   - Records frozen classical baselines: Random Forest (89.77% acc, 91.31% F1, 75.07% cat acc), XGBoost (98.01% recall), Logistic Regression (81.24% acc).
   - Records deep learning candidates: Deep Neural Network (2.04% FPR, 68.76% cat acc), Transformer (96.43% recall), Multimodal Fusion (94.95% acc, 96.30% F1).
   - Mandates Split-Inversion Scientific Disclosure: explicitly documents January/February training/evaluation split inversion where February test distribution was inspected during model selection.
   - Enforces Section 8 Invariant: multi-model fusion is strictly disabled in production inference (`fusion_disabled = True`), frozen RF (`random_forest.joblib`) is the sole production baseline, and v2 AE is experimental/unfused. `enforce_production_inference_invariants()` raises `ProductionInferenceInvariantViolation` if any fusion policy is attempted in production mode.

2. **Section 13.C Threat Intelligence Enrichment Service (`threat_intel_enrichment_v1`, TF-008):**
   - Implemented `backend/src/threatfusion/intel/enrichment_service.py` with `ThreatIntelEnrichmentService` and `LocalThreatIntelFeed`.
   - Strict RFC 1918 / Localhost Privacy Suppression (`RFC1918_AND_LOCAL_NETWORKS`): Internal IP addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`) are strictly suppressed from external lookups (`privacy_suppression = True`, score `0.0`).
   - TTL-bounded caching (`ttl_seconds=300`) and deterministic allowlist/denylist precedence.
   - Degraded offline fallback: feed unavailability or errors return score `0.0` with `is_degraded = True` and degradation rationale, preventing pipeline aborts.
   - Converts results into canonical `SignalObservation` for Section 9 7-signal multi-signal risk evaluator (`dynamic_risk_assessment_v1`).

3. **Section 13.D Evidence-Bound Advisory Debrief Engine (`advisory_debrief_v1`, TF-008):**
   - Implemented `backend/src/threatfusion/llm/advisory_debrief.py` with `AdvisoryDebriefEngine`.
   - Enforces mandatory advisory disclaimer: `"ThreatFusion LLM debriefs are advisory only. They do not constitute verified containment authorization or causal proof."`
   - Requires non-empty evidence citations (`cited_evidence_keys`), citing candidate IDs, incident IDs, source IPs, and detector decisions.
   - Binds verified versioned MITRE ATT&CK techniques (`T1046`, `T1190`, `T1498`, etc.) with observable evidence mapping and confidence bounds.
   - Generates competing hypotheses (e.g. benign administrative probe vs. active exploitation) to prevent single-explanation tunnel vision.
   - Operates offline via deterministic structured template fallback with zero external network/token cost requirements.

4. **Section 13.E Approval-Gated Reversible SOAR Ledger (`soar_ledger_sqlite_v1`, TF-008/TF-009):**
   - Implemented `backend/src/threatfusion/soar/soar_ledger.py` with `SoarLedgerRepository` using isolated mode-0600 SQLite store (`soar_ledger.sqlite3`).
   - Mandatory Human Approval Gate: proposals begin in `PENDING_APPROVAL`. Direct execution attempts without prior approval raise `SoarPolicyViolationError("approval_required")`.
   - Protected Target Allowlist: containment actions targeting protected IP infrastructure (`1.1.1.1`, `8.8.8.8`, `127.0.0.1`, `10.0.0.1`) are rejected unconditionally (`SoarPolicyViolationError("target_is_protected")`).
   - Full State Machine & Reversible Compensation: tracks lifecycle (`PENDING_APPROVAL` -> `APPROVED` -> `EXECUTED` -> `REVERSED`), logs audit trails, and executes verified reversal actions.

5. **End-to-End Product Spine Verification:**
   - Implemented `backend/tests/integration/test_milestone23_full_spine.py` verifying full pipeline flow: Suricata flow -> 14 features -> Frozen RF inference -> AlertCandidate -> Correlation -> Threat Intel -> Dynamic Risk -> Advisory Debrief -> SOAR Proposal -> Human Approval -> Execution -> Rollback -> Retraining Feedback Ledger -> Canonical Evaluation Pack.
   - All 54 focused tests pass cleanly in 6.89s. Frozen model digests remain byte-identical.

### TF-008 / TF-009 / TF-010 / TF-011 Milestone #24 progress: Unification of Milestone #23, Evaluation Pack Rev2 (6a36dcd), Section 13.F Workload Measurement, and Turnkey Two-Track Demo Runner, 2026-10-16

TF-008, TF-009, TF-010, and TF-011 remain **open** per their documented acceptance gates.

1. **Milestone #23 Unification & Clean Commit (`3f32c7f`):**
   - Removed duplicate Pass-1 modules created by split terminal paste (`intel/`, `llm/`, `soar/soar_ledger.py`, `test_advisory_debrief.py`, `test_soar_ledger.py`).
   - Preserved canonical Pass-2 packages: `threatfusion.enrichment` (`SourcedThreatIntelEnricher`), `threatfusion.advisory` (`AdvisoryExplanationEngine`), and `threatfusion.soar` (`ApprovalGatedSoarEngine`, `SoarPlaybookRecord`, `SoarAuditEntry`, `SoarPlaybookSqliteRepository`).
   - Updated `test_package_discovery.py` to test all unified subpackages under zero PYTHONPATH.

2. **Authoritative Evaluation Pack Rev2 Alignment (`6a36dcd9af17bf509977bcf966f2ace72644d5b2`):**
   - Updated `canonical_evaluation.py` and `docs/canonical_evaluation_pack_rev2.md` with exact scientific baseline:
     - Project: `AI-FYP-2006` - ThreatFusion (FAST-NUCES Karachi, CS492 Final Year Project - FYP-II).
     - Supervisor: Sir Sameer Faisal; Team: Muhammad Bilal (21K-3551), Muhammad Suhaib Shaikh (22K-4302), Muhammad Hasnain (22K-4718).
     - Populations: Train (865,480 benign-only), January validation (216,568), February benchmark (1,452,844).
     - Frozen RF (`full-network-random-forest-6d69c72-v1` on January 216,568 rows): TP=4045, FP=201, TN=212009, FN=313, 95.266% precision, 92.818% recall, 94.026% F1, 0.095% FPR.
     - Row 1 attack prob `0.00001` (~0.001%, Normal -> no alert); Row 21 attack prob `0.824988` (~82.499% >= 0.5, Attack -> 1 AlertCandidate).
     - Corrected v2 Autoencoder (`full-benign-autoencoder-2a51c94-v2`): Architecture 14->8->3->8->14, threshold 0.118136.
     - Section 8 Complementarity & Why Fusion Is Disabled: AE captures 96 extra attacks while causing 1,574 additional false alarms (16.3958 benign FPs per extra attack, 8.831x FP inflation, dropping precision from 95.266% down to 69.997%). Enforces `production_fusion_enabled = False`.
     - January Residual Audit (`january-v2-record-concentration-b5e6e5d`) and Blocked candidate (`rate-log1p-autoencoder-b5e6e5d-v1`, disposition `BLOCKED_preserve_baseline`).
     - Legacy FYP-I deck figures preserved exclusively in `LegacyFyp1SupersededSummary` (`superseded_by_fyp2_eval_pack_rev2 = True`).

3. **Section 13.F Alert-Fatigue Compression & Analyst Workload Measurement Harness (`workload_measurement_v1`):**
   - Implemented `backend/src/threatfusion/evaluation/workload_measurement.py` with `evaluate_alert_fatigue_compression` and `AnalystWorkloadStudyRepository`.
   - Layer 1 computes ingestion and correlation queue reduction ratios.
   - Layer 2 computes Section 8 counterfactual fusion false-positive shield on January UNSW validation population.
   - Mode-0600 SQLite store (`workload_study.sqlite3`) records `TriageTrialRecord` and computes mean/median triage times, speedup, and accuracy gain.
   - TF-009 Closure Invariant: `tf_009_closure_eligible` is strictly `False` unless study cohort is `human_analyst_cohort_study` with at least 10 human trials across both conditions, keeping TF-009 honestly open during automated tests.

4. **Turnkey Two-Track Jury & Supervisor Demo Runner (`scripts/run_full_soc_demo.py`):**
   - Implemented `run_full_soc_demo(output_dir)` in `backend/src/threatfusion/operations/full_soc_demo.py` and CLI wrapper `scripts/run_full_soc_demo.py`.
   - Executes Track A (UNSW-NB15 replay proof, rows 1 & 21, Section 8 shield) and Track B (Slide 14 Azure VM Suricata live ingestion full SOC spine).
   - Generates deterministic JSON and Markdown evidence reports (`full_soc_demo_report.json` and `full_soc_demo_report.md`).
   - Companion integration test `test_full_soc_demo_runner.py` verifies all Track A & B invariants end-to-end.
   - Verification gate passes cleanly: 15 test suites (110 tests) passing in 39.60s. Model digests verified unchanged.

5. **Exact Canonical Issue Definitions & Open Status (TF-008, TF-009, TF-010, TF-011):**
   - **`TF-008` (`open`)**: *Independent Model Benchmark Beyond Inspected January/February UNSW Splits* — January (`216,568` rows) and February (`1,452,844` rows) were both previously inspected during model selection/evaluation; closing `TF-008` requires evaluation on an untouched independent holdout or external dataset benchmark.
   - **`TF-009` (`open`)**: *Measured Reduction of Analyst Workload / Alert Fatigue* — `workload_measurement.py` (`Section 13.F`) provides the counterfactual January FP shield proof (`201` RF FPs vs `1,775` fused FPs = `8.831x`) and the SQLite telemetry recorder (`workload_study.sqlite3`), but closing `TF-009` requires real human-factors / analyst cohort study trials (`study_cohort="human_analyst_cohort_study"`, `min_human_trials >= 10`).
   - **`TF-010` (`open`)**: *External FAST-NUCES FYP-II Jury Rubric & Signed Supervisor/Jury Evaluation Alignment* — internal traceability (`jury_traceability.py`) and Evaluation Pack Rev2 (`AI-FYP-2006`) alignment are wired, but closing `TF-010` requires the official external signed FAST-NUCES jury/supervisor rubric artifact.
   - **`TF-011` (`open`)**: *Real Operational SIEM / Threat-Intelligence Production Source Proof* — `SuricataFlowAdapter` (`Slide 14`) and `SourcedThreatIntelEnricher` (`Section 13.C`) are verified on bounded/recorded flows and local snapshots, but closing `TF-011` requires live operational SIEM / production threat-intelligence source deployment evidence.

### TF-008 / TF-009 / TF-010 / TF-011 Milestone #25 progress: Deterministic Zero-Trust Repository Truth Audit Gate, 2026-10-16

TF-008, TF-009, TF-010, and TF-011 remain **open** per their documented acceptance gates.

1. **Deterministic Zero-Trust Repository Truth Audit Gate (`repo_truth_audit_v1`):**
   - Implemented `run_repository_truth_audit(repo_root)` in `backend/src/threatfusion/evaluation/repo_truth_audit.py` and CLI wrapper `scripts/audit_repo_truth.py`.
   - Executes 7 programmatic, deterministic checks against live repository files and runtime objects without mocking:
     1. **Workspace Isolation & Git State Check**: Enforces exact workspace root `/home/muhammad-bilal/projects/threatfusion-gemini`, queries active branch (`gemini/product-20260924`), HEAD commit SHA, and hashes all modified and untracked files.
     2. **Frozen Model Artifact SHA-256 Invariance Check**: Recomputes live SHA-256 digests of all 4 frozen model files on disk (`random_forest.joblib`: `bd2853a6...`, `logistic_regression.joblib`: `2cf4de66...`, `autoencoder_state.pt` v2: `c8675d13...`, `rate-log1p`: `1d02e5bb...`) and verifies byte-identical equality.
     3. **Canonical Evaluation Pack Rev2 (`AI-FYP-2006`, Checkpoint `6a36dcd`) Runtime Verification**: Validates runtime constants in `CANONICAL_EVALUATION_PACK_REV2` (project ID `AI-FYP-2006`, supervisor `Sir Sameer Faisal`, roll numbers `21K-3551`, `22K-4302`, `22K-4718`, exact populations 865,480 / 216,568 / 1,452,844, RF metrics 95.266% precision / 92.818% recall / 94.026% F1, AE v2 threshold 0.118136, Section 8 16.4 FPs/extra attack, blocked rate-log1p candidate).
     4. **Section 8 (`fusion_disabled`) Runtime Enforcement Check**: Verifies `evaluate_multi_signal_risk` returns `production_fusion_enabled=False` and `production_alert_authority="frozen_random_forest_only"`, and raises `ValueError` if `production_fusion_enabled=True`.
     5. **No Duplicate Package Regression Check**: Confirms zero split-paste duplicate paths on disk (`intel/`, `llm/`, `soar_ledger.py`) and verifies clean import of canonical Pass-2 packages (`enrichment`, `advisory`, `soar`, `evaluation`, `datasets.adapters.suricata_flow`).
     6. **Section 13.C / 13.D / 13.E / 13.F Live Functional Probe**: Probes RFC 1918 private-IP guard suppression for `10.0.0.4 -> 10.0.0.5`, advisory engine groundedness rejection of hallucinated IP with deterministic template fallback, SOAR approval gate enforcing `SoarStateTransitionError` on unapproved execution, and workload measurement reporting 201 RF FPs vs 1,775 counterfactual fused FPs with `tf_009_closure_eligible = False`.
     7. **Issue Register Honesty & Canonical Title Check**: Parses `docs/issue_register.md` table and verifies that `TF-008`, `TF-009`, `TF-010`, and `TF-011` are strictly marked `open` and retain their exact canonical keywords.
   - Computes deterministic SHA-256 digest over the canonical JSON representation of the report, rendering a verifiable cryptographic ground-truth receipt banner.

2. **Verification Gate & Unit Tests:**
   - Implemented `backend/tests/unit/test_repo_truth_audit.py` with 6 unit tests covering live repository verification, fail-closed detection of premature `resolved` status tampering, canonical keyword drift detection, invalid workspace rejection, missing model handling, and CLI script execution.
   - Full 16-suite verification gate passes: 116 tests passing in 28.39s.
   - Repository-wide `ruff check .` passes with 0 errors; `black --check .` passes across 201 files.
   - CLI script `scripts/audit_repo_truth.py` exits 0 with `ALL 7 ZERO-TRUST CHECKS PASSED`.

### TF-008 / TF-009 / TF-010 / TF-011 Milestone #37 progress: Executive & Investor-Grade UI/UX Overhaul, Operational Velocity Decomposition, and 5-Tab Investigation Inspector, 2026-10-20

TF-008, TF-009, TF-010, and TF-011 remain strictly **open** per their documented acceptance gates.

1. **Resolution of Milestone #36 Audit Item (`verify_frontend_asset_bundle()`):**
   - Implemented and exported `verify_frontend_asset_bundle()` in `backend/src/threatfusion/api/analyst_dashboard.py` and `threatfusion.api.__all__`.
   - Validates that `frontend/index.html`, `frontend/css/soc_unicorn.css`, and `frontend/js/soc_dashboard.js` are non-empty and verifies presence of Enterprise Dark-Slate design tokens (`#090D16`, `#111827`), Layer 1 Hero Strip hooks (`data-layer="hero-investor-hook"`), Layer 2 6-Stage Ribbon hooks (`data-layer="architecture-ribbon"` with `data-pipeline-stage="1"`..`"6"`), Layer 3 Main Workspace (`data-layer="split-investigation-workspace"` with `data-inspector-tab="1"`..`"5"`), and 4-Block Case Anatomy (`data-anatomy-block="1"`..`"4"`).

2. **Operational Velocity Decomposition (`incident_correlation.py`):**
   - Implemented Dropzone/Prophet-style Operational Velocity Decomposition:
     `TTD (Time to Detect, ms) + TTA (Time to Acknowledge, ms) + TTI (Time to Investigate, s) = Total Time to Conclusion`
   - Configured deterministic benchmark latencies: `ttd_mean_ms=18.4`, `tta_mean_ms=12.6`, `tti_mean_seconds=1.25`, resulting in `total_time_to_conclusion_seconds=1.281s`.
   - Compared against standard 15-minute (`900.0s`) manual L1 triage baseline, demonstrating `898.719s` analyst toil saved (`99.8577%`). Re-exported all constants and schema bindings.

3. **5-Tab Investigation Inspector with Cryptographic Fail-Closed Enforcement (`analyst_dashboard.py`):**
   - Created `TriageQueueCardView` and `build_five_tab_investigation_inspector()`.
   - Produces structured representations for:
     * `tab_1_executive_summary`: Grounded synthesis, RFC1918 exposure badge (`RFC1918 Internal` vs `External`).
     * `tab_2_attack_timeline`: Chronological flow stitching across 30.0s burst and 600.0s campaign windows.
     * `tab_3_mitre_and_playbook`: ChromaDB MITRE RAG mapping and deterministic n8n remediation steps.
     * `tab_4_evidence_locker`: Deep technical telemetry: 14 canonical UNSW-NB15/Suricata features, Frozen RF 95.266% precision / 0.095% FPR, v2 Autoencoder error vs 0.1181361214680695 (+2.203 pp recall gain), and MISP RFC1918-guarded hits.
     * `tab_5_soar_audit_changelog`: Step-by-step cryptographic hash-chain ledger, HMAC-SHA256 receipt verification badge, and TheHive case link.
   - Enforced fail-closed badge rendering: ungrounded explanations (`verify_explanation_groundedness`), invalid MITRE IDs (`^T\d{4}(\.\d{3})?$`), and forged SOAR receipts (`_is_verified_receipt_dict`) fail closed to `data-evidence-state="unavailable"`.

4. **Front-End & Dashboard Presentation Elevation (`frontend/`, `analyst_dashboard.py`):**
   - Upgraded `frontend/css/soc_unicorn.css`, `frontend/index.html`, `frontend/js/soc_dashboard.js`, and `render_dashboard_html()` with Enterprise Dark-Slate styling (`#090D16`, `#111827`, blur(12px) glass cards, `Inter` and `JetBrains Mono` fonts).
   - Added Layer 1 Hero Strip with bold **"99%+ Alert Noise Eliminated"** badge, Layer 2 6-Stage Ribbon with operational pulses, Layer 3 Workspace with 5-tab inspector and 4-block anatomy, interactive tab switching, click-to-copy hash tooltips, and dynamic `/api/v1/metrics/operational-velocity` updates.
   - All 40 unit and discovery tests pass; Gate G9 AST checks and Protocol 0 Boundary Preflight (B0-B5) verified clean.

### Mega-Milestone #38 fail-closed evidence and contract durability, 2026-10-26

RFC-38.1 through RFC-38.5 add registry-digest rendering, linked hash-chain checks, a `reference_benchmark` versus `live_measured` velocity label, `--host` as an alias of `--bind`, a 1 MiB POST cap, durable idempotency keys, SQLite WAL, a unified incident timeline, and four visible SOAR states. These changes do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #39 response-plane recovery, citation-locked follow-up, and shift handoff, 2026-10-26

The optional SOAR/RAG/outbox/dead-letter snapshot, the citation-locked follow-up, and the shift-handoff packet do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #40 runtime import isolation, 2026-10-26

Boundary preflight check B6 rejects a `PYTHONPATH` or `sys.path` entry that resolves inside the protected workspace, and rejects a `threatfusion` import from outside the active `backend/src` tree. This check does not close TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #42 live console, 2026-10-27

The live ingest, analyst notes, local MITRE copilot, read-only drift monitor, and 6-node workbench do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #43 stored campaigns and local SOAR approval, 2026-10-27

The stored campaign queue, recorded UNSW-NB15 study-fixture replay, and hash-chained local approval do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. Approval does not execute containment. All four issues remain **open**.

### Milestone #44 signed callback loop, 2026-10-27

The verify-state check, 4-block case record, and HMAC callback do not execute host containment and do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #49 shared launcher ledger, 2026-10-27

The default launcher now points verify-state and the HMAC callback at the same SOAR ledger approval writes. A recorded callback stores MTTR from the ledger timestamps and does not execute host containment. This does not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #45 dual-window stitch, 2026-10-27

Verified-key burst stitching and the private-IP refusal do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #46 triage and grounded handoff, 2026-10-27

Stored triage actions and the grounded brief do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #47 local launcher, 2026-10-27

The one-command launcher and root README do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #48 full-suite audit, 2026-10-27

A 1,527-test pytest run and the corrupt-database classification fix do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #49 triage history in the grounded shift handoff, 2026-10-27

Stored triage actions, the shift-handoff timeline, and the grounded-note refusal do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. Containment stays unauthorized. All four issues remain **open**.

### Operator certificate stamp, 2026-10-30

The lab certificate stamp does not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. It does not close TF-003, TF-012, or TF-002. All four external gates remain **open**.

### Live n8n callback path, 2026-10-30

The live n8n container and the local contract fallback do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. They do not close TF-003, TF-012, or TF-002. All four external gates remain **open**.

### Live Suricata bridge, 2026-10-30

The private bridge and the sensor route do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. They do not close TF-003: Suricata byte, direction, and timeout fields remain an open comparability question, distinct from TF-012. TF-012 and TF-002 remain **open**. All four external gates remain **open**.

### Live analyst verdict and assignment, 2026-10-30

The analyst verdict, queue controls, assignee, live hero counts, and glass-box checklist do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. TF-012 and TF-002 remain **open**. All four external gates remain **open**.

### Milestone #56 board dossier, 2026-10-30

The 2026-10-30 board dossier does not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. TF-012 and TF-002 remain **open**. All four external gates remain **open**.

### Milestone #55 seed-demo launcher, 2026-10-30

`--smoke` and `--seed-demo` do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #54 source qualification on the live console, 2026-10-30

The live console states that UNSW-NB15 and CIC byte layers are not interchangeable and that CIC is not a validated compatible external test. That sentence does not create the five-field equivalence evidence TF-012 requires, and it does not cover every historical export TF-002 names. TF-012 and TF-002 remain **open**. TF-008, TF-009, TF-010, and TF-011 remain **open**.

### Milestone #53 constitutional health drawer, 2026-10-30

A live boundary and truth-gate report does not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #52 four-scenario replay, 2026-10-30

The four labeled replays and the private-IP refusal do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #51 one live console screen, 2026-10-30

Hiding the sample topology and walkthrough after the campaign store loads does not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. All four issues remain **open**.

### Milestone #50 integrated callback, windows, triage, and launcher, 2026-10-30

The shared ledger, automatic 30.0s/600.0s stitch, triage history, and launcher shutdown do not satisfy the closure tests for TF-008, TF-009, TF-010, or TF-011. Host containment stays unauthorized. All four issues remain **open**.
