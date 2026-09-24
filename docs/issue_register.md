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
| TF-008 | P0 / critical | **Demo/acceptance gap; bounded producer serving, per-alert state and separate human mTLS analyst listener implemented through 2026-09-24.** The [producer protocol](producer_admission_transport_policy.md) retains bounded replay/inference/persistence and cleanup. The [analyst-state contract](alert_correlation_analyst_state.md) and [human transport](analyst_authentication_transport.md) provide credential-bound viewer reads and analyst transitions through a local one-request listener. Retained alerts have no defensible distinct-alert relationship key, so no incident/window claim is made. Explanation, browser/dashboard integration and operational credential deployment remain absent. Azure remains disabled. | Core product, demo readiness, usefulness claims | Independently review the human boundary, then integrate the authenticated path with an operator dashboard and required failure/evidence presentation; separately obtain a reviewed relationship key before proposing correlation. | One authenticated supported input reaches the dashboard with reconciled identity/status; authentication/admission failures have zero predictor/repository calls; failures are visible; optional services can be off; replay/duplicates are idempotent; bounded resource evidence is recorded. | open |
| TF-009 | P1 / high | **Reliability evidence gap; bounded serving cleanup/restart and analyst-state transaction/reopen behavior implemented through 2026-09-23.** Serving regressions cover startup/readiness, graceful drain, overlap, replay, worker failure/timeout and resource cleanup. Analyst-state regressions cover atomic state/history writes, exact replay, concurrent version conflicts, rollback and schema-checked restart persistence. The short serving workload remains the only measured resource sample. This does not establish endurance, frozen operational limits, service-manager/signal behavior, cross-database snapshot/backup/recovery, audit export/retention/rotation, or optional-service outages. | Core workflow, demo reliability, deployment claims | Preserve terminating isolation and atomic state history; add the remaining operational resource, service-entry, backup/recovery and degradation evidence under separately bounded milestones. | The charter's malformed/partial-input, mismatch, offline-service, restart/replay, idempotency, interruption, timeout, concurrency/rate/body/queue, database backup/recovery and measured-resource cases pass end to end. | open |
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
