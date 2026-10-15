# Alert correlation boundary and analyst-state contract

## Milestone decision

This milestone does **not** correlate distinct alerts and does not create incidents. The supported
`alert_candidate_v1` persistence contract deliberately omits endpoints, hosts, accounts, sessions,
flow identity, attack category and other reviewed relationship keys. `observed_at` alone cannot
establish a relationship, and `correlation_id` is an inference-attempt UUID rather than an event,
entity or campaign identity. Grouping distinct candidates by time, model, score, source dataset or
creation order would therefore invent a relationship that the retained evidence cannot support.

The independently useful product boundary implemented here is a local, per-alert analyst workflow.
It refers to an immutable `AlertCandidate` by its stable `alert_candidate_id` and stores analyst state
and annotations in a separate SQLite repository. It does not change detection evidence, producer
admission, inference, alert creation, model artifacts, decision policy or replay behavior.

## Correlation input and non-grouping rule

All fields admitted to any future correlation design must first be validated immutable fields from
`alert_candidate_v1`. Within that contract:

- `source_event_id` identifies one registered offline row;
- `alert_candidate_id` identifies one source-event/detector/model/artifact/policy decision;
- `observed_at` is the registered row's UTC observation time;
- detector, model, artifact, feature-contract and source-representation identities describe how the
  decision was produced;
- `created_at` is local persistence-attempt time, `correlation_id` is an inference-attempt identifier,
  and the uncalibrated model score is not probability, severity or relational evidence.

None of those fields is a defensible key for relating two distinct candidates. The exact rule for
this version is consequently: equal `alert_candidate_id` values are duplicate persistence attempts
for one candidate and are handled by `AlertCandidateRepository`; unequal IDs are never grouped. There
is no correlation time window, because no correlation is performed. No incident identity is derived
or emitted. This is identity deduplication, not a singleton-incident claim.

Missing candidate identity produces no analyst state. Conflicting content for one candidate identity
continues to fail in the alert repository. Reordered candidate arrivals remain independent and the
alert list retains its existing `(created_at, alert_candidate_id)` order. Exact candidate replay keeps
the first immutable candidate. These behaviors do not prove a shared attacker, campaign, host,
session, technique or cause; absence of grouping does not prove events are unrelated.

A future correlation contract requires a separately reviewed, retained relationship key and its
provenance, privacy, missing-value, conflict, clock-quality and window semantics. The existing
`host_event_v1` type is not enough: host events do not currently enter this supported alert repository
and its grouping/window rules remain unresolved.

### Retained relationship-evidence audit, 2026-09-27

The supported producer accepts a registered raw-member SHA-256 and one-based row ordinal.
Its request ID, producer ID, `produced_at`, nonce and admission `received_at` bind the
request/replay journal, not a host or event relationship in `AlertCandidate`.
The verified reader maps the row to a temporary `NetworkFlow`, including source and
destination addresses/ports, protocol, flow ID and start/end times. The private
feature projection uses destination port and protocol but does not retain that
vector in the candidate. Only the row's numeric `stime`, parsed as UTC
`observed_at`, crosses with the opaque `source_event_id`; the end time and
endpoint/flow fields do not. The source-event digest binds the representation,
manifest digest, member digest and ordinal, so equal values mean the **same
registered row**, not the same host across rows. The digest itself does not
carry endpoint or session evidence; recovering row values requires the verified
source material, which is not retained in the alert.

The parent builds an Attack-only candidate with that source-event ID and
`observed_at`, an `alert_candidate_id` additionally bound to detector, model,
artifact and policy identities, a local `created_at`, and an inference-attempt
`correlation_id`. SQLite stores these fields; exact candidate retry returns the
first row and retains its original creation time and attempt UUID. The analyst
view presents candidate/source IDs, observation/creation times and model evidence,
but omits the attempt UUID. Its workflow state and rationale are separate analyst
annotations. Neither the replay journal nor analyst annotation adds a relationship
between distinct observations.

The only supported equality rule remains **same candidate ID plus compatible
stable evidence = one alert's idempotent retry**; conflicting same-ID content
is rejected, with no correlation window. Equal source-event IDs under
different model/artifact/policy identities would refer to different decisions on
one registered row, not two related events; the current product path uses the
frozen RF. Different rows can share `observed_at`, model, score, source
representation, producer or destination service without sharing a host or
incident. `created_at` is processing time; the UUID is an inference attempt.
Those are counterexamples to time-only, model-only, request-only and UUID-based
grouping. No distinct-alert rule, window or incident identity is supported.

Before proposing one, a future supported source must supply an immutable,
validated **scoped observed-entity identifier** (for example, an authenticated
sensor's stable asset ID plus its namespace and source/destination role) bound to
each observation and retained with the alert. The identity must have documented
issuance/mapping provenance, lifetime, privacy treatment, missing/conflict
behavior, and evidence that aliases, address reuse or NAT do not falsely merge
entities. Raw UNSW IP strings alone would not establish that provenance, and
the registered offline replay currently has no authenticated asset namespace.
The observation clock's origin, precision and error bound must also be retained
or verified before choosing a bounded time window. No duration can be justified
from the current fields alone.

Acceptance for a future relationship rule requires a reviewed source contract
and immutable persistence/view binding for those fields; a predeclared rule and
window; and tests that relate independently observed events only when scoped
identity and time evidence agree. Tests must keep different entities apart when
timestamps/model scores match, reject absent or conflicting identity/clock
evidence, enforce window boundaries and replay idempotency, and avoid asserting
shared campaign, attacker or incident without separate evidence. Until then,
different candidate IDs remain independent alerts.

### Registered UNSW source-provenance check, 2026-09-27

The pinned manifest records four official raw CSV member paths, byte hashes and
row counts, plus the official UNSW dataset page; it does not define a capture
segment, sensor, address-assignment domain or asset namespace. The official page
attributes packet generation to IXIA PerfectStorm in the UNSW Canberra Cyber
Range Lab, capture to tcpdump, and 49-feature production to Argus, Bro and other
algorithms. Its feature metadata names `srcip`/`dstip` as record endpoint
addresses, `stime` as record start and `ltime` as record last time. Those are
field descriptions, not proof of host identity, source initiator, attack actor,
clock calibration or a stable address assignment.

The headerless raw CSV has no native ID column. `UnswRawReader` creates
`flow_id=<filename stem>:<one-based row>` solely for row bookkeeping. The
registered inference reader independently uses a verified member hash and row
ordinal, and its adapter checks endpoint address syntax and record source/
destination ports. The adapter computes `timestamp_end` from parsed numeric
epoch `stime` plus `dur`; it does not validate or retain the source `ltime`.
UTC parsing is a code convention, not evidence of the original capture clock's
timezone, synchronization, precision or error bound. The private feature
projection and worker result discard addresses, row `flow_id` and end time;
the alert retains only the row identity and start observation time.

The registered snapshot therefore supports deterministic *row* identity, not
a stable observed entity within a defined capture namespace. Its documentation
does not establish address allocation/translation, reuse or alias lifetime;
the historical Argus version, direction and flow-boundary configuration are
also unbound. Keeping raw addresses would expose endpoint data without filling
those provenance gaps. A reviewed capture/sensor namespace and authenticated
address-to-asset mapping or source-issued stable asset ID, with role, validity
interval, privacy/retention policy and clock-quality evidence, are required
before adding an entity field. No identity contract or correlation window is
introduced by this check.

## Analyst identity and authorization

The local boundary has two fixed roles:

- `viewer` may list alerts and read alert detail and transition history;
- `analyst` has the same read permission and may perform allowed state transitions.

The process-local registry accepts only an exact, enabled actor ID from an already authenticated
caller and issues a registry-bound capability. Unknown, disabled, forged, cross-registry and
viewer transition attempts fail closed. This registry is authorization enforcement, not credential
authentication and not a public API. A future network/dashboard boundary must authenticate a user,
map that identity to this allowlist and never trust a client-supplied actor ID by itself.

At the 2026-09-24 internal view-model checkpoint, no such user-authentication boundary existed. The
only TLS listener authenticated a producer certificate against a producer-only registry and accepted
a fixed ingestion route. Its admitted producer identity, certificate label, or request bytes cannot be promoted into an
analyst actor or capability. There is no accepted client role/user ID/header/JSON field. Therefore no
network analyst endpoint was enabled then. The subsequent adapter requires a separately reviewed user
credential and server-owned mapping from that authenticated identity to an enabled registry entry; it must never
reuse producer credentials for analyst operations.

The subsequent human mTLS demonstration boundary implements that separate adapter; its certificate
verification, allowlist, routes, revocation and browser limits are documented in
[`analyst_authentication_transport.md`](analyst_authentication_transport.md). The internal registry
still does not authenticate a caller by itself.

## State machine and idempotency

Every persisted `AlertCandidate` begins in an implicit `new` state at version 0. The only transitions
are:

```text
new --(analyst)--> in_review --(analyst)--> closed
                                  `-------> escalated
```

`closed` and `escalated` are terminal. Each transition requires the exact current version, an
enabled `analyst` capability, a canonical UUIDv4 transition ID and a non-empty bounded printable
rationale. State changes and append-only transition history commit in one SQLite transaction.

The transition ID is the idempotency identity. Repeating it with the same alert ID, expected version,
target state, actor and rationale returns the stored event and current state without another change.
Reusing it with different content fails as an identity conflict. Two different commands for the same
version serialize: at most one commits and the other receives a version conflict. A command received
before its expected predecessor also receives a version conflict. Skipped, backward, same-state and
post-terminal changes are invalid and create no event. Repository busy waits are bounded to 500 ms and
are not retried internally.

## Evidence, annotations and reads

The alert database remains the immutable detection-evidence authority. The analyst repository stores
only candidate ID, current workflow state/version, transition ID, actor ID, trusted repository time
and analyst-authored rationale. Rationale is annotation, not source evidence, model input, severity,
correlation evidence or an explanation, and it can never modify an `AlertCandidate`. Transition
history is append-only; there is no edit or delete operation in this contract.

The internal read boundary requires a valid `viewer` or `analyst` capability and provides:

- `list_alerts(limit, offset)`: at most 100 immutable candidates in the alert repository's stable
  first-created order, each paired with current analyst state; alerts without a state row appear as
  `new` version 0;
- `get_alert(alert_candidate_id)`: one immutable candidate, its current state and its complete ordered
  transition history, or no result when the candidate does not exist.

The state graph bounds history to two events per alert. Limit and offset remain bounded by the alert
repository contract. The original state milestone added no external HTTP endpoint, state filter,
search, aggregate count, notification, assignment, severity, retention policy or dashboard. It supplies a deterministic
internal list/detail contract for a later authenticated API and UI without claiming that dashboard
acceptance exists.

The internal `analyst_alert_view_v1` formatter now presents that contract as JSON-safe dictionaries.
List responses contain schema version, requested limit/offset and ordered items; detail responses
contain one item and ordered `analyst_history`; transition responses contain disposition, candidate ID,
current state and the applied or replayed event. Each item separates `detection_evidence` from
`analyst_state`. Evidence includes only candidate/source IDs, observation and creation time, source
representation, feature contract, model identity/version/artifact digest, uncalibrated score, threshold,
decision policy and decision. History contains the analyst-authored rationale, actor, sequence, state
change and trusted transition time. Rationale is never copied into detection evidence. The formatter
accepts only an internal registry-bound capability and delegates authorization and all state semantics
to the repository. Known validation/conflict errors become fixed codes; storage and unexpected errors
become `analyst_view_unavailable`, without database paths or raw exceptions. This is internal view-model
preparation only; its capability argument is not an external authentication mechanism.
The later loopback mTLS adapter supplies that external authentication boundary for a bounded local
demonstration without changing the view schema or frozen state rules.

## Failure and restart behavior

An unknown candidate, invalid input, invalid transition, stale version, identity conflict,
unauthorized actor, database corruption/schema mismatch, lock timeout or write failure fails without a
partial state/event commit. The separate analyst database is reopened and schema-checked on restart;
committed state and history survive. Loss of this database loses analyst annotations but does not alter
the immutable alert database. Backup/recovery, cross-database snapshot consistency, audit export,
multi-process endurance and long-running operational behavior remain unverified.

### Factual explanation v1 (2026-09-27)

Authorized detail results add `explanation`, with `schema_version=alert_explanation_v1`,
`alert_candidate_id`, `evidence_sha256`, `status`, `summary`, and `limitations`.
The digest is SHA-256 of the displayed detection-evidence object serialized as
sorted, compact JSON (UTF-8, no NaN). It binds score/threshold and timestamps as
well as identity; it is not a signature or a distinct-alert relationship key.
Analyst state/history are separate and are not explanation inputs. Results are
computed on read, not stored as new detection evidence.

Available means only a factual stored-rule summary: the retained RF identity and
artifact hash match the code-owned approved registry, the candidate ID recomputes,
the feature/source/policy identities match, and the stored Attack score meets the
inclusive frozen 0.5 threshold. This does not reload/hash artifact bytes, verify
original measurement provenance, or perform inference. Existing ingestion verified
the frozen model bundle; this display checks its retained identity. The score is
uncalibrated, not severity or a calibrated attack probability.

Feature values/attributions, causal evidence and source endpoints are not retained;
the page explicitly marks these unavailable. No LLM or MITRE claim is generated.
Unsupported evidence or a generator exception yields a fixed unavailable result.
Missing, modified, wrong-version or differently bound results are unavailable at
the dashboard parser. Neither failure changes the model decision, immutable alert,
analyst state or history; the authenticated detail page remains readable. Existing
backend failures still follow the browser's unavailable/503 contract.

## Authenticated Entity-Bearing Telemetry Contract and Dual-Window Correlation Engine (Milestone #18, TF-008)

Milestone #18 implements the fail-closed dual-window correlation engine and authenticated entity provenance contract
in `backend/src/threatfusion/alerts/correlation_engine.py`, surfacing incident metadata into `AnalystAlertViewModel`
and the analyst browser dashboard without weakening existing immutable alert schemas or making false correlation claims.

### 1. Scoped Entity Provenance Contract (`EntityProvenanceContract`)

To prevent the false grouping of distinct entities or unverified network traces, any candidate entering correlation
must present a structured `EntityProvenanceContract`:
- `entity_namespace_id`: Explicit sensor/asset namespace ID (e.g. `edge-router-01`, `sensor-karachi-01`).
- `clock_synchronized`: Boolean asserting that observation timestamps originate from an authenticated, NTP/PTP-synchronized clock.
- `src_entity_id`: Authenticated source host/asset identifier (IP, MAC, or asset UUID).
- `dst_entity_id`: Authenticated destination host/asset identifier.
- `protocol`: Transport protocol (e.g. `tcp`, `udp`, `icmp`).
- `service_or_port`: Destination port or service name (e.g. `80`, `443`, `ssh`).
- `observed_at_utc`: ISO-8601 UTC observation timestamp string.

**The UNSW-NB15 Fail-Closed Singleton Guarantee:**
Raw UNSW-NB15 dataset rows lack authenticated sensor namespaces, lack clock synchronization guarantees, and lack verifiable
entity lifetime/NAT-free mappings. Under `is_verified()`, if `entity_namespace_id` is missing, `clock_synchronized` is false,
or endpoints are absent, the correlation engine refuses to merge the alert with any other alert. Every unverified alert is
assigned to an isolated singleton incident (`correlation_mode = "singleton_unverified_provenance"`, `window_type = "none"`,
`constituent_alert_ids = (alert_candidate_id,)`). Zero false merges occur across synthetic or unverified rows.

### 2. Dual-Window Correlation Architecture

When alerts carry verified provenance (`is_verified() is True`), they are grouped strictly within matching `entity_namespace_id`
boundaries under two predeclared temporal windows:

1. **30-Second Burst Window (`BURST_WINDOW_SECONDS = 30.0`)**:
   - Relationship key: `(entity_namespace_id, src_entity_id, dst_entity_id, protocol, service_or_port)`.
   - Window duration: $\Delta t \le 30.0$ seconds from the anchor alert.
   - Result: Collapses high-frequency network bursts and port floods into a single burst incident (`window_type = "burst_30s"`, `correlation_rule_id = "corr_burst_5tuple_30s_v1"`).
2. **10-Minute Campaign Window (`CAMPAIGN_WINDOW_SECONDS = 600.0`)**:
   - Relationship key: `(entity_namespace_id, frozenset({src_entity_id, dst_entity_id}))`.
   - Window duration: $\Delta t \le 600.0$ seconds from the anchor alert.
   - Result: Correlates multi-port, multi-service lateral movement and reconnaissance across host pairs into a campaign incident (`window_type = "campaign_600s"`, `correlation_rule_id = "corr_campaign_entity_pair_600s_v1"`).

**Strict Cross-Namespace Isolation:**
Alerts from different namespaces (e.g. `sensor-a` vs `sensor-b`) never correlate, even if timestamps, IPs, and ports match identically.

### 3. Empirical Alert Fatigue Reduction Metric and 100% Critical Scenario Retention Safety Gate

The correlation engine evaluates every batch with `compute_alert_reduction_metrics`:
- **Alert Fatigue Reduction Ratio**:
  $$\text{Reduction Ratio} = 1.0 - \frac{\text{Total Incidents}}{\text{Total Alerts}}$$
- **100% Critical Scenario Retention Safety Gate**:
  The engine verifies that:
  - Every input alert candidate is accounted for in exactly one output incident (`alerts_accounted_for == total_input_alerts`).
  - No critical/attack alert is ever dropped or orphaned (`critical_retention_ratio == 1.0`). If any attack alert is omitted, the engine raises `CorrelationSafetyError("critical_alert_dropped")`.
  - Every incident inherits the maximum uncalibrated model score of its constituents (`max_probability_score = max(score)`).
  - If any constituent alert has `decision == "Attack"`, the correlated incident's `escalated_decision` is deterministically `"Attack"` (zero-downgrade invariant).

### 4. Incident SQLite Persistence (`IncidentSqliteRepository`)

Correlated incidents are transactionally persisted to SQLite (`incidents.sqlite3`) with file permissions `0600`:
- `incidents`: Stores `incident_id`, `schema_version`, `correlation_mode`, `window_type`, `correlation_rule_id`, `entity_namespace_id`, `constituent_alert_count`, `max_probability_score`, `escalated_decision`, `first_observed_at`, `last_observed_at`, and `created_at`.
- `incident_constituent_alerts`: Maps `incident_id` to `alert_candidate_id` with sequence indexing.
- Provides idempotent insertion and indexed lookups by `incident_id` or `alert_candidate_id`.

### 5. View Model & Dashboard Integration

- `AnalystAlertViewModel.get_alert(...)` queries `IncidentSqliteRepository` to surface `incident_correlation` metadata in the alert detail response.
- If an alert candidate lacks a correlated incident record (e.g. raw UNSW-NB15 alerts), the view model automatically defaults it to `singleton_unverified_provenance` with an explicit notice: `"UNSW-NB15 raw telemetry lacks authenticated entity endpoints and clock synchronization; evaluated as an isolated singleton incident."`
- The browser dashboard (`analyst_dashboard.py`) renders an **Incident Correlation &amp; Provenance** section displaying correlation mode, window type, rule identity, constituent count, provenance status badges (`verified_entity_bearing` / `unverified_provenance`), and explanatory narrative.

### 6. Supported Source Provenance Adapters & Complete Section 8 Correlation Gate (Milestone #20)

Milestone #20 implements the full Phase P3 and Phase P4 requirements from `docs/GEMINI_PROJECT_MASTER.md`:

1. **Supported Source Provenance Adapters (`provenance_sources.py`):**
   - **`MordorScenarioAdapter`**: Normalizes supported Mordor host/security events bound to specific scenario captures, with explicit `source_mode = "scenario_replay"`, `scenario_id`, `entity_namespace_id = f"mordor:{scenario_id}"`, entity endpoints, validity intervals, clock origin (`"utc_event_log"`), and clock synchronization evidence. Rejects missing endpoints, invalid timestamps, or wrong modes with `SourceRowValidationError`.
   - **`AuthorizedLabSensorAdapter`**: Normalizes real or lab sensor events gated by an allowlisted `RegisteredSensorManifest`. Enforces pre-registered `sensor_id` validation, duplicate `source_event_id` detection, and strict separation between dataset/scenario replay and authorized lab sensors (`source_mode = "authorized_lab_sensor"`).
2. **Address Reuse / NAT & Entity Validity Interval Enforcement:**
   - If `address_reuse_or_nat is True` (e.g. unmapped NAT gateway or DHCP lease churn without host identity), or if `observed_at_utc` falls outside `[validity_start_utc, validity_end_utc]`, the engine fails closed into `singleton_unverified_provenance` with specific provenance status (`"nat_address_reuse_ambiguous"` or `"outside_entity_validity_interval"`).
3. **Clock Skew Tolerance Gate:**
   - `max_clock_skew_seconds <= 5.0` is tolerated under synchronized clocks (`MAX_ALLOWABLE_CLOCK_SKEW_SECONDS = 5.0`). Exceeding this bound fails closed to `singleton_unverified_provenance` (`"clock_skew_exceeded"`).
4. **Candidate Deduplication vs. Incident Grouping:**
   - Repeated submissions of the exact same `alert_candidate_id` collapse cleanly upfront without inflating total alert counts or constituent alert counts.
5. **Exact Boundary Semantics & Out-of-Order Determinism:**
   - Pre-sorting on `(parsed_timestamp, alert_candidate_id)` guarantees out-of-order and late-arriving events produce identical incident clusters.
   - Boundaries: $\Delta t \le 30.0\text{s}$ is included in burst window; $\Delta t = 30.001\text{s}$ is excluded. $\Delta t \le 600.0\text{s}$ is included in campaign window; $\Delta t = 600.001\text{s}$ is excluded and starts a new cluster.
6. **Per-Event Grouping Justification (`MemberJustification`):**
   - Every constituent alert carries an explicit structured `MemberJustification` (`anchor_alert_id`, `delta_seconds`, `matched_relationship_key`, `rule_id`, `provenance_summary`) persisted to `incident_constituent_alerts` in SQLite.
7. **Audited Grouping Correction (`correct_incident_grouping`):**
   - Investigators can manually split erroneously grouped alerts into separate standalone incidents (`correlation_mode = "manual_correction_split"`).
   - Replays with the identical UUIDv4 `correction_request_id` return the existing split incident idempotently, while conflicts raise `CorrelationSafetyError("correction_request_conflict")`.
   - All manual split actions are immutably logged to `incident_grouping_corrections`.
