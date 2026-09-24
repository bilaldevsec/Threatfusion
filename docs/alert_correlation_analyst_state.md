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
