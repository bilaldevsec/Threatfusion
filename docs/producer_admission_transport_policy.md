# Supported producer admission and bounded transport policy

## Status and scope

This document defines the implementation contract for the first authenticated ThreatFusion producer
boundary under TF-008 and TF-009. The transport-independent schema, certificate registry, bounded body
reader, strict decoder, timestamp/source admission, replay-evidence record, response serializer and
durable request replay journal are implemented internally. The fixed v1 process-local rate bucket and
nonqueueing concurrency gate and the bounded local security-audit repository are also implemented;
this is not an implemented service. No HTTP
listener, live-source adapter or AlertCandidate persistence change exists merely because these
components are present.

Protocol v1 supports only registered-offline UNSW replay on the same Linux workstation as the
ThreatFusion backend. It preserves the existing registered source lookup, trusted 49-column adapter,
frozen inference boundary, Attack-only `alert_candidate_v1`, and SQLite repository. It does not make a
live flow semantically equivalent to UNSW, authenticate physical network measurements, or authorize
CIC, Mordor, arbitrary raw arrays, feature vectors, model selection, or containment.

The planned Azure sensor may use the same mutual-TLS credential model later, but it is **disabled and
not admitted by v1**. A separately reviewed live-source representation, feature-semantics decision,
stable live-event identity, and compatible AlertCandidate identity contract are required before it can
be enabled. In particular, a live sensor must not fabricate the UNSW label, registered member digest,
or row ordinal required by the current offline contract.

## Threat model and claim boundary

The protocol is designed to block unauthenticated network clients; unknown, disabled, expired, revoked,
or producer-mismatched credentials; in-transit request modification; wrong-source submission; stale,
future, replayed, duplicated, oversized, malformed, partial, compressed, or unbounded requests;
connection and iterator interruption; admission races; uncontrolled concurrency/rate; and sensitive
payload leakage through normal errors or audit logs. Durable claims and the final AlertCandidate key
also limit duplicate prediction/persistence and make ambiguous restart state visible.

It does not protect against compromise of the producer or backend host, CA/private-key theft, malicious
trusted code or dependencies, kernel/filesystem/database compromise, denial of service before the TLS
listener can enforce limits, traffic analysis, or an authorized producer deliberately selecting a
different valid registered row. It does not prove that registered dataset observations are authentic
live traffic, detect valid-field positional swaps in a future raw contract, establish cross-source
feature compatibility, provide distributed durability, backup/retention, disaster recovery, Azure
deployment security, analyst authorization, correlation, explanation, dashboard safety, or
containment. These remain separate controls or open evidence gaps.

## Producer and authorization registry

The only v1 producer type is `registered_unsw_replay_v1`: a ThreatFusion-managed replay process running
as a separate unprivileged OS account on the same host. It connects over loopback to a directly
terminating ThreatFusion TLS listener. It may read only operator-selected registered member identities
and row ordinals; it receives no model, database, server private-key, or repository write access.

The initial logical producer ID is `tf-demo-unsw-replay-01`. Deployment configuration, not request
content, maps one client certificate to this ID. The certificate must contain exactly one configured
URI subject-alternative name:

`urn:threatfusion:producer:tf-demo-unsw-replay-01`

Its credential ID is the lowercase SHA-256 fingerprint of the complete DER client certificate. The
fingerprint is an identifier, not a secret. A root-owned allowlist maps `(producer_id, credential_id)`
to producer type, enabled state, validity interval, and allowed source contract. The sole v1 mapping is:

| Producer ID | Type | Allowed source contract | State |
|---|---|---|---|
| `tf-demo-unsw-replay-01` | `registered_unsw_replay_v1` | `unsw_registered_event_ref_v1` | enabled by deployment |
| any Azure sensor ID | future live sensor | none | disabled/unregistered |
| any other ID or credential | unknown | none | rejected |

`unsw_registered_event_ref_v1` is a transport contract for references into the already pinned offline
UNSW manifest. It does not replace the canonical source representation
`unsw_nb15.argus.raw_49.transaction_bytes.v1`; trusted code resolves and verifies that representation
after admission. A known producer with a disabled credential, an unknown certificate, an ID/SAN
mismatch, an expired or not-yet-valid certificate, or a source contract not on that producer's
allowlist is rejected before inference.

## Authentication and credential lifecycle

### Mechanism

The listener must use TLS 1.3 mutual X.509 authentication with a private ThreatFusion demonstration CA.
ThreatFusion terminates TLS itself; v1 does not trust identity headers from a reverse proxy. The server
validates the client chain, certificate time validity, Extended Key Usage `clientAuth`, the exact URI
SAN, and the configured full-certificate fingerprint, then checks the enabled allowlist on **every
request**, including requests on reused TLS connections. Hostname verification and `serverAuth` apply
to the producer's validation of the server certificate.

This uses the established TLS protocol and Python's standard-library `ssl`, `hashlib`, and certificate
decoding facilities rather than a custom signing construction. Directly terminated TLS 1.3
authenticates the peer certificate and integrity-protects the connection bytes carrying the request;
mutual TLS does not create an independent application-level signature over the request. There is no
JSON canonicalization and no application HMAC or signature. After TLS authentication, the application
binds the mapped producer and certificate fingerprint to the exact accepted method, target, headers,
body bytes and interpreted envelope in one immutable admission record. The server records a SHA-256
digest of the exact bounded body bytes only for replay comparison and audit; the digest is not an
authentication substitute.

The current workstation has OpenSSL 3.0.13 available for operator-controlled certificate issuance and
ephemeral test-certificate generation. Runtime verification uses the Python standard library. If the
implementation instead proposes a Python X.509 package such as `cryptography`, that is a new dependency
decision requiring explicit authorization; this policy does not authorize installing it.

The authenticated admission tuple is:

1. TLS-derived `producer_id` and DER-certificate `credential_id`;
2. method `POST` and target `/v1/ingest/unsw-registered`;
3. exact `Content-Type` and `Content-Length`;
4. body fields `schema_version`, `producer_id`, `request_id`, `produced_at`, `nonce`, and
   `source_contract`;
5. SHA-256 of the exact body bytes; and
6. the ordered member-digest/row references in the body.

The body `producer_id` must exactly equal the TLS-derived producer ID. Changing any authenticated tuple
field requires a new nonce and request ID. TLS protects the bytes in transit; the durable replay journal
binds their interpreted identity across connections and process restarts.

### Storage, rotation, and revocation

No CA private key, server private key, producer private key, certificate, credential bundle, admission
journal, or secret may be stored in the repository, source configuration, logs, fixtures, images, or
model/data directories. For the single-node demo, private material must be provisioned beneath a
root-owned deployment directory outside the checkout: directory mode `0700`, private-key and credential
files mode `0600`, and public trust/allowlist files no broader than `0644`. The producer private key is
readable only by its dedicated OS account; the server key is readable only by the backend account.

For a later Azure deployment, private keys must be non-exportable where the selected Azure service
supports it, or supplied at runtime from Azure Key Vault/managed secret mounting. Selecting and
provisioning that Azure service is a deployment decision requiring separate authorization. Certificates
and keys must never be baked into an image or passed in command-line arguments or environment-variable
values that can be exposed by process inspection.

Rotation issues a new certificate and adds its fingerprint to the same producer with an overlap of at
most 24 hours. Both credentials remain independently auditable. After confirmation, the old fingerprint
is disabled; new requests using it fail immediately, including on an existing TLS connection. Normal
client certificates have a maximum 90-day validity. An emergency revocation sets `enabled=false` first,
terminates active connections for that credential, and then replaces credentials. CA compromise revokes
all issued credentials and requires a new CA and server trust configuration. Replay records are retained
by producer ID across ordinary credential rotation so a new certificate cannot replay old requests.

## Request contract and admission order

The only method and target are `POST /v1/ingest/unsw-registered`. `Content-Type` must be exactly
`application/json`; parameters, content negotiation, compression, multipart bodies, chunked transfer,
and any non-identity content encoding are rejected. `Content-Length` is mandatory.

The body must be valid UTF-8 without replacement decoding. Its JSON value is one object with exactly
these keys; duplicate keys at every object level and unknown keys are rejected. The parser rejects
`NaN`, `Infinity`, and `-Infinity` and enforces the four-level structural-depth limit before constructing
the immutable envelope:

```json
{
  "schema_version": "producer_ingest_request_v1",
  "producer_id": "tf-demo-unsw-replay-01",
  "request_id": "00000000-0000-4000-8000-000000000000",
  "produced_at": "2026-09-12T12:00:00Z",
  "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "source_contract": "unsw_registered_event_ref_v1",
  "records": [
    {"source_member_sha256": "<64 lowercase hexadecimal characters>", "row_number": 1}
  ]
}
```

The shown UUID and nonce are structural examples, not reusable values. `request_id` is a lowercase
canonical UUIDv4 identifying one submission attempt. `nonce` is unpadded base64url encoding of exactly
32 cryptographically random bytes and is unique per producer request. `produced_at` is RFC 3339 UTC with
literal `Z`, whole seconds, and no fractional component. It must be no more than 60 seconds in the future
and no more than 300 seconds old when admission checks it against a UTC clock. Clock rollback or an
unavailable trustworthy clock fails closed.

Each record object has exactly `source_member_sha256` and `row_number`. The digest is exactly 64
lowercase hexadecimal characters and must identify a member of the pinned manifest. `row_number` is a
JSON integer, not boolean or float, in `1..9_223_372_036_854_775_807`, and must not exceed the registered
member count. Duplicate record references within one request are rejected before prediction.

Admission proceeds in this order:

1. finish the bounded TLS handshake and authenticate/map the client certificate;
2. check the current enabled credential and producer/source route allowlist before reading a body;
3. enforce method, target, header and declared-size limits, then charge the authenticated producer's
   rate bucket;
4. attempt the global and per-producer concurrency acquisition without waiting or queueing;
5. read exactly the declared bounded byte count; reject an early EOF or trailing bytes;
6. decode strict UTF-8 and parse JSON with duplicate-key, non-finite-number, type, exact-key, and depth
   rejection;
7. validate the envelope, producer match, source allowlist, timestamp, nonce, request identity, and the
   entire batch of registered references;
8. atomically claim the request and all stable source-event identities in the durable replay journal;
9. only then invoke trusted registered UNSW inference and Attack-only persistence; and
10. durably record the sanitized outcome before returning it.

Any failure through step 8 causes zero calls to the predictor and zero calls to
`AlertCandidateRepository.insert`. No partially read or partially validated batch reaches inference.
The implementation must snapshot bounded plain built-in values before handing work to trusted code; no
caller iterator crosses the admission boundary.

The order deliberately consumes a rate token when an already authenticated attempt finds concurrency
busy. Otherwise a producer could bypass the six-per-minute control by repeatedly probing a saturated
worker. Authentication, disabled/revoked credential, or producer/source-route rejection occurs before
the gate is called and creates no rate or concurrency state. Rate denial occurs before concurrency and
body reading. Concurrency denial is immediate `server_busy`; queue capacity is exactly zero. The later
orchestration layer, not the gate itself, will perform the replay claim.

### Internal rate and concurrency algorithm

The v1 configuration is immutable and contains exactly the sole producer
`tf-demo-unsw-replay-01`, rate six attempts per minute, burst two, global concurrency one,
per-producer concurrency one, and queue zero. There is no attacker-keyed producer map. A bucket stores
integer nanoseconds of credit: one token is exactly `10_000_000_000` credit units and the cap is
`20_000_000_000`. On each authenticated attempt, nonnegative integer monotonic nanoseconds replenish
credit by exact elapsed nanoseconds up to the cap, then one complete token is charged before checking
concurrency. Partial intervals accumulate but do not form a token early; floating-point arithmetic is
not used.

The monotonic clock is injected. Exceptions, booleans, negative values, non-integers, values outside
the signed 64-bit nonnegative range, and movement behind the last accepted clock reading fail closed
as `monotonic_clock_invalid` without adding credit or acquiring concurrency. Tests use a deterministic
fake clock and never sleep. The current policy does not freeze an HTTP `Retry-After` representation, so
the internal decision invents none; the later transport contract must decide that separately.

Successful concurrency acquisition returns an immutable opaque lease containing a random 32-byte-
equivalent capability. The gate retains only its digest and count state. Release requires the exact
active token and gate instance, uses constant-time digest comparison, succeeds exactly once, and is
also available through a context manager whose `finally` path covers normal return and exceptions.
Stale, foreign, forged and double releases fail as sanitized `lease_not_active`. Snapshots contain
counts only: available whole tokens, exact credit units, active counts and aggregate disposition/
release/clock-rejection counts. They contain no producer, request, payload or credential data.

Rate/concurrency state is memory-only and resets when the service process restarts. Separate gate
instances enforce independently; this is not durable or multi-process rate enforcement. Correct v1
operation therefore requires the same externally coordinated single-service-owner/process assumption
as replay recovery. The operating service must instantiate exactly one shared gate.

## Replay, duplicate, and stable identity rules

The replay journal is a separate standard-library SQLite database with a versioned exact schema; it is
not the AlertCandidate repository. Its configured path and WAL/SHM files remain outside the repository
and ignored. It stores no request body, raw nonce, raw row, feature, endpoint, filename, path, label,
attack category, certificate, private key or claim token. It stores producer ID, credential ID, request
ID, nonce digest, exact-body digest, exact accepted request metadata, produced/received/claim time,
first server correlation ID, an ordered-record-set digest, service generation, request state, and—only
for completed requests—the bounded sanitized response, its digest and completion time. The response
contains the bounded per-record dispositions. Stable source-event IDs still require trusted manifest
membership validation by the later orchestration layer and are not invented by this journal.

After trusted manifest membership validation, each record's stable identity is the existing
`unsw_registered_source_event_v1` value derived from source representation, pinned manifest digest,
member digest, and row ordinal. The request/correlation ID is never substituted for this event ID.

The claim transaction enforces these outcomes:

- A new `(producer_id, request_id, nonce)` and exact ordered reference set is committed as
  `in_progress`; only its returned unpredictable ownership token may proceed to processing.
- An exact retry with the same producer, request ID, nonce, body digest, and ordered event set returns
  the journaled sanitized result if `completed`; it makes zero predictor and repository calls.
- Reuse of either request ID or nonce with any different authenticated tuple is `replay_rejected`; it
  makes zero predictor and repository calls.
- A second concurrent exact request while the first is `in_progress` is `request_in_progress`; it is not
  queued and makes zero predictor and repository calls.
- An event submitted under another request after its completed disposition returns that per-event
  disposition as a duplicate without repeating prediction or persistence.
- The AlertCandidate repository remains the final idempotency boundary for a race or recovery path:
  equal Attack evidence is `existing`; conflicting same-ID evidence fails closed.

The journal must be committed before inference begins. On restart, `completed` entries remain reusable
and all replay uniqueness remains effective. An `in_progress` entry left by interruption becomes
`outcome_unknown`; it is not automatically re-executed or expired. Recovery may reconcile an Attack
event by its stable candidate ID against the AlertCandidate repository, but Normal/rejected events have
no durable candidate and therefore require an explicit audited operator disposition before retry. This
deliberately prefers a visible unavailable result to possible duplicate prediction. Journal retention
must be at least the greater of certificate lifetime plus 24 hours or the lifetime of the registered
offline demo dataset; pruning/backup policy must be approved and tested before implementation.

The implemented state machine has exactly `in_progress`, `completed`, and `outcome_unknown`; it has no
automatic-retry failure state. First claim and request/nonce uniqueness use `BEGIN IMMEDIATE`. The raw
32-byte-equivalent claim token is returned only once and only its SHA-256 digest is stored. Completion
requires the exact active token and service generation, validates the response schema and first
correlation ID, then changes state and stores response bytes/digest in one transaction. Exact completed
retries revalidate the digest and response before returning the original bytes.

Recovery is explicit and generation-scoped. Constructing another repository or opening another SQLite
connection never changes a live claim. `recover_abandoned_generation` may be called only after an
external single-service owner, such as the service manager, has proved the named previous generation is
stopped and the replacement exclusively owns service startup. SQLite connections, elapsed time and a
weak lease are not treated as crash proof. The idempotent transaction changes only that generation's
`in_progress` rows to terminal `outcome_unknown`; completed and already-unknown rows are unchanged.

## Exact bounded-transport limits

| Resource | Hard v1 limit | Failure behavior |
|---|---:|---|
| TLS version | TLS 1.3 only | close connection; sanitized authentication audit |
| TLS handshake | 3 seconds | close; `authentication_timeout` audit |
| Request line | 512 bytes | `400 invalid_request`; do not read body |
| Headers | 32 fields, 16 KiB total | `431 request_headers_too_large`; do not read body |
| Header name/value | 64/1,024 bytes | `431 request_headers_too_large` |
| Request body | 131,072 bytes | `413 request_too_large`; drain nothing; close connection |
| Socket/TLS body read | 5 seconds total, 1 second idle | `408 request_timeout`; discard buffer; close |
| JSON nesting | 4 levels | `400 invalid_request` |
| Records | 1..256 | `400 batch_size_invalid`; zero downstream calls |
| String field | 1,024 UTF-8 bytes unless narrower below | `400 invalid_request` |
| Producer ID | 1..128 ASCII bytes | `401 request_unauthorized` on mismatch |
| Schema/source identifiers | 1..64 ASCII bytes and exact allowlist match | `403 admission_rejected` |
| Request ID | exactly 36 lowercase UUIDv4 characters | `400 invalid_request` |
| Nonce | exactly 43 base64url characters encoding 32 bytes | `400 invalid_request` |
| Timestamp | exactly 20 bytes; `YYYY-MM-DDTHH:MM:SSZ` | `400 request_time_invalid` |
| Member digest | exactly 64 lowercase hex characters | `400 record_invalid` |
| Per-record processing | 30 seconds | terminate isolated worker; `processing_timeout` |
| Whole request processing | 300 seconds | terminate isolated worker; retain completed work; `processing_timeout` |
| Admission/alert SQLite busy wait | 500 ms per operation | `503 service_busy`; no retry loop or queue |
| Processing concurrency | 1 request globally and 1 per producer | `429 server_busy`; no queue |
| Rate | token bucket: 6 requests/minute, burst 2, per producer | `429 rate_limited`; no body read |
| Response body | 65,536 bytes | reject serializer contract violation with bounded `500 internal_error`; never truncate |

The 256-record ceiling equals, and never exceeds, `MAX_INFERENCE_BATCH_SIZE`. Admission validates the
whole batch before work. Processing is synchronous and stable-order but not transactionally atomic
across records: candidates already committed before a later timeout remain valid and journaled; no
unstarted record is predicted or persisted. A worker process, not an uninterruptible application
thread, must enforce processing deadlines. There is no in-memory backlog, retry loop, unbounded socket
read, unbounded iterator, or implicit request queue.

Malformed UTF-8, invalid JSON, duplicate keys, non-finite numbers, unsupported encodings, early EOF,
extra bytes, disconnect, and iterator/worker failure discard the bounded input and fail closed. A
disconnect after admission cancels the worker if safe; otherwise processing may finish only to a
journaled state and never writes a response to another connection. It does not cause automatic retry.

The internal milestone's transport-independent reader accepts an already selected binary body stream.
It makes only explicitly sized reads, enforces both the declared length and the observed 131,072-byte
ceiling, requires exact completion, and performs one bounded byte probe to reject trailing data. A pure
function reading an arbitrary blocking stream cannot guarantee a wall-clock or idle timeout. The later
socket/TLS adapter must enforce the five-second total and one-second idle deadlines before calling this
reader; no thread is introduced to pretend that a blocking read is cancellable.

## Privacy, errors, and audit

Client responses contain a server-generated correlation UUID, one stable reason code, and bounded
per-record dispositions only after successful authentication. Unauthenticated responses are uniformly
`401 request_unauthorized`; they do not reveal whether a producer ID, certificate, source contract,
member digest, row, or event exists. No response contains submitted values, exception text, stack trace,
SQL, path, hostname, endpoint, raw feature, model input, label, attack category, or secret.

The frozen response representation is compact ASCII JSON with exact top-level keys
`schema_version`, `correlation_id`, `reason`, and `records`. Each record contains only the one-based
`record_index`, an allowlisted `disposition`, and an allowlisted `reason`; it contains no request or
event value. Sorted keys and compact separators are used, with one final newline. Using the longest
frozen disposition/reason values independently for all 256 records produces 25,142 bytes, including
the newline. Therefore the 65,536-byte response ceiling is consistent with the frozen worst case and
leaves 40,394 bytes of margin. A regression test must calculate this value from the serializer; the
implementation must reject an invalid response object rather than truncate it.

The server correlation UUID identifies one handling attempt. The producer request ID identifies one
authenticated submission. The stable source-event ID identifies a registered dataset event. The model's
existing inference correlation UUID identifies one inference attempt. They are distinct and must not be
used interchangeably.

The immutable `producer_security_audit_event_v1` contract has exactly these fields:

- server-generated canonical UUIDv4 `audit_event_id` and trusted UTC `event_time`;
- optional server handling `correlation_id` UUID;
- fixed `event_type`, `processing_stage`, `outcome`, and granular `reason_code`;
- optional canonical `producer_id` only after internal resolution and optional canonical
  `source_contract_id`; and
- optional complete lowercase SHA-256 digests for credential, validated request ID, and exact body only
  when those digests already exist at the trusted boundary.

It has no free-form message or exception-detail field. It cannot store raw rows/bodies, nonces,
features, predictions, endpoints, labels/categories, submitted producer text, certificate/key contents,
filenames/paths, stack traces, SQL, secrets/tokens, or cached inference responses. The complete
credential fingerprint is an existing canonical identifier, not certificate content; it remains absent
until authentication has internally resolved it. A request-ID digest is used instead of the submitted
request text. Contract construction rejects extra fields, arbitrary identifiers, invalid UUIDs/digests,
non-UTC time, wrong types, and any stage/outcome/reason combination outside the frozen table below.

| v1 event type | fixed stage | fixed outcome | preserved canonical reason mapping |
|---|---|---|---|
| `authentication_rejected` | `authentication` | `rejected` | `authentication_failed`, `credential_disabled`, `credential_revoked`, `credential_not_yet_valid`, `credential_expired` |
| `producer_admission_rejected` | `admission` | `rejected` | `producer_mismatch`, `source_contract_denied`, `invalid_request`, `request_time_invalid`, `request_too_large`, `body_incomplete` |
| `rate_limited` | `rate_control` | `rejected` | `rate_limited` |
| `server_busy` | `concurrency_control` | `rejected` | `server_busy` |
| `request_admitted` | `admission` | `admitted` | `request_admitted` |
| `replay_in_progress` | `replay` | `deferred` | `request_in_progress` |
| `replay_conflict` | `replay` | `rejected` | `request_replay_rejected` |
| `replay_outcome_unknown` | `replay` | `unknown` | `outcome_unknown` |
| `request_completed` | `completion` | `completed` | `request_completed` |
| `internal_failure` | `internal`, `processing`, or `audit` as fixed by reason | `failed` | `internal_error`, `registry_invalid`, `clock_unavailable`, `request_timeout`, `processing_timeout`, `audit_unavailable` |

This preserves the policy's existing granular reason names beneath the broader frozen taxonomy instead
of creating synonymous reason codes. The transport/orchestration milestone must select the mapping; the
audit repository never accepts a client message or converts an exception to a field.

`producer_security_audit_sqlite_v1` uses a strict validated metadata table, strict event table, and a
unique `(event_time, audit_event_id)` ordering index with `PRAGMA user_version=1`. Initialization checks
the exact schema, table SQL, indexes, constraints, metadata, and database integrity. Appends use
`BEGIN IMMEDIATE`, a 500 ms busy timeout, and one transaction. A first ID returns an immutable sanitized
`created` result; an identical retry returns `existing`; the same ID with different security content
rolls back as `audit_event_identity_conflict`. The original timestamp and correlation UUID are excluded
from retry equivalence because they are server attempt metadata, not the logical security fact named by
the durable audit-event ID; the first stored values are retained. Every classification, canonical ID,
and digest remains identity-significant.

Listing is ordered by trusted timestamp then audit-event ID and requires a positive integer limit no
greater than 100. There is no unbounded list/read and no application update or delete API. Reopening
preserves events. The hard v1 repository capacity is 100,000 events. At capacity, identical retries may
still resolve as `existing`, but a new event fails `audit_capacity_reached`; history is never silently
deleted, overwritten, wrapped, or rotated. Orchestration must treat any audit storage/capacity failure as
generic `audit_unavailable`, block a request that would otherwise proceed to prediction or persistence,
and may return that generic outcome for a denial whose audit event cannot itself be stored.

The cap is a demo/single-node safety bound, not a production retention policy. Export, retention,
rotation, backup and recovery are future production work. SQLite supplies local durability and
serialized application writes; it is not tamper-evident and offers no malicious-host protection against
a filesystem owner, compromised process, SQLite administrator, or kernel. No hash chain, HMAC log,
signature or encryption claim is made.

## End-to-end enforcement sequence

For each newly admitted record, the intended code path is exactly:

`mTLS authentication` → `producer/credential allowlist` → `bounded header validation` →
`integer rate-token decision` → `nonqueueing concurrency lease` → `bounded body read` →
`strict producer_ingest_request_v1 validation` → `timestamp and durable replay claim` →
`unsw_registered_event_ref_v1 member/row allowlist` →
`infer_and_persist_registered_attack` → `UnswNetworkInferenceBoundary.infer_registered` →
`single-open-file hash/row-count verification` → `shared 49-column mapping` → `adapt_unsw_row` →
`NetworkFlow` validation → exact `network_behavior_v1` projection → private frozen predictor →
`build_alert_candidate` only for a completed Attack → `AlertCandidateRepository.insert`.

Normal, rejected, failed, timed-out-before-decision, unauthenticated, unadmitted, duplicate, and replayed
requests do not create AlertCandidates. Exact completed duplicate requests do not predict again.
Attack-only construction and the repository's `created`/`existing`/identity-conflict behavior remain
unchanged. The transport layer cannot assert provenance, supply a feature vector, choose an adapter,
select CIC, choose a model, change a threshold, or manufacture an AlertCandidate.

## Acceptance test matrix

All tests use synthetic references/mocks or existing small repository fixtures; they must not access
datasets or generated model artifacts. Predictor and repository spies are mandatory.

| Case | Expected result | Predictor calls | Repository insert calls |
|---|---|---:|---:|
| Valid enabled producer, fresh request, valid registered Attack fixture | created or existing | 1 per new event | 1 per actionable Attack |
| Valid enabled producer, valid registered Normal fixture | completed/not actionable | 1 | 0 |
| Unknown, disabled, expired, not-yet-valid, revoked, wrong-EKU, or wrong-SAN certificate | uniform 401 | 0 | 0 |
| Body producer ID differs from certificate mapping | 401 | 0 | 0 |
| Producer requests wrong/unknown/CIC/live source contract | 403 | 0 | 0 |
| Header/body tampering in transit | TLS failure or invalid request | 0 | 0 |
| Body changed while request ID or nonce is reused | replay rejected | 0 | 0 |
| Exact completed retry | cached duplicate result | 0 | 0 |
| Two concurrent identical requests | one claim; other in progress/cached | exactly 1 total per event | at most 1 total per Attack |
| Expired request; request more than 60 seconds future | invalid time | 0 | 0 |
| Nonce or request-ID replay after service restart | replay rejected/cached | 0 | 0 |
| Oversized body, missing length, chunked/compressed body | reject before JSON | 0 | 0 |
| Empty or 257-record batch; duplicate record in batch | batch invalid | 0 | 0 |
| 256 structurally valid records | admitted within ceiling | at most 256 | Attack records only |
| Wrong types, extra/duplicate keys, malformed UTF-8/JSON, NaN, bad digest/ordinal | invalid request/record | 0 | 0 |
| Partial body, early EOF, extra bytes, or disconnect before claim | reject and close | 0 | 0 |
| Admission iterator/decoder failure | invalid request | 0 | 0 |
| Trusted inference iterator/worker failure before any decision | bounded failure | 0 | 0 |
| Per-record or request processing timeout | worker terminated; partial state visible | only completed records | only completed Attacks |
| Admission or alert database busy beyond 500 ms | service busy | 0 before claim; otherwise journaled | 0 before claim; otherwise bounded |
| Restart with completed journal entry | cached response | 0 | 0 |
| Restart with `in_progress` journal entry | outcome unknown after explicit recovery; no automatic retry | 0 | 0 |

Tests must additionally prove body buffers never exceed 131,072 bytes, parser depth/field limits hold,
no request queue forms at concurrency saturation, timeouts terminate workers, security audits are
emitted, and client/audit outputs contain none of the prohibited values. Tests must patch the predictor
and `AlertCandidateRepository.insert` at the final trusted seams and assert zero calls for every
authentication or admission failure—not merely inspect response codes.

## Implementation milestones and issue closure

1. Implement and unit-test the strict envelope, certificate-to-producer registry, bounded reader,
   timestamp/source gates, immutable replay-journal input and bounded sanitized response types without
   an external listener. **Implemented 2026-09-12.**
2. Implement the versioned durable replay journal and its restart/concurrent-claim tests, including
   explicit `outcome_unknown` recovery. **Implemented internally 2026-09-12.** This journal is separate
   from AlertCandidate persistence.
3. Implement fixed process-local integer rate limiting and nonqueueing global/per-producer concurrency
   leases. **Implemented internally 2026-09-12.** Stable source-event orchestration remains required.
4. Implement the bounded sanitized ten-event security-audit contract and local SQLite sink, including
   capacity, failure-injection, concurrency, restart, drift/integrity and downstream-zero-call tests.
   **Implemented internally 2026-09-13.** It is not yet wired to request handling.
5. Add an isolated synchronous loopback TLS service that directly terminates mTLS and connects only the
   admitted registered-reference request to the existing trusted workflow; run all zero-spy and timeout
   tests.
6. Add bounded failure-injection and single-node restart/recovery evidence, then integrate correlation,
   explanation, and dashboard contracts separately.
7. Before enabling Azure, approve a live representation and stable event/candidate identity, verify
   feature semantics, provision Azure-held credentials, and repeat admission/replay/resource tests in
   that deployment. Do not map Azure telemetry to registered UNSW identity.

This policy alone resolves neither issue. TF-008 remains open until one authenticated supported input
reaches the dashboard with reconciled identity/status and all failure boundaries visible while optional
services are unavailable. TF-009 remains open until implemented end-to-end tests and measured evidence
cover malformed/partial input, mismatch, restart/replay, idempotency, interruption, timeouts,
concurrency/rate/body/queue bounds, database recovery/backup, and resource usage. Azure enablement is not
a prerequisite for the single-node offline demo, but it cannot be claimed supported before milestone 7.

Internal-milestone validation used synthetic requests and temporary SQLite databases with no
dataset/model artifacts. All 44 replay-journal tests and 195 focused replay/admission/inference-binding/
persistence tests pass. The full suite passes with 625 tests and the four existing TF-005 timestamp
warnings. Repository-wide Ruff and all three individual 30-second-bounded Black checks pass. The
response serializer test independently reproduces the 25,142-byte 256-record worst case, while journal
tests accept exactly 65,536 valid bounded bytes and reject one byte more. These component results do not
establish TLS, stable source-event orchestration, audit orchestration, backup/recovery or end-to-end
service behavior. All 37 deterministic rate/concurrency cases and 232 directly related gate/admission/
replay/inference-binding/persistence tests pass. The complete repository suite passes with 662 tests
and the same four TF-005 warnings; repository-wide Ruff and both bounded gate-file Black checks pass.

The subsequent bounded-audit milestone uses only synthetic events and temporary SQLite databases. All
66 audit tests and 163 directly related admission, gate, replay-journal and alert-persistence tests
pass. The complete repository suite passes with 728 tests and the same four TF-005 warnings;
repository-wide Ruff and both individual audit-file Black checks pass. Failure tests cover concurrent
identical and conflicting appends, rollback, 500 ms locking, restart, corruption/integrity and exact
schema/index/constraint drift, privacy, deterministic listing, and a small internal capacity boundary
while separately asserting the production constant is exactly 100,000. Predictor, replay-processing
and AlertCandidate-repository spies remain at zero for every audit operation and failure. This does not
establish TLS termination, socket deadlines, final orchestration, production retention/export/rotation,
backup/recovery, or malicious-host tamper resistance.
