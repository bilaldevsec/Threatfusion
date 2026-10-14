# Human analyst authentication and loopback transport v1

## Trust path and scope

This bounded demonstration boundary uses a distinct TLS 1.3 mutual X.509 client certificate as the
human credential. The human keeps the corresponding private key. The directly terminating
`AnalystTlsListener` verifies the client chain and `clientAuth` purpose with Python/OpenSSL using its
configured **human CA**, then reads the DER certificate and decoded SAN from that same authenticated
TLS connection. It hashes the complete DER bytes and accepts only a fingerprint present in the
server-owned `HumanCredentialRegistry`, with an exact single URI SAN
`urn:threatfusion:human:<actor_id>`, enabled and unrevoked record, and current validity interval.
Common name, client-provided certificate labels, IDs, roles, headers, and JSON fields grant nothing.
OpenSSL's client-purpose check rejects an incompatible EKU such as `serverAuth` alone. It does not
require an EKU extension to be present: a certificate without EKU can authenticate if its exact
fingerprint and human SAN were explicitly allowlisted. Issuance must supply the intended explicit
`clientAuth` restriction; the local operator enrollment interface now enforces explicit
clientAuth-only EKU and CA:FALSE. Manually constructed registries retain the existing listener rule.

The matched record yields only an actor ID. The separate `AnalystAuthorizationRegistry` then maps
that server-owned actor ID to its enabled `viewer` or `analyst` role and issues a process-local
capability. The existing analyst repository checks that capability on every list, detail, and
transition call. The transport has no role in the certificate or request. Viewer transitions fail
with `forbidden`; analysts use the frozen state machine, optimistic version and UUIDv4 operation ID.
An exact replay by the same actor returns `existing`; the same operation ID used by another actor is
an identity conflict. Detection evidence remains immutable and distinct from analyst annotations.

This listener is separate from producer ingestion: it has its own loopback socket, human CA,
fingerprint allowlist (at most 64 records), URI SAN namespace, fixed analyst routes, and view-model
dependency. It does
not call producer admission, inference, replay journal, or alert insertion. Producer certificates are
not in the human allowlist and producer-only routes are invalid here. The producer listener is not
modified and accepts no analyst route.
The configured trust file and allowlist are trusted deployment inputs. The listener does not inspect
the producer deployment's CA file or prove that an operator has provisioned distinct CA keys.

## Credential operations

An operator must issue short-lived, `clientAuth` certificates under a dedicated human CA outside
the repository. The certificate must carry exactly one URI SAN bound to the assigned actor ID. CA
and client private keys, server key, certificate files and the fingerprint allowlist must be
provisioned outside the checkout with access limited to their designated accounts. No reusable
credential is tracked here; tests generate disposable certificates under pytest temporary paths.
The issuer and provisioning process are deployment responsibilities, not implemented by this module.

The [local operator runbook](human_credential_operator_runbook.md) implements offline Root CA
management, encrypted PKCS#12 client bundle issuance, public-certificate enrollment,
exact-fingerprint disable/revoke into versioned private metadata, and automated fail-closed Firefox
NSS SQLite profile provisioning (`threatfusion.operations.human_browser_provisioning`). Browser
write authentication/CSRF protection, long-term endurance, and live production telemetry remain open.

To rotate, issue a new certificate and add its fingerprint as another record for the same actor while
retaining the old record for a bounded operational overlap. To revoke or disable, replace the
deployment-owned registry with the old fingerprint marked revoked/disabled (the operator CLI retains
the record), close the old listener, join its caller-owned `process_one` worker, and construct a new listener with the replacement
registry. Reopening the same object retains its original registry and does not apply revocation.
There is no live reload: changing a configuration file alone has no effect. A disabled actor also
requires a replacement authorization registry and repository/view objects bound to that registry.

`close()` prevents pending accepted/handshaking/reading connections from starting repository work,
interrupts their sockets, and waits for any repository operation already dispatched under its state
lock. In both `AnalystBrowserTlsListener` and `AnalystTlsListener`, `process_one()` assigns
`self._active` to the accepted connection under lock before `connection.do_handshake()`.
When `close()` runs, it calls `shutdown(socket.SHUT_RDWR)` and `close()` on the active connection,
promptly interrupting stalled TLS handshakes so caller-owned workers join in < 5.0 seconds rather
than blocking for the 60.0-second browser handshake deadline. An admitted operation already inside
the protected dispatch section finishes cleanly before `close()` returns; no new operation can start
afterward. Its response may be lost during shutdown, so the client must use the same UUIDv4 command ID on retry.
Revocation is effective for the replacement listener's first request; credentials are checked both
after TLS authentication and again before dispatch. The registry interval is `[not_before, not_after)`.
Expired, not-yet-valid, unknown, wrong-SAN, revoked and disabled credentials are denied. CA replacement
requires a new listener/context too. There is no certificate revocation list or OCSP mechanism.

## Wire boundary

The listener binds only `127.0.0.1`, handles one TLS connection and one HTTP/1.1 request per
`process_one()` call, and closes it. Concurrent calls on one listener fail with `listener_busy`;
there is no application queue. The caller controls termination; this is not a daemon. It
requires `Host: threatfusion-analyst-loopback` and `Connection: close`, rejects other headers, and
has fixed 4 KiB head, 2 KiB command body, 128 KiB response and 3/5-second handshake/request limits.
Present excess body bytes and decrypted pending bytes are rejected even if the head and body arrive
separately. Bytes arriving after the sole request has been accepted are never interpreted as another
request; this is not a claim to detect arbitrary future bytes. Socket timeouts do not bound a stalled
trusted filesystem or repository call, and no overall shutdown/endurance deadline is claimed.
The minimal routes are:

- `GET /v1/analyst/alerts?limit=1..100&offset=0..1000000` (defaults 50 and 0);
- `GET /v1/analyst/alerts/<alert_candidate_id>`;
- `POST /v1/analyst/alerts/<alert_candidate_id>/transitions` with only
  `expected_version`, `to_state`, canonical UUIDv4 `transition_id`, and bounded `rationale` JSON fields.

Responses use the existing `analyst_alert_view_v1` list/detail/transition schemas. Invalid input,
forbidden writes, missing alerts, conflicts and unavailable storage use fixed generic error codes;
authentication failure may close the TLS connection or return only `authentication_failed`. No
credential, path, raw exception, model input or submitted body is logged or reflected in errors.
Security audit events are captured in a separate bounded local audit table (`analyst_security_audit_sqlite_v1`),
distinct from alert detection and analyst state databases.

## Browser and claim boundary

The strict `AnalystTlsListener` header contract does not accept browser requests. The separate
`AnalystBrowserTlsListener` now serves a bounded, read-only HTML queue and alert detail over local
mTLS, with Host, Origin and Fetch-Site checks. Browser certificate selection, trust-store installation,
private-key protection, accessibility and future write authentication/CSRF protection remain to be
designed and tested operationally. Neither listener is an internet-facing or production-ready service.

Real-loopback tests establish these properties for temporary test certificates and one-request
connections:

- A viewer certificate reads list/detail but cannot transition; two analyst certificates map to
  distinct actor IDs, and only the authenticated actor is recorded in transition history.
- Missing, producer-CA and wrong-`clientAuth`-purpose certificates cannot complete a usable analyst
  request. Revoked, unknown and
  wrong-SAN certificates cannot read; a wrong-SAN certificate is denied even when its fingerprint is
  present in the human allowlist.
- Extra identity/role headers, extra actor/role JSON fields, duplicate JSON keys, wrong routes and
  out-of-bound query values are rejected before state mutation.
- Exact same-actor UUIDv4 retry returns `existing` without a second event; reuse by another analyst
  and a stale different command return conflicts. Alert detection evidence remains unchanged.
- Old and new certificate fingerprints can overlap for one actor; after listener restart with the
  old fingerprint revoked, the old certificate is denied while the new one still reads.
- An injected storage exception produces only a fixed `unavailable` response, with no path, secret or
  raw exception text.

The tests do not establish secure real-world credential issuance, workstation account isolation,
browser safety, long-running concurrency, audit completeness, backup/recovery or operational capacity.

## Security Audit Events

Bounded local security audit events are persisted through the TLS listener using the `AnalystSecurityAuditRepository` (`analyst_security_audit_sqlite_v1`). State mutations (`states.sqlite3`) and security audit records (`audit.sqlite3`) reside in two independent SQLite databases with distinct transaction boundaries; there is no distributed transaction or two-phase commit across them.

- **Authentication Failures:** When an authenticated peer fails the internal application registry check (e.g. revoked/disabled certificate or wrong SAN), an `authentication_rejected` event is logged detailing `reason_code` `authentication_failed`. Audit append for authentication failures is best-effort: if appending to the audit repository fails, the listener swallows the audit error and returns 401 `authentication_failed` (or closes the connection) to preserve the authentication contract without leaking internal audit storage status or 503 errors to unauthenticated peers.
- **Authorization Failures:** A certificate-mapped actor absent or disabled in the authorization registry receives 401 `authentication_failed` (or TLS close), with best-effort `authorization_rejected` / `forbidden` audit. When an admitted actor attempts an unauthorized action (e.g., a viewer attempting an analyst transition), an `authorization_rejected` event is logged with `reason_code` `forbidden`. An audit failure at this boundary returns 503 `unavailable`.
- **Success & Lifecycle:** A `request_admitted` event is recorded before repository dispatch or mutation, and a `request_completed` event is written after dispatch terminates.
- **Route Normalization:** Audit records persist only fixed recognized route templates (`/v1/analyst/alerts`, `/v1/analyst/alerts/<alert_candidate_id>`, `/v1/analyst/alerts/<alert_candidate_id>/transitions`) or omit the route (`None`) for unrecognized paths, preventing raw unvalidated URL paths and query strings from entering audit storage.
- **Idle Connections & Handshake Drops:** Unauthenticated peers failing TLS handshake, as well as valid TLS connections that close (empty disconnect) or time out before sending any HTTP request bytes, do not generate false authentication or request-rejection audit events. Malformed framed HTTP requests continue to be rejected and audited as `request_rejected`.
- **Audit Failures, Replay, and Audit Gap:** An audit write failure before state mutation (`request_admitted`) blocks the request with a 503 `unavailable` response. If an audit write fails after a state transition has committed to `states.sqlite3`, the listener returns 503 `unavailable` rather than falsely claiming success. When the client retries the transition with the same canonical UUIDv4 `transition_id`, the state repository detects the idempotent replay, returns `existing` disposition, and avoids duplicating state history; the retry attempt records its own `request_admitted` and `request_completed` events. However, because the state commit and audit append have independent transaction boundaries, the original failed completion write is not retroactively inserted into `audit.sqlite3`, leaving an audit gap for the initial request's completion event.

### Security Audit Export, Archive Verification, and Quiescent Retention Pruning

To manage `audit.sqlite3` capacity safely without risking the loss of unarchived audit trails,
`threatfusion.operations.audit_retention` provides fail-closed export, verification, and prefix pruning:

- **Tamper-Evident Archive Export (`export_security_audit_archive`):**
  Reads rows from `audit.sqlite3` in strict order (`ORDER BY event_time ASC, audit_event_id ASC`),
  optionally bounded up to a specific `up_to_audit_id`. Writes a deterministic JSONL export
  (`audit_events.jsonl`, mode 0600) and companion manifest (`manifest.json`, mode 0600, schema
  `security_audit_archive_v1`) into a locked mode-0700 archive directory. The manifest records
  `sha256_digest`, `size_bytes`, `row_count`, `first_audit_id`, `last_audit_id`, `first_recorded_at_utc`,
  and `last_recorded_at_utc`.
- **Cryptographic & Structural Verification (`verify_security_audit_archive`):**
  Enforces mode-0700 directory, mode-0600 files, symlink absence, JSONL schema validation, monotonic
  timestamp/UUID ordering, row count match, and exact SHA-256 digest match against the manifest.
  Any tampering or mismatch raises `AuditRetentionError`.
- **Atomic Contiguous Prefix Pruning (`prune_archived_security_audit`):**
  First verifies the target archive via `verify_security_audit_archive`. Opens an exclusive transaction
  (`BEGIN IMMEDIATE`) on `audit.sqlite3`, reads the first `manifest["row_count"]` rows, and compares
  every field against the archive. If any field or prefix mismatch is detected, it rolls back and raises
  `AuditRetentionError("prefix_mismatch")`. Only after 100% prefix equivalence is established does it
  execute `DELETE FROM audit_events WHERE event_time < ? OR (event_time = ? AND audit_event_id <= ?)`,
  ensuring zero unarchived rows are deleted.
- **Quiescent Lifecycle Pruning (`HumanListenerLifecycle.prune_security_audit_quiescent`):**
  Synchronously pauses listener admission, joins active worker threads (< 5.0s drain), executes
  `prune_archived_security_audit`, and automatically restarts fresh listeners via `replace()`.

## Read-Only Analyst Dashboard Slice

The authenticated read-only analyst dashboard slice (`threatfusion.api.analyst_dashboard`) connects a human analyst to the `AnalystTlsListener` over mutual TLS 1.3 loopback transport, retrieving real persisted alerts and detail without violating transport constraints:

- **Client Authentication:** Uses `create_dashboard_ssl_context` with verified human mTLS credentials (human CA plus client cert and private key) matching the `HumanCredentialRegistry` allowlist and URI SAN (`urn:threatfusion:human:<actor_id>`).
- **Data Flow & Presentation:** The `AnalystDashboardClient` issues authenticated `GET /v1/analyst/alerts` and `GET /v1/analyst/alerts/<alert_candidate_id>` requests conforming to the strict wire contract (`Host: threatfusion-analyst-loopback`, `Connection: close`). Results are structured into `DashboardAlertQueue`, `DashboardAlertDetail`, and `DashboardSnapshot` models, with an escaped HTML view rendered via `render_dashboard_html`.
- **State Invariance:** Dashboard queries are strictly read-only; viewing queue and detail views produces zero state mutations or transition events in `states.sqlite3`.
- **Failure & Empty States:** An empty triage queue is explicitly distinguished from an unavailable backend; backend errors (e.g., connection refused, 503 storage failure) and authentication failures raise sanitized typed exceptions (`AnalystDashboardUnavailableError`, `AnalystDashboardAuthenticationError`) without leaking database paths or internal secrets.
- **Browser Read-Only Boundary:** The system now supports a read-only local browser listener (`AnalystBrowserTlsListener`) over loopback TLS 1.3. Identity is derived from the verified client certificate SAN and SHA-256 fingerprint; headers are used strictly for admission control (Host, Origin, Sec-Fetch-Site), not identity. Queue rows link to full alert IDs, and UTF-8 HTML response bodies are limited to 131,072 bytes. Oversized rendering returns a sanitized 503. Future write authentication and CSRF protection need an explicit design. TF-008 and TF-009 remain open for operational provisioning and reliability evidence.

## Independent security review, 2026-09-24

Two failing regressions reproduced defects in the initial unstaged implementation:

- **High: dispatch after shutdown.** A connection paused before its TLS handshake committed a
  transition after `close()` returned. Lifecycle synchronization now closes admission by listener
  instance, cancels accepted sockets and serializes repository dispatch with close. Regressions cover
  pre-handshake close, partial-body close, reopen, competing handler rejection and draining an already
  dispatched transaction.
- **Medium: segmentation-dependent trailing-body acceptance.** When the header and body arrived
  separately, a read of exactly Content-Length bytes ignored trailing bytes already present. The body
  reader now reads one excess byte and checks decrypted pending data. The original deterministic
  reproduction and a real TLS transition test reject the malformed request with no state change.

Additional tests verify TLS 1.2 denial, absent/producer/wrong-purpose certificates, disabled credentials
and actors, unknown actors, exact validity boundaries, duplicate/ambiguous SAN rejection, oversized and
duplicate-framed requests, accelerated handshake/read timeouts and expiry rechecking before dispatch.
Every credential-denial case exercises list, detail and transition with spies proving zero underlying
alert-storage calls. Temporary test credential files are removed at fixture teardown. No producer,
model, artifact or state-rule change was needed. Provisioning, browser origin/session safety, security
audit and endurance requirements remain open under TF-008/TF-009.

## Controlled local human lifecycle, 2026-09-28

`HumanListenerLifecycle` supplies a bounded composition for both human listeners
with explicit TLS, authorization, view and audit dependencies; see the
[operator runbook](human_credential_operator_runbook.md#controlled-restart-and-integration).
It calls `human_credentials.construct_listener` under one shared directory lock,
validates both listeners and repository schemas/read probes before opening, then
owns one process_one worker per listener. No demo credentials or producer are involved.
At least one active authorized credential must remain for startup.

Disk save, old-generation stop/join, policy loading and replacement readiness are
separate states. Replacement first sets both admission-stop flags, closes both
listeners, and joins all old workers. A flag prevents pending peers from entering
the dispatch section; a peer already inside that section may finish while close
waits. Only after that drain can a new generation load and open. Startup failure,
including partial open/worker startup, closes the candidate generation without
resuming old credentials. Generation counters are process-local, not policy hashes.

The lifecycle context/finally boundary cleans up on KeyboardInterrupt. It does not
claim bounded shutdown against stalled trusted storage or service-manager/SIGKILL
handling. Same-actor exact UUIDv4 retries keep their existing idempotency semantics;
Automated operator Firefox profile provisioning (`threatfusion.operations.human_browser_provisioning`),
offline Root CA issuance, encrypted PKCS#12 bundle delivery, operator-action journaling (`journal.jsonl`),
multi-database snapshot/restore, and service-manager deployment are implemented and verified. Long-term
endurance, browser write authentication/CSRF protection, and the defensible distinct-alert correlation
key remain open under TF-008 and TF-009.
