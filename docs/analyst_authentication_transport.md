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
`clientAuth` restriction; automatic provisioning validation is still an open operational requirement.

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

To rotate, issue a new certificate and add its fingerprint as another record for the same actor while
retaining the old record for a bounded operational overlap. To revoke or disable, replace the
deployment-owned registry with the old fingerprint marked revoked/disabled or removed, close the old
listener, join its caller-owned `process_one` worker, and construct a new listener with the replacement
registry. Reopening the same object retains its original registry and does not apply revocation.
There is no live reload: changing a configuration file alone has no effect. A disabled actor also
requires a replacement authorization registry and repository/view objects bound to that registry.

`close()` prevents pending accepted/handshaking/reading connections from starting repository work,
interrupts their sockets, and waits for any repository operation already dispatched under its state
lock. Such an operation may commit before close returns; no old operation can start afterward. Its
response may be lost during shutdown, so the client must use the same UUIDv4 command ID on retry.
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
There is no audit/retention facility in this milestone.

## Browser and claim boundary

Browsers can sometimes select a client certificate for mTLS, but certificate selection, trust-store
installation, private-key protection, local origin/Host routing, CSRF, CORS, same-origin UI delivery
and accessibility have not been designed or tested. The current strict header contract intentionally
does not support arbitrary browser requests. A dashboard requires a separately reviewed browser
session/origin design; do not weaken this boundary by accepting browser-supplied role headers or
placing an unverified reverse proxy in front of it. The listener is a local demonstration component,
not an internet-facing or production-ready service.

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
