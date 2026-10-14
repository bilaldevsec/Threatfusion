# Local human credential enrollment and restriction

This Linux procedure manages only public fingerprint metadata for the existing
human mTLS listeners. Use the same trusted local account for policy administration
and listener construction. CA issuance, secure delivery/private-key protection,
recovery, live reload and endurance are outside this phase. No daemon is added.
Do not run the disposable browser demo launcher as an operational service: it
constructs its own temporary credentials and does not consume this policy.

## Preconditions and commands

Use the repository's `threatfusion-venv`, installed OpenSSL 3 and Python 3.11.
An operator must already have a public PEM certificate issued under the dedicated
human CA and an independently assigned actor in `AnalystAuthorizationRegistry`.
The enrollment command assigns no role. Provision server and client private keys
separately; none is an input to this CLI. Do not place credentials or registry
files in Git, print certificate bodies, or pass passwords/private keys to commands.

Choose a new, absolute, operator-owned directory outside the checkout, mode 0700.
Its ancestors must be root/operator owned, without group/world write permission
(root-owned sticky temporary parents are allowed for tests). Symlink components
are rejected. Paths below are illustrative deployment paths, not supplied files.

```sh
install -d -m 700 /home/operator/threatfusion-human-policy
PYTHONPATH=backend/src threatfusion-venv/bin/python -m threatfusion.operations.human_credentials --directory /home/operator/threatfusion-human-policy init --certificate /home/operator/public/viewer.pem --human-ca /home/operator/public/human-ca.pem --actor queue.viewer
PYTHONPATH=backend/src threatfusion-venv/bin/python -m threatfusion.operations.human_credentials --directory /home/operator/threatfusion-human-policy enroll --certificate /home/operator/public/analyst.pem --human-ca /home/operator/public/human-ca.pem --actor analyst_a
PYTHONPATH=backend/src threatfusion-venv/bin/python -m threatfusion.operations.human_credentials --directory /home/operator/threatfusion-human-policy disable --fingerprint EXACT_64_LOWERCASE_HEX_SHA256
PYTHONPATH=backend/src threatfusion-venv/bin/python -m threatfusion.operations.human_credentials --directory /home/operator/threatfusion-human-policy revoke --fingerprint EXACT_64_LOWERCASE_HEX_SHA256
```

`init` atomically creates `human-credentials.json` without replacing an existing
file, including unrelated files or dangling symlinks. `enroll` requires valid
existing policy and rejects duplicate fingerprints. Multiple distinct certificates
may map to one actor for rotation overlap. Both restriction commands retain the
record; disable sets `enabled=false`, revoke sets `revoked=true`. Repeating the
same restriction is safe. Unknown fingerprints fail. There is no delete, enable
or un-revoke command. The fingerprint returned by enrollment is the SHA-256 of
the complete DER certificate, not a subject or public-key hash. Record the exact
fingerprint, action and restart outcome in the operator's controlled change log.
Under the existing directory lock, each successful state-changing action
(`init`, `enroll`, `disable`, `revoke`) appends a deterministic entry to
`journal.jsonl` (mode 0600, schema `operator_human_credential_journal_v1`,
capped at 64 records and 64 KiB) in the policy directory.

Success exits 0 with `saved_restart_required` (enrollment also returns the public
fingerprint); policy failure exits 1 with only `credential_policy_invalid`.
Argument syntax errors exit 2. Success means metadata saved, not access revoked
on a running listener. A filesystem error after replacement/fsync may leave the
new policy installed despite a failure result: keep the service stopped and
validate construction before proceeding. Never recover by falling back to demo
credentials or by deleting audit history.

## Validation and storage contract

Enrollment accepts one bounded PEM public certificate (at most 64 KiB), verifies
its chain against the supplied human CA with OpenSSL `sslclient` purpose and
requires explicit clientAuth-only EKU, CA:FALSE and exactly one SAN: the URI
`urn:threatfusion:human:<actor_id>`. This is deliberately narrower than the
listener's existing OpenSSL purpose rule, which also permits absent EKU for a
manually constructed allowlist. The URI must match the operator's actor argument.
The validity interval is copied from the certificate and must contain current UTC.
OpenSSL defaults are disabled for CA directories/stores; no network retrieval is
performed. The chosen CA remains a trusted deployment input and must match the
listener configuration. Enrollment does not establish CA key separation.

Version `operator_human_credentials_v1` has exactly `schema_version` and
`credentials`; each entry has the six existing HumanCredential fields:
`actor_id`, `certificate_sha256`, `enabled`, `revoked`, `not_before`, `not_after`.
Dates are canonical UTC ISO strings with `+00:00`. No certificate body, role,
private key or password is retained. The 64-entry bound includes tombstones;
retention/archival at capacity requires a future reviewed procedure.

Loading rejects duplicate JSON keys, unknown fields/versions, invalid types,
conflicting/duplicate fingerprints, invalid intervals and active entries outside
current validity. Disabled/revoked historical entries may expire and remain
loadable; the restriction commands also permit restricting an expired entry.
An expired active entry blocks construction until explicitly disabled/revoked.
All active actors must exist and be enabled in the separate authorization registry.

Policy must be a regular, singly linked file owned by the current account with
exact mode 0600, bounded to 64 KiB. Reads and updates use descriptor-relative,
no-symlink access and a nonblocking shared/exclusive directory lock. Updates write
a mode-0600 temporary file, fsync, atomically replace, then fsync the directory.
Cooperating concurrent operators fail immediately on contention. The directory
must stay in place; these protections do not defend against root or a malicious
process using the same trusted account. Crash recovery and backups are unproven.

An append-only journal (`journal.jsonl`, mode 0600, schema
`operator_human_credential_journal_v1`) records every successful state change
under the same directory lock and descriptor-relative traversal. Each JSONL line
contains a monotonic 1-based sequence number (`seq`), UTC ISO timestamp
(`recorded_at_utc`), `action` (`init`|`enroll`|`disable`|`revoke`|`journal_rotated`),
`actor_id` (or null for non-enrollment actions), `sha256_fingerprint`, `resulting_status`
(`initialized`|`active`|`disabled`|`revoked`|`rotated`), `total_records`, and `active_records`.
Raw PEM bytes and secret keys are never written to the journal. The journal is
capped at 64 records and 64 KiB. Symlinks, unsafe permissions, corrupt JSON,
non-monotonic sequence numbers, or capacity overflows raise `CredentialPolicyError`.
The `threatfusion.operations.human_credentials.read_journal(policy_dir)` helper
reads and validates journal integrity under the directory lock.

### Hash-chained journal rotation at the 64-record cap

When the journal reaches its 64-record cap, subsequent write actions (`enroll`, `disable`, `revoke`)
fail closed with `CredentialPolicyError`. To archive the journal and continue operating without
losing sequence monotonicity or cryptographic chain provenance, the operator rotates the journal:

```sh
install -d -m 700 /home/operator/threatfusion-archives/journal-01
PYTHONPATH=backend/src threatfusion-venv/bin/python -m threatfusion.operations.human_credentials \
  --directory /home/operator/threatfusion-human-policy \
  rotate-journal --archive-dir /home/operator/threatfusion-archives/journal-01
```

Rotation executes under exclusive locks on both directories:
1. Validates the active journal, reads its exact byte content, and computes its SHA-256 digest.
2. Atomically writes the archived `journal.jsonl` (mode 0600) and companion manifest `manifest.json`
   (mode 0600, schema `operator_human_credential_journal_archive_v1`) into the archive directory.
   The manifest records `sha256_digest`, `size_bytes`, `record_count`, `first_seq`, `last_seq`,
   `archived_up_to_seq`, and `previous_archive_sha256`.
3. Atomically replaces `journal.jsonl` in the policy directory with a seeded continuation checkpoint:
   `seq = last_seq + 1`, `action = "journal_rotated"`, `resulting_status = "rotated"`,
   `previous_archive_sha256 = sha256_digest`, `archived_up_to_seq = last_seq`, and current
   policy `active_records` / `total_records`.
4. Monotonic sequence progression continues seamlessly (`last_seq + 2`, `last_seq + 3`, ...) while
   the active file's record count resets to 1, allowing up to 63 additional operator actions before
   the next rotation.
5. Archived journals can be cryptographically verified at any time using
   `threatfusion.operations.human_credentials.verify_journal_archive(archive_dir)`.

## Controlled restart and integration

The local Python entry point is
`threatfusion.operations.human_listener_lifecycle.HumanListenerLifecycle`.
It follows the producer's fixed-worker ownership pattern but does not construct or
run a producer. The existing registered browser demo generates temporary credentials
and performs inference, so it is deliberately not the composition path here.

Supply two `AnalystTlsConfiguration` objects, the existing
`AnalystAuthorizationRegistry`, `AnalystAlertViewModel`, and
`AnalystSecurityAuditRepository`. Construct the view from
`AnalystStateRepository(state_path, AlertCandidateRepository(alert_path), authorization)`;
use the same authorization object throughout. Provision these retained repositories
and TLS files separately; this lifecycle does not ingest alerts, issue certificates,
assign roles, select demo identities, or migrate storage. Changing authorization
requires new registry and state/view objects and a new lifecycle after shutdown.

A local operator's Python control loop can use the following integration code with
those explicitly supplied objects. Run the integrating script with
`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src threatfusion-venv/bin/python /absolute/path/to/operator_script.py`.
This is an integration example, not a supplied deployment configuration or a command
that was executed against operational credentials in this milestone.

```python
import json
from threatfusion.operations.human_listener_lifecycle import (
    HumanListenerLifecycle, HumanLifecycleError,
)

service = HumanListenerLifecycle(
    policy_directory, api_configuration, browser_configuration,
    authorization, view, audit,
)
try:
    with service:
        print(json.dumps(service.snapshot()))
        # service.addresses returns API then browser loopback endpoints.
        # Keep all listener objects and process_one workers owned by service.
        while True:
            command = input("replace or stop: ").strip()
            if command == "stop":
                break
            if command == "replace":
                print(json.dumps(service.replace()))
except HumanLifecycleError:
    print('{"error":"human_lifecycle_failed"}')
except (KeyboardInterrupt, EOFError):
    print('{"status":"operator_interrupted"}')
finally:
    service.shutdown()
    print(json.dumps(service.snapshot()))
```

The control sequence has four distinct meanings:

1. **Metadata saved:** the CLI returns `saved_restart_required`. This changes disk
   only. A running generation still uses its immutable policy and may admit the
   restricted certificate. Prefer `service.shutdown()` before applying a restriction
   when the operator must avoid this interval.
2. **Old generation stopped:** `replace()` first signals admission stop on both
   listeners, closes both sockets and active connections, and joins both caller-owned
   `process_one` workers. It does not construct a replacement until this completes.
   A previously dispatched operation may finish; retain its UUIDv4 if the response
   is lost. `shutdown()` returns `state=stopped` only after cleanup.
3. **New policy loaded:** under a shared policy-directory lock, `replace()` calls
   `human_credentials.construct_listener` separately for API and browser. Both loads
   see the same policy while cooperating writers are excluded. Both TLS contexts,
   authorization/view binding, repository schemas and bounded view/audit reads must
   validate before opening. At least one enabled, unrevoked, authorized actor must
   remain; an all-restricted policy leaves the service stopped with a failure.
4. **New listeners accepting:** both sockets open before workers are released.
   `replace()` returns `state=accepting`, `accepting=true`, two live workers and an
   incremented process-local `generation`. This count is not a disk revision or a
   persisted change journal. `policy_loaded` is an intermediate state, not readiness.
   Saving another policy does not alter the snapshot or active generation.

Invalid policy/dependencies, failure opening the second listener, and partial worker
startup close every constructed listener and join started workers. There is no
rollback to the old generation or demo credentials. Ordinary failure reports only
`human_lifecycle_failed`; interruption during startup also cleans up before propagating
`KeyboardInterrupt`. Use the context manager or a `finally: service.shutdown()` in
all callers. An unexpected worker failure stops admission on both; the operator must
call shutdown to join workers before reuse. Do not invoke control methods from a
request worker, expose private listener objects, or attach additional process_one
threads. The lifecycle owns the complete set of workers it must join.

Verify a restricted certificate is denied (TLS close or HTTP 401, never protected
view access) and a separate valid actor still reads. Existing audit history is
retained: registry denials remain `authentication_rejected` / `authentication_failed`
with absent actor and the peer fingerprint; TLS handshake failures need not log an
event. Audit's best-effort denial and independent-database gap semantics are unchanged.

The tests use disposable certificates and synthetic retained alert fixtures without
model inference. Shutdown interrupts incomplete handshakes/reads and drains already
dispatched work. No upper bound is claimed for a stuck trusted filesystem/repository
operation; repeated asynchronous signals, SIGKILL, and crash recovery are not established.
No hot reload, CRL or OCSP is implemented.
The directory must remain in place and all writers must use the locking operator API.
These controls do not defend against root or a malicious process on the trusted account.

## Signal-safe supervisor runner and service manager integration

For long-running operational supervision, `threatfusion.operations.human_service_runner.HumanServiceRunner`
wraps `HumanListenerLifecycle` in a single-process supervisor loop with signal handling:

- **Signal Handling:**
  - `SIGTERM` / `SIGINT`: invokes `trigger_shutdown()`, stops listener admission, closes sockets,
    interrupts pending handshakes, drains in-flight requests, joins workers (< 5.0s), and exits `0`.
  - `SIGHUP`: invokes `trigger_reload()`, executing `lifecycle.replace()` under directory lock to
    load the updated credential policy and advance generation. If reload fails (e.g., all actors
    restricted or corrupted policy), the runner fails closed, shuts down listeners, and exits `2`.
  - Initial startup failure (e.g. invalid policy directory or corrupted repository) or unhandled
    listener worker crash immediately exits `1`.
- **Programmatic Control:**
  - `runner.is_ready`: returns `True` only when listeners are accepting and shutdown is not requested.
  - `runner.generation`: tracks current lifecycle generation count.
  - `runner.state`: tracks supervisor lifecycle state (`"initialized"`, `"running"`, `"reloading"`, `"stopping"`, `"stopped"`, `"failed"`).
  - `runner.trigger_shutdown()` and `runner.trigger_reload()`: allow deterministic programmatic triggers.
  - `runner.run_until_stopped(poll_interval_seconds=0.05)`: blocks until signal or stop trigger.
  - Context manager `with HumanServiceRunner(lifecycle) as runner:` ensures clean shutdown drain on exit.

### Hardened reference systemd unit (`threatfusion-analyst.service`)

Deploying under Linux `systemd` requires a dedicated unprivileged user (`operator`) with strict
isolation privileges and read-only access to system binaries:

```ini
[Unit]
Description=ThreatFusion Analyst Loopback TLS Service
After=network.target

[Service]
Type=simple
User=operator
Group=operator
WorkingDirectory=/home/operator/threatfusion
Environment=PYTHONPATH=backend/src
ExecStart=/home/operator/threatfusion/threatfusion-venv/bin/python -m threatfusion.operations.human_service_runner
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
KillSignal=SIGTERM
TimeoutStopSec=10s
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/operator/threatfusion-storage /home/operator/threatfusion-human-policy

[Install]
WantedBy=multi-user.target
```

Reloading credentials under systemd is performed via `systemctl reload threatfusion-analyst`, which
issues `SIGHUP` to trigger generation replacement without dropping the service supervisor process.

CA issuance, secure certificate/private-key delivery to Firefox, backup/recovery,
endurance, and the defensible distinct-alert correlation key remain open.
Operator-action journaling is implemented via `journal.jsonl`.
The existing 64-record bound includes tombstones. Restore access by enrolling a
replacement certificate, not by reverting revoked metadata. TF-008 and TF-009 remain open.
