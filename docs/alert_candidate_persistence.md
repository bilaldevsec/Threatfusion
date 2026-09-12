# AlertCandidate and local persistence boundary

## Product decision and supported path

ThreatFusion persists actionable **Attack** candidates, not every inference decision. A Normal decision
is not a security alert, and rejected or failed inference has no trustworthy model decision to persist.
A separate bounded inference-audit contract may be designed later; it is deliberately absent here so an
actionable alert table does not imply that Normal or failed attempts need analyst action.

The supported offline path is:

`UnswNetworkInferenceBoundary.infer_registered` → pinned manifest member lookup → hash and row-count
verification of one open raw-file snapshot → shared 49-column mapping → `adapt_unsw_row` → validated
`NetworkFlow` → exact `network_behavior_v1` projection → private frozen predictor → immutable registered
result → `build_alert_candidate` → `AlertCandidateRepository.insert`.

The caller supplies only a registered raw-member SHA-256 digest and one-based CSV record ordinal. The
manifest path, source representation, feature mapping, adapter, artifacts, and source identity are
selected by trusted repository code. The digest is an opaque registered-member identity; no filename or
filesystem path enters the source-event ID or candidate. A single streaming pass updates SHA-256 with
each byte line as that same line is decoded and supplied to the CSV parser; there is no verified-then-read
reopen or rewind. Device, inode, size, modification time, and change time must also remain stable. The
complete logical CSV-record count must equal the pinned manifest before prediction. This can be expensive for large offline
members, but avoids a hash/reopen substitution and false row-membership claim.

The earlier `infer`/`infer_batch` raw-array interface remains the supported adaptation-bound inference
interface, but it cannot produce a durable candidate because it lacks registered member and row identity.
CIC and unknown members cannot enter the registered path.

## Versioned identities

`source_event_id` uses schema `unsw_registered_source_event_v1`. Its SHA-256 input is the ordered tuple:

1. source-event schema version;
2. canonical source representation `unsw_nb15.argus.raw_49.transaction_bytes.v1`;
3. pinned manifest SHA-256;
4. registered raw-member SHA-256;
5. canonical decimal one-based CSV record ordinal.

`alert_candidate_id` uses schema `alert_candidate_v1`. Its SHA-256 input is the ordered tuple:

1. AlertCandidate schema version;
2. stable source-event ID;
3. detector identity;
4. detector version;
5. model identity;
6. model version;
7. exact model artifact SHA-256;
8. decision-policy version.

Both hashes use an ASCII domain string followed by NUL. Each UTF-8 tuple part is encoded as a four-byte
unsigned big-endian byte length followed by the bytes. The domains are respectively
`threatfusion:source-event` and `threatfusion:alert-candidate`; the returned value is
`<schema-version>:<lowercase-sha256>`.

Model score, decision result, creation time, observed time, and per-attempt correlation UUID are not
identity inputs. Thus retries of the same event/detector/model/policy reproduce an ID, while another
model, artifact, detector version, or policy produces another ID. Correlation UUIDs remain attempt
identifiers, not ingestion identities.

## AlertCandidate v1 and privacy

The immutable contract stores only schema/candidate/source-event identities, the first successful
attempt's correlation UUID, detector/model/artifact/feature/source identities, legitimate observed and
UTC creation timestamps, explicitly uncalibrated model score, frozen threshold and policy, and the
sanitized `Attack`/`completed`/`inference_succeeded` disposition.

It does not store raw UNSW rows, raw or transformed feature vectors, addresses, ports as evidence,
labels, attack categories, reader-injected IDs, usernames, filenames, paths, secrets, arbitrary caller
provenance, exception text, severity, calibrated confidence, ATT&CK technique, incident identity, or
analyst/correlation state. Diagnostic representations omit all contract values. Model scores are not
calibrated confidence or real-world attack likelihood.

## SQLite transaction and idempotency behavior

`AlertCandidateRepository` is a standard-library SQLite boundary with explicit schema identity
`alert_candidate_sqlite_v1` and `PRAGMA user_version=1`. Initialization checks file type, non-empty
existing state, SQLite integrity, metadata and exact column constraints. It does not replace a corrupt
or version-mismatched database.

Insertion uses `BEGIN IMMEDIATE`. A missing primary key is inserted and reported `created`; an existing
row with equal stable content is reported `existing` and retains the first creation time/correlation
UUID. A same-ID row whose stable content differs rolls back and reports
`alert_candidate_identity_conflict`. Exact contract evidence must match; uncalibrated scores use
absolute tolerance 1e-15 so harmless binary-float roundoff is idempotent while material score
differences remain conflicts. Write failures roll back. Retrieval uses the candidate ID;
listing is ordered by creation timestamp then candidate ID, limited to 100 records per call and a bounded
offset. Queries use fixed SQL and parameterized values. SQLite busy waits are bounded to 500 ms and all
externally reportable errors are stable codes without paths, SQL or underlying exception details.

SQLite provides local single-node durability and serialized writes, not distributed locking, queueing,
retention, automated migration, backup, or disaster recovery. Blocking file systems and total database
size are not bounded by this component. Runtime database files and their WAL/SHM companions are ignored.

The producer replay journal is a separate SQLite database and does not change this final Attack-only
idempotency boundary. It durably prevents an exact completed producer request from invoking inference
or this repository again, while `outcome_unknown` prohibits automatic reprocessing after an abandoned
claim. The replay journal stores only request/evidence digests and a sanitized cached response; it does
not store an AlertCandidate, raw evidence or model result internals. The AlertCandidate primary key
remains the final idempotency boundary for later recovery reconciliation or a race after inference.

## Trust and future boundaries

This is application-path enforcement, not cryptographic authentication. Trusted application code,
configured root, manifest/hash allowlists, adapters, feature builders, model dependencies, SQLite and
local filesystem semantics (including stable open-file-descriptor reads and `fstat` metadata) remain in
the trusted computing base. Python frozen/private objects do not
protect against malicious code already executing in-process, and local file permissions/host integrity
remain deployment responsibilities.

The registered identity applies only to pinned offline UNSW files. Future live telemetry needs a
producer-assigned authenticated event identity, admission policy, bounded transport/body/time controls,
and replay rules. Correlation, analyst state, explanation, retention and external APIs remain separate
future contracts. TF-012 remains open and CIC remains rejected.
