# Coordinated multi-database online backup, snapshot verification, and atomic restore

This Linux operational runbook defines the procedures for creating verified online
snapshots and performing offline atomic restores across ThreatFusion's three local
SQLite databases:
1. **Retained Alerts Database** (`alerts.sqlite3` / `alert_candidate_sqlite_v1`)
2. **Analyst Workflow State Database** (`states.sqlite3` / `analyst_state_sqlite_v1`)
3. **Analyst Security Audit Database** (`audit.sqlite3` / `analyst_security_audit_sqlite_v1`)

## Preconditions and security boundaries

Use the repository's `threatfusion-venv` and Python 3.11.

- **Private Directory and File Modes:** All storage directories (source, snapshot,
  and restore target) must be absolute paths owned by the operator account with exact
  mode `0700`. Ancestors must be owned by `root` or the operator account without
  group/world write permissions (mode `0700` or root-owned sticky directories).
  All snapshot and restored database files and manifests are created with exact mode `0600`.
- **Symlink Rejection:** Symlinks in directory paths, ancestor components, database files,
  or manifest files are rejected (`O_NOFOLLOW` descriptor-relative traversal).
- **Concurrency and Locking:** Operations acquire non-blocking directory inode locks
  (`fcntl.flock(fd, LOCK_EX | LOCK_NB)`). Concurrent backup or restore operations fail
  immediately on contention with `StorageBackupError("lock_failed")`.
- **Online Backup Mechanism:** Snapshots use Python's `sqlite3.Connection.backup()` API
  over read-only connections (`mode=ro`), obtaining page-level consistency from SQLite
  rather than performing raw unsafe filesystem copies.
- **Sequential Backup Notice:** The three databases are snapshotted sequentially.
  Because SQLite databases reside in independent transaction boundaries without a
  distributed two-phase commit, taking snapshots while listeners are actively handling
  high-throughput transitions could allow slight interleaving. To ensure strict cross-database
  point-in-time synchronization, **snapshots should be taken while listeners are stopped or
  quiescent** (such as between batch processing intervals or during scheduled maintenance).
- **Cryptographic & Relational Integrity:** Every snapshot produces a SHA-256 manifest
  (`manifest.json`, schema `storage_snapshot_manifest_v1`, capped at 64 KiB), runs
  `PRAGMA integrity_check` on all three databases, verifies `schema_identity` and
  `schema_version`, and enforces cross-database referential consistency (every
  `alert_candidate_id` present in `states.sqlite3` must exist in `alerts.sqlite3`).
- **Atomic Offline Restore:** Restores require the target storage directory to be locked
  and listeners to be stopped. Restoration stages each database file through a private
  temporary file (`.{filename}.tmp.{uuid}`, mode `0600`), fsyncs, atomically replaces
  (`os.replace`), cleans up any obsolete `-wal` or `-shm` sidecars, and fsyncs the
  directory inode. If an error occurs, uncommitted target databases remain completely
  untouched.

## CLI commands

The operational entry point is `threatfusion.operations.storage_backup`:

```sh
# 1. Create a verified snapshot from active storage into a fresh snapshot directory
PYTHONPATH=backend/src threatfusion-venv/bin/python -m threatfusion.operations.storage_backup create \
  --source-dir /home/operator/threatfusion-storage \
  --snapshot-dir /home/operator/threatfusion-snapshots/20261014-01

# 2. Cryptographically and relationally verify an existing snapshot
PYTHONPATH=backend/src threatfusion-venv/bin/python -m threatfusion.operations.storage_backup verify \
  --snapshot-dir /home/operator/threatfusion-snapshots/20261014-01

# 3. Atomically restore a verified snapshot into a target storage directory (listeners stopped)
PYTHONPATH=backend/src threatfusion-venv/bin/python -m threatfusion.operations.storage_backup restore \
  --snapshot-dir /home/operator/threatfusion-snapshots/20261014-01 \
  --target-dir /home/operator/threatfusion-storage
```

Success exits `0` with the formatted JSON manifest. Policy/integrity failure exits `1`
with sanitized error `storage_backup_error: <code>` on stderr. Syntax errors exit `2`.

## Python API integration

Programs driving listener lifecycles or maintenance scripts can import the operations directly:

```python
from pathlib import Path
from threatfusion.operations.storage_backup import (
    create_storage_snapshot,
    verify_storage_snapshot,
    restore_storage_snapshot,
    StorageBackupError,
)

storage_dir = Path("/home/operator/threatfusion-storage")
snapshot_dir = Path("/home/operator/threatfusion-snapshots/snapshot-1")

# Create snapshot
try:
    manifest = create_storage_snapshot(source_dir=storage_dir, snapshot_dir=snapshot_dir)
    print(f"Snapshot created at {manifest['created_at_utc']}")
except StorageBackupError as err:
    print(f"Backup failed: {err.code}")

# Verify snapshot
try:
    verified = verify_storage_snapshot(snapshot_dir)
    print("Snapshot verification succeeded")
except StorageBackupError as err:
    print(f"Verification failed: {err.code}")

# Restore snapshot (with service listeners stopped)
target_dir = Path("/home/operator/threatfusion-storage-restored")
try:
    restore_storage_snapshot(snapshot_dir=snapshot_dir, target_dir=target_dir)
    print("Restore completed successfully")
except StorageBackupError as err:
    print(f"Restore failed: {err.code}")
```

## Manifest schema specification (`storage_snapshot_manifest_v1`)

The generated `manifest.json` contains:

```json
{
  "schema": "storage_snapshot_manifest_v1",
  "created_at_utc": "2026-10-14T07:05:00+00:00",
  "databases": {
    "alerts": {
      "filename": "alerts.sqlite3",
      "sha256": "4a5c...",
      "size_bytes": 16384,
      "schema_identity": "alert_candidate_sqlite_v1",
      "schema_version": 1,
      "row_counts": {
        "alert_candidates": 3,
        "repository_metadata": 1
      }
    },
    "states": {
      "filename": "states.sqlite3",
      "sha256": "8f2d...",
      "size_bytes": 20480,
      "schema_identity": "analyst_state_sqlite_v1",
      "schema_version": 1,
      "row_counts": {
        "analyst_states": 2,
        "analyst_transition_events": 3,
        "repository_metadata": 1
      }
    },
    "audit": {
      "filename": "audit.sqlite3",
      "sha256": "e3b0...",
      "size_bytes": 16384,
      "schema_identity": "analyst_security_audit_sqlite_v1",
      "schema_version": 1,
      "row_counts": {
        "audit_events": 3,
        "audit_metadata": 1
      }
    }
  },
  "cross_database_consistency": {
    "total_alert_candidates": 3,
    "total_analyst_states": 2,
    "orphan_states_count": 0
  }
}
```

## Error code reference

All failures raise `StorageBackupError` (CLI exit code 1) with one of the following sanitized reason codes:

- `directory_invalid`: Directory path is not absolute or contains parent references (`..`).
- `permission_invalid`: Directory mode is not `0700`, file mode is not `0600`, or ownership mismatch.
- `symlink_rejected`: Path component or database/manifest file is a symbolic link.
- `lock_failed`: File system lock could not be acquired due to concurrent activity.
- `snapshot_directory_not_empty`: Snapshot directory exists and already contains non-hidden entries.
- `unexpected_file`: Snapshot directory contains unknown or extraneous files.
- `snapshot_incomplete`: One or more required snapshot files (`manifest.json` or databases) are missing.
- `manifest_invalid`: Manifest file is corrupt, not valid JSON, or schema mismatch.
- `manifest_too_large`: Manifest file exceeds maximum size threshold (64 KiB).
- `digest_mismatch`: SHA-256 hash or size in bytes does not match the recorded manifest.
- `database_corrupt` / `integrity_check_failed`: SQLite `PRAGMA integrity_check` failed.
- `schema_mismatch`: Table structure, column layout, user_version, or schema identity mismatch.
- `referential_integrity_failed`: An `alert_candidate_id` referenced in `states.sqlite3` is absent from `alerts.sqlite3`.
- `source_file_invalid` / `file_invalid`: File access error or file is not a regular file.

## Quiescent snapshot and restore coordination with HumanListenerLifecycle

To eliminate any risk of sequential interleaving during active listener traffic without requiring manual
process stopping, `HumanListenerLifecycle` provides programmatic quiescent coordination methods:

- **`snapshot_quiescent(snapshot_dir, storage_dir=None) -> dict[str, object]`**:
  1. Stops listener admission on both API and browser mTLS endpoints.
  2. Closes sockets and active connections, interrupting pending handshakes and joining both worker
     threads (< 5.0s drain) so zero in-flight requests or writes are active across the three databases.
  3. Executes `create_storage_snapshot(source_dir, snapshot_dir)` under exclusive directory lock,
     performing page-level backups, `PRAGMA integrity_check`, referential integrity verification, and
     manifest generation.
  4. Starts a fresh listener generation via `replace()`, restoring listener admission.
  5. Returns the verified `storage_snapshot_manifest_v1` dictionary. If restarting the generation fails,
     fails closed leaving no half-open listeners.

- **`restore_quiescent(snapshot_dir, storage_dir=None) -> dict[str, object]`**:
  1. Validates the candidate snapshot directory via `verify_storage_snapshot(snapshot_dir)`.
  2. Stops listener admission, closes sockets, and joins both worker threads.
  3. Executes `restore_storage_snapshot(snapshot_dir, target_dir)` under directory lock, atomically
     replacing active database files from the verified snapshot.
  4. Starts a fresh listener generation bound to the restored database state, verifying schema integrity.
  5. Returns the verified `storage_snapshot_manifest_v1` dictionary.

Example programmatic usage:

```python
# Create quiescent point-in-time snapshot with automated drain and resume
manifest = lifecycle.snapshot_quiescent("/home/operator/threatfusion-snapshots/quiescent-01")
print(f"Quiescent snapshot generation: {lifecycle.snapshot()['generation']}")

# Restore snapshot quiescing active listeners and resuming on restored state
restored_manifest = lifecycle.restore_quiescent("/home/operator/threatfusion-snapshots/quiescent-01")
print(f"Resumed on restored snapshot, generation: {lifecycle.snapshot()['generation']}")
```

## Open boundaries under TF-008 and TF-009

This procedure solves coordinated snapshot creation, integrity verification, and atomic restore
for local SQLite storage. Operational browser credential delivery, CA issuance,
long-term endurance testing, and the defensible distinct-alert correlation key remain open under TF-008 and TF-009.
