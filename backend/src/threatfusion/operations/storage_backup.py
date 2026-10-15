"""Fail-closed, local operator multi-database online backup and atomic restore.

Implements storage snapshot creation, cryptographic verification, and atomic
offline restore across the three ThreatFusion SQLite databases:
- Retained alerts database (alerts.sqlite3 / alert_candidate_sqlite_v1)
- Analyst state workflow database (states.sqlite3 / analyst_state_sqlite_v1)
- Analyst security audit database (audit.sqlite3 / analyst_security_audit_sqlite_v1)

Enforces mode-0700 private directories, mode-0600 files, no symlinks, descriptor-
relative traversal, filesystem locks (flock), SHA-256 manifests, SQLite integrity
checks, and cross-database referential consistency (every alert_candidate_id in
analyst states must exist in retained alerts).
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import sys
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Generator

SNAPSHOT_MANIFEST_SCHEMA = "storage_snapshot_manifest_v1"
MANIFEST_FILENAME = "manifest.json"

ALERTS_DB_ROLE = "alerts"
STATES_DB_ROLE = "states"
AUDIT_DB_ROLE = "audit"
INCIDENTS_DB_ROLE = "incidents"

ALERTS_DB_FILENAME = "alerts.sqlite3"
STATES_DB_FILENAME = "states.sqlite3"
AUDIT_DB_FILENAME = "audit.sqlite3"
INCIDENTS_DB_FILENAME = "incidents.sqlite3"

CORE_DB_ROLES = (ALERTS_DB_ROLE, STATES_DB_ROLE, AUDIT_DB_ROLE)
SUPPORTED_DB_ROLES = (ALERTS_DB_ROLE, STATES_DB_ROLE, AUDIT_DB_ROLE, INCIDENTS_DB_ROLE)
EXPECTED_DB_FILENAMES = {
    ALERTS_DB_ROLE: ALERTS_DB_FILENAME,
    STATES_DB_ROLE: STATES_DB_FILENAME,
    AUDIT_DB_ROLE: AUDIT_DB_FILENAME,
    INCIDENTS_DB_ROLE: INCIDENTS_DB_FILENAME,
}

EXPECTED_SCHEMA_IDENTITIES = {
    ALERTS_DB_ROLE: "alert_candidate_sqlite_v1",
    STATES_DB_ROLE: "analyst_state_sqlite_v1",
    AUDIT_DB_ROLE: "analyst_security_audit_sqlite_v1",
    INCIDENTS_DB_ROLE: "incident_sqlite_v1",
}

EXPECTED_SCHEMA_VERSIONS = {
    ALERTS_DB_ROLE: 1,
    STATES_DB_ROLE: 1,
    AUDIT_DB_ROLE: 1,
    INCIDENTS_DB_ROLE: 1,
}

MAX_MANIFEST_BYTES = 65536
SQLITE_TIMEOUT_SECONDS = 5.0


class StorageBackupError(RuntimeError):
    """Sanitized failure for storage backup, verification, and restore operations."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"<StorageBackupError: {self.code}>"


@contextmanager
def _directory_context(directory: Path, *, write: bool = True) -> Generator[int, None, None]:
    """Walk descriptors without following symlinks; verify ancestor modes/ownership; lock inode."""
    if not isinstance(directory, Path):
        directory = Path(directory)
    if not directory.is_absolute() or ".." in directory.parts:
        raise StorageBackupError("directory_invalid")

    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        raise StorageBackupError("directory_invalid") from None

    try:
        for part in directory.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as err:
                if err.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise StorageBackupError("symlink_rejected") from None
                raise StorageBackupError("directory_invalid") from None
            os.close(fd)
            fd = child
            try:
                info = os.fstat(fd)
            except OSError:
                raise StorageBackupError("directory_invalid") from None

            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not sticky_root):
                raise StorageBackupError("permission_invalid")

        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise StorageBackupError("directory_invalid")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise StorageBackupError("permission_invalid")

        try:
            lock_flag = (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB
            fcntl.flock(fd, lock_flag)
        except (BlockingIOError, OSError):
            raise StorageBackupError("lock_failed") from None

        yield fd
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _ensure_private_directory(directory: Path) -> None:
    """Ensure directory exists with mode 0700 under verified ancestors."""
    if not isinstance(directory, Path):
        directory = Path(directory)
    if not directory.is_absolute() or ".." in directory.parts:
        raise StorageBackupError("directory_invalid")

    if not directory.exists():
        parent = directory.parent
        with _directory_context(parent, write=True) as pfd:
            try:
                os.mkdir(directory.name, 0o700, dir_fd=pfd)
            except OSError as err:
                if err.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise StorageBackupError("symlink_rejected") from None
                raise StorageBackupError("directory_invalid") from None
            child_fd = os.open(
                directory.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=pfd,
            )
            try:
                os.fchmod(child_fd, 0o700)
            finally:
                os.close(child_fd)


def _check_no_symlink(path: Path) -> os.stat_result:
    """Check that path is a regular file owned by current user and not a symlink."""
    try:
        info = path.lstat()
    except OSError:
        raise StorageBackupError("file_invalid") from None

    if stat.S_ISLNK(info.st_mode):
        raise StorageBackupError("symlink_rejected")
    if not stat.S_ISREG(info.st_mode):
        raise StorageBackupError("file_invalid")
    return info


def _compute_sha256(path: Path) -> str:
    """Calculate the SHA-256 hex digest of a file."""
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as stream:
            while chunk := stream.read(65536):
                hasher.update(chunk)
    except OSError:
        raise StorageBackupError("file_invalid") from None
    return hasher.hexdigest()


def _backup_sqlite(src_path: Path, dest_path: Path) -> None:
    """Perform online SQLite backup from src_path to dest_path with mode 0600."""
    _check_no_symlink(src_path)
    if dest_path.exists():
        _check_no_symlink(dest_path)

    try:
        src_conn = sqlite3.connect(
            f"file:{src_path.resolve()}?mode=ro",
            uri=True,
            timeout=SQLITE_TIMEOUT_SECONDS,
        )
    except sqlite3.Error:
        raise StorageBackupError("database_corrupt") from None

    try:
        dest_conn = sqlite3.connect(str(dest_path.resolve()), timeout=SQLITE_TIMEOUT_SECONDS)
        try:
            src_conn.backup(dest_conn)
        finally:
            dest_conn.close()
    except (sqlite3.Error, OSError):
        raise StorageBackupError("backup_failed") from None
    finally:
        src_conn.close()

    try:
        os.chmod(dest_path, 0o600)
        fd = os.open(dest_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        raise StorageBackupError("file_invalid") from None


def _inspect_database(db_path: Path, role: str) -> dict[str, object]:
    """Inspect and verify integrity, schema identity, and row counts of a database."""
    info = _check_no_symlink(db_path)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise StorageBackupError("permission_invalid")
    if info.st_size == 0:
        raise StorageBackupError("database_corrupt")

    sha256_digest = _compute_sha256(db_path)

    try:
        conn = sqlite3.connect(
            f"file:{db_path.resolve()}?mode=ro",
            uri=True,
            timeout=SQLITE_TIMEOUT_SECONDS,
        )
        conn.row_factory = sqlite3.Row
        try:
            result = conn.execute("PRAGMA integrity_check").fetchall()
            if not result or result[0][0] != "ok":
                raise StorageBackupError("integrity_check_failed")

            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version != EXPECTED_SCHEMA_VERSIONS[role]:
                raise StorageBackupError("schema_mismatch")

            meta_table = "audit_metadata" if role == AUDIT_DB_ROLE else "repository_metadata"
            meta_row = conn.execute(
                f"SELECT value FROM {meta_table} WHERE key = 'schema_identity'"
            ).fetchone()
            if meta_row is None or meta_row[0] != EXPECTED_SCHEMA_IDENTITIES[role]:
                raise StorageBackupError("schema_mismatch")

            row_counts: dict[str, int] = {}
            if role == ALERTS_DB_ROLE:
                row_counts["alert_candidates"] = conn.execute(
                    "SELECT COUNT(*) FROM alert_candidates"
                ).fetchone()[0]
                row_counts["repository_metadata"] = conn.execute(
                    "SELECT COUNT(*) FROM repository_metadata"
                ).fetchone()[0]
            elif role == STATES_DB_ROLE:
                row_counts["analyst_states"] = conn.execute(
                    "SELECT COUNT(*) FROM analyst_states"
                ).fetchone()[0]
                row_counts["analyst_transition_events"] = conn.execute(
                    "SELECT COUNT(*) FROM analyst_transition_events"
                ).fetchone()[0]
                row_counts["repository_metadata"] = conn.execute(
                    "SELECT COUNT(*) FROM repository_metadata"
                ).fetchone()[0]
            elif role == AUDIT_DB_ROLE:
                row_counts["audit_events"] = conn.execute(
                    "SELECT COUNT(*) FROM audit_events"
                ).fetchone()[0]
                row_counts["audit_metadata"] = conn.execute(
                    "SELECT COUNT(*) FROM audit_metadata"
                ).fetchone()[0]
            elif role == INCIDENTS_DB_ROLE:
                row_counts["incidents"] = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[
                    0
                ]
                row_counts["incident_constituent_alerts"] = conn.execute(
                    "SELECT COUNT(*) FROM incident_constituent_alerts"
                ).fetchone()[0]
                has_corrections = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='incident_grouping_corrections'"
                ).fetchone()
                if has_corrections:
                    row_counts["incident_grouping_corrections"] = conn.execute(
                        "SELECT COUNT(*) FROM incident_grouping_corrections"
                    ).fetchone()[0]
                row_counts["repository_metadata"] = conn.execute(
                    "SELECT COUNT(*) FROM repository_metadata"
                ).fetchone()[0]
        finally:
            conn.close()
    except (sqlite3.DatabaseError, sqlite3.Error):
        raise StorageBackupError("database_corrupt") from None

    return {
        "filename": EXPECTED_DB_FILENAMES[role],
        "sha256": sha256_digest,
        "size_bytes": info.st_size,
        "schema_identity": EXPECTED_SCHEMA_IDENTITIES[role],
        "schema_version": EXPECTED_SCHEMA_VERSIONS[role],
        "row_counts": row_counts,
    }


def _check_cross_database_consistency(
    alerts_path: Path, states_path: Path, incidents_path: Path | None = None
) -> dict[str, int]:
    """Verify that every alert_candidate_id in analyst state and incidents exists in retained alerts."""
    try:
        alerts_conn = sqlite3.connect(
            f"file:{alerts_path.resolve()}?mode=ro",
            uri=True,
            timeout=SQLITE_TIMEOUT_SECONDS,
        )
        states_conn = sqlite3.connect(
            f"file:{states_path.resolve()}?mode=ro",
            uri=True,
            timeout=SQLITE_TIMEOUT_SECONDS,
        )
        incidents_conn = None
        if incidents_path is not None and incidents_path.exists():
            incidents_conn = sqlite3.connect(
                f"file:{incidents_path.resolve()}?mode=ro",
                uri=True,
                timeout=SQLITE_TIMEOUT_SECONDS,
            )
        try:
            alert_ids = {
                row[0]
                for row in alerts_conn.execute("SELECT alert_candidate_id FROM alert_candidates")
            }
            state_ids = {
                row[0]
                for row in states_conn.execute("SELECT alert_candidate_id FROM analyst_states")
            }
            transition_ids = {
                row[0]
                for row in states_conn.execute(
                    "SELECT alert_candidate_id FROM analyst_transition_events"
                )
            }
            orphans = (state_ids | transition_ids) - alert_ids
            if orphans:
                raise StorageBackupError("referential_integrity_failed")

            total_incidents = 0
            if incidents_conn is not None:
                inc_alert_ids = {
                    row[0]
                    for row in incidents_conn.execute(
                        "SELECT alert_candidate_id FROM incident_constituent_alerts"
                    )
                }
                inc_orphans = inc_alert_ids - alert_ids
                if inc_orphans:
                    raise StorageBackupError("referential_integrity_failed")
                total_incidents = incidents_conn.execute(
                    "SELECT COUNT(*) FROM incidents"
                ).fetchone()[0]

            res = {
                "total_alert_candidates": len(alert_ids),
                "total_analyst_states": len(state_ids),
                "orphan_states_count": 0,
            }
            if incidents_conn is not None:
                res["total_incidents"] = total_incidents
                res["orphan_incident_alerts_count"] = 0
            return res
        finally:
            alerts_conn.close()
            states_conn.close()
            if incidents_conn is not None:
                incidents_conn.close()
    except (sqlite3.DatabaseError, sqlite3.Error):
        raise StorageBackupError("database_corrupt") from None


def _write_manifest(snapshot_dir: Path, manifest_data: dict[str, object]) -> None:
    """Atomically write and fsync manifest.json with mode 0600."""
    manifest_bytes = (json.dumps(manifest_data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise StorageBackupError("manifest_too_large")

    tmp_path = snapshot_dir / f".{MANIFEST_FILENAME}.tmp.{uuid.uuid4().hex}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(tmp_path, flags, 0o600)
    except OSError:
        raise StorageBackupError("file_invalid") from None

    try:
        os.fchmod(fd, 0o600)
        os.write(fd, manifest_bytes)
        os.fsync(fd)
    finally:
        os.close(fd)

    manifest_path = snapshot_dir / MANIFEST_FILENAME
    try:
        os.replace(tmp_path, manifest_path)
    except OSError:
        raise StorageBackupError("file_invalid") from None

    dfd = os.open(snapshot_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _resolve_paths(
    arg1: Path | str | None = None,
    arg2: Path | str | None = None,
    *,
    source_dir: Path | str | None = None,
    snapshot_dir: Path | str | None = None,
    alerts_path: Path | str | None = None,
    states_path: Path | str | None = None,
    audit_path: Path | str | None = None,
    incidents_path: Path | str | None = None,
) -> tuple[Path, Path, Path, Path, Path | None]:
    """Resolve snapshot directory and source database paths from positional/keyword args."""
    resolved_source_dir: Path | None = None
    resolved_snapshot_dir: Path | None = None

    if arg1 is not None and arg2 is not None:
        resolved_source_dir = Path(arg1)
        resolved_snapshot_dir = Path(arg2)
    elif arg1 is not None:
        if snapshot_dir is not None:
            resolved_source_dir = Path(arg1)
            resolved_snapshot_dir = Path(snapshot_dir)
        elif source_dir is not None:
            resolved_snapshot_dir = Path(arg1)
            resolved_source_dir = Path(source_dir)
        else:
            resolved_snapshot_dir = Path(arg1)
    else:
        if snapshot_dir is not None:
            resolved_snapshot_dir = Path(snapshot_dir)
        if source_dir is not None:
            resolved_source_dir = Path(source_dir)

    if resolved_snapshot_dir is None:
        raise StorageBackupError("snapshot_directory_missing")

    if resolved_source_dir is not None:
        res_alerts = (
            Path(alerts_path) if alerts_path else (resolved_source_dir / ALERTS_DB_FILENAME)
        )
        res_states = (
            Path(states_path) if states_path else (resolved_source_dir / STATES_DB_FILENAME)
        )
        res_audit = Path(audit_path) if audit_path else (resolved_source_dir / AUDIT_DB_FILENAME)
        if incidents_path is not None:
            res_incidents = Path(incidents_path) if Path(incidents_path).exists() else None
        else:
            cand = resolved_source_dir / INCIDENTS_DB_FILENAME
            res_incidents = cand if cand.exists() else None
    else:
        if not (alerts_path and states_path and audit_path):
            raise StorageBackupError("source_directory_missing")
        res_alerts = Path(alerts_path)
        res_states = Path(states_path)
        res_audit = Path(audit_path)
        res_incidents = (
            Path(incidents_path) if incidents_path and Path(incidents_path).exists() else None
        )

    return resolved_snapshot_dir, res_alerts, res_states, res_audit, res_incidents


def create_storage_snapshot(
    source: Path | str | None = None,
    destination: Path | str | None = None,
    *,
    source_dir: Path | str | None = None,
    snapshot_dir: Path | str | None = None,
    alerts_path: Path | str | None = None,
    states_path: Path | str | None = None,
    audit_path: Path | str | None = None,
    incidents_path: Path | str | None = None,
) -> dict[str, object]:
    """Create a consistent online snapshot of all three SQLite databases into snapshot_dir."""
    target_snapshot_dir, src_alerts, src_states, src_audit, src_incidents = _resolve_paths(
        source,
        destination,
        source_dir=source_dir,
        snapshot_dir=snapshot_dir,
        alerts_path=alerts_path,
        states_path=states_path,
        audit_path=audit_path,
        incidents_path=incidents_path,
    )

    _ensure_private_directory(target_snapshot_dir)

    with _directory_context(target_snapshot_dir, write=True):
        existing_entries = [
            name for name in os.listdir(target_snapshot_dir) if not name.startswith(".")
        ]
        if existing_entries:
            raise StorageBackupError("snapshot_directory_not_empty")

        dest_alerts = target_snapshot_dir / ALERTS_DB_FILENAME
        dest_states = target_snapshot_dir / STATES_DB_FILENAME
        dest_audit = target_snapshot_dir / AUDIT_DB_FILENAME

        _backup_sqlite(src_alerts, dest_alerts)
        _backup_sqlite(src_states, dest_states)
        _backup_sqlite(src_audit, dest_audit)

        alerts_info = _inspect_database(dest_alerts, ALERTS_DB_ROLE)
        states_info = _inspect_database(dest_states, STATES_DB_ROLE)
        audit_info = _inspect_database(dest_audit, AUDIT_DB_ROLE)

        databases_manifest = {
            ALERTS_DB_ROLE: alerts_info,
            STATES_DB_ROLE: states_info,
            AUDIT_DB_ROLE: audit_info,
        }

        dest_incidents = None
        if src_incidents is not None and src_incidents.exists():
            dest_incidents = target_snapshot_dir / INCIDENTS_DB_FILENAME
            _backup_sqlite(src_incidents, dest_incidents)
            incidents_info = _inspect_database(dest_incidents, INCIDENTS_DB_ROLE)
            databases_manifest[INCIDENTS_DB_ROLE] = incidents_info

        consistency_info = _check_cross_database_consistency(
            dest_alerts, dest_states, dest_incidents
        )

        manifest_data = {
            "schema": SNAPSHOT_MANIFEST_SCHEMA,
            "created_at_utc": datetime.now(UTC).isoformat(),
            "databases": databases_manifest,
            "cross_database_consistency": consistency_info,
        }

        _write_manifest(target_snapshot_dir, manifest_data)
        return manifest_data


def verify_storage_snapshot(snapshot_dir: Path | str) -> dict[str, object]:
    """Verify cryptographic digests, schema versions, and referential integrity of a snapshot."""
    target_snapshot_dir = Path(snapshot_dir) if not isinstance(snapshot_dir, Path) else snapshot_dir

    with _directory_context(target_snapshot_dir, write=False):
        all_entries = os.listdir(target_snapshot_dir)
        non_hidden = [name for name in all_entries if not name.startswith(".")]
        expected_set = {
            MANIFEST_FILENAME,
            ALERTS_DB_FILENAME,
            STATES_DB_FILENAME,
            AUDIT_DB_FILENAME,
        }
        if INCIDENTS_DB_FILENAME in non_hidden:
            expected_set.add(INCIDENTS_DB_FILENAME)

        if set(non_hidden) != expected_set:
            unexpected = set(non_hidden) - expected_set
            if unexpected:
                raise StorageBackupError("unexpected_file")
            raise StorageBackupError("snapshot_incomplete")

        manifest_path = target_snapshot_dir / MANIFEST_FILENAME
        _check_no_symlink(manifest_path)
        minfo = manifest_path.stat()
        if minfo.st_uid != os.geteuid() or stat.S_IMODE(minfo.st_mode) != 0o600:
            raise StorageBackupError("permission_invalid")

        try:
            with open(manifest_path, "r", encoding="utf-8") as stream:
                manifest = json.load(stream)
        except (OSError, json.JSONDecodeError):
            raise StorageBackupError("manifest_invalid") from None

        if (
            not isinstance(manifest, dict)
            or manifest.get("schema") != SNAPSHOT_MANIFEST_SCHEMA
            or "databases" not in manifest
            or not isinstance(manifest["databases"], dict)
        ):
            raise StorageBackupError("manifest_invalid")

        db_manifests = manifest["databases"]
        for role in CORE_DB_ROLES:
            if role not in db_manifests:
                raise StorageBackupError("manifest_invalid")

        for role in db_manifests:
            if role not in SUPPORTED_DB_ROLES:
                raise StorageBackupError("manifest_invalid")

            expected_filename = EXPECTED_DB_FILENAMES[role]
            db_path = target_snapshot_dir / expected_filename
            _check_no_symlink(db_path)
            finfo = db_path.stat()
            if finfo.st_uid != os.geteuid() or stat.S_IMODE(finfo.st_mode) != 0o600:
                raise StorageBackupError("permission_invalid")

            expected_sha256 = db_manifests[role].get("sha256")
            actual_sha256 = _compute_sha256(db_path)
            if actual_sha256 != expected_sha256:
                raise StorageBackupError("digest_mismatch")

            expected_size = db_manifests[role].get("size_bytes")
            if finfo.st_size != expected_size:
                raise StorageBackupError("digest_mismatch")

            inspected = _inspect_database(db_path, role)
            if inspected["row_counts"] != db_manifests[role].get("row_counts"):
                raise StorageBackupError("schema_mismatch")

        alerts_path = target_snapshot_dir / ALERTS_DB_FILENAME
        states_path = target_snapshot_dir / STATES_DB_FILENAME
        incidents_path = (
            target_snapshot_dir / INCIDENTS_DB_FILENAME
            if INCIDENTS_DB_ROLE in db_manifests
            else None
        )
        _check_cross_database_consistency(alerts_path, states_path, incidents_path)

        return manifest


def restore_storage_snapshot(
    snapshot: Path | str | None = None,
    target: Path | str | None = None,
    *,
    snapshot_dir: Path | str | None = None,
    target_dir: Path | str | None = None,
) -> dict[str, object]:
    """Atomically restore verified snapshot databases into target_dir."""
    resolved_snapshot_dir: Path | None = None
    resolved_target_dir: Path | None = None

    if snapshot is not None and target is not None:
        resolved_snapshot_dir = Path(snapshot)
        resolved_target_dir = Path(target)
    elif snapshot is not None:
        if target_dir is not None:
            resolved_snapshot_dir = Path(snapshot)
            resolved_target_dir = Path(target_dir)
        elif snapshot_dir is not None:
            resolved_target_dir = Path(snapshot)
            resolved_snapshot_dir = Path(snapshot_dir)
        else:
            raise StorageBackupError("target_directory_missing")
    else:
        if snapshot_dir is not None:
            resolved_snapshot_dir = Path(snapshot_dir)
        if target_dir is not None:
            resolved_target_dir = Path(target_dir)

    if resolved_snapshot_dir is None:
        raise StorageBackupError("snapshot_directory_missing")
    if resolved_target_dir is None:
        raise StorageBackupError("target_directory_missing")

    manifest = verify_storage_snapshot(resolved_snapshot_dir)

    with _directory_context(resolved_target_dir, write=True) as target_fd:
        for role in manifest["databases"]:
            filename = EXPECTED_DB_FILENAMES[role]
            src_file = resolved_snapshot_dir / filename
            dest_file = resolved_target_dir / filename
            tmp_file = resolved_target_dir / f".{filename}.tmp.{uuid.uuid4().hex}"

            try:
                tfd = os.open(
                    tmp_file,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
            except OSError:
                raise StorageBackupError("file_invalid") from None

            try:
                with open(src_file, "rb") as s_in:
                    while chunk := s_in.read(65536):
                        os.write(tfd, chunk)
                os.fchmod(tfd, 0o600)
                os.fsync(tfd)
            finally:
                os.close(tfd)

            try:
                os.replace(tmp_file, dest_file)
            except OSError:
                raise StorageBackupError("file_invalid") from None

            for sidecar in (f"{filename}-wal", f"{filename}-shm"):
                sidecar_path = resolved_target_dir / sidecar
                if sidecar_path.exists():
                    try:
                        os.unlink(sidecar_path)
                    except OSError:
                        pass

        try:
            os.fsync(target_fd)
        except OSError:
            raise StorageBackupError("file_invalid") from None

        for role in manifest["databases"]:
            dest_file = resolved_target_dir / EXPECTED_DB_FILENAMES[role]
            _inspect_database(dest_file, role)

        incidents_path = (
            resolved_target_dir / INCIDENTS_DB_FILENAME
            if INCIDENTS_DB_ROLE in manifest["databases"]
            else None
        )
        _check_cross_database_consistency(
            resolved_target_dir / ALERTS_DB_FILENAME,
            resolved_target_dir / STATES_DB_FILENAME,
            incidents_path,
        )

        return manifest


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for storage backup operations."""
    parser = argparse.ArgumentParser(
        prog="storage_backup",
        description="ThreatFusion storage snapshot backup and restore CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create", help="Create a storage snapshot")
    create_parser.add_argument("--source-dir", required=True, type=Path)
    create_parser.add_argument("--snapshot-dir", required=True, type=Path)

    verify_parser = subparsers.add_parser("verify", help="Verify an existing snapshot")
    verify_parser.add_argument("--snapshot-dir", required=True, type=Path)

    restore_parser = subparsers.add_parser("restore", help="Restore snapshot into target directory")
    restore_parser.add_argument("--snapshot-dir", required=True, type=Path)
    restore_parser.add_argument("--target-dir", required=True, type=Path)

    args = parser.parse_args(argv)

    try:
        if args.command == "create":
            result = create_storage_snapshot(
                source_dir=args.source_dir,
                snapshot_dir=args.snapshot_dir,
            )
            print(json.dumps(result, indent=2))
        elif args.command == "verify":
            result = verify_storage_snapshot(args.snapshot_dir)
            print(json.dumps(result, indent=2))
        elif args.command == "restore":
            result = restore_storage_snapshot(
                snapshot_dir=args.snapshot_dir,
                target_dir=args.target_dir,
            )
            print(json.dumps(result, indent=2))
        return 0
    except StorageBackupError as err:
        sys.stderr.write(f"storage_backup_error: {err.code}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
