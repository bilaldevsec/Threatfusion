"""Tamper-evident security audit export, archive verification, and quiescent retention pruning."""

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
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Generator

from threatfusion.db.analyst_security_audit import (
    AUDIT_EVENT_SCHEMA_VERSION,
    AUDIT_REPOSITORY_SCHEMA_IDENTITY,
    AUDIT_REPOSITORY_SCHEMA_VERSION,
)
from threatfusion.schemas.analyst_state import is_utc

AUDIT_ARCHIVE_SCHEMA = "security_audit_archive_v1"
AUDIT_ARCHIVE_EVENTS_FILENAME = "audit_events.jsonl"
AUDIT_ARCHIVE_MANIFEST_FILENAME = "manifest.json"
MAX_MANIFEST_BYTES = 65536
MAX_ARCHIVE_EVENTS_BYTES = 100 * 1024 * 1024  # 100 MiB limit

AUDIT_EVENT_COLUMNS = (
    "schema_version",
    "audit_event_id",
    "event_time",
    "correlation_id",
    "event_type",
    "processing_stage",
    "outcome",
    "reason_code",
    "actor_id",
    "credential_sha256",
    "request_route",
    "body_sha256",
)
_AUDIT_COLUMN_LIST = ", ".join(AUDIT_EVENT_COLUMNS)


class AuditRetentionError(RuntimeError):
    """Sanitized failure for security audit export, verification, and retention pruning."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"<AuditRetentionError: {self.code}>"


@contextmanager
def _directory_context(directory: Path, *, write: bool = True) -> Generator[int, None, None]:
    """Walk descriptors without following symlinks; verify ancestor modes/ownership; lock inode."""
    if not isinstance(directory, Path):
        directory = Path(directory)
    if not directory.is_absolute() or ".." in directory.parts:
        raise AuditRetentionError("directory_invalid")

    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        raise AuditRetentionError("directory_invalid") from None

    try:
        for part in directory.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as err:
                if err.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise AuditRetentionError("symlink_rejected") from None
                raise AuditRetentionError("directory_invalid") from None
            os.close(fd)
            fd = child
            try:
                info = os.fstat(fd)
            except OSError:
                raise AuditRetentionError("directory_invalid") from None

            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not sticky_root):
                raise AuditRetentionError("permission_invalid")

        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise AuditRetentionError("directory_invalid")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise AuditRetentionError("permission_invalid")

        try:
            lock_flag = (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB
            fcntl.flock(fd, lock_flag)
        except (BlockingIOError, OSError):
            raise AuditRetentionError("lock_failed") from None

        yield fd
    finally:
        os.close(fd)


def _validate_audit_db_path(db_path: Path | str) -> Path:
    """Validate SQLite database path: absolute, descriptor-relative ancestors, mode 0600, no symlinks."""
    path = Path(db_path) if not isinstance(db_path, Path) else db_path
    if not path.is_absolute() or ".." in path.parts:
        raise AuditRetentionError("directory_invalid")

    # Walk ancestors to verify ownership & permissions
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        raise AuditRetentionError("directory_invalid") from None

    try:
        for part in path.parts[1:-1]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as err:
                if err.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise AuditRetentionError("symlink_rejected") from None
                raise AuditRetentionError("directory_invalid") from None
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not sticky_root):
                raise AuditRetentionError("permission_invalid")

        # Now check the target database file inside parent dir
        try:
            file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        except OSError as err:
            if err.errno in (errno.ELOOP, errno.ENOTDIR):
                raise AuditRetentionError("symlink_rejected") from None
            raise AuditRetentionError("file_invalid") from None
        try:
            file_info = os.fstat(file_fd)
            if (
                not stat.S_ISREG(file_info.st_mode)
                or file_info.st_uid != os.geteuid()
                or bool(file_info.st_mode & 0o022)
                or file_info.st_nlink != 1
            ):
                raise AuditRetentionError("permission_invalid")
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)

    return path


def _unique_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AuditRetentionError("manifest_invalid")
        result[key] = value
    return result


def _verify_audit_db_schema(conn: sqlite3.Connection) -> None:
    try:
        res = conn.execute("PRAGMA quick_check").fetchone()
        if res is None or res[0] != "ok":
            raise AuditRetentionError("database_corrupt")

        user_version = conn.execute("PRAGMA user_version").fetchone()[0]
        if user_version != AUDIT_REPOSITORY_SCHEMA_VERSION:
            raise AuditRetentionError("schema_mismatch")

        metadata = dict(conn.execute("SELECT key, value FROM audit_metadata").fetchall())
        if metadata.get("schema_identity") != AUDIT_REPOSITORY_SCHEMA_IDENTITY:
            raise AuditRetentionError("schema_mismatch")
    except sqlite3.Error:
        raise AuditRetentionError("schema_mismatch") from None


def export_security_audit_archive(
    audit_db_path: Path | str,
    archive_dir: Path | str,
    *,
    up_to_audit_id: str | None = None,
) -> dict[str, object]:
    """Export security audit rows from SQLite into a signed/tamper-evident archive.

    Creates audit_events.jsonl (mode 0600) and manifest.json (mode 0600) in archive_dir.
    """
    path = _validate_audit_db_path(audit_db_path)
    arch_dir = Path(archive_dir) if not isinstance(archive_dir, Path) else archive_dir

    with _directory_context(arch_dir, write=True) as arch_fd:
        # Check archive_dir is clean of existing archive files
        for filename in (AUDIT_ARCHIVE_EVENTS_FILENAME, AUDIT_ARCHIVE_MANIFEST_FILENAME):
            try:
                chk = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=arch_fd)
                os.close(chk)
                raise AuditRetentionError("archive_directory_not_empty")
            except FileNotFoundError:
                pass

        uri_path = f"file:{path.resolve()}?mode=ro"
        try:
            conn = sqlite3.connect(uri_path, uri=True, timeout=5.0)
        except sqlite3.Error:
            raise AuditRetentionError("file_invalid") from None

        try:
            _verify_audit_db_schema(conn)

            if up_to_audit_id is not None:
                # Find boundary target event
                target = conn.execute(
                    "SELECT event_time, audit_event_id FROM audit_events WHERE audit_event_id = ?",
                    (up_to_audit_id,),
                ).fetchone()
                if target is None:
                    raise AuditRetentionError("event_not_found")
                target_time, target_id = target
                rows = conn.execute(
                    f"SELECT {_AUDIT_COLUMN_LIST} FROM audit_events "
                    "WHERE event_time < ? OR (event_time = ? AND audit_event_id <= ?) "
                    "ORDER BY event_time ASC, audit_event_id ASC",
                    (target_time, target_time, target_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT {_AUDIT_COLUMN_LIST} FROM audit_events "
                    "ORDER BY event_time ASC, audit_event_id ASC"
                ).fetchall()

            if not rows:
                raise AuditRetentionError("no_events_to_archive")

            events: list[dict[str, object]] = []
            lines: list[bytes] = []
            for row in rows:
                event_dict = dict(zip(AUDIT_EVENT_COLUMNS, row))
                events.append(event_dict)
                line = json.dumps(event_dict, sort_keys=True).encode("utf-8") + b"\n"
                lines.append(line)

            raw_events = b"".join(lines)
            if len(raw_events) > MAX_ARCHIVE_EVENTS_BYTES:
                raise AuditRetentionError("manifest_too_large")

            # Write audit_events.jsonl into archive_dir
            events_fd = os.open(
                AUDIT_ARCHIVE_EVENTS_FILENAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=arch_fd,
            )
            try:
                os.fchmod(events_fd, 0o600)
                written = os.write(events_fd, raw_events)
                if written != len(raw_events):
                    raise AuditRetentionError("file_invalid")
                os.fsync(events_fd)
            finally:
                os.close(events_fd)

            sha256_digest = hashlib.sha256(raw_events).hexdigest()
            now_str = datetime.now(UTC).isoformat()
            manifest = {
                "schema": AUDIT_ARCHIVE_SCHEMA,
                "created_at_utc": now_str,
                "archive_file": AUDIT_ARCHIVE_EVENTS_FILENAME,
                "sha256_digest": sha256_digest,
                "size_bytes": len(raw_events),
                "row_count": len(events),
                "first_audit_id": str(events[0]["audit_event_id"]),
                "last_audit_id": str(events[-1]["audit_event_id"]),
                "first_recorded_at_utc": str(events[0]["event_time"]),
                "last_recorded_at_utc": str(events[-1]["event_time"]),
            }

            raw_manifest = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
            m_fd = os.open(
                AUDIT_ARCHIVE_MANIFEST_FILENAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=arch_fd,
            )
            try:
                os.fchmod(m_fd, 0o600)
                written = os.write(m_fd, raw_manifest)
                if written != len(raw_manifest):
                    raise AuditRetentionError("file_invalid")
                os.fsync(m_fd)
            finally:
                os.close(m_fd)

            os.fsync(arch_fd)
            return manifest
        finally:
            conn.close()


def verify_security_audit_archive(archive_dir: Path | str) -> dict[str, object]:
    """Cryptographically, structurally, and sequentially verify a security audit archive."""
    arch_dir = Path(archive_dir) if not isinstance(archive_dir, Path) else archive_dir

    with _directory_context(arch_dir, write=False) as arch_fd:
        # Check files inside archive_dir: only manifest.json and audit_events.jsonl allowed
        expected_files = {AUDIT_ARCHIVE_MANIFEST_FILENAME, AUDIT_ARCHIVE_EVENTS_FILENAME}
        try:
            names = set(os.listdir(arch_dir))
            if not expected_files.issubset(names) or not names.issubset(expected_files):
                raise AuditRetentionError("archive_incomplete")
        except OSError:
            raise AuditRetentionError("file_invalid") from None

        # Verify manifest.json
        try:
            m_fd = os.open(
                AUDIT_ARCHIVE_MANIFEST_FILENAME,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=arch_fd,
            )
        except FileNotFoundError:
            raise AuditRetentionError("archive_incomplete") from None
        try:
            info = os.fstat(m_fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size > MAX_MANIFEST_BYTES
            ):
                raise AuditRetentionError("permission_invalid")
            raw_manifest = os.read(m_fd, MAX_MANIFEST_BYTES + 1)
        finally:
            os.close(m_fd)

        try:
            manifest = json.loads(raw_manifest.decode("utf-8"), object_pairs_hook=_unique_hook)
        except Exception:
            raise AuditRetentionError("manifest_invalid") from None

        if type(manifest) is not dict or manifest.get("schema") != AUDIT_ARCHIVE_SCHEMA:
            raise AuditRetentionError("manifest_invalid")

        # Verify audit_events.jsonl
        try:
            e_fd = os.open(
                AUDIT_ARCHIVE_EVENTS_FILENAME,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=arch_fd,
            )
        except FileNotFoundError:
            raise AuditRetentionError("archive_incomplete") from None
        try:
            info = os.fstat(e_fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size > MAX_ARCHIVE_EVENTS_BYTES
            ):
                raise AuditRetentionError("permission_invalid")
            raw_events = os.read(e_fd, MAX_ARCHIVE_EVENTS_BYTES + 1)
        finally:
            os.close(e_fd)

        if len(raw_events) != manifest.get("size_bytes"):
            raise AuditRetentionError("digest_mismatch")
        if hashlib.sha256(raw_events).hexdigest() != manifest.get("sha256_digest"):
            raise AuditRetentionError("digest_mismatch")

        lines = raw_events.split(b"\n")
        if lines[-1] != b"":
            raise AuditRetentionError("archive_tampered")

        event_rows = lines[:-1]
        if len(event_rows) != manifest.get("row_count"):
            raise AuditRetentionError("archive_tampered")

        prev_order_key = None
        first_row = None
        last_row = None

        for idx, line in enumerate(event_rows):
            if not line:
                raise AuditRetentionError("archive_tampered")
            try:
                event = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_hook)
            except Exception:
                raise AuditRetentionError("archive_tampered") from None

            if (
                type(event) is not dict
                or event.get("schema_version") != AUDIT_EVENT_SCHEMA_VERSION
                or not all(col in event for col in AUDIT_EVENT_COLUMNS)
            ):
                raise AuditRetentionError("archive_tampered")

            ev_time = event["event_time"]
            ev_id = event["audit_event_id"]
            if type(ev_time) is not str or type(ev_id) is not str:
                raise AuditRetentionError("archive_tampered")

            try:
                parsed_ts = datetime.fromisoformat(ev_time)
                if not is_utc(parsed_ts):
                    raise AuditRetentionError("archive_tampered")
            except Exception:
                raise AuditRetentionError("archive_tampered") from None

            curr_order_key = (ev_time, ev_id)
            if prev_order_key is not None and curr_order_key <= prev_order_key:
                raise AuditRetentionError("archive_tampered")
            prev_order_key = curr_order_key

            if idx == 0:
                first_row = event
            if idx == len(event_rows) - 1:
                last_row = event

        assert first_row is not None and last_row is not None
        if (
            manifest.get("first_audit_id") != first_row["audit_event_id"]
            or manifest.get("last_audit_id") != last_row["audit_event_id"]
            or manifest.get("first_recorded_at_utc") != first_row["event_time"]
            or manifest.get("last_recorded_at_utc") != last_row["event_time"]
        ):
            raise AuditRetentionError("archive_tampered")

        return manifest


def prune_archived_security_audit(
    audit_db_path: Path | str,
    archive_dir: Path | str,
) -> dict[str, object]:
    """Verify archive and delete exactly the archived prefix rows from audit.sqlite3 atomically.

    Guarantees that zero unarchived rows are deleted and fails closed on prefix mismatch.
    """
    manifest = verify_security_audit_archive(archive_dir)
    path = _validate_audit_db_path(audit_db_path)
    arch_dir = Path(archive_dir) if not isinstance(archive_dir, Path) else archive_dir

    # Read events from verified archive
    with _directory_context(arch_dir, write=False) as arch_fd:
        e_fd = os.open(
            AUDIT_ARCHIVE_EVENTS_FILENAME,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=arch_fd,
        )
        try:
            raw_events = os.read(e_fd, MAX_ARCHIVE_EVENTS_BYTES + 1)
        finally:
            os.close(e_fd)

    archived_events = [
        json.loads(line.decode("utf-8"), object_pairs_hook=_unique_hook)
        for line in raw_events.split(b"\n")[:-1]
    ]
    row_count = len(archived_events)
    if row_count != manifest["row_count"]:
        raise AuditRetentionError("archive_tampered")

    uri_path = f"file:{path.resolve()}"
    try:
        conn = sqlite3.connect(uri_path, uri=True, timeout=5.0)
    except sqlite3.Error:
        raise AuditRetentionError("file_invalid") from None

    try:
        conn.execute("BEGIN IMMEDIATE")
        _verify_audit_db_schema(conn)

        # Fetch first row_count rows from DB
        db_rows = conn.execute(
            f"SELECT {_AUDIT_COLUMN_LIST} FROM audit_events "
            "ORDER BY event_time ASC, audit_event_id ASC LIMIT ?",
            (row_count,),
        ).fetchall()

        if len(db_rows) < row_count:
            conn.rollback()
            raise AuditRetentionError("prefix_mismatch")

        # Compare every row for exact field match
        for idx, (arch_ev, db_row) in enumerate(zip(archived_events, db_rows)):
            db_ev = dict(zip(AUDIT_EVENT_COLUMNS, db_row))
            if arch_ev != db_ev:
                conn.rollback()
                raise AuditRetentionError("prefix_mismatch")

        # Perform exact prefix delete
        last_time = str(manifest["last_recorded_at_utc"])
        last_id = str(manifest["last_audit_id"])

        cursor = conn.execute(
            "DELETE FROM audit_events WHERE event_time < ? OR (event_time = ? AND audit_event_id <= ?)",
            (last_time, last_time, last_id),
        )
        if cursor.rowcount != row_count:
            conn.rollback()
            raise AuditRetentionError("prefix_mismatch")

        conn.commit()

        # Checkpoint WAL if present
        try:
            conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except sqlite3.Error:
            pass

        return {
            "status": "pruned",
            "pruned_rows_count": row_count,
            "archive_sha256": manifest["sha256_digest"],
            "first_pruned_audit_id": manifest["first_audit_id"],
            "last_pruned_audit_id": manifest["last_audit_id"],
            "archived_up_to_utc": manifest["last_recorded_at_utc"],
        }
    except AuditRetentionError:
        conn.rollback()
        raise
    except sqlite3.Error:
        conn.rollback()
        raise AuditRetentionError("database_corrupt") from None
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    export_cmd = commands.add_parser("export")
    export_cmd.add_argument("--audit-db", type=Path, required=True)
    export_cmd.add_argument("--archive-dir", type=Path, required=True)
    export_cmd.add_argument("--up-to-audit-id", type=str, default=None)

    verify_cmd = commands.add_parser("verify")
    verify_cmd.add_argument("--archive-dir", type=Path, required=True)

    prune_cmd = commands.add_parser("prune")
    prune_cmd.add_argument("--audit-db", type=Path, required=True)
    prune_cmd.add_argument("--archive-dir", type=Path, required=True)

    args = parser.parse_args(argv)

    try:
        if args.command == "export":
            manifest = export_security_audit_archive(
                args.audit_db, args.archive_dir, up_to_audit_id=args.up_to_audit_id
            )
            print(json.dumps(manifest, indent=2))
        elif args.command == "verify":
            manifest = verify_security_audit_archive(args.archive_dir)
            print(json.dumps(manifest, indent=2))
        elif args.command == "prune":
            result = prune_archived_security_audit(args.audit_db, args.archive_dir)
            print(json.dumps(result, indent=2))
        return 0
    except AuditRetentionError as err:
        sys.stderr.write(f"audit_retention_error: {err.code}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
