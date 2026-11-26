"""Pure-stdlib SQLite file/directory permission hardening helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat
import threading

_UMASK_LOCK = threading.RLock()
_SQLITE_SIDE_SUFFIXES: tuple[str, ...] = ("", "-wal", "-shm", "-journal")


def ensure_secure_parent_dir(parent: Path) -> None:
    """Create parent directory if missing and enforce 0o700 when user-owned and non-sticky."""
    if parent.is_symlink():
        raise OSError(f"refusing symlink parent directory: {parent.name}")
    with scoped_umask_077():
        parent.mkdir(parents=True, exist_ok=True)
    try:
        info = parent.lstat()
    except OSError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OSError(f"refusing non-directory parent: {parent.name}")
    # Never alter root-owned sticky directories (e.g., /tmp, /var/tmp); refuse foreign-owned non-root dirs.
    if (info.st_mode & stat.S_ISVTX) and info.st_uid == 0:
        return
    if info.st_uid != os.getuid():
        raise PermissionError(f"refusing foreign-owned parent directory: {parent.name}")
    if info.st_mode & stat.S_ISVTX:
        return
    if stat.S_IMODE(info.st_mode) != 0o700:
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass


@contextmanager
def scoped_umask_077() -> Iterator[None]:
    """Temporarily set process umask to 0o077 under a lock so created files start 0600/0700."""
    with _UMASK_LOCK:
        old_umask = os.umask(0o077)
        try:
            yield
        finally:
            os.umask(old_umask)


def precreate_sqlite_0600(db_path: Path) -> bool:
    """Pre-create a brand-new SQLite database file as mode 0600 with O_NOFOLLOW.

    Callers should invoke this only after confirming the target does not exist
    so zero-byte existing-file corruption checks remain intact.
    """
    ensure_secure_parent_dir(db_path.parent)
    if db_path.is_symlink():
        raise OSError(f"refusing symlink for sqlite database: {db_path.name}")
    with scoped_umask_077():
        try:
            fd = os.open(
                str(db_path),
                os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,
                stat.S_IRUSR | stat.S_IWUSR,
            )
        except FileExistsError:
            return False
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        finally:
            os.close(fd)
    return True


def harden_sqlite_permissions(db_path: Path) -> None:
    """Enforce mode 0600 on an existing SQLite database and its WAL/SHM/journal sidecars."""
    for suffix in _SQLITE_SIDE_SUFFIXES:
        target = db_path if not suffix else db_path.with_name(f"{db_path.name}{suffix}")
        try:
            info = target.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            continue
        if stat.S_IMODE(info.st_mode) == 0o600:
            continue
        try:
            fd = os.open(str(target), os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            finally:
                os.close(fd)
        except OSError:
            pass


def connect_sqlite_readonly(db_path: Path, *, timeout: float = 5.0) -> sqlite3.Connection:
    """Open an existing non-symlink SQLite database strictly read-only with safe pragmas."""
    path = Path(db_path)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OSError(f"refusing non-regular sqlite database: {path.name}")
    uri = f"{path.resolve().as_uri()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=timeout)
    try:
        conn.execute("PRAGMA query_only = ON")
        conn.execute("PRAGMA trusted_schema = OFF")
    except Exception:
        conn.close()
        raise
    return conn


__all__ = [
    "connect_sqlite_readonly",
    "ensure_secure_parent_dir",
    "harden_sqlite_permissions",
    "precreate_sqlite_0600",
    "scoped_umask_077",
]
