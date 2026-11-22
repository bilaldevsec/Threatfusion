"""Cross-OS POSIX helpers for macOS OpenSSL 3 resolution and symlink-safe directory walks."""

from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

_DARWIN_OPENSSL_CANDIDATES: tuple[str, ...] = (
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
    "/opt/homebrew/bin/openssl",
    "/usr/local/bin/openssl",
    "/usr/bin/openssl",
)
_DARWIN_PREFIXES: frozenset[str] = frozenset({"tmp", "var", "etc"})


def _resolve_openssl_bin() -> str:
    """Resolve an executable OpenSSL binary, preferring Homebrew OpenSSL 3 on macOS."""
    if sys.platform == "darwin":
        for candidate in _DARWIN_OPENSSL_CANDIDATES:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return shutil.which("openssl") or "/usr/bin/openssl"
    if os.path.isfile("/usr/bin/openssl") and os.access("/usr/bin/openssl", os.X_OK):
        return "/usr/bin/openssl"
    return shutil.which("openssl") or "openssl"


def _sterile_openssl_env(openssl_bin: str | None = None) -> dict[str, str]:
    """Return a minimal sterile subprocess environment containing the resolved OpenSSL dir."""
    resolved = openssl_bin if openssl_bin is not None else _resolve_openssl_bin()
    bin_dir = os.path.dirname(resolved) if os.path.isabs(resolved) else ""
    path_parts: list[str] = []
    if bin_dir and bin_dir not in ("/usr/bin", "/bin"):
        path_parts.append(bin_dir)
    path_parts.extend(["/usr/bin", "/bin"])
    return {
        "PATH": os.pathsep.join(path_parts),
        "LC_ALL": "C",
    }


def normalize_darwin_system_prefix(path: Path) -> Path:
    """Rewrite macOS root-owned /tmp, /var, /etc firmlinks to /private/{name} without resolving leaf symlinks.

    Never calls blanket realpath() on the full path, so user-planted symlinks below the
    OS prefix are preserved and still caught by subsequent O_NOFOLLOW walks.
    """
    if not isinstance(path, Path):
        path = Path(path)
    if sys.platform != "darwin" or not path.is_absolute():
        return path
    parts = path.parts
    if len(parts) < 2:
        return path
    top = parts[1]
    if top not in _DARWIN_PREFIXES:
        return path
    top_path = f"/{top}"
    try:
        info = os.lstat(top_path)
    except OSError:
        return path
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
        return path
    try:
        target = os.readlink(top_path)
    except OSError:
        return path
    resolved_target = Path(target) if os.path.isabs(target) else Path("/") / target
    expected_prefix = Path("/private") / top
    if resolved_target != expected_prefix:
        return path
    return expected_prefix.joinpath(*parts[2:])


def open_private_leaf_nofollow(
    parent_fd: int,
    leaf_name: str,
    flags: int,
    mode: int = 0o600,
) -> int:
    """Open a leaf entry relative to an already-verified parent directory descriptor with O_NOFOLLOW."""
    return os.open(leaf_name, flags | os.O_NOFOLLOW, mode, dir_fd=parent_fd)
