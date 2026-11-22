#!/usr/bin/env python3
"""Bootstrap mode-0600 ThreatFusion runtime secrets without printing secret values.

Generates 256-bit cryptographically random secrets for SOAR HMAC, sensor ingestion,
live write tokens, MISP, TheHive, and bootstrap admin credentials. Writes secrets
strictly to a mode-0600 file inside a mode-0700 directory using O_NOFOLLOW.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import stat
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_SRC = REPO_ROOT / "backend" / "src"
if BACKEND_SRC.is_dir() and str(BACKEND_SRC) not in sys.path:
    sys.path.insert(0, str(BACKEND_SRC))

from threatfusion.db.sqlite_permissions import (  # noqa: E402
    ensure_secure_parent_dir,
    scoped_umask_077,
)
from threatfusion.operations.commercial_hardening import (  # noqa: E402
    resolve_data_dir,
    threatfusion_environment,
)

REQUIRED_SECRET_KEYS: tuple[str, ...] = (
    "THREATFUSION_SOAR_HMAC_SECRET",
    "THREATFUSION_SENSOR_INGEST_TOKEN",
    "THREATFUSION_LIVE_WRITE_TOKEN",
    "THREATFUSION_MISP_API_KEY",
    "THREATFUSION_THEHIVE_API_KEY",
    "THREATFUSION_BOOTSTRAP_ADMIN",
)

_TMP_PREFIXES: tuple[str, ...] = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp")


def _is_tmp_path(target: Path) -> bool:
    for candidate in (str(target), os.path.realpath(str(target))):
        normalized = candidate.rstrip("/") or "/"
        for prefix in _TMP_PREFIXES:
            if normalized == prefix or normalized.startswith(f"{prefix}/"):
                return True
    return False


def _parse_existing_secrets(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OSError(f"refusing non-regular or symlink secrets file: {path.name}")
    parsed: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        clean_key = key.strip()
        clean_val = val.strip()
        if clean_key and clean_val:
            parsed[clean_key] = clean_val
    return parsed


def bootstrap_secrets_file(
    output_path: Path | None = None,
    *,
    rotate: bool = False,
) -> dict[str, object]:
    """Create or update a mode-0600 secrets env file without emitting secret values."""
    is_prod = threatfusion_environment() == "production"
    if output_path is None:
        base_dir = resolve_data_dir()
        target = base_dir / ".env.secrets"
    else:
        target = Path(output_path)

    if is_prod and _is_tmp_path(target):
        raise RuntimeError("refusing /tmp secrets path when THREATFUSION_ENV=production")

    parent = target.parent
    if parent.is_symlink() or target.is_symlink():
        raise OSError("refusing symlink path for secrets bootstrap")
    ensure_secure_parent_dir(parent)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass

    existing = {} if rotate else _parse_existing_secrets(target)
    merged: dict[str, str] = {}
    generated_keys: list[str] = []
    preserved_keys: list[str] = []

    for key in REQUIRED_SECRET_KEYS:
        current = existing.get(key, "").strip()
        if current and len(current) >= 32 and not rotate:
            merged[key] = current
            preserved_keys.append(key)
        else:
            merged[key] = secrets.token_hex(32)
            generated_keys.append(key)

    lines = [f"{key}={merged[key]}" for key in REQUIRED_SECRET_KEYS]
    payload = ("\n".join(lines) + "\n").encode("utf-8")

    with scoped_umask_077():
        fd = os.open(
            str(target),
            os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            os.write(fd, payload)
        finally:
            os.close(fd)

    file_mode = stat.S_IMODE(target.lstat().st_mode)
    parent_mode = stat.S_IMODE(parent.lstat().st_mode)
    return {
        "output_path": str(target),
        "file_mode": oct(file_mode),
        "parent_mode": oct(parent_mode),
        "generated_keys": generated_keys,
        "preserved_keys": preserved_keys,
        "key_count": len(REQUIRED_SECRET_KEYS),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bootstrap mode-0600 ThreatFusion runtime secrets (never prints secrets)."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Target mode-0600 secrets file path (defaults to <data_dir>/.env.secrets)",
    )
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="Force regeneration of all secret keys",
    )
    args = parser.parse_args(argv)
    summary = bootstrap_secrets_file(args.output, rotate=args.rotate)
    print(
        f"Bootstrapped {summary['key_count']} secrets into {summary['output_path']} "
        f"(mode={summary['file_mode']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
