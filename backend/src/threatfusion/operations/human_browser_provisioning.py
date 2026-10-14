"""Operator Firefox NSS Profile Provisioning from Encrypted PKCS#12 Bundles.

Enforces strict filesystem discipline: mode-0700 private directories, mode-0600
files, symlink rejection (O_NOFOLLOW), descriptor-relative ancestor ownership
verification (root or current EUID), non-blocking directory filesystem locks
(flock), and atomic temporary file replacement.

Initializes an isolated NSS SQLite database (sql:<profile_dir>), imports the Root
CA certificate as trusted for server/peer verification, and imports the client
certificate and private key from an encrypted PKCS#12 bundle without leaking
passphrases to command lines (/proc/<pid>/cmdline) or persisting them in profile storage.

Hardens the profile with a mode-0600 user.js disabling background telemetry,
captive portal noise, and enterprise roots, and configuring automatic client
certificate selection for seamless loopback mTLS inspection.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Generator
from uuid import uuid4

from threatfusion.operations import human_ca_issuance as ca_ops

PROFILE_MANIFEST_SCHEMA = "operator_human_firefox_profile_v1"
PROFILE_MANIFEST_FILENAME = "profile_manifest.json"
USER_JS_FILENAME = "user.js"

CERT9_DB_FILENAME = "cert9.db"
KEY4_DB_FILENAME = "key4.db"
PKCS11_TXT_FILENAME = "pkcs11.txt"

EXPECTED_PROFILE_FILES = frozenset(
    {
        PROFILE_MANIFEST_FILENAME,
        USER_JS_FILENAME,
        CERT9_DB_FILENAME,
        KEY4_DB_FILENAME,
        PKCS11_TXT_FILENAME,
    }
)

MAX_MANIFEST_BYTES = 65536
MAX_DB_BYTES = 10485760  # 10 MB bound for NSS SQLite database files
MIN_PASSPHRASE_LENGTH = 12

HARDENED_USER_JS = (
    'user_pref("security.default_personal_cert", "Select Automatically");\n'
    'user_pref("security.enterprise_roots.enabled", false);\n'
    'user_pref("network.proxy.type", 0);\n'
    'user_pref("network.captive-portal-service.enabled", false);\n'
    'user_pref("toolkit.telemetry.enabled", false);\n'
    'user_pref("toolkit.telemetry.unified", false);\n'
    'user_pref("toolkit.telemetry.archive.enabled", false);\n'
    'user_pref("datareporting.healthreport.uploadEnabled", false);\n'
    'user_pref("datareporting.policy.dataSubmissionEnabled", false);\n'
    'user_pref("app.shield.optoutstudy.enabled", false);\n'
    'user_pref("app.normandy.enabled", false);\n'
    'user_pref("app.normandy.api_url", "");\n'
    'user_pref("browser.discovery.enabled", false);\n'
)


class HumanBrowserProvisioningError(RuntimeError):
    """Sanitized failure for operator Firefox NSS profile provisioning."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"<HumanBrowserProvisioningError: {self.code}>"


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HumanBrowserProvisioningError("duplicate_json_keys")
        result[key] = value
    return result


@contextmanager
def _directory_context(directory: Path, *, write: bool = True) -> Generator[int, None, None]:
    """Walk descriptors without following symlinks; verify ancestor modes/ownership; lock inode."""
    if not isinstance(directory, Path):
        directory = Path(directory)
    if not directory.is_absolute() or ".." in directory.parts:
        raise HumanBrowserProvisioningError("directory_invalid")

    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        raise HumanBrowserProvisioningError("directory_invalid") from None

    try:
        for part in directory.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as err:
                if err.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise HumanBrowserProvisioningError("symlink_rejected") from None
                raise HumanBrowserProvisioningError("directory_invalid") from None
            os.close(fd)
            fd = child
            try:
                info = os.fstat(fd)
            except OSError:
                raise HumanBrowserProvisioningError("directory_invalid") from None

            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not sticky_root):
                raise HumanBrowserProvisioningError("permission_invalid")

        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise HumanBrowserProvisioningError("directory_invalid")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise HumanBrowserProvisioningError("permission_invalid")

        try:
            lock_flag = (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB
            fcntl.flock(fd, lock_flag)
        except (BlockingIOError, OSError):
            raise HumanBrowserProvisioningError("lock_failed") from None

        yield fd
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _check_file_stat(
    dir_fd: int, filename: str, max_bytes: int = MAX_MANIFEST_BYTES
) -> os.stat_result:
    """Verify regular file, ownership, mode 0600, single link, and byte bound."""
    try:
        file_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError as err:
        if err.errno in (errno.ELOOP, errno.ENOTDIR):
            raise HumanBrowserProvisioningError("symlink_rejected") from None
        if err.errno == errno.ENOENT:
            raise HumanBrowserProvisioningError("file_not_found") from None
        raise HumanBrowserProvisioningError("file_invalid") from None

    try:
        info = os.fstat(file_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > max_bytes
        ):
            raise HumanBrowserProvisioningError("file_invalid")
        return info
    finally:
        os.close(file_fd)


def _read_file(dir_fd: int, filename: str, max_bytes: int = MAX_MANIFEST_BYTES) -> bytes:
    """Read a bounded regular file under directory descriptor checks."""
    try:
        file_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError as err:
        if err.errno in (errno.ELOOP, errno.ENOTDIR):
            raise HumanBrowserProvisioningError("symlink_rejected") from None
        if err.errno == errno.ENOENT:
            raise HumanBrowserProvisioningError("file_not_found") from None
        raise HumanBrowserProvisioningError("file_invalid") from None

    try:
        info = os.fstat(file_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > max_bytes
        ):
            raise HumanBrowserProvisioningError("file_invalid")
        data = os.read(file_fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise HumanBrowserProvisioningError("file_invalid")
        return data
    finally:
        os.close(file_fd)


def _hash_file(dir_fd: int, filename: str, max_bytes: int = MAX_DB_BYTES) -> str:
    """Compute SHA-256 digest of a regular file under directory descriptor checks."""
    try:
        file_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError as err:
        if err.errno in (errno.ELOOP, errno.ENOTDIR):
            raise HumanBrowserProvisioningError("symlink_rejected") from None
        if err.errno == errno.ENOENT:
            raise HumanBrowserProvisioningError("file_not_found") from None
        raise HumanBrowserProvisioningError("file_invalid") from None

    try:
        info = os.fstat(file_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > max_bytes
        ):
            raise HumanBrowserProvisioningError("file_invalid")

        hasher = hashlib.sha256()
        total_read = 0
        while True:
            chunk = os.read(file_fd, 65536)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > max_bytes:
                raise HumanBrowserProvisioningError("file_invalid")
            hasher.update(chunk)
        return hasher.hexdigest()
    finally:
        os.close(file_fd)


def _write_atomic_file(
    dir_fd: int,
    filename: str,
    data: bytes,
    *,
    mode: int = 0o600,
    create_only: bool = False,
) -> None:
    """Atomically write data to a file in dir_fd using a temporary file and fsync."""
    if len(data) > MAX_DB_BYTES:
        raise HumanBrowserProvisioningError("file_invalid")

    temp_name = f".tmp-{uuid4().hex}"
    try:
        temp_fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode,
            dir_fd=dir_fd,
        )
    except OSError:
        raise HumanBrowserProvisioningError("file_invalid") from None

    try:
        os.fchmod(temp_fd, mode)
        written = os.write(temp_fd, data)
        if written != len(data):
            raise HumanBrowserProvisioningError("file_invalid")
        os.fsync(temp_fd)
    finally:
        os.close(temp_fd)

    try:
        if create_only:
            os.link(
                temp_name, filename, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False
            )
            os.unlink(temp_name, dir_fd=dir_fd)
        else:
            os.replace(temp_name, filename, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    except OSError:
        try:
            os.unlink(temp_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise HumanBrowserProvisioningError("file_invalid") from None


def _validate_passphrase(passphrase: str) -> None:
    """Validate PKCS#12 passphrase strength and character hygiene."""
    if not isinstance(passphrase, str):
        raise HumanBrowserProvisioningError("invalid_passphrase")
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise HumanBrowserProvisioningError("invalid_passphrase")
    if any(c in passphrase for c in ("\n", "\r", "\0")):
        raise HumanBrowserProvisioningError("invalid_passphrase")


def _run_nss_command(
    command: list[str],
    *,
    timeout: float = 15.0,
) -> subprocess.CompletedProcess[bytes]:
    """Execute an NSS tool command safely under controlled environment."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LC_ALL": "C",
    }
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        raise HumanBrowserProvisioningError("nss_tool_failed") from None

    return proc


def init_policy_directory(policy_dir: Path | str) -> Path:
    """Initialize a mode-0700 policy directory for operator credential enrollment."""
    p = Path(policy_dir) if not isinstance(policy_dir, Path) else policy_dir
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(p, 0o700)
    return p


def provision_firefox_profile(
    ca_dir: Path | str,
    delivery_dir: Path | str,
    profile_dir: Path | str,
    *,
    pkcs12_passphrase: str,
) -> dict[str, object]:
    """Provision a hardened Firefox NSS profile from an encrypted PKCS#12 bundle.

    Fails closed on missing/tampered CA, invalid bundle, weak or incorrect passphrase,
    pre-existing profile files, or unsafe filesystem permissions.
    """
    _validate_passphrase(pkcs12_passphrase)

    c_dir = Path(ca_dir) if not isinstance(ca_dir, Path) else ca_dir
    d_dir = Path(delivery_dir) if not isinstance(delivery_dir, Path) else delivery_dir
    p_dir = Path(profile_dir) if not isinstance(profile_dir, Path) else profile_dir

    if not c_dir.is_absolute() or ".." in c_dir.parts:
        raise HumanBrowserProvisioningError("directory_invalid")
    if not d_dir.is_absolute() or ".." in d_dir.parts:
        raise HumanBrowserProvisioningError("directory_invalid")
    if not p_dir.is_absolute() or ".." in p_dir.parts:
        raise HumanBrowserProvisioningError("directory_invalid")

    if len({str(c_dir), str(d_dir), str(p_dir)}) != 3:
        raise HumanBrowserProvisioningError("directory_invalid")

    # 1. Pre-verify Root CA
    try:
        ca_result = ca_ops.verify_human_ca(c_dir)
    except ca_ops.HumanCaIssuanceError as err:
        if err.code in ("permission_invalid", "symlink_rejected", "directory_invalid"):
            raise HumanBrowserProvisioningError(err.code) from None
        raise HumanBrowserProvisioningError("ca_corrupted") from None

    ca_manifest = ca_result.get("ca_manifest", {})
    if not isinstance(ca_manifest, dict):
        raise HumanBrowserProvisioningError("ca_corrupted")
    ca_cert_sha256 = ca_manifest.get("ca_cert_sha256")
    if not isinstance(ca_cert_sha256, str) or len(ca_cert_sha256) != 64:
        raise HumanBrowserProvisioningError("ca_corrupted")

    # 2. Pre-verify client bundle against Root CA
    try:
        bundle_result = ca_ops.verify_client_bundle(d_dir, ca_dir=c_dir)
    except ca_ops.HumanCaIssuanceError as err:
        if err.code in ("permission_invalid", "symlink_rejected", "directory_invalid"):
            raise HumanBrowserProvisioningError(err.code) from None
        if err.code in ("ca_bundle_mismatch", "openssl_failed"):
            raise HumanBrowserProvisioningError("ca_bundle_mismatch") from None
        if err.code in ("bundle_invalid", "manifest_invalid"):
            raise HumanBrowserProvisioningError("bundle_invalid") from None
        raise HumanBrowserProvisioningError(err.code) from None

    bundle_manifest = bundle_result.get("bundle_manifest", {})
    if not isinstance(bundle_manifest, dict):
        raise HumanBrowserProvisioningError("bundle_invalid")

    # Verify bundle was issued by this CA
    if bundle_manifest.get("ca_cert_sha256") != ca_cert_sha256:
        raise HumanBrowserProvisioningError("ca_bundle_mismatch")

    actor_id = bundle_manifest.get("actor_id")
    client_cert_sha256 = bundle_manifest.get("certificate_sha256")
    serial_number = bundle_manifest.get("serial")
    if (
        not isinstance(actor_id, str)
        or not isinstance(client_cert_sha256, str)
        or not isinstance(serial_number, int)
    ):
        raise HumanBrowserProvisioningError("bundle_invalid")

    # Ensure NSS utilities are available
    if shutil.which("certutil") is None or shutil.which("pk12util") is None:
        raise HumanBrowserProvisioningError("nss_tool_failed")

    # 3. Lock directories in deterministic order
    sorted_dirs = sorted([c_dir, d_dir, p_dir], key=lambda p: str(p))
    with _directory_context(sorted_dirs[0], write=True) as fd0:
        with _directory_context(sorted_dirs[1], write=True) as fd1:
            with _directory_context(sorted_dirs[2], write=True) as fd2:
                fds = {sorted_dirs[0]: fd0, sorted_dirs[1]: fd1, sorted_dirs[2]: fd2}
                c_fd = fds[c_dir]
                d_fd = fds[d_dir]
                p_fd = fds[p_dir]

                # Profile directory must be clean
                existing_entries = [f for f in os.listdir(p_fd) if not f.startswith(".tmp-")]
                if existing_entries:
                    raise HumanBrowserProvisioningError("profile_dir_not_empty")

                # Verify files inside ca_dir and delivery_dir descriptors
                _check_file_stat(c_fd, ca_ops.CA_CERT_FILENAME)
                _check_file_stat(d_fd, ca_ops.CLIENT_BUNDLE_FILENAME)

                # Initialize fresh NSS SQLite database
                proc_init = _run_nss_command(
                    ["certutil", "-N", "-d", f"sql:{p_dir}", "--empty-password"]
                )
                if proc_init.returncode != 0:
                    raise HumanBrowserProvisioningError("nss_tool_failed")

                # Import Root CA certificate as trusted for server authentication
                ca_cert_file = c_dir / ca_ops.CA_CERT_FILENAME
                proc_ca = _run_nss_command(
                    [
                        "certutil",
                        "-A",
                        "-n",
                        "ThreatFusion Local Human Root CA",
                        "-t",
                        "C,,",
                        "-d",
                        f"sql:{p_dir}",
                        "-i",
                        str(ca_cert_file),
                        "-a",
                    ]
                )
                if proc_ca.returncode != 0:
                    raise HumanBrowserProvisioningError("nss_tool_failed")

                # Import encrypted PKCS#12 bundle using a temporary mode-0600 passphrase file
                p12_file = d_dir / ca_ops.CLIENT_BUNDLE_FILENAME
                with tempfile.TemporaryDirectory(prefix=".tf-nss-pass-") as tmp_pass_dir:
                    tmp_pass_file = Path(tmp_pass_dir) / "pass.txt"
                    tmp_pass_file.write_bytes(pkcs12_passphrase.encode("utf-8") + b"\n")
                    tmp_pass_file.chmod(0o600)
                    try:
                        proc_p12 = _run_nss_command(
                            [
                                "pk12util",
                                "-i",
                                str(p12_file),
                                "-d",
                                f"sql:{p_dir}",
                                "-w",
                                str(tmp_pass_file),
                            ]
                        )
                    finally:
                        try:
                            if tmp_pass_file.exists():
                                tmp_pass_file.write_bytes(b"\x00" * (len(pkcs12_passphrase) + 1))
                                tmp_pass_file.unlink()
                        except OSError:
                            pass

                if proc_p12.returncode != 0:
                    if b"SEC_ERROR_BAD_PASSWORD" in proc_p12.stderr or proc_p12.returncode in (
                        17,
                        18,
                    ):
                        raise HumanBrowserProvisioningError("invalid_passphrase")
                    raise HumanBrowserProvisioningError("nss_tool_failed")

                # Write hardened user.js
                _write_atomic_file(
                    p_fd,
                    USER_JS_FILENAME,
                    HARDENED_USER_JS.encode("ascii"),
                    mode=0o600,
                    create_only=True,
                )

                # Enforce mode 0600 on NSS database files
                for fname in (CERT9_DB_FILENAME, KEY4_DB_FILENAME, PKCS11_TXT_FILENAME):
                    _check_file_stat(p_fd, fname, MAX_DB_BYTES)
                    f_fd = os.open(fname, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=p_fd)
                    try:
                        os.fchmod(f_fd, 0o600)
                    finally:
                        os.close(f_fd)

                # Compute file SHA-256 digests
                cert9_sha256 = _hash_file(p_fd, CERT9_DB_FILENAME)
                key4_sha256 = _hash_file(p_fd, KEY4_DB_FILENAME)
                pkcs11_sha256 = _hash_file(p_fd, PKCS11_TXT_FILENAME)
                user_js_sha256 = _hash_file(p_fd, USER_JS_FILENAME)

                # Construct profile manifest
                manifest = {
                    "schema": PROFILE_MANIFEST_SCHEMA,
                    "actor_id": actor_id,
                    "client_cert_sha256": client_cert_sha256,
                    "ca_cert_sha256": ca_cert_sha256,
                    "serial_number": serial_number,
                    "provisioned_at_utc": datetime.now(UTC).isoformat(),
                    "cert9_db_sha256": cert9_sha256,
                    "key4_db_sha256": key4_sha256,
                    "pkcs11_txt_sha256": pkcs11_sha256,
                    "user_js_sha256": user_js_sha256,
                }
                manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(
                    "utf-8"
                )
                _write_atomic_file(
                    p_fd,
                    PROFILE_MANIFEST_FILENAME,
                    manifest_bytes,
                    mode=0o600,
                    create_only=True,
                )

                return manifest


def verify_firefox_profile(
    profile_dir: Path | str,
    *,
    delivery_dir: Path | str | None = None,
    ca_dir: Path | str | None = None,
) -> dict[str, object]:
    """Verify Firefox NSS profile integrity, permissions, digests, and certificate presence.

    Fails closed on mode violations, symlinks, unexpected files, altered file digests,
    missing certificates in NSS database, or mismatch with delivery_dir / ca_dir.
    """
    p_dir = Path(profile_dir) if not isinstance(profile_dir, Path) else profile_dir
    if not p_dir.is_absolute() or ".." in p_dir.parts:
        raise HumanBrowserProvisioningError("directory_invalid")
    with _directory_context(p_dir, write=False) as p_fd:
        # Check files inside profile directory
        entries = set(os.listdir(p_fd))
        if entries != EXPECTED_PROFILE_FILES:
            if not EXPECTED_PROFILE_FILES.issubset(entries):
                raise HumanBrowserProvisioningError("file_not_found")
            raise HumanBrowserProvisioningError("unexpected_files")

        # Verify permissions and size of each file
        for fname in EXPECTED_PROFILE_FILES:
            _check_file_stat(p_fd, fname, MAX_DB_BYTES)

        # Read and parse profile_manifest.json
        manifest_raw = _read_file(p_fd, PROFILE_MANIFEST_FILENAME, MAX_MANIFEST_BYTES)
        try:
            manifest = json.loads(manifest_raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise HumanBrowserProvisioningError("manifest_invalid") from None

        if manifest.get("schema") != PROFILE_MANIFEST_SCHEMA:
            raise HumanBrowserProvisioningError("manifest_invalid")

        required_keys = (
            "actor_id",
            "client_cert_sha256",
            "ca_cert_sha256",
            "serial_number",
            "provisioned_at_utc",
            "cert9_db_sha256",
            "key4_db_sha256",
            "pkcs11_txt_sha256",
            "user_js_sha256",
        )
        for key in required_keys:
            if key not in manifest:
                raise HumanBrowserProvisioningError("manifest_invalid")

        if not isinstance(manifest["serial_number"], int) or isinstance(
            manifest["serial_number"], bool
        ):
            raise HumanBrowserProvisioningError("manifest_invalid")

        for digest_key in (
            "client_cert_sha256",
            "ca_cert_sha256",
            "cert9_db_sha256",
            "key4_db_sha256",
            "pkcs11_txt_sha256",
            "user_js_sha256",
        ):
            val = manifest[digest_key]
            if not isinstance(val, str) or len(val) != 64:
                raise HumanBrowserProvisioningError("manifest_invalid")

        # Verify SHA-256 digests against manifest
        if _hash_file(p_fd, CERT9_DB_FILENAME) != manifest["cert9_db_sha256"]:
            raise HumanBrowserProvisioningError("profile_corrupted")
        if _hash_file(p_fd, KEY4_DB_FILENAME) != manifest["key4_db_sha256"]:
            raise HumanBrowserProvisioningError("profile_corrupted")
        if _hash_file(p_fd, PKCS11_TXT_FILENAME) != manifest["pkcs11_txt_sha256"]:
            raise HumanBrowserProvisioningError("profile_corrupted")
        if _hash_file(p_fd, USER_JS_FILENAME) != manifest["user_js_sha256"]:
            raise HumanBrowserProvisioningError("profile_corrupted")

        # Verify NSS certificate store content via certutil -L
        if shutil.which("certutil") is None:
            raise HumanBrowserProvisioningError("nss_tool_failed")

        proc_list = _run_nss_command(["certutil", "-L", "-d", f"sql:{p_dir}"])
        if proc_list.returncode != 0:
            raise HumanBrowserProvisioningError("nss_tool_failed")

        out = proc_list.stdout.decode("utf-8", errors="replace")
        if "C,," not in out or "u,u,u" not in out:
            raise HumanBrowserProvisioningError("profile_corrupted")

        # Cross-check against delivery_dir if provided
        if delivery_dir is not None:
            d_dir = Path(delivery_dir) if not isinstance(delivery_dir, Path) else delivery_dir
            if not d_dir.is_absolute() or ".." in d_dir.parts:
                raise HumanBrowserProvisioningError("directory_invalid")
            try:
                b_res = ca_ops.verify_client_bundle(d_dir, ca_dir=ca_dir)
            except ca_ops.HumanCaIssuanceError as err:
                if err.code in ("permission_invalid", "symlink_rejected", "directory_invalid"):
                    raise HumanBrowserProvisioningError(err.code) from None
                if err.code in ("ca_bundle_mismatch", "openssl_failed"):
                    raise HumanBrowserProvisioningError("ca_bundle_mismatch") from None
                raise HumanBrowserProvisioningError("bundle_invalid") from None

            b_manifest = b_res.get("bundle_manifest", {})
            if (
                b_manifest.get("certificate_sha256") != manifest["client_cert_sha256"]
                or b_manifest.get("ca_cert_sha256") != manifest["ca_cert_sha256"]
                or b_manifest.get("actor_id") != manifest["actor_id"]
                or b_manifest.get("serial") != manifest["serial_number"]
            ):
                raise HumanBrowserProvisioningError("ca_bundle_mismatch")

        # Cross-check against ca_dir if provided
        if ca_dir is not None:
            c_dir = Path(ca_dir) if not isinstance(ca_dir, Path) else ca_dir
            if not c_dir.is_absolute() or ".." in c_dir.parts:
                raise HumanBrowserProvisioningError("directory_invalid")
            try:
                c_res = ca_ops.verify_human_ca(c_dir)
            except ca_ops.HumanCaIssuanceError as err:
                if err.code in ("permission_invalid", "symlink_rejected", "directory_invalid"):
                    raise HumanBrowserProvisioningError(err.code) from None
                raise HumanBrowserProvisioningError("ca_corrupted") from None

            c_manifest = c_res.get("ca_manifest", {})
            if c_manifest.get("ca_cert_sha256") != manifest["ca_cert_sha256"]:
                raise HumanBrowserProvisioningError("ca_bundle_mismatch")

        return {
            "status": "valid",
            "profile_manifest": manifest,
        }


def _read_passphrase_from_cli(args: argparse.Namespace) -> str:
    """Read passphrase from environment variable or stdin."""
    if args.passphrase_env:
        val = os.environ.get(args.passphrase_env)
        if val is None:
            raise HumanBrowserProvisioningError("invalid_passphrase")
        return val
    if args.passphrase_stdin:
        val = sys.stdin.readline().rstrip("\r\n")
        return val
    raise HumanBrowserProvisioningError("invalid_passphrase")


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for Firefox NSS profile provisioning and verification."""
    parser = argparse.ArgumentParser(
        description="Operator Firefox NSS Profile Provisioning from PKCS#12 Bundles"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # provision-profile
    prov_parser = subparsers.add_parser("provision-profile")
    prov_parser.add_argument(
        "--ca-dir", required=True, type=Path, help="Path to Human Root CA directory"
    )
    prov_parser.add_argument(
        "--delivery-dir",
        required=True,
        type=Path,
        help="Path to client PKCS#12 bundle delivery directory",
    )
    prov_parser.add_argument(
        "--profile-dir", required=True, type=Path, help="Target Firefox profile directory"
    )
    prov_group = prov_parser.add_mutually_exclusive_group(required=True)
    prov_group.add_argument(
        "--passphrase-env", type=str, help="Environment variable containing PKCS#12 passphrase"
    )
    prov_group.add_argument(
        "--passphrase-stdin", action="store_true", help="Read PKCS#12 passphrase from stdin"
    )

    # verify-profile
    ver_parser = subparsers.add_parser("verify-profile")
    ver_parser.add_argument(
        "--profile-dir", required=True, type=Path, help="Firefox profile directory to verify"
    )
    ver_parser.add_argument(
        "--delivery-dir", type=Path, default=None, help="Optional delivery directory to cross-check"
    )
    ver_parser.add_argument(
        "--ca-dir", type=Path, default=None, help="Optional CA directory to cross-check"
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2

    try:
        if args.subcommand == "provision-profile":
            passphrase = _read_passphrase_from_cli(args)
            manifest = provision_firefox_profile(
                ca_dir=args.ca_dir,
                delivery_dir=args.delivery_dir,
                profile_dir=args.profile_dir,
                pkcs12_passphrase=passphrase,
            )
            print(json.dumps({"status": "provisioned", "profile_manifest": manifest}, indent=2))
            return 0
        elif args.subcommand == "verify-profile":
            result = verify_firefox_profile(
                profile_dir=args.profile_dir,
                delivery_dir=args.delivery_dir,
                ca_dir=args.ca_dir,
            )
            print(json.dumps(result, indent=2))
            return 0
    except HumanBrowserProvisioningError as err:
        print(json.dumps({"status": "failed", "reason": err.code}))
        return 1
    except Exception:
        print(json.dumps({"status": "failed", "reason": "internal_error"}))
        return 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
