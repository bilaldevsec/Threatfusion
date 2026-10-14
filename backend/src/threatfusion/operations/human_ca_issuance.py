"""Local Offline Human Root CA initialization, client certificate issuance,
encrypted PKCS#12 browser bundle delivery, and enrollment coordination.

Enforces strict filesystem discipline: mode-0700 private directories, mode-0600
files, no symlinks (O_NOFOLLOW), descriptor-relative ancestor ownership
verification (root or current EUID), non-blocking directory filesystem locks
(flock), and atomic temporary file replacement.

Never writes unencrypted client private keys to persistent delivery storage or
logs; client key generation occurs in locked temporary directories and temporary
private keys are unlinked immediately after PKCS#12 bundle creation.
Passphrases are validated for minimum length (>= 12 chars), never stored or
logged, and passed to OpenSSL exclusively via stdin.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import ssl
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Generator
from uuid import uuid4

from threatfusion.operations import human_credentials
from threatfusion.schemas.analyst_state import valid_actor_id

CA_MANIFEST_SCHEMA = "operator_human_ca_v1"
CA_MANIFEST_FILENAME = "ca_manifest.json"
CA_KEY_FILENAME = "ca_key.pem"
CA_CERT_FILENAME = "ca_cert.pem"
CA_JOURNAL_SCHEMA = "operator_human_ca_issuance_journal_v1"
CA_JOURNAL_FILENAME = "issuance_journal.jsonl"

CLIENT_BUNDLE_SCHEMA = "operator_human_client_bundle_v1"
BUNDLE_MANIFEST_FILENAME = "bundle_manifest.json"
CLIENT_CERT_FILENAME = "client_cert.pem"
CLIENT_BUNDLE_FILENAME = "client_bundle.p12"

MAX_BYTES = 65536
MIN_PASSPHRASE_LENGTH = 12
DEFAULT_CA_COMMON_NAME = "ThreatFusion Local Human Root CA"
DEFAULT_CA_VALIDITY_DAYS = 365
DEFAULT_CLIENT_VALIDITY_DAYS = 30


class HumanCaIssuanceError(RuntimeError):
    """Sanitized failure for human CA issuance and client bundle delivery."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"<HumanCaIssuanceError: {self.code}>"


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HumanCaIssuanceError("duplicate_json_keys")
        result[key] = value
    return result


@contextmanager
def _directory_context(directory: Path, *, write: bool = True) -> Generator[int, None, None]:
    """Walk descriptors without following symlinks; verify ancestor modes/ownership; lock inode."""
    if not isinstance(directory, Path):
        directory = Path(directory)
    if not directory.is_absolute() or ".." in directory.parts:
        raise HumanCaIssuanceError("directory_invalid")

    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        raise HumanCaIssuanceError("directory_invalid") from None

    try:
        for part in directory.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as err:
                if err.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise HumanCaIssuanceError("symlink_rejected") from None
                raise HumanCaIssuanceError("directory_invalid") from None
            os.close(fd)
            fd = child
            try:
                info = os.fstat(fd)
            except OSError:
                raise HumanCaIssuanceError("directory_invalid") from None

            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not sticky_root):
                raise HumanCaIssuanceError("permission_invalid")

        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise HumanCaIssuanceError("directory_invalid")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise HumanCaIssuanceError("permission_invalid")

        try:
            lock_flag = (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB
            fcntl.flock(fd, lock_flag)
        except (BlockingIOError, OSError):
            raise HumanCaIssuanceError("lock_failed") from None

        yield fd
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _check_file_stat(dir_fd: int, filename: str, max_bytes: int = MAX_BYTES) -> os.stat_result:
    """Verify regular file, ownership, mode 0600, single link, and byte bound."""
    try:
        file_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError as err:
        if err.errno in (errno.ELOOP, errno.ENOTDIR):
            raise HumanCaIssuanceError("symlink_rejected") from None
        if err.errno == errno.ENOENT:
            raise HumanCaIssuanceError("file_not_found") from None
        raise HumanCaIssuanceError("file_invalid") from None

    try:
        info = os.fstat(file_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > max_bytes
        ):
            raise HumanCaIssuanceError("file_invalid")
        return info
    finally:
        os.close(file_fd)


def _read_file(dir_fd: int, filename: str, max_bytes: int = MAX_BYTES) -> bytes:
    """Read a bounded regular file under directory descriptor checks."""
    try:
        file_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError as err:
        if err.errno in (errno.ELOOP, errno.ENOTDIR):
            raise HumanCaIssuanceError("symlink_rejected") from None
        if err.errno == errno.ENOENT:
            raise HumanCaIssuanceError("file_not_found") from None
        raise HumanCaIssuanceError("file_invalid") from None

    try:
        info = os.fstat(file_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > max_bytes
        ):
            raise HumanCaIssuanceError("file_invalid")
        data = os.read(file_fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise HumanCaIssuanceError("file_invalid")
        return data
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
    if len(data) > MAX_BYTES:
        raise HumanCaIssuanceError("file_invalid")

    temp_name = f".tmp-{uuid4().hex}"
    try:
        temp_fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode,
            dir_fd=dir_fd,
        )
    except OSError:
        raise HumanCaIssuanceError("file_invalid") from None

    try:
        os.fchmod(temp_fd, mode)
        written = os.write(temp_fd, data)
        if written != len(data):
            raise HumanCaIssuanceError("file_invalid")
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
        raise HumanCaIssuanceError("file_invalid") from None


def _run_openssl(
    args: list[str],
    *,
    input_bytes: bytes | None = None,
    timeout: float = 15.0,
) -> str:
    """Run an OpenSSL subprocess safely with bounded timeout and sterile environment."""
    try:
        proc = subprocess.run(
            ["openssl", *args],
            input=input_bytes,
            capture_output=True,
            timeout=timeout,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        raise HumanCaIssuanceError("openssl_failed") from None

    if proc.returncode != 0:
        raise HumanCaIssuanceError("openssl_failed")

    try:
        return proc.stdout.decode("ascii")
    except UnicodeDecodeError:
        return proc.stdout.decode("utf-8", errors="replace")


def _validate_passphrase(passphrase: str) -> None:
    """Validate PKCS#12 passphrase strength and byte hygiene."""
    if not isinstance(passphrase, str):
        raise HumanCaIssuanceError("invalid_passphrase")
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise HumanCaIssuanceError("invalid_passphrase")
    if "\n" in passphrase or "\r" in passphrase or "\0" in passphrase:
        raise HumanCaIssuanceError("invalid_passphrase")


def _validate_actor(actor_id: str) -> None:
    """Validate actor ID format against ThreatFusion authorization schema."""
    if not valid_actor_id(actor_id):
        raise HumanCaIssuanceError("invalid_actor")


def _validate_validity_days(validity_days: int) -> None:
    """Validate certificate validity period in days."""
    if not isinstance(validity_days, int) or isinstance(validity_days, bool):
        raise HumanCaIssuanceError("invalid_validity_days")
    if validity_days < 1 or validity_days > 3650:
        raise HumanCaIssuanceError("invalid_validity_days")


def init_human_ca(
    ca_dir: Path | str,
    *,
    common_name: str = DEFAULT_CA_COMMON_NAME,
    validity_days: int = DEFAULT_CA_VALIDITY_DAYS,
) -> dict[str, object]:
    """Initialize a local offline Root CA for human operator/analyst issuance.

    Generates a 2048-bit RSA Root CA key (mode 0600) and self-signed X.509v3
    certificate with critical basicConstraints=CA:TRUE,pathlen:0 and
    critical keyUsage=keyCertSign,cRLSign.
    Fails closed if the CA already exists in ca_dir.
    """
    _validate_validity_days(validity_days)
    if not isinstance(common_name, str) or not common_name.strip():
        raise HumanCaIssuanceError("invalid_common_name")

    ca_dir_path = Path(ca_dir) if not isinstance(ca_dir, Path) else ca_dir
    with _directory_context(ca_dir_path, write=True) as ca_fd:
        # Check if CA files already exist
        for fname in (CA_MANIFEST_FILENAME, CA_KEY_FILENAME, CA_CERT_FILENAME):
            try:
                chk_fd = os.open(fname, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=ca_fd)
                os.close(chk_fd)
                raise HumanCaIssuanceError("ca_already_exists")
            except FileNotFoundError:
                pass

        with tempfile.TemporaryDirectory(prefix=".tf-ca-init-") as td:
            temp_path = Path(td)
            tmp_key = temp_path / "ca_key.pem"
            tmp_cert = temp_path / "ca_cert.pem"

            _run_openssl(
                [
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(tmp_key),
                    "-out",
                    str(tmp_cert),
                    "-days",
                    str(validity_days),
                    "-sha256",
                    "-subj",
                    f"/CN={common_name}",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE,pathlen:0",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                ]
            )

            cert_pem = tmp_cert.read_bytes()
            key_pem = tmp_key.read_bytes()

            # Verify the generated CA certificate
            ca_der = ssl.PEM_cert_to_DER_cert(cert_pem.decode("ascii"))
            ca_cert_sha256 = hashlib.sha256(ca_der).hexdigest()

            # Write CA private key, cert, manifest, and empty journal
            _write_atomic_file(ca_fd, CA_KEY_FILENAME, key_pem, mode=0o600, create_only=True)
            _write_atomic_file(ca_fd, CA_CERT_FILENAME, cert_pem, mode=0o600, create_only=True)

            manifest = {
                "schema": CA_MANIFEST_SCHEMA,
                "common_name": common_name,
                "ca_cert_sha256": ca_cert_sha256,
                "created_at_utc": datetime.now(UTC).isoformat(),
                "validity_days": validity_days,
                "next_serial": 1,
                "issued_count": 0,
            }
            manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
            _write_atomic_file(
                ca_fd, CA_MANIFEST_FILENAME, manifest_bytes, mode=0o600, create_only=True
            )
            _write_atomic_file(ca_fd, CA_JOURNAL_FILENAME, b"", mode=0o600, create_only=True)

        return manifest


def issue_human_client_bundle(
    ca_dir: Path | str,
    delivery_dir: Path | str,
    *,
    actor_id: str,
    validity_days: int = DEFAULT_CLIENT_VALIDITY_DAYS,
    pkcs12_passphrase: str,
) -> dict[str, object]:
    """Issue a signed client certificate and encrypted PKCS#12 bundle for browser delivery.

    Strictly ensures:
    - Actor ID satisfies valid_actor_id schema
    - Client certificate contains critical basicConstraints=CA:FALSE,
      critical keyUsage=digitalSignature, extendedKeyUsage=clientAuth,
      and subjectAltName=URI:urn:threatfusion:human:<actor_id>
    - PKCS#12 bundle is encrypted with provided passphrase via stdin
    - Zero unencrypted client private keys in delivery_dir or persistent storage
    - Appends to issuance_journal.jsonl and updates ca_manifest.json under lock
    - Fails closed if delivery_dir already contains files
    """
    _validate_actor(actor_id)
    _validate_passphrase(pkcs12_passphrase)
    _validate_validity_days(validity_days)

    ca_dir_path = Path(ca_dir) if not isinstance(ca_dir, Path) else ca_dir
    del_dir_path = Path(delivery_dir) if not isinstance(delivery_dir, Path) else delivery_dir

    # Deterministic lock ordering to prevent deadlocks
    dirs_to_lock = (
        (ca_dir_path, del_dir_path)
        if str(ca_dir_path) <= str(del_dir_path)
        else (del_dir_path, ca_dir_path)
    )

    with _directory_context(dirs_to_lock[0], write=True) as fd_first:
        with _directory_context(dirs_to_lock[1], write=True) as fd_second:
            ca_fd = fd_first if ca_dir_path == dirs_to_lock[0] else fd_second
            del_fd = fd_second if ca_dir_path == dirs_to_lock[0] else fd_first

            # 1. Delivery directory must be empty
            existing_files = [f for f in os.listdir(del_fd) if not f.startswith(".tmp-")]
            if existing_files:
                raise HumanCaIssuanceError("delivery_dir_not_empty")

            # 2. Read and validate CA manifest
            manifest_raw = _read_file(ca_fd, CA_MANIFEST_FILENAME)
            ca_manifest = json.loads(manifest_raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
            if ca_manifest.get("schema") != CA_MANIFEST_SCHEMA:
                raise HumanCaIssuanceError("manifest_invalid")

            serial = ca_manifest.get("next_serial")
            if not isinstance(serial, int) or serial < 1:
                raise HumanCaIssuanceError("manifest_invalid")

            ca_cert_pem = _read_file(ca_fd, CA_CERT_FILENAME)
            ca_der = ssl.PEM_cert_to_DER_cert(ca_cert_pem.decode("ascii"))
            ca_sha256 = hashlib.sha256(ca_der).hexdigest()
            if ca_sha256 != ca_manifest.get("ca_cert_sha256"):
                raise HumanCaIssuanceError("ca_corrupted")

            _check_file_stat(ca_fd, CA_KEY_FILENAME)

            # 3. Secure issuance in temporary workspace
            with tempfile.TemporaryDirectory(prefix=".tf-client-issuance-") as td:
                temp_path = Path(td)
                tmp_ca_cert = temp_path / "ca_cert.pem"
                tmp_ca_key = temp_path / "ca_key.pem"
                tmp_client_key = temp_path / "client.key"
                tmp_client_csr = temp_path / "client.csr"
                tmp_client_cert = temp_path / "client_cert.pem"
                tmp_client_ext = temp_path / "client.ext"
                tmp_client_p12 = temp_path / "client_bundle.p12"

                tmp_ca_cert.write_bytes(ca_cert_pem)
                tmp_ca_cert.chmod(0o600)
                tmp_ca_key.write_bytes(_read_file(ca_fd, CA_KEY_FILENAME))
                tmp_ca_key.chmod(0o600)

                # Generate client key & CSR
                _run_openssl(
                    [
                        "req",
                        "-new",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-keyout",
                        str(tmp_client_key),
                        "-out",
                        str(tmp_client_csr),
                        "-subj",
                        f"/CN={actor_id}",
                    ]
                )
                tmp_client_key.chmod(0o600)

                # Write extension configuration
                tmp_client_ext.write_text(
                    "basicConstraints = critical, CA:FALSE\n"
                    "keyUsage = critical, digitalSignature\n"
                    "extendedKeyUsage = clientAuth\n"
                    f"subjectAltName = URI:urn:threatfusion:human:{actor_id}\n",
                    encoding="ascii",
                )

                # Sign client certificate
                _run_openssl(
                    [
                        "x509",
                        "-req",
                        "-in",
                        str(tmp_client_csr),
                        "-CA",
                        str(tmp_ca_cert),
                        "-CAkey",
                        str(tmp_ca_key),
                        "-set_serial",
                        str(serial),
                        "-out",
                        str(tmp_client_cert),
                        "-days",
                        str(validity_days),
                        "-sha256",
                        "-extfile",
                        str(tmp_client_ext),
                    ]
                )
                tmp_client_cert.chmod(0o600)

                client_cert_pem = tmp_client_cert.read_bytes()

                # Verify certificate against strict human credential criteria
                _run_openssl(
                    [
                        "verify",
                        "-CAfile",
                        str(tmp_ca_cert),
                        "-no-CApath",
                        "-no-CAstore",
                        "-purpose",
                        "sslclient",
                        str(tmp_client_cert),
                    ]
                )
                eku = _run_openssl(
                    ["x509", "-in", str(tmp_client_cert), "-noout", "-ext", "extendedKeyUsage"]
                )
                constraints = _run_openssl(
                    ["x509", "-in", str(tmp_client_cert), "-noout", "-ext", "basicConstraints"]
                )
                if (
                    not eku.strip()
                    or eku.strip().splitlines()[-1].strip() != "TLS Web Client Authentication"
                    or "CA:FALSE" not in constraints
                ):
                    raise HumanCaIssuanceError("certificate_verification_failed")

                decoded = ssl._ssl._test_decode_cert(str(tmp_client_cert))
                if decoded.get("subjectAltName") != (
                    ("URI", f"urn:threatfusion:human:{actor_id}"),
                ):
                    raise HumanCaIssuanceError("certificate_verification_failed")

                client_der = ssl.PEM_cert_to_DER_cert(client_cert_pem.decode("ascii"))
                cert_fingerprint = hashlib.sha256(client_der).hexdigest()

                # Export PKCS#12 bundle encrypted with passphrase via stdin
                _run_openssl(
                    [
                        "pkcs12",
                        "-export",
                        "-out",
                        str(tmp_client_p12),
                        "-inkey",
                        str(tmp_client_key),
                        "-in",
                        str(tmp_client_cert),
                        "-certfile",
                        str(tmp_ca_cert),
                        "-name",
                        f"ThreatFusion human {actor_id}",
                        "-passout",
                        "stdin",
                    ],
                    input_bytes=(pkcs12_passphrase + "\n").encode("utf-8"),
                )
                tmp_client_p12.chmod(0o600)

                # Verify the generated bundle can be opened with the passphrase
                _run_openssl(
                    ["pkcs12", "-in", str(tmp_client_p12), "-noout", "-passin", "stdin"],
                    input_bytes=(pkcs12_passphrase + "\n").encode("utf-8"),
                )

                bundle_p12_bytes = tmp_client_p12.read_bytes()

                # Destroy unencrypted private keys from disk immediately
                os.unlink(tmp_client_key)
                os.unlink(tmp_ca_key)

            # 4. Deliver into delivery directory (mode 0600)
            _write_atomic_file(
                del_fd, CLIENT_CERT_FILENAME, client_cert_pem, mode=0o600, create_only=True
            )
            _write_atomic_file(
                del_fd, CLIENT_BUNDLE_FILENAME, bundle_p12_bytes, mode=0o600, create_only=True
            )

            issued_at_utc = datetime.now(UTC).isoformat()
            bundle_manifest = {
                "schema": CLIENT_BUNDLE_SCHEMA,
                "actor_id": actor_id,
                "serial": serial,
                "certificate_sha256": cert_fingerprint,
                "ca_cert_sha256": ca_sha256,
                "issued_at_utc": issued_at_utc,
                "validity_days": validity_days,
                "bundle_filename": CLIENT_BUNDLE_FILENAME,
                "certificate_filename": CLIENT_CERT_FILENAME,
            }
            b_manifest_bytes = (
                json.dumps(bundle_manifest, sort_keys=True, indent=2) + "\n"
            ).encode("utf-8")
            _write_atomic_file(
                del_fd, BUNDLE_MANIFEST_FILENAME, b_manifest_bytes, mode=0o600, create_only=True
            )

            # 5. Update CA manifest (next_serial + 1, issued_count + 1)
            ca_manifest["next_serial"] = serial + 1
            ca_manifest["issued_count"] = ca_manifest.get("issued_count", 0) + 1
            upd_manifest_bytes = (json.dumps(ca_manifest, sort_keys=True, indent=2) + "\n").encode(
                "utf-8"
            )
            _write_atomic_file(ca_fd, CA_MANIFEST_FILENAME, upd_manifest_bytes, mode=0o600)

            # 6. Append to issuance journal
            journal_entry = {
                "schema": CA_JOURNAL_SCHEMA,
                "serial": serial,
                "actor_id": actor_id,
                "certificate_sha256": cert_fingerprint,
                "issued_at_utc": issued_at_utc,
                "validity_days": validity_days,
            }
            journal_line = (json.dumps(journal_entry, sort_keys=True) + "\n").encode("utf-8")

            j_fd = os.open(
                CA_JOURNAL_FILENAME,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
                dir_fd=ca_fd,
            )
            try:
                os.fchmod(j_fd, 0o600)
                written = os.write(j_fd, journal_line)
                if written != len(journal_line):
                    raise HumanCaIssuanceError("journal_write_failed")
                os.fsync(j_fd)
                os.fsync(ca_fd)
            finally:
                os.close(j_fd)

            # 7. Final assertion: zero unencrypted private keys in delivery_dir
            for entry in os.listdir(del_fd):
                if entry.endswith(".key"):
                    raise HumanCaIssuanceError("unencrypted_private_key_present")

            return bundle_manifest


def issue_and_enroll_human_credential(
    ca_dir: Path | str,
    policy_dir: Path | str,
    delivery_dir: Path | str,
    *,
    actor_id: str,
    validity_days: int = DEFAULT_CLIENT_VALIDITY_DAYS,
    pkcs12_passphrase: str,
    create_policy: bool = False,
) -> dict[str, object]:
    """Issue a client bundle and atomically enroll its public certificate into operator policy."""
    ca_dir_path = Path(ca_dir) if not isinstance(ca_dir, Path) else ca_dir
    delivery_dir_path = Path(delivery_dir) if not isinstance(delivery_dir, Path) else delivery_dir
    policy_dir_path = Path(policy_dir) if not isinstance(policy_dir, Path) else policy_dir

    bundle_manifest = issue_human_client_bundle(
        ca_dir=ca_dir_path,
        delivery_dir=delivery_dir_path,
        actor_id=actor_id,
        validity_days=validity_days,
        pkcs12_passphrase=pkcs12_passphrase,
    )

    cert_path = delivery_dir_path / CLIENT_CERT_FILENAME
    ca_cert_path = ca_dir_path / CA_CERT_FILENAME

    try:
        if create_policy:
            fingerprint = human_credentials.init(
                policy_dir_path,
                cert_path,
                ca_cert_path,
                actor_id,
            )
        else:
            fingerprint = human_credentials.enroll(
                policy_dir_path,
                cert_path,
                ca_cert_path,
                actor_id,
            )
    except human_credentials.CredentialPolicyError:
        raise HumanCaIssuanceError("policy_enrollment_failed") from None

    return {
        "bundle": bundle_manifest,
        "enrolled_fingerprint": fingerprint,
    }


def verify_human_ca(ca_dir: Path | str) -> dict[str, object]:
    """Verify Root CA structure, permissions, self-signature, and issuance journal consistency."""
    ca_dir_path = Path(ca_dir) if not isinstance(ca_dir, Path) else ca_dir
    with _directory_context(ca_dir_path, write=False) as ca_fd:
        manifest_raw = _read_file(ca_fd, CA_MANIFEST_FILENAME)
        manifest = json.loads(manifest_raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        if manifest.get("schema") != CA_MANIFEST_SCHEMA:
            raise HumanCaIssuanceError("manifest_invalid")

        cert_raw = _read_file(ca_fd, CA_CERT_FILENAME)
        ca_der = ssl.PEM_cert_to_DER_cert(cert_raw.decode("ascii"))
        computed_sha = hashlib.sha256(ca_der).hexdigest()
        if computed_sha != manifest.get("ca_cert_sha256"):
            raise HumanCaIssuanceError("ca_corrupted")

        _check_file_stat(ca_fd, CA_KEY_FILENAME)

        with tempfile.TemporaryDirectory(prefix=".tf-ca-verify-") as td:
            tmp_cert = Path(td) / "ca.pem"
            tmp_cert.write_bytes(cert_raw)
            tmp_cert.chmod(0o600)

            _run_openssl(
                ["verify", "-CAfile", str(tmp_cert), "-no-CApath", "-no-CAstore", str(tmp_cert)]
            )
            basic_constraints = _run_openssl(
                ["x509", "-in", str(tmp_cert), "-noout", "-ext", "basicConstraints"]
            )
            if "CA:TRUE" not in basic_constraints:
                raise HumanCaIssuanceError("ca_corrupted")

        try:
            journal_raw = _read_file(ca_fd, CA_JOURNAL_FILENAME)
            if journal_raw.strip():
                lines = [line for line in journal_raw.strip().split(b"\n") if line.strip()]
                if len(lines) != manifest.get("issued_count"):
                    raise HumanCaIssuanceError("journal_corrupted")
                # Verify each line has required schema
                for line in lines:
                    entry = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_pairs)
                    if entry.get("schema") != CA_JOURNAL_SCHEMA:
                        raise HumanCaIssuanceError("journal_corrupted")
        except HumanCaIssuanceError as err:
            if err.code != "file_not_found":
                raise

        return {
            "status": "valid",
            "ca_manifest": manifest,
        }


def verify_client_bundle(
    delivery_dir: Path | str,
    ca_cert_path: Path | str | None = None,
    *,
    ca_dir: Path | str | None = None,
) -> dict[str, object]:
    """Verify delivery directory permissions, manifest integrity, and absence of private keys."""
    delivery_dir_path = Path(delivery_dir) if not isinstance(delivery_dir, Path) else delivery_dir
    if ca_dir is not None and ca_cert_path is None:
        ca_dir_path = Path(ca_dir) if not isinstance(ca_dir, Path) else ca_dir
        ca_cert_path = ca_dir_path / CA_CERT_FILENAME
    with _directory_context(delivery_dir_path, write=False) as del_fd:
        manifest_raw = _read_file(del_fd, BUNDLE_MANIFEST_FILENAME)
        manifest = json.loads(manifest_raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        if manifest.get("schema") != CLIENT_BUNDLE_SCHEMA:
            raise HumanCaIssuanceError("manifest_invalid")

        cert_raw = _read_file(del_fd, CLIENT_CERT_FILENAME)
        client_der = ssl.PEM_cert_to_DER_cert(cert_raw.decode("ascii"))
        computed_sha = hashlib.sha256(client_der).hexdigest()
        if computed_sha != manifest.get("certificate_sha256"):
            raise HumanCaIssuanceError("bundle_invalid")

        if ca_dir is not None:
            ca_dir_path = Path(ca_dir) if not isinstance(ca_dir, Path) else ca_dir
            ca_cert_raw = (ca_dir_path / CA_CERT_FILENAME).read_bytes()
            ca_der_val = ssl.PEM_cert_to_DER_cert(ca_cert_raw.decode("ascii"))
            ca_sha_val = hashlib.sha256(ca_der_val).hexdigest()
            if manifest.get("ca_cert_sha256") != ca_sha_val:
                raise HumanCaIssuanceError("ca_bundle_mismatch")

        _check_file_stat(del_fd, CLIENT_BUNDLE_FILENAME)

        for entry in os.listdir(del_fd):
            if entry.endswith(".key"):
                raise HumanCaIssuanceError("unencrypted_private_key_present")

        if ca_cert_path is not None:
            resolved_ca_path = (
                Path(ca_cert_path) if not isinstance(ca_cert_path, Path) else ca_cert_path
            )
            with tempfile.TemporaryDirectory(prefix=".tf-bundle-verify-") as td:
                tmp_cert = Path(td) / "client.pem"
                tmp_cert.write_bytes(cert_raw)
                tmp_cert.chmod(0o600)

                _run_openssl(
                    [
                        "verify",
                        "-CAfile",
                        str(resolved_ca_path),
                        "-no-CApath",
                        "-no-CAstore",
                        "-purpose",
                        "sslclient",
                        str(tmp_cert),
                    ]
                )

        return {
            "status": "valid",
            "bundle_manifest": manifest,
        }


def extract_client_bundle_for_testing(
    bundle_path: Path | str,
    passphrase: str,
    out_cert_path: Path | str,
    out_key_path: Path | str,
) -> None:
    """Helper for test suites to extract certificates and keys from encrypted PKCS#12 bundle."""
    _validate_passphrase(passphrase)
    b_path = Path(bundle_path).resolve()
    c_path = Path(out_cert_path).resolve()
    k_path = Path(out_key_path).resolve()

    _run_openssl(
        [
            "pkcs12",
            "-in",
            str(b_path),
            "-clcerts",
            "-nokeys",
            "-out",
            str(c_path),
            "-passin",
            "stdin",
        ],
        input_bytes=(passphrase + "\n").encode("utf-8"),
    )
    _run_openssl(
        [
            "pkcs12",
            "-in",
            str(b_path),
            "-nocerts",
            "-nodes",
            "-out",
            str(k_path),
            "-passin",
            "stdin",
        ],
        input_bytes=(passphrase + "\n").encode("utf-8"),
    )
    c_path.chmod(0o600)
    k_path.chmod(0o600)


def _get_passphrase_from_args(args: argparse.Namespace) -> str:
    """Read passphrase from environment variable or stdin, never command line argument."""
    if getattr(args, "passphrase_env", None):
        val = os.environ.get(args.passphrase_env)
        if not val:
            raise HumanCaIssuanceError("passphrase_env_missing")
        return val
    elif getattr(args, "passphrase_stdin", False):
        line = sys.stdin.readline()
        if not line:
            raise HumanCaIssuanceError("passphrase_stdin_empty")
        return line.rstrip("\r\n")
    else:
        raise HumanCaIssuanceError("passphrase_source_required")


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for human CA initialization, bundle issuance, and enrollment."""
    parser = argparse.ArgumentParser(
        prog="human_ca_issuance",
        description="ThreatFusion human CA management and encrypted client bundle issuance CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init-ca
    init_parser = subparsers.add_parser("init-ca", help="Initialize local offline Root CA")
    init_parser.add_argument("--ca-dir", required=True, type=Path)
    init_parser.add_argument("--common-name", default=DEFAULT_CA_COMMON_NAME)
    init_parser.add_argument("--validity-days", type=int, default=DEFAULT_CA_VALIDITY_DAYS)

    # issue-bundle
    bundle_parser = subparsers.add_parser(
        "issue-bundle", help="Issue client certificate and PKCS#12 bundle"
    )
    bundle_parser.add_argument("--ca-dir", required=True, type=Path)
    bundle_parser.add_argument("--delivery-dir", required=True, type=Path)
    bundle_parser.add_argument("--actor-id", required=True)
    bundle_parser.add_argument("--validity-days", type=int, default=DEFAULT_CLIENT_VALIDITY_DAYS)
    bundle_parser.add_argument(
        "--passphrase-env", help="Environment variable containing PKCS#12 passphrase"
    )
    bundle_parser.add_argument(
        "--passphrase-stdin", action="store_true", help="Read passphrase from stdin"
    )

    # issue-and-enroll
    enroll_parser = subparsers.add_parser(
        "issue-and-enroll", help="Issue client bundle and enroll public certificate in policy"
    )
    enroll_parser.add_argument("--ca-dir", required=True, type=Path)
    enroll_parser.add_argument("--policy-dir", required=True, type=Path)
    enroll_parser.add_argument("--delivery-dir", required=True, type=Path)
    enroll_parser.add_argument("--actor-id", required=True)
    enroll_parser.add_argument("--validity-days", type=int, default=DEFAULT_CLIENT_VALIDITY_DAYS)
    enroll_parser.add_argument(
        "--create-policy", action="store_true", help="Initialize new policy file"
    )
    enroll_parser.add_argument(
        "--passphrase-env", help="Environment variable containing PKCS#12 passphrase"
    )
    enroll_parser.add_argument(
        "--passphrase-stdin", action="store_true", help="Read passphrase from stdin"
    )

    # verify-ca
    vca_parser = subparsers.add_parser(
        "verify-ca", help="Verify Root CA directory and certificates"
    )
    vca_parser.add_argument("--ca-dir", required=True, type=Path)

    # verify-bundle
    vb_parser = subparsers.add_parser(
        "verify-bundle", help="Verify client bundle delivery directory"
    )
    vb_parser.add_argument("--delivery-dir", required=True, type=Path)
    vb_parser.add_argument("--ca-cert", type=Path, default=None)

    args = parser.parse_args(argv)

    try:
        if args.command == "init-ca":
            res = init_human_ca(
                ca_dir=args.ca_dir,
                common_name=args.common_name,
                validity_days=args.validity_days,
            )
            print(json.dumps(res, indent=2))
        elif args.command == "issue-bundle":
            passphrase = _get_passphrase_from_args(args)
            res = issue_human_client_bundle(
                ca_dir=args.ca_dir,
                delivery_dir=args.delivery_dir,
                actor_id=args.actor_id,
                validity_days=args.validity_days,
                pkcs12_passphrase=passphrase,
            )
            print(json.dumps(res, indent=2))
        elif args.command == "issue-and-enroll":
            passphrase = _get_passphrase_from_args(args)
            res = issue_and_enroll_human_credential(
                ca_dir=args.ca_dir,
                policy_dir=args.policy_dir,
                delivery_dir=args.delivery_dir,
                actor_id=args.actor_id,
                validity_days=args.validity_days,
                pkcs12_passphrase=passphrase,
                create_policy=args.create_policy,
            )
            print(json.dumps(res, indent=2))
        elif args.command == "verify-ca":
            res = verify_human_ca(args.ca_dir)
            print(json.dumps(res, indent=2))
        elif args.command == "verify-bundle":
            res = verify_client_bundle(args.delivery_dir, ca_cert_path=args.ca_cert)
            print(json.dumps(res, indent=2))
        return 0
    except HumanCaIssuanceError as err:
        sys.stderr.write(f"human_ca_error: {err.code}\n")
        return 1
    except human_credentials.CredentialPolicyError:
        sys.stderr.write("credential_policy_invalid\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
