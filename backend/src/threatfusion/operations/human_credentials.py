"""Local Linux operator metadata; no issuance, private keys, or live reload."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import ssl
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from threatfusion.api.analyst_tls_service import (
    ANALYST_URI_PREFIX,
    AnalystTlsError,
    HumanCredential,
    HumanCredentialRegistry,
)
from threatfusion.schemas.analyst_state import (
    AnalystAuthorizationRegistry,
    AnalystStateError,
    valid_actor_id,
    is_utc,
)

SCHEMA = "operator_human_credentials_v1"
FILENAME = "human-credentials.json"
MAX_BYTES = 65536
_FIELDS = {"actor_id", "certificate_sha256", "enabled", "revoked", "not_before", "not_after"}


class CredentialPolicyError(RuntimeError):
    """Only a fixed error reaches operator output."""

    def __init__(self):
        super().__init__("credential_policy_invalid")


@contextmanager
def _boundary():
    try:
        yield
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
        subprocess.SubprocessError,
        AnalystTlsError,
        AnalystStateError,
    ):
        raise CredentialPolicyError() from None


@contextmanager
def _directory(directory: Path, *, write=False):
    """Walk descriptors without symlinks; lock the private directory inode."""
    if not directory.is_absolute() or ".." in directory.parts:
        raise CredentialPolicyError()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in directory.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            # Root-owned sticky temporary parents are permitted for isolated tests.
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not sticky_root):
                raise CredentialPolicyError()
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise CredentialPolicyError()
        fcntl.flock(fd, (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        yield fd
    finally:
        os.close(fd)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CredentialPolicyError()
        result[key] = value
    return result


def _validate(records, *, current):
    registry = HumanCredentialRegistry(tuple(records))
    now = datetime.now(UTC)
    if current and any(
        r.enabled and not r.revoked and not r.not_before <= now < r.not_after for r in records
    ):
        raise CredentialPolicyError()
    return registry


def _read(fd, *, current=True):
    file_fd = os.open(FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(file_fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > MAX_BYTES
        ):
            raise CredentialPolicyError()
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise CredentialPolicyError()
    payload = json.loads(raw, object_pairs_hook=_unique)
    if type(payload) is not dict or set(payload) != {"schema_version", "credentials"}:
        raise CredentialPolicyError()
    if payload["schema_version"] != SCHEMA or type(payload["credentials"]) is not list:
        raise CredentialPolicyError()
    records = []
    for entry in payload["credentials"]:
        if type(entry) is not dict or set(entry) != _FIELDS:
            raise CredentialPolicyError()
        entry = dict(entry)
        for key in ("not_before", "not_after"):
            value = entry[key]
            if type(value) is not str:
                raise CredentialPolicyError()
            parsed = datetime.fromisoformat(value)
            if not is_utc(parsed) or parsed.isoformat() != value:
                raise CredentialPolicyError()
            entry[key] = parsed
        records.append(HumanCredential(**entry))
    _validate(records, current=current)
    return records


def _write(fd, records, *, create=False):
    _validate(records, current=False)
    entries = []
    for record in records:
        entry = asdict(record)
        for key in ("not_before", "not_after"):
            entry[key] = entry[key].isoformat()
        entries.append(entry)
    raw = (
        json.dumps({"schema_version": SCHEMA, "credentials": entries}, sort_keys=True) + "\n"
    ).encode()
    if len(raw) > MAX_BYTES:
        raise CredentialPolicyError()
    name = ".human-policy-" + uuid4().hex
    file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(file_fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if create:
            # Atomic no-clobber publication, including dangling symlink destinations.
            os.link(name, FILENAME, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.unlink(name, dir_fd=fd)
        else:
            os.replace(name, FILENAME, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass


def _openssl(*args):
    result = subprocess.run(
        ["openssl", *args],
        capture_output=True,
        timeout=10,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    if result.returncode:
        raise CredentialPolicyError()
    return result.stdout.decode("ascii")


def _certificate(certificate: Path, ca: Path, actor: str):
    if not valid_actor_id(actor):
        raise CredentialPolicyError()
    with certificate.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if (
        len(raw) > MAX_BYTES
        or re.fullmatch(
            rb"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*", raw
        )
        is None
    ):
        raise CredentialPolicyError()
    # One immutable public snapshot is decoded and verified. Never read a private key.
    with tempfile.TemporaryDirectory(prefix="tf-public-certificate-") as directory:
        snapshot = Path(directory) / "public.pem"
        with snapshot.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
        decoded = ssl._ssl._test_decode_cert(str(snapshot))
        _openssl(
            "verify",
            "-CAfile",
            str(ca),
            "-no-CApath",
            "-no-CAstore",
            "-purpose",
            "sslclient",
            str(snapshot),
        )
        eku = _openssl("x509", "-in", str(snapshot), "-noout", "-ext", "extendedKeyUsage")
        constraints = _openssl("x509", "-in", str(snapshot), "-noout", "-ext", "basicConstraints")
        if (
            not eku.strip()
            or eku.strip().splitlines()[-1].strip() != "TLS Web Client Authentication"
            or "CA:FALSE" not in constraints
        ):
            raise CredentialPolicyError()
    if decoded.get("subjectAltName") != (("URI", ANALYST_URI_PREFIX + actor),):
        raise CredentialPolicyError()
    record = HumanCredential(
        actor,
        hashlib.sha256(ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))).hexdigest(),
        True,
        False,
        datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notBefore"]), UTC),
        datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notAfter"]), UTC),
    )
    _validate([record], current=True)
    return record


def enroll(directory: Path, certificate: Path, ca: Path, actor: str, *, create=False) -> str:
    """Create or extend local policy; returns only the enrolled DER fingerprint."""
    with _boundary(), _directory(directory, write=True) as fd:
        records = [] if create else _read(fd)
        record = _certificate(certificate, ca, actor)
        records.append(record)
        _write(fd, records, create=create)
        return record.certificate_sha256


def restrict(directory: Path, fingerprint: str, *, revoke: bool) -> None:
    """Retain the exact record; no delete, re-enable, or un-revoke operation."""
    with _boundary(), _directory(directory, write=True) as fd:
        if (
            type(revoke) is not bool
            or type(fingerprint) is not str
            or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
        ):
            raise CredentialPolicyError()
        # Expired records may still be restricted, but cannot be loaded as active.
        records = _read(fd, current=False)
        if not any(r.certificate_sha256 == fingerprint for r in records):
            raise CredentialPolicyError()
        records = [
            (
                replace(r, **({"revoked": True} if revoke else {"enabled": False}))
                if r.certificate_sha256 == fingerprint
                else r
            )
            for r in records
        ]
        _write(fd, records)


def load_registry(directory: Path, authorization) -> HumanCredentialRegistry:
    """Build a new immutable snapshot; active actors must already be authorized."""
    with _boundary(), _directory(directory) as fd:
        if type(authorization) is not AnalystAuthorizationRegistry:
            raise CredentialPolicyError()
        records = _read(fd)
        for record in records:
            if record.enabled and not record.revoked:
                authorization.issue_for_trusted_actor(record.actor_id)
        return HumanCredentialRegistry(tuple(records))


def construct_listener(
    directory: Path, configuration, authorization, view, audit, *, browser=False
):
    """Construction integration point, with no demo fallback or automatic open."""
    from threatfusion.api.analyst_browser_tls_service import AnalystBrowserTlsListener
    from threatfusion.api.analyst_tls_service import AnalystTlsListener

    credentials = load_registry(directory, authorization)
    listener_type = AnalystBrowserTlsListener if browser else AnalystTlsListener
    return listener_type(configuration, credentials, authorization, view, audit)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "enroll"):
        command = commands.add_parser(name)
        command.add_argument("--certificate", type=Path, required=True)
        command.add_argument("--human-ca", type=Path, required=True)
        command.add_argument("--actor", required=True)
    for name in ("disable", "revoke"):
        command = commands.add_parser(name)
        command.add_argument("--fingerprint", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in ("init", "enroll"):
            fingerprint = enroll(
                args.directory,
                args.certificate,
                args.human_ca,
                args.actor,
                create=args.command == "init",
            )
            print(
                json.dumps({"status": "saved_restart_required", "certificate_sha256": fingerprint})
            )
        else:
            restrict(args.directory, args.fingerprint, revoke=args.command == "revoke")
            print('{"status":"saved_restart_required"}')
    except CredentialPolicyError:
        print('{"error":"credential_policy_invalid"}')
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
