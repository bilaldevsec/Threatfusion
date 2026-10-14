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

JOURNAL_SCHEMA = "operator_human_credential_journal_v1"
JOURNAL_FILENAME = "journal.jsonl"
JOURNAL_ARCHIVE_SCHEMA = "operator_human_credential_journal_archive_v1"
JOURNAL_ARCHIVE_MANIFEST_FILENAME = "manifest.json"
MAX_JOURNAL_BYTES = 65536
MAX_JOURNAL_RECORDS = 64
_ALLOWED_JOURNAL_FIELDS = {
    "schema",
    "seq",
    "sequence",
    "recorded_at_utc",
    "timestamp",
    "action",
    "actor_id",
    "sha256_fingerprint",
    "resulting_status",
    "status",
    "active_records",
    "total_records",
    "active_count",
    "total_count",
    "previous_archive_sha256",
    "archived_up_to_seq",
}
_REQUIRED_JOURNAL_FIELDS = {
    "schema",
    "seq",
    "recorded_at_utc",
    "action",
    "resulting_status",
    "total_records",
}


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


def _read_journal(fd) -> list[dict[str, object]]:
    try:
        file_fd = os.open(JOURNAL_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return []
    with os.fdopen(file_fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > MAX_JOURNAL_BYTES
        ):
            raise CredentialPolicyError()
        raw = stream.read(MAX_JOURNAL_BYTES + 1)
    if len(raw) > MAX_JOURNAL_BYTES:
        raise CredentialPolicyError()
    if not raw:
        return []
    lines = raw.split(b"\n")
    if lines[-1] != b"":
        raise CredentialPolicyError()
    entries = []
    expected_seq = 1
    for i, line in enumerate(lines[:-1]):
        if not line:
            raise CredentialPolicyError()
        entry = json.loads(line.decode("utf-8"), object_pairs_hook=_unique)
        if type(entry) is not dict:
            raise CredentialPolicyError()
        if not _REQUIRED_JOURNAL_FIELDS.issubset(set(entry)) or not set(entry).issubset(
            _ALLOWED_JOURNAL_FIELDS
        ):
            raise CredentialPolicyError()
        if entry["schema"] != JOURNAL_SCHEMA:
            raise CredentialPolicyError()
        action = entry["action"]
        if action not in {
            "init",
            "enroll",
            "disable",
            "revoke",
            "journal_rotated",
            "archive_checkpoint",
        }:
            raise CredentialPolicyError()
        if entry["resulting_status"] not in {
            "initialized",
            "active",
            "disabled",
            "revoked",
            "rotated",
        }:
            raise CredentialPolicyError()
        if action in {"journal_rotated", "archive_checkpoint"}:
            if i != 0 or entry["resulting_status"] != "rotated":
                raise CredentialPolicyError()
            prev_hash = entry.get("previous_archive_sha256")
            if type(prev_hash) is not str or re.fullmatch(r"[0-9a-f]{64}", prev_hash) is None:
                raise CredentialPolicyError()
            seq = entry["seq"]
            arch_up_to = entry.get("archived_up_to_seq")
            if (
                type(seq) is not int
                or isinstance(seq, bool)
                or seq <= 1
                or type(arch_up_to) is not int
                or isinstance(arch_up_to, bool)
                or arch_up_to != seq - 1
            ):
                raise CredentialPolicyError()
            expected_seq = seq
        else:
            if i == 0:
                expected_seq = 1
        seq = entry["seq"]
        if type(seq) is not int or isinstance(seq, bool) or seq != expected_seq:
            raise CredentialPolicyError()
        ts = entry["recorded_at_utc"]
        if type(ts) is not str:
            raise CredentialPolicyError()
        parsed = datetime.fromisoformat(ts)
        if not is_utc(parsed) or parsed.isoformat() != ts:
            raise CredentialPolicyError()
        actor = entry.get("actor_id")
        if actor is not None and (type(actor) is not str or not valid_actor_id(actor)):
            raise CredentialPolicyError()
        fp = entry.get("sha256_fingerprint")
        if fp is not None and (type(fp) is not str or re.fullmatch(r"[0-9a-f]{64}", fp) is None):
            raise CredentialPolicyError()
        tot = entry["total_records"]
        if type(tot) is not int or isinstance(tot, bool) or tot < 0 or tot > MAX_JOURNAL_RECORDS:
            raise CredentialPolicyError()
        act = entry.get("active_records", entry.get("active_count"))
        if act is not None and (
            type(act) is not int or isinstance(act, bool) or act < 0 or act > tot
        ):
            raise CredentialPolicyError()
        entries.append(entry)
        expected_seq += 1
    if len(entries) > MAX_JOURNAL_RECORDS:
        raise CredentialPolicyError()
    return entries


def _journal_counts(records: list[HumanCredential]) -> tuple[int, int]:
    return sum(1 for r in records if r.enabled and not r.revoked), len(records)


def _append_journal(
    fd,
    existing_entries: list[dict[str, object]],
    *,
    action: str,
    resulting_status: str,
    actor_id: str | None,
    sha256_fingerprint: str | None,
    total_records: int,
    active_records: int,
) -> None:
    if len(existing_entries) >= MAX_JOURNAL_RECORDS:
        raise CredentialPolicyError()
    seq = existing_entries[-1]["seq"] + 1 if existing_entries else 1
    now_str = datetime.now(UTC).isoformat()
    entry = {
        "schema": JOURNAL_SCHEMA,
        "seq": seq,
        "sequence": seq,
        "recorded_at_utc": now_str,
        "timestamp": now_str,
        "action": action,
        "actor_id": actor_id,
        "sha256_fingerprint": sha256_fingerprint,
        "resulting_status": resulting_status,
        "status": resulting_status,
        "active_records": active_records,
        "active_count": active_records,
        "total_records": total_records,
        "total_count": total_records,
    }
    raw = (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8")
    if len(existing_entries) == 0:
        name = ".journal-" + uuid4().hex
        file_fd = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
        )
        try:
            with os.fdopen(file_fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(name, JOURNAL_FILENAME, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.unlink(name, dir_fd=fd)
            os.fsync(fd)
        finally:
            try:
                os.unlink(name, dir_fd=fd)
            except FileNotFoundError:
                pass
    else:
        file_fd = os.open(JOURNAL_FILENAME, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=fd)
        try:
            info = os.fstat(file_fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size + len(raw) > MAX_JOURNAL_BYTES
            ):
                raise CredentialPolicyError()
            written = os.write(file_fd, raw)
            if written != len(raw):
                raise CredentialPolicyError()
            os.fsync(file_fd)
            os.fsync(fd)
        finally:
            os.close(file_fd)


def read_journal(policy_dir: Path | str) -> tuple[dict[str, object], ...]:
    """Validate and read operator credential journal entries under directory lock."""
    directory = Path(policy_dir) if not isinstance(policy_dir, Path) else policy_dir
    with _boundary(), _directory(directory) as fd:
        return tuple(_read_journal(fd))


def rotate_journal(policy_dir: Path | str, archive_dir: Path | str) -> dict[str, object]:
    """Rotate active journal at capacity into an archive directory and seed a hash-chained checkpoint."""
    p_dir = Path(policy_dir) if not isinstance(policy_dir, Path) else policy_dir
    a_dir = Path(archive_dir) if not isinstance(archive_dir, Path) else archive_dir
    if not p_dir.is_absolute() or ".." in p_dir.parts:
        raise CredentialPolicyError()
    if not a_dir.is_absolute() or ".." in a_dir.parts:
        raise CredentialPolicyError()

    with _boundary(), _directory(p_dir, write=True) as pol_fd:
        with _directory(a_dir, write=True) as arch_fd:
            for check_name in (JOURNAL_FILENAME, JOURNAL_ARCHIVE_MANIFEST_FILENAME):
                try:
                    chk = os.open(check_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=arch_fd)
                    os.close(chk)
                    raise CredentialPolicyError()
                except FileNotFoundError:
                    pass

            entries = _read_journal(pol_fd)
            if not entries:
                raise CredentialPolicyError()

            try:
                jfd = os.open(
                    JOURNAL_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pol_fd
                )
            except FileNotFoundError:
                raise CredentialPolicyError()
            try:
                info = os.fstat(jfd)
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JOURNAL_BYTES:
                    raise CredentialPolicyError()
                raw_bytes = os.read(jfd, MAX_JOURNAL_BYTES + 1)
                if len(raw_bytes) > MAX_JOURNAL_BYTES:
                    raise CredentialPolicyError()
            finally:
                os.close(jfd)

            sha256_digest = hashlib.sha256(raw_bytes).hexdigest()
            first_seq = entries[0]["seq"]
            last_seq = entries[-1]["seq"]
            record_count = len(entries)
            prev_archive = entries[0].get("previous_archive_sha256")

            arch_jfd = os.open(
                JOURNAL_FILENAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=arch_fd,
            )
            try:
                os.fchmod(arch_jfd, 0o600)
                written = os.write(arch_jfd, raw_bytes)
                if written != len(raw_bytes):
                    raise CredentialPolicyError()
                os.fsync(arch_jfd)
            finally:
                os.close(arch_jfd)

            now_str = datetime.now(UTC).isoformat()
            manifest = {
                "schema": JOURNAL_ARCHIVE_SCHEMA,
                "archived_at_utc": now_str,
                "archive_file": JOURNAL_FILENAME,
                "sha256_digest": sha256_digest,
                "size_bytes": len(raw_bytes),
                "record_count": record_count,
                "first_seq": first_seq,
                "last_seq": last_seq,
                "archived_up_to_seq": last_seq,
                "previous_archive_sha256": prev_archive,
            }
            manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
            mfd = os.open(
                JOURNAL_ARCHIVE_MANIFEST_FILENAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=arch_fd,
            )
            try:
                os.fchmod(mfd, 0o600)
                written = os.write(mfd, manifest_bytes)
                if written != len(manifest_bytes):
                    raise CredentialPolicyError()
                os.fsync(mfd)
            finally:
                os.close(mfd)
            os.fsync(arch_fd)

            records = _read(pol_fd)
            active_count, total_count = _journal_counts(records)

            checkpoint_entry = {
                "schema": JOURNAL_SCHEMA,
                "seq": last_seq + 1,
                "sequence": last_seq + 1,
                "recorded_at_utc": now_str,
                "timestamp": now_str,
                "action": "journal_rotated",
                "resulting_status": "rotated",
                "status": "rotated",
                "previous_archive_sha256": sha256_digest,
                "archived_up_to_seq": last_seq,
                "active_records": active_count,
                "active_count": active_count,
                "total_records": total_count,
                "total_count": total_count,
            }
            cp_raw = (json.dumps(checkpoint_entry, sort_keys=True) + "\n").encode("utf-8")

            tmp_name = ".journal-" + uuid4().hex
            tmp_fd = os.open(
                tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=pol_fd
            )
            try:
                os.fchmod(tmp_fd, 0o600)
                written = os.write(tmp_fd, cp_raw)
                if written != len(cp_raw):
                    raise CredentialPolicyError()
                os.fsync(tmp_fd)
            finally:
                os.close(tmp_fd)

            try:
                os.replace(tmp_name, JOURNAL_FILENAME, src_dir_fd=pol_fd, dst_dir_fd=pol_fd)
                os.fsync(pol_fd)
            finally:
                try:
                    os.unlink(tmp_name, dir_fd=pol_fd)
                except FileNotFoundError:
                    pass

            return manifest


def verify_journal_archive(archive_dir: Path | str) -> dict[str, object]:
    """Cryptographically and structurally verify an archived operator credential journal."""
    a_dir = Path(archive_dir) if not isinstance(archive_dir, Path) else archive_dir
    if not a_dir.is_absolute() or ".." in a_dir.parts:
        raise CredentialPolicyError()

    with _boundary(), _directory(a_dir, write=False) as arch_fd:
        try:
            mfd = os.open(
                JOURNAL_ARCHIVE_MANIFEST_FILENAME,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=arch_fd,
            )
        except FileNotFoundError:
            raise CredentialPolicyError()
        try:
            info = os.fstat(mfd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size > MAX_JOURNAL_BYTES
            ):
                raise CredentialPolicyError()
            raw_manifest = os.read(mfd, MAX_JOURNAL_BYTES + 1)
        finally:
            os.close(mfd)

        manifest = json.loads(raw_manifest.decode("utf-8"), object_pairs_hook=_unique)
        if type(manifest) is not dict or manifest.get("schema") != JOURNAL_ARCHIVE_SCHEMA:
            raise CredentialPolicyError()

        try:
            jfd = os.open(
                JOURNAL_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=arch_fd
            )
        except FileNotFoundError:
            raise CredentialPolicyError()
        try:
            info = os.fstat(jfd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size > MAX_JOURNAL_BYTES
            ):
                raise CredentialPolicyError()
            raw_journal = os.read(jfd, MAX_JOURNAL_BYTES + 1)
        finally:
            os.close(jfd)

        if len(raw_journal) != manifest.get("size_bytes"):
            raise CredentialPolicyError()
        if hashlib.sha256(raw_journal).hexdigest() != manifest.get("sha256_digest"):
            raise CredentialPolicyError()

        entries = _read_journal(arch_fd)
        if len(entries) != manifest.get("record_count"):
            raise CredentialPolicyError()
        if entries[0]["seq"] != manifest.get("first_seq") or entries[-1]["seq"] != manifest.get(
            "last_seq"
        ):
            raise CredentialPolicyError()
        if manifest.get("archived_up_to_seq") != manifest.get("last_seq"):
            raise CredentialPolicyError()

        return manifest


def init(directory: Path, certificate: Path, ca: Path, actor: str) -> str:
    """Initialize local policy with the first credential; returns DER fingerprint."""
    return enroll(directory, certificate, ca, actor, create=True)


def enroll(directory: Path, certificate: Path, ca: Path, actor: str, *, create=False) -> str:
    """Create or extend local policy; returns only the enrolled DER fingerprint."""
    with _boundary(), _directory(directory, write=True) as fd:
        existing_journal = _read_journal(fd)
        if create and len(existing_journal) > 0:
            raise CredentialPolicyError()
        if len(existing_journal) >= MAX_JOURNAL_RECORDS:
            raise CredentialPolicyError()
        records = [] if create else _read(fd)
        record = _certificate(certificate, ca, actor)
        records.append(record)
        _write(fd, records, create=create)
        active_count = sum(1 for r in records if r.enabled and not r.revoked)
        _append_journal(
            fd,
            existing_journal,
            action="init" if create else "enroll",
            resulting_status="initialized" if create else "active",
            actor_id=record.actor_id,
            sha256_fingerprint=record.certificate_sha256,
            total_records=len(records),
            active_records=active_count,
        )
        return record.certificate_sha256


def restrict(directory: Path, fingerprint: str, *, revoke: bool) -> None:
    """Retain the exact record; no delete, re-enable, or un-revoke operation."""
    with _boundary(), _directory(directory, write=True) as fd:
        existing_journal = _read_journal(fd)
        if len(existing_journal) >= MAX_JOURNAL_RECORDS:
            raise CredentialPolicyError()
        if (
            type(revoke) is not bool
            or type(fingerprint) is not str
            or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
        ):
            raise CredentialPolicyError()
        # Expired records may still be restricted, but cannot be loaded as active.
        records = _read(fd, current=False)
        matched = None
        for r in records:
            if r.certificate_sha256 == fingerprint:
                matched = r
                break
        if matched is None:
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
        active_count = sum(1 for r in records if r.enabled and not r.revoked)
        _append_journal(
            fd,
            existing_journal,
            action="revoke" if revoke else "disable",
            resulting_status="revoked" if revoke else "disabled",
            actor_id=matched.actor_id,
            sha256_fingerprint=fingerprint,
            total_records=len(records),
            active_records=active_count,
        )


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
    rotate_cmd = commands.add_parser("rotate-journal")
    rotate_cmd.add_argument("--archive-dir", type=Path, required=True)
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
        elif args.command == "rotate-journal":
            manifest = rotate_journal(args.directory, args.archive_dir)
            print(json.dumps(manifest))
        else:
            restrict(args.directory, args.fingerprint, revoke=args.command == "revoke")
            print('{"status":"saved_restart_required"}')
    except CredentialPolicyError:
        print('{"error":"credential_policy_invalid"}')
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
