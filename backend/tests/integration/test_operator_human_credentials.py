"""Operator policy persistence and reconstructed listeners, using disposable certificates."""

import json
import os
import ssl
from datetime import UTC, datetime, timedelta

import pytest

from backend.tests.integration import test_analyst_tls_service as api
from backend.tests.integration import test_analyst_browser_tls_service as browser

from threatfusion.operations import human_credentials as policy
from threatfusion.schemas.analyst_state import AnalystAuthorizationRegistry, AnalystRegistryEntry
from threatfusion.api.analyst_tls_service import AnalystTlsError

certificates = api.certificates


@pytest.fixture
def directory(tmp_path):
    path = tmp_path / "policy"
    path.mkdir(mode=0o700)
    return path


def authorization():
    return AnalystAuthorizationRegistry(
        (
            AnalystRegistryEntry("queue.viewer", "viewer"),
            AnalystRegistryEntry("analyst_a", "analyst"),
        )
    )


def enroll(directory, certs, name="viewer", actor="queue.viewer", *, create=True):
    return policy.enroll(directory, certs[name][0], certs["human_ca"], actor, create=create)


def test_enroll_identity_and_exact_mapping(directory, certificates):
    fingerprint = enroll(directory, certificates)
    assert fingerprint == api._fingerprint(certificates["viewer"][0])
    registry = policy.load_registry(directory, authorization())
    der = ssl.PEM_cert_to_DER_cert(certificates["viewer"][0].read_text())
    decoded = ssl._ssl._test_decode_cert(str(certificates["viewer"][0]))
    assert registry._actor_for_verified_peer(der, decoded, datetime.now(UTC)) == "queue.viewer"
    with pytest.raises(AnalystTlsError, match="authentication_failed"):
        registry._actor_for_verified_peer(
            der,
            {"subjectAltName": (("URI", "urn:threatfusion:human:analyst_a"),)},
            datetime.now(UTC),
        )
    assert (directory / policy.FILENAME).stat().st_mode & 0o777 == 0o600
    assert b"CERTIFICATE" not in (directory / policy.FILENAME).read_bytes()


@pytest.mark.parametrize(
    "name,actor",
    [
        ("wrong_san", "analyst_a"),
        ("wrong_eku", "analyst_a"),
        ("no_eku", "queue.viewer"),
        ("producer", "analyst_a"),
        ("viewer", "analyst_a"),
        ("viewer", "BAD ACTOR"),
    ],
)
def test_reject_certificate_policy(directory, certificates, name, actor):
    with pytest.raises(policy.CredentialPolicyError):
        enroll(directory, certificates, name, actor)
    assert not (directory / policy.FILENAME).exists()


def test_duplicates_and_unknown_actor(directory, certificates):
    enroll(directory, certificates)
    before = (directory / policy.FILENAME).read_bytes()
    for create in (True, False):
        with pytest.raises(policy.CredentialPolicyError):
            enroll(directory, certificates, create=create)
        assert (directory / policy.FILENAME).read_bytes() == before
    enroll(directory, certificates, "unknown", "unknown.analyst", create=False)
    with pytest.raises(policy.CredentialPolicyError):
        policy.load_registry(directory, authorization())


@pytest.mark.parametrize(
    "damage",
    [
        "duplicate",
        "conflict",
        "extra",
        "boolean",
        "expired",
        "future",
        "version",
        "empty",
        "timestamp",
        "json",
        "duplicate_key",
        "oversize",
    ],
)
def test_invalid_metadata(directory, certificates, damage):
    enroll(directory, certificates)
    path = directory / policy.FILENAME
    data = json.loads(path.read_text())
    entry = data["credentials"][0]
    if damage in ("duplicate", "conflict"):
        data["credentials"].append(dict(entry))
        if damage == "conflict":
            data["credentials"][1]["actor_id"] = "analyst_a"
    elif damage == "extra":
        entry["role"] = "analyst"
    elif damage == "boolean":
        entry["enabled"] = 1
    elif damage == "expired":
        entry["not_before"] = (datetime.now(UTC) - timedelta(days=3)).isoformat()
        entry["not_after"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    elif damage == "future":
        entry["not_before"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    elif damage == "version":
        data["schema_version"] = "other"
    elif damage == "empty":
        data["credentials"] = []
    elif damage == "timestamp":
        entry["not_after"] = "tomorrow"
    raw = json.dumps(data)
    if damage == "json":
        raw = "{"
    elif damage == "duplicate_key":
        raw = raw.replace('"enabled": true', '"enabled": false, "enabled": true')
    elif damage == "oversize":
        raw = " " * (policy.MAX_BYTES + 1)
    path.write_text(raw)
    with pytest.raises(policy.CredentialPolicyError):
        policy.load_registry(directory, authorization())


@pytest.mark.parametrize(
    "damage", ["mode", "directory_mode", "missing", "symlink", "hardlink", "fifo", "parent_symlink"]
)
def test_unsafe_files_fail_closed(directory, certificates, tmp_path, damage):
    enroll(directory, certificates)
    path = directory / policy.FILENAME
    if damage == "mode":
        path.chmod(0o644)
    elif damage == "directory_mode":
        directory.chmod(0o755)
    elif damage == "hardlink":
        os.link(path, directory / "alias")
    elif damage == "parent_symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        directory = alias
    else:
        path.unlink()
        if damage == "symlink":
            path.symlink_to(tmp_path / "missing")
        elif damage == "fifo":
            os.mkfifo(path, 0o600)
    with pytest.raises(policy.CredentialPolicyError):
        policy.load_registry(directory, authorization())
    with pytest.raises(policy.CredentialPolicyError):
        policy.restrict(directory, "a" * 64, revoke=True)


def test_exact_restriction_and_failed_replace(directory, certificates, monkeypatch):
    fingerprint = enroll(directory, certificates)
    path = directory / policy.FILENAME
    before = path.read_bytes()
    with pytest.raises(policy.CredentialPolicyError):
        policy.restrict(directory, "a" * 64, revoke=True)
    assert path.read_bytes() == before

    def fail(*args, **kwargs):
        raise OSError("sensitive filesystem detail")

    monkeypatch.setattr(policy.os, "replace", fail)
    with pytest.raises(policy.CredentialPolicyError, match="^credential_policy_invalid$"):
        policy.restrict(directory, fingerprint, revoke=True)
    assert path.read_bytes() == before
    assert list(directory.iterdir()) == [path]


@pytest.mark.parametrize("browser_mode", [False, True])
@pytest.mark.parametrize("revoke", [False, True])
def test_real_mtls_restart_is_required(directory, certificates, tmp_path, browser_mode, revoke):
    fingerprint = enroll(directory, certificates)
    enroll(directory, certificates, "analyst_a", "analyst_a", create=False)
    helper = browser if browser_mode else api
    template = helper._listener(tmp_path, certificates)[0]

    def construct():
        return policy.construct_listener(
            directory,
            template._configuration,
            template._authorization,
            template._view,
            template._audit,
            browser=browser_mode,
        )

    def exchange(listener, identity):
        request = (
            browser._req(listener.address[1])
            if browser_mode
            else api._request("GET", "/v1/analyst/alerts")
        )
        return helper._exchange(listener, certificates, identity, request)

    listener = construct()
    try:
        listener.open()
        assert exchange(listener, "viewer")[0] == 200
        assert exchange(listener, "unknown")[0] in (None, 401)
        policy.restrict(directory, fingerprint, revoke=revoke)
        assert exchange(listener, "viewer")[0] == 200  # disk edits do not reload
        listener.close()
        listener.open()
        assert exchange(listener, "viewer")[0] == 200  # same object is still stale
    finally:
        listener.close()
        template.close()
    history = template._audit.list()
    listener = construct()
    try:
        listener.open()
        response = exchange(listener, "viewer")
        assert response[0] in (None, 401)
        if response[0] is None:
            pass  # The contract permits TLS close before a denial response is read.
        elif browser_mode:
            assert b"Authentication failed" in response[2]
            assert fingerprint.encode() not in response[2]
        else:
            assert response[1] == {"error": "authentication_failed"}
        assert exchange(listener, "analyst_a")[0] == 200
    finally:
        listener.close()
    events = template._audit.list()
    assert events[: len(history)] == history
    denial = events[len(history)]
    assert (denial.event_type, denial.reason_code, denial.actor_id, denial.credential_sha256) == (
        "authentication_rejected",
        "authentication_failed",
        None,
        fingerprint,
    )
    assert events[-1].actor_id == "analyst_a"


def test_cli_sanitized(directory, certificates, capsys):
    args = [
        "--directory",
        str(directory),
        "init",
        "--certificate",
        str(certificates["viewer"][0]),
        "--human-ca",
        str(certificates["human_ca"]),
        "--actor",
        "queue.viewer",
    ]
    assert policy.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "saved_restart_required"
    assert (
        policy.main(
            ["--directory", str(directory), "revoke", "--fingerprint", result["certificate_sha256"]]
        )
        == 0
    )
    assert "saved_restart_required" in capsys.readouterr().out
    assert policy.main(args) == 1
    assert capsys.readouterr().out == '{"error":"credential_policy_invalid"}\n'


def test_busy_directory_and_no_clobber(directory, certificates):
    import fcntl

    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(policy.CredentialPolicyError):
            enroll(directory, certificates)
    finally:
        os.close(fd)
    path = directory / policy.FILENAME
    path.write_text("unrelated operator file")
    path.chmod(0o600)
    with pytest.raises(policy.CredentialPolicyError):
        enroll(directory, certificates)
    assert path.read_text() == "unrelated operator file"


@pytest.mark.parametrize("kind", ["expired", "future", "non_utc", "capacity"])
def test_validity_and_capacity_fail_closed(directory, certificates, kind, monkeypatch):
    if kind in ("expired", "future"):
        original = policy.ssl._ssl._test_decode_cert

        def decoded(path):
            result = original(path)
            if kind == "expired":
                result["notBefore"] = "Jan  1 00:00:00 2020 GMT"
                result["notAfter"] = "Jan  2 00:00:00 2020 GMT"
            else:
                result["notBefore"] = "Jan  1 00:00:00 2099 GMT"
                result["notAfter"] = "Jan  2 00:00:00 2099 GMT"
            return result

        monkeypatch.setattr(policy.ssl._ssl, "_test_decode_cert", decoded)
        with pytest.raises(policy.CredentialPolicyError):
            enroll(directory, certificates)
        assert not (directory / policy.FILENAME).exists()
        return
    enroll(directory, certificates)
    path = directory / policy.FILENAME
    payload = json.loads(path.read_text())
    if kind == "non_utc":
        payload["credentials"][0]["not_after"] = "2099-01-01T00:00:00+01:00"
    else:
        entry = payload["credentials"][0]
        payload["credentials"] = [dict(entry, certificate_sha256=f"{n:064x}") for n in range(65)]
    path.write_text(json.dumps(payload))
    with pytest.raises(policy.CredentialPolicyError):
        policy.load_registry(directory, authorization())
