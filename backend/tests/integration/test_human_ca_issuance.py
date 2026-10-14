"""Integration tests for local offline human CA initialization, encrypted client bundle issuance,
policy enrollment coordination, and real loopback mTLS 1.3 authentication.
"""

from __future__ import annotations

import json
import socket
import ssl
from pathlib import Path

import pytest

from backend.tests.integration import test_analyst_tls_service as api
from threatfusion.api.analyst_tls_service import AnalystTlsConfiguration
from threatfusion.operations import human_ca_issuance as ca_ops
from threatfusion.operations import human_credentials as policy
from threatfusion.operations.human_listener_lifecycle import HumanListenerLifecycle
from threatfusion.schemas.analyst_state import (
    AnalystAuthorizationRegistry,
    AnalystRegistryEntry,
)

certificates = api.certificates


@pytest.fixture
def ca_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "threatfusion-ca"
    directory.mkdir(mode=0o700)
    return directory


@pytest.fixture
def policy_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "threatfusion-policy"
    directory.mkdir(mode=0o700)
    return directory


@pytest.fixture
def delivery_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "threatfusion-delivery"
    directory.mkdir(mode=0o700)
    return directory


def test_init_human_ca_success(ca_dir: Path) -> None:
    """Initializing Human CA creates manifest, key, cert, and journal with mode 0600."""
    manifest = ca_ops.init_human_ca(ca_dir)

    assert manifest["schema"] == ca_ops.CA_MANIFEST_SCHEMA
    assert manifest["common_name"] == ca_ops.DEFAULT_CA_COMMON_NAME
    assert manifest["next_serial"] == 1
    assert manifest["issued_count"] == 0
    assert len(manifest["ca_cert_sha256"]) == 64

    # Check files exist with mode 0600
    for filename in (
        ca_ops.CA_MANIFEST_FILENAME,
        ca_ops.CA_KEY_FILENAME,
        ca_ops.CA_CERT_FILENAME,
        ca_ops.CA_JOURNAL_FILENAME,
    ):
        file_path = ca_dir / filename
        assert file_path.is_file()
        assert not file_path.is_symlink()
        stat_res = file_path.stat()
        assert oct(stat_res.st_mode)[-3:] == "600"

    # Repeated initialization fails closed
    with pytest.raises(ca_ops.HumanCaIssuanceError) as exc_info:
        ca_ops.init_human_ca(ca_dir)
    assert exc_info.value.code == "ca_already_exists"


def test_init_human_ca_invalid_arguments(ca_dir: Path) -> None:
    """Invalid validity days or common name fails closed."""
    with pytest.raises(ca_ops.HumanCaIssuanceError) as exc_info:
        ca_ops.init_human_ca(ca_dir, validity_days=0)
    assert exc_info.value.code == "invalid_validity_days"

    with pytest.raises(ca_ops.HumanCaIssuanceError) as exc_info:
        ca_ops.init_human_ca(ca_dir, common_name="   ")
    assert exc_info.value.code == "invalid_common_name"


def test_issue_human_client_bundle_success(ca_dir: Path, delivery_dir: Path) -> None:
    """Issuing bundle creates client_cert.pem, client_bundle.p12, bundle_manifest.json with no raw keys."""
    ca_ops.init_human_ca(ca_dir)
    passphrase = "CorrectHorseBatteryStaple123!"

    manifest = ca_ops.issue_human_client_bundle(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        actor_id="analyst_a",
        validity_days=30,
        pkcs12_passphrase=passphrase,
    )

    assert manifest["schema"] == ca_ops.CLIENT_BUNDLE_SCHEMA
    assert manifest["actor_id"] == "analyst_a"
    assert manifest["serial"] == 1
    assert len(manifest["certificate_sha256"]) == 64
    assert len(manifest["ca_cert_sha256"]) == 64
    assert manifest["validity_days"] == 30

    # Verify delivery files exist with mode 0600
    for filename in (
        ca_ops.BUNDLE_MANIFEST_FILENAME,
        ca_ops.CLIENT_CERT_FILENAME,
        ca_ops.CLIENT_BUNDLE_FILENAME,
    ):
        file_path = delivery_dir / filename
        assert file_path.is_file()
        assert not file_path.is_symlink()
        assert oct(file_path.stat().st_mode)[-3:] == "600"

    # Zero unencrypted private keys in delivery_dir
    for f in delivery_dir.iterdir():
        assert not f.name.endswith(".key")
        assert not f.name.endswith(".pem") or f.name == ca_ops.CLIENT_CERT_FILENAME

    # CA state incremented
    ca_status = ca_ops.verify_human_ca(ca_dir)
    assert ca_status["ca_manifest"]["next_serial"] == 2
    assert ca_status["ca_manifest"]["issued_count"] == 1

    # Extract bundle with correct passphrase
    out_cert = delivery_dir / "extracted_cert.pem"
    out_key = delivery_dir / "extracted_key.pem"
    ca_ops.extract_client_bundle_for_testing(
        bundle_path=delivery_dir / ca_ops.CLIENT_BUNDLE_FILENAME,
        passphrase=passphrase,
        out_cert_path=out_cert,
        out_key_path=out_key,
    )
    assert out_cert.exists()
    assert out_key.exists()

    # Verify extracted cert/key can be loaded into client SSLContext
    ctx = ssl.create_default_context()
    ctx.load_cert_chain(str(out_cert), str(out_key))

    # Extraction with bad passphrase fails
    with pytest.raises(ca_ops.HumanCaIssuanceError) as exc_info:
        ca_ops.extract_client_bundle_for_testing(
            bundle_path=delivery_dir / ca_ops.CLIENT_BUNDLE_FILENAME,
            passphrase="WrongPassphrase123!",
            out_cert_path=delivery_dir / "bad_cert.pem",
            out_key_path=delivery_dir / "bad_key.pem",
        )
    assert exc_info.value.code == "openssl_failed"


def test_issue_bundle_rejects_non_empty_delivery_dir(ca_dir: Path, delivery_dir: Path) -> None:
    """Issuing bundle into non-empty directory fails closed."""
    ca_ops.init_human_ca(ca_dir)
    (delivery_dir / "stray_file.txt").write_text("hello")

    with pytest.raises(ca_ops.HumanCaIssuanceError) as exc_info:
        ca_ops.issue_human_client_bundle(
            ca_dir=ca_dir,
            delivery_dir=delivery_dir,
            actor_id="analyst_a",
            pkcs12_passphrase="CorrectHorseBatteryStaple123!",
        )
    assert exc_info.value.code == "delivery_dir_not_empty"


def test_issue_bundle_validates_actor_and_passphrase(ca_dir: Path, delivery_dir: Path) -> None:
    """Actor ID and passphrase validation enforce strict invariants."""
    ca_ops.init_human_ca(ca_dir)

    # Invalid actor ID
    with pytest.raises(ca_ops.HumanCaIssuanceError) as exc_info:
        ca_ops.issue_human_client_bundle(
            ca_dir=ca_dir,
            delivery_dir=delivery_dir,
            actor_id="INVALID ACTOR",
            pkcs12_passphrase="CorrectHorseBatteryStaple123!",
        )
    assert exc_info.value.code == "invalid_actor"

    # Passphrase too short (< 12 chars)
    with pytest.raises(ca_ops.HumanCaIssuanceError) as exc_info:
        ca_ops.issue_human_client_bundle(
            ca_dir=ca_dir,
            delivery_dir=delivery_dir,
            actor_id="analyst_a",
            pkcs12_passphrase="short12345",
        )
    assert exc_info.value.code == "invalid_passphrase"

    # Passphrase with newline
    with pytest.raises(ca_ops.HumanCaIssuanceError) as exc_info:
        ca_ops.issue_human_client_bundle(
            ca_dir=ca_dir,
            delivery_dir=delivery_dir,
            actor_id="analyst_a",
            pkcs12_passphrase="Invalid\nPassphrase123!",
        )
    assert exc_info.value.code == "invalid_passphrase"


def test_issue_and_enroll_coordination(ca_dir: Path, policy_dir: Path, tmp_path: Path) -> None:
    """Coordinating issuance and policy enrollment maintains journal monotonicity."""
    ca_ops.init_human_ca(ca_dir)

    del1 = tmp_path / "delivery_1"
    del1.mkdir(mode=0o700)
    del2 = tmp_path / "delivery_2"
    del2.mkdir(mode=0o700)

    passphrase = "CorrectHorseBatteryStaple123!"

    # 1. Issue and initialize policy with first credential
    res1 = ca_ops.issue_and_enroll_human_credential(
        ca_dir=ca_dir,
        policy_dir=policy_dir,
        delivery_dir=del1,
        actor_id="queue.viewer",
        pkcs12_passphrase=passphrase,
        create_policy=True,
    )
    assert res1["enrolled_fingerprint"] == res1["bundle"]["certificate_sha256"]

    # 2. Issue and extend policy with second credential
    res2 = ca_ops.issue_and_enroll_human_credential(
        ca_dir=ca_dir,
        policy_dir=policy_dir,
        delivery_dir=del2,
        actor_id="analyst_a",
        pkcs12_passphrase=passphrase,
        create_policy=False,
    )
    assert res2["enrolled_fingerprint"] == res2["bundle"]["certificate_sha256"]

    # Verify policy journal
    journal_entries = policy.read_journal(policy_dir)
    assert len(journal_entries) == 2
    assert journal_entries[0]["action"] == "init"
    assert journal_entries[0]["actor_id"] == "queue.viewer"
    assert journal_entries[1]["action"] == "enroll"
    assert journal_entries[1]["actor_id"] == "analyst_a"

    # Verify both can be loaded by policy.load_registry
    auth_reg = AnalystAuthorizationRegistry(
        (
            AnalystRegistryEntry("queue.viewer", "viewer"),
            AnalystRegistryEntry("analyst_a", "analyst"),
        )
    )
    cred_reg = policy.load_registry(policy_dir, auth_reg)
    assert len(cred_reg._records) == 2


def test_ca_verification_and_tamper_detection(ca_dir: Path) -> None:
    """CA verification validates certificates, manifests, and detects tampering."""
    ca_ops.init_human_ca(ca_dir)
    res = ca_ops.verify_human_ca(ca_dir)
    assert res["status"] == "valid"

    # Corrupting manifest schema causes failure
    manifest_path = ca_dir / ca_ops.CA_MANIFEST_FILENAME
    data = json.loads(manifest_path.read_text())
    data["schema"] = "corrupted_schema"
    manifest_path.write_text(json.dumps(data))

    with pytest.raises(ca_ops.HumanCaIssuanceError) as exc_info:
        ca_ops.verify_human_ca(ca_dir)
    assert exc_info.value.code == "manifest_invalid"


def test_client_bundle_verification(ca_dir: Path, delivery_dir: Path) -> None:
    """Bundle verification validates client cert against manifest and CA."""
    ca_ops.init_human_ca(ca_dir)
    ca_ops.issue_human_client_bundle(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        actor_id="analyst_a",
        pkcs12_passphrase="CorrectHorseBatteryStaple123!",
    )

    ca_cert_path = ca_dir / ca_ops.CA_CERT_FILENAME
    res = ca_ops.verify_client_bundle(delivery_dir, ca_cert_path=ca_cert_path)
    assert res["status"] == "valid"

    # Stray private key in delivery_dir fails verification
    stray_key = delivery_dir / "unencrypted.key"
    stray_key.write_text("DUMMY KEY")
    with pytest.raises(ca_ops.HumanCaIssuanceError) as exc_info:
        ca_ops.verify_client_bundle(delivery_dir, ca_cert_path=ca_cert_path)
    assert exc_info.value.code == "unencrypted_private_key_present"
    stray_key.unlink()


def test_filesystem_permission_and_symlink_rejection(
    ca_dir: Path, delivery_dir: Path, tmp_path: Path
) -> None:
    """Mode != 0700 or symlink components are strictly rejected."""
    # Perm 0755 rejected
    ca_dir.chmod(0o755)
    with pytest.raises(ca_ops.HumanCaIssuanceError) as exc_info:
        ca_ops.init_human_ca(ca_dir)
    assert exc_info.value.code == "permission_invalid"
    ca_dir.chmod(0o700)

    # Symlink directory rejected
    symlink_dir = tmp_path / "symlink_ca"
    symlink_dir.symlink_to(ca_dir)
    with pytest.raises(ca_ops.HumanCaIssuanceError) as exc_info:
        ca_ops.init_human_ca(symlink_dir)
    assert exc_info.value.code == "symlink_rejected"


def test_loopback_mtls_with_issued_bundle(
    tmp_path: Path, certificates: dict[str, tuple[Path, Path]]
) -> None:
    """End-to-end loopback mTLS 1.3 authentication using credentials issued by Human CA."""
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir(mode=0o700)
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir(mode=0o700)
    del_dir = tmp_path / "delivery"
    del_dir.mkdir(mode=0o700)

    ca_ops.init_human_ca(ca_dir)
    passphrase = "CorrectHorseBatteryStaple123!"

    # Issue and enroll viewer
    ca_ops.issue_and_enroll_human_credential(
        ca_dir=ca_dir,
        policy_dir=policy_dir,
        delivery_dir=del_dir,
        actor_id="queue.viewer",
        pkcs12_passphrase=passphrase,
        create_policy=True,
    )

    # Extract client cert and key from PKCS#12 bundle
    extract_dir = tmp_path / "client_keys"
    extract_dir.mkdir(mode=0o700)
    client_cert = extract_dir / "client.pem"
    client_key = extract_dir / "client.key"
    ca_ops.extract_client_bundle_for_testing(
        bundle_path=del_dir / ca_ops.CLIENT_BUNDLE_FILENAME,
        passphrase=passphrase,
        out_cert_path=client_cert,
        out_key_path=client_key,
    )

    # Setup listener lifecycle with CA cert as client CA
    template, candidate, alerts, states, audit = api._listener(tmp_path, certificates)
    ca_cert_path = ca_dir / ca_ops.CA_CERT_FILENAME

    server_config = AnalystTlsConfiguration(
        certificates["server"][0],
        certificates["server"][1],
        ca_cert_path,
    )

    service = HumanListenerLifecycle(
        policy_dir,
        server_config,
        server_config,
        template._authorization,
        template._view,
        audit,
    )

    try:
        service.replace()
        api_addr, browser_addr = service.addresses

        # Build client context trusting server CA, presenting extracted client bundle
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.minimum_version = client_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        client_ctx.verify_mode = ssl.CERT_REQUIRED
        client_ctx.check_hostname = True
        client_ctx.load_verify_locations(cafile=str(certificates["human_ca"]))
        client_ctx.load_cert_chain(str(client_cert), str(client_key))

        # Send request to browser listener
        with socket.create_connection(browser_addr, timeout=3) as raw:
            with client_ctx.wrap_socket(raw, server_hostname="localhost") as client:
                req = (
                    b"GET / HTTP/1.1\r\n"
                    b"Host: localhost:" + str(browser_addr[1]).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n\r\n"
                )
                client.sendall(req)
                resp = client.recv(4096)
                assert resp.startswith(b"HTTP/1.1 200 OK")

    finally:
        service.shutdown()


def test_cli_operations(ca_dir: Path, delivery_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI subcommands execute successfully and respect passphrase sources."""
    # 1. init-ca via CLI
    code = ca_ops.main(["init-ca", "--ca-dir", str(ca_dir)])
    assert code == 0

    # 2. verify-ca via CLI
    code = ca_ops.main(["verify-ca", "--ca-dir", str(ca_dir)])
    assert code == 0

    # 3. issue-bundle via CLI with passphrase-env
    passphrase = "CorrectHorseBatteryStaple123!"
    monkeypatch.setenv("TEST_P12_PASS", passphrase)
    code = ca_ops.main(
        [
            "issue-bundle",
            "--ca-dir",
            str(ca_dir),
            "--delivery-dir",
            str(delivery_dir),
            "--actor-id",
            "analyst_a",
            "--passphrase-env",
            "TEST_P12_PASS",
        ]
    )
    assert code == 0

    # 4. verify-bundle via CLI
    code = ca_ops.main(
        [
            "verify-bundle",
            "--delivery-dir",
            str(delivery_dir),
            "--ca-cert",
            str(ca_dir / ca_ops.CA_CERT_FILENAME),
        ]
    )
    assert code == 0

    # 5. Missing passphrase source returns error exit code 1
    code = ca_ops.main(
        [
            "issue-bundle",
            "--ca-dir",
            str(ca_dir),
            "--delivery-dir",
            str(delivery_dir / "sub"),
            "--actor-id",
            "analyst_a",
        ]
    )
    assert code == 1
