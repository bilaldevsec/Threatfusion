"""Integration tests for operator Firefox NSS profile provisioning from encrypted PKCS#12 bundles.

Verifies end-to-end chain:
  init_human_ca() -> init_policy_directory() -> issue_and_enroll_human_credential() ->
  provision_firefox_profile() -> verify_firefox_profile() ->
  NSS certutil -L verification, mode 0600 file permissions, zero passphrase leakage,
  and real loopback mTLS GET /analyst/alerts (HTTP 200) on AnalystBrowserTlsListener
  via HumanListenerLifecycle.

Verifies fail-closed rejection on wrong passphrases, tampered database digests,
symlinks, insecure permissions, non-empty profile directories, and CA/bundle mismatch.
"""

from __future__ import annotations

import io
import socket
import ssl
import subprocess
from pathlib import Path

import pytest

from backend.tests.integration import test_analyst_tls_service as api
from threatfusion.api.analyst_tls_service import AnalystTlsConfiguration
from threatfusion.operations import human_ca_issuance as ca_ops
from threatfusion.operations import human_browser_provisioning as prov_ops
from threatfusion.operations.human_listener_lifecycle import HumanListenerLifecycle

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


@pytest.fixture
def profile_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "threatfusion-firefox-profile"
    directory.mkdir(mode=0o700)
    return directory


def test_end_to_end_firefox_profile_provisioning_and_mtls_alerts(
    ca_dir: Path,
    policy_dir: Path,
    delivery_dir: Path,
    profile_dir: Path,
    tmp_path: Path,
    certificates: dict[str, tuple[Path, Path]],
) -> None:
    """End-to-end chain from CA init to profile provisioning, verification, and mTLS browser access."""
    # 1. Initialize Human Root CA
    ca_ops.init_human_ca(ca_dir)

    # 2. Initialize Policy Directory
    prov_ops.init_policy_directory(policy_dir)

    # 3. Issue and Enroll Human Credential
    passphrase = "CorrectHorseBatteryStaple123!"
    actor_id = "queue.viewer"
    enroll_res = ca_ops.issue_and_enroll_human_credential(
        ca_dir=ca_dir,
        policy_dir=policy_dir,
        delivery_dir=delivery_dir,
        actor_id=actor_id,
        validity_days=30,
        pkcs12_passphrase=passphrase,
        create_policy=True,
    )
    assert enroll_res["bundle"]["actor_id"] == actor_id

    # 4. Provision Firefox NSS Profile
    manifest = prov_ops.provision_firefox_profile(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        profile_dir=profile_dir,
        pkcs12_passphrase=passphrase,
    )

    assert manifest["schema"] == prov_ops.PROFILE_MANIFEST_SCHEMA
    assert manifest["actor_id"] == actor_id
    assert manifest["client_cert_sha256"] == enroll_res["bundle"]["certificate_sha256"]
    assert manifest["ca_cert_sha256"] == enroll_res["bundle"]["ca_cert_sha256"]
    assert manifest["serial_number"] == enroll_res["bundle"]["serial"]

    # 5. Verify Firefox NSS Profile
    verify_res = prov_ops.verify_firefox_profile(
        profile_dir=profile_dir,
        delivery_dir=delivery_dir,
        ca_dir=ca_dir,
    )
    assert verify_res["status"] == "valid"
    assert verify_res["profile_manifest"] == manifest

    # 6. Verify filesystem discipline: modes, absence of raw passphrases, and file integrity
    for fname in (
        prov_ops.CERT9_DB_FILENAME,
        prov_ops.KEY4_DB_FILENAME,
        prov_ops.PKCS11_TXT_FILENAME,
        prov_ops.USER_JS_FILENAME,
        prov_ops.PROFILE_MANIFEST_FILENAME,
    ):
        fpath = profile_dir / fname
        assert fpath.is_file()
        assert not fpath.is_symlink()
        stat_res = fpath.stat()
        assert oct(stat_res.st_mode)[-3:] == "600"

        # Ensure no raw passphrase leaked into text files
        if fname in (prov_ops.USER_JS_FILENAME, prov_ops.PROFILE_MANIFEST_FILENAME):
            content = fpath.read_text(encoding="utf-8")
            assert passphrase not in content

    user_js_content = (profile_dir / prov_ops.USER_JS_FILENAME).read_text(encoding="utf-8")
    assert 'user_pref("security.default_personal_cert", "Select Automatically");' in user_js_content
    assert 'user_pref("toolkit.telemetry.enabled", false);' in user_js_content

    # 7. Check NSS database with certutil -L
    proc = subprocess.run(
        ["certutil", "-L", "-d", f"sql:{profile_dir}"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "ThreatFusion Local Human Root CA" in proc.stdout
    assert "C,," in proc.stdout
    assert f"ThreatFusion human {actor_id}" in proc.stdout
    assert "u,u,u" in proc.stdout

    # 8. Loopback mTLS 1.3: extract client cert & key and serve GET /analyst/alerts on AnalystBrowserTlsListener
    extract_dir = tmp_path / "extracted_keys"
    extract_dir.mkdir(mode=0o700)
    client_cert = extract_dir / "client.pem"
    client_key = extract_dir / "client.key"
    ca_ops.extract_client_bundle_for_testing(
        bundle_path=delivery_dir / ca_ops.CLIENT_BUNDLE_FILENAME,
        passphrase=passphrase,
        out_cert_path=client_cert,
        out_key_path=client_key,
    )

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
        _, browser_addr = service.addresses

        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.minimum_version = client_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        client_ctx.verify_mode = ssl.CERT_REQUIRED
        client_ctx.check_hostname = True
        client_ctx.load_verify_locations(cafile=str(certificates["human_ca"]))
        client_ctx.load_cert_chain(str(client_cert), str(client_key))

        # GET /analyst/alerts on browser listener
        with socket.create_connection(browser_addr, timeout=3) as raw:
            with client_ctx.wrap_socket(raw, server_hostname="localhost") as client:
                req = (
                    b"GET /analyst/alerts HTTP/1.1\r\n"
                    b"Host: localhost:" + str(browser_addr[1]).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n\r\n"
                )
                client.sendall(req)
                resp = client.recv(4096)
                assert resp.startswith(b"HTTP/1.1 200 OK")
                assert b"text/html" in resp

        # GET / on browser listener
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
                assert b"text/html" in resp
    finally:
        service.shutdown()


def test_provision_firefox_profile_wrong_passphrase(
    ca_dir: Path, delivery_dir: Path, profile_dir: Path
) -> None:
    """Supplying an incorrect PKCS#12 passphrase fails closed with invalid_passphrase."""
    ca_ops.init_human_ca(ca_dir)
    ca_ops.issue_human_client_bundle(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        actor_id="analyst_a",
        pkcs12_passphrase="CorrectPassphrase123!",
    )

    with pytest.raises(prov_ops.HumanBrowserProvisioningError) as exc_info:
        prov_ops.provision_firefox_profile(
            ca_dir=ca_dir,
            delivery_dir=delivery_dir,
            profile_dir=profile_dir,
            pkcs12_passphrase="WrongPassphrase456!",
        )
    assert exc_info.value.code == "invalid_passphrase"


def test_provision_firefox_profile_non_empty_profile_dir(
    ca_dir: Path, delivery_dir: Path, profile_dir: Path
) -> None:
    """Provisioning into a directory with pre-existing files fails closed with profile_dir_not_empty."""
    ca_ops.init_human_ca(ca_dir)
    passphrase = "CorrectPassphrase123!"
    ca_ops.issue_human_client_bundle(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        actor_id="analyst_a",
        pkcs12_passphrase=passphrase,
    )

    # Pre-populate profile directory
    (profile_dir / "pre_existing.txt").write_text("already here")

    with pytest.raises(prov_ops.HumanBrowserProvisioningError) as exc_info:
        prov_ops.provision_firefox_profile(
            ca_dir=ca_dir,
            delivery_dir=delivery_dir,
            profile_dir=profile_dir,
            pkcs12_passphrase=passphrase,
        )
    assert exc_info.value.code == "profile_dir_not_empty"


def test_verify_firefox_profile_tampered_cert9_db(
    ca_dir: Path, delivery_dir: Path, profile_dir: Path
) -> None:
    """Tampering with cert9.db causes verification to fail closed with profile_corrupted."""
    ca_ops.init_human_ca(ca_dir)
    passphrase = "CorrectPassphrase123!"
    ca_ops.issue_human_client_bundle(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        actor_id="analyst_a",
        pkcs12_passphrase=passphrase,
    )
    prov_ops.provision_firefox_profile(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        profile_dir=profile_dir,
        pkcs12_passphrase=passphrase,
    )

    # Tamper with cert9.db
    cert9_path = profile_dir / prov_ops.CERT9_DB_FILENAME
    content = bytearray(cert9_path.read_bytes())
    content[100] ^= 0xFF
    cert9_path.write_bytes(bytes(content))

    with pytest.raises(prov_ops.HumanBrowserProvisioningError) as exc_info:
        prov_ops.verify_firefox_profile(profile_dir)
    assert exc_info.value.code == "profile_corrupted"


def test_verify_firefox_profile_tampered_user_js(
    ca_dir: Path, delivery_dir: Path, profile_dir: Path
) -> None:
    """Tampering with user.js causes verification to fail closed with profile_corrupted."""
    ca_ops.init_human_ca(ca_dir)
    passphrase = "CorrectPassphrase123!"
    ca_ops.issue_human_client_bundle(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        actor_id="analyst_a",
        pkcs12_passphrase=passphrase,
    )
    prov_ops.provision_firefox_profile(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        profile_dir=profile_dir,
        pkcs12_passphrase=passphrase,
    )

    # Tamper with user.js
    user_js_path = profile_dir / prov_ops.USER_JS_FILENAME
    user_js_path.write_text('user_pref("injected.tamper", true);\n')

    with pytest.raises(prov_ops.HumanBrowserProvisioningError) as exc_info:
        prov_ops.verify_firefox_profile(profile_dir)
    assert exc_info.value.code == "profile_corrupted"


def test_provision_firefox_profile_insecure_permissions_and_symlinks(
    ca_dir: Path, delivery_dir: Path, profile_dir: Path, tmp_path: Path
) -> None:
    """Mode != 0700 or symlink directory paths are strictly rejected."""
    ca_ops.init_human_ca(ca_dir)
    passphrase = "CorrectPassphrase123!"
    ca_ops.issue_human_client_bundle(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        actor_id="analyst_a",
        pkcs12_passphrase=passphrase,
    )

    # Insecure mode 0755 on profile_dir
    profile_dir.chmod(0o755)
    with pytest.raises(prov_ops.HumanBrowserProvisioningError) as exc_info:
        prov_ops.provision_firefox_profile(
            ca_dir=ca_dir,
            delivery_dir=delivery_dir,
            profile_dir=profile_dir,
            pkcs12_passphrase=passphrase,
        )
    assert exc_info.value.code == "permission_invalid"
    profile_dir.chmod(0o700)

    # Symlink profile directory
    symlink_dir = tmp_path / "symlink-profile"
    symlink_dir.symlink_to(profile_dir)
    with pytest.raises(prov_ops.HumanBrowserProvisioningError) as exc_info:
        prov_ops.provision_firefox_profile(
            ca_dir=ca_dir,
            delivery_dir=delivery_dir,
            profile_dir=symlink_dir,
            pkcs12_passphrase=passphrase,
        )
    assert exc_info.value.code == "symlink_rejected"


def test_provision_firefox_profile_ca_bundle_mismatch(
    ca_dir: Path, delivery_dir: Path, profile_dir: Path, tmp_path: Path
) -> None:
    """Attempting to provision a bundle with a mismatched CA fails closed with ca_bundle_mismatch."""
    ca2_dir = tmp_path / "ca2"
    ca2_dir.mkdir(mode=0o700)
    ca_ops.init_human_ca(ca_dir)
    ca_ops.init_human_ca(ca2_dir, common_name="ThreatFusion Alternate CA")

    passphrase = "CorrectPassphrase123!"
    # Issue bundle from ca2
    ca_ops.issue_human_client_bundle(
        ca_dir=ca2_dir,
        delivery_dir=delivery_dir,
        actor_id="analyst_a",
        pkcs12_passphrase=passphrase,
    )

    # Attempt provisioning using ca_dir (first CA)
    with pytest.raises(prov_ops.HumanBrowserProvisioningError) as exc_info:
        prov_ops.provision_firefox_profile(
            ca_dir=ca_dir,
            delivery_dir=delivery_dir,
            profile_dir=profile_dir,
            pkcs12_passphrase=passphrase,
        )
    assert exc_info.value.code == "ca_bundle_mismatch"


def test_verify_firefox_profile_unexpected_files(
    ca_dir: Path, delivery_dir: Path, profile_dir: Path
) -> None:
    """Extra unexpected files inside profile_dir trigger unexpected_files failure."""
    ca_ops.init_human_ca(ca_dir)
    passphrase = "CorrectPassphrase123!"
    ca_ops.issue_human_client_bundle(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        actor_id="analyst_a",
        pkcs12_passphrase=passphrase,
    )
    prov_ops.provision_firefox_profile(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        profile_dir=profile_dir,
        pkcs12_passphrase=passphrase,
    )

    # Plant unexpected file
    extra_file = profile_dir / "injected_script.sh"
    extra_file.write_text("echo malicious")
    extra_file.chmod(0o600)

    with pytest.raises(prov_ops.HumanBrowserProvisioningError) as exc_info:
        prov_ops.verify_firefox_profile(profile_dir)
    assert exc_info.value.code == "unexpected_files"


def test_cli_provision_and_verify(
    ca_dir: Path,
    delivery_dir: Path,
    profile_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI subcommands execute successfully with environment and stdin passphrase sources."""
    ca_ops.init_human_ca(ca_dir)
    passphrase = "CorrectPassphrase123!"
    ca_ops.issue_human_client_bundle(
        ca_dir=ca_dir,
        delivery_dir=delivery_dir,
        actor_id="analyst_a",
        pkcs12_passphrase=passphrase,
    )

    # 1. Provision via CLI with --passphrase-env
    monkeypatch.setenv("TEST_P12_PASS", passphrase)
    code = prov_ops.main(
        [
            "provision-profile",
            "--ca-dir",
            str(ca_dir),
            "--delivery-dir",
            str(delivery_dir),
            "--profile-dir",
            str(profile_dir),
            "--passphrase-env",
            "TEST_P12_PASS",
        ]
    )
    assert code == 0

    # 2. Verify via CLI
    code = prov_ops.main(
        [
            "verify-profile",
            "--profile-dir",
            str(profile_dir),
            "--delivery-dir",
            str(delivery_dir),
            "--ca-dir",
            str(ca_dir),
        ]
    )
    assert code == 0

    # 3. Provisioning into non-empty profile returns error code 1
    code = prov_ops.main(
        [
            "provision-profile",
            "--ca-dir",
            str(ca_dir),
            "--delivery-dir",
            str(delivery_dir),
            "--profile-dir",
            str(profile_dir),
            "--passphrase-env",
            "TEST_P12_PASS",
        ]
    )
    assert code == 1

    # 4. Provision via CLI with --passphrase-stdin into a fresh profile directory
    profile2_dir = profile_dir.parent / "fresh-profile-2"
    profile2_dir.mkdir(mode=0o700)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{passphrase}\n"))
    code = prov_ops.main(
        [
            "provision-profile",
            "--ca-dir",
            str(ca_dir),
            "--delivery-dir",
            str(delivery_dir),
            "--profile-dir",
            str(profile2_dir),
            "--passphrase-stdin",
        ]
    )
    assert code == 0
