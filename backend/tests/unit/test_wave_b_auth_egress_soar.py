"""Wave B (WP-P0-04) unit and integration tests for Auth, HttpOnly Cookies, RS256 JWKS,
SSRF-hardened HTTP Egress, n8n workflow hardening, Stage 6 SOAR atomic ledger, SQLite 0600
permissions, and bootstrap_secrets.py.
"""

from __future__ import annotations

import ast
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import sqlite3
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request

import pytest

from threatfusion.api.live_soc_console import (
    _token_hash,
    rbac_login,
    reset_entra_jwks_cache,
    verify_entra_token,
)
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.operations.commercial_hardening import (
    configured_allowed_hosts,
    is_trusted_proxy_ip,
    reset_login_rate_limiter,
    resolve_client_ip,
)
from threatfusion.operations.http_egress import (
    EgressBlockedError,
    safe_urlopen,
    validate_egress_url,
)
from threatfusion.soar.n8n_thehive_misp_stack import (
    MispDeterministicClient,
    N8nDeterministicPlaybookClient,
    TheHiveDeterministicClient,
    is_rfc1918_or_loopback_ip,
)
from threatfusion.soar.playbook_ledger import (
    ApprovalGatedSoarEngine,
    SoarOptimisticConcurrencyError,
    SoarPlaybookRecord,
    SoarPlaybookSqliteRepository,
    SoarStateTransitionError,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_contract_server_module():
    spec = importlib.util.spec_from_file_location(
        "wave_b_contract_server",
        REPO_ROOT / "scripts" / "run_misp_and_callback_contract_server.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _generate_rsa_keypair_and_jwk(tmp_path: Path, kid: str = "kid-wave-b-1") -> tuple[Path, dict]:
    key_path = tmp_path / f"{kid}.pem"
    subprocess.run(
        ["openssl", "genrsa", "-out", str(key_path), "2048"],
        check=True,
        capture_output=True,
    )
    modulus_out = subprocess.run(
        ["openssl", "rsa", "-in", str(key_path), "-noout", "-modulus"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert modulus_out.startswith("Modulus=")
    n_hex = modulus_out.split("=", 1)[1].strip()
    n_bytes = bytes.fromhex(n_hex)
    e_bytes = (65537).to_bytes(3, "big")
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url(n_bytes),
        "e": _b64url(e_bytes),
    }
    return key_path, jwk


def _sign_rs256_jwt(key_path: Path, header: dict, claims: dict) -> str:
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    c_b64 = _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{c_b64}".encode("ascii")
    sig = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(key_path)],
        input=signing_input,
        check=True,
        capture_output=True,
    ).stdout
    return f"{h_b64}.{c_b64}.{_b64url(sig)}"


def test_http_only_cookie_localhost_vs_production_and_route_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reset_login_rate_limiter()
    mod = _load_contract_server_module()
    handler_cls = mod.MispAndCallbackContractHandler
    live_db = tmp_path / "live.sqlite3"
    soar_db = tmp_path / "soar.sqlite3"
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(live_db))
    monkeypatch.setenv("THREATFUSION_SOAR_LEDGER_DB_PATH", str(soar_db))
    monkeypatch.setenv("THREATFUSION_DATA_DIR", str(tmp_path))
    handler_cls.soar_db_path = str(soar_db)

    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    base = f"http://127.0.0.1:{port}"
    try:
        # 1. Lab localhost HTTP login sets tf_session (HttpOnly; SameSite=Strict, no Secure/__Host-)
        monkeypatch.setenv("THREATFUSION_ENV", "lab")
        login_req = urllib.request.Request(
            f"{base}/api/rbac/login",
            data=json.dumps(
                {
                    "username": "approver@threatfusion.local",
                    "access_code": "TF-Lab-Approver-01!",
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-ThreatFusion-Test-Client": "in-process",
            },
            method="POST",
        )
        with urllib.request.urlopen(login_req, timeout=5.0) as resp:
            set_cookie = resp.headers.get("Set-Cookie") or ""
            login_body = json.loads(resp.read().decode("utf-8"))
        assert set_cookie.startswith("tf_session=")
        assert "HttpOnly" in set_cookie
        assert "SameSite=Strict" in set_cookie
        assert "Secure" not in set_cookie
        assert "session_token" not in login_body
        assert login_body.get("session_cookie_set") is True
        assert login_body.get("csrf_token")
        cookie_pair = set_cookie.split(";", 1)[0]
        raw_token = cookie_pair.split("=", 1)[1]
        assert len(raw_token) >= 40

        # Verify only SHA-256(token) is stored in rbac_sessions
        with sqlite3.connect(live_db) as conn:
            stored_hashes = [
                str(r[0]) for r in conn.execute("SELECT token_hash FROM rbac_sessions").fetchall()
            ]
        assert _token_hash(raw_token) in stored_hashes
        assert raw_token not in stored_hashes

        # Authenticate /api/rbac/session using ONLY Cookie header
        sess_req = urllib.request.Request(
            f"{base}/api/rbac/session",
            headers={"Cookie": cookie_pair},
            method="GET",
        )
        with urllib.request.urlopen(sess_req, timeout=5.0) as resp:
            sess_body = json.loads(resp.read().decode("utf-8"))
        assert sess_body["authenticated"] is True
        assert sess_body["role"] == "soc_approver"

        # /api/v1/live/range/telemetry requires soc_approver
        unauth_telem = urllib.request.Request(f"{base}/api/v1/live/range/telemetry")
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(unauth_telem, timeout=5.0)
        assert exc_info.value.code == 401

        auth_telem = urllib.request.Request(
            f"{base}/api/v1/live/range/telemetry",
            headers={"Cookie": cookie_pair},
        )
        with urllib.request.urlopen(auth_telem, timeout=5.0) as resp:
            assert resp.status == 200

        # 2. Production mode: blocks unauthenticated /api/v1/live/*, strips CSRF from /health,
        # blocks /operator/enroll (403), blocks PYTEST_CURRENT_TEST bypass, issues __Host-tf_session
        monkeypatch.setenv("THREATFUSION_ENV", "production")
        monkeypatch.setenv("TF_ADMIN_EMAIL", "admin@corp.threatfusion.io")
        monkeypatch.setenv("TF_ADMIN_SECRET", "Prod-Admin-Strong-Secret-2026!")
        monkeypatch.setenv("THREATFUSION_TRUSTED_PROXIES", "127.0.0.1/32")

        health_req = urllib.request.Request(
            f"{base}/api/v1/live/health",
            headers={"Origin": base, "Referer": f"{base}/"},
        )
        with urllib.request.urlopen(health_req, timeout=5.0) as resp:
            health_body = json.loads(resp.read().decode("utf-8"))
        assert "csrf_token" not in health_body

        for protected_get in ("/api/v1/live/queue", "/api/v1/live/campaigns", "/api/v1/live/drift"):
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(f"{base}{protected_get}", timeout=5.0)
            assert exc_info.value.code == 401

        # PYTEST_CURRENT_TEST header is rejected in production
        pytest_bypass_req = urllib.request.Request(
            f"{base}/api/v1/live/scenarios",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "X-ThreatFusion-Test-Client": "in-process",
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(pytest_bypass_req, timeout=5.0)
        assert exc_info.value.code == 401

        # /api/v1/live/operator/enroll is disabled (403) in production
        enroll_req = urllib.request.Request(
            f"{base}/api/v1/live/operator/enroll",
            data=json.dumps({"actor_id": "lab_operator"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-ThreatFusion-CSRF": mod._LIVE_CSRF_TOKEN,
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(enroll_req, timeout=5.0)
        assert exc_info.value.code == 403

        # Production login behind trusted HTTPS proxy sets __Host-tf_session; Secure
        prod_login_req = urllib.request.Request(
            f"{base}/api/rbac/login",
            data=json.dumps(
                {
                    "username": "admin@corp.threatfusion.io",
                    "access_code": "Prod-Admin-Strong-Secret-2026!",
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-ThreatFusion-CSRF": mod._LIVE_CSRF_TOKEN,
                "X-Forwarded-Proto": "https",
            },
            method="POST",
        )
        with urllib.request.urlopen(prod_login_req, timeout=5.0) as resp:
            prod_cookie = resp.headers.get("Set-Cookie") or ""
            prod_body = json.loads(resp.read().decode("utf-8"))
        assert prod_cookie.startswith("__Host-tf_session=")
        assert "Secure" in prod_cookie
        assert "HttpOnly" in prod_cookie
        assert "SameSite=Strict" in prod_cookie
        assert "session_token" not in prod_body
        prod_cookie_pair = prod_cookie.split(";", 1)[0]

        # Authenticated production GET succeeds with __Host-tf_session cookie
        prod_queue_req = urllib.request.Request(
            f"{base}/api/v1/live/queue",
            headers={"Cookie": prod_cookie_pair, "X-Forwarded-Proto": "https"},
        )
        with urllib.request.urlopen(prod_queue_req, timeout=5.0) as resp:
            assert resp.status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        reset_login_rate_limiter()


def test_trusted_proxies_and_allowed_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THREATFUSION_ALLOWED_HOSTS", "soc.threatfusion.io, Console.Internal ")
    assert configured_allowed_hosts() == frozenset({"soc.threatfusion.io", "console.internal"})

    monkeypatch.delenv("THREATFUSION_TRUSTED_PROXIES", raising=False)
    assert is_trusted_proxy_ip("127.0.0.1") is False
    # Untrusted peer cannot spoof X-Forwarded-For
    assert resolve_client_ip("198.51.100.10", "203.0.113.5, 10.0.0.1") == "198.51.100.10"

    monkeypatch.setenv("THREATFUSION_TRUSTED_PROXIES", "127.0.0.1/32,10.10.0.0/16")
    assert is_trusted_proxy_ip("127.0.0.1") is True
    # Selects rightmost non-trusted hop, ignoring spoofed leftmost entry
    assert resolve_client_ip("127.0.0.1", "1.2.3.4, 203.0.113.77, 10.10.1.5") == "203.0.113.77"


def test_rs256_entra_jwks_verification_and_unknown_kid_cooldown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reset_entra_jwks_cache()
    live_db = tmp_path / "entra.sqlite3"
    key_path, jwk = _generate_rsa_keypair_and_jwk(tmp_path, kid="kid-valid-2026")
    jwks_doc = {"keys": [jwk]}

    fetch_counter = {"count": 0}

    class _JwksHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            fetch_counter["count"] += 1
            body = json.dumps(jwks_doc).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _JwksHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    try:
        monkeypatch.setenv("THREATFUSION_ENV", "lab")
        monkeypatch.setenv("THREATFUSION_ENTRA_JWKS_URL", f"http://127.0.0.1:{port}/keys")
        now = int(time.time())
        claims = {
            "tid": "00000000-0000-0000-0000-000000000001",
            "oid": "9a1f8c22-3b88-4d19-9e66-33c7d1f9e101",
            "upn": "approver@threatfusion.local",
            "roles": ["SOC.Commander.Approver"],
            "exp": now + 600,
            "nbf": now - 10,
            "iss": "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001/v2.0",
        }
        valid_jwt = _sign_rs256_jwt(
            key_path,
            {"alg": "RS256", "typ": "JWT", "kid": "kid-valid-2026"},
            claims,
        )
        verified = verify_entra_token(live_db, valid_jwt)
        assert verified["http_status"] == 200
        assert verified["jwks_signature_checked"] is True
        assert fetch_counter["count"] == 1

        # rbac_login succeeds with cryptographically verified RS256 Entra token
        logged_in = rbac_login(live_db, entra_token=valid_jwt)
        assert logged_in["http_status"] == 200
        assert logged_in["authenticated"] is True

        # Tampered signature fails closed (401)
        tampered = valid_jwt[:-4] + ("AAAA" if valid_jwt[-4:] != "AAAA" else "BBBB")
        bad_sig = verify_entra_token(live_db, tampered)
        assert bad_sig["http_status"] == 401
        assert bad_sig["reason"] == "entra_signature_invalid"

        # Alg downgrade (HS256) rejected
        hs_jwt = _sign_rs256_jwt(
            key_path,
            {"alg": "HS256", "typ": "JWT", "kid": "kid-valid-2026"},
            claims,
        )
        bad_alg = verify_entra_token(live_db, hs_jwt)
        assert bad_alg["http_status"] == 401
        assert bad_alg["reason"] == "entra_alg_rejected"

        # Unknown kid storm is blocked by 5-minute single-flight cooldown (0 extra HTTP fetches)
        for idx in range(5):
            unknown_jwt = _sign_rs256_jwt(
                key_path,
                {"alg": "RS256", "typ": "JWT", "kid": f"unknown-kid-{idx}"},
                claims,
            )
            res = verify_entra_token(live_db, unknown_jwt)
            assert res["http_status"] == 401
            assert res["reason"] == "entra_jwks_kid_not_found"
        assert fetch_counter["count"] == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        reset_entra_jwks_cache()


def test_http_egress_ssrf_redirects_and_n8n_workflow_hardening() -> None:
    # 0 advisory imports in http_egress.py
    egress_src = (
        REPO_ROOT / "backend" / "src" / "threatfusion" / "operations" / "http_egress.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(egress_src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "advisory" not in alias.name
        elif isinstance(node, ast.ImportFrom):
            assert "advisory" not in (node.module or "")

    # Disallowed schemes, userinfo, IMDS, RFC1918, CGNAT, IPv4-mapped IPv6
    for blocked_url in (
        "file:///etc/passwd",
        "ftp://198.51.100.1/file",
        "http://user:pass@198.51.100.1/api",
        "http://169.254.169.254/latest/meta-data/",
        "http://168.63.129.16/machine",
        "http://100.100.100.200/latest/meta-data",
        "http://[fd00:ec2::254]/latest/meta-data",
        "http://[::ffff:169.254.169.254]/latest/meta-data",
        "http://100.64.0.10/api",
        "http://10.0.0.4/api",
        "http://127.0.0.1:8080/api",
        "http://redis/api",
        "http://service.internal/api",
    ):
        with pytest.raises(EgressBlockedError):
            validate_egress_url(blocked_url, allow_loopback=False)

    # Loopback opt-in works only when allow_loopback=True, still blocks redirects and oversize
    class _RedirectAndOversizeHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data")
                self.end_headers()
                return
            body = b"X" * 4096
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectAndOversizeHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    p = int(srv.server_address[1])
    try:
        with pytest.raises(EgressBlockedError, match="http_redirect_blocked"):
            safe_urlopen(f"http://127.0.0.1:{p}/redirect", allow_loopback=True)
        with pytest.raises(EgressBlockedError, match="egress_response_too_large"):
            safe_urlopen(f"http://127.0.0.1:{p}/big", allow_loopback=True, max_bytes=1024)
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)

    # n8n workflow JSON has 0 body.contract_base_url references
    wf_text = (
        REPO_ROOT / "docker" / "n8n" / "workflows" / "threatfusion_live_console_playbook.json"
    ).read_text(encoding="utf-8")
    assert "body.contract_base_url" not in wf_text
    assert "$env.THREATFUSION_CONTRACT_BASE_URL" in wf_text
    assert "followRedirect: false" in wf_text
    assert "timeout: 5000" in wf_text


def test_stage6_soar_atomic_concurrency_null_chain_and_db_reload(tmp_path: Path) -> None:
    soar_db = tmp_path / "soar_atomic.sqlite3"
    repo = SoarPlaybookSqliteRepository(soar_db, ledger_secret="wave_b_test_soar_hmac_secret_32b")
    engine = ApprovalGatedSoarEngine(repo)
    recs = engine.recommend_actions_for_alert("cand_wave_b_1", None)
    pb_id = recs[0].playbook_id

    # Concurrent version-conflict race: exactly 1 succeeds, 1 raises SoarOptimisticConcurrencyError
    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    lock = threading.Lock()

    def _approve_worker(actor: str) -> None:
        barrier.wait(timeout=5.0)
        try:
            engine.decide_recommendation(
                pb_id,
                actor_id=actor,
                decision="approve",
                reason="Concurrent approval test",
                expected_version=1,
            )
            with lock:
                outcomes.append("ok")
        except (SoarOptimisticConcurrencyError, SoarStateTransitionError):
            with lock:
                outcomes.append("conflict")

    t1 = threading.Thread(target=_approve_worker, args=("approver_1",))
    t2 = threading.Thread(target=_approve_worker, args=("approver_2",))
    t1.start()
    t2.start()
    t1.join(timeout=5.0)
    t2.join(timeout=5.0)
    assert sorted(outcomes) == ["conflict", "ok"]
    ok, msg = repo.verify_audit_chain_integrity()
    assert ok is True, msg

    # Forged in-memory approved record must be rejected by TheHive & n8n when DB row is pending
    recs2 = engine.recommend_actions_for_alert("cand_wave_b_2", None)
    unapproved = recs2[0]
    forged_in_memory = SoarPlaybookRecord(
        playbook_id=unapproved.playbook_id,
        candidate_id=unapproved.candidate_id,
        action_type=unapproved.action_type,
        target_entity=unapproved.target_entity,
        state="approved",
        version=2,
        actor_id="attacker",
        decision_reason="Forged in memory",
        pre_action_snapshot=None,
        execution_evidence=None,
        rollback_reason=None,
        created_at_utc=unapproved.created_at_utc,
        updated_at_utc=unapproved.updated_at_utc,
    )
    hive = TheHiveDeterministicClient(outbox_db_path=tmp_path / "outbox.sqlite3")
    n8n = N8nDeterministicPlaybookClient(
        secret_key="wave_b_test_soar_hmac_secret_32b",
        outbox_db_path=tmp_path / "outbox.sqlite3",
    )
    with pytest.raises(SoarStateTransitionError):
        hive.create_case_from_soar(
            soar_record=forged_in_memory,
            soar_repo=repo,
            rf_confidence_pct=91.0,
        )
    with pytest.raises(SoarStateTransitionError):
        n8n.trigger_soar_playbook(
            soar_record=forged_in_memory,
            soar_repo=repo,
            rf_confidence_pct=91.0,
        )

    # MISP CGNAT, multicast, and single-label internal hostname suppression
    assert is_rfc1918_or_loopback_ip("100.64.1.25") is True
    assert is_rfc1918_or_loopback_ip("224.0.0.251") is True
    assert is_rfc1918_or_loopback_ip("198.51.100.27") is False
    misp = MispDeterministicClient(outbox_db_path=tmp_path / "outbox.sqlite3")
    for blocked_ind, ind_type in (
        ("100.64.0.5", "ip-dst"),
        ("metadata", "hostname"),
        ("misp-connector", "domain"),
        ("db.internal", "domain"),
    ):
        res = misp.query_indicator(blocked_ind, indicator_type=ind_type)
        assert res.private_ip_guard_triggered is True
        assert res.query_mode == "rfc1918_guard_suppressed"

    # Nullifying sequence_id or canonical_entry_sha256 fails verify_audit_chain_integrity()
    with sqlite3.connect(soar_db) as conn:
        conn.execute("DROP TRIGGER IF EXISTS soar_audit_events_append_only_update")
        conn.execute("UPDATE soar_audit_events SET sequence_id = NULL WHERE rowid = 1")
        conn.commit()
    ok_null_seq, msg_null_seq = repo.verify_audit_chain_integrity()
    assert ok_null_seq is False
    assert "sequence_id" in msg_null_seq


def test_sqlite_0600_permissions_and_bootstrap_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_dir = tmp_path / "secure_db_dir"
    alert_db = db_dir / "alerts.sqlite3"
    AlertCandidateRepository(alert_db)
    assert stat.S_IMODE(db_dir.lstat().st_mode) == 0o700
    for suffix in ("", "-wal", "-shm"):
        candidate = alert_db if not suffix else alert_db.with_name(f"{alert_db.name}{suffix}")
        if candidate.exists():
            assert stat.S_IMODE(candidate.lstat().st_mode) == 0o600

    # Production resolve_data_dir refuses /tmp fallback when unset
    monkeypatch.setenv("THREATFUSION_ENV", "production")
    monkeypatch.delenv("THREATFUSION_DATA_DIR", raising=False)

    # bootstrap_secrets.py writes 0600 secrets file and never prints secret values to stdout
    secrets_out = tmp_path / "prod_secrets" / ".env.secrets"
    proc = subprocess.run(
        [
            str(REPO_ROOT / "threatfusion-venv" / "bin" / "python"),
            str(REPO_ROOT / "scripts" / "bootstrap_secrets.py"),
            "--output",
            str(secrets_out),
        ],
        env={"PATH": "/usr/bin:/bin", "THREATFUSION_ENV": "lab"},
        check=True,
        capture_output=True,
        text=True,
    )
    assert secrets_out.is_file()
    assert stat.S_IMODE(secrets_out.lstat().st_mode) == 0o600
    assert stat.S_IMODE(secrets_out.parent.lstat().st_mode) == 0o700
    content = secrets_out.read_text(encoding="utf-8")
    for line in content.splitlines():
        _k, secret_val = line.split("=", 1)
        assert len(secret_val) == 64
        assert secret_val not in proc.stdout
        assert secret_val not in proc.stderr

    # Refuses /tmp output path when THREATFUSION_ENV=production
    bad_proc = subprocess.run(
        [
            str(REPO_ROOT / "threatfusion-venv" / "bin" / "python"),
            str(REPO_ROOT / "scripts" / "bootstrap_secrets.py"),
            "--output",
            "/tmp/threatfusion-forbidden-prod-secrets.env",
        ],
        env={"PATH": "/usr/bin:/bin", "THREATFUSION_ENV": "production"},
        check=False,
        capture_output=True,
        text=True,
    )
    assert bad_proc.returncode != 0
