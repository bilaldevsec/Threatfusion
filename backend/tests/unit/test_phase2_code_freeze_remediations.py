"""Phase 2 code-freeze regression tests covering C1-C4, H1-H9, M1-M7, and L2-L3."""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import sqlite3
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from scripts.run_misp_and_callback_contract_server import (
    MispAndCallbackContractHandler,
    ThreatFusionThreadingHTTPServer,
    configure_server_tls,
    http_client_certificate_fingerprint,
)
from threatfusion.advisory.explanation_engine import (
    AdvisoryEvidenceBundle,
    build_four_block_investigation_anatomy,
)
from threatfusion.advisory.telemetry_shield import (
    draft_detection_rule,
    mcp_action_is_forbidden,
    reset_burst_deduplicator,
    verify_advisory_against_ledger,
)
from threatfusion.alerts.correlation_engine import EntityProvenanceContract
from threatfusion.api.live_soc_console import (
    _ATTACK_PROFILE_CANONICAL,
    _BENIGN_ROW1_CANONICAL,
    _BENIGN_WEB_CANONICAL,
    _ae_input_vector,
    _lock_demo_passwords_for_production,
    _refuse_soar_role,
    _score_autoencoder,
    answer_mitre_copilot,
    approve_live_soar,
    build_alert_fatigue_compression_funnel,
    build_forensic_scope,
    canonical_from_dnn_features,
    enroll_lab_operator,
    launch_range_vector,
    persist_scored_flow,
    rbac_login,
    rbac_register,
    read_advisory_trace,
    register_operator,
    score_canonical_flow,
    validate_thehive_case_id,
    verify_entra_token,
)
from threatfusion.correlation.incident_correlation import build_operational_velocity_report
from threatfusion.datasets.adapters.suricata_flow import SuricataFlowAdapter
from threatfusion.models.drift_and_supply_chain import (
    CANONICAL_14_FEATURES,
    DEFAULT_BASELINE_MEANS,
    TelemetryDriftError,
    evaluate_14_feature_telemetry_drift,
)
from threatfusion.models.multi_signal_risk import rank_rf_alerts_for_triage_queue
from threatfusion.operations.cloud_live_telemetry import evaluate_budget_kill_switch
from threatfusion.operations.commercial_hardening import (
    apply_posture_to_index,
    isolation_refusal_reason,
    reset_login_rate_limiter,
)
from threatfusion.api.analyst_tls_service import ANALYST_URI_PREFIX
from threatfusion.operations.human_credentials import (
    active_fingerprint,
    init as enroll_cert_policy,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


class _Width14Model:
    n_features_in_ = 14

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        return [[0.15, 0.85]]


def _canonical_ones() -> dict[str, float]:
    return {name: 1.0 for name in CANONICAL_14_FEATURES}


def _jwt_segment(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _forged_jwt(claims: dict[str, object]) -> str:
    return ".".join(
        (
            _jwt_segment({"alg": "RS256", "typ": "JWT"}),
            _jwt_segment(claims),
            _jwt_segment({"sig": "forged"}),
        )
    )


def _generate_ephemeral_mtls_bundle(cert_dir: Path) -> dict[str, Path]:
    """Generate ephemeral CA, server cert, enrolled client cert, and rogue client cert."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_key = cert_dir / "ca.key"
    ca_crt = cert_dir / "ca.crt"
    srv_key = cert_dir / "server.key"
    srv_csr = cert_dir / "server.csr"
    srv_crt = cert_dir / "server.crt"
    srv_ext = cert_dir / "server.ext"
    cli_key = cert_dir / "client.key"
    cli_csr = cert_dir / "client.csr"
    cli_crt = cert_dir / "client.crt"
    rogue_key = cert_dir / "rogue.key"
    rogue_csr = cert_dir / "rogue.csr"
    rogue_crt = cert_dir / "rogue.crt"

    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_crt),
            "-days",
            "1",
            "-subj",
            "/CN=ThreatFusion-Test-CA",
        ],
        check=True,
        capture_output=True,
    )
    srv_ext.write_text("subjectAltName=IP:127.0.0.1,DNS:localhost\n", encoding="utf-8")
    subprocess.run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(srv_key),
            "-out",
            str(srv_csr),
            "-subj",
            "/CN=127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(srv_csr),
            "-CA",
            str(ca_crt),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(srv_crt),
            "-days",
            "1",
            "-extfile",
            str(srv_ext),
        ],
        check=True,
        capture_output=True,
    )
    for key_p, csr_p, crt_p, cn in (
        (cli_key, cli_csr, cli_crt, "lab_operator"),
        (rogue_key, rogue_csr, rogue_crt, "rogue_operator"),
    ):
        ext_p = cert_dir / f"{cn}.ext"
        ext_p.write_text(
            f"basicConstraints=CA:FALSE\n"
            f"extendedKeyUsage=clientAuth\n"
            f"subjectAltName=URI:{ANALYST_URI_PREFIX}{cn}\n",
            encoding="utf-8",
        )
        subprocess.run(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key_p),
                "-out",
                str(csr_p),
                "-subj",
                f"/CN={cn}",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr_p),
                "-CA",
                str(ca_crt),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(crt_p),
                "-days",
                "1",
                "-extfile",
                str(ext_p),
            ],
            check=True,
            capture_output=True,
        )
    return {
        "ca_crt": ca_crt,
        "srv_key": srv_key,
        "srv_crt": srv_crt,
        "cli_key": cli_key,
        "cli_crt": cli_crt,
        "rogue_key": rogue_key,
        "rogue_crt": rogue_crt,
    }


# --- C1: Z-score preprocessing in score_canonical_flow & fail-closed scaler ---


def test_c1_score_canonical_flow_zscores_and_fails_closed(tmp_path: Path) -> None:
    """C1: Frozen RF must receive SHA-256-verified Z-scored features and fail closed if absent."""
    # 1. Fails closed when preprocessor_state.json is missing in repo_root
    withheld = score_canonical_flow(
        _canonical_ones(),
        repo_root=tmp_path,
        model=_Width14Model(),
        supply_verified=True,
    )
    assert withheld["decision"] == "withheld"
    assert withheld["reason"] == "preprocessor_state_unverified"
    assert withheld["evidence_state"] == "unavailable"

    # 2. All 4 attack vectors score Attack and both benign profiles score Benign
    for vec_id, vec in _ATTACK_PROFILE_CANONICAL.items():
        scored = score_canonical_flow(vec, repo_root=REPO_ROOT)
        assert scored["decision"] == "Attack", (vec_id, scored)
        assert float(scored["rf_attack_probability"]) >= 0.50
    for benign in (_BENIGN_ROW1_CANONICAL, _BENIGN_WEB_CANONICAL):
        scored = score_canonical_flow(benign, repo_root=REPO_ROOT)
        assert scored["decision"] == "Benign", scored
        assert float(scored["rf_attack_probability"]) < 0.50

    # 3. Verify high recall (>90%) on real UNSW-NB15_1 attack sample and 0% FP on benign sample
    raw_csv = REPO_ROOT / "data/raw/unsw_nb15/official/UNSW-NB15_1.csv"
    if raw_csv.is_file():
        attack_hits = 0
        attack_total = 0
        benign_fp = 0
        benign_total = 0
        with raw_csv.open("r", encoding="utf-8", errors="ignore") as handle:
            for row in csv.reader(handle):
                if len(row) < 49:
                    continue
                lbl = row[48].strip()
                if lbl == "1" and attack_total >= 40:
                    continue
                if lbl == "0" and benign_total >= 40:
                    continue
                try:
                    proto = row[4].strip().lower()
                    dur = float(row[6] or 0.0)
                    sbytes = float(row[7] or 0.0)
                    dbytes = float(row[8] or 0.0)
                    spkts = float(row[16] or 0.0)
                    dpkts = float(row[17] or 0.0)
                    dport = float(int(row[3], 0)) if row[3].strip() else 0.0
                except ValueError:
                    continue
                tot_pkts = spkts + dpkts
                tot_bytes = sbytes + dbytes
                vec = {
                    "duration_ms": dur * 1000.0,
                    "fwd_packets": spkts,
                    "bwd_packets": dpkts,
                    "fwd_bytes": sbytes,
                    "bwd_bytes": dbytes,
                    "packets_per_second": tot_pkts / dur if dur > 0 else 0.0,
                    "bytes_per_second": tot_bytes / dur if dur > 0 else 0.0,
                    "fwd_packet_length_mean": sbytes / spkts if spkts > 0 else 0.0,
                    "bwd_packet_length_mean": dbytes / dpkts if dpkts > 0 else 0.0,
                    "dst_port": dport,
                    "protocol_tcp": 1.0 if proto == "tcp" else 0.0,
                    "protocol_udp": 1.0 if proto == "udp" else 0.0,
                    "protocol_icmp": 1.0 if proto == "icmp" else 0.0,
                    "protocol_other": 0.0 if proto in {"tcp", "udp", "icmp"} else 1.0,
                }
                res = score_canonical_flow(vec, repo_root=REPO_ROOT)
                if lbl == "1":
                    attack_total += 1
                    if res["decision"] == "Attack":
                        attack_hits += 1
                elif lbl == "0":
                    benign_total += 1
                    if res["decision"] == "Attack":
                        benign_fp += 1
                if attack_total >= 40 and benign_total >= 40:
                    break
        assert attack_total >= 20
        assert (attack_hits / attack_total) >= 0.90, f"recall={attack_hits}/{attack_total}"
        assert benign_fp == 0, f"benign_fp={benign_fp}/{benign_total}"


# --- C2: Forged Entra JWT, production registration, and Entra rate limiting ---


def test_c2_entra_forged_jwt_and_production_register_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reset_login_rate_limiter()
    live_db = tmp_path / "live.sqlite3"
    forged = _forged_jwt(
        {
            "tid": "00000000-0000-0000-0000-000000000001",
            "oid": "8f3c1a20-6b4e-4d11-9c2a-71e0b5d4a101",
            "upn": "muhammad.bilal@nu.edu.pk",
            "roles": ["SOC.Commander.Approver"],
            "exp": int(time.time()) + 3600,
        }
    )
    # 1. Forged unsigned JWT cannot mint an RBAC session even in lab mode
    denied = rbac_login(live_db, entra_token=forged, client_ip="203.0.113.10")
    assert denied["http_status"] == 401
    assert denied["authenticated"] is False

    # 2. Expired JWT rejected by verify_entra_token
    expired = _forged_jwt(
        {
            "tid": "00000000-0000-0000-0000-000000000001",
            "oid": "4c2e9b11-1a77-4e08-8d55-22b6c0e8f202",
            "upn": "suhaib.shaikh@nu.edu.pk",
            "roles": ["SOC.Analyst.Tier1"],
            "exp": int(time.time()) - 10,
        }
    )
    exp_res = verify_entra_token(live_db, expired)
    assert exp_res["http_status"] == 401
    assert exp_res["reason"] == "entra_token_expired"

    # 3. Self-assigning soc_approver via rbac_register refused even in lab mode
    self_approver = rbac_register(
        live_db,
        username="evil.approver@example.com",
        access_code="VeryStrongPass1!",
        display_name="Evil Approver",
        role="soc_approver",
    )
    assert self_approver["http_status"] == 403
    assert self_approver["authenticated"] is False

    # 4. Production mode refuses unsigned Entra parsing and unauthenticated registration
    monkeypatch.setenv("THREATFUSION_ENV", "production")
    monkeypatch.setenv("THREATFUSION_DATA_DIR", str(tmp_path / "prod"))
    monkeypatch.setenv("TF_ADMIN_SECRET", "Prod-Admin-Secret-2026!")
    prod_entra = verify_entra_token(live_db, forged)
    assert prod_entra["http_status"] == 401
    assert prod_entra["reason"] == "entra_jwks_verification_required"

    prod_reg = rbac_register(
        live_db,
        username="unauth.user@example.com",
        access_code="VeryStrongPass1!",
        display_name="Unauth User",
        role="tier1_triage",
    )
    assert prod_reg["http_status"] == 403
    assert prod_reg["reason"] == "admin_session_required"

    prod_op = register_operator(
        live_db,
        actor_id="unauth_op",
        display_name="Unauth Op",
        role="tier1_triage",
    )
    assert prod_op["http_status"] == 403
    assert prod_op["reason"] == "admin_session_required"

    # 5. Authenticated production admin CAN register a new operator
    admin = rbac_login(
        live_db,
        username="muhammad.bilal@nu.edu.pk",
        access_code="Prod-Admin-Secret-2026!",
    )
    assert admin["authenticated"] is True
    created = rbac_register(
        live_db,
        username="approved.analyst@example.com",
        access_code="VeryStrongPass1!",
        display_name="Approved Analyst",
        role="tier1_triage",
        session_token=str(admin["session_token"]),
    )
    assert created["authenticated"] is True


def test_c2_entra_login_is_rate_limited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reset_login_rate_limiter()
    live_db = tmp_path / "live.sqlite3"
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(live_db))
    monkeypatch.setenv("THREATFUSION_ENV", "lab")
    server = ThreatFusionThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    forged = _forged_jwt(
        {
            "tid": "00000000-0000-0000-0000-000000000001",
            "oid": "8f3c1a20-6b4e-4d11-9c2a-71e0b5d4a101",
            "upn": "muhammad.bilal@nu.edu.pk",
            "roles": ["SOC.Commander.Approver"],
        }
    )
    try:
        statuses: list[int] = []
        for _ in range(6):
            req = urllib.request.Request(
                f"http://{host}:{port}/api/rbac/login",
                data=json.dumps({"entra_token": forged}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatFusion-Test-Client": "in-process",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=5)
                statuses.append(200)
            except urllib.error.HTTPError as exc:
                statuses.append(exc.code)
        assert statuses[:5] == [401, 401, 401, 401, 401]
        assert statuses[5] == 429
    finally:
        server.shutdown()
        server.server_close()
        reset_login_rate_limiter()


# --- C3: Tampered SOAR chain fails closed on approve (no silent reseal) ---


def test_c3_tampered_soar_chain_fails_closed_on_approve(tmp_path: Path) -> None:
    live_db = tmp_path / "live.sqlite3"
    soar_db = tmp_path / "soar.sqlite3"
    policy = tmp_path / "operator-policy"
    assert enroll_lab_operator(policy, "lab_operator")["identity_verified"] is True
    fp = active_fingerprint(policy, "lab_operator")
    assert fp

    scored = score_canonical_flow(
        _canonical_ones(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
    )
    f1 = int(persist_scored_flow(live_db, _canonical_ones(), scored)["flow_id"])
    f2 = int(persist_scored_flow(live_db, _canonical_ones(), scored)["flow_id"])

    first = approve_live_soar(
        live_db,
        soar_db,
        flow_id=f1,
        actor_id="lab_operator",
        reason="Valid initial approval.",
        policy_dir=policy,
        presented_fingerprint=fp,
    )
    assert first["http_status"] == 200
    assert first["execution_authorized"] is True

    # Tamper ledger directly
    with sqlite3.connect(soar_db) as conn:
        conn.execute("DROP TRIGGER IF EXISTS soar_audit_events_append_only_update")
        conn.execute("UPDATE soar_audit_events SET reason = 'TAMPERED_BY_ATTACKER' WHERE rowid = 1")
        conn.commit()

    second = approve_live_soar(
        live_db,
        soar_db,
        flow_id=f2,
        actor_id="lab_operator",
        reason="Follow-up approval must refuse tampered chain.",
        policy_dir=policy,
        presented_fingerprint=fp,
    )
    assert second["http_status"] == 409
    assert second["reason"] == "audit_chain_tampered"
    assert second["execution_authorized"] is False
    assert second["evidence_state"] == "unavailable"


# --- C4: Real TLS/mTLS peer cert verification + header spoofing ignored ---


def test_c4_mtls_peer_cert_enforced_and_headers_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. http_client_certificate_fingerprint ignores all HTTP headers
    assert (
        http_client_certificate_fingerprint(
            {
                "X-SSL-Client-Cert": "deadbeef",
                "X-Client-Cert-SHA256": "aa" * 32,
                "X-Forwarded-Client-Cert": "Hash=" + "bb" * 32,
            }
        )
        == ""
    )

    bundle = _generate_ephemeral_mtls_bundle(tmp_path / "certs")
    live_db = tmp_path / "live.sqlite3"
    soar_db = tmp_path / "soar.sqlite3"
    policy = tmp_path / "operator-policy"
    policy.mkdir(parents=True, exist_ok=True)
    policy.chmod(0o700)
    tmp_path.chmod(0o700)

    # Enroll the real X.509 client certificate for lab_operator via human_credentials.init
    der_bytes = subprocess.run(
        ["openssl", "x509", "-in", str(bundle["cli_crt"]), "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    client_fp = hashlib.sha256(der_bytes).hexdigest()
    enrolled_fp = enroll_cert_policy(policy, bundle["cli_crt"], bundle["ca_crt"], "lab_operator")
    assert enrolled_fp == client_fp

    scored = score_canonical_flow(
        _canonical_ones(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
    )
    flow_id = int(persist_scored_flow(live_db, _canonical_ones(), scored)["flow_id"])

    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(live_db))
    monkeypatch.setenv("THREATFUSION_OPERATOR_POLICY_DIR", str(policy))
    monkeypatch.setenv("THREATFUSION_SOAR_HMAC_SECRET", "lab-hmac-secret-012345")
    prev_soar = MispAndCallbackContractHandler.soar_db_path
    MispAndCallbackContractHandler.soar_db_path = str(soar_db)

    # A. Plain HTTP + spoofed header must return 403
    plain_srv = ThreatFusionThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    plain_thread = threading.Thread(target=plain_srv.serve_forever, daemon=True)
    plain_thread.start()
    try:
        p_host, p_port = plain_srv.server_address
        req = urllib.request.Request(
            f"http://{p_host}:{p_port}/api/v1/live/soar/approve",
            data=json.dumps(
                {
                    "flow_id": flow_id,
                    "actor_id": "lab_operator",
                    "reason": "Spoofed header attempt",
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-ThreatFusion-Test-Client": "in-process",
                "X-Client-Cert-SHA256": client_fp,
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 403
    finally:
        plain_srv.shutdown()
        plain_srv.server_close()

    # B. Real TLS/mTLS server
    tls_srv = ThreatFusionThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    configure_server_tls(
        tls_srv,
        str(bundle["srv_crt"]),
        str(bundle["srv_key"]),
        str(bundle["ca_crt"]),
    )
    assert tls_srv.tls_enabled is True
    tls_thread = threading.Thread(target=tls_srv.serve_forever, daemon=True)
    tls_thread.start()
    try:
        t_host, t_port = tls_srv.server_address
        base = f"https://{t_host}:{t_port}"

        def _https_post(
            path: str, payload: dict[str, object], cert: tuple[Path, Path] | None
        ) -> tuple[int, dict[str, object]]:
            ctx = ssl.create_default_context(cafile=str(bundle["ca_crt"]))
            if cert is not None:
                ctx.load_cert_chain(certfile=str(cert[0]), keyfile=str(cert[1]))
            req = urllib.request.Request(
                f"{base}{path}",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatFusion-Test-Client": "in-process",
                    "Origin": base,
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    return resp.status, json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode("utf-8"))

        # B1: HTTPS without client cert -> 403
        st_no, body_no = _https_post(
            "/api/v1/live/soar/approve",
            {"flow_id": flow_id, "actor_id": "lab_operator", "reason": "No client cert"},
            None,
        )
        assert st_no == 403
        assert body_no["execution_authorized"] is False

        # B2: HTTPS with rogue (unenrolled) CA-signed cert -> 403 actor_identity_mismatch
        st_rogue, body_rogue = _https_post(
            "/api/v1/live/soar/approve",
            {"flow_id": flow_id, "actor_id": "lab_operator", "reason": "Rogue cert"},
            (bundle["rogue_crt"], bundle["rogue_key"]),
        )
        assert st_rogue == 403
        assert body_rogue.get("error") == "actor_identity_mismatch"

        # B3: HTTPS with enrolled client cert -> 200 approved & stamp verified
        ctx_valid = ssl.create_default_context(cafile=str(bundle["ca_crt"]))
        ctx_valid.load_cert_chain(certfile=str(bundle["cli_crt"]), keyfile=str(bundle["cli_key"]))
        with urllib.request.urlopen(
            f"{base}/api/v1/live/operator/stamp", timeout=5, context=ctx_valid
        ) as stamp_resp:
            stamp_body = json.loads(stamp_resp.read().decode("utf-8"))
        assert stamp_body["identity_verified"] is True

        st_ok, body_ok = _https_post(
            "/api/v1/live/soar/approve",
            {"flow_id": flow_id, "actor_id": "lab_operator", "reason": "Valid mTLS approval"},
            (bundle["cli_crt"], bundle["cli_key"]),
        )
        assert st_ok == 200, body_ok
        assert body_ok["execution_authorized"] is True
        assert body_ok["identity_verified"] is True
    finally:
        MispAndCallbackContractHandler.soar_db_path = prev_soar
        tls_srv.shutdown()
        tls_srv.server_close()


# --- H1: Real IPs & technique stay grounded in copilot ledger verification ---


def test_h1_real_ips_stay_grounded_in_copilot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GEMINI_ENABLED", "false")
    live_db = tmp_path / "live.sqlite3"
    rag_db = tmp_path / "rag.sqlite3"
    scored = score_canonical_flow(
        _canonical_ones(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
    )
    stored = persist_scored_flow(
        live_db,
        _canonical_ones(),
        scored,
        source_label="suricata_eve_bridge",
        case_title="Network Service Discovery scenario label T1046",
        provenance={
            "entity_namespace_id": "lab:range",
            "src_entity_id": "172.29.0.10",
            "dst_entity_id": "172.29.0.20",
            "protocol": "tcp",
            "service_or_port": "445",
            "clock_synchronized": True,
        },
    )
    answer = answer_mitre_copilot(
        live_db,
        "Analyze T1046 scan from 172.29.0.10 to 172.29.0.20 on port 445",
        int(stored["flow_id"]),
        rag_db,
    )
    ledger = answer.get("ledger_verification") or {}
    assert "172.29.0.10" not in (ledger.get("ungrounded_indicators") or [])
    assert "172.29.0.20" not in (ledger.get("ungrounded_indicators") or [])
    assert "172.29.0.10" in (ledger.get("verified_indicators") or [])


# --- H2: Linear alert-fatigue funnel math (no N^2 burst inflation) ---


def test_h2_alert_fatigue_funnel_is_linear_not_quadratic(tmp_path: Path) -> None:
    reset_burst_deduplicator()
    live_db = tmp_path / "live.sqlite3"
    scored = score_canonical_flow(
        _canonical_ones(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
    )
    prov = {
        "entity_namespace_id": "lab:range",
        "src_entity_id": "172.29.0.10",
        "dst_entity_id": "172.29.0.20",
        "protocol": "tcp",
        "service_or_port": "445",
        "clock_synchronized": True,
    }
    for _ in range(10):
        persist_scored_flow(
            live_db, _canonical_ones(), scored, provenance=prov, case_title="T1046 burst"
        )
    funnel = build_alert_fatigue_compression_funnel(live_db)
    assert funnel["raw_telemetry_events"] == 10
    assert funnel["simhash_deduplicated_clusters"] == 1
    assert funnel["high_confidence_incidents"] == 1
    assert funnel["noise_reduction_pct"] == 90.0


# --- H3: Explicit SOAR role allowlist + authenticated mutating routes + Origin port ---


def test_h3_soar_allowlist_and_mutating_routes_require_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live_db = tmp_path / "live.sqlite3"
    # Unregistered / empty / tier1 actors must ALL be refused by allowlist
    for actor in ("", "ghost_attacker", "tier1_analyst", "compliance_auditor"):
        refused = _refuse_soar_role(live_db, actor)
        assert refused is not None
        assert refused["http_status"] == 403
        assert refused["reason"] == "role_insufficient_for_soar"
    assert _refuse_soar_role(live_db, "lab_operator") is None

    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(live_db))
    monkeypatch.setenv("THREATFUSION_ENV", "lab")
    srv = ThreatFusionThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host, port = srv.server_address
    try:
        # Unauthenticated POST to /api/soar/isolate and /api/range/launch -> 401
        for route, body in (
            ("/api/soar/isolate", {"flow_id": 1}),
            ("/api/range/launch", {"vector_id": "T1046"}),
            ("/api/v1/live/soar/dispatch", {"flow_id": 1}),
        ):
            req = urllib.request.Request(
                f"http://{host}:{port}{route}",
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatFusion-Test-Client": "in-process",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(req, timeout=5)
            assert exc.value.code == 401, route

        # Origin without explicit port on non-80 listener must be rejected (403)
        req_origin = urllib.request.Request(
            f"http://{host}:{port}/api/v1/live/verdict",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Origin": "http://127.0.0.1",
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_orig:
            urllib.request.urlopen(req_origin, timeout=5)
        assert exc_orig.value.code == 403
    finally:
        srv.shutdown()
        srv.server_close()


# --- H4 & H5: AE labels match canonical 14, DNN imputation metadata & bits/bytes ---


def test_h4_h5_ae_labels_dnn_imputation_and_bytes_per_second(tmp_path: Path) -> None:
    live_db = tmp_path / "live.sqlite3"
    launched = launch_range_vector(
        live_db,
        vector_id="T1046",
        src_ip="172.29.0.10",
        dst_ip="172.29.0.20",
        repo_root=REPO_ROOT,
    )
    labels = {row["feature"] for row in launched["feature_error_breakdown"]}
    assert labels == set(CANONICAL_14_FEATURES)

    # Canonical-only scoring must surface 8 imputed DNN features explicitly
    scored_canon = score_canonical_flow(_ATTACK_PROFILE_CANONICAL["T1046"], repo_root=REPO_ROOT)
    assert scored_canon["imputed_feature_count"] == 8
    assert len(scored_canon["imputed_features"]) == 8

    # canonical_from_dnn_features converts bits/s (sload+dload) to bytes/s (/ 8.0)
    mapped = canonical_from_dnn_features(
        {
            "dur": 1.0,
            "spkts": 10.0,
            "dpkts": 5.0,
            "sbytes": 1000.0,
            "dbytes": 500.0,
            "rate": 15.0,
            "sload": 8000.0,
            "dload": 4000.0,
        }
    )
    assert mapped["bytes_per_second"] == pytest.approx(1500.0)


# --- H6: Production password lock caches per DB + secret ---


def test_h6_production_lock_is_cached_across_connects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("THREATFUSION_ENV", "production")
    monkeypatch.setenv("THREATFUSION_DATA_DIR", str(tmp_path / "prod"))
    monkeypatch.setenv("TF_ADMIN_SECRET", "Prod-Cache-Secret-2026!")
    live_db = tmp_path / "live.sqlite3"
    # First login initializes DB and caches hash + DB lock
    res = rbac_login(
        live_db,
        username="muhammad.bilal@nu.edu.pk",
        access_code="Prod-Cache-Secret-2026!",
    )
    assert res["authenticated"] is True
    # Subsequent 20 lock calls must complete well under 0.25s (not 20x200k PBKDF2!)
    t0 = time.monotonic()
    with sqlite3.connect(live_db) as conn:
        for _ in range(20):
            _lock_demo_passwords_for_production(conn)
    elapsed = time.monotonic() - t0
    assert elapsed < 0.25, f"production lock took {elapsed:.3f}s"


# --- H7: Boundary-aware ledger verification & rule drafting sanitization ---


def test_h7_ledger_verification_boundary_and_rule_sanitization() -> None:
    res = verify_advisory_against_ledger(
        "Host 10.0.0.80 connected on port 80 and port 8080.",
        {"src_ip": "10.0.0.80", "dst_ip": "10.0.0.5", "dst_port": 443},
        [],
    )
    assert res["status"] == "FLAGGED_UNGROUNDED"
    annotated = str(res["annotated_summary"])
    # 10.0.0.80 must NOT be mangled by ungrounded port 80!
    assert "10.0.0.80 " in annotated
    assert "10.0.0.80 [UNGROUNDED" not in annotated
    assert "80 [UNGROUNDED" in annotated

    draft = draft_detection_rule(
        query='evil"; sid:1; \nmalicious: true',
        flow_record={"technique_id": 'T1046"; drop;\nbad', "proto": "tcp", "dst_port": 445},
    )
    assert draft["grounding"]["technique_id"] == "T1046"
    assert "\n" not in draft["suricata"]
    assert "drop;" not in draft["suricata"]
    assert "drop;" not in draft["spl"]
    assert "drop;" not in draft["yara_l"]


# --- H8: Server-side thehive_case_id validation & frontend escaping ---


def test_h8_thehive_case_id_validation_and_xss_escape(tmp_path: Path) -> None:
    assert validate_thehive_case_id("case_12345_abc-9") == "case_12345_abc-9"
    for bad in ("case_<img src=x onerror=alert(1)>", "bad_prefix", "case_live_flow:1"):
        with pytest.raises(ValueError, match="invalid_thehive_case_id"):
            validate_thehive_case_id(bad)
    js_text = (REPO_ROOT / "frontend/js/soc_dashboard.js").read_text(encoding="utf-8")
    assert "${escapeHtml(hiveLabel)}" in js_text
    assert "${hiveLabel}" not in js_text


# --- H9: Cloud scripts hardening ---


def test_h9_cloud_scripts_env_and_ssh_hardening() -> None:
    azure = (REPO_ROOT / "scripts/deploy_azure_cyber_range.sh").read_text(encoding="utf-8")
    cloud = (REPO_ROOT / "scripts/deploy_cloud_range.sh").read_text(encoding="utf-8")
    assert "THREATFUSION_SENSOR_INGEST_TOKEN" in azure
    assert "StrictHostKeyChecking=no" not in cloud
    assert "StrictHostKeyChecking=accept-new" in cloud
    assert "threatfusion-live-console.sqlite3" in cloud
    assert "shlex.quote" in cloud
    assert '"Deleting"' in cloud


# --- M1-M7 & L2-L3 polish ---


def test_m1_to_m7_and_l2_polish(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # M1: Only copyTextBlock invokes navigator.clipboard.writeText(
    js_text = (REPO_ROOT / "frontend/js/soc_dashboard.js").read_text(encoding="utf-8")
    assert js_text.count("navigator.clipboard.writeText(") == 1

    # M2: Drift rejects bools and aligns to preprocessor_state.json
    assert DEFAULT_BASELINE_MEANS["duration_ms"] == pytest.approx(674.7873430327663)
    bad_rec = dict(DEFAULT_BASELINE_MEANS)
    bad_rec["protocol_tcp"] = True  # type: ignore[assignment]
    with pytest.raises(TelemetryDriftError):
        evaluate_14_feature_telemetry_drift([bad_rec])

    # M3: AE fails closed when preprocessor_state.json is absent
    assert _ae_input_vector([0.0] * 14, tmp_path) is None
    ae_empty = _score_autoencoder([0.0] * 14, tmp_path)
    assert ae_empty["ae_loss"] is None

    # M4: NaN/bool rejected in triage ranker and budget kill-switch
    ranked = rank_rf_alerts_for_triage_queue(
        [
            {"candidate_id": "nan_alert", "rf_attack_probability": float("nan")},
            {"candidate_id": "bool_alert", "rf_attack_probability": True},
            {"candidate_id": "real_alert", "rf_attack_probability": 0.91},
        ]
    )
    assert [r["candidate_id"] for r in ranked] == ["real_alert"]
    ks = evaluate_budget_kill_switch(False)  # type: ignore[arg-type]
    assert ks["kill_switch_triggered"] is True
    assert ks["status"] == "triggered_fail_closed"

    # M5: Benign excluded from build_forensic_scope; empty narrative -> UNAVAILABLE; velocity label aligned
    scope = build_forensic_scope(
        [
            {
                "flow_id": 1,
                "decision": "Benign",
                "src_entity_id": "10.0.0.99",
                "dst_entity_id": "10.0.0.100",
            },
            {
                "flow_id": 2,
                "decision": "Attack",
                "src_entity_id": "172.29.0.10",
                "dst_entity_id": "172.29.0.20",
            },
        ]
    )
    assert scope["patient_zero"]["host_ip"] == "172.29.0.10"
    assert "10.0.0.99" not in scope["decomposed_cti"]["operational_iocs"]["ips"]

    live_db = tmp_path / "live_trace.sqlite3"
    scored = score_canonical_flow(
        _canonical_ones(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
    )
    fid = int(persist_scored_flow(live_db, _canonical_ones(), scored)["flow_id"])
    trace = read_advisory_trace(live_db, fid)
    assert trace["ledger_verification"]["status"] == "UNAVAILABLE"

    vel = build_operational_velocity_report(
        incident_timings=[],
        response_timings=[],
        strict_measured_only=True,
    )
    vd = vel.velocity_decomposition
    assert vd["measurement_label"] == vd["telemetry_source"]

    anatomy = build_four_block_investigation_anatomy(
        AdvisoryEvidenceBundle(
            candidate_id="c1",
            record_id="r1",
            rf_model_version="v1",
            rf_attack_probability=0.9,
            rf_threshold=0.5,
            top_feature_signals={},
        )
    )
    assert anatomy.block_4_cryptographic_soar_status.playbook_id == "unavailable"
    assert anatomy.block_4_cryptographic_soar_status.entry_sha256 == ""

    # M6: Production HTML strips demo codes
    monkeypatch.setenv("THREATFUSION_ENV", "production")
    html_src = (REPO_ROOT / "frontend/index.html").read_text(encoding="utf-8")
    rendered = apply_posture_to_index(html_src)
    assert "TF-Bilal-3551!" not in rendered
    assert "TF-Suhaib-4302!" not in rendered

    # M7: /0 CIDR refused; ICMP flow without ports accepted; NaN/negative clock skew rejected
    assert isolation_refusal_reason("0.0.0.0/0") == "protected_infrastructure_ip"
    assert isolation_refusal_reason("172.29.0.10/0") == "protected_infrastructure_ip"
    assert isolation_refusal_reason("172.29.0.0/24") == "invalid_ip"

    adapter = SuricataFlowAdapter()
    icmp_res = adapter.adapt_eve_flow_record(
        {
            "event_type": "flow",
            "timestamp": "2026-11-20T00:00:00Z",
            "src_ip": "172.29.0.10",
            "dest_ip": "172.29.0.20",
            "proto": "ICMP",
            "flow": {
                "pkts_toserver": 4,
                "pkts_toclient": 4,
                "bytes_toserver": 336,
                "bytes_toclient": 336,
                "start": "2026-11-20T00:00:00Z",
                "end": "2026-11-20T00:00:01Z",
            },
        }
    )
    assert icmp_res.flow.dst_port == 0
    assert icmp_res.features_14["protocol_icmp"] == 1.0

    for bad_skew in (float("nan"), -1.0, float("inf")):
        c = EntityProvenanceContract(
            entity_namespace_id="ns",
            clock_synchronized=True,
            src_entity_id="172.29.0.10",
            dst_entity_id="172.29.0.20",
            max_clock_skew_seconds=bad_skew,
        )
        assert c.is_verified() is False

    # M7: n8n workflow references node display name, not raw node ID
    wf_text = (REPO_ROOT / "docker/n8n/workflows/threatfusion_soar_playbook.json").read_text(
        encoding="utf-8"
    )
    assert "$('node-1-webhook-trigger')" not in wf_text
    assert "$('1. Webhook Trigger (POST /webhook/threatfusion-soar-approved)')" in wf_text

    # L2: MCP word-boundary guard blocks forbidden verbs without false-blocking benign words
    assert mcp_action_is_forbidden("approve_containment") is True
    assert mcp_action_is_forbidden("executePlaybook") is True
    assert mcp_action_is_forbidden("contain_host") is True
    assert mcp_action_is_forbidden("container escape") is False
    assert mcp_action_is_forbidden("remote code execution") is False
