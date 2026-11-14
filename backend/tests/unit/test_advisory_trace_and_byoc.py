"""Advisory trace, frozen-authority locks, and provider-agnostic cloud binding."""

from __future__ import annotations

import json
import sqlite3
import stat
import subprocess
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from threatfusion.advisory.advisory_trace import (
    DISPLAY_ADJUSTED,
    MEASURED_RAW,
    build_advisory_trace,
    module_has_no_write_or_network_calls,
    read_cached_narratives,
)
from threatfusion.evaluation.repo_truth_audit import (
    GATE_G9_STAGE_1_TO_4_MODULES,
    verify_gate_g9_ast_import_graph,
)
from threatfusion.models.drift_and_supply_chain import FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY
from threatfusion.models.multi_signal_risk import evaluate_multi_signal_risk

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "backend" / "src"
_PERSONAL_CLOUD_IDS = (
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "7fb77266-5bb4-4d03-8a91-a744fd38db5c",
)
_FROZEN_DIGESTS = {
    "random_forest": "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
    "logistic_regression": "2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148",
    "autoencoder_v2": "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23",
    "rate_log1p_candidate": "1d02e5bba556cb28709bd0faefce5f29da424a419a2d95332ad27a8995b26f63",
}
_DNN_DIGEST = "614850ad84fc4ab32dc6e6d2318900668d97cad6edba37290ed9fe2b2482df1f"
_NARRATIVE = (
    "[1] EXECUTIVE TRIAGE\n"
    "[2] CORRELATED TELEMETRY\n"
    "[3] MITRE ATT&CK CVE-2024-0001\n"
    "[5] GOVERNED SOAR\n"
    "[E1] [E2] [E3] [E5]"
)


def _flow(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "flow_id": 7,
        "decision": "Attack",
        "rf_attack_probability": 0.91,
        "observed_at_utc": "2026-11-14T12:00:00+00:00",
        "production_fusion_enabled": 0,
        "ae_changes_alert_decision": False,
        "case_title": "T1190 public-facing probe",
        "canonical_features": {"duration_ms": 1.0},
        "ae_loss": 0.042,
        "dnn_class_distribution": {"Normal": 0.2, "Exploits": 0.8},
        "chroma_rag_hits": [
            {"technique_id": "T1190", "cosine_similarity": 0.91, "playbook_id": "pb-t1190"}
        ],
        "cve_ids": ["CVE-2024-0001"],
    }
    record.update(overrides)
    return record


def test_g9_compliance() -> None:
    passed, violations = verify_gate_g9_ast_import_graph(SRC)
    assert passed, violations
    for relative in GATE_G9_STAGE_1_TO_4_MODULES:
        text = (SRC / relative).read_text(encoding="utf-8")
        assert "advisory_trace" not in text
        assert "from threatfusion.advisory" not in text
    trace = build_advisory_trace(_flow(), narrative=_NARRATIVE)
    assert trace["authority"]["gate_g9"] == "PASS"


def test_rf_verdict_invariance() -> None:
    flow = _flow()
    original = flow["decision"]
    trace = build_advisory_trace(flow, narrative=_NARRATIVE)
    assert flow["decision"] == original == "Attack"
    authority = trace["authority"]
    assert authority["frozen_rf_verdict"] == "Attack"
    assert authority["frozen_rf_unchanged"] is True
    assert authority["decision_writes_by_advisory_components"] == 0
    assert authority["summary"] == (
        "Decision writes by advisory components: 0, "
        "Frozen RF verdict: Attack (unchanged), Gate G9: PASS"
    )
    assert "Decision writes: 0 · Frozen RF verdict: Attack (unchanged) · Gate G9: PASS" in (
        trace["authority_bar"]
    )


def test_frozen_digests_preserved() -> None:
    for key, digest in _FROZEN_DIGESTS.items():
        assert FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY[key]["expected_sha256"] == digest
    console = (SRC / "threatfusion/api/live_soc_console.py").read_text(encoding="utf-8")
    assert _DNN_DIGEST in console
    for digest in _FROZEN_DIGESTS.values():
        assert digest in (SRC / "threatfusion/models/drift_and_supply_chain.py").read_text(
            encoding="utf-8"
        )


def test_fusion_flag_locked() -> None:
    source = (SRC / "threatfusion/models/multi_signal_risk.py").read_text(encoding="utf-8")
    assert "production_fusion_enabled=False" in source.replace(" ", "")
    with pytest.raises(ValueError):
        evaluate_multi_signal_risk(production_fusion_enabled=True)
    engine = (SRC / "threatfusion/alerts/correlation_engine.py").read_text(encoding="utf-8")
    assert "production_fusion_enabled = True" not in engine


def test_read_only(tmp_path: Path) -> None:
    source = (SRC / "threatfusion/advisory/advisory_trace.py").read_text(encoding="utf-8")
    assert module_has_no_write_or_network_calls() is True
    for token in ("subprocess", "requests", "socket", "urlopen(", "INSERT ", "DELETE FROM"):
        assert token not in source
    database = tmp_path / "live.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("""
        CREATE TABLE live_copilot_cache (
            cache_key TEXT PRIMARY KEY,
            narrative TEXT,
            created_at_utc TEXT
        )
        """)
    connection.execute(
        "INSERT INTO live_copilot_cache VALUES (?, ?, ?)",
        ("7\nquestion\nlocal", "stored narrative", "2026-11-14T12:00:00+00:00"),
    )
    connection.commit()
    connection.close()
    loaded = read_cached_narratives(database)
    assert loaded[7]["narrative"] == "stored narrative"
    check = sqlite3.connect(database)
    row = check.execute("SELECT narrative FROM live_copilot_cache").fetchone()
    assert row is not None
    assert row[0] == "stored narrative"
    check.close()
    from threatfusion.api.live_soc_console import read_advisory_trace

    missing = read_advisory_trace(tmp_path / "absent.sqlite3", flow_id=4)
    assert missing["http_status"] == 404
    assert missing["decision_writes_by_advisory_components"] == 0
    server = (ROOT / "scripts/run_misp_and_callback_contract_server.py").read_text(encoding="utf-8")
    assert 'path == "/api/v1/live/advisory-trace"' in server


def test_display_adjusted_flagged() -> None:
    flow = _flow(ae_loss=None, ae_display_band="HIGH")
    trace = build_advisory_trace(flow, narrative=_NARRATIVE)
    autoencoder = next(
        item for item in trace["components"] if item["component_id"] == "v2_autoencoder_ranker"
    )
    assert autoencoder["actual_output"] == "HIGH"
    assert autoencoder["measurement_integrity"] == DISPLAY_ADJUSTED
    assert trace["completeness_badge"] == "PARTIAL"
    assert any(DISPLAY_ADJUSTED in gap for gap in trace["completeness_gaps"])


def test_completeness_badge() -> None:
    complete = build_advisory_trace(_flow(), narrative=_NARRATIVE)
    assert complete["completeness_badge"] == "COMPLETE"
    assert complete["completeness_gaps"] == []
    for item in complete["components"]:
        assert item["assigned_scope"]
        assert item["measurement_integrity"] == MEASURED_RAW
        assert item["evidence_ids_read"]
    pending = build_advisory_trace(_flow(), narrative=None)
    assert pending["completeness_badge"] == "PENDING ADVISORY"
    narrative = next(
        item
        for item in pending["components"]
        if item["component_id"] == "grounded_narrative_copilot"
    )
    assert narrative["actual_output"] is None
    partial = build_advisory_trace(_flow(ae_loss=None, canonical_features={}), narrative=_NARRATIVE)
    assert partial["completeness_badge"] == "PARTIAL"
    assert any("missing assigned_scope" in gap for gap in partial["completeness_gaps"])
    assert any("missing actual_output" in gap for gap in partial["completeness_gaps"])


def test_no_hardcoded_personal_cloud_ids() -> None:
    offenders: list[str] = []
    for base in (ROOT / "frontend", ROOT / "backend" / "src", ROOT / "scripts"):
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for needle in _PERSONAL_CLOUD_IDS:
                if needle in text:
                    offenders.append(f"{path}: {needle}")
    assert offenders == []
    cloud = (ROOT / "scripts/deploy_cloud_range.sh").read_text(encoding="utf-8")
    azure = (ROOT / "scripts/deploy_azure_cyber_range.sh").read_text(encoding="utf-8")
    assert "--provider" in cloud
    assert "--provision-range" in cloud
    assert "--deploy-full-stack" in cloud
    assert "--teardown" in cloud
    assert "deploy_cloud_range.sh" in azure
    assert "TF_AZURE_RANGE_IMPL" in azure


def test_cloud_status_reads_operator_state(tmp_path: Path) -> None:
    from threatfusion.api.live_soc_console import azure_portal_status, cloud_range_status

    path = tmp_path / "cloud_state.json"
    path.write_text(
        """
        {
          "provider": "generic",
          "account_id": "operator-account",
          "region": "lab",
          "resource_group": "generic-linux-hosts",
          "victim_public_ip": "203.0.113.20",
          "attacker_public_ip": "203.0.113.10",
          "victim_vm_ip": "172.29.0.20",
          "attacker_vm_ip": "172.29.0.10",
          "ssh_user": "ubuntu",
          "victim_state": "recorded",
          "attacker_state": "recorded",
          "cost_guardrail": "teardown returns spend to 0.00"
        }
        """,
        encoding="utf-8",
    )
    status = cloud_range_status(path)
    assert status["provider_label"] == "Generic"
    assert status["connected"] is True
    assert status["account_id"] == "operator-account"
    assert status["victim_host"]["public_ip"] == "203.0.113.20"
    assert status["ssh_user"] == "ubuntu"
    assert "72f988bf" not in str(status)
    azure = azure_portal_status(path)
    assert azure["terminal_snippet"] == "scripts/deploy_azure_cyber_range.sh --provision-live-azure"
    assert azure["connected"] is False


_MODEL_RELATIVE = (
    "artifacts/models/network_random_forest_baseline/"
    "full-network-random-forest-6d69c72-v1/random_forest.joblib",
    "artifacts/models/network_logistic_baseline/"
    "full-network-logistic-5e70ed9-v1/logistic_regression.joblib",
    "artifacts/models/network_autoencoder/"
    "full-benign-autoencoder-2a51c94-v2/autoencoder_state.pt",
    "artifacts/models/network_rate_log1p_autoencoder/"
    "rate-log1p-autoencoder-b5e6e5d-v1/autoencoder_state.pt",
    "artifacts/models/fyp2_dnn_same_split_v1/dnn_model.pt",
)


def _http_json(
    method: str,
    url: str,
    payload: dict[str, object] | None = None,
) -> tuple[int, dict[str, str], dict[str, object]]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"X-ThreatFusion-Test-Client": "in-process"}
    if data is not None:
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(data))
    req = urlrequest.Request(url, data=data, headers=headers, method=method)
    try:
        with urlrequest.urlopen(req, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
            return response.status, dict(response.headers), body
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        body = json.loads(raw) if raw else {}
        return exc.code, dict(exc.headers), body


def _listen(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    from scripts.run_misp_and_callback_contract_server import MispAndCallbackContractHandler

    monkeypatch.setenv("THREATFUSION_ENV", "lab")
    monkeypatch.setenv("THREATFUSION_DATA_DIR", str(db_path.parent))
    monkeypatch.setenv("THREATFUSION_LIVE_CONSOLE_DB", str(db_path))
    monkeypatch.delenv("SSH_CLIENT", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_production_mode_disables_demo_quickfill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("THREATFUSION_ENV", "production")
    monkeypatch.setenv("THREATFUSION_DATA_DIR", str(tmp_path / "prod-data"))
    from threatfusion.api.live_soc_console import rbac_login
    from threatfusion.operations.commercial_hardening import (
        apply_posture_to_index,
        console_posture,
    )

    posture = console_posture()
    assert posture["environment"] == "production"
    assert posture["posture_label"] == "POSTURE: PRODUCTION HARDENED"
    assert posture["demo_quickfill_enabled"] is False
    assert posture["demo_passwords_accepted"] is False
    page = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    rendered = apply_posture_to_index(page)
    assert 'id="demoQuickFill" class="demo-credential-box role-quick-grid" hidden' in rendered
    assert 'data-demo-code="TF-Bilal-3551!"' not in rendered
    refused = rbac_login(
        tmp_path / "live.sqlite3",
        username="bilal.21k3551@nu.edu.pk",
        access_code="TF-Bilal-3551!",
    )
    assert refused["http_status"] == 401
    assert refused["message"] == "Invalid credentials"
    assert refused["authenticated"] is False


def test_login_rate_limiting_429(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from threatfusion.operations.commercial_hardening import reset_login_rate_limiter

    reset_login_rate_limiter()
    server, _thread = _listen(tmp_path / "live.sqlite3", monkeypatch)
    host, port = server.server_address
    url = f"http://{host}:{port}/api/rbac/login"
    try:
        last_status = 0
        last_headers: dict[str, str] = {}
        for _attempt in range(6):
            last_status, last_headers, body = _http_json(
                "POST",
                url,
                {"username": "bilal.21k3551@nu.edu.pk", "access_code": "wrong-code"},
            )
        assert last_status == 429
        assert body["message"] == "Too Many Requests"
        assert body["reason"] == "login_rate_limited"
        assert int(last_headers.get("Retry-After") or last_headers.get("retry-after") or "0") >= 1
    finally:
        server.shutdown()
        reset_login_rate_limiter()


def test_uniform_invalid_credentials_no_enumeration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from threatfusion.operations.commercial_hardening import reset_login_rate_limiter

    reset_login_rate_limiter()
    server, _thread = _listen(tmp_path / "live.sqlite3", monkeypatch)
    host, port = server.server_address
    url = f"http://{host}:{port}/api/rbac/login"
    try:
        unknown_status, _headers, unknown = _http_json(
            "POST",
            url,
            {"username": "nobody@example.com", "access_code": "not-a-real-code"},
        )
        wrong_status, _headers, wrong = _http_json(
            "POST",
            url,
            {"username": "bilal.21k3551@nu.edu.pk", "access_code": "wrong-code"},
        )
    finally:
        server.shutdown()
        reset_login_rate_limiter()
    assert unknown_status == wrong_status == 401
    assert unknown == wrong
    assert unknown["message"] == "Invalid credentials"
    assert "username" not in unknown
    assert "not registered" not in json.dumps(unknown).lower()


def test_auth_events_audited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from threatfusion.api.live_soc_console import rbac_login, rbac_register
    from threatfusion.operations.commercial_hardening import reset_login_rate_limiter

    reset_login_rate_limiter()
    database = tmp_path / "live.sqlite3"
    monkeypatch.setenv("THREATFUSION_ENV", "lab")
    monkeypatch.setenv("THREATFUSION_DATA_DIR", str(tmp_path))
    refused = rbac_login(
        database,
        username="bilal.21k3551@nu.edu.pk",
        access_code="wrong-code",
        client_ip="203.0.113.8",
    )
    assert refused["http_status"] == 401
    signed_in = rbac_login(
        database,
        username="bilal.21k3551@nu.edu.pk",
        access_code="TF-Bilal-3551!",
        client_ip="203.0.113.8",
    )
    assert signed_in["authenticated"] is True
    created = rbac_register(
        database,
        username="new.analyst@example.com",
        access_code="analyst-code-1",
        display_name="New Analyst",
        role="tier1_triage",
    )
    assert created["authenticated"] is True
    server, _thread = _listen(database, monkeypatch)
    host, port = server.server_address
    try:
        for _attempt in range(6):
            _http_json(
                "POST",
                f"http://{host}:{port}/api/rbac/login",
                {"username": "rate.limit@example.com", "access_code": "wrong-code"},
            )
    finally:
        server.shutdown()
        reset_login_rate_limiter()
    connection = sqlite3.connect(database)
    events = {
        str(row[0]) for row in connection.execute("SELECT DISTINCT event_type FROM auth_audit_log")
    }
    connection.close()
    assert {
        "login_success",
        "login_failed",
        "login_rate_limited",
        "operator_registered",
    } <= events


def test_protected_allowlist_blocks_self_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from threatfusion.operations.commercial_hardening import (
        guard_isolation_source,
        reset_login_rate_limiter,
    )

    reset_login_rate_limiter()
    monkeypatch.setenv("SSH_CLIENT", "203.0.113.44 54000 22")
    for address in ("127.0.0.1", "::1", "169.254.10.10", "203.0.113.44"):
        guarded = guard_isolation_source(address)
        assert guarded is not None
        assert guarded["http_status"] == 400
        assert guarded["reason"] == "protected_infrastructure_ip"
    assert guard_isolation_source("172.29.0.10") is None
    server, _thread = _listen(tmp_path / "live.sqlite3", monkeypatch)
    monkeypatch.setenv("SSH_CLIENT", "203.0.113.44 54000 22")
    host, port = server.server_address
    try:
        status, _headers, body = _http_json(
            "POST",
            f"http://{host}:{port}/api/soar/isolate",
            {"src_ip": "127.0.0.1", "flow_id": 1},
        )
    finally:
        server.shutdown()
    assert status == 400
    assert body["reason"] == "protected_infrastructure_ip"
    console = (SRC / "threatfusion/api/live_soc_console.py").read_text(encoding="utf-8")
    server_text = (ROOT / "scripts/run_misp_and_callback_contract_server.py").read_text(
        encoding="utf-8"
    )
    assert "shell=True" not in console
    assert "shell=True" not in server_text


def test_invalid_ip_rejected_400(monkeypatch: pytest.MonkeyPatch) -> None:
    from threatfusion.operations.commercial_hardening import (
        assert_isolation_command_safe,
        guard_isolation_source,
    )

    monkeypatch.delenv("SSH_CLIENT", raising=False)
    for address in ("not-an-ip", "10.0.0.4; rm -rf /", "172.29.0.10 && id"):
        guarded = guard_isolation_source(address)
        assert guarded is not None
        assert guarded["http_status"] == 400
        assert guarded["reason"] == "invalid_ip"
        with pytest.raises(ValueError):
            assert_isolation_command_safe(address)
    assert assert_isolation_command_safe("172.29.0.10") == "172.29.0.10"


def test_security_headers_and_readyz(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from threatfusion.api.live_soc_console import build_compliance_dossier

    server, _thread = _listen(tmp_path / "live.sqlite3", monkeypatch)
    host, port = server.server_address
    try:
        status, headers, body = _http_json("GET", f"http://{host}:{port}/readyz")
    finally:
        server.shutdown()
    assert status == 200
    assert body["status"] == "ready"
    assert body["pill"] == "DB WAL · Models 4/4 · RAG Ready"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "http://" not in headers["Content-Security-Policy"]
    assert headers["Cache-Control"] == "no-store"
    dossier = build_compliance_dossier(tmp_path / "live.sqlite3", repo_root=ROOT)
    markdown = str(dossier["dossier_markdown"])
    assert "Advisory Trace (Decision writes: 0, Frozen RF authoritative, Gate G9: PASS)" in markdown
    assert "POSTURE: LAB DEMO" in markdown
    assert "DB WAL · Models 4/4 · RAG Ready" in markdown
    assert "TF-008, TF-009, TF-010, and TF-011 remain open." in markdown


def test_fresh_clone_zero_laptop_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from threatfusion.operations.commercial_hardening import prepare_cold_boot

    monkeypatch.delenv("THREATFUSION_SOAR_HMAC_SECRET", raising=False)
    report = prepare_cold_boot(tmp_path / "empty-data", ROOT)
    assert report["directory_mode"] == 0o700
    assert report["journal_mode"] == "wal"
    assert report["synchronous"] == 1
    assert report["busy_timeout"] == 5000
    assert "auth_audit_log_block_update" in report["triggers"]
    assert "auth_audit_log_block_delete" in report["triggers"]
    assert report["hmac_mode"] == 0o600
    assert report["chromadb_ready"] is True
    assert report["fixtures_verified"] is True
    assert report["models"]["ok"] is True
    assert Path(report["data_dir"]) == tmp_path / "empty-data"
    connection = sqlite3.connect(report["db_path"])
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("UPDATE auth_audit_log SET detail = 'tampered' WHERE event_id = 1")
        connection.commit()
    connection.close()
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", *_MODEL_RELATIVE],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert tracked.returncode == 0, tracked.stderr
    for relative in _MODEL_RELATIVE:
        assert (ROOT / relative).stat().st_size < 50 * 1024 * 1024
    fixture = ROOT / "artifacts/benchmarks/unsw_nb15_calibrated_runtime_fixtures.json"
    loaded = json.loads(fixture.read_text(encoding="utf-8"))
    assert loaded["held_out_rows"] == 507846
    assert loaded["requires_raw_csv"] is False
    assert stat.S_IMODE(Path(report["hmac_path"]).stat().st_mode) == 0o600


def test_no_hardcoded_personal_paths_or_cloud_ids() -> None:
    personal = "/home/" + "muhammad-bilal"
    offenders: list[str] = []
    suffixes = {".py", ".sh", ".js", ".html", ".css", ".yml", ".yaml"}
    for base in (ROOT / "backend" / "src", ROOT / "frontend", ROOT / "scripts"):
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in suffixes:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if personal in text:
                offenders.append(f"{path}: personal path")
            for needle in _PERSONAL_CLOUD_IDS:
                if needle in text:
                    offenders.append(f"{path}: {needle}")
    assert offenders == []
    index = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    assert "http://" not in index
    assert "https://" not in index
    cloud = (ROOT / "scripts" / "deploy_cloud_range.sh").read_text(encoding="utf-8")
    assert "ssh -N -L 8766:127.0.0.1:8766" in cloud
    assert "THREATFUSION_ENV=production" in cloud
    assert "--exclude .git" in cloud
    assert "/readyz" in cloud
    assert "tcp:8766" not in cloud
    assert "Port 8766 stays closed to 0.0.0.0/0" in cloud
    assert "Idle burn 0.00" in cloud
    demo = (ROOT / "scripts" / "run_full_range_demo.sh").read_text(encoding="utf-8")
    assert 'THREATFUSION_ENV="${THREATFUSION_ENV:-lab}"' in demo
