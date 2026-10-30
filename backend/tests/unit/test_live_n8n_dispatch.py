"""Live-console n8n dispatch. The Python path remains the fallback when no webhook is set."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from threatfusion.api.live_soc_console import (
    approve_live_soar,
    dispatch_approved_callback,
    persist_scored_flow,
    score_canonical_flow,
    store_flow_provenance,
)
from threatfusion.models.drift_and_supply_chain import CANONICAL_14_FEATURES

REPO_ROOT = Path(__file__).resolve().parents[3]
SECRET = "lab-hmac-secret-01"
MISP_KEY = "lab-only-misp-key-16xx"


def _features() -> dict[str, float]:
    return {name: 1.0 for name in CANONICAL_14_FEATURES}


class _Width14Model:
    n_features_in_ = 14

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        return [[0.2, 0.81]]


def _contract_server():
    spec = importlib.util.spec_from_file_location(
        "contract_server_n8n_dispatch",
        REPO_ROOT / "scripts" / "run_misp_and_callback_contract_server.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.MispAndCallbackContractHandler


def _signed_post(url: str, body: str, signature: str, key: str) -> tuple[int, dict]:
    request = urllib.request.Request(
        url,
        data=body.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-ThreatFusion-Signature-256": signature,
            "X-Idempotency-Key": key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read()
            return int(response.status), json.loads(raw.decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return int(exc.code), json.loads(raw.decode("utf-8") or "{}")


class _FakeN8n(BaseHTTPRequestHandler):
    """Posts the console's canonical bytes and records an HTTP 422 without skipping the callback."""

    calls = 0
    callback_posts = 0

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        envelope = json.loads(self.rfile.read(length).decode("utf-8"))
        type(self).calls += 1
        base = str(envelope["contract_base_url"]).rstrip("/")
        verify_status, verified = _signed_post(
            f"{base}/api/v1/soar/verify-state",
            str(envelope["verify_body"]),
            str(envelope["verify_signature"]),
            str(envelope["verify_idempotency_key"]),
        )
        state_verified = verify_status == 200 and verified.get("state_verified") is True
        misp_status = None
        private_guard = False
        if state_verified and envelope.get("target_value"):
            request = urllib.request.Request(
                f"{base}/attributes/restSearch",
                data=json.dumps(
                    {
                        "returnFormat": "json",
                        "value": envelope["target_value"],
                        "type": "ip-dst",
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": MISP_KEY,
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    misp_status = int(response.status)
            except urllib.error.HTTPError as exc:
                misp_status = int(exc.code)
            private_guard = misp_status == 422
        callback_status = 0
        recorded = False
        t_response = None
        if state_verified and envelope.get("callback_body"):
            type(self).callback_posts += 1
            callback_status, callback = _signed_post(
                f"{base}/api/v1/soar/callback",
                str(envelope["callback_body"]),
                str(envelope["callback_signature"]),
                str(envelope["callback_idempotency_key"]),
            )
            recorded = callback_status == 200 and callback.get("callback_recorded") is True
            if isinstance(callback.get("t_response"), (int, float)):
                t_response = callback["t_response"]
        payload = {
            "execution_path": "n8n_live_container",
            "verify_status": verify_status,
            "misp_status": misp_status,
            "private_ip_guard_triggered": private_guard,
            "callback_recorded": recorded,
            "callback_status": callback_status,
            "t_response": t_response,
        }
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def _stored_callback(live_db: Path, flow_id: int) -> sqlite3.Row:
    conn = sqlite3.connect(live_db)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT callback_recorded, callback_signature, execution_path FROM live_flows WHERE flow_id = ?",
        (flow_id,),
    ).fetchone()
    conn.close()
    assert row is not None
    return row


def _serve(handler) -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, int(server.server_address[1])


def _score(live_db: Path) -> int:
    stored = persist_scored_flow(
        live_db,
        _features(),
        score_canonical_flow(
            _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
        ),
    )
    return int(stored["flow_id"])


def test_live_workflow_file_uses_host_gateway_and_keeps_the_callback_schema() -> None:
    text = (
        REPO_ROOT / "docker" / "n8n" / "workflows" / "threatfusion_live_console_playbook.json"
    ).read_text(encoding="utf-8")
    document = json.loads(text)
    if isinstance(document, list):
        document = document[0]
    assert document["active"] is True
    assert document["nodes"][0]["parameters"]["responseMode"] == "lastNode"
    assert "http://host.docker.internal:8766" in text
    for key in (
        "candidate_id",
        "playbook_id",
        "case_id",
        "t_approval_queued",
        "t_callback_verified",
    ):
        assert key in text
    assert "422" in text
    assert "autonomous" not in text.lower()
    assert "thehive:9000" not in text
    compose = (REPO_ROOT / "docker" / "docker-compose.n8n.yml").read_text(encoding="utf-8")
    assert "extra_hosts:" in compose
    assert "host.docker.internal:host-gateway" in compose


def test_n8n_dispatch_records_422_without_dropping_the_callback(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("THREATFUSION_SOAR_HMAC_SECRET", SECRET)
    monkeypatch.setenv("THREATFUSION_MISP_API_KEY", MISP_KEY)
    handler = _contract_server()
    live_db = tmp_path / "live.sqlite3"
    soar_db = tmp_path / "soar.sqlite3"
    handler.soar_db_path = str(soar_db)
    _FakeN8n.calls = 0
    _FakeN8n.callback_posts = 0
    contract, contract_port = _serve(handler)
    webhook, webhook_port = _serve(_FakeN8n)
    contract_base = f"http://127.0.0.1:{contract_port}"
    webhook_url = f"http://127.0.0.1:{webhook_port}/webhook/threatfusion-live-console"
    try:
        _approved_other = _score(live_db)
        approve_live_soar(
            live_db,
            soar_db,
            flow_id=_approved_other,
            actor_id="analyst_a",
            reason="Analyst recorded local approval. Containment is not executed.",
        )
        unapproved = _score(live_db)
        refused = dispatch_approved_callback(
            live_db,
            soar_db,
            flow_id=unapproved,
            contract_base_url=contract_base,
            hmac_secret=SECRET,
            n8n_webhook_url=webhook_url,
            n8n_contract_base_url=contract_base,
        )
        assert refused["reason"] == "playbook_not_approved"
        assert refused["callback_recorded"] is False
        assert refused["containment_executed"] is False
        assert _FakeN8n.calls == 0

        approved_id = _score(live_db)
        store_flow_provenance(
            live_db,
            approved_id,
            entity_namespace_id="lab:range-bridge-01",
            src_entity_id="172.29.0.10",
            dst_entity_id="172.29.0.20",
            protocol="tcp",
            service_or_port="80",
            clock_synchronized=True,
        )
        approve_live_soar(
            live_db,
            soar_db,
            flow_id=approved_id,
            actor_id="analyst_a",
            reason="Analyst recorded local approval. Containment is not executed.",
        )
        dispatched = dispatch_approved_callback(
            live_db,
            soar_db,
            flow_id=approved_id,
            contract_base_url=contract_base,
            hmac_secret=SECRET,
            n8n_webhook_url=webhook_url,
            n8n_contract_base_url=contract_base,
            outbox_db_path=tmp_path / "thehive-ok.sqlite3",
        )
        assert dispatched["evidence_state"] == "verified"
        assert dispatched["execution_path"] == "n8n_live_container"
        assert dispatched["callback_recorded"] is True
        assert dispatched["containment_executed"] is False
        assert dispatched["execution_authorized"] is False
        assert dispatched["private_ip_guard_triggered"] is True
        assert len(dispatched["signature_sha256"]) == 64
        stored = _stored_callback(live_db, approved_id)
        assert stored["execution_path"] == "n8n_live_container"
        assert stored["callback_recorded"] == 1
        assert _FakeN8n.callback_posts == 1
    finally:
        contract.shutdown()
        webhook.shutdown()


def test_tampered_chain_returns_no_callback(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("THREATFUSION_SOAR_HMAC_SECRET", SECRET)
    monkeypatch.setenv("THREATFUSION_MISP_API_KEY", MISP_KEY)
    handler = _contract_server()
    live_db = tmp_path / "live.sqlite3"
    soar_db = tmp_path / "soar.sqlite3"
    handler.soar_db_path = str(soar_db)
    _FakeN8n.calls = 0
    _FakeN8n.callback_posts = 0
    contract, contract_port = _serve(handler)
    webhook, webhook_port = _serve(_FakeN8n)
    contract_base = f"http://127.0.0.1:{contract_port}"
    webhook_url = f"http://127.0.0.1:{webhook_port}/hook"
    try:
        flow_id = _score(live_db)
        approve_live_soar(
            live_db,
            soar_db,
            flow_id=flow_id,
            actor_id="analyst_a",
            reason="Analyst recorded local approval. Containment is not executed.",
        )
        with sqlite3.connect(soar_db) as conn:
            conn.execute("UPDATE soar_audit_events SET entry_sha256 = ?", ("0" * 64,))
        result = dispatch_approved_callback(
            live_db,
            soar_db,
            flow_id=flow_id,
            contract_base_url=contract_base,
            hmac_secret=SECRET,
            n8n_webhook_url=webhook_url,
            n8n_contract_base_url=contract_base,
            outbox_db_path=tmp_path / "thehive.sqlite3",
        )
        assert result["callback_recorded"] is False
        assert result["execution_path"] == "n8n_live_container"
        assert result["containment_executed"] is False
        assert _stored_callback(live_db, flow_id)["callback_recorded"] in (0, None)
        assert _FakeN8n.calls == 1
        assert _FakeN8n.callback_posts == 0
    finally:
        contract.shutdown()
        webhook.shutdown()
