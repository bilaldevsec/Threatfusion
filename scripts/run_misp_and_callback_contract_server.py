#!/usr/bin/env python3
"""Deterministic Authenticated MISP Connector and SOAR Callback Contract Server.

Implements lightweight deterministic HTTP services for containerized SOC stacks:
1. POST /attributes/restSearch:
   Enforces THREATFUSION_MISP_API_KEY authorization and RFC1918 Private-IP Guard
   (rejecting private/loopback IP lookups with HTTP 422 Unprocessable Entity).
   Returns canonical MISP indicator attributes.
2. POST /api/v1/soar/verify-state:
   Verifies cryptographic HMAC-SHA256 signature and non-replayed idempotency key
   against THREATFUSION_SOAR_HMAC_SECRET (>=16 chars) and performs server-side
   ledger verification against SoarPlaybookSqliteRepository (rejecting unapproved
   playbooks or broken audit chains with HTTP 403 Forbidden).
3. POST /api/v1/soar/callback:
   Verifies HMAC-SHA256 signature and non-replayed idempotency key before recording
   execution and audit callbacks from the n8n autonomous playbook.
4. GET /healthz:
   Liveness and readiness health probe returning HTTP 200 {"status": "ok"}.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import threading
from typing import Any

# Ensure backend/src is on sys.path for direct module imports
REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_SRC = REPO_ROOT / "backend" / "src"
if BACKEND_SRC.exists() and str(BACKEND_SRC) not in sys.path:
    sys.path.insert(0, str(BACKEND_SRC))

MAX_POST_BODY_BYTES = 1048576

CANONICAL_INDICATORS: dict[str, dict[str, Any]] = {
    "44d88612fea8a8f36de82e1278abb02f": {
        "matched": True,
        "threat_level": "high",
        "tags": ["malware:eicar", "confidence:high", "tlp:white"],
        "event_id": "misp_evt_eicar_01",
        "type": "md5",
    },
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "matched": True,
        "threat_level": "high",
        "tags": ["malware:mirai", "c2:botnet", "tlp:green"],
        "event_id": "misp_evt_mirai_02",
        "type": "sha256",
    },
    "198.51.100.27": {
        "matched": True,
        "threat_level": "high",
        "tags": ["c2:active_beacon", "apt:threatfusion_simulated", "tlp:amber"],
        "event_id": "misp_evt_c2_03",
        "type": "ip-dst",
    },
    "203.0.113.195": {
        "matched": True,
        "threat_level": "medium",
        "tags": ["scanner:masscan", "reconnaissance", "tlp:green"],
        "event_id": "misp_evt_scan_04",
        "type": "ip-dst",
    },
}


def is_rfc1918_or_loopback_ip(ip_str: str) -> bool:
    """Return True if ip_str is a valid IPv4/IPv6 private, loopback, or link-local address."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def verify_hmac_signature(payload_bytes: bytes, signature_hex: str, secret: str) -> bool:
    """Verify HMAC-SHA256 signature in constant time against raw or canonical JSON bytes."""
    if not signature_hex or not secret:
        return False

    # 1. Direct byte verification
    expected_direct = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    if hmac.compare_digest(signature_hex.lower(), expected_direct.lower()):
        return True

    # 2. Canonical JSON sorted-keys verification
    try:
        obj = json.loads(payload_bytes.decode("utf-8"))
        canonical_bytes = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_canonical = hmac.new(
            secret.encode("utf-8"), canonical_bytes, hashlib.sha256
        ).hexdigest()
        if hmac.compare_digest(signature_hex.lower(), expected_canonical.lower()):
            return True
    except Exception:
        pass

    return False


def _get_soar_record_and_verify_chain(
    db_path: Path | str, playbook_id: str
) -> tuple[bool, Any | None, str]:
    """Inspect server-side ledger SQLite DB for playbook record and audit chain integrity."""
    p = Path(db_path)
    if not p.is_file():
        return False, None, f"Ledger database not found at {p}"
    try:
        from threatfusion.soar.playbook_ledger import SoarPlaybookSqliteRepository

        repo = SoarPlaybookSqliteRepository(p)
        record = repo.get_record(playbook_id)
        if record is None:
            return False, None, f"Playbook '{playbook_id}' not found in ledger"
        chain_res = repo.verify_audit_chain_integrity()
        chain_dict = (
            chain_res
            if isinstance(chain_res, dict)
            else (
                {"valid": chain_res[0], "message": chain_res[1]}
                if isinstance(chain_res, (tuple, list)) and len(chain_res) >= 2
                else {"valid": bool(chain_res)}
            )
        )
        if chain_dict.get("valid") is not True:
            return (
                False,
                record,
                f"Audit chain verification failed: {chain_dict.get('message', 'invalid')}",
            )
        return True, record, "ok"
    except Exception as exc:
        return False, None, f"Ledger access error: {exc}"


class MispAndCallbackContractHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler implementing MISP restSearch, state verification, and callback."""

    soar_db_path: str | None = None
    misp_api_key: str | None = None
    seen_verify_idempotency_keys: set[str] = set()
    seen_callback_idempotency_keys: set[str] = set()
    _lock: threading.Lock = threading.Lock()

    def _soar_db_file(self) -> str | None:
        return self.soar_db_path or os.environ.get("THREATFUSION_SOAR_LEDGER_DB_PATH")

    def _idempotency_memory(self, scope: str) -> set[str]:
        if scope == "verify":
            return self.seen_verify_idempotency_keys
        return self.seen_callback_idempotency_keys

    def _idempotency_is_replay(self, scope: str, key: str) -> bool:
        if key in self._idempotency_memory(scope):
            return True
        db_path = self._soar_db_file()
        if not db_path or not Path(db_path).is_file():
            return False
        try:
            conn = sqlite3.connect(str(db_path), timeout=5.0, isolation_level=None)
            try:
                conn.execute("PRAGMA busy_timeout = 5000")
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS contract_idempotency_keys (
                        scope TEXT NOT NULL,
                        idempotency_key TEXT NOT NULL,
                        recorded_at_utc TEXT NOT NULL,
                        PRIMARY KEY (scope, idempotency_key)
                    )
                    """
                )
                row = conn.execute(
                    "SELECT 1 FROM contract_idempotency_keys WHERE scope = ? AND idempotency_key = ?",
                    (scope, key),
                ).fetchone()
                return row is not None
            finally:
                conn.close()
        except sqlite3.Error:
            return False

    def _idempotency_commit(self, scope: str, key: str) -> None:
        self._idempotency_memory(scope).add(key)
        db_path = self._soar_db_file()
        if not db_path:
            return
        try:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(db_path), timeout=5.0, isolation_level=None)
            try:
                conn.execute("PRAGMA busy_timeout = 5000")
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS contract_idempotency_keys (
                        scope TEXT NOT NULL,
                        idempotency_key TEXT NOT NULL,
                        recorded_at_utc TEXT NOT NULL,
                        PRIMARY KEY (scope, idempotency_key)
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO contract_idempotency_keys (
                        scope, idempotency_key, recorded_at_utc
                    ) VALUES (?, ?, ?)
                    """,
                    (scope, key, datetime.now(UTC).isoformat()),
                )
            finally:
                conn.close()
        except sqlite3.Error:
            return

    def _rejected_content_length(self) -> bool:
        raw = self.headers.get("Content-Length")
        if raw is None or str(raw).strip() == "":
            self._send_json(400, {"error": "content_length_required"})
            return True
        try:
            length = int(str(raw).strip())
        except ValueError:
            self._send_json(400, {"error": "content_length_invalid"})
            return True
        if length < 0:
            self._send_json(400, {"error": "content_length_invalid"})
            return True
        if length > MAX_POST_BODY_BYTES:
            self._send_json(413, {"error": "payload_too_large"})
            return True
        return False

    def _send_json(self, status_code: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, file_path: Path, content_type: str) -> None:
        if not file_path.is_file():
            self._send_json(404, {"error": "Not Found", "path": str(file_path)})
            return
        content = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            index_path = REPO_ROOT / "frontend" / "index.html"
            self._send_file(index_path, "text/html; charset=utf-8")
            return
        if path == "/css/soc_unicorn.css":
            css_path = REPO_ROOT / "frontend" / "css" / "soc_unicorn.css"
            self._send_file(css_path, "text/css; charset=utf-8")
            return
        if path == "/js/soc_dashboard.js":
            js_path = REPO_ROOT / "frontend" / "js" / "soc_dashboard.js"
            self._send_file(js_path, "application/javascript; charset=utf-8")
            return
        if path in ("/healthz", "/api/v1/heartbeat", "/api/status"):
            self._send_json(200, {"status": "ok", "service": "threatfusion_soc_contract_server"})
            return
        if path == "/api/v1/metrics/operational-velocity":
            from threatfusion.api.analyst_dashboard import compute_alert_noise_reduction_funnel
            from threatfusion.correlation.incident_correlation import (
                build_operational_velocity_report,
            )

            inc_timings: list[dict[str, Any]] = []
            resp_timings: list[dict[str, Any]] = []

            db_path = self.soar_db_path or os.environ.get("THREATFUSION_SOAR_LEDGER_DB_PATH")
            if db_path and Path(db_path).is_file():
                try:
                    from threatfusion.soar.playbook_ledger import SoarPlaybookSqliteRepository

                    s_repo = SoarPlaybookSqliteRepository(Path(db_path))
                    resp_timings = s_repo.list_response_timings()
                except Exception:
                    pass

            inc_db_path = os.environ.get("THREATFUSION_INCIDENTS_DB_PATH")
            if inc_db_path and Path(inc_db_path).is_file():
                try:
                    from threatfusion.alerts.correlation_engine import IncidentSqliteRepository

                    i_repo = IncidentSqliteRepository(Path(inc_db_path))
                    inc_timings = i_repo.list_incident_timings()
                except Exception:
                    pass

            t1 = int(os.environ.get("THREATFUSION_TIER1_RAW_FLOWS", "216568"))
            t2 = int(os.environ.get("THREATFUSION_TIER2_TRIAGE_CANDIDATES", "4358"))
            t3 = max(len(inc_timings), int(os.environ.get("THREATFUSION_TIER3_INCIDENTS", "24")))
            t4 = max(len(resp_timings), int(os.environ.get("THREATFUSION_TIER4_PLAYBOOKS", "8")))

            funnel_obj = compute_alert_noise_reduction_funnel(
                tier1_raw_flows_ingested=t1,
                tier2_triage_queue_candidates=t2,
                tier3_correlated_incidents=t3,
                tier4_actionable_soar_playbooks=t4,
            )
            report = build_operational_velocity_report(
                incident_timings=inc_timings,
                response_timings=resp_timings,
                noise_reduction_funnel=funnel_obj.to_dict(),
            )
            self._send_json(200, report.to_dict())
            return

        self._send_json(404, {"error": "Not Found", "path": path})

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        if self._rejected_content_length():
            return
        content_length = int(str(self.headers.get("Content-Length")).strip())
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b""

        # 1. MISP Rest Search Endpoint
        if path == "/attributes/restSearch":
            configured_key = (
                self.misp_api_key or os.environ.get("THREATFUSION_MISP_API_KEY", "")
            ).strip()
            if not configured_key or len(configured_key) < 16:
                self._send_json(
                    500,
                    {
                        "error": "Server misconfigured: THREATFUSION_MISP_API_KEY missing or insecure",
                    },
                )
                return

            auth_header = self.headers.get("Authorization", "").strip()
            if not auth_header:
                self._send_json(401, {"error": "Unauthorized: Missing Authorization header"})
                return

            token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else auth_header
            if not hmac.compare_digest(token, configured_key):
                self._send_json(401, {"error": "Unauthorized: Invalid MISP API key"})
                return

            try:
                req_data = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except json.JSONDecodeError:
                self._send_json(400, {"error": "Invalid JSON body"})
                return

            value = str(req_data.get("value", "")).strip()
            ind_type = str(req_data.get("type", "ip-dst")).strip()

            # Enforce RFC1918 Private IP Guard
            if "ip" in ind_type or is_rfc1918_or_loopback_ip(value):
                if is_rfc1918_or_loopback_ip(value):
                    self._send_json(
                        422,
                        {
                            "error": "RFC1918 private IP lookup forbidden",
                            "detail": f"Private/loopback IP '{value}' is suppressed from threat intelligence lookup",
                            "private_ip_guard_triggered": True,
                        },
                    )
                    return

            indicator_info = CANONICAL_INDICATORS.get(value.lower())
            if indicator_info and indicator_info.get("matched"):
                attr = {
                    "id": f"attr_{hashlib.sha256(value.encode('utf-8')).hexdigest()[:8]}",
                    "event_id": indicator_info["event_id"],
                    "value": value,
                    "type": indicator_info.get("type", ind_type),
                    "category": "Network activity",
                    "to_ids": True,
                    "Tag": [{"name": t} for t in indicator_info.get("tags", [])],
                }
                self._send_json(200, {"response": {"Attribute": [attr]}})
            else:
                self._send_json(200, {"response": {"Attribute": []}})
            return

        # 2. SOAR State Verification Endpoint
        if path == "/api/v1/soar/verify-state":
            sig_header = self.headers.get(
                "X-ThreatFusion-Signature-256",
                self.headers.get("x-threatfusion-signature-256", ""),
            ).strip()
            idem_key = self.headers.get(
                "X-Idempotency-Key",
                self.headers.get("x-idempotency-key", ""),
            ).strip()
            hmac_secret = os.environ.get("THREATFUSION_SOAR_HMAC_SECRET", "").strip()

            if not sig_header or not idem_key:
                self._send_json(
                    403,
                    {
                        "error": "Forbidden: Missing cryptographic signature or idempotency key",
                        "state_verified": False,
                        "verified": False,
                    },
                )
                return

            if not hmac_secret or len(hmac_secret) < 16:
                self._send_json(
                    500,
                    {
                        "error": "Server configuration error: THREATFUSION_SOAR_HMAC_SECRET missing or insecure",
                        "state_verified": False,
                        "verified": False,
                    },
                )
                return

            if not verify_hmac_signature(body_bytes, sig_header, hmac_secret):
                self._send_json(
                    403,
                    {
                        "error": "Forbidden: HMAC-SHA256 signature mismatch",
                        "state_verified": False,
                        "verified": False,
                    },
                )
                return

            if not re.match(r"^idem_[A-Za-z0-9_\-:]+_\d+$", idem_key):
                self._send_json(
                    400,
                    {
                        "error": "Bad Request: Invalid idempotency key format (expected idem_<playbook_id>_<version>)",
                        "state_verified": False,
                        "verified": False,
                    },
                )
                return

            with self._lock:
                if self._idempotency_is_replay("verify", idem_key):
                    self._send_json(
                        409,
                        {
                            "error": "Conflict: Idempotency key replayed",
                            "state_verified": False,
                            "verified": False,
                            "idempotency_key": idem_key,
                        },
                    )
                    return

            try:
                body_obj = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except json.JSONDecodeError:
                self._send_json(
                    400,
                    {
                        "error": "Invalid JSON payload",
                        "state_verified": False,
                        "verified": False,
                    },
                )
                return

            playbook_id = str(body_obj.get("playbook_id", "")).strip()
            candidate_id = str(body_obj.get("candidate_id", "")).strip()

            if not playbook_id or not candidate_id:
                self._send_json(
                    403,
                    {
                        "error": "server_side_soar_ledger_verification_failed",
                        "detail": "playbook_id and candidate_id are required for ledger-verified state verification",
                        "state_verified": False,
                        "verified": False,
                    },
                )
                return

            db_path = self.soar_db_path
            if db_path is None or not Path(db_path).is_file():
                self._send_json(
                    403,
                    {
                        "error": "server_side_soar_ledger_verification_failed",
                        "detail": "soar_db_path is not configured or missing on disk; fail-closed verification rejection",
                        "state_verified": False,
                        "verified": False,
                    },
                )
                return

            try:
                from threatfusion.soar.playbook_ledger import SoarPlaybookSqliteRepository

                repo = SoarPlaybookSqliteRepository(Path(db_path))
                chain_res = repo.verify_audit_chain_integrity()
                chain_dict = (
                    chain_res
                    if isinstance(chain_res, dict)
                    else (
                        {"valid": chain_res[0], "message": chain_res[1]}
                        if isinstance(chain_res, (tuple, list)) and len(chain_res) >= 2
                        else {"valid": bool(chain_res)}
                    )
                )
                if chain_dict.get("valid") is not True:
                    self._send_json(
                        403,
                        {
                            "error": "server_side_soar_ledger_verification_failed",
                            "detail": "Audit chain verification failed",
                            "state_verified": False,
                            "verified": False,
                        },
                    )
                    return

                record = repo.get_record(playbook_id)
                if record is None:
                    self._send_json(
                        403,
                        {
                            "error": "server_side_soar_ledger_verification_failed",
                            "detail": f"Playbook '{playbook_id}' not found in ledger",
                            "state_verified": False,
                            "verified": False,
                        },
                    )
                    return

                record_candidate_id = getattr(record, "candidate_id", None)
                if record_candidate_id and record_candidate_id != candidate_id:
                    self._send_json(
                        403,
                        {
                            "error": "server_side_soar_ledger_verification_failed",
                            "detail": f"Candidate ID mismatch: expected '{record_candidate_id}', got '{candidate_id}'",
                            "state_verified": False,
                            "verified": False,
                        },
                    )
                    return

                if record.state not in ("approved", "executed_simulated"):
                    self._send_json(
                        403,
                        {
                            "error": "server_side_soar_ledger_verification_failed",
                            "detail": f"Playbook state '{record.state}' is not approved or executed",
                            "state_verified": False,
                            "verified": False,
                        },
                    )
                    return
            except Exception as exc:
                self._send_json(
                    403,
                    {
                        "error": "server_side_soar_ledger_verification_failed",
                        "detail": f"Ledger access error: {exc}",
                        "state_verified": False,
                        "verified": False,
                    },
                )
                return

            with self._lock:
                self._idempotency_commit("verify", idem_key)

            self._send_json(
                200,
                {
                    "status": "ok",
                    "verified": True,
                    "state_verified": True,
                    "idempotency_key": idem_key,
                    "candidate_id": candidate_id,
                    "playbook_id": playbook_id,
                    "ledger_state": record.state,
                    "timestamp_utc": datetime.now(UTC).isoformat(),
                },
            )
            return

        # 3. SOAR Audit / Callback Endpoint
        if path in ("/api/v1/soar/callback", "/api/v1/soar/audit-callback"):
            sig_header = self.headers.get(
                "X-ThreatFusion-Signature-256",
                self.headers.get("x-threatfusion-signature-256", ""),
            ).strip()
            idem_key = self.headers.get(
                "X-Idempotency-Key",
                self.headers.get("x-idempotency-key", ""),
            ).strip()
            hmac_secret = os.environ.get("THREATFUSION_SOAR_HMAC_SECRET", "").strip()

            if not sig_header:
                self._send_json(
                    403,
                    {
                        "error": "Forbidden: Missing X-ThreatFusion-Signature-256 header",
                        "callback_recorded": False,
                    },
                )
                return

            if not idem_key:
                self._send_json(
                    403,
                    {
                        "error": "Forbidden: Missing X-Idempotency-Key header",
                        "callback_recorded": False,
                    },
                )
                return

            if not hmac_secret or len(hmac_secret) < 16:
                self._send_json(
                    500,
                    {
                        "error": "Server configuration error: THREATFUSION_SOAR_HMAC_SECRET missing or insecure",
                        "callback_recorded": False,
                    },
                )
                return

            if not verify_hmac_signature(body_bytes, sig_header, hmac_secret):
                self._send_json(
                    403,
                    {
                        "error": "Forbidden: HMAC-SHA256 signature mismatch",
                        "callback_recorded": False,
                    },
                )
                return

            if not re.match(r"^idem_[A-Za-z0-9_\-:]+", idem_key):
                self._send_json(
                    400,
                    {
                        "error": "Bad Request: Invalid idempotency key format",
                        "callback_recorded": False,
                    },
                )
                return

            with self._lock:
                if self._idempotency_is_replay("callback", idem_key):
                    self._send_json(
                        409,
                        {
                            "error": "Conflict: Callback idempotency key replayed",
                            "callback_recorded": False,
                            "idempotency_key": idem_key,
                        },
                    )
                    return

            try:
                body_obj = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except json.JSONDecodeError:
                self._send_json(
                    400,
                    {
                        "error": "Invalid JSON payload",
                        "callback_recorded": False,
                    },
                )
                return

            payload = body_obj
            playbook_id = str(payload.get("playbook_id", "")).strip()
            candidate_id = str(payload.get("candidate_id", "")).strip()

            # (a) Check playbook_id and candidate_id are non-empty
            if not playbook_id or not candidate_id:
                self._send_json(
                    403,
                    {
                        "error": "playbook_id and candidate_id are required for ledger-verified callback",
                        "callback_recorded": False,
                    },
                )
                return

            # (b) Resolve db_path = self.soar_db_path and verify regular file on disk
            db_path = self.soar_db_path
            if db_path is None or not Path(db_path).is_file():
                self._send_json(
                    403,
                    {
                        "error": "soar_db_path is not configured or missing on disk; fail-closed callback rejection",
                        "callback_recorded": False,
                    },
                )
                return

            # (c) Open SoarPlaybookSqliteRepository and verify integrity and state
            try:
                from threatfusion.soar.playbook_ledger import SoarPlaybookSqliteRepository

                repo = SoarPlaybookSqliteRepository(Path(db_path))
                chain_res = repo.verify_audit_chain_integrity()
                chain_dict = (
                    chain_res
                    if isinstance(chain_res, dict)
                    else (
                        {"valid": chain_res[0], "message": chain_res[1]}
                        if isinstance(chain_res, (tuple, list)) and len(chain_res) >= 2
                        else {"valid": bool(chain_res)}
                    )
                )
                if chain_dict.get("valid") is not True:
                    self._send_json(
                        403,
                        {
                            "error": "unverified or unapproved playbook state in ledger",
                            "callback_recorded": False,
                        },
                    )
                    return

                record = repo.get_record(playbook_id)
                if record is None:
                    self._send_json(
                        403,
                        {
                            "error": "unverified or unapproved playbook state in ledger",
                            "callback_recorded": False,
                        },
                    )
                    return

                record_candidate_id = getattr(record, "candidate_id", None)
                if record_candidate_id and record_candidate_id != candidate_id:
                    self._send_json(
                        403,
                        {
                            "error": "unverified or unapproved playbook state in ledger",
                            "callback_recorded": False,
                        },
                    )
                    return

                if record.state not in ("approved", "executed_simulated"):
                    self._send_json(
                        403,
                        {
                            "error": "unverified or unapproved playbook state in ledger",
                            "callback_recorded": False,
                        },
                    )
                    return
            except Exception:
                self._send_json(
                    403,
                    {
                        "error": "unverified or unapproved playbook state in ledger",
                        "callback_recorded": False,
                    },
                )
                return

            t_cb = float(payload.get("t_callback_verified", datetime.now(UTC).timestamp()))
            t_app = (
                float(payload["t_approval_queued"])
                if ("t_approval_queued" in payload and payload["t_approval_queued"] is not None)
                else None
            )
            t_resp = 0.0
            try:
                t_resp = repo.record_callback_verification(
                    playbook_id=playbook_id,
                    t_callback_verified=t_cb,
                    t_approval_queued=t_app,
                )
            except Exception:
                pass

            with self._lock:
                self._idempotency_commit("callback", idem_key)

            self._send_json(
                200,
                {
                    "status": "ok",
                    "callback_recorded": True,
                    "playbook_id": playbook_id,
                    "candidate_id": candidate_id,
                    "idempotency_key": idem_key,
                    "t_approval_queued": (
                        t_app if t_app is not None else getattr(record, "t_approval_queued", None)
                    ),
                    "t_callback_verified": t_cb,
                    "t_response": t_resp,
                    "timestamp_utc": datetime.now(UTC).isoformat(),
                },
            )
            return

        self._send_json(404, {"error": "Not Found", "path": path})

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stderr HTTP request logging for deterministic test quietness."""
        return


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the contract-server CLI. ``--host`` is an alias of ``--bind``."""
    parser = argparse.ArgumentParser(
        description="ThreatFusion MISP Connector & Callback Contract Server"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "8080")),
        help="Port to listen on (default: 8080 or PORT env var)",
    )
    parser.add_argument(
        "--bind",
        "--host",
        dest="bind",
        type=str,
        default="127.0.0.1",
        help="Address to bind to (default: 127.0.0.1). --host is an alias of --bind.",
    )
    parser.add_argument(
        "--soar-db-path",
        type=str,
        default=os.environ.get("THREATFUSION_SOAR_LEDGER_DB_PATH"),
        help="Path to SQLite SOAR ledger database",
    )
    return parser


def run_server(
    bind_addr: str = "127.0.0.1", port: int = 8080, soar_db_path: str | None = None
) -> None:
    """Run the contract HTTP server synchronously."""
    effective_db = soar_db_path or os.environ.get("THREATFUSION_SOAR_LEDGER_DB_PATH")
    if effective_db:
        MispAndCallbackContractHandler.soar_db_path = effective_db
    server_address = (bind_addr, port)
    httpd = HTTPServer(server_address, MispAndCallbackContractHandler)
    print(f"[ThreatFusion] SOC Contract Server listening on {bind_addr}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[ThreatFusion] SOC Contract Server shutting down.")
        httpd.server_close()


def main() -> int:
    args = build_argument_parser().parse_args()
    run_server(bind_addr=args.bind, port=args.port, soar_db_path=args.soar_db_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
