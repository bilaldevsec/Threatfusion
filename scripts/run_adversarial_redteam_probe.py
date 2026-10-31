#!/usr/bin/env python3
"""Isolated adversarial probe for a ThreatFusion console.

The default run starts its own console on a temporary database. It does not
open or write threatfusion-live-console.sqlite3. A full pass writes the audit
file the live health drawer reads.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HMAC_SECRET = "lab-only-not-a-production-secret"
MISP_KEY = "lab-only-misp-key-16xx"
ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "scripts" / "run_misp_and_callback_contract_server.py"


def _post(
    base: str, path: str, payload: dict, headers: dict[str, str] | None = None
) -> tuple[int, dict]:
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers=request_headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"error": raw}
        return exc.code, parsed if isinstance(parsed, dict) else {}


def _get(base: str, path: str) -> tuple[int, dict]:
    request = urllib.request.Request(f"{base}{path}", method="GET")
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_ready(base: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            status, payload = _get(base, "/healthz")
            if status == 200 and payload.get("status") == "ok":
                return
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            time.sleep(0.2)
    raise RuntimeError("isolated console did not become ready")


def _flow_ids(base: str) -> list[int]:
    _status, payload = _get(base, "/api/v1/live/campaigns")
    found: list[int] = []
    for campaign in payload.get("campaigns") or []:
        for flow in campaign.get("flows") or []:
            flow_id = flow.get("flow_id")
            if isinstance(flow_id, int):
                found.append(flow_id)
    return found


def _paint(ok: bool, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    color = "\033[32m" if ok else "\033[31m"
    return f"{color}{text}\033[0m"


def run_probes(base: str) -> list[tuple[str, bool, str]]:
    """Exercise five refusals. The caller owns the database behind base."""
    scenario_status, _scenario = _post(base, "/api/v1/live/scenarios", {})
    if scenario_status != 200:
        raise RuntimeError(f"could not seed an isolated scenario flow: {scenario_status}")
    flow_ids = _flow_ids(base)
    if len(flow_ids) < 2:
        raise RuntimeError("isolated console did not store two flows")
    approved_id, other_id = flow_ids[0], flow_ids[1]
    approve_status, _approved = _post(
        base,
        "/api/v1/live/soar/approve",
        {
            "flow_id": approved_id,
            "actor_id": "analyst_a",
            "reason": "Isolated probe approval so the ledger file exists.",
        },
    )
    if approve_status != 200:
        raise RuntimeError(f"isolated approval failed: {approve_status}")

    dispatch_status, dispatch = _post(base, "/api/v1/live/soar/dispatch", {"flow_id": other_id})
    forged_status, _forged = _post(
        base,
        "/api/v1/soar/callback",
        {"candidate_id": "probe"},
        headers={
            "X-ThreatFusion-Signature-256": "0" * 64,
            "X-Idempotency-Key": "idem_redteam_probe_1",
        },
    )
    guard_status, guard = _post(base, "/api/v1/live/misp-guard", {"value": "172.29.0.10"})
    handoff_status, handoff = _post(
        base,
        "/api/v1/live/handoff",
        {"flow_id": approved_id, "brief": "host 203.0.113.99 was isolated"},
    )
    identity_status, identity = _post(
        base,
        "/api/v1/live/triage",
        {"flow_id": approved_id, "action": "acknowledge", "actor_id": "analyst_a"},
    )
    checks = [
        (
            "unapproved dispatch",
            dispatch_status == 403 and dispatch.get("reason") == "playbook_not_approved",
            f"HTTP {dispatch_status} {dispatch.get('reason')}",
        ),
        (
            "forged HMAC",
            forged_status == 403,
            f"HTTP {forged_status}",
        ),
        (
            "private IP",
            guard_status == 422 and guard.get("private_ip_guard_triggered") is True,
            f"HTTP {guard_status}",
        ),
        (
            "hallucinated handoff",
            handoff_status == 400 and handoff.get("reason") == "explanation_not_grounded",
            f"HTTP {handoff_status} {handoff.get('reason')}",
        ),
        (
            "unenrolled identity",
            identity_status == 200
            and identity.get("identity_verified") is False
            and identity.get("identity_label") == "unverified_local_label",
            f"HTTP {identity_status} {identity.get('identity_label')}",
        ),
    ]
    return checks


def _write_audit(passed: int, audit_path: Path) -> None:
    payload = {
        "evidence_state": "verified" if passed == 5 else "unavailable",
        "passed": passed,
        "total": 5,
        "label": (
            "External agy Red-Team Audit: 5/5 Boundaries Held"
            if passed == 5
            else f"External agy Red-Team Audit: {passed}/5 Boundaries Held"
        ),
    }
    audit_path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(audit_path, 0o600)


def run_isolated_audit(audit_path: Path | None = None) -> int:
    """Start a private console, run the five probes, and stop it."""
    destination = audit_path or (
        Path(os.environ.get("TMPDIR", "/tmp")) / "threatfusion-agy-audit.json"
    )
    with tempfile.TemporaryDirectory(prefix="threatfusion-agy-") as raw:
        work = Path(raw)
        port = _free_port()
        env = os.environ.copy()
        env["THREATFUSION_LIVE_CONSOLE_DB"] = str(work / "console.sqlite3")
        env["THREATFUSION_SOAR_LEDGER_DB_PATH"] = str(work / "soar.sqlite3")
        env["THREATFUSION_LIVE_RAG_DB"] = str(work / "rag.sqlite3")
        env["THREATFUSION_SOAR_HMAC_SECRET"] = HMAC_SECRET
        env["THREATFUSION_MISP_API_KEY"] = MISP_KEY
        env.pop("THREATFUSION_N8N_WEBHOOK_URL", None)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env.pop("PYTHONPATH", None)
        python = ROOT / "threatfusion-venv" / "bin" / "python"
        if not python.is_file():
            python = Path(sys.executable)
        process = subprocess.Popen(
            [str(python), str(SERVER), "--bind", "127.0.0.1", "--port", str(port)],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        base = f"http://127.0.0.1:{port}"
        try:
            _wait_ready(base)
            checks = run_probes(base)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
    passed = sum(1 for _name, ok, _detail in checks if ok)
    for name, ok, detail in checks:
        mark = "PASS" if ok else "FAIL"
        print(_paint(ok, f"[{mark}] {name}: {detail}"))
    print(
        _paint(
            passed == 5,
            f"[AGY RED-TEAM AUDIT] {passed}/5 Adversarial Bypasses Defeated by ThreatFusion",
        )
    )
    _write_audit(passed, destination)
    return 0 if passed == 5 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Isolated ThreatFusion adversarial probe")
    parser.add_argument(
        "--target",
        default="",
        help="Unused for the isolated run. Present so an operator can see the intended console.",
    )
    parser.add_argument("--audit-path", default="")
    args = parser.parse_args(argv)
    if args.target and "8766" in args.target:
        print(
            "The probe uses a temporary database and does not write the live console database.",
            file=sys.stderr,
        )
    audit_path = Path(args.audit_path) if args.audit_path else None
    return run_isolated_audit(audit_path)


if __name__ == "__main__":
    raise SystemExit(main())
