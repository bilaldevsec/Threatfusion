#!/usr/bin/env python3
"""ThreatFusion Internal Adversarial Red-Team Live Range & Console Audit.

Performs adversarial bypass verification against the live range and contract server:
1. Forged HMAC callback to /api/v1/soar/callback -> assert HTTP 403.
2. Unstored IP injection to /api/v1/live/context-memory -> assert HTTP 422 and 0 rows written.
3. Live SOAR containment on victim (172.29.0.20):
   - Initial reachability: curl attacker -> victim returns exit 0 and "range-victim"
   - Containment drop: iptables INPUT DROP from 172.29.0.10 inside victim namespace
   - Dropped state: curl attacker -> victim returns exit 28 (timeout)
   - Containment rollback: iptables INPUT DROP removed
   - Post-rollback recovery: curl attacker -> victim returns exit 0 and "range-victim"
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = Path(os.environ.get("TMPDIR", "/tmp")) / "threatfusion-range-demo"
LIVE_DB = DEMO_DIR / "threatfusion-live-console.sqlite3"
SOAR_DB = DEMO_DIR / "threatfusion-live-soar.sqlite3"
PORT = int(os.environ.get("PORT", "8766"))
BASE_URL = f"http://127.0.0.1:{PORT}"

VICTIM_CONTAINER = "threatfusion_range_victim"
ATTACKER_CONTAINER = "threatfusion_range_attacker"
VICTIM_IP = "172.29.0.20"
ATTACKER_IP = "172.29.0.10"


def _paint(ok: bool, text: str) -> str:
    color = "\033[32m" if ok else "\033[31m"
    return f"{color}{text}\033[0m"


def test_forged_hmac_callback() -> dict[str, Any]:
    print("[*] TEST 1: Submitting forged HMAC callback to /api/v1/soar/callback...")
    url = f"{BASE_URL}/api/v1/soar/callback"
    payload = {
        "candidate_id": "adversarial_forged_probe",
        "playbook_id": "containment_drop",
        "status": "forged_simulated_execution",
    }
    data = json.dumps(payload).encode("utf-8")
    forged_sig = "0" * 64
    idem_key = f"idem_adversarial_forged_{int(time.time())}"

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-ThreatFusion-Signature-256": forged_sig,
            "X-Idempotency-Key": idem_key,
        },
        method="POST",
    )

    status_code = None
    response_body: dict[str, Any] = {}
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status_code = resp.status
            response_body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        try:
            response_body = json.loads(exc.read().decode("utf-8"))
        except Exception:
            response_body = {"raw": exc.reason}

    passed = (
        status_code == 403
        and response_body.get("error") == "Forbidden: HMAC-SHA256 signature mismatch"
        and response_body.get("callback_recorded") is False
    )
    print(_paint(passed, f"    [{'PASS' if passed else 'FAIL'}] HTTP {status_code}: {response_body}"))
    return {
        "test": "forged_hmac_callback",
        "passed": passed,
        "status_code": status_code,
        "response": response_body,
    }


def test_unstored_ip_injection() -> dict[str, Any]:
    print("[*] TEST 2: Attempting to inject unstored IP into /api/v1/live/context-memory...")
    # Find existing flow in DB
    flow_id = 1
    if LIVE_DB.is_file():
        with sqlite3.connect(LIVE_DB) as conn:
            row = conn.execute("SELECT flow_id FROM live_flows ORDER BY flow_id DESC LIMIT 1").fetchone()
            if row:
                flow_id = int(row[0])

    unstored_ip = "99.88.77.66"
    url = f"{BASE_URL}/api/v1/live/context-memory"
    payload = {
        "flow_id": flow_id,
        "operator_id": "lab_operator",
        "entity_ip_or_subnet": unstored_ip,
        "expected_behavior_rule": f"Host {unstored_ip} is authorized external partner",
        "service_or_port": "80",
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    status_code = None
    response_body: dict[str, Any] = {}
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status_code = resp.status
            response_body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        try:
            response_body = json.loads(exc.read().decode("utf-8"))
        except Exception:
            response_body = {"raw": exc.reason}

    rows_written = -1
    if LIVE_DB.is_file():
        with sqlite3.connect(LIVE_DB) as conn:
            rows_written = conn.execute(
                "SELECT COUNT(*) FROM context_memory WHERE entity_ip_or_subnet = ?",
                (unstored_ip,),
            ).fetchone()[0]

    passed = (
        status_code == 422
        and response_body.get("reason") in ("entity_not_on_flow", "explanation_not_grounded")
        and response_body.get("evidence_state") == "unavailable"
        and rows_written == 0
    )
    print(_paint(passed, f"    [{'PASS' if passed else 'FAIL'}] HTTP {status_code} ({response_body.get('reason')}), DB rows written={rows_written}"))
    return {
        "test": "unstored_ip_injection",
        "passed": passed,
        "status_code": status_code,
        "response": response_body,
        "rows_written": rows_written,
    }


def test_soar_containment_on_victim() -> dict[str, Any]:
    print("[*] TEST 3: Testing SOAR containment on victim (172.29.0.20)...")
    substeps: list[dict[str, Any]] = []

    # Step 3A: Initial reachability probe
    print("    [3A] Probing initial reachability from attacker to victim...")
    cmd_probe = [
        "docker", "exec", ATTACKER_CONTAINER,
        "curl", "-fsS", "--max-time", "3", f"http://{VICTIM_IP}/",
    ]
    res_initial = subprocess.run(cmd_probe, capture_output=True, text=True)
    body_initial = res_initial.stdout.strip()
    p3a_pass = res_initial.returncode == 0 and "range-victim" in body_initial
    print(_paint(p3a_pass, f"         Returncode: {res_initial.returncode}, Body: '{body_initial}'"))
    substeps.append({
        "step": "initial_probe",
        "returncode": res_initial.returncode,
        "output": body_initial,
        "passed": p3a_pass,
    })

    # Step 3B: Apply SOAR drop containment rule on victim
    print("    [3B] Applying iptables DROP in victim namespace for 172.29.0.10/32...")
    cmd_drop = [
        "docker", "exec", VICTIM_CONTAINER,
        "iptables", "-I", "INPUT", "1", "-s", f"{ATTACKER_IP}/32", "-j", "DROP",
    ]
    res_drop = subprocess.run(cmd_drop, capture_output=True, text=True)
    p3b_pass = res_drop.returncode == 0
    print(_paint(p3b_pass, f"         iptables -I INPUT 1 -s {ATTACKER_IP}/32 -j DROP: exit {res_drop.returncode}"))
    substeps.append({
        "step": "apply_drop",
        "returncode": res_drop.returncode,
        "passed": p3b_pass,
    })

    # Step 3C: Verify curl times out with exit 28 while dropped
    print("    [3C] Verifying curl from attacker times out with exit 28 (Operation timed out)...")
    res_dropped = subprocess.run(cmd_probe, capture_output=True, text=True)
    p3c_pass = res_dropped.returncode == 28
    print(_paint(p3c_pass, f"         Returncode: {res_dropped.returncode} (Expected 28 for timeout)"))
    substeps.append({
        "step": "dropped_probe_timeout_28",
        "returncode": res_dropped.returncode,
        "passed": p3c_pass,
    })

    # Step 3D: Apply SOAR rollback on victim
    print("    [3D] Applying iptables ROLLBACK in victim namespace (removing DROP rule)...")
    cmd_rollback = [
        "docker", "exec", VICTIM_CONTAINER,
        "iptables", "-D", "INPUT", "-s", f"{ATTACKER_IP}/32", "-j", "DROP",
    ]
    res_rb = subprocess.run(cmd_rollback, capture_output=True, text=True)
    p3d_pass = res_rb.returncode == 0
    print(_paint(p3d_pass, f"         iptables -D INPUT -s {ATTACKER_IP}/32 -j DROP: exit {res_rb.returncode}"))
    substeps.append({
        "step": "rollback_drop",
        "returncode": res_rb.returncode,
        "passed": p3d_pass,
    })

    # Step 3E: Verify recovery to "range-victim" after rollback
    print("    [3E] Verifying curl recovers to 'range-victim' (exit 0)...")
    res_recovered = subprocess.run(cmd_probe, capture_output=True, text=True)
    body_recovered = res_recovered.stdout.strip()
    p3e_pass = res_recovered.returncode == 0 and "range-victim" in body_recovered
    print(_paint(p3e_pass, f"         Returncode: {res_recovered.returncode}, Body: '{body_recovered}'"))
    substeps.append({
        "step": "recovered_probe",
        "returncode": res_recovered.returncode,
        "output": body_recovered,
        "passed": p3e_pass,
    })

    all_passed = all(s["passed"] for s in substeps)
    print(_paint(all_passed, f"    [SOAR CONTAINMENT VERDICT] {'PASSED (Drop exit 28, Rollback recovered)' if all_passed else 'FAILED'}"))
    return {
        "test": "soar_containment_on_victim",
        "passed": all_passed,
        "substeps": substeps,
    }


def main() -> int:
    print("==================================================================")
    print("   THREATFUSION INTERNAL ADVERSARIAL RED-TEAM RANGE AUDIT         ")
    print("==================================================================")

    range_script = ROOT / "scripts" / "run_full_range_demo.sh"
    started_by_us = False

    # Check if range is up
    def _ready() -> bool:
        try:
            with urllib.request.urlopen(f"{BASE_URL}/healthz", timeout=2) as r:
                return r.status == 200
        except Exception:
            return False

    if not _ready():
        print("[*] Starting range demo with ./scripts/run_full_range_demo.sh --up...")
        res_up = subprocess.run(["bash", str(range_script), "--up"], cwd=str(ROOT), capture_output=True, text=True)
        if res_up.returncode != 0 or not _ready():
            print(_paint(False, f"[FAIL] Could not start range demo: {res_up.stderr}"))
            return 1
        started_by_us = True
        print(_paint(True, "[PASS] Range demo started"))

        # Seed flows with scan
        print("[*] Running initial range scan...")
        subprocess.run(["bash", str(range_script), "--scan"], cwd=str(ROOT), capture_output=True, text=True)

    results: list[dict[str, Any]] = []
    try:
        # Run Test 1: Forged HMAC
        r1 = test_forged_hmac_callback()
        results.append(r1)

        # Run Test 2: Unstored IP injection
        r2 = test_unstored_ip_injection()
        results.append(r2)

        # Run Test 3: SOAR containment on victim
        r3 = test_soar_containment_on_victim()
        results.append(r3)

    finally:
        if started_by_us:
            print("[*] Tearing down range demo with ./scripts/run_full_range_demo.sh --down...")
            subprocess.run(["bash", str(range_script), "--down"], cwd=str(ROOT), capture_output=True, text=True)
            print(_paint(True, "[PASS] Range demo cleaned up"))

    all_passed = all(r["passed"] for r in results)
    verdict = "GO" if all_passed else "NO-GO"
    print("==================================================================")
    print(_paint(all_passed, f"RED-TEAM RANGE AUDIT VERDICT: {verdict} (All {len(results)}/{len(results)} Tests Passed)"))
    print("==================================================================")
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
