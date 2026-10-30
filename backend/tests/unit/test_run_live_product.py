"""Smoke and dry-run checks for scripts/run_live_product.sh."""

from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "run_live_product.sh"
PYTHON = REPO_ROOT / "threatfusion-venv" / "bin" / "python"


def _require_launcher() -> None:
    if not SCRIPT.is_file() or not os.access(SCRIPT, os.X_OK):
        pytest.skip("scripts/run_live_product.sh is not executable")
    if not PYTHON.is_file():
        pytest.skip("threatfusion-venv is not installed")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _env(tmp_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("THREATFUSION_SOAR_LEDGER_DB_PATH", None)
    env.pop("THREATFUSION_LIVE_CONSOLE_DB", None)
    env["TMPDIR"] = str(tmp_path)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _run(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SCRIPT), *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=40,
        check=False,
    )


def _port_open(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def _wait_http(url: str, needle: str, timeout: float = 15.0) -> str:
    deadline = time.monotonic() + timeout
    last_error = "no response"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                body = response.read().decode("utf-8", "replace")
                if response.status == 200 and needle in body:
                    return body
                last_error = body[:240]
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc.__class__.__name__
            time.sleep(0.1)
    raise AssertionError(last_error)


def test_dry_run_prints_both_surfaces_and_does_not_bind(tmp_path: Path) -> None:
    _require_launcher()
    port = _free_port()
    result = _run(["--dry-run", "--port", str(port)], _env(tmp_path))
    assert result.returncode == 0, result.stderr
    assert f"soc_console: http://127.0.0.1:{port}/" in result.stdout
    assert f"contract_health: http://127.0.0.1:{port}/healthz" in result.stdout
    assert "/api/v1/soar/verify-state" in result.stdout
    assert "/api/v1/soar/callback" in result.stdout
    assert "run_misp_and_callback_contract_server.py" in result.stdout
    assert "dry-run: preflight passed; no process was started." in result.stdout
    ledger = tmp_path / "threatfusion-live-soar.sqlite3"
    assert f"soar_ledger: {ledger}" in result.stdout
    assert _port_open(port) is False
    assert not (tmp_path / f"threatfusion-live-product-{port}.pid").exists()


def test_dry_run_rejects_a_busy_port_a_short_secret_and_a_bad_port(tmp_path: Path) -> None:
    _require_launcher()
    port = _free_port()
    holder = socket.socket()
    holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    holder.bind(("127.0.0.1", port))
    holder.listen(1)
    try:
        busy = _run(["--dry-run", "--port", str(port)], _env(tmp_path))
    finally:
        holder.close()
    assert busy.returncode == 1
    assert "already in use" in busy.stderr

    short = _env(tmp_path)
    short["THREATFUSION_SOAR_HMAC_SECRET"] = "too-short"
    rejected = _run(["--dry-run", "--port", str(_free_port())], short)
    assert rejected.returncode == 1
    assert "THREATFUSION_SOAR_HMAC_SECRET must be at least 16 characters" in rejected.stderr

    invalid = _run(["--dry-run", "--port", "0"], _env(tmp_path))
    assert invalid.returncode == 1
    assert "outside 1-65535" in invalid.stderr

    unknown = _run(["--not-a-mode"], _env(tmp_path))
    assert unknown.returncode == 2
    assert "unknown argument" in unknown.stderr


def test_seed_demo_stores_four_scenarios_and_stays_up(tmp_path: Path) -> None:
    _require_launcher()
    port = _free_port()
    proc = subprocess.Popen(
        [str(SCRIPT), "--seed-demo", "--port", str(port)],
        cwd=REPO_ROOT,
        env=_env(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        seen = ""
        deadline = time.time() + 60
        assert proc.stdout is not None
        while time.time() < deadline and "seed-demo: four scenarios stored" not in seen:
            line = proc.stdout.readline()
            if not line:
                break
            seen += line
        assert "seed-demo: four scenarios stored" in seen
        assert _port_open(port) is True
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            proc.communicate(timeout=10)


def test_smoke_starts_console_and_contract_then_releases_the_port(tmp_path: Path) -> None:
    _require_launcher()
    port = _free_port()
    result = _run(["--smoke", "--port", str(port)], _env(tmp_path))
    assert result.returncode == 0, result.stderr
    assert "both responded" in result.stdout
    assert "shutdown released" in result.stdout
    assert _port_open(port) is False
    assert not (tmp_path / f"threatfusion-live-product-{port}.pid").exists()


def test_sigterm_stops_the_shared_process_and_exports_one_ledger(tmp_path: Path) -> None:
    _require_launcher()
    port = _free_port()
    proc = subprocess.Popen(
        [str(SCRIPT), "--port", str(port)],
        cwd=REPO_ROOT,
        env=_env(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        page = _wait_http(f"http://127.0.0.1:{port}/", "ThreatFusion SOC Console")
        health = _wait_http(f"http://127.0.0.1:{port}/healthz", '"status": "ok"')
        assert "ThreatFusion SOC Console" in page
        assert "threatfusion_soc_contract_server" in health
        pid_text = (tmp_path / f"threatfusion-live-product-{port}.pid").read_text(encoding="utf-8")
        server_pid = int(pid_text.strip())
        environ = Path(f"/proc/{server_pid}/environ").read_bytes().split(b"\0")
        ledger = str(tmp_path / "threatfusion-live-soar.sqlite3").encode()
        assert b"THREATFUSION_SOAR_LEDGER_DB_PATH=" + ledger in environ
        proc.send_signal(signal.SIGTERM)
        _stdout, stderr = proc.communicate(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=5)
    assert proc.returncode == 0
    assert "Shutting down the SOC console and the contract server" in stderr
    assert _port_open(port) is False
