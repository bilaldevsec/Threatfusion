"""Wave B regressions for WP-P0-05 (Cross-OS macOS/Linux) & WP-P0-06 (Multi-Cloud)."""

from __future__ import annotations

import ast
import errno
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from threatfusion.operations import (
    _posix_safety,
    audit_retention,
    human_browser_provisioning as prov_ops,
    human_ca_issuance as ca_ops,
    human_credentials,
    storage_backup,
)
from threatfusion.operations.bridge_noise import is_lab_bridge_noise

REPO_ROOT = Path(__file__).resolve().parents[3]
VENV_PYTHON = REPO_ROOT / "threatfusion-venv" / "bin" / "python"
PYTHON_BIN = VENV_PYTHON if VENV_PYTHON.is_file() else Path(sys.executable)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _write_executable(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


# ---------------------------------------------------------------------------
# Task 1: pyproject.toml + uv.lock (TF-015 byte-identical Linux torch hashes)
# ---------------------------------------------------------------------------


def test_pyproject_and_uv_lock_cross_os_torch_markers_and_linux_hashes() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    assert project["version"] == "1.1.0"
    assert (
        project["description"]
        == "ThreatFusion: AI-assisted SOC alert triage and approval-gated SOAR platform"
    )
    assert project["license"] == "MIT"
    assert project["readme"] == "README.md"

    deps = project["dependencies"]
    assert "scikit-learn>=1.9.0" in deps
    assert "torch==2.10.0+cpu; sys_platform == 'linux'" in deps
    assert "torch==2.10.0; sys_platform != 'linux'" in deps
    assert "torch==2.10.0+cpu" not in deps

    assert pyproject["tool"]["setuptools"]["package-dir"]["src"] == "src"
    assert pyproject["tool"]["uv"]["sources"]["torch"] == [
        {"index": "pytorch-cpu", "marker": "sys_platform == 'linux'"}
    ]

    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    torch_pkgs = [pkg for pkg in lock["package"] if pkg.get("name") == "torch"]
    by_version = {pkg["version"]: pkg for pkg in torch_pkgs}
    assert "2.10.0+cpu" in by_version
    assert "2.10.0" in by_version

    linux_wheels = {
        Path(w["url"]).name: w["hash"] for w in by_version["2.10.0+cpu"].get("wheels", [])
    }
    expected_linux_hashes = {
        "torch-2.10.0%2Bcpu-cp311-cp311-manylinux_2_28_x86_64.whl": (
            "sha256:b7cb1ec66cefb90fd7b676eac72cfda3b8d4e4d0cacd7a531963bc2e0a9710ab"
        ),
        "torch-2.10.0%2Bcpu-cp311-cp311-manylinux_2_28_aarch64.whl": (
            "sha256:1cfcb9b1558c6e52dffd0d4effce83b13c5ae5d97338164c372048c21f9cfccb"
        ),
        "torch-2.10.0%2Bcpu-cp311-cp311-linux_aarch64.whl": (
            "sha256:ce5c113d1f55f8c1f5af05047a24e50d11d293e0cbbb5bf7a75c6c761edd6eaa"
        ),
        "torch-2.10.0%2Bcpu-cp311-cp311-linux_s390x.whl": (
            "sha256:0e286fcf6ce0cc7b204396c9b4ea0d375f1f0c3e752f68ce3d3aeb265511db8c"
        ),
    }
    for wheel_name, expected_hash in expected_linux_hashes.items():
        assert linux_wheels.get(wheel_name) == expected_hash


# ---------------------------------------------------------------------------
# Task 2: _posix_safety.py + 5 operations/ modules
# ---------------------------------------------------------------------------


def test_posix_safety_is_pure_stdlib_with_zero_advisory_imports() -> None:
    src_path = REPO_ROOT / "backend" / "src" / "threatfusion" / "operations" / "_posix_safety.py"
    source = src_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                assert root in sys.stdlib_module_names
        elif isinstance(node, ast.ImportFrom):
            assert node.module is not None
            root = node.module.split(".", 1)[0]
            assert root in sys.stdlib_module_names or root == "__future__"
    for forbidden in ("advisory", "gemini_client", "explanation_engine", "chromadb"):
        assert forbidden not in source


def test_resolve_openssl_bin_and_sterile_env_darwin_and_linux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_posix_safety.sys, "platform", "darwin")
    monkeypatch.setattr(
        _posix_safety.os.path,
        "isfile",
        lambda p: p in {"/usr/local/opt/openssl@3/bin/openssl", "/usr/bin/openssl"},
    )
    monkeypatch.setattr(_posix_safety.os, "access", lambda _p, _m: True)
    resolved = _posix_safety._resolve_openssl_bin()
    assert resolved == "/usr/local/opt/openssl@3/bin/openssl"
    env = _posix_safety._sterile_openssl_env(resolved)
    assert env["LC_ALL"] == "C"
    assert env["PATH"].split(os.pathsep) == [
        "/usr/local/opt/openssl@3/bin",
        "/usr/bin",
        "/bin",
    ]

    monkeypatch.setattr(_posix_safety.sys, "platform", "linux")
    monkeypatch.setattr(_posix_safety.os.path, "isfile", lambda p: p == "/usr/bin/openssl")
    assert _posix_safety._resolve_openssl_bin() == "/usr/bin/openssl"
    assert _posix_safety._sterile_openssl_env("/usr/bin/openssl")["PATH"] == "/usr/bin:/bin"


def test_normalize_darwin_system_prefix_preserves_user_symlinks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sample = Path("/var/folders/ab/cd/T/tf-run/alias")
    # On Linux, prefix normalization is a strict no-op.
    monkeypatch.setattr(_posix_safety.sys, "platform", "linux")
    assert _posix_safety.normalize_darwin_system_prefix(sample) == sample

    # On macOS, root-owned /tmp, /var, /etc firmlinks rewrite ONLY the leading OS prefix.
    monkeypatch.setattr(_posix_safety.sys, "platform", "darwin")
    monkeypatch.setattr(
        _posix_safety.os,
        "lstat",
        lambda p: SimpleNamespace(st_mode=stat.S_IFLNK | 0o755, st_uid=0),
    )
    monkeypatch.setattr(
        _posix_safety.os,
        "readlink",
        lambda p: f"private/{Path(p).name}",
    )
    normalized = _posix_safety.normalize_darwin_system_prefix(sample)
    assert normalized == Path("/private/var/folders/ab/cd/T/tf-run/alias")

    # Non-root-owned top-level symlinks are never rewritten.
    monkeypatch.setattr(
        _posix_safety.os,
        "lstat",
        lambda p: SimpleNamespace(st_mode=stat.S_IFLNK | 0o755, st_uid=1000),
    )
    assert _posix_safety.normalize_darwin_system_prefix(sample) == sample

    # Real user symlink inside a normalized prefix is still caught by O_NOFOLLOW.
    real_dir = tmp_path / "real"
    real_dir.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(real_dir)
    dir_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(OSError) as exc_info:
            _posix_safety.open_private_leaf_nofollow(dir_fd, "alias", os.O_RDONLY)
        assert exc_info.value.errno in (errno.ELOOP, errno.ENOTDIR)
    finally:
        os.close(dir_fd)


def test_operations_modules_wire_posix_safety_and_homebrew_nss(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: list[Path] = []

    def _spy(p: Path) -> Path:
        seen.append(p)
        return _posix_safety.normalize_darwin_system_prefix(p)

    for mod in (human_credentials, ca_ops, prov_ops, audit_retention, storage_backup):
        monkeypatch.setattr(mod, "normalize_darwin_system_prefix", _spy)

    d = tmp_path / "d"
    d.mkdir(mode=0o700)
    with pytest.raises(ca_ops.HumanCaIssuanceError):
        ca_ops.verify_human_ca(d)
    assert d in seen

    seen.clear()
    with pytest.raises(prov_ops.HumanBrowserProvisioningError):
        prov_ops.verify_firefox_profile(d)
    assert d in seen

    seen.clear()
    with pytest.raises(audit_retention.AuditRetentionError):
        audit_retention._validate_audit_db_path(d / "missing.sqlite3")
    assert d / "missing.sqlite3" in seen

    seen.clear()
    with pytest.raises(storage_backup.StorageBackupError):
        storage_backup.verify_storage_snapshot(d)
    assert d in seen

    seen.clear()
    assert human_credentials.active_fingerprint(d, "analyst_a") is None
    assert d in seen

    # _run_nss_command includes Homebrew NSS dirs while missing NSS tools still fails closed.
    captured_envs: list[dict[str, str]] = []

    def _fake_subproc_run(argv, **kwargs):
        captured_envs.append(dict(kwargs.get("env") or {}))
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(prov_ops.subprocess, "run", _fake_subproc_run)
    proc = prov_ops._run_nss_command(["certutil", "-L"])
    assert proc.returncode == 0
    path_parts = captured_envs[0]["PATH"].split(os.pathsep)
    assert "/opt/homebrew/opt/nss/bin" in path_parts
    assert "/usr/local/opt/nss/bin" in path_parts

    monkeypatch.setattr(prov_ops.shutil, "which", lambda _name: None)
    with pytest.raises(prov_ops.HumanBrowserProvisioningError, match="nss_tools_missing"):
        prov_ops._refuse_missing_nss_tools(None, None)


# ---------------------------------------------------------------------------
# Task 3: POSIX Launchers & Local Range Auth
# ---------------------------------------------------------------------------


def test_shell_scripts_syntax_and_zero_gnu_only_bashisms() -> None:
    scripts = list((REPO_ROOT / "scripts").glob("*.sh"))
    assert scripts
    for script in scripts:
        res = subprocess.run(
            ["bash", "-n", str(script)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0, f"{script.name}: {res.stderr}"

    entry = REPO_ROOT / "docker" / "range" / "entrypoint-victim.sh"
    res_entry = subprocess.run(
        ["sh", "-n", str(entry)], capture_output=True, text=True, check=False
    )
    assert res_entry.returncode == 0, res_entry.stderr
    entry_text = entry.read_text(encoding="utf-8")
    assert "set -eu" in entry_text
    assert "ethtool -K eth0 gro off lro off tso off gso off" in entry_text

    for rel in (
        "scripts/run_live_product.sh",
        "scripts/run_full_range_demo.sh",
        "scripts/deploy_cloud_range.sh",
        "scripts/deploy_azure_cyber_range.sh",
    ):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "stat -c" not in text, rel
        assert "mapfile" not in text, rel
        assert "ss -ltn" not in text, rel
        assert "${offline,,}" not in text, rel
        assert "Pakistan Standard Time" not in text, rel
        assert "/usr/bin/python3" not in text, rel
        assert "id_ed25519" not in text or "threatfusion-range-ed25519" in text, rel


def test_run_live_product_strips_trailing_slash_from_macos_tmpdir(tmp_path: Path) -> None:
    port = _free_port()
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("THREATFUSION_SOAR_LEDGER_DB_PATH", None)
    env.pop("THREATFUSION_LIVE_CONSOLE_DB", None)
    env["TMPDIR"] = f"{tmp_path}/"
    env["THREATFUSION_PYTHON"] = str(PYTHON_BIN)

    res = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "run_live_product.sh"),
            "--dry-run",
            "--port",
            str(port),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stderr
    assert f"live_db: {tmp_path}/threatfusion-live-console.sqlite3" in res.stdout
    assert f"soar_ledger: {tmp_path}/threatfusion-live-soar.sqlite3" in res.stdout
    assert f"{tmp_path}//" not in res.stdout


def test_run_full_range_demo_approver_session_auth_and_scan_attack(tmp_path: Path) -> None:
    from scripts.run_misp_and_callback_contract_server import MispAndCallbackContractHandler

    # 1. Verify login_lab_approver_session against the real contract server handler
    live_db = tmp_path / "live.sqlite3"
    saved_env = {
        k: os.environ.get(k)
        for k in ("THREATFUSION_LIVE_CONSOLE_DB", "THREATFUSION_ENV", "THREATFUSION_DATA_DIR")
    }
    os.environ["THREATFUSION_LIVE_CONSOLE_DB"] = str(live_db)
    os.environ["THREATFUSION_ENV"] = "lab"
    os.environ["THREATFUSION_DATA_DIR"] = str(tmp_path)

    real_srv = ThreadingHTTPServer(("127.0.0.1", 0), MispAndCallbackContractHandler)
    real_thread = threading.Thread(target=real_srv.serve_forever, daemon=True)
    real_thread.start()
    real_port = real_srv.server_address[1]
    demo_dir = tmp_path / "demo_real"
    demo_dir.mkdir(mode=0o700)
    try:
        login_probe = subprocess.run(
            [
                "bash",
                "-c",
                f"""
                set -euo pipefail
                PORT={real_port}
                PYTHON={PYTHON_BIN!s}
                DEMO_DIR={demo_dir!s}
                die() {{ echo "$*" >&2; exit 1; }}
                eval "$(sed -n '/^LAB_COOKIE_JAR=/,/^}}/p' "$1")"
                eval "$(sed -n '/^login_lab_approver_session()/,/^}}/p' "$1")"
                login_lab_approver_session 127.0.0.1
                test -n "$LAB_SESSION_TOKEN"
                test -n "$LAB_CSRF_TOKEN"
                test -f "$LAB_COOKIE_JAR"
                mode="$(python3 -c 'import os,stat,sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))' "$LAB_COOKIE_JAR")"
                echo "cookie_jar=$LAB_COOKIE_JAR mode=$mode token_len=${{#LAB_SESSION_TOKEN}}"
                """,
                "bash",
                str(REPO_ROOT / "scripts" / "run_full_range_demo.sh"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert login_probe.returncode == 0, login_probe.stderr + login_probe.stdout
        assert "mode=0o600" in login_probe.stdout
        cookie_path = Path(login_probe.stdout.split("cookie_jar=")[1].split(" ")[0])
        assert not cookie_path.exists()
    finally:
        real_srv.shutdown()
        real_srv.server_close()
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # 2. Verify --scan and --attack send authenticated headers & cookie and fail on 401
    recorded_requests: list[tuple[str, dict[str, str], str]] = []

    class _StubRangeHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/api/v1/live/health":
                body = json.dumps({"status": "ok", "csrf_token": "csrf-tok-123"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length).decode("utf-8")
            hdrs = {k.lower(): v for k, v in self.headers.items()}
            recorded_requests.append((self.path, hdrs, raw))
            if self.path == "/api/rbac/login":
                body = json.dumps(
                    {
                        "authenticated": True,
                        "session_token": "sess-approver-xyz",
                        "csrf_token": "csrf-tok-456",
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "tf_session=cookieval; Path=/; HttpOnly")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if (
                hdrs.get("x-threatfusion-session") == "sess-approver-xyz"
                and hdrs.get("x-threatfusion-csrf") == "csrf-tok-456"
                and "tf_session=cookieval" in hdrs.get("cookie", "")
            ):
                body = json.dumps({"ingested": True, "decision": "Attack"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(401)
            self.end_headers()

    stub = ThreadingHTTPServer(("127.0.0.1", 0), _StubRangeHandler)
    stub_thread = threading.Thread(target=stub.serve_forever, daemon=True)
    stub_thread.start()
    stub_port = stub.server_address[1]

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_executable(fake_bin / "docker", "#!/bin/sh\necho true\n")

    demo_tmp = tmp_path / "tmp"
    demo_tmp.mkdir()
    demo_state = demo_tmp / "threatfusion-range-demo"
    demo_state.mkdir(mode=0o700)
    (demo_state / "bind-host").write_text("127.0.0.1\n", encoding="utf-8")

    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    env["TMPDIR"] = f"{demo_tmp}/"
    env["PORT"] = str(stub_port)
    env["THREATFUSION_PYTHON"] = str(PYTHON_BIN)

    try:
        scan_res = subprocess.run(
            ["bash", str(REPO_ROOT / "scripts" / "run_full_range_demo.sh"), "--scan"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert scan_res.returncode == 0, scan_res.stderr + scan_res.stdout

        atk_res = subprocess.run(
            ["bash", str(REPO_ROOT / "scripts" / "run_full_range_demo.sh"), "--attack", "T1046"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert atk_res.returncode == 0, atk_res.stderr + atk_res.stdout
    finally:
        stub.shutdown()
        stub.server_close()

    paths = [item[0] for item in recorded_requests]
    assert "/api/v1/live/range-scan" in paths
    assert "/api/v1/live/range/launch-vector" in paths
    assert not list(demo_state.glob("lab-cookies.*"))


# ---------------------------------------------------------------------------
# Task 4: Multi-Cloud AWS / GCP / Azure / BYOH + bridge_noise.py
# ---------------------------------------------------------------------------


def test_deploy_cloud_range_ssh_key_isolation_and_byoh_precedence(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    state_dir = tmp_path / "state"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    # Pretend all cloud CLIs are logged in; --victim-host must still win!
    _write_executable(fake_bin / "az", "#!/bin/sh\nexit 0\n")
    _write_executable(fake_bin / "aws", "#!/bin/sh\nexit 0\n")
    _write_executable(fake_bin / "gcloud", "#!/bin/sh\necho my-project\n")

    env = os.environ.copy()
    env["HOME"] = str(fake_home)
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    env["THREATFUSION_CLOUD_STATE_DIR"] = str(state_dir)

    # 1. --victim-host without --provider picks generic BEFORE az/aws/gcloud
    res_byoh = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_cloud_range.sh"),
            "--dry-run",
            "--victim-host",
            "203.0.113.20",
            "--attacker-host",
            "203.0.113.10",
            "--provision-range",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_byoh.returncode == 0, res_byoh.stderr
    assert "provider=generic" in res_byoh.stdout

    # 2. --provider ssh alias + deploy-full-stack dry-run uses isolated key path
    res_ssh = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_cloud_range.sh"),
            "--dry-run",
            "--provider",
            "ssh",
            "--victim-host",
            "203.0.113.20",
            "--attacker-host",
            "203.0.113.10",
            "--deploy-full-stack",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_ssh.returncode == 0, res_ssh.stderr
    assert f"{state_dir}/threatfusion-range-ed25519" in res_ssh.stdout
    assert not (fake_home / ".ssh").exists()

    # 3. Real key creation writes ONLY ${STATE_DIR}/threatfusion-range-ed25519 (mode 0600)
    #    and --victim-host overrides stale azure cloud_state.json
    state_dir.mkdir(parents=True)
    (state_dir / "cloud_state.json").write_text(
        json.dumps(
            {
                "provider": "azure",
                "victim_public_ip": "198.51.100.99",
                "ssh_user": "azureuser",
            }
        ),
        encoding="utf-8",
    )
    res_status = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_cloud_range.sh"),
            "--victim-host",
            "203.0.113.20",
            "--status",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_status.returncode == 0, res_status.stderr
    updated = json.loads((state_dir / "cloud_state.json").read_text(encoding="utf-8"))
    assert updated["provider"] == "generic"
    assert updated["victim_public_ip"] == "203.0.113.20"
    assert updated["ssh_user"] == "ubuntu"

    # 4. teardown_generic passes ssh_args (-i isolated_key) and AWS prefers ${STATE_DIR}/${RANGE_TAG}.pem
    ssh_log = tmp_path / "ssh.log"
    _write_executable(fake_bin / "ssh", f'#!/bin/sh\necho "$@" >> "{ssh_log}"\nexit 0\n')
    res_td = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_cloud_range.sh"),
            "--provider",
            "generic",
            "--victim-host",
            "203.0.113.20",
            "--teardown",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_td.returncode == 0, res_td.stderr
    isolated_key = state_dir / "threatfusion-range-ed25519"
    assert isolated_key.is_file()
    assert stat.S_IMODE(isolated_key.stat().st_mode) == 0o600
    assert not (fake_home / ".ssh").exists()
    assert f"-i {isolated_key}" in ssh_log.read_text(encoding="utf-8")

    aws_pem = state_dir / "threatfusion-range.pem"
    aws_pem.write_text("dummy", encoding="utf-8")
    aws_pem.chmod(0o600)
    pem_check = subprocess.run(
        [
            "bash",
            "-c",
            f"""
            set -euo pipefail
            STATE_DIR={state_dir!s}
            RANGE_TAG="threatfusion-range"
            PROVIDER="aws"
            DRY_RUN=1
            eval "$(sed -n '/^ensure_admin_ssh_key()/,/^}}/p' "$1")"
            ensure_admin_ssh_key
            echo "SSH_IDENTITY=$SSH_IDENTITY"
            """,
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_cloud_range.sh"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert pem_check.returncode == 0, pem_check.stderr
    assert f"SSH_IDENTITY={aws_pem}" in pem_check.stdout


def test_deploy_cloud_range_aws_and_gcp_remediations(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    aws_log = tmp_path / "aws.log"
    gcloud_log = tmp_path / "gcloud.log"

    _write_executable(
        fake_bin / "aws",
        f"""#!/usr/bin/env python3
import sys
with open({str(aws_log)!r}, "a", encoding="utf-8") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\\n")
args = sys.argv[1:]
if "get-caller-identity" in args:
    print('{{"Account": "123456789012"}}')
elif "describe-vpcs" in args:
    print("vpc-123")
elif "describe-subnets" in args:
    print("subnet-123")
elif "describe-internet-gateways" in args:
    print("igw-123")
elif "describe-route-tables" in args:
    print("rtb-123")
elif "describe-security-groups" in args:
    print("sg-123")
elif "get-parameter" in args:
    print("ami-0abc")
elif "describe-images" in args:
    print("/dev/sda1")
elif "describe-instances" in args:
    if "Name=tag:Name,Values=tf-soc-victim-vm" in args or "Name=tag:Name,Values=tf-attacker-redteam-vm" in args:
        print("None")
    elif "--instance-ids" in args:
        print("203.0.113.55")
    else:
        print("i-111 i-222")
elif "run-instances" in args:
    print("i-new")
""",
    )
    _write_executable(
        fake_bin / "gcloud",
        f"""#!/usr/bin/env python3
import sys
with open({str(gcloud_log)!r}, "a", encoding="utf-8") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\\n")
args = sys.argv[1:]
if args[:3] == ["config", "get-value", "project"]:
    print("tf-test-project")
elif args[:3] == ["config", "get-value", "account"]:
    print("ops@example.com")
elif args[:3] == ["config", "get-value", "compute/region"]:
    print("us-central1")
elif args[:3] == ["compute", "instances", "describe"]:
    if "--format=get(networkInterfaces[0].accessConfigs[0].natIP)" in args:
        print("203.0.113.77")
        sys.exit(0)
    sys.exit(1)
elif args[:3] == ["compute", "firewall-rules", "describe"]:
    sys.exit(1)
""",
    )

    state_dir = tmp_path / "state"
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    env["THREATFUSION_CLOUD_STATE_DIR"] = str(state_dir)
    env["CLOUD_ADMIN_SSH_CIDR"] = "203.0.113.1/32"

    # AWS default (t3.small, amd64, 24 GiB gp3, intra-subnet SG, volume tags)
    res_aws = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_cloud_range.sh"),
            "--provider",
            "aws",
            "--provision-range",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_aws.returncode == 0, res_aws.stderr
    aws_calls = aws_log.read_text(encoding="utf-8")
    assert "--protocol -1 --cidr 172.29.0.0/24" in aws_calls
    assert "--instance-type t3.small" in aws_calls
    assert "/stable/current/amd64/hvm/ebs-gp3/ami-id" in aws_calls
    assert '"VolumeSize":24' in aws_calls and '"VolumeType":"gp3"' in aws_calls
    assert '"DeleteOnTermination":true' in aws_calls
    assert (
        "ResourceType=volume,Tags=[{Key=Name,Value=tf-soc-victim-vm},{Key=Project,Value=threatfusion-range}]"
        in aws_calls
    )

    # AWS Graviton ARM64 + teardown vpc-id / tag:Project checks
    aws_log.unlink()
    env_arm = dict(env, CLOUD_INSTANCE_TYPE="t4g.small")
    res_arm = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_cloud_range.sh"),
            "--provider",
            "aws",
            "--provision-range",
        ],
        cwd=REPO_ROOT,
        env=env_arm,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_arm.returncode == 0, res_arm.stderr
    assert "/stable/current/arm64/hvm/ebs-gp3/ami-id" in aws_log.read_text(encoding="utf-8")

    aws_log.unlink()
    res_aws_td = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_cloud_range.sh"),
            "--provider",
            "aws",
            "--teardown",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_aws_td.returncode == 0, res_aws_td.stderr
    td_calls = aws_log.read_text(encoding="utf-8")
    assert (
        "describe-security-groups --region us-east-1 --filters Name=vpc-id,Values=vpc-123 Name=group-name,Values=threatfusion-range"
        in td_calls
    )
    assert (
        "describe-volumes --region us-east-1 --filters Name=tag:Project,Values=threatfusion-range Name=status,Values=available"
        in td_calls
    )

    # GCP provision + ARM + teardown
    res_gcp = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_cloud_range.sh"),
            "--provider",
            "gcp",
            "--provision-range",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_gcp.returncode == 0, res_gcp.stderr
    gcp_calls = gcloud_log.read_text(encoding="utf-8")
    assert (
        "firewall-rules create threatfusion-range-internal --network threatfusion-range --allow tcp,udp,icmp --source-ranges 172.29.0.0/24 --target-tags threatfusion-range"
        in gcp_calls
    )
    assert (
        "--image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --boot-disk-size 24GB"
        in gcp_calls
    )
    assert "--metadata ssh-keys=ubuntu:" in gcp_calls

    gcloud_log.unlink()
    env_gcp_arm = dict(env, CLOUD_INSTANCE_TYPE="t2a-standard-1")
    res_gcp_arm = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_cloud_range.sh"),
            "--provider",
            "gcp",
            "--provision-range",
        ],
        cwd=REPO_ROOT,
        env=env_gcp_arm,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_gcp_arm.returncode == 0, res_gcp_arm.stderr
    assert "--image-family ubuntu-2404-lts-arm64" in gcloud_log.read_text(encoding="utf-8")

    gcloud_log.unlink()
    res_gcp_td = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_cloud_range.sh"),
            "--provider",
            "gcp",
            "--teardown",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_gcp_td.returncode == 0, res_gcp_td.stderr
    gcp_td_calls = gcloud_log.read_text(encoding="utf-8")
    assert gcp_td_calls.index(
        "firewall-rules delete threatfusion-range-internal"
    ) < gcp_td_calls.index("networks delete threatfusion-range")


def test_azure_low_cost_tier_location_and_pair_forwarder_suricata_offload() -> None:
    env = os.environ.copy()
    env["AZURE_LOCATION"] = "eastus"
    env["AZURE_AUTO_SHUTDOWN_UTC"] = "1930"
    res = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_azure_cyber_range.sh"),
            "--dry-run",
            "--low-cost-tier",
            "--provision",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stderr
    assert "--location eastus" in res.stdout
    assert "--time 1930 --timezone UTC" in res.stdout

    res_alias = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_azure_cyber_range.sh"),
            "--dry-run",
            "--student-free-tier",
            "--provision",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_alias.returncode == 0, res_alias.stderr

    res_pair = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deploy_azure_cyber_range.sh"),
            "--dry-run",
            "--pair-forwarder",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res_pair.returncode == 0, res_pair.stderr
    assert "suricata ethtool python3 python3-venv" in res_pair.stdout
    assert "python3 -m venv /opt/threatfusion-venv" in res_pair.stdout
    assert "PRIMARY_NIC=" in res_pair.stdout
    assert "checksum-validation: no" in res_pair.stdout
    assert (
        "ExecStartPre=-${ETHTOOL_BIN} -K ${PRIMARY_NIC} gro off lro off tso off gso off"
        in res_pair.stdout
    )
    assert "chown -R suricata:suricata /var/log/suricata" in res_pair.stdout

    azure_text = (REPO_ROOT / "scripts" / "deploy_azure_cyber_range.sh").read_text(encoding="utf-8")
    assert '"${ADMIN_USER}@${public_ip}"' in azure_text
    assert "COPYFILE_DISABLE=1 tar" in (REPO_ROOT / "scripts" / "deploy_cloud_range.sh").read_text(
        encoding="utf-8"
    )


def test_bridge_noise_filters_all_multicloud_metadata_and_ipv4_mapped_ips() -> None:
    cloud_ips = (
        "169.254.169.254",
        "169.254.169.253",
        "169.254.169.123",
        "169.254.170.2",
        "168.63.129.16",
        "fd00:ec2::254",
        "100.100.100.200",
        "::ffff:169.254.169.254",
        "::ffff:168.63.129.16",
        "::ffff:100.100.100.200",
    )
    for ip in cloud_ips:
        assert is_lab_bridge_noise(ip, "172.29.0.20", 44120, 80) is True
        assert is_lab_bridge_noise("172.29.0.20", ip, 80, 44120) is True

    assert is_lab_bridge_noise("172.29.0.10", "172.29.0.20", 44120, 80) is False
    assert is_lab_bridge_noise("::ffff:172.29.0.10", "::ffff:172.29.0.20", 44120, 80) is False
