"""Commercial posture, login defense, cold-boot data directory, and /readyz.

Lab is the local default. Production hides demo quick-fill, refuses the
hardcoded TF-* access codes, and keeps a one-time bootstrap admin secret in
the data directory. Detection stays on the frozen Random Forest.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
import time
from collections.abc import Mapping
from typing import Any

from threatfusion.models.drift_and_supply_chain import (
    FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY,
    verify_frozen_model_supply_chain,
)

FIXTURE_RELATIVE = "artifacts/benchmarks/unsw_nb15_calibrated_runtime_fixtures.json"
FIXTURE_SHA256 = "0c38310e84c6869947cc60118a3e2dec91577757c81aded654757ea7ecabcaf6"
DNN_MODEL_RELATIVE = "artifacts/models/fyp2_dnn_same_split_v1/dnn_model.pt"
DNN_MODEL_SHA256 = "614850ad84fc4ab32dc6e6d2318900668d97cad6edba37290ed9fe2b2482df1f"
MODEL_SIZE_LIMIT_BYTES = 50 * 1024 * 1024
HELD_OUT_ROWS = 507846
ADVISORY_TRACE_DOSSIER_LINE = (
    "Advisory Trace (Decision writes: 0, Frozen RF authoritative, Gate G9: PASS)"
)
READYZ_PILL = "DB WAL · Models 4/4 · RAG Ready"
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
DEMO_ACCESS_CODES = frozenset(
    {
        "TF-Bilal-3551!",
        "TF-Suhaib-4302!",
        "TF-Hasnain-4718!",
    }
)
KNOWN_DEMO_PASSWORD_HASHES = frozenset(
    {
        "pbkdf2_sha256$200000$d283503ed41d21060378e6b7ef6a2419$"
        "d9f6ec94ab33018220a30e221f64b314c73a7180baeacc7bb6dc71a191702e3c",
        "pbkdf2_sha256$200000$9171434638ae2e75de01dece752454f7$"
        "9a22959b9157c4cd18d8b9128acb70b07109f83dcc7fe2d86b7cde12573f9ad2",
        "pbkdf2_sha256$200000$cff7d4adbff740379d5de2ca263fb9f0$"
        "ab4e39aed30043977308f150fffbc18433ba98b91b54c2384f2af1a3c20c7d78",
    }
)
_AUTH_EVENTS = frozenset(
    {"login_success", "login_failed", "login_rate_limited", "operator_registered"}
)
_LOGIN_LIMIT = 5
_LOGIN_WINDOW_SECONDS = 60.0


def threatfusion_environment() -> str:
    """Return lab unless THREATFUSION_ENV is exactly production."""
    raw = os.environ.get("THREATFUSION_ENV", "lab").strip().lower()
    if raw == "production":
        return "production"
    return "lab"


def demo_passwords_enabled() -> bool:
    return threatfusion_environment() != "production"


def demo_password_rejected(password: str) -> bool:
    """Production refuses the three hardcoded lab access codes."""
    if demo_passwords_enabled():
        return False
    return str(password or "") in DEMO_ACCESS_CODES


def console_posture() -> dict[str, Any]:
    production = threatfusion_environment() == "production"
    return {
        "schema_version": "console_posture_v1",
        "environment": "production" if production else "lab",
        "posture_label": ("POSTURE: PRODUCTION HARDENED" if production else "POSTURE: LAB DEMO"),
        "demo_quickfill_enabled": not production,
        "demo_passwords_accepted": not production,
        "production_fusion_enabled": False,
        "http_status": 200,
    }


def apply_posture_to_index(page: str) -> str:
    """Stamp the posture pill and hide demo cards when the process is production."""
    import re

    posture = console_posture()
    rendered = page.replace("POSTURE: LAB DEMO", str(posture["posture_label"]))
    rendered = rendered.replace("POSTURE: PRODUCTION HARDENED", str(posture["posture_label"]))
    if posture["demo_quickfill_enabled"]:
        return rendered
    rendered = rendered.replace(
        'id="demoQuickFill" class="demo-credential-box role-quick-grid"',
        'id="demoQuickFill" class="demo-credential-box role-quick-grid" hidden',
    )
    return re.sub(r'data-demo-code="[^"]*"', 'data-demo-code=""', rendered)


def resolve_data_dir() -> Path:
    """Prefer THREATFUSION_DATA_DIR, then /var/lib/threatfusion, then the lab tmp dir."""
    configured = os.environ.get("THREATFUSION_DATA_DIR", "").strip()
    if configured:
        path = Path(configured)
    else:
        preferred = Path("/var/lib/threatfusion")
        path = preferred
        try:
            preferred.mkdir(parents=True, exist_ok=True)
            probe = preferred / ".write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
        except OSError:
            path = Path("/tmp/threatfusion-range-demo")
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def _write_mode_0600(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def ensure_hmac_secret(data_dir: Path | None = None) -> Path:
    """Keep a mode-0600 HMAC secret when the environment variable is unset."""
    directory = data_dir or resolve_data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ".hmac_secret"
    existing = os.environ.get("THREATFUSION_SOAR_HMAC_SECRET", "").strip()
    if existing:
        if not path.is_file():
            _write_mode_0600(path, existing + "\n")
        else:
            try:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        return path
    if path.is_file() and not path.is_symlink():
        stored = path.read_text(encoding="utf-8").strip()
        if stored:
            os.environ["THREATFUSION_SOAR_HMAC_SECRET"] = stored
            try:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
            return path
    secret = secrets.token_hex(32)
    _write_mode_0600(path, secret + "\n")
    os.environ["THREATFUSION_SOAR_HMAC_SECRET"] = secret
    return path


def _bootstrap_secret_from_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("THREATFUSION_BOOTSTRAP_ADMIN="):
            return line.split("=", 1)[1].strip()
    return ""


def ensure_bootstrap_admin_secret(data_dir: Path | None = None) -> str:
    """Write a one-time 32-byte admin secret. Print it only on first creation."""
    directory = data_dir or resolve_data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ".env.runtime"
    stored = _bootstrap_secret_from_file(path)
    if stored:
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        return stored
    secret = secrets.token_hex(32)
    body = "THREATFUSION_ENV=production\n" f"THREATFUSION_BOOTSTRAP_ADMIN={secret}\n"
    _write_mode_0600(path, body)
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        print(f"ThreatFusion bootstrap admin secret (shown once): {secret}", flush=True)
    return secret


def apply_sqlite_pragmas(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA busy_timeout=5000")
    previous = conn.isolation_level
    conn.isolation_level = None
    conn.execute("PRAGMA journal_mode=WAL")
    conn.isolation_level = previous
    conn.execute("PRAGMA synchronous=NORMAL")


def ensure_auth_audit_schema(conn: sqlite3.Connection) -> None:
    """Immutable auth events. UPDATE and DELETE abort."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_audit_log (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            username TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            recorded_at_utc TEXT NOT NULL,
            detail TEXT NOT NULL
        )
        """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS auth_audit_log_block_update
        BEFORE UPDATE ON auth_audit_log
        BEGIN
            SELECT RAISE(ABORT, 'auth_audit_immutable');
        END
        """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS auth_audit_log_block_delete
        BEFORE DELETE ON auth_audit_log
        BEGIN
            SELECT RAISE(ABORT, 'auth_audit_immutable');
        END
        """)


def record_auth_event(
    conn: sqlite3.Connection,
    event_type: str,
    username: str,
    client_ip: str = "",
    detail: str = "",
) -> None:
    if event_type not in _AUTH_EVENTS:
        raise ValueError("auth_event_invalid")
    ensure_auth_audit_schema(conn)
    from datetime import UTC, datetime

    conn.execute(
        """
        INSERT INTO auth_audit_log (
            event_type, username, client_ip, recorded_at_utc, detail
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            event_type,
            str(username or "")[:180],
            str(client_ip or "")[:64],
            datetime.now(UTC).isoformat(),
            str(detail or "")[:120],
        ),
    )


def append_auth_event(
    db_path: Path,
    event_type: str,
    username: str,
    client_ip: str = "",
    detail: str = "",
) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        apply_sqlite_pragmas(conn)
        record_auth_event(conn, event_type, username, client_ip, detail)
        conn.commit()
    finally:
        conn.close()
    if db_path.exists():
        try:
            os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


class LoginRateLimiter:
    """Sliding window of failed logins. Five failures per 60s per IP or email."""

    def __init__(
        self, *, limit: int = _LOGIN_LIMIT, window_seconds: float = _LOGIN_WINDOW_SECONDS
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._events.clear()

    def _prune(self, key: str, now: float) -> list[float]:
        fresh = [stamp for stamp in self._events.get(key, []) if now - stamp < self.window_seconds]
        if fresh:
            self._events[key] = fresh
        else:
            self._events.pop(key, None)
        return fresh

    def rejected(self, client_ip: str, email: str, *, now: float | None = None) -> int | None:
        """Return Retry-After seconds when either key is already at the limit."""
        moment = time.monotonic() if now is None else now
        keys = [f"ip:{client_ip or 'unknown'}", f"email:{str(email or '').strip().lower()}"]
        with self._lock:
            waits: list[int] = []
            for key in keys:
                stamps = self._prune(key, moment)
                if len(stamps) >= self.limit:
                    retry = int(math.ceil(stamps[0] + self.window_seconds - moment))
                    waits.append(max(retry, 1))
            if not waits:
                return None
            return max(waits)

    def record_failure(self, client_ip: str, email: str, *, now: float | None = None) -> None:
        moment = time.monotonic() if now is None else now
        keys = [f"ip:{client_ip or 'unknown'}", f"email:{str(email or '').strip().lower()}"]
        with self._lock:
            for key in keys:
                stamps = self._prune(key, moment)
                stamps.append(moment)
                self._events[key] = stamps


LOGIN_RATE_LIMITER = LoginRateLimiter()


def reset_login_rate_limiter() -> None:
    LOGIN_RATE_LIMITER.reset()


def uniform_invalid_credentials() -> dict[str, Any]:
    """One body for every failed password login. Accounts are not enumerated."""
    return {
        "schema_version": "rbac_session_v1",
        "authenticated": False,
        "evidence_state": "unavailable",
        "reason": "invalid_credentials",
        "message": "Invalid credentials",
        "header_identity": "unverified local label",
        "identity_verified": False,
        "identity_label": "unverified_local_label",
        "certificate_subject": "",
        "production_fusion_enabled": False,
        "http_status": 401,
    }


def security_headers(*, cache_no_store: bool) -> list[tuple[str, str]]:
    headers = [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Content-Security-Policy", CONTENT_SECURITY_POLICY),
    ]
    if cache_no_store:
        headers.append(("Cache-Control", "no-store"))
    return headers


def _admin_ip() -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    raw = os.environ.get("SSH_CLIENT", "").strip()
    if not raw:
        raw = os.environ.get("SSH_CONNECTION", "").strip()
    token = raw.split()[0] if raw else ""
    if not token:
        return None
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


def isolation_refusal_reason(src_ip: str) -> str | None:
    """Return invalid_ip, protected_infrastructure_ip, or None when isolation may proceed."""
    raw = str(src_ip or "").strip()
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    try:
        parsed = ipaddress.ip_address(raw)
    except ValueError:
        return "invalid_ip"
    if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified or parsed.is_multicast:
        return "protected_infrastructure_ip"
    admin = _admin_ip()
    if admin is not None and parsed == admin:
        return "protected_infrastructure_ip"
    return None


def assert_isolation_command_safe(src_ip: str) -> str:
    """Canonical address safe to pass as an argv element. Never a shell string."""
    reason = isolation_refusal_reason(src_ip)
    if reason is not None:
        raise ValueError(reason)
    return str(ipaddress.ip_address(str(src_ip).strip()))


def guard_isolation_source(src_ip: str) -> dict[str, Any] | None:
    reason = isolation_refusal_reason(src_ip)
    if reason is None:
        return None
    return {
        "schema_version": "live_range_containment_v1",
        "evidence_state": "unavailable",
        "reason": reason,
        "error": reason,
        "message": reason,
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
        "target": str(src_ip or ""),
        "http_status": 400,
    }


def load_runtime_fixtures(repo_root: Path) -> dict[str, Any] | None:
    """Load the tracked scorecard. A digest mismatch returns None."""
    path = repo_root / FIXTURE_RELATIVE
    if path.is_symlink() or not path.is_file():
        return None
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != FIXTURE_SHA256:
        return None
    try:
        loaded = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(loaded, dict):
        return None
    if int(loaded.get("held_out_rows") or 0) != HELD_OUT_ROWS:
        return None
    if loaded.get("requires_raw_csv") is not False:
        return None
    return loaded


def runtime_scorecard_fallback(repo_root: Path) -> dict[str, Any]:
    """Held-out metrics and calibrated vectors without opening raw CSVs."""
    fixtures = load_runtime_fixtures(repo_root)
    if not isinstance(fixtures, dict):
        return {}
    score = fixtures.get("held_out_scorecard")
    if not isinstance(score, dict):
        return {}
    report = dict(score)
    vectors: dict[str, Any] = {}
    attack = fixtures.get("attack_vectors")
    if isinstance(attack, Mapping):
        for key, item in attack.items():
            if not isinstance(item, Mapping):
                continue
            canonical = item.get("canonical_features") or item.get("runtime_canonical_features")
            raw = item.get("raw_features") or item.get("runtime_raw_features")
            if isinstance(canonical, Mapping) and isinstance(raw, Mapping):
                vectors[str(key)] = {
                    "canonical_features": dict(canonical),
                    "raw_features": dict(raw),
                }
    report["scenario_vectors"] = vectors
    report["attack_cat_classes"] = list(report.get("attack_categories") or [])
    report["binary_metrics"] = {
        "accuracy": report.get("accuracy"),
        "precision": report.get("precision"),
        "recall": report.get("recall"),
        "f1": report.get("f1"),
        "fpr": report.get("fpr"),
        "confusion_matrix": report.get("confusion_matrix"),
    }
    report["production_fusion_enabled"] = False
    return report


def verify_portable_models(repo_root: Path) -> dict[str, Any]:
    """Confirm the four frozen weights and the 9-class DNN are small and digest-pinned."""
    supply = verify_frozen_model_supply_chain(repo_root, fail_closed=False)
    entries = supply.get("entries") if isinstance(supply, dict) else {}
    verified = 0
    oversized: list[str] = []
    if isinstance(entries, dict):
        for key, spec in FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY.items():
            entry = entries.get(key)
            path = repo_root / spec["rel_path"]
            size = path.stat().st_size if path.is_file() and not path.is_symlink() else 0
            if size >= MODEL_SIZE_LIMIT_BYTES:
                oversized.append(key)
            if (
                isinstance(entry, dict)
                and entry.get("verified") is True
                and size < MODEL_SIZE_LIMIT_BYTES
            ):
                verified += 1
    dnn_path = repo_root / DNN_MODEL_RELATIVE
    dnn_ok = False
    if dnn_path.is_file() and not dnn_path.is_symlink():
        size = dnn_path.stat().st_size
        if size < MODEL_SIZE_LIMIT_BYTES:
            digest = hashlib.sha256(dnn_path.read_bytes()).hexdigest()
            dnn_ok = digest == DNN_MODEL_SHA256
        else:
            oversized.append("same_split_dnn")
    return {
        "verified_count": verified,
        "models_verified": f"{verified}/4",
        "dnn_verified": dnn_ok,
        "oversized": oversized,
        "ok": verified == 4 and dnn_ok and not oversized,
    }


def seed_chromadb(db_path: Path) -> dict[str, Any]:
    """Create the local MITRE vector store on first boot."""
    from threatfusion.advisory.chromadb_mitre_rag import (
        CANONICAL_MITRE_AND_PLAYBOOK_CORPUS,
        ChromaDbMitrePlaybookRag,
    )

    db_path.parent.mkdir(parents=True, exist_ok=True)
    ChromaDbMitrePlaybookRag(db_path)
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        apply_sqlite_pragmas(conn)
        count = int(conn.execute("SELECT COUNT(*) FROM chroma_embeddings").fetchone()[0])
        conn.commit()
    finally:
        conn.close()
    try:
        os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    expected = len(CANONICAL_MITRE_AND_PLAYBOOK_CORPUS)
    return {"ready": count >= expected and count > 0, "documents": count}


def _sqlite_wal_writable(db_path: Path) -> bool:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        apply_sqlite_pragmas(conn)
        mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS readyz_probe (
                id INTEGER PRIMARY KEY,
                note TEXT NOT NULL
            )
            """)
        conn.execute("INSERT INTO readyz_probe (note) VALUES ('readyz')")
        conn.execute("DELETE FROM readyz_probe WHERE note = 'readyz'")
        conn.commit()
    except sqlite3.Error:
        return False
    finally:
        conn.close()
    try:
        os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return mode == "wal"


def build_readiness(repo_root: Path, db_path: Path) -> dict[str, Any]:
    """200 ready when WAL, the four frozen digests, and ChromaDB all check out."""
    wal_ok = False
    try:
        wal_ok = _sqlite_wal_writable(db_path)
    except OSError:
        wal_ok = False
    models = verify_portable_models(repo_root)
    fixtures = load_runtime_fixtures(repo_root)
    chroma_path = db_path.with_name("chromadb_vectors.sqlite3")
    try:
        chroma = seed_chromadb(chroma_path)
    except (OSError, sqlite3.Error, TypeError, ValueError):
        chroma = {"ready": False, "documents": 0}
    ready = bool(wal_ok and models.get("ok") and chroma.get("ready") and fixtures is not None)
    verified = str(models.get("models_verified") or "0/4")
    if ready:
        pill = READYZ_PILL
    else:
        rag = "RAG Ready" if chroma.get("ready") else "RAG Unavailable"
        db_label = "DB WAL" if wal_ok else "DB UNAVAILABLE"
        pill = f"{db_label} · Models {verified} · {rag}"
    return {
        "schema_version": "threatfusion_readyz_v1",
        "status": "ready" if ready else "degraded",
        "http_status": 200 if ready else 503,
        "pill": pill,
        "sqlite_wal": wal_ok,
        "models_verified": verified,
        "dnn_verified": bool(models.get("dnn_verified")),
        "chromadb_ready": bool(chroma.get("ready")),
        "fixtures_verified": fixtures is not None,
        "requires_raw_csv": False,
        "production_fusion_enabled": False,
    }


def prepare_cold_boot(data_dir: Path, repo_root: Path) -> dict[str, Any]:
    """Empty data directory: 0700 dir, WAL, immutable auth triggers, HMAC, ChromaDB."""
    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    hmac_path = ensure_hmac_secret(directory)
    db_path = directory / "threatfusion-live-console.sqlite3"
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        apply_sqlite_pragmas(conn)
        ensure_auth_audit_schema(conn)
        record_auth_event(conn, "operator_registered", "cold-boot", "127.0.0.1", "schema")
        journal = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        synchronous = int(conn.execute("PRAGMA synchronous").fetchone()[0])
        busy = int(conn.execute("PRAGMA busy_timeout").fetchone()[0])
        triggers = [
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name"
            )
        ]
        conn.commit()
    finally:
        conn.close()
    os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)
    chroma = seed_chromadb(directory / "chromadb_vectors.sqlite3")
    return {
        "data_dir": str(directory),
        "directory_mode": stat.S_IMODE(directory.stat().st_mode),
        "journal_mode": journal,
        "synchronous": synchronous,
        "busy_timeout": busy,
        "triggers": triggers,
        "hmac_path": str(hmac_path),
        "hmac_mode": stat.S_IMODE(hmac_path.stat().st_mode),
        "chromadb_ready": bool(chroma.get("ready")),
        "fixtures_verified": load_runtime_fixtures(repo_root) is not None,
        "models": verify_portable_models(repo_root),
        "db_path": str(db_path),
        "production_fusion_enabled": False,
    }
