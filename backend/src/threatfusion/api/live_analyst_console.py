"""Local live-analyst console: admit flows, score only with the frozen boundary, persist in SQLite WAL.

Suricata eve.json flows are validated by ``SuricataFlowAdapter`` and stored.
They are not scored. The frozen Random Forest accepts registered UNSW raw rows
through ``UnswNetworkInferenceBoundary`` only. The v2 autoencoder stays a
secondary ranker: its artifact may be hash-checked, and its reconstruction
error is withheld until a verified transformed matrix exists. Section 8 keeps
``production_fusion_enabled`` false. Client-supplied probabilities are ignored.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any
from urllib.parse import urlparse

from threatfusion.advisory.chromadb_mitre_rag import ChromaDbMitrePlaybookRag
from threatfusion.datasets.adapters.base import SourceRowValidationError
from threatfusion.datasets.adapters.suricata_flow import SuricataFlowAdapter
from threatfusion.datasets.unsw_raw import UNSW_RAW_COLUMN_COUNT
from threatfusion.models.drift_and_supply_chain import verify_frozen_model_supply_chain

LIVE_CONSOLE_SCHEMA_VERSION = "live_analyst_console_v1"
MAX_JSON_BYTES = 1024 * 1024
MAX_QUESTION_CHARS = 2000
PRODUCTION_FUSION_ENABLED = False
AE_WITHHELD_REASON = "secondary_ranker_withheld_without_verified_transformed_matrix"
SURICATA_WITHHELD_REASON = "suricata_flow_is_not_a_registered_unsw_raw_row"

_FRONTEND_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/css/soc_unicorn.css": ("css/soc_unicorn.css", "text/css; charset=utf-8"),
    "/js/soc_dashboard.js": ("js/soc_dashboard.js", "application/javascript; charset=utf-8"),
}


class LiveConsoleError(ValueError):
    """Sanitized console failure. ``code`` is safe to return to a local caller."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_fusion_disabled(payload: Mapping[str, Any]) -> None:
    if "production_fusion_enabled" not in payload:
        return
    if payload["production_fusion_enabled"] is not False:
        raise LiveConsoleError("production_fusion_enabled_must_remain_false")


def _json_object(payload: object) -> dict[str, Any]:
    if type(payload) is not dict:
        raise LiveConsoleError("json_object_required")
    return payload


def secondary_autoencoder_disposition(repo_root: Path) -> dict[str, Any]:
    """Hash-check the frozen v2 autoencoder and withhold a reconstruction score.

    ``load_verified_autoencoder_detector`` does not accept a score from raw
    Suricata or UNSW columns. Emitting an error here would be an invented signal.
    """
    report = verify_frozen_model_supply_chain(repo_root, fail_closed=False)
    entry = report["entries"]["autoencoder_v2"]
    if entry["verified"] is True:
        return {
            "ae_state": "withheld",
            "ae_reason": AE_WITHHELD_REASON,
            "ae_reconstruction_error": None,
            "ae_model_sha256": entry["actual_sha256"],
        }
    return {
        "ae_state": "unavailable",
        "ae_reason": "autoencoder_artifact_unverified",
        "ae_reconstruction_error": None,
        "ae_model_sha256": None,
    }


def score_registered_unsw_raw_row(repo_root: Path, raw_values: list[str]) -> dict[str, Any]:
    """Score one 49-column UNSW string row with the frozen Random Forest boundary.

    Missing artifacts, hash failures, and rejected rows produce no probability
    and no Attack/Normal decision.
    """
    from threatfusion.models.network_inference import (
        APPROVED_MODEL_HASHES,
        NetworkInferenceError,
        NetworkModelChoice,
        UnswNetworkInferenceBoundary,
    )

    withheld = {
        "scoring_state": "unavailable",
        "scoring_reason": "inference_boundary_unavailable",
        "rf_attack_probability": None,
        "rf_decision": None,
        "rf_model_sha256": None,
        "evidence_state": "model_supply_chain_unverified",
    }
    try:
        boundary = UnswNetworkInferenceBoundary(project_root=repo_root)
        result = boundary.infer(list(raw_values), model=NetworkModelChoice.RANDOM_FOREST)
    except NetworkInferenceError as exc:
        withheld["scoring_reason"] = exc.code
        return withheld
    probability = result.attack_probability
    decision = result.predicted_class
    if (
        result.status != "completed"
        or type(probability) is not float
        or not math.isfinite(probability)
        or not 0.0 <= probability <= 1.0
        or decision not in {"Attack", "Normal"}
    ):
        return {
            "scoring_state": "rejected",
            "scoring_reason": result.reason,
            "rf_attack_probability": None,
            "rf_decision": None,
            "rf_model_sha256": None,
            "evidence_state": "scoring_rejected",
        }
    return {
        "scoring_state": "completed",
        "scoring_reason": result.reason,
        "rf_attack_probability": probability,
        "rf_decision": decision,
        "rf_model_sha256": APPROVED_MODEL_HASHES["random_forest"]["model"],
        "evidence_state": "live_scored",
    }


class LiveAdmissionLedger:
    """Mode-0600 SQLite WAL ledger of admitted flows. Decisions are server-written."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.db_path.parent, stat.S_IRWXU)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS live_admissions (
                    admission_id TEXT PRIMARY KEY,
                    source_event_id TEXT NOT NULL UNIQUE,
                    source_kind TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    observed_at TEXT,
                    feature_contract TEXT NOT NULL,
                    features_json TEXT NOT NULL,
                    endpoints_json TEXT NOT NULL,
                    scoring_state TEXT NOT NULL,
                    scoring_reason TEXT NOT NULL,
                    rf_attack_probability REAL,
                    rf_decision TEXT,
                    rf_model_sha256 TEXT,
                    ae_state TEXT NOT NULL,
                    ae_reason TEXT NOT NULL,
                    ae_reconstruction_error REAL,
                    ae_model_sha256 TEXT,
                    evidence_state TEXT NOT NULL,
                    production_fusion_enabled INTEGER NOT NULL
                        CHECK (production_fusion_enabled = 0),
                    mitre_hits_json TEXT,
                    raw_digest_sha256 TEXT NOT NULL
                )
                """)
        self._lock_down()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        previous = conn.isolation_level
        conn.isolation_level = None
        conn.execute("PRAGMA journal_mode=WAL")
        conn.isolation_level = previous
        return conn

    def _lock_down(self) -> None:
        if self.db_path.exists():
            os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)

    def journal_mode(self) -> str:
        with self._connect() as conn:
            row = conn.execute("PRAGMA journal_mode").fetchone()
        self._lock_down()
        return str(row[0]).lower()

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM live_admissions").fetchone()
        return int(row["n"])

    def list_admissions(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM live_admissions ORDER BY received_at DESC, admission_id ASC"
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def get(self, admission_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM live_admissions WHERE admission_id = ?",
                (admission_id,),
            ).fetchone()
        return None if row is None else _row_to_dict(row)

    def admit(self, record: Mapping[str, Any]) -> dict[str, Any]:
        if record.get("production_fusion_enabled") is not False:
            raise LiveConsoleError("production_fusion_enabled_must_remain_false")
        if record.get("rf_decision") not in {None, "Attack", "Normal"}:
            raise LiveConsoleError("rf_decision_invalid")
        admission_id = "live_admission_v1:" + _sha256_text(
            record["source_kind"] + "\n" + record["source_event_id"]
        )
        received_at = _utc_now()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM live_admissions WHERE source_event_id = ?",
                (record["source_event_id"],),
            ).fetchone()
            if existing is not None:
                payload = _row_to_dict(existing)
                payload["replayed"] = True
                self._lock_down()
                return payload
            conn.execute(
                """
                INSERT INTO live_admissions (
                    admission_id, source_event_id, source_kind, received_at, observed_at,
                    feature_contract, features_json, endpoints_json, scoring_state,
                    scoring_reason, rf_attack_probability, rf_decision, rf_model_sha256,
                    ae_state, ae_reason, ae_reconstruction_error, ae_model_sha256,
                    evidence_state, production_fusion_enabled, mitre_hits_json,
                    raw_digest_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)
                """,
                (
                    admission_id,
                    record["source_event_id"],
                    record["source_kind"],
                    received_at,
                    record.get("observed_at"),
                    record["feature_contract"],
                    json.dumps(record["features"], sort_keys=True, separators=(",", ":")),
                    json.dumps(record["endpoints"], sort_keys=True, separators=(",", ":")),
                    record["scoring_state"],
                    record["scoring_reason"],
                    record["rf_attack_probability"],
                    record["rf_decision"],
                    record["rf_model_sha256"],
                    record["ae_state"],
                    record["ae_reason"],
                    record["ae_reconstruction_error"],
                    record["ae_model_sha256"],
                    record["evidence_state"],
                    record["raw_digest_sha256"],
                ),
            )
        self._lock_down()
        stored = self.get(admission_id)
        if stored is None:
            raise LiveConsoleError("admission_persist_failed")
        stored["replayed"] = False
        return stored

    def attach_mitre_hits(self, admission_id: str, hits: list[dict[str, Any]]) -> dict[str, Any]:
        current = self.get(admission_id)
        if current is None:
            raise LiveConsoleError("admission_not_found")
        with self._connect() as conn:
            conn.execute(
                "UPDATE live_admissions SET mitre_hits_json = ? WHERE admission_id = ?",
                (json.dumps(hits, sort_keys=True, separators=(",", ":")), admission_id),
            )
            row = conn.execute(
                "SELECT rf_attack_probability, rf_decision, evidence_state FROM live_admissions WHERE admission_id = ?",
                (admission_id,),
            ).fetchone()
        if (
            row["rf_attack_probability"] != current["rf_attack_probability"]
            or row["rf_decision"] != current["rf_decision"]
            or row["evidence_state"] != current["evidence_state"]
        ):
            raise LiveConsoleError("mitre_retrieval_mutated_decision")
        self._lock_down()
        updated = self.get(admission_id)
        if updated is None:
            raise LiveConsoleError("admission_not_found")
        return updated


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    hits_raw = row["mitre_hits_json"]
    return {
        "schema_version": LIVE_CONSOLE_SCHEMA_VERSION,
        "admission_id": row["admission_id"],
        "source_event_id": row["source_event_id"],
        "source_kind": row["source_kind"],
        "received_at": row["received_at"],
        "observed_at": row["observed_at"],
        "feature_contract": row["feature_contract"],
        "features": json.loads(row["features_json"]),
        "endpoints": json.loads(row["endpoints_json"]),
        "scoring_state": row["scoring_state"],
        "scoring_reason": row["scoring_reason"],
        "rf_attack_probability": row["rf_attack_probability"],
        "rf_decision": row["rf_decision"],
        "rf_model_sha256": row["rf_model_sha256"],
        "ae_state": row["ae_state"],
        "ae_reason": row["ae_reason"],
        "ae_reconstruction_error": row["ae_reconstruction_error"],
        "ae_model_sha256": row["ae_model_sha256"],
        "evidence_state": row["evidence_state"],
        "production_fusion_enabled": False,
        "mitre_hits": [] if hits_raw is None else json.loads(hits_raw),
        "raw_digest_sha256": row["raw_digest_sha256"],
    }


def ingest_suricata_eve(
    ledger: LiveAdmissionLedger,
    payload: Mapping[str, Any],
    *,
    repo_root: Path,
) -> dict[str, Any]:
    """Validate one Suricata flow and store it without a model decision."""
    _require_fusion_disabled(payload)
    record_in = payload["record"] if "record" in payload else payload
    if type(record_in) is not dict:
        raise LiveConsoleError("suricata_record_invalid")
    record = dict(record_in)
    record.pop("production_fusion_enabled", None)
    for forbidden in (
        "rf_attack_probability",
        "rf_decision",
        "uncalibrated_model_score",
        "decision",
    ):
        record.pop(forbidden, None)
    try:
        adapted = SuricataFlowAdapter().adapt_eve_flow_record(record)
    except SourceRowValidationError as exc:
        raise LiveConsoleError(f"suricata_record_rejected:{exc.reason}") from exc
    features = {key: adapted.features_14[key] for key in sorted(adapted.features_14)}
    feature_digest = _sha256_text(json.dumps(features, sort_keys=True, separators=(",", ":")))
    flow = adapted.flow
    ae = secondary_autoencoder_disposition(repo_root)
    return ledger.admit(
        {
            "source_event_id": f"{adapted.source_event_id}:{feature_digest}",
            "source_kind": "suricata_eve",
            "observed_at": flow.timestamp_start.isoformat(),
            "feature_contract": "network_behavior_v1",
            "features": features,
            "endpoints": {
                "src_ip": str(flow.src_ip),
                "dst_ip": str(flow.dst_ip),
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "proto": str(flow.protocol),
            },
            "scoring_state": "withheld",
            "scoring_reason": SURICATA_WITHHELD_REASON,
            "rf_attack_probability": None,
            "rf_decision": None,
            "rf_model_sha256": None,
            "evidence_state": "adapted_unscored",
            "raw_digest_sha256": feature_digest,
            "production_fusion_enabled": False,
            **ae,
        }
    )


def ingest_unsw_raw_row(
    ledger: LiveAdmissionLedger,
    payload: Mapping[str, Any],
    *,
    repo_root: Path,
) -> dict[str, Any]:
    """Admit one UNSW raw string row and score it only through the frozen boundary."""
    _require_fusion_disabled(payload)
    raw_values = payload.get("raw_values")
    if (
        type(raw_values) is not list
        or len(raw_values) != UNSW_RAW_COLUMN_COUNT
        or any(type(value) is not str or len(value) > 1024 for value in raw_values)
    ):
        raise LiveConsoleError("unsw_raw_row_invalid")
    canonical = "\n".join(raw_values)
    digest = _sha256_text("unsw_raw_submission_v1\n" + canonical)
    scored = score_registered_unsw_raw_row(repo_root, raw_values)
    ae = secondary_autoencoder_disposition(repo_root)
    return ledger.admit(
        {
            "source_event_id": f"unsw_raw_submission_v1:{digest}",
            "source_kind": "unsw_raw",
            "observed_at": None,
            "feature_contract": "unsw_nb15.argus.raw_49",
            "features": {"column_count": UNSW_RAW_COLUMN_COUNT},
            "endpoints": {},
            "raw_digest_sha256": digest,
            "production_fusion_enabled": False,
            **scored,
            **ae,
        }
    )


def answer_mitre_copilot(
    *,
    question: str,
    rag: ChromaDbMitrePlaybookRag,
    ledger: LiveAdmissionLedger | None = None,
    admission_id: str | None = None,
) -> dict[str, Any]:
    """Retrieve canonical MITRE playbook rows. Retrieval does not change a decision."""
    text = question.strip()
    if not text or len(text) > MAX_QUESTION_CHARS:
        raise LiveConsoleError("empty_question" if not text else "question_too_long")
    hits = []
    for item in rag.query_semantic_rag(text, top_k=3):
        hits.append(
            {
                "technique_id": item.technique_id,
                "technique_name": item.technique_name,
                "tactic": item.tactic,
                "playbook_id": item.playbook_id,
                "cosine_similarity": item.cosine_similarity,
                "rank": item.rank,
            }
        )
    attached = None
    if admission_id is not None:
        if ledger is None:
            raise LiveConsoleError("admission_not_found")
        before = ledger.get(admission_id)
        if before is None:
            raise LiveConsoleError("admission_not_found")
        attached = ledger.attach_mitre_hits(admission_id, hits)
        if (
            attached["rf_decision"] != before["rf_decision"]
            or attached["rf_attack_probability"] != before["rf_attack_probability"]
            or attached["evidence_state"] != before["evidence_state"]
        ):
            raise LiveConsoleError("mitre_retrieval_mutated_decision")
    return {
        "schema_version": LIVE_CONSOLE_SCHEMA_VERSION,
        "evidence_state": "retrieved" if hits else "unavailable",
        "detection_authority": False,
        "production_fusion_enabled": False,
        "answer": (
            "Local canonical MITRE corpus retrieval. This is not a detection "
            "and it does not authorize containment."
        ),
        "hits": hits,
        "admission": attached,
    }


def build_health(ledger: LiveAdmissionLedger, repo_root: Path) -> dict[str, Any]:
    supply = verify_frozen_model_supply_chain(repo_root, fail_closed=False)
    return {
        "schema_version": LIVE_CONSOLE_SCHEMA_VERSION,
        "production_fusion_enabled": PRODUCTION_FUSION_ENABLED,
        "model_supply_chain_verified": supply["verified"] is True,
        "queue_count": ledger.count(),
        "live_scoring": "registered_unsw_raw_only",
        "suricata_scoring": SURICATA_WITHHELD_REASON,
        "autoencoder_role": AE_WITHHELD_REASON,
    }


class LiveAnalystConsoleServer(ThreadingHTTPServer):
    """Loopback HTTP server for the live ledger and the static console assets."""

    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        ledger: LiveAdmissionLedger,
        *,
        repo_root: Path,
        frontend_dir: Path,
        rag: ChromaDbMitrePlaybookRag,
    ) -> None:
        self.ledger = ledger
        self.repo_root = repo_root
        self.frontend_dir = frontend_dir
        self.rag = rag
        super().__init__(server_address, LiveAnalystConsoleHandler)


class LiveAnalystConsoleHandler(BaseHTTPRequestHandler):
    server: LiveAnalystConsoleServer

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in _FRONTEND_FILES:
            self._send_file(path)
            return
        if path == "/api/v1/health":
            self._send_json(200, build_health(self.server.ledger, self.server.repo_root))
            return
        if path == "/api/v1/live-queue":
            self._send_json(
                200,
                {
                    "schema_version": LIVE_CONSOLE_SCHEMA_VERSION,
                    "production_fusion_enabled": False,
                    "admissions": self.server.ledger.list_admissions(),
                },
            )
            return
        prefix = "/api/v1/live-queue/"
        if path.startswith(prefix):
            admission = self.server.ledger.get(path[len(prefix) :])
            if admission is None:
                self._send_json(404, {"error": "admission_not_found"})
                return
            self._send_json(200, admission)
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            payload = _json_object(self._read_json())
            if path == "/api/v1/ingest/suricata-eve":
                result = ingest_suricata_eve(
                    self.server.ledger, payload, repo_root=self.server.repo_root
                )
            elif path == "/api/v1/ingest/unsw-raw":
                result = ingest_unsw_raw_row(
                    self.server.ledger, payload, repo_root=self.server.repo_root
                )
            elif path == "/api/v1/copilot/mitre":
                question = payload.get("question")
                if type(question) is not str:
                    raise LiveConsoleError("empty_question")
                admission_id = payload.get("admission_id")
                if admission_id is not None and type(admission_id) is not str:
                    raise LiveConsoleError("admission_not_found")
                result = answer_mitre_copilot(
                    question=question,
                    rag=self.server.rag,
                    ledger=self.server.ledger,
                    admission_id=admission_id,
                )
            else:
                self._send_json(404, {"error": "not_found"})
                return
        except LiveConsoleError as exc:
            status = _error_status(exc.code)
            self._send_json(status, {"error": exc.code})
            return
        self._send_json(200, result)

    def _read_json(self) -> object:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None or not raw_length.isdigit():
            raise LiveConsoleError("content_length_required")
        length = int(raw_length)
        if length > MAX_JSON_BYTES:
            raise LiveConsoleError("payload_too_large")
        data = self.rfile.read(length)
        if len(data) != length:
            raise LiveConsoleError("json_invalid")
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LiveConsoleError("json_invalid") from exc

    def _send_file(self, path: str) -> None:
        relative, content_type = _FRONTEND_FILES[path]
        asset = self.server.frontend_dir / relative
        if not asset.is_file() or asset.is_symlink():
            self._send_json(404, {"error": "not_found"})
            return
        body = asset.read_bytes()
        self.send_response(200)
        self._common_headers(content_type, len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: Mapping[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self._common_headers("application/json", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _common_headers(self, content_type: str, length: int) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'none'; connect-src 'self'; object-src 'none'; base-uri 'none'",
        )


def _error_status(code: str) -> int:
    if code == "payload_too_large":
        return 413
    if code in {"content_length_required", "json_invalid", "json_object_required"}:
        return 400
    if code == "admission_not_found":
        return 404
    return 422


def serve_live_analyst_console(
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    ledger_path: Path,
    repo_root: Path,
    frontend_dir: Path | None = None,
    rag_db_path: Path | None = None,
) -> LiveAnalystConsoleServer:
    """Bind a loopback console. Non-loopback hosts are refused."""
    if host not in {"127.0.0.1", "::1"}:
        raise LiveConsoleError("loopback_bind_required")
    root = Path(repo_root).resolve()
    assets = frontend_dir or (root / "frontend")
    ledger = LiveAdmissionLedger(Path(ledger_path))
    rag = ChromaDbMitrePlaybookRag(
        rag_db_path or (Path(ledger_path).parent / "live_mitre_rag.sqlite3")
    )
    server = LiveAnalystConsoleServer(
        (host, port),
        ledger,
        repo_root=root,
        frontend_dir=assets,
        rag=rag,
    )
    return server


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="ThreatFusion loopback live analyst console")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[4])
    args = parser.parse_args(argv)
    try:
        server = serve_live_analyst_console(
            host=args.host,
            port=args.port,
            ledger_path=args.ledger,
            repo_root=args.repo_root,
        )
    except LiveConsoleError as exc:
        print(exc.code)
        return 2
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


__all__ = [
    "AE_WITHHELD_REASON",
    "LIVE_CONSOLE_SCHEMA_VERSION",
    "PRODUCTION_FUSION_ENABLED",
    "SURICATA_WITHHELD_REASON",
    "LiveAdmissionLedger",
    "LiveConsoleError",
    "answer_mitre_copilot",
    "build_health",
    "ingest_suricata_eve",
    "ingest_unsw_raw_row",
    "score_registered_unsw_raw_row",
    "secondary_autoencoder_disposition",
    "serve_live_analyst_console",
]
