"""Live analyst console services for the local SOC walkthrough.

Scores a 14-feature flow only when the frozen Random Forest artifact verifies and
its input width matches the canonical feature contract. The autoencoder never
changes the alert decision. Analyst notes, MITRE answers, drift, and the n8n
workbench read local files. Containment stays unauthorized.
"""

from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import stat
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threatfusion.advisory.chromadb_mitre_rag import ChromaDbMitrePlaybookRag
from threatfusion.models.drift_and_supply_chain import (
    CANONICAL_14_FEATURES,
    FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY,
    evaluate_14_feature_telemetry_drift,
    verify_frozen_model_supply_chain,
)
from threatfusion.models.drift_and_supply_chain import TelemetryDriftError

_CONTAINMENT_REQUEST = re.compile(
    r"\b(isolate|contain|containment|quarantine|execute|block|kill)\b",
    re.IGNORECASE,
)


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    conn.row_factory = sqlite3.Row
    previous = conn.isolation_level
    conn.isolation_level = None
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.isolation_level = previous
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS live_flows (
            flow_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at_utc TEXT NOT NULL,
            features_json TEXT NOT NULL,
            rf_attack_probability REAL,
            decision TEXT NOT NULL,
            evidence_state TEXT NOT NULL,
            reason TEXT NOT NULL,
            model_sha256 TEXT NOT NULL,
            production_fusion_enabled INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_notes (
            note_id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER,
            author_id TEXT NOT NULL,
            note_text TEXT NOT NULL,
            created_at_utc TEXT NOT NULL
        )
        """
    )
    if db_path.exists():
        os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)
    return conn


def _finite_feature_vector(features: Mapping[str, Any]) -> tuple[list[float] | None, str]:
    ordered: list[float] = []
    for name in CANONICAL_14_FEATURES:
        if name not in features:
            return None, f"missing_feature:{name}"
        try:
            value = float(features[name])
        except (TypeError, ValueError):
            return None, f"non_numeric_feature:{name}"
        if not math.isfinite(value):
            return None, f"non_finite_feature:{name}"
        ordered.append(value)
    return ordered, ""


def score_canonical_flow(
    features: Mapping[str, Any],
    *,
    repo_root: Path,
    model: Any | None = None,
    supply_verified: bool | None = None,
) -> dict[str, Any]:
    """Score one canonical 14-feature flow without fusing the autoencoder."""
    expected = FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY["random_forest"]["expected_sha256"]
    vector, reason = _finite_feature_vector(features)
    base = {
        "schema_version": "live_flow_score_v1",
        "production_fusion_enabled": False,
        "alert_authority": "frozen_random_forest",
        "model_sha256": expected,
        "ae_operational_role": "secondary_non_blocking_ranker",
        "ae_changes_alert_decision": False,
        "rf_attack_probability": None,
        "decision": "withheld",
        "evidence_state": "unavailable",
        "reason": reason or "unscored",
    }
    if vector is None:
        return base
    if supply_verified is None:
        supply = verify_frozen_model_supply_chain(repo_root, fail_closed=False)
        entries = supply.get("entries") if isinstance(supply, dict) else None
        rf_entry = entries.get("random_forest") if isinstance(entries, dict) else None
        supply_verified = bool(isinstance(rf_entry, dict) and rf_entry.get("verified") is True)
    if not supply_verified:
        base["reason"] = "frozen_random_forest_unverified"
        return base
    if model is None:
        model_path = repo_root / FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY["random_forest"]["rel_path"]
        try:
            import joblib

            model = joblib.load(model_path)
        except (OSError, ImportError, ValueError, EOFError):
            base["reason"] = "frozen_random_forest_unreadable"
            return base
    width = getattr(model, "n_features_in_", None)
    if width != len(CANONICAL_14_FEATURES):
        base["reason"] = "feature_contract_mismatch"
        base["model_feature_width"] = width
        return base
    try:
        probabilities = model.predict_proba([vector])
        attack_probability = float(probabilities[0][1])
    except (AttributeError, IndexError, TypeError, ValueError):
        base["reason"] = "frozen_random_forest_score_failed"
        return base
    if not math.isfinite(attack_probability):
        base["reason"] = "non_finite_score"
        return base
    decision = "Attack" if attack_probability >= 0.5 else "Benign"
    base.update(
        {
            "rf_attack_probability": attack_probability,
            "decision": decision,
            "evidence_state": "verified",
            "reason": "frozen_random_forest_scored",
        }
    )
    return base


def persist_scored_flow(db_path: Path, features: Mapping[str, Any], score: Mapping[str, Any]) -> dict[str, Any]:
    """Append one scored flow to the live WAL queue."""
    observed = datetime.now(UTC).isoformat()
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO live_flows (
                observed_at_utc, features_json, rf_attack_probability, decision,
                evidence_state, reason, model_sha256, production_fusion_enabled
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observed,
                json.dumps({name: features.get(name) for name in CANONICAL_14_FEATURES}),
                score.get("rf_attack_probability"),
                str(score.get("decision")),
                str(score.get("evidence_state")),
                str(score.get("reason")),
                str(score.get("model_sha256")),
                0,
            ),
        )
        flow_id = int(cursor.lastrowid)
    stored = dict(score)
    stored["flow_id"] = flow_id
    stored["observed_at_utc"] = observed
    return stored


def list_live_flows(db_path: Path, *, limit: int = 20) -> list[dict[str, Any]]:
    """Return the newest live flows. A missing database is an empty queue."""
    if not db_path.is_file():
        return []
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT flow_id, observed_at_utc, rf_attack_probability, decision,
                   evidence_state, reason, model_sha256
            FROM live_flows
            ORDER BY flow_id DESC
            LIMIT ?
            """,
            (max(1, min(limit, 100)),),
        ).fetchall()
    return [dict(row) for row in rows]


def add_analyst_note(db_path: Path, *, flow_id: int | None, author_id: str, note_text: str) -> dict[str, Any]:
    """Store one analyst note. Empty text is refused."""
    text = note_text.strip()
    author = author_id.strip()
    if not text or not author:
        return {"evidence_state": "unavailable", "reason": "note_incomplete"}
    created = datetime.now(UTC).isoformat()
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO analyst_notes (flow_id, author_id, note_text, created_at_utc)
            VALUES (?, ?, ?, ?)
            """,
            (flow_id, author, text, created),
        )
        note_id = int(cursor.lastrowid)
    return {
        "evidence_state": "verified",
        "note_id": note_id,
        "flow_id": flow_id,
        "author_id": author,
        "note_text": text,
        "created_at_utc": created,
    }


def answer_mitre_copilot(question: str, rag_db_path: Path) -> dict[str, Any]:
    """Answer from the local MITRE corpus. Containment requests are refused."""
    if _CONTAINMENT_REQUEST.search(question or ""):
        return {
            "schema_version": "live_mitre_copilot_v1",
            "evidence_state": "unavailable",
            "execution_authorized": False,
            "reason": "containment_refused",
            "hits": [],
        }
    rag = ChromaDbMitrePlaybookRag(rag_db_path)
    hits = rag.query_semantic_rag(question or "", top_k=3)
    return {
        "schema_version": "live_mitre_copilot_v1",
        "evidence_state": "verified" if hits else "unavailable",
        "execution_authorized": False,
        "reason": "local_corpus" if hits else "no_corpus_hit",
        "hits": [
            {
                "technique_id": hit.technique_id,
                "technique_name": hit.technique_name,
                "playbook_id": hit.playbook_id,
                "cosine_similarity": hit.cosine_similarity,
            }
            for hit in hits
        ],
    }


def drift_for_stored_flows(db_path: Path) -> dict[str, Any]:
    """Run the read-only 14-feature drift monitor on stored live flows."""
    if not db_path.is_file():
        return {"evidence_state": "unavailable", "reason": "no_live_flows"}
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT features_json FROM live_flows").fetchall()
    records = []
    for row in rows:
        payload = json.loads(row["features_json"])
        if all(name in payload and payload[name] is not None for name in CANONICAL_14_FEATURES):
            records.append({name: float(payload[name]) for name in CANONICAL_14_FEATURES})
    if not records:
        return {"evidence_state": "unavailable", "reason": "no_complete_feature_rows"}
    try:
        report = evaluate_14_feature_telemetry_drift(records)
    except TelemetryDriftError as exc:
        return {"evidence_state": "unavailable", "reason": str(exc)}
    body = report.to_dict() if hasattr(report, "to_dict") else {"drift_status": getattr(report, "drift_status", None)}
    body["evidence_state"] = "verified"
    body["changes_model_weights"] = False
    return body


def read_n8n_workbench(workflow_path: Path) -> dict[str, Any]:
    """List the workflow nodes. This does not dispatch a playbook."""
    if not workflow_path.is_file():
        return {
            "evidence_state": "unavailable",
            "reason": "workflow_missing",
            "execution_authorized": False,
            "nodes": [],
        }
    document = json.loads(workflow_path.read_text(encoding="utf-8"))
    nodes = [
        {"name": node.get("name"), "type": node.get("type")}
        for node in document.get("nodes", [])
        if isinstance(node, dict) and str(node.get("type", "")).startswith("n8n-nodes-base.")
    ]
    return {
        "schema_version": "n8n_workbench_v1",
        "evidence_state": "verified",
        "execution_authorized": False,
        "node_count": len(nodes),
        "nodes": nodes,
        "reason": "local_workflow_definition",
    }
