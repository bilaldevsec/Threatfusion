"""Live analyst console services for the local SOC walkthrough.

Scores a 14-feature flow only when the frozen Random Forest artifact verifies and
its input width matches the canonical feature contract. The autoencoder never
changes the alert decision. Analyst notes, MITRE answers, drift, and the n8n
workbench read local files. Containment stays unauthorized.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import stat
import urllib.error
import urllib.request
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threatfusion.advisory.chromadb_mitre_rag import ChromaDbMitrePlaybookRag
from threatfusion.models.drift_and_supply_chain import (
    CANONICAL_14_FEATURES,
    FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY,
    TelemetryDriftError,
    evaluate_14_feature_telemetry_drift,
    verify_frozen_model_supply_chain,
)
from threatfusion.soar.playbook_ledger import (
    ApprovalGatedSoarEngine,
    SoarOptimisticConcurrencyError,
    SoarPlaybookSqliteRepository,
    SoarStateTransitionError,
)

_CONTAINMENT_REQUEST = re.compile(
    r"\b(isolate|contain|containment|quarantine|execute|block|kill)\b",
    re.IGNORECASE,
)
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_FLOW_EXTRA_COLUMNS: tuple[tuple[str, str], ...] = (
    ("campaign_id", "TEXT"),
    ("source_label", "TEXT"),
    ("case_title", "TEXT"),
    ("playbook_id", "TEXT"),
    ("ledger_state", "TEXT"),
    ("entry_sha256", "TEXT"),
    ("prev_entry_sha256", "TEXT"),
    ("audit_chain_verified", "INTEGER"),
    ("callback_signature", "TEXT"),
    ("thehive_case_id", "TEXT"),
    ("mttr_seconds", "REAL"),
    ("callback_recorded", "INTEGER"),
    ("triage_state", "TEXT"),
    ("src_entity_id", "TEXT"),
    ("dst_entity_id", "TEXT"),
    ("entity_namespace_id", "TEXT"),
    ("flow_protocol", "TEXT"),
    ("service_or_port", "TEXT"),
    ("clock_synchronized", "INTEGER"),
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
    conn.execute("""
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
        """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyst_notes (
            note_id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER,
            author_id TEXT NOT NULL,
            note_text TEXT NOT NULL,
            created_at_utc TEXT NOT NULL
        )
        """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS live_campaigns (
            campaign_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            source_label TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            member_count INTEGER NOT NULL
        )
        """)
    existing = {row[1] for row in conn.execute("PRAGMA table_info(live_flows)")}
    for name, declaration in _FLOW_EXTRA_COLUMNS:
        if name not in existing:
            conn.execute(f"ALTER TABLE live_flows ADD COLUMN {name} {declaration}")
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


def persist_scored_flow(
    db_path: Path,
    features: Mapping[str, Any],
    score: Mapping[str, Any],
    *,
    campaign_id: str | None = None,
    source_label: str | None = None,
    case_title: str | None = None,
) -> dict[str, Any]:
    """Append one scored flow to the live WAL queue."""
    observed = datetime.now(UTC).isoformat()
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO live_flows (
                observed_at_utc, features_json, rf_attack_probability, decision,
                evidence_state, reason, model_sha256, production_fusion_enabled,
                campaign_id, source_label, case_title
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                campaign_id,
                source_label,
                case_title,
            ),
        )
        flow_id = int(cursor.lastrowid)
    stored = dict(score)
    stored["flow_id"] = flow_id
    stored["observed_at_utc"] = observed
    stored["campaign_id"] = campaign_id
    stored["source_label"] = source_label
    stored["case_title"] = case_title
    stored["production_fusion_enabled"] = False
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


def add_analyst_note(
    db_path: Path, *, flow_id: int | None, author_id: str, note_text: str
) -> dict[str, Any]:
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
    body = (
        report.to_dict()
        if hasattr(report, "to_dict")
        else {"drift_status": getattr(report, "drift_status", None)}
    )
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


def _flow_rows(db_path: Path, *, limit: int) -> list[dict[str, Any]]:
    if not db_path.is_file():
        return []
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT flow_id, observed_at_utc, rf_attack_probability, decision,
                   evidence_state, reason, model_sha256, campaign_id, source_label,
                   case_title, playbook_id, ledger_state, entry_sha256,
                   prev_entry_sha256, audit_chain_verified, callback_signature,
                   thehive_case_id, mttr_seconds, callback_recorded, triage_state,
                   src_entity_id, dst_entity_id, entity_namespace_id, flow_protocol,
                   service_or_port, clock_synchronized
            FROM live_flows
            ORDER BY flow_id DESC
            LIMIT ?
            """,
            (max(1, min(limit, 100)),),
        ).fetchall()
    return [dict(row) for row in rows]


def _read_stored_incidents(incidents_db_path: Path | None, *, limit: int) -> list[dict[str, Any]]:
    """Read incident rows when a database already exists. A missing file stays empty."""
    if incidents_db_path is None or not incidents_db_path.is_file():
        return []
    try:
        conn = sqlite3.connect(f"file:{incidents_db_path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return []
    try:
        conn.row_factory = sqlite3.Row
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "incidents" not in tables:
            return []
        rows = conn.execute(
            """
            SELECT incident_id, window_type, constituent_alert_count,
                   max_probability_score, escalated_decision, earliest_observed_at,
                   provenance_status
            FROM incidents
            ORDER BY earliest_observed_at DESC
            LIMIT ?
            """,
            (max(1, min(limit, 100)),),
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    return [dict(row) for row in rows]


def list_live_campaigns(
    db_path: Path,
    *,
    incidents_db_path: Path | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Return stored flow campaigns and any incident rows already on disk."""
    flows = _flow_rows(db_path, limit=limit)
    incidents = _read_stored_incidents(incidents_db_path, limit=limit)
    grouped: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for row in flows:
        key = str(row.get("campaign_id") or f"flow:{row['flow_id']}")
        if key not in grouped:
            order.append(key)
            grouped[key] = []
        grouped[key].append(row)
    campaigns = []
    for key in order:
        members = grouped[key]
        campaigns.append(
            {
                "campaign_id": key,
                "title": members[0].get("case_title") or key,
                "source_label": members[0].get("source_label") or "live_flow",
                "member_count": len(members),
                "flows": members,
                "production_fusion_enabled": False,
            }
        )
    populated = bool(campaigns or incidents)
    return {
        "schema_version": "live_campaign_queue_v1",
        "evidence_state": "verified" if populated else "unavailable",
        "reason": "stored_rows" if populated else "no_stored_campaigns",
        "production_fusion_enabled": False,
        "execution_authorized": False,
        "campaigns": campaigns,
        "incidents": incidents,
        "flow_count": len(flows),
        "incident_count": len(incidents),
    }


def replay_benchmark_attack_burst(
    db_path: Path,
    *,
    repo_root: Path,
    model: Any | None = None,
    supply_verified: bool | None = None,
) -> dict[str, Any]:
    """Score the recorded UNSW-NB15 study vectors and store them as one campaign.

    The decision is the frozen Random Forest score. The study card's printed
    probability is not copied onto the row.
    """
    from threatfusion.evaluation.study_runner import STUDY_TRIAGE_CASES

    selected = [case for case in STUDY_TRIAGE_CASES if case.source == "recorded_unsw_nb15"]
    if not selected:
        return {
            "schema_version": "live_campaign_replay_v1",
            "evidence_state": "unavailable",
            "reason": "no_recorded_unsw_fixtures",
            "production_fusion_enabled": False,
            "execution_authorized": False,
            "ae_changes_alert_decision": False,
            "member_count": 0,
            "flows": [],
        }
    campaign_id = "campaign_recorded_unsw_nb15:" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    created = datetime.now(UTC).isoformat()
    stored: list[dict[str, Any]] = []
    for case in selected:
        features = {name: float(case.raw_features_14[name]) for name in CANONICAL_14_FEATURES}
        score = score_canonical_flow(
            features,
            repo_root=repo_root,
            model=model,
            supply_verified=supply_verified,
        )
        stored.append(
            persist_scored_flow(
                db_path,
                features,
                score,
                campaign_id=campaign_id,
                source_label="recorded_unsw_nb15",
                case_title=case.title,
            )
        )
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO live_campaigns (
                campaign_id, title, source_label, created_at_utc, member_count
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                campaign_id,
                "Recorded UNSW-NB15 study burst",
                "recorded_unsw_nb15",
                created,
                len(stored),
            ),
        )
    return {
        "schema_version": "live_campaign_replay_v1",
        "evidence_state": "verified" if stored else "unavailable",
        "reason": "study_fixture_scored_by_frozen_random_forest",
        "campaign_id": campaign_id,
        "source_label": "recorded_unsw_nb15",
        "fixture_origin": "study_triage_cases",
        "production_fusion_enabled": False,
        "execution_authorized": False,
        "ae_changes_alert_decision": False,
        "changes_model_weights": False,
        "member_count": len(stored),
        "flows": stored,
    }


def _receipt_from_ledger(
    repository: SoarPlaybookSqliteRepository, playbook_id: str
) -> dict[str, Any]:
    chain_ok, chain_message = repository.verify_audit_chain_integrity(
        playbook_id, require_non_empty=True
    )
    entries = repository.list_audit_entries(playbook_id)
    approval = next(
        (entry for entry in reversed(entries) if entry.action == "analyst_approve"), None
    )
    entry_hash = approval.entry_sha256 if approval is not None else ""
    prev_hash = approval.prev_entry_sha256 if approval is not None else ""
    linked = bool(_SHA256_HEX.fullmatch(entry_hash) and _SHA256_HEX.fullmatch(prev_hash))
    verified = bool(chain_ok and linked and approval is not None)
    return {
        "evidence_state": "verified" if verified else "unavailable",
        "audit_chain_verified": verified,
        "chain_message": chain_message,
        "playbook_id": playbook_id,
        "entry_sha256": entry_hash if verified else "",
        "prev_entry_sha256": prev_hash if verified else "",
        "ledger_state": "approved" if verified else "pending_approval",
        "operator_state": "approved_local" if verified else "pending_approval",
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
    }


def _store_flow_receipt(db_path: Path, flow_id: int, receipt: Mapping[str, Any]) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET playbook_id = ?, ledger_state = ?, entry_sha256 = ?,
                prev_entry_sha256 = ?, audit_chain_verified = ?
            WHERE flow_id = ?
            """,
            (
                receipt.get("playbook_id"),
                receipt.get("ledger_state"),
                receipt.get("entry_sha256"),
                receipt.get("prev_entry_sha256"),
                1 if receipt.get("audit_chain_verified") else 0,
                flow_id,
            ),
        )


def approve_live_soar(
    live_db_path: Path,
    soar_db_path: Path,
    *,
    flow_id: int,
    actor_id: str,
    reason: str,
) -> dict[str, Any]:
    """Record analyst approval on the SOAR hash chain. Containment is not executed."""
    refused = {
        "schema_version": "live_soar_approval_v1",
        "evidence_state": "unavailable",
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
        "operator_state": "pending_approval",
        "entry_sha256": "",
        "prev_entry_sha256": "",
    }
    author = actor_id.strip()
    decision_reason = reason.strip()
    if flow_id <= 0 or not author or not decision_reason:
        refused["reason"] = "approval_incomplete"
        return refused
    if not live_db_path.is_file():
        refused["reason"] = "flow_not_stored"
        return refused
    with _connect(live_db_path) as conn:
        row = conn.execute(
            "SELECT flow_id FROM live_flows WHERE flow_id = ?", (flow_id,)
        ).fetchone()
    if row is None:
        refused["reason"] = "flow_not_stored"
        return refused
    candidate_id = f"live_flow:{flow_id}"
    repository = SoarPlaybookSqliteRepository(soar_db_path)
    engine = ApprovalGatedSoarEngine(repository)
    existing = repository.list_records_for_candidate(candidate_id)
    approved = next((record for record in existing if record.state == "approved"), None)
    if approved is not None:
        receipt = _receipt_from_ledger(repository, approved.playbook_id)
        receipt["schema_version"] = "live_soar_approval_v1"
        receipt["reason"] = "already_approved"
        receipt["flow_id"] = flow_id
        receipt["candidate_id"] = candidate_id
        _store_flow_receipt(live_db_path, flow_id, receipt)
        return receipt
    pending = next((record for record in existing if record.state == "pending_approval"), None)
    try:
        if pending is None:
            created = engine.recommend_actions_for_alert(candidate_id, None)
            pending = created[0]
        updated = engine.decide_recommendation(
            pending.playbook_id,
            actor_id=author,
            decision="approve",
            reason=decision_reason,
            expected_version=pending.version,
        )
    except (SoarStateTransitionError, SoarOptimisticConcurrencyError, KeyError, ValueError) as exc:
        refused["reason"] = exc.__class__.__name__
        return refused
    receipt = _receipt_from_ledger(repository, updated.playbook_id)
    receipt["schema_version"] = "live_soar_approval_v1"
    receipt["reason"] = "analyst_approved_local"
    receipt["flow_id"] = flow_id
    receipt["candidate_id"] = candidate_id
    receipt["ledger_state"] = updated.state
    _store_flow_receipt(live_db_path, flow_id, receipt)
    return receipt


def _canonical_body(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hmac_sha256(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _post_signed(
    url: str, body: bytes, signature: str, idem_key: str
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-ThreatFusion-Signature-256": signature,
            "X-Idempotency-Key": idem_key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            raw = response.read().decode("utf-8")
            parsed = json.loads(raw) if raw else {}
            return response.status, parsed if isinstance(parsed, dict) else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"error": "invalid_response"}
        return exc.code, parsed if isinstance(parsed, dict) else {}
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return 0, {"error": exc.__class__.__name__}


def _store_callback_receipt(
    db_path: Path,
    flow_id: int,
    *,
    signature: str,
    case_id: str,
    mttr_seconds: float,
) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET callback_signature = ?, thehive_case_id = ?, mttr_seconds = ?,
                callback_recorded = 1
            WHERE flow_id = ?
            """,
            (signature, case_id, mttr_seconds, flow_id),
        )


def dispatch_approved_callback(
    live_db_path: Path,
    soar_db_path: Path,
    *,
    flow_id: int,
    contract_base_url: str,
    hmac_secret: str,
    thehive_url: str = "http://127.0.0.1:9",
    outbox_db_path: Path | None = None,
) -> dict[str, Any]:
    """Verify an approved playbook, open a local 4-block case, and record the HMAC callback.

    Host containment is not executed. The callback is the signed local contract loop.
    """
    refused: dict[str, Any] = {
        "schema_version": "live_soar_callback_v1",
        "evidence_state": "unavailable",
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
        "callback_recorded": False,
        "signature_sha256": "",
    }
    if flow_id <= 0:
        refused["reason"] = "flow_not_stored"
        return refused
    secret = hmac_secret.strip()
    base = contract_base_url.rstrip("/")
    if len(secret) < 16 or not base:
        refused["reason"] = "callback_contract_unconfigured"
        return refused
    if not live_db_path.is_file() or not soar_db_path.is_file():
        refused["reason"] = "flow_not_stored"
        return refused
    with _connect(live_db_path) as conn:
        flow = conn.execute("SELECT * FROM live_flows WHERE flow_id = ?", (flow_id,)).fetchone()
    if flow is None:
        refused["reason"] = "flow_not_stored"
        return refused
    stored_sig = str(flow["callback_signature"] or "")
    if flow["callback_recorded"] and _SHA256_HEX.fullmatch(stored_sig):
        return {
            "schema_version": "live_soar_callback_v1",
            "evidence_state": "verified",
            "reason": "already_recorded",
            "execution_authorized": False,
            "containment_executed": False,
            "production_fusion_enabled": False,
            "callback_recorded": True,
            "signature_sha256": stored_sig,
            "thehive_case_id": flow["thehive_case_id"],
            "mttr_seconds": flow["mttr_seconds"],
            "flow_id": flow_id,
            "playbook_id": flow["playbook_id"],
        }
    candidate_id = f"live_flow:{flow_id}"
    repository = SoarPlaybookSqliteRepository(soar_db_path)
    approved = next(
        (
            record
            for record in repository.list_records_for_candidate(candidate_id)
            if record.state in {"approved", "executed_simulated"}
        ),
        None,
    )
    if approved is None:
        refused["reason"] = "playbook_not_approved"
        return refused
    verify_payload = {"candidate_id": candidate_id, "playbook_id": approved.playbook_id}
    verify_body = _canonical_body(verify_payload)
    verify_key = f"idem_{approved.playbook_id}_{approved.version}"
    verify_sig = _hmac_sha256(verify_body, secret)
    status, verified = _post_signed(
        f"{base}/api/v1/soar/verify-state",
        verify_body,
        verify_sig,
        verify_key,
    )
    if status != 200 or verified.get("state_verified") is not True:
        refused["reason"] = "verify_state_rejected"
        refused["http_status"] = status
        return refused
    from threatfusion.soar.n8n_thehive_misp_stack import TheHiveDeterministicClient

    probability = flow["rf_attack_probability"]
    confidence = float(probability) * 100.0 if probability is not None else 0.0
    case = TheHiveDeterministicClient(
        thehive_url=thehive_url,
        api_key=secret,
        outbox_db_path=outbox_db_path,
    ).create_case_from_soar(
        soar_record=approved,
        soar_repo=repository,
        rf_confidence_pct=confidence,
        incident_id=flow["campaign_id"],
    )
    queued_at = (
        approved.t_approval_queued
        if approved.t_approval_queued is not None
        else datetime.now(UTC).timestamp()
    )
    verified_at = datetime.now(UTC).timestamp()
    callback_payload = {
        "candidate_id": candidate_id,
        "playbook_id": approved.playbook_id,
        "case_id": case.case_id,
        "t_approval_queued": queued_at,
        "t_callback_verified": verified_at,
    }
    callback_body = _canonical_body(callback_payload)
    callback_sig = _hmac_sha256(callback_body, secret)
    callback_key = f"idem_{approved.playbook_id}_{approved.version}_cb"
    callback_status, callback = _post_signed(
        f"{base}/api/v1/soar/callback",
        callback_body,
        callback_sig,
        callback_key,
    )
    if callback_status != 200 or callback.get("callback_recorded") is not True:
        refused["reason"] = "callback_rejected"
        refused["http_status"] = callback_status
        refused["thehive_case_id"] = case.case_id
        return refused
    mttr = float(callback.get("t_response") or 0.0)
    _store_callback_receipt(
        live_db_path,
        flow_id,
        signature=callback_sig,
        case_id=case.case_id,
        mttr_seconds=mttr,
    )
    return {
        "schema_version": "live_soar_callback_v1",
        "evidence_state": "verified",
        "reason": "signed_callback_recorded",
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
        "callback_recorded": True,
        "signature_sha256": callback_sig,
        "thehive_case_id": case.case_id,
        "thehive_status": case.status,
        "mttr_seconds": mttr,
        "flow_id": flow_id,
        "playbook_id": approved.playbook_id,
        "candidate_id": candidate_id,
        "verify_state": True,
    }
