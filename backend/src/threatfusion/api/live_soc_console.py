"""Live analyst console services.

Scores a 14-feature flow only when the frozen Random Forest artifact verifies and
its input width matches the canonical feature contract. The autoencoder never
changes the alert decision. Analyst notes, MITRE answers, drift, and the n8n
workbench read local files. Containment stays unauthorized.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import sqlite3
import stat
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threatfusion.advisory.chromadb_mitre_rag import ChromaDbMitrePlaybookRag
from threatfusion.operations.bridge_noise import is_lab_bridge_noise
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
    ("analyst_verdict", "TEXT"),
    ("analyst_rationale", "TEXT"),
    ("analyst_verdict_actor", "TEXT"),
    ("analyst_verdict_at", "TEXT"),
    ("assignee_id", "TEXT"),
    ("review_status", "TEXT"),
    ("correlation_window_checked", "INTEGER"),
    ("source_event_id", "TEXT"),
    ("sensor_observation_json", "TEXT"),
    ("execution_path", "TEXT"),
    ("operator_id", "TEXT"),
    ("cert_sha256_prefix", "TEXT"),
    ("identity_verified", "INTEGER"),
    ("identity_label", "TEXT"),
    ("containment_state", "TEXT"),
    ("containment_at", "TEXT"),
    ("rollback_at", "TEXT"),
)

_ANALYST_VERDICTS = frozenset({"true_positive", "false_positive", "inconclusive"})
_REVIEW_STATUSES = frozenset({"unassigned", "in_review", "reviewed"})
_LOCAL_ACTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


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
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS live_flows_source_event_id
        ON live_flows(source_event_id)
        WHERE source_event_id IS NOT NULL
        """)
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


def _coerce_observed_at(value: str | None) -> str | None:
    """Return a UTC timestamp. An empty value means now. An invalid value is refused."""
    if value is None or not str(value).strip():
        return datetime.now(UTC).isoformat()
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat()


def _provenance_fields(
    provenance: Mapping[str, Any] | None,
) -> tuple[str | None, str | None, str | None, str | None, str | None, int | None]:
    """Copy caller-supplied entity fields. Missing fields stay empty and fail closed later."""
    if provenance is None:
        return None, None, None, None, None, None

    def _text(key: str) -> str | None:
        raw = provenance.get(key)
        if raw is None:
            return None
        text = str(raw).strip()
        return text or None

    clock = 1 if provenance.get("clock_synchronized") is True else 0
    return (
        _text("entity_namespace_id"),
        _text("src_entity_id"),
        _text("dst_entity_id"),
        _text("protocol"),
        _text("service_or_port"),
        clock,
    )


SENSOR_BRIDGE_SOURCE = "suricata_bridge"
SENSOR_BRIDGE_NAMESPACE = "lab:range-bridge-01"
_SENSOR_EVENT_ID = re.compile(r"^suricata_flow_v1:[0-9a-f]{64}$")
_ENTITY_ID_PREFIXES = (
    "attacker:",
    "victim:",
    "client:",
    "server:",
    "sensor:",
    "node:",
    "host:",
    "vm:",
)
_SENSOR_PROTOCOLS = frozenset({"tcp", "udp", "icmp", "other"})


def _probability_text(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "unavailable"
    number = float(value)
    if not math.isfinite(number):
        return "unavailable"
    return format(number, ".17g")


def _bare_ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or any(text.startswith(prefix) for prefix in _ENTITY_ID_PREFIXES):
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _sensor_observation_body(
    observation: Mapping[str, Any], score: Mapping[str, Any]
) -> dict[str, Any]:
    proto = str(observation["proto"])
    src = str(observation["src_ip"])
    dst = str(observation["dst_ip"])
    src_port = int(observation["src_port"])
    dst_port = int(observation["dst_port"])
    signature = observation.get("signature")
    signature_text = signature.strip() if isinstance(signature, str) and signature.strip() else ""
    suffix = signature_text or "flow only, no signature"

    def _endpoint(host: str, port: int) -> str:
        if ":" in host:
            return f"[{host}]:{port}"
        return f"{host}:{port}"

    return {
        "proto": proto,
        "src_ip": src,
        "src_port": src_port,
        "dst_ip": dst,
        "dst_port": dst_port,
        "signature": signature_text or None,
        "suricata_line": f"{proto} {_endpoint(src, src_port)} -> {_endpoint(dst, dst_port)}, {suffix}",
        "forest_line": (
            f"{score.get('decision')}, {_probability_text(score.get('rf_attack_probability'))}, "
            f"{score.get('reason')}"
        ),
    }


def _validate_sensor_request(
    features: Any,
    provenance: Any,
    observation: Any,
    source_event_id: Any,
) -> str | None:
    if not isinstance(features, Mapping):
        return "features_required"
    if not isinstance(observation, Mapping):
        return "sensor_observation_required"
    if not isinstance(provenance, Mapping):
        return "provenance_required"
    if provenance.get("entity_namespace_id") != SENSOR_BRIDGE_NAMESPACE:
        return "namespace_mismatch"
    if provenance.get("clock_synchronized") is not True:
        return "clock_not_synchronized"
    src = _bare_ip(provenance.get("src_entity_id"))
    dst = _bare_ip(provenance.get("dst_entity_id"))
    obs_src = _bare_ip(observation.get("src_ip"))
    obs_dst = _bare_ip(observation.get("dst_ip"))
    if src is None or dst is None or obs_src is None or obs_dst is None:
        return "prefixed_or_invalid_address"
    if src != obs_src or dst != obs_dst:
        return "address_mismatch"
    proto = observation.get("proto")
    if proto not in _SENSOR_PROTOCOLS or str(provenance.get("protocol") or "") != proto:
        return "invalid_sensor_observation"
    try:
        src_port = int(observation["src_port"])
        dst_port = int(observation["dst_port"])
    except (KeyError, TypeError, ValueError):
        return "invalid_sensor_observation"
    if src_port < 0 or src_port > 65535 or dst_port < 0 or dst_port > 65535:
        return "invalid_sensor_observation"
    if str(provenance.get("service_or_port") or "") != str(dst_port):
        return "invalid_sensor_observation"
    if not isinstance(source_event_id, str) or _SENSOR_EVENT_ID.fullmatch(source_event_id) is None:
        return "invalid_source_event_id"
    signature = observation.get("signature")
    if signature is not None and not isinstance(signature, str):
        return "invalid_sensor_observation"
    if is_lab_bridge_noise(src, dst, src_port, dst_port):
        return "bridge_noise_ignored"
    return None


def _refused_sensor(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "live_sensor_flow_v1",
        "evidence_state": "unavailable",
        "reason": reason,
        "decision": "withheld",
        "rf_attack_probability": None,
        "production_fusion_enabled": False,
        "source_label": SENSOR_BRIDGE_SOURCE,
        "duplicate": False,
    }


def persist_scored_flow(
    db_path: Path,
    features: Mapping[str, Any],
    score: Mapping[str, Any],
    *,
    campaign_id: str | None = None,
    source_label: str | None = None,
    case_title: str | None = None,
    observed_at_utc: str | None = None,
    provenance: Mapping[str, Any] | None = None,
    source_event_id: str | None = None,
    sensor_observation_json: str | None = None,
) -> dict[str, Any]:
    """Append one scored flow to the live WAL queue."""
    observed = _coerce_observed_at(observed_at_utc)
    if observed is None:
        return {
            "schema_version": "live_flow_score_v1",
            "evidence_state": "unavailable",
            "reason": "invalid_observed_at",
            "decision": "withheld",
            "rf_attack_probability": None,
            "production_fusion_enabled": False,
        }
    namespace, src_entity, dst_entity, protocol, service, clock = _provenance_fields(provenance)
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO live_flows (
                observed_at_utc, features_json, rf_attack_probability, decision,
                evidence_state, reason, model_sha256, production_fusion_enabled,
                campaign_id, source_label, case_title,
                entity_namespace_id, src_entity_id, dst_entity_id,
                flow_protocol, service_or_port, clock_synchronized,
                source_event_id, sensor_observation_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                namespace,
                src_entity,
                dst_entity,
                protocol,
                service,
                clock,
                source_event_id,
                sensor_observation_json,
            ),
        )
        flow_id = int(cursor.lastrowid)
    stored = dict(score)
    stored["flow_id"] = flow_id
    stored["observed_at_utc"] = observed
    stored["campaign_id"] = campaign_id
    stored["source_label"] = source_label
    stored["case_title"] = case_title
    stored["source_event_id"] = source_event_id
    stored["production_fusion_enabled"] = False
    if sensor_observation_json:
        try:
            stored["sensor_observation"] = json.loads(sensor_observation_json)
        except json.JSONDecodeError:
            stored["sensor_observation"] = None
    return stored


def record_suricata_bridge_flow(
    db_path: Path,
    features: Mapping[str, Any],
    *,
    repo_root: Path,
    provenance: Mapping[str, Any] | None,
    sensor_observation: Mapping[str, Any] | None,
    source_event_id: str | None,
    observed_at_utc: str | None = None,
    model: Any | None = None,
    supply_verified: bool | None = None,
) -> dict[str, Any]:
    """Score one adapted Suricata flow and store it under its own bridge campaign.

    The forest score is whatever the frozen model returns. The Suricata line is
    display text. No technique id is written onto the row.
    """
    reason = _validate_sensor_request(features, provenance, sensor_observation, source_event_id)
    if reason is not None or provenance is None or sensor_observation is None:
        return _refused_sensor(reason or "sensor_observation_required")
    if not isinstance(source_event_id, str):
        return _refused_sensor("invalid_source_event_id")
    campaign_id = f"campaign_suricata_bridge:{source_event_id}"
    with _connect(db_path) as conn:
        existing = conn.execute(
            """
            SELECT flow_id, decision, rf_attack_probability, reason, evidence_state,
                   campaign_id, source_label, case_title, sensor_observation_json,
                   observed_at_utc
            FROM live_flows
            WHERE source_event_id = ?
            """,
            (source_event_id,),
        ).fetchone()
    if existing is not None:
        body = {
            "schema_version": "live_sensor_flow_v1",
            "evidence_state": existing["evidence_state"],
            "reason": existing["reason"],
            "decision": existing["decision"],
            "rf_attack_probability": existing["rf_attack_probability"],
            "production_fusion_enabled": False,
            "source_label": existing["source_label"],
            "campaign_id": existing["campaign_id"],
            "case_title": existing["case_title"],
            "flow_id": int(existing["flow_id"]),
            "observed_at_utc": existing["observed_at_utc"],
            "source_event_id": source_event_id,
            "duplicate": True,
        }
        raw_observation = existing["sensor_observation_json"]
        if isinstance(raw_observation, str):
            try:
                body["sensor_observation"] = json.loads(raw_observation)
            except json.JSONDecodeError:
                body["sensor_observation"] = None
        return body
    score = score_canonical_flow(
        features,
        repo_root=repo_root,
        model=model,
        supply_verified=supply_verified,
    )
    if score.get("reason") != "frozen_random_forest_scored":
        refused = _refused_sensor(str(score.get("reason") or "unscored"))
        refused["model_sha256"] = score.get("model_sha256")
        return refused
    observation = _sensor_observation_body(sensor_observation, score)
    stored = persist_scored_flow(
        db_path,
        features,
        score,
        campaign_id=campaign_id,
        source_label=SENSOR_BRIDGE_SOURCE,
        case_title=None,
        observed_at_utc=observed_at_utc,
        provenance=provenance,
        source_event_id=source_event_id,
        sensor_observation_json=json.dumps(observation, sort_keys=True),
    )
    if stored.get("reason") == "invalid_observed_at":
        return _refused_sensor("invalid_observed_at")
    created = datetime.now(UTC).isoformat()
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO live_campaigns (
                campaign_id, title, source_label, created_at_utc, member_count
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (campaign_id, "Live sensor flow", SENSOR_BRIDGE_SOURCE, created, 1),
        )
    stored["schema_version"] = "live_sensor_flow_v1"
    stored["duplicate"] = False
    stored["sensor_observation"] = observation
    stored["case_title"] = None
    return stored


def list_live_flows(db_path: Path, *, limit: int = 20) -> list[dict[str, Any]]:
    """Return the newest live flows. A missing database is an empty queue."""
    if not db_path.is_file():
        return []
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT flow_id, observed_at_utc, rf_attack_probability, decision,
                   evidence_state, reason, model_sha256, triage_state
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
                   service_or_port, clock_synchronized, features_json,
                   analyst_verdict, analyst_rationale, analyst_verdict_actor,
                   analyst_verdict_at, assignee_id, review_status,
                   correlation_window_checked, source_event_id, sensor_observation_json,
                   execution_path, operator_id, cert_sha256_prefix,
                   identity_verified, identity_label
            FROM live_flows
            ORDER BY flow_id DESC
            LIMIT ?
            """,
            (max(1, min(limit, 100)),),
        ).fetchall()
    published: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["glass_box"] = build_glass_box_checklist(item)
        raw_observation = item.pop("sensor_observation_json", None)
        item.pop("features_json", None)
        if isinstance(raw_observation, str) and raw_observation:
            try:
                parsed_observation = json.loads(raw_observation)
            except json.JSONDecodeError:
                parsed_observation = None
            item["sensor_observation"] = (
                parsed_observation if isinstance(parsed_observation, dict) else None
            )
        else:
            item["sensor_observation"] = None
        if not item.get("review_status"):
            item["review_status"] = "unassigned"
        published.append(item)
    return published


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
        "bridge_flow_count": sum(
            1 for row in flows if row.get("source_label") == SENSOR_BRIDGE_SOURCE
        ),
        "campaign_count": len(campaigns),
        "incident_count": len(incidents),
        "queue_count": len(flows) + len(incidents),
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


_ATTACK_SHAPED_UDP: dict[str, float] = {
    "duration_ms": 3200,
    "fwd_packets": 240,
    "bwd_packets": 4,
    "fwd_bytes": 19200,
    "bwd_bytes": 320,
    "packets_per_second": 76.25,
    "bytes_per_second": 6100.0,
    "fwd_packet_length_mean": 80.0,
    "bwd_packet_length_mean": 80.0,
    "dst_port": 53,
    "protocol_tcp": 0,
    "protocol_udp": 1,
    "protocol_icmp": 0,
    "protocol_other": 0,
}

# The technique id is the scenario label. The frozen forest does not emit it.
LIVE_SCENARIO_REPLAYS: tuple[dict[str, Any], ...] = (
    {
        "scenario_id": "web_exploit",
        "title": "Web exploit replay",
        "scenario_label": "T1190",
        "dst_port": 80,
        "protocol_tcp": 0,
        "protocol_udp": 1,
    },
    {
        "scenario_id": "ssh_brute",
        "title": "SSH brute replay",
        "scenario_label": "T1110",
        "dst_port": 22,
        "protocol_tcp": 0,
        "protocol_udp": 1,
    },
    {
        "scenario_id": "internal_recon",
        "title": "Internal recon replay",
        "scenario_label": "T1046",
        "dst_port": 445,
        "protocol_tcp": 0,
        "protocol_udp": 1,
        "guard_value": "10.0.0.4",
        "provenance": {
            "entity_namespace_id": "lab:edge-01",
            "src_entity_id": "10.0.0.4",
            "dst_entity_id": "10.0.0.5",
            "protocol": "udp",
            "service_or_port": "445",
            "clock_synchronized": True,
        },
    },
    {
        "scenario_id": "benign_false_alarm",
        "title": "Benign false alarm",
        "scenario_label": None,
        "dst_port": 80,
        "protocol_tcp": 1,
        "protocol_udp": 0,
    },
)


def constitutional_health(repo_root: Path) -> dict[str, Any]:
    """Run the boundary preflight and the seven repository-truth checks.

    The digest list is the supply-chain result. A dirty worktree fails check 1.
    """
    from threatfusion.evaluation.boundary_preflight import run_boundary_preflight
    from threatfusion.evaluation.repo_truth_audit import run_repository_truth_audit

    boundary = run_boundary_preflight(active=repo_root, venv=repo_root / "threatfusion-venv")
    audit = run_repository_truth_audit(repo_root)
    digests = {
        name: {
            "sha256": entry.get("actual_sha256") or entry.get("expected_sha256"),
            "verified": entry.get("matched") is True,
        }
        for name, entry in audit.model_digests.items()
    }
    return {
        "schema_version": "live_constitutional_health_v1",
        "evidence_state": (
            "verified" if audit.all_checks_passed and boundary.passed else "unavailable"
        ),
        "boundary_verdict": boundary.decision_verdict,
        "truth_verdict": audit.decision_verdict,
        "checks_passed": sum(1 for check in audit.checks if check.passed),
        "checks_total": len(audit.checks),
        "checks": [
            {"check_id": check.check_id, "name": check.name, "passed": check.passed}
            for check in audit.checks
        ],
        "model_digests": digests,
        "receipt_sha256": audit.receipt_digest,
        "production_fusion_enabled": False,
        "tf_008_through_tf_011": "open",
        "containment_executed": False,
    }


def replay_live_scenarios(
    db_path: Path,
    *,
    repo_root: Path,
    model: Any | None = None,
    supply_verified: bool | None = None,
) -> dict[str, Any]:
    """Score four labeled scenarios with the frozen Random Forest and store them.

    The technique id is stored as a scenario label. It is not a model output.
    The internal-recon row asks the private-IP guard and does not perform a lookup.
    """
    campaign_id = "campaign_live_scenarios:" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    created = datetime.now(UTC).isoformat()
    stored: list[dict[str, Any]] = []
    for spec in LIVE_SCENARIO_REPLAYS:
        features = dict(_ATTACK_SHAPED_UDP)
        features["dst_port"] = spec["dst_port"]
        features["protocol_tcp"] = spec["protocol_tcp"]
        features["protocol_udp"] = spec["protocol_udp"]
        score = score_canonical_flow(
            features,
            repo_root=repo_root,
            model=model,
            supply_verified=supply_verified,
        )
        label = spec["scenario_label"]
        title = spec["title"] if label is None else f"{spec['title']} (scenario label {label})"
        row = persist_scored_flow(
            db_path,
            features,
            score,
            campaign_id=campaign_id,
            source_label="live_scenario_replay",
            case_title=title,
            provenance=spec.get("provenance"),
        )
        row["scenario_id"] = spec["scenario_id"]
        row["scenario_label"] = label
        row["case_title"] = title
        guard_value = spec.get("guard_value")
        if isinstance(guard_value, str):
            status, guard = private_ip_guard_response(guard_value)
            row["misp_guard_status"] = status
            row["private_ip_guard_triggered"] = guard.get("private_ip_guard_triggered")
            row["external_lookup_performed"] = False
        stored.append(row)
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO live_campaigns (
                campaign_id, title, source_label, created_at_utc, member_count
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                campaign_id,
                "Four-scenario live replay",
                "live_scenario_replay",
                created,
                len(stored),
            ),
        )
    return {
        "schema_version": "live_scenario_replay_v1",
        "evidence_state": "verified" if stored else "unavailable",
        "reason": "scenarios_scored_by_frozen_random_forest",
        "campaign_id": campaign_id,
        "source_label": "live_scenario_replay",
        "production_fusion_enabled": False,
        "execution_authorized": False,
        "containment_executed": False,
        "ae_changes_alert_decision": False,
        "member_count": len(stored),
        "flows": stored,
    }


def replay_supplied_flows(
    db_path: Path,
    flows: list[Any],
    *,
    repo_root: Path,
    model: Any | None = None,
    supply_verified: bool | None = None,
) -> dict[str, Any]:
    """Score caller-supplied flows, store their timestamps and entity keys, and return them.

    The frozen Random Forest still makes the decision. Entity keys are stored only
    when the caller supplies them.
    """
    stored: list[dict[str, Any]] = []
    for item in flows:
        if not isinstance(item, Mapping):
            continue
        features = item.get("features")
        if not isinstance(features, Mapping):
            continue
        observed = item.get("observed_at_utc")
        if isinstance(observed, str) and _coerce_observed_at(observed) is None:
            return {
                "schema_version": "live_campaign_replay_v1",
                "evidence_state": "unavailable",
                "reason": "invalid_observed_at",
                "production_fusion_enabled": False,
                "execution_authorized": False,
                "member_count": 0,
                "flows": [],
            }
    for item in flows:
        if not isinstance(item, Mapping):
            continue
        features = item.get("features")
        if not isinstance(features, Mapping):
            continue
        provenance = item.get("provenance")
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
                campaign_id="campaign_replayed_flows",
                source_label="replayed_flow",
                case_title="Replayed flow",
                observed_at_utc=(
                    item.get("observed_at_utc")
                    if isinstance(item.get("observed_at_utc"), str)
                    else None
                ),
                provenance=provenance if isinstance(provenance, Mapping) else None,
            )
        )
    return {
        "schema_version": "live_campaign_replay_v1",
        "evidence_state": "verified" if stored else "unavailable",
        "reason": "supplied_flows_scored_by_frozen_random_forest",
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


def operator_stamp(actor_id: str, policy_dir: Path | None) -> dict[str, Any]:
    """Stamp a verified operator only when an enrolled credential matches this actor."""
    unverified = {
        "operator_id": "",
        "cert_sha256_prefix": "",
        "identity_verified": False,
        "identity_label": "unverified_local_label",
    }
    author = actor_id.strip()
    if author == "analyst_a" or policy_dir is None or _LOCAL_ACTOR.fullmatch(author) is None:
        return unverified
    from threatfusion.operations.human_credentials import active_fingerprint

    fingerprint = active_fingerprint(policy_dir, author)
    if not fingerprint:
        return unverified
    return {
        "operator_id": author,
        "cert_sha256_prefix": fingerprint[:16],
        "identity_verified": True,
        "identity_label": "verified_operator",
    }


def _store_operator_stamp(db_path: Path, flow_id: int, stamp: Mapping[str, Any]) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET operator_id = ?, cert_sha256_prefix = ?,
                identity_verified = ?, identity_label = ?
            WHERE flow_id = ?
            """,
            (
                stamp.get("operator_id") or None,
                stamp.get("cert_sha256_prefix") or None,
                1 if stamp.get("identity_verified") else 0,
                stamp.get("identity_label") or "unverified_local_label",
                flow_id,
            ),
        )


def enroll_lab_operator(directory: Path, actor_id: str) -> dict[str, Any]:
    """Issue a short-lived lab client certificate and enroll its fingerprint."""
    import subprocess
    import tempfile

    from threatfusion.api.analyst_tls_service import ANALYST_URI_PREFIX
    from threatfusion.operations import human_credentials as policy
    from threatfusion.schemas.analyst_state import valid_actor_id

    actor = actor_id.strip()
    refused = {
        "evidence_state": "unavailable",
        "identity_verified": False,
        "identity_label": "unverified_local_label",
        "operator_id": "",
        "cert_sha256_prefix": "",
    }
    if actor == "analyst_a" or not valid_actor_id(actor):
        refused["reason"] = "actor_rejected"
        return refused
    try:
        policy.init_policy_directory(directory)
    except policy.CredentialPolicyError:
        refused["reason"] = "policy_directory_rejected"
        return refused
    existing = policy.active_fingerprint(directory, actor)
    if existing:
        stamp = operator_stamp(actor, directory)
        stamp["evidence_state"] = "verified"
        stamp["reason"] = "already_enrolled"
        return stamp
    try:
        with tempfile.TemporaryDirectory(prefix="tf-lab-operator-") as tmp:
            folder = Path(tmp)
            ca_cert, ca_key = folder / "ca.pem", folder / "ca.key"
            cert, key = folder / "client.pem", folder / "client.key"
            request, extension = folder / "client.csr", folder / "client.ext"
            extension.write_text(
                "basicConstraints=CA:FALSE\n"
                "keyUsage=digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=clientAuth\n"
                f"subjectAltName=URI:{ANALYST_URI_PREFIX}{actor}\n",
                encoding="ascii",
            )
            commands = (
                (
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(ca_key),
                    "-out",
                    str(ca_cert),
                    "-days",
                    "30",
                    "-sha256",
                    "-subj",
                    f"/CN={actor} lab CA",
                ),
                (
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(request),
                    "-subj",
                    f"/CN={actor}",
                ),
                (
                    "x509",
                    "-req",
                    "-in",
                    str(request),
                    "-CA",
                    str(ca_cert),
                    "-CAkey",
                    str(ca_key),
                    "-CAcreateserial",
                    "-out",
                    str(cert),
                    "-days",
                    "30",
                    "-sha256",
                    "-extfile",
                    str(extension),
                ),
            )
            for command in commands:
                result = subprocess.run(
                    ["openssl", *command],
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
                if result.returncode != 0:
                    refused["reason"] = "certificate_not_issued"
                    return refused
            policy_file = directory / policy.FILENAME
            if policy_file.is_file():
                policy.enroll(directory, cert, ca_cert, actor, create=False)
            else:
                policy.init(directory, cert, ca_cert, actor)
    except (policy.CredentialPolicyError, OSError, subprocess.TimeoutExpired):
        refused["reason"] = "enrollment_rejected"
        return refused
    stamp = operator_stamp(actor, directory)
    if not stamp["identity_verified"]:
        refused["reason"] = "enrollment_rejected"
        return refused
    stamp["evidence_state"] = "verified"
    stamp["reason"] = "lab_operator_enrolled"
    return stamp


def approve_live_soar(
    live_db_path: Path,
    soar_db_path: Path,
    *,
    flow_id: int,
    actor_id: str,
    reason: str,
    policy_dir: Path | None = None,
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
        stamp = operator_stamp(author, policy_dir)
        _store_operator_stamp(live_db_path, flow_id, stamp)
        receipt.update(stamp)
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
    stamp = operator_stamp(author, policy_dir)
    _store_operator_stamp(live_db_path, flow_id, stamp)
    receipt.update(stamp)
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
    execution_path: str,
) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET callback_signature = ?, thehive_case_id = ?, mttr_seconds = ?,
                callback_recorded = 1, execution_path = ?
            WHERE flow_id = ?
            """,
            (signature, case_id, mttr_seconds, execution_path, flow_id),
        )


def _mark_execution_path(db_path: Path, flow_id: int, execution_path: str) -> None:
    if not db_path.is_file():
        return
    with _connect(db_path) as conn:
        conn.execute(
            "UPDATE live_flows SET execution_path = ? WHERE flow_id = ?",
            (execution_path, flow_id),
        )


def _n8n_result_dict(payload: Any) -> dict[str, Any]:
    if isinstance(payload, list) and payload:
        payload = payload[0]
    if isinstance(payload, dict) and isinstance(payload.get("json"), dict):
        payload = payload["json"]
    return payload if isinstance(payload, dict) else {}


LOCAL_CONTRACT_FALLBACK = "local_contract_fallback"
N8N_LIVE_CONTAINER = "n8n_live_container"


def _n8n_contract_base(contract_base_url: str, override: str | None) -> str:
    if override and override.strip():
        return override.strip().rstrip("/")
    parsed = urllib.parse.urlparse(contract_base_url)
    port = parsed.port or 8766
    return f"http://host.docker.internal:{port}"


def _post_n8n_webhook(webhook_url: str, envelope: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    encoded = json.dumps(envelope).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=encoded,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(65536)
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        raw = exc.read(65536)
        status = int(exc.code)
    payload = json.loads(raw.decode("utf-8")) if raw else {}
    return status, _n8n_result_dict(payload)


def _dispatch_through_live_n8n(
    live_db_path: Path,
    flow: sqlite3.Row,
    approved: Any,
    repository: Any,
    refused: dict[str, Any],
    *,
    flow_id: int,
    candidate_id: str,
    secret: str,
    thehive_url: str,
    outbox_db_path: Path | None,
    webhook_url: str,
    contract_base_url: str,
) -> dict[str, Any]:
    """Hand the exact signed bytes to n8n. A missing callback is a refusal."""
    from threatfusion.soar.n8n_thehive_misp_stack import TheHiveDeterministicClient
    from threatfusion.soar.playbook_ledger import SoarStateTransitionError

    verify_body = _canonical_body(
        {"candidate_id": candidate_id, "playbook_id": approved.playbook_id}
    )
    verify_key = f"idem_{approved.playbook_id}_{approved.version}"
    verify_sig = _hmac_sha256(verify_body, secret)
    case = None
    try:
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
    except SoarStateTransitionError:
        case = None
    callback_body = ""
    callback_sig = ""
    callback_key = ""
    if case is not None:
        queued_at = (
            approved.t_approval_queued
            if approved.t_approval_queued is not None
            else datetime.now(UTC).timestamp()
        )
        callback_body = _canonical_body(
            {
                "candidate_id": candidate_id,
                "playbook_id": approved.playbook_id,
                "case_id": case.case_id,
                "t_approval_queued": queued_at,
                "t_callback_verified": datetime.now(UTC).timestamp(),
            }
        )
        callback_sig = _hmac_sha256(callback_body, secret)
        callback_key = f"idem_{approved.playbook_id}_{approved.version}_cb"
    target = str(flow["src_entity_id"] or "")
    envelope = {
        "contract_base_url": contract_base_url,
        "verify_body": verify_body.decode("utf-8"),
        "verify_signature": verify_sig,
        "verify_idempotency_key": verify_key,
        "callback_body": callback_body.decode("utf-8") if callback_body else "",
        "callback_signature": callback_sig,
        "callback_idempotency_key": callback_key,
        "target_value": target if _bare_ip(target) else "",
    }
    try:
        status, result = _post_n8n_webhook(webhook_url, envelope)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        _mark_execution_path(live_db_path, flow_id, N8N_LIVE_CONTAINER)
        refused["reason"] = "n8n_unreachable"
        refused["execution_path"] = N8N_LIVE_CONTAINER
        return refused
    recorded = result.get("callback_recorded") is True
    if status != 200 or not recorded or case is None:
        _mark_execution_path(live_db_path, flow_id, N8N_LIVE_CONTAINER)
        refused["reason"] = "verify_state_rejected" if not recorded else "callback_rejected"
        refused["http_status"] = result.get("verify_status") or status
        refused["execution_path"] = N8N_LIVE_CONTAINER
        refused["private_ip_guard_triggered"] = result.get("private_ip_guard_triggered") is True
        return refused
    mttr = result.get("t_response")
    if not isinstance(mttr, (int, float)) or isinstance(mttr, bool):
        mttr = 0.0
    four_block_labels = (
        "Block 1 (Executive Summary):",
        "Block 2 (Attack Timeline):",
        "Block 3 (MITRE Mapping):",
        "Block 4 (Cryptographic SOAR Status):",
    )
    _store_callback_receipt(
        live_db_path,
        flow_id,
        signature=callback_sig,
        case_id=case.case_id,
        mttr_seconds=float(mttr),
        execution_path=N8N_LIVE_CONTAINER,
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
        "four_block_recorded": all(label in case.description for label in four_block_labels),
        "mttr_seconds": float(mttr),
        "flow_id": flow_id,
        "playbook_id": approved.playbook_id,
        "candidate_id": candidate_id,
        "verify_state": True,
        "execution_path": N8N_LIVE_CONTAINER,
        "private_ip_guard_triggered": result.get("private_ip_guard_triggered") is True,
    }


def dispatch_approved_callback(
    live_db_path: Path,
    soar_db_path: Path,
    *,
    flow_id: int,
    contract_base_url: str,
    hmac_secret: str,
    thehive_url: str = "http://127.0.0.1:9",
    outbox_db_path: Path | None = None,
    n8n_webhook_url: str | None = None,
    n8n_contract_base_url: str | None = None,
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
            "execution_path": flow["execution_path"] or LOCAL_CONTRACT_FALLBACK,
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
    webhook = (n8n_webhook_url or "").strip()
    if webhook:
        return _dispatch_through_live_n8n(
            live_db_path,
            flow,
            approved,
            repository,
            refused,
            flow_id=flow_id,
            candidate_id=candidate_id,
            secret=secret,
            thehive_url=thehive_url,
            outbox_db_path=outbox_db_path,
            webhook_url=webhook,
            contract_base_url=_n8n_contract_base(base, n8n_contract_base_url),
        )
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
        _mark_execution_path(live_db_path, flow_id, LOCAL_CONTRACT_FALLBACK)
        refused["reason"] = "verify_state_rejected"
        refused["http_status"] = status
        refused["execution_path"] = LOCAL_CONTRACT_FALLBACK
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
    four_block_labels = (
        "Block 1 (Executive Summary):",
        "Block 2 (Attack Timeline):",
        "Block 3 (MITRE Mapping):",
        "Block 4 (Cryptographic SOAR Status):",
    )
    _store_callback_receipt(
        live_db_path,
        flow_id,
        signature=callback_sig,
        case_id=case.case_id,
        mttr_seconds=mttr,
        execution_path=LOCAL_CONTRACT_FALLBACK,
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
        "four_block_recorded": all(label in case.description for label in four_block_labels),
        "t_approval_queued": callback.get("t_approval_queued"),
        "t_callback_verified": callback.get("t_callback_verified"),
        "mttr_seconds": mttr,
        "flow_id": flow_id,
        "playbook_id": approved.playbook_id,
        "candidate_id": candidate_id,
        "verify_state": True,
        "execution_path": LOCAL_CONTRACT_FALLBACK,
    }


def store_flow_provenance(
    db_path: Path,
    flow_id: int,
    *,
    entity_namespace_id: str,
    src_entity_id: str,
    dst_entity_id: str,
    protocol: str,
    service_or_port: str,
    clock_synchronized: bool,
) -> dict[str, Any]:
    """Store the entity key used by the correlation engine. This does not invent one."""
    if not db_path.is_file():
        return {"evidence_state": "unavailable", "reason": "flow_not_stored"}
    with _connect(db_path) as conn:
        updated = conn.execute(
            """
            UPDATE live_flows
            SET entity_namespace_id = ?, src_entity_id = ?, dst_entity_id = ?,
                flow_protocol = ?, service_or_port = ?, clock_synchronized = ?
            WHERE flow_id = ?
            """,
            (
                entity_namespace_id,
                src_entity_id,
                dst_entity_id,
                protocol,
                service_or_port,
                1 if clock_synchronized else 0,
                flow_id,
            ),
        )
        if updated.rowcount != 1:
            return {"evidence_state": "unavailable", "reason": "flow_not_stored"}
    return {
        "evidence_state": "verified",
        "flow_id": flow_id,
        "clock_synchronized": clock_synchronized,
    }


def _candidate_from_attack_row(row: sqlite3.Row) -> Any:
    from threatfusion.features.network_behavior import (
        NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
        UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
    )
    from threatfusion.schemas.alert_candidate import (
        ALERT_CANDIDATE_SCHEMA_VERSION,
        DECISION_POLICY_VERSION,
        DETECTOR_IDENTITY,
        DETECTOR_VERSION,
        AlertCandidate,
        derive_alert_candidate_id,
        derive_source_event_id,
    )

    observed = datetime.fromisoformat(str(row["observed_at_utc"]).replace("Z", "+00:00"))
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=UTC)
    source_event_id = derive_source_event_id(
        source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        manifest_sha256="b" * 64,
        source_member_sha256=f"{int(row['flow_id']):064x}",
        row_number=int(row["flow_id"]),
    )
    model_sha = str(row["model_sha256"])
    candidate_id = derive_alert_candidate_id(
        source_event_id=source_event_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256=model_sha,
        decision_policy_version=DECISION_POLICY_VERSION,
    )
    return AlertCandidate(
        schema_version=ALERT_CANDIDATE_SCHEMA_VERSION,
        alert_candidate_id=candidate_id,
        source_event_id=source_event_id,
        correlation_id=str(uuid.uuid4()),
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256=model_sha,
        feature_contract_identity=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
        source_representation_identity=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        observed_at=observed,
        created_at=observed,
        uncalibrated_model_score=float(row["rf_attack_probability"]),
        decision_threshold=0.5,
        decision_policy_version=DECISION_POLICY_VERSION,
        decision="Attack",
        inference_status="completed",
        reason="inference_succeeded",
    )


def _drop_stale_incidents(incidents_db_path: Path, keep_ids: set[str]) -> None:
    """Remove incident rows from an earlier stitch of a smaller attack set."""
    if not incidents_db_path.is_file():
        return
    connection = sqlite3.connect(str(incidents_db_path), timeout=5.0)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "incidents" not in tables:
            return
        if keep_ids:
            marks = ",".join("?" for _ in keep_ids)
            params = tuple(sorted(keep_ids))
            if "incident_constituent_alerts" in tables:
                connection.execute(
                    f"DELETE FROM incident_constituent_alerts WHERE incident_id NOT IN ({marks})",
                    params,
                )
            connection.execute(
                f"DELETE FROM incidents WHERE incident_id NOT IN ({marks})",
                params,
            )
        else:
            if "incident_constituent_alerts" in tables:
                connection.execute("DELETE FROM incident_constituent_alerts")
            connection.execute("DELETE FROM incidents")
        connection.commit()
    except sqlite3.Error:
        return
    finally:
        connection.close()


def correlate_stored_attacks(live_db_path: Path, incidents_db_path: Path) -> dict[str, Any]:
    """Stitch stored Attack rows with the dual-window engine.

    Rows without a verified entity key stay singletons. Benign rows are not grouped.
    The burst window is 30.0 seconds and the campaign window is 600.0 seconds.
    A gap equal to either boundary stays inside that window.
    """
    from threatfusion.alerts.correlation_engine import (
        BURST_WINDOW_SECONDS,
        CAMPAIGN_WINDOW_SECONDS,
        CorrelatableAlert,
        EntityProvenanceContract,
        IncidentCorrelationEngine,
        IncidentSqliteRepository,
    )
    from threatfusion.api.analyst_dashboard import build_unified_incident_timeline

    empty = {
        "schema_version": "live_correlation_v1",
        "evidence_state": "unavailable",
        "reason": "no_attack_flows",
        "production_fusion_enabled": False,
        "incident_count": 0,
        "burst_incident_count": 0,
        "campaign_incident_count": 0,
        "correlated_flow_count": 0,
        "burst_window_seconds": BURST_WINDOW_SECONDS,
        "campaign_window_seconds": CAMPAIGN_WINDOW_SECONDS,
        "max_constituent_count": 0,
        "incidents": [],
        "timeline": build_unified_incident_timeline(flow_members=[]),
    }
    if not live_db_path.is_file():
        return empty
    with _connect(live_db_path) as conn:
        rows = conn.execute("""
            SELECT * FROM live_flows
            WHERE decision = 'Attack' AND rf_attack_probability >= 0.5
            ORDER BY flow_id ASC
            """).fetchall()
    correlatable = []
    checked_flow_ids: list[int] = []
    for row in rows:
        try:
            candidate = _candidate_from_attack_row(row)
        except (TypeError, ValueError, RuntimeError):
            continue
        checked_flow_ids.append(int(row["flow_id"]))
        provenance = EntityProvenanceContract(
            entity_namespace_id=row["entity_namespace_id"],
            clock_synchronized=row["clock_synchronized"] == 1,
            src_entity_id=row["src_entity_id"],
            dst_entity_id=row["dst_entity_id"],
            protocol=row["flow_protocol"],
            service_or_port=row["service_or_port"],
            observed_at_utc=row["observed_at_utc"],
            address_reuse_or_nat=False,
            max_clock_skew_seconds=0.0,
        )
        correlatable.append(CorrelatableAlert(candidate=candidate, provenance=provenance))
    if not correlatable:
        return empty
    result = IncidentCorrelationEngine(IncidentSqliteRepository(incidents_db_path)).correlate(
        correlatable
    )
    _mark_correlation_window_checked(live_db_path, checked_flow_ids)
    _drop_stale_incidents(
        incidents_db_path, {incident.incident_id for incident in result.incidents}
    )
    observed_by_id = {
        item.candidate.alert_candidate_id: item.candidate.observed_at.astimezone(UTC).isoformat()
        for item in correlatable
    }
    incidents = [
        {
            "incident_id": incident.incident_id,
            "correlation_mode": incident.correlation_mode,
            "window_type": incident.window_type,
            "correlation_rule_id": incident.correlation_rule_id,
            "constituent_alert_count": incident.constituent_alert_count,
            "earliest_observed_at": incident.earliest_observed_at,
            "latest_observed_at": incident.latest_observed_at,
        }
        for incident in result.incidents
    ]
    members = []
    for incident in result.incidents:
        for alert_id in incident.constituent_alert_ids:
            justification = incident.member_justifications.get(alert_id)
            member = {
                "observed_at": observed_by_id.get(alert_id, incident.earliest_observed_at),
                "alert_candidate_id": alert_id,
                "summary": incident.correlation_mode,
                "window_type": incident.window_type,
                "correlation_mode": incident.correlation_mode,
                "matched_relationship_key": (
                    None if justification is None else justification.matched_relationship_key
                ),
            }
            if justification is not None:
                member["delta_seconds"] = justification.delta_seconds
            members.append(member)
    burst = sum(
        1 for incident in result.incidents if incident.correlation_mode == "burst_correlated"
    )
    campaign = sum(
        1 for incident in result.incidents if incident.correlation_mode == "campaign_correlated"
    )
    stitched = {"burst_correlated", "campaign_correlated"}
    correlated_flow_count = sum(
        incident.constituent_alert_count
        for incident in result.incidents
        if incident.correlation_mode in stitched
    )
    return {
        "schema_version": "live_correlation_v1",
        "evidence_state": "verified",
        "reason": "dual_window_correlation",
        "production_fusion_enabled": False,
        "incident_count": len(incidents),
        "burst_incident_count": burst,
        "campaign_incident_count": campaign,
        "correlated_flow_count": correlated_flow_count,
        "burst_window_seconds": BURST_WINDOW_SECONDS,
        "campaign_window_seconds": CAMPAIGN_WINDOW_SECONDS,
        "max_constituent_count": max(
            (item["constituent_alert_count"] for item in incidents), default=0
        ),
        "incidents": incidents,
        "timeline": build_unified_incident_timeline(flow_members=members),
    }


def _mark_correlation_window_checked(db_path: Path, flow_ids: Sequence[int]) -> None:
    """Record that the 30.0s and 600.0s windows were applied to these Attack rows."""
    if not flow_ids or not db_path.is_file():
        return
    with _connect(db_path) as conn:
        conn.executemany(
            "UPDATE live_flows SET correlation_window_checked = 1 WHERE flow_id = ?",
            [(flow_id,) for flow_id in flow_ids],
        )


def build_glass_box_checklist(row: Mapping[str, Any]) -> dict[str, Any]:
    """Five checks from stored columns. The analyst verdict is not the forest decision."""
    from threatfusion.soar.n8n_thehive_misp_stack import is_rfc1918_or_loopback_ip

    parsed: Any = None
    raw_features = row.get("features_json")
    if isinstance(raw_features, str):
        try:
            parsed = json.loads(raw_features)
        except json.JSONDecodeError:
            parsed = None
    contract_ok = False
    if isinstance(parsed, dict):
        vector, _reason = _finite_feature_vector(parsed)
        contract_ok = vector is not None
    try:
        probability_ok = row.get("rf_attack_probability") is not None and math.isfinite(
            float(row["rf_attack_probability"])
        )
    except (TypeError, ValueError):
        probability_ok = False
    rf_ok = (
        row.get("reason") == "frozen_random_forest_scored"
        and row.get("decision") in {"Attack", "Benign"}
        and row.get("evidence_state") == "verified"
        and probability_ok
    )
    if row.get("decision") == "Benign":
        correlation = {
            "id": "correlation_window_checked",
            "status": "excluded",
            "passed": False,
            "detail": "Benign rows are not correlation members.",
        }
    elif row.get("correlation_window_checked") == 1:
        correlation = {
            "id": "correlation_window_checked",
            "status": "checked",
            "passed": True,
            "detail": "The 30.0 second and 600.0 second windows were applied.",
        }
    else:
        correlation = {
            "id": "correlation_window_checked",
            "status": "not_recorded",
            "passed": False,
            "detail": "This Attack row has not been submitted to the correlation windows.",
        }
    addresses = _stored_ipv4_addresses(row.get("src_entity_id"), row.get("dst_entity_id"))
    if not addresses:
        misp = {
            "id": "misp_rfc1918_guard",
            "status": "not_recorded",
            "passed": False,
            "private_ip_guard_triggered": False,
            "external_lookup_performed": False,
            "detail": "No address is stored on this flow.",
        }
    else:
        blocked = any(is_rfc1918_or_loopback_ip(item) for item in addresses)
        misp = {
            "id": "misp_rfc1918_guard",
            "status": "refused" if blocked else "clear",
            "passed": True,
            "private_ip_guard_triggered": blocked,
            "external_lookup_performed": False,
            "detail": "Stored addresses were classified locally. No external lookup was performed.",
        }
    entry = str(row.get("entry_sha256") or "")
    chain_ok = row.get("audit_chain_verified") == 1 and _SHA256_HEX.match(entry) is not None
    return {
        "schema_version": "glass_box_evidence_v1",
        "frozen_rf_decision": row.get("decision"),
        "analyst_verdict": row.get("analyst_verdict") or None,
        "items": [
            {
                "id": "flow_contract_valid",
                "status": "valid" if contract_ok else "invalid",
                "passed": contract_ok,
                "detail": (
                    "All 14 canonical features are finite."
                    if contract_ok
                    else "The stored feature contract is incomplete."
                ),
            },
            {
                "id": "rf_scored",
                "status": "scored" if rf_ok else "unscored",
                "passed": rf_ok,
                "detail": "The frozen Random Forest decision is stored separately from the analyst verdict.",
            },
            correlation,
            misp,
            {
                "id": "soar_hash_chain",
                "status": "verified" if chain_ok else "pending",
                "passed": chain_ok,
                "detail": (
                    "SHA-256 chain verified."
                    if chain_ok
                    else "No verified hash-chain receipt is stored."
                ),
            },
        ],
    }


def private_ip_guard_response(value: str) -> tuple[int, dict[str, Any]]:
    """Return HTTP 422 for RFC1918, IPv6 ULA, loopback, or link-local. No lookup is performed."""
    from threatfusion.soar.n8n_thehive_misp_stack import is_rfc1918_or_loopback_ip

    blocked = is_rfc1918_or_loopback_ip(value)
    if blocked:
        return 422, {
            "error": "RFC1918 private IP lookup forbidden",
            "private_ip_guard_triggered": True,
            "external_lookup_performed": False,
            "value": value.strip(),
        }
    return 200, {
        "private_ip_guard_triggered": False,
        "external_lookup_performed": False,
        "matched": False,
        "value": value.strip(),
    }


_TRIAGE_ACTIONS = {
    "acknowledge": "acknowledged",
    "escalate": "escalated",
    "dismiss": "dismissed",
}


def _stored_ipv4_addresses(*values: object) -> tuple[str, ...]:
    """Keep stored IPv4 entity ids. Other text is not treated as an address."""
    import ipaddress

    found: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        text = value.strip()
        try:
            parsed = ipaddress.ip_address(text)
        except ValueError:
            continue
        if parsed.version != 4:
            continue
        rendered = str(parsed)
        if rendered not in found:
            found.append(rendered)
    return tuple(found)


def _any_non_public_ipv4(addresses: Sequence[str]) -> bool:
    """True when a stored address is private, loopback, or link-local."""
    import ipaddress

    for item in addresses:
        parsed = ipaddress.ip_address(item)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            return True
    return False


def _shift_handoff_markdown(
    *,
    flow_id: int,
    report: Mapping[str, Any],
    brief: str,
    timeline_events: Sequence[Mapping[str, Any]],
) -> str:
    """Render the four stored blocks. Technique stays unavailable until one is stored."""
    lines = [
        f"# Shift handoff for flow {flow_id}",
        "",
        "## Block 1: Decision",
        f"Frozen Random Forest decision: {report['block_1_decision']}",
        f"Probability: {report['block_1_probability']}",
        f"Analyst verdict: {report['analyst_verdict']}",
        "The analyst verdict is stored separately from the frozen Random Forest decision.",
        f"Assignee: {report['assignee_id']}",
        f"Review status: {report['review_status']}",
        "",
        "## Block 2: Timeline",
        f"Observed at: {report['block_2_observed_at']}",
        f"Latest triage state: {report['block_2_latest_triage_state']}",
        f"Triage events: {report['block_2_triage_count']}",
    ]
    addresses = report.get("stored_addresses") or []
    if addresses:
        lines.append("Stored addresses: " + ", ".join(str(item) for item in addresses))
    else:
        lines.append("Stored addresses: none")
    for event in timeline_events:
        if event.get("kind") != "analyst_transition":
            continue
        lines.append(
            f"- {event.get('observed_at') or ''} {event.get('to_state') or 'unreviewed'} "
            f"by {event.get('actor_id') or 'unknown'}"
        )
    entry = report["block_4_entry_sha256"] or "none"
    lines.extend(
        [
            "",
            "## Block 3: Technique",
            "Technique: unavailable",
            "",
            "## Block 4: Playbook",
            f"Playbook state: {report['block_4_playbook_state']}",
            f"Entry SHA-256: {entry}",
            "",
            "Containment was not executed.",
            "production_fusion_enabled is false.",
            "",
            "## Brief",
            brief,
            "",
            "## Analyst record",
            f"Analyst verdict: {report['analyst_verdict']}",
            f"Rationale: {report['analyst_rationale'] or 'none'}",
            f"Assignee: {report['assignee_id']}",
            f"Review status: {report['review_status']}",
            "",
        ]
    )
    return "\n".join(lines)


def record_triage_action(
    db_path: Path,
    *,
    flow_id: int,
    action: str,
    actor_id: str,
    policy_dir: Path | None = None,
) -> dict[str, Any]:
    """Persist one analyst triage action. Unknown actions are refused."""
    state = _TRIAGE_ACTIONS.get(action.strip().lower())
    author = actor_id.strip()
    if state is None or not author or flow_id <= 0 or not db_path.is_file():
        return {"evidence_state": "unavailable", "reason": "triage_incomplete"}
    created = datetime.now(UTC).isoformat()
    with _connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS triage_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                triage_state TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            )
            """)
        found = conn.execute(
            "SELECT flow_id FROM live_flows WHERE flow_id = ?", (flow_id,)
        ).fetchone()
        if found is None:
            return {"evidence_state": "unavailable", "reason": "flow_not_stored"}
        conn.execute("UPDATE live_flows SET triage_state = ? WHERE flow_id = ?", (state, flow_id))
        cursor = conn.execute(
            """
            INSERT INTO triage_events (flow_id, action, triage_state, actor_id, created_at_utc)
            VALUES (?, ?, ?, ?, ?)
            """,
            (flow_id, action.strip().lower(), state, author, created),
        )
        event_id = int(cursor.lastrowid)
    stamp = operator_stamp(author, policy_dir)
    _store_operator_stamp(db_path, flow_id, stamp)
    return {
        "evidence_state": "verified",
        "event_id": event_id,
        "flow_id": flow_id,
        "triage_state": state,
        "actor_id": author,
        "created_at_utc": created,
        **stamp,
    }


def _load_flow_row(db_path: Path, flow_id: int) -> dict[str, Any] | None:
    if flow_id <= 0 or not db_path.is_file():
        return None
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM live_flows WHERE flow_id = ?", (flow_id,)).fetchone()
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def _rationale_stays_on_stored_flow(text: str, stored: Mapping[str, Any]) -> bool:
    """Refuse a rationale that names an address the flow does not store."""
    from threatfusion.advisory.explanation_engine import (
        AdvisoryEvidenceBundle,
        verify_explanation_groundedness,
    )
    from threatfusion.enrichment.threat_intel import ThreatIntelEnrichmentResult

    addresses = _stored_ipv4_addresses(stored.get("src_entity_id"), stored.get("dst_entity_id"))
    enrichment = None
    if addresses:
        enrichment = ThreatIntelEnrichmentResult(
            status="internal_lab_entity_annotated",
            provenance_verified=True,
            external_lookup_performed=False,
            private_ip_guard_triggered=_any_non_public_ipv4(addresses),
            inspected_entities=addresses,
            internal_lab_annotations={},
            matches=(),
            feed_snapshot_id=None,
            reason="stored_flow_entities",
        )
    probability = stored.get("rf_attack_probability")
    bundle = AdvisoryEvidenceBundle(
        candidate_id=f"live_flow:{stored.get('flow_id')}",
        record_id=f"live_flow:{stored.get('flow_id')}",
        rf_model_version="network_random_forest_baseline_v1",
        rf_attack_probability=float(probability) if probability is not None else 0.0,
        rf_threshold=0.5,
        top_feature_signals={},
        incident_id=stored.get("campaign_id"),
        observed_at=stored.get("observed_at_utc"),
        enrichment_result=enrichment,
    )
    return verify_explanation_groundedness(text, bundle)


def record_analyst_verdict(
    db_path: Path,
    *,
    flow_id: int,
    verdict: str,
    rationale: str,
    actor_id: str,
    policy_dir: Path | None = None,
) -> dict[str, Any]:
    """Store an analyst verdict beside the frozen Random Forest decision."""
    chosen = verdict.strip().lower()
    text = rationale.strip()
    actor = actor_id.strip()
    refused = {
        "evidence_state": "unavailable",
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
    }
    if (
        chosen not in _ANALYST_VERDICTS
        or not text
        or _LOCAL_ACTOR.match(actor) is None
        or flow_id <= 0
        or not db_path.is_file()
    ):
        refused["reason"] = "verdict_incomplete"
        return refused
    stored = _load_flow_row(db_path, flow_id)
    if stored is None:
        refused["reason"] = "flow_not_stored"
        return refused
    if not _rationale_stays_on_stored_flow(text, stored):
        refused["reason"] = "explanation_not_grounded"
        return refused
    recorded_at = datetime.now(UTC).isoformat()
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET analyst_verdict = ?, analyst_rationale = ?,
                analyst_verdict_actor = ?, analyst_verdict_at = ?
            WHERE flow_id = ?
            """,
            (chosen, text, actor, recorded_at, flow_id),
        )
        decision = conn.execute(
            "SELECT decision FROM live_flows WHERE flow_id = ?", (flow_id,)
        ).fetchone()
    frozen_decision = None if decision is None else decision["decision"]
    stamp = operator_stamp(actor, policy_dir)
    _store_operator_stamp(db_path, flow_id, stamp)
    return {
        "evidence_state": "verified",
        "reason": "analyst_verdict_stored",
        "flow_id": flow_id,
        "analyst_verdict": chosen,
        "analyst_rationale": text,
        "actor_id": actor,
        "recorded_at_utc": recorded_at,
        "frozen_rf_decision": frozen_decision,
        "decision_unchanged": frozen_decision == stored["decision"],
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
        **stamp,
    }


def record_case_assignment(
    db_path: Path,
    *,
    flow_id: int,
    assignee_id: str,
    review_status: str,
    policy_dir: Path | None = None,
) -> dict[str, Any]:
    """Store a local assignee and review status. This does not dispatch containment."""
    status = review_status.strip().lower()
    assignee = assignee_id.strip()
    refused = {
        "evidence_state": "unavailable",
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
    }
    if status not in _REVIEW_STATUSES or flow_id <= 0 or not db_path.is_file():
        refused["reason"] = "assignment_incomplete"
        return refused
    if status == "unassigned":
        assignee = ""
    elif _LOCAL_ACTOR.match(assignee) is None:
        refused["reason"] = "assignment_incomplete"
        return refused
    stored = _load_flow_row(db_path, flow_id)
    if stored is None:
        refused["reason"] = "flow_not_stored"
        return refused
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET assignee_id = ?, review_status = ?
            WHERE flow_id = ?
            """,
            (assignee or None, status, flow_id),
        )
    stamp = operator_stamp(assignee, policy_dir)
    _store_operator_stamp(db_path, flow_id, stamp)
    return {
        "evidence_state": "verified",
        "reason": "case_assignment_stored",
        "flow_id": flow_id,
        "assignee_id": assignee or None,
        "review_status": status,
        "frozen_rf_decision": stored["decision"],
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
        **stamp,
    }


def export_grounded_handoff(
    db_path: Path, *, flow_id: int, brief: str | None = None
) -> dict[str, Any]:
    """Export a 4-block brief only when the text stays inside stored evidence.

    The default brief is built from the stored decision and triage state. A supplied
    note is checked with verify_explanation_groundedness and refused when it names
    an address that is not stored on the flow. Containment stays unauthorized.
    """
    from threatfusion.advisory.explanation_engine import (
        AdvisoryEvidenceBundle,
        verify_explanation_groundedness,
    )
    from threatfusion.api.analyst_dashboard import build_analyst_shift_handoff
    from threatfusion.enrichment.threat_intel import ThreatIntelEnrichmentResult

    refused = {
        "schema_version": "live_grounded_handoff_v1",
        "evidence_state": "unavailable",
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
        "grounded": False,
    }
    if flow_id <= 0 or not db_path.is_file():
        refused["reason"] = "flow_not_stored"
        return refused
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM live_flows WHERE flow_id = ?", (flow_id,)).fetchone()
        if row is None:
            refused["reason"] = "flow_not_stored"
            return refused
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'triage_events'"
        ).fetchone()
        event_rows = []
        if table is not None:
            event_rows = conn.execute(
                """
                SELECT event_id, action, triage_state, actor_id, created_at_utc
                FROM triage_events
                WHERE flow_id = ?
                ORDER BY event_id ASC
                """,
                (flow_id,),
            ).fetchall()
        stored = {key: row[key] for key in row.keys()}
    probability = stored["rf_attack_probability"]
    probability_text = "unavailable" if probability is None else f"{float(probability):.4f}"
    latest = stored["triage_state"] or "unreviewed"
    default_brief = (
        f"Flow {flow_id} decision {stored['decision']} probability {probability_text}. "
        f"Triage state {latest}. "
        "production_fusion_enabled is false. Containment was not executed."
    )
    supplied = brief.strip() if isinstance(brief, str) else ""
    checked = supplied or default_brief
    addresses = _stored_ipv4_addresses(stored["src_entity_id"], stored["dst_entity_id"])
    private_guard = _any_non_public_ipv4(addresses)
    enrichment = None
    if addresses:
        enrichment = ThreatIntelEnrichmentResult(
            status="internal_lab_entity_annotated",
            provenance_verified=True,
            external_lookup_performed=False,
            private_ip_guard_triggered=private_guard,
            inspected_entities=addresses,
            internal_lab_annotations={},
            matches=(),
            feed_snapshot_id=None,
            reason="stored_flow_entities",
        )
    bundle = AdvisoryEvidenceBundle(
        candidate_id=f"live_flow:{flow_id}",
        record_id=f"live_flow:{flow_id}",
        rf_model_version="network_random_forest_baseline_v1",
        rf_attack_probability=float(probability) if probability is not None else 0.0,
        rf_threshold=0.5,
        top_feature_signals={},
        incident_id=stored["campaign_id"],
        observed_at=stored["observed_at_utc"],
        enrichment_result=enrichment,
    )
    if not verify_explanation_groundedness(checked, bundle):
        refused["reason"] = "explanation_not_grounded"
        return refused
    triage_events = [
        {
            "event_id": int(event["event_id"]),
            "action": event["action"],
            "triage_state": event["triage_state"],
            "actor_id": event["actor_id"],
            "created_at_utc": event["created_at_utc"],
        }
        for event in event_rows
    ]
    transitions = [
        {
            "observed_at": event["created_at_utc"],
            "to_state": event["triage_state"],
            "actor_id": event["actor_id"],
        }
        for event in triage_events
    ]
    handoff = build_analyst_shift_handoff(
        incident_id=f"live_flow:{flow_id}",
        relationship_key=stored["campaign_id"],
        flow_members=[
            {
                "observed_at": stored["observed_at_utc"],
                "alert_candidate_id": f"live_flow:{flow_id}",
                "matched_relationship_key": stored["campaign_id"],
            }
        ],
        analyst_transitions=transitions,
        playbook_state=stored["ledger_state"],
    )
    verdict = stored.get("analyst_verdict") or "not recorded"
    rationale = stored.get("analyst_rationale") or ""
    if rationale and not _rationale_stays_on_stored_flow(str(rationale), stored):
        rationale = ""
        verdict = "not recorded"
    review_status = stored.get("review_status") or "unassigned"
    assignee = stored.get("assignee_id") or "unassigned"
    report = {
        "block_1_decision": stored["decision"],
        "block_1_probability": probability_text,
        "analyst_verdict": verdict,
        "analyst_rationale": rationale,
        "assignee_id": assignee,
        "review_status": review_status,
        "block_2_observed_at": stored["observed_at_utc"],
        "block_2_latest_triage_state": latest,
        "block_2_triage_count": len(triage_events),
        "block_3_technique": "unavailable",
        "block_4_playbook_state": stored["ledger_state"] or "pending_approval",
        "block_4_entry_sha256": stored["entry_sha256"] or "",
        "stored_addresses": list(addresses),
        "triage_events": triage_events,
    }
    markdown = _shift_handoff_markdown(
        flow_id=flow_id,
        report=report,
        brief=checked,
        timeline_events=handoff["timeline"]["events"],
    )
    return {
        "schema_version": "live_grounded_handoff_v1",
        "evidence_state": "verified",
        "reason": "grounded_brief",
        "grounded": True,
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
        "brief": checked,
        "report": report,
        "handoff": handoff,
        "markdown": markdown,
        "flow_id": flow_id,
    }


RANGE_VICTIM_CONTAINER = "threatfusion_range_victim"
RANGE_ATTACKER_CONTAINER = "threatfusion_range_attacker"
RANGE_CONTAINMENT_SOURCE = "172.29.0.10"
RANGE_VICTIM_ADDRESS = "172.29.0.20"


def range_docker_argv(action: str) -> tuple[str, ...]:
    """Commands that run only inside the victim or attacker container."""
    source = f"{RANGE_CONTAINMENT_SOURCE}/32"
    if action == "status":
        return ("docker", "inspect", "-f", "{{.State.Running}}", RANGE_VICTIM_CONTAINER)
    if action == "drop_check":
        return (
            "docker",
            "exec",
            RANGE_VICTIM_CONTAINER,
            "iptables",
            "-C",
            "INPUT",
            "-s",
            source,
            "-j",
            "DROP",
        )
    if action == "drop":
        return (
            "docker",
            "exec",
            RANGE_VICTIM_CONTAINER,
            "iptables",
            "-I",
            "INPUT",
            "1",
            "-s",
            source,
            "-j",
            "DROP",
        )
    if action == "rollback":
        return (
            "docker",
            "exec",
            RANGE_VICTIM_CONTAINER,
            "iptables",
            "-D",
            "INPUT",
            "-s",
            source,
            "-j",
            "DROP",
        )
    if action == "probe":
        return (
            "docker",
            "exec",
            RANGE_ATTACKER_CONTAINER,
            "curl",
            "-fsS",
            "--max-time",
            "3",
            f"http://{RANGE_VICTIM_ADDRESS}/",
        )
    raise ValueError(action)


def _run_range_action(action: str) -> dict[str, Any]:
    import subprocess

    if action == "status":
        completed = subprocess.run(
            range_docker_argv("status"),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return {"running": completed.returncode == 0 and completed.stdout.strip() == "true"}
    if action == "drop":
        present = subprocess.run(
            range_docker_argv("drop_check"),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if present.returncode != 0:
            inserted = subprocess.run(
                range_docker_argv("drop"),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if inserted.returncode != 0:
                return {"applied": False}
        return {"applied": True}
    if action == "rollback":
        removed = subprocess.run(
            range_docker_argv("rollback"),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return {"removed": removed.returncode == 0}
    if action == "probe":
        probed = subprocess.run(
            range_docker_argv("probe"),
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return {"reachable": probed.returncode == 0}
    raise ValueError(action)


def _containment_refusal(reason: str, http_status: int) -> dict[str, Any]:
    return {
        "schema_version": "live_range_containment_v1",
        "evidence_state": "unavailable",
        "reason": reason,
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
        "target": RANGE_CONTAINMENT_SOURCE,
        "http_status": http_status,
    }


def _authorized_range_flow(
    live_db_path: Path, soar_db_path: Path, flow_id: int
) -> tuple[sqlite3.Row | None, dict[str, Any] | None]:
    if flow_id <= 0 or not live_db_path.is_file() or not soar_db_path.is_file():
        return None, _containment_refusal("flow_not_stored", 403)
    with _connect(live_db_path) as conn:
        flow = conn.execute("SELECT * FROM live_flows WHERE flow_id = ?", (flow_id,)).fetchone()
    if flow is None:
        return None, _containment_refusal("flow_not_stored", 403)
    if str(flow["src_entity_id"] or "") != RANGE_CONTAINMENT_SOURCE:
        return None, _containment_refusal("containment_target_rejected", 403)
    signature = str(flow["callback_signature"] or "")
    if not flow["callback_recorded"] or _SHA256_HEX.fullmatch(signature) is None:
        return None, _containment_refusal("callback_not_recorded", 403)
    from threatfusion.soar.playbook_ledger import SoarPlaybookSqliteRepository

    repository = SoarPlaybookSqliteRepository(soar_db_path)
    chain_ok, _message = repository.verify_audit_chain_integrity()
    approved = next(
        (
            record
            for record in repository.list_records_for_candidate(f"live_flow:{flow_id}")
            if record.state in {"approved", "executed_simulated"}
        ),
        None,
    )
    if not chain_ok or approved is None:
        return None, _containment_refusal("playbook_not_approved", 403)
    return flow, None


def _store_containment_state(db_path: Path, flow_id: int, state: str, *, when: str) -> None:
    column = "containment_at" if state == "applied" else "rollback_at"
    with _connect(db_path) as conn:
        conn.execute(
            f"""
            UPDATE live_flows
            SET containment_state = ?, {column} = ?
            WHERE flow_id = ?
            """,
            (state, when, flow_id),
        )


def contain_range_source(
    live_db_path: Path,
    soar_db_path: Path,
    *,
    flow_id: int,
    runner: Any | None = None,
) -> dict[str, Any]:
    """Drop 172.29.0.10 inside the victim network namespace after a verified callback."""
    _flow, refused = _authorized_range_flow(live_db_path, soar_db_path, flow_id)
    if refused is not None:
        return refused
    act = runner or _run_range_action
    if not act("status").get("running"):
        return _containment_refusal("range_not_running", 409)
    if not act("drop").get("applied"):
        return _containment_refusal("range_command_failed", 409)
    if act("probe").get("reachable"):
        act("rollback")
        return _containment_refusal("containment_not_observed", 502)
    recorded_at = datetime.now(UTC).isoformat()
    _store_containment_state(live_db_path, flow_id, "applied", when=recorded_at)
    return {
        "schema_version": "live_range_containment_v1",
        "evidence_state": "verified",
        "reason": "containment_applied",
        "execution_authorized": False,
        "containment_executed": True,
        "production_fusion_enabled": False,
        "target": RANGE_CONTAINMENT_SOURCE,
        "containment_at": recorded_at,
        "http_status": 200,
    }


def rollback_range_source(
    live_db_path: Path,
    soar_db_path: Path,
    *,
    flow_id: int,
    runner: Any | None = None,
) -> dict[str, Any]:
    """Remove the victim-namespace drop and require the attacker path to succeed again."""
    _flow, refused = _authorized_range_flow(live_db_path, soar_db_path, flow_id)
    if refused is not None:
        return refused
    act = runner or _run_range_action
    if not act("status").get("running"):
        return _containment_refusal("range_not_running", 409)
    if not act("rollback").get("removed"):
        return _containment_refusal("rollback_rule_missing", 409)
    if not act("probe").get("reachable"):
        return _containment_refusal("rollback_not_observed", 502)
    recorded_at = datetime.now(UTC).isoformat()
    _store_containment_state(live_db_path, flow_id, "rolled_back", when=recorded_at)
    return {
        "schema_version": "live_range_containment_v1",
        "evidence_state": "verified",
        "reason": "containment_rolled_back",
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
        "target": RANGE_CONTAINMENT_SOURCE,
        "rollback_at": recorded_at,
        "http_status": 200,
    }


def purge_bridge_noise_rows(db_path: Path) -> int:
    """Delete stored bridge rows that are multicast, link-local, broadcast, or mDNS."""
    if not db_path.is_file():
        return 0
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT flow_id, src_entity_id, dst_entity_id, service_or_port,
                   sensor_observation_json
            FROM live_flows
            WHERE source_label = ?
            """,
            (SENSOR_BRIDGE_SOURCE,),
        ).fetchall()
        doomed: list[int] = []
        for row in rows:
            raw_port = str(row["service_or_port"] or "0")
            try:
                dst_port = int(raw_port)
            except ValueError:
                dst_port = 0
            src = str(row["src_entity_id"] or "")
            dst = str(row["dst_entity_id"] or "")
            observation = str(row["sensor_observation_json"] or "")
            if (
                is_lab_bridge_noise(src, dst, 0, dst_port)
                or "224.0.0.251" in observation
                or "ff02::" in observation
                or "ff02::" in src
                or "ff02::" in dst
            ):
                doomed.append(int(row["flow_id"]))
        for flow_id in doomed:
            conn.execute("DELETE FROM live_flows WHERE flow_id = ?", (flow_id,))
    return len(doomed)


def _latest_range_pair(db_path: Path, after_flow_id: int) -> sqlite3.Row | None:
    if not db_path.is_file():
        return None
    with _connect(db_path) as conn:
        return conn.execute(
            """
            SELECT flow_id, src_entity_id, dst_entity_id, service_or_port
            FROM live_flows
            WHERE source_label = ?
              AND src_entity_id = ?
              AND dst_entity_id = ?
              AND flow_id > ?
            ORDER BY flow_id DESC
            LIMIT 1
            """,
            (SENSOR_BRIDGE_SOURCE, "172.29.0.10", "172.29.0.20", after_flow_id),
        ).fetchone()


def _max_flow_id(db_path: Path) -> int:
    if not db_path.is_file():
        return 0
    with _connect(db_path) as conn:
        row = conn.execute("SELECT COALESCE(MAX(flow_id), 0) FROM live_flows").fetchone()
    return int(row[0] if row is not None else 0)


def _docker_range_scan() -> None:
    import subprocess

    commands = (
        (
            "docker",
            "exec",
            RANGE_ATTACKER_CONTAINER,
            "curl",
            "-fsS",
            "--max-time",
            "5",
            f"http://{RANGE_VICTIM_ADDRESS}/",
        ),
        (
            "docker",
            "exec",
            RANGE_ATTACKER_CONTAINER,
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            f"root@{RANGE_VICTIM_ADDRESS}",
            "exit",
        ),
    )
    for command in commands:
        subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)


def run_live_range_scan(
    db_path: Path,
    *,
    runner: Any | None = None,
    timeout_seconds: float = 30.0,
    eve_path: Path | None = None,
) -> dict[str, Any]:
    """Fire the lab scan and wait until a new unicast bridge row is stored."""
    import time

    removed = purge_bridge_noise_rows(db_path)
    before = _max_flow_id(db_path)
    try:
        if runner is None:
            _docker_range_scan()
        else:
            runner()
    except (OSError, TimeoutError):
        return {
            "evidence_state": "unavailable",
            "reason": "range_not_running",
            "removed_noise": removed,
            "ingested": False,
            "containment_executed": False,
            "production_fusion_enabled": False,
        }
    deadline = time.monotonic() + timeout_seconds
    while True:
        row = _latest_range_pair(db_path, before)
        eve_seen = _eve_has_range_pair(eve_path)
        eve_ready = eve_path is None or eve_seen
        if row is not None and eve_ready:
            return {
                "evidence_state": "verified",
                "reason": "range_scan_ingested",
                "removed_noise": removed,
                "ingested": True,
                "flow_id": int(row["flow_id"]),
                "src_entity_id": "172.29.0.10",
                "dst_entity_id": "172.29.0.20",
                "eve_seen": eve_seen,
                "containment_executed": False,
                "production_fusion_enabled": False,
            }
        if time.monotonic() >= deadline:
            return {
                "evidence_state": "unavailable",
                "reason": "scan_not_ingested",
                "removed_noise": removed,
                "ingested": False,
                "eve_seen": eve_seen,
                "containment_executed": False,
                "production_fusion_enabled": False,
            }
        time.sleep(0.4)


def _eve_has_range_pair(eve_path: Path | None) -> bool:
    if eve_path is None or not eve_path.is_file():
        return False
    tail = eve_path.read_bytes()[-262144:].decode("utf-8", "replace")
    return "172.29.0.10" in tail and "172.29.0.20" in tail
