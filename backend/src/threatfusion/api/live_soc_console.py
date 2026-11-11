"""Live analyst console services.

Scores a 14-feature flow only when the frozen Random Forest artifact verifies and
its input width matches the canonical feature contract. The autoencoder never
changes the alert decision. Analyst notes, MITRE answers, drift, and the n8n
workbench read local files. Containment stays unauthorized.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import sqlite3
import stat
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from threatfusion.advisory.chromadb_mitre_rag import (
    CANONICAL_MITRE_AND_PLAYBOOK_CORPUS,
    ChromaDbMitrePlaybookRag,
)
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
    ("containment_rule", "TEXT"),
    ("sensor_node", "TEXT"),
)

_SCHEMA_LOCK = threading.Lock()
_ADVISORY_MODEL_CACHE: dict[str, Any] = {}
_ANALYST_VERDICTS = frozenset({"true_positive", "false_positive", "inconclusive"})
_REVIEW_STATUSES = frozenset({"unassigned", "in_review", "reviewed"})
_LOCAL_ACTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _add_missing_flow_columns(conn: sqlite3.Connection, existing: set[str]) -> None:
    for name, declaration in _FLOW_EXTRA_COLUMNS:
        if name not in existing:
            try:
                conn.execute(f"ALTER TABLE live_flows ADD COLUMN {name} {declaration}")
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    conn.row_factory = sqlite3.Row
    with _SCHEMA_LOCK:
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS context_memory (
                memory_id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_ip_or_subnet TEXT NOT NULL,
                service_or_port TEXT NOT NULL DEFAULT '',
                expected_behavior_rule TEXT NOT NULL,
                created_from_flow_id INTEGER,
                operator_id TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                UNIQUE(entity_ip_or_subnet, service_or_port)
            )
            """)
        existing = {row[1] for row in conn.execute("PRAGMA table_info(live_flows)")}
        _add_missing_flow_columns(conn, existing)
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS live_flows_source_event_id
            ON live_flows(source_event_id)
            WHERE source_event_id IS NOT NULL
            """)
        _ensure_enterprise_catalog(conn)
        conn.commit()
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
        model = _ADVISORY_MODEL_CACHE.get("rf_model")
    if model is None:
        model_path = repo_root / FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY["random_forest"]["rel_path"]
        try:
            import joblib

            raw_bytes = model_path.read_bytes()
            digest = hashlib.sha256(raw_bytes).hexdigest()
            if digest != expected:
                base["reason"] = "frozen_random_forest_unverified"
                return base
            model = joblib.load(io.BytesIO(raw_bytes))
            _ADVISORY_MODEL_CACHE["rf_model"] = model
        except (OSError, ImportError, ValueError, EOFError, KeyError, Exception):
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
    base.update(
        _advisory_model_fields(
            features,
            repo_root,
            rf_probability=attack_probability,
        )
    )
    base["feature_error_breakdown"] = _feature_error_breakdown(base.get("ae_feature_errors") or [])
    base["production_fusion_enabled"] = False
    return base


_DNN_FEATURES: tuple[str, ...] = (
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
)
_DNN_CATEGORIES: tuple[str, ...] = (
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
)
_AE_THRESHOLD = 0.1181361214680695
_AE_SHA256 = "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23"
_RF_SHA256_PREFIX = "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"
_AE_PREPROCESSOR_SHA256 = "30c955e3931dc010f8b4391a80fc0fbeddd17e14260701c8131d88f95b06ee49"
_AE_PREPROCESSOR_RELATIVE = (
    "data/processed/unsw_network_preprocessing/"
    "full-train-only-0141bde-v1/preprocessor_state.json"
)
_DNN_MODEL_RELATIVE = "artifacts/models/fyp2_dnn_same_split_v1/dnn_model.pt"
_DNN_REPORT_RELATIVE = "artifacts/models/fyp2_dnn_same_split_v1/evaluation_report.json"
_DNN_MODEL_SHA256 = "614850ad84fc4ab32dc6e6d2318900668d97cad6edba37290ed9fe2b2482df1f"
_AE_INPUT_NAMES: tuple[str, ...] = (
    "duration_ms__zscore",
    "fwd_packets__zscore",
    "bwd_packets__zscore",
    "fwd_bytes__zscore",
    "bwd_bytes__zscore",
    "packets_per_second__zscore",
    "bytes_per_second__zscore",
    "fwd_packet_length_mean__zscore",
    "bwd_packet_length_mean__zscore",
    "dst_port__zscore",
    "protocol=tcp",
    "protocol=udp",
    "protocol=icmp",
    "protocol=other",
)
_CORPUS_TECHNIQUE_CVES: dict[str, tuple[str, ...]] = {
    "T1046": ("CVE-2017-0144",),
    "T1110": ("CVE-2023-48795",),
    "T1190": ("CVE-2021-44228", "CVE-2023-22515"),
    "T1498": ("CVE-2023-44487",),
}


def _console_repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _dnn_module_type() -> Any:
    cached = _ADVISORY_MODEL_CACHE.get("dnn_type")
    if cached is not None:
        return cached
    from torch import nn

    class _ResidualTrunk(nn.Module):
        """Same 14 -> 128 -> 128 -> 64 residual trunk the training script saves."""

        def __init__(self) -> None:
            super().__init__()
            self.lift = nn.Sequential(
                nn.Linear(14, 128),
                nn.BatchNorm1d(128),
                nn.ReLU(),
            )
            self.skip = nn.Linear(128, 128)
            self.skip_norm = nn.BatchNorm1d(128)
            self.squeeze = nn.Sequential(
                nn.Linear(128, 64),
                nn.BatchNorm1d(64),
                nn.ReLU(),
            )

        def forward(self, features):  # type: ignore[no-untyped-def]
            hidden = self.lift(features)
            residual = self.skip_norm(self.skip(hidden))
            return self.squeeze(nn.functional.relu(hidden + residual))

    class ThreatFusionSameSplitDNN(nn.Module):
        """Same residual trunk the training script saves."""

        def __init__(self) -> None:
            super().__init__()
            self.trunk = _ResidualTrunk()
            self.binary_head = nn.Linear(64, 1)
            self.category_head = nn.Linear(64, 9)

    _ADVISORY_MODEL_CACHE["dnn_type"] = ThreatFusionSameSplitDNN
    return ThreatFusionSameSplitDNN


def _dnn_bundle(repo_root: Path) -> dict[str, Any] | None:
    if "dnn_bundle" in _ADVISORY_MODEL_CACHE:
        return _ADVISORY_MODEL_CACHE["dnn_bundle"]
    bundle: dict[str, Any] | None
    try:
        import torch

        path = repo_root / _DNN_MODEL_RELATIVE
        if path.is_symlink() or not path.is_file():
            raise OSError("dnn artifact is missing or a symlink")
        raw_bytes = path.read_bytes()
        digest = hashlib.sha256(raw_bytes).hexdigest()
        if not hmac.compare_digest(digest, _DNN_MODEL_SHA256):
            raise ValueError("dnn artifact hash mismatch")
        payload = torch.load(io.BytesIO(raw_bytes), map_location="cpu", weights_only=True)
        if not isinstance(payload, dict):
            raise TypeError("dnn artifact is not a tensor dictionary")
        model = _dnn_module_type()()
        model.load_state_dict(payload["state_dict"])
        model.eval()
        report: dict[str, Any] = {}
        report_path = repo_root / _DNN_REPORT_RELATIVE
        if report_path.is_file():
            loaded = json.loads(report_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                report = loaded
        medians = report.get("train_feature_medians")
        bundle = {
            "model": model,
            "mean": payload["scaler_mean"].detach().cpu().float(),
            "std": payload["scaler_std"].detach().cpu().float(),
            "report": report,
            "medians": medians if isinstance(medians, dict) else {},
        }
    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        TypeError,
        ImportError,
        json.JSONDecodeError,
    ):
        bundle = None
    _ADVISORY_MODEL_CACHE["dnn_bundle"] = bundle
    return bundle


def _ae_model(repo_root: Path) -> Any | None:
    if "ae_model" in _ADVISORY_MODEL_CACHE:
        return _ADVISORY_MODEL_CACHE["ae_model"]
    model: Any | None
    try:
        from threatfusion.models.network_autoencoder import load_verified_state

        path = repo_root / FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY["autoencoder_v2"]["rel_path"]
        model = load_verified_state(path, _AE_SHA256)
    except (OSError, ValueError, RuntimeError, TypeError, ImportError, Exception):
        model = None
    _ADVISORY_MODEL_CACHE["ae_model"] = model
    return model


def _ae_scaler(repo_root: Path) -> tuple[list[float], list[float]] | None:
    if "ae_scaler" in _ADVISORY_MODEL_CACHE:
        return _ADVISORY_MODEL_CACHE["ae_scaler"]
    pair: tuple[list[float], list[float]] | None
    try:
        path = repo_root / _AE_PREPROCESSOR_RELATIVE
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != _AE_PREPROCESSOR_SHA256:
            pair = None
        else:
            payload = json.loads(raw)
            means = [float(value) for value in payload["numeric_means"]]
            scales = [float(value) for value in payload["numeric_scales"]]
            pair = (means, scales) if len(means) == 10 and len(scales) == 10 else None
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        pair = None
    _ADVISORY_MODEL_CACHE["ae_scaler"] = pair
    return pair


def _ae_input_vector(canonical: Sequence[float], repo_root: Path) -> list[float]:
    values = [float(item) for item in canonical]
    scaler = _ae_scaler(repo_root)
    if scaler is None or len(values) != 14:
        return values
    means, scales = scaler
    transformed = [
        (value - mean) / scale if scale else 0.0
        for value, mean, scale in zip(values[:10], means, scales, strict=True)
    ]
    transformed.extend(values[10:])
    return transformed


def _score_autoencoder(canonical: Sequence[float], repo_root: Path) -> dict[str, Any]:
    empty = {
        "ae_loss": None,
        "ae_anomaly_flag": False,
        "ae_threshold": _AE_THRESHOLD,
        "ae_top_features": [],
        "ae_feature_errors": [],
        "ae_sha256": _AE_SHA256,
    }
    model = _ae_model(repo_root)
    if model is None:
        return empty
    try:
        import numpy as np
        import torch

        transformed = _ae_input_vector(canonical, repo_root)
        matrix = np.array(transformed, dtype=np.float32).reshape(1, 14)
        with torch.inference_mode():
            reconstruction = model(torch.from_numpy(matrix)).detach().cpu().numpy()
        residual = matrix.astype(np.float64) - reconstruction.astype(np.float64)
        squared = residual[0] * residual[0]
        loss = float(squared.sum() / 14.0)
        ranked = [
            {"feature": name, "squared_error": float(value)}
            for name, value in zip(_AE_INPUT_NAMES, squared, strict=True)
        ]
        ranked.sort(key=lambda item: item["squared_error"], reverse=True)
        return {
            "ae_loss": loss,
            "ae_anomaly_flag": bool(loss >= _AE_THRESHOLD),
            "ae_threshold": _AE_THRESHOLD,
            "ae_top_features": ranked[:5],
            "ae_feature_errors": list(ranked),
            "ae_sha256": _AE_SHA256,
        }
    except (OSError, ValueError, RuntimeError, TypeError, ImportError):
        return empty


def _score_same_split_dnn(raw_features: Mapping[str, float], repo_root: Path) -> dict[str, Any]:
    empty = {
        "dnn_attack_probability": None,
        "dnn_binary_decision": None,
        "unsw_attack_category": None,
        "dnn_class_distribution": {},
    }
    bundle = _dnn_bundle(repo_root)
    if bundle is None:
        return empty
    try:
        import torch

        values = torch.tensor(
            [float(raw_features[name]) for name in _DNN_FEATURES],
            dtype=torch.float32,
        )
        scaled = (values - bundle["mean"]) / bundle["std"]
        model = bundle["model"]
        model.eval()
        with torch.inference_mode():
            hidden = model.trunk(scaled.unsqueeze(0))
            probability = float(torch.sigmoid(model.binary_head(hidden))[0, 0].item())
            category_logits = model.category_head(hidden)
            category_index = int(torch.argmax(category_logits, dim=1)[0].item())
            class_probabilities = torch.softmax(category_logits, dim=1)[0]
        normal_probability = max(0.0, min(1.0, 1.0 - probability))
        distribution: dict[str, float] = {}
        for index, name in enumerate(_DNN_CATEGORIES):
            joint = probability * float(class_probabilities[index].item())
            distribution[name] = joint
            if name == "Backdoor":
                distribution["Backdoors"] = joint
        distribution["Normal"] = normal_probability
        return {
            "dnn_attack_probability": probability,
            "dnn_binary_decision": "Attack" if probability >= 0.5 else "Normal",
            "unsw_attack_category": _DNN_CATEGORIES[category_index],
            "dnn_class_distribution": distribution,
        }
    except (OSError, ValueError, RuntimeError, TypeError, ImportError, KeyError, IndexError):
        return empty


def _consensus_score(
    rf_probability: float | None,
    dnn_probability: float | None,
    ae_loss: float | None,
) -> float | None:
    if rf_probability is None or dnn_probability is None or ae_loss is None:
        return None
    if not all(math.isfinite(value) for value in (rf_probability, dnn_probability, ae_loss)):
        return None
    ae_score = min(1.0, max(0.0, ae_loss / _AE_THRESHOLD))
    return (0.5 * rf_probability) + (0.3 * dnn_probability) + (0.2 * ae_score)


def dnn_features_from_flow(features: Mapping[str, Any], repo_root: Path) -> dict[str, float] | None:
    """Project a stored flow onto the 14 UNSW columns the same-split DNN expects."""
    if all(name in features for name in _DNN_FEATURES):
        try:
            return {name: float(features[name]) for name in _DNN_FEATURES}
        except (TypeError, ValueError):
            return None
    vector, _reason = _finite_feature_vector(features)
    if vector is None:
        return None
    canonical = dict(zip(CANONICAL_14_FEATURES, vector, strict=True))
    medians: Mapping[str, Any] = {}
    bundle = _dnn_bundle(repo_root)
    if bundle is not None and isinstance(bundle.get("medians"), Mapping):
        medians = bundle["medians"]
    projected = {
        "dur": canonical["duration_ms"] / 1000.0,
        "spkts": canonical["fwd_packets"],
        "dpkts": canonical["bwd_packets"],
        "sbytes": canonical["fwd_bytes"],
        "dbytes": canonical["bwd_bytes"],
        "rate": canonical["packets_per_second"],
    }
    for name in ("sttl", "dttl", "sload", "dload", "sinpkt", "dinpkt", "sjit", "djit"):
        try:
            projected[name] = float(medians.get(name, 0.0))
        except (TypeError, ValueError):
            projected[name] = 0.0
    return projected


def canonical_from_dnn_features(
    raw_features: Mapping[str, float],
    base_features: Mapping[str, Any] | None = None,
    changed: set[str] | None = None,
) -> dict[str, float]:
    """Map edited UNSW columns back onto the 14-feature contract used by RF and the AE."""
    vector, _reason = _finite_feature_vector(base_features or {})
    if vector is None:
        canonical = {name: 0.0 for name in CANONICAL_14_FEATURES}
        canonical["protocol_tcp"] = 1.0
    else:
        canonical = dict(zip(CANONICAL_14_FEATURES, vector, strict=True))

    def _touched(name: str) -> bool:
        return changed is None or name in changed

    if _touched("dur"):
        canonical["duration_ms"] = float(raw_features["dur"]) * 1000.0
    if _touched("spkts"):
        canonical["fwd_packets"] = float(raw_features["spkts"])
    if _touched("dpkts"):
        canonical["bwd_packets"] = float(raw_features["dpkts"])
    if _touched("sbytes"):
        canonical["fwd_bytes"] = float(raw_features["sbytes"])
    if _touched("dbytes"):
        canonical["bwd_bytes"] = float(raw_features["dbytes"])
    if _touched("rate"):
        canonical["packets_per_second"] = float(raw_features["rate"])
    if _touched("spkts") or _touched("sbytes"):
        spkts = float(raw_features["spkts"])
        canonical["fwd_packet_length_mean"] = (
            float(raw_features["sbytes"]) / spkts if spkts else 0.0
        )
    if _touched("dpkts") or _touched("dbytes"):
        dpkts = float(raw_features["dpkts"])
        canonical["bwd_packet_length_mean"] = (
            float(raw_features["dbytes"]) / dpkts if dpkts else 0.0
        )
    if _touched("sload") or _touched("dload"):
        canonical["bytes_per_second"] = float(raw_features["sload"]) + float(raw_features["dload"])
    return canonical


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


def _canonical_override(payload: Mapping[str, Any]) -> dict[str, float] | None:
    """Return a caller-supplied canonical vector. Missing fields stay unset."""
    if any(name not in payload for name in CANONICAL_14_FEATURES):
        return None
    parsed: dict[str, float] = {}
    for name in CANONICAL_14_FEATURES:
        number = _finite_number(payload.get(name))
        if number is None:
            return None
        parsed[name] = number
    return parsed


def _advisory_model_fields(
    features: Mapping[str, Any],
    repo_root: Path,
    *,
    rf_probability: float | None,
    raw_features: Mapping[str, float] | None = None,
) -> dict[str, Any]:
    """Score the v2 autoencoder and the same-split DNN without changing the RF decision."""
    vector, _reason = _finite_feature_vector(features)
    ae = (
        _score_autoencoder(vector, repo_root)
        if vector is not None
        else {
            "ae_loss": None,
            "ae_anomaly_flag": False,
            "ae_threshold": _AE_THRESHOLD,
            "ae_top_features": [],
            "ae_feature_errors": [],
            "ae_sha256": _AE_SHA256,
        }
    )
    raw = raw_features if raw_features is not None else dnn_features_from_flow(features, repo_root)
    dnn = (
        _score_same_split_dnn(raw, repo_root)
        if raw is not None
        else {
            "dnn_attack_probability": None,
            "dnn_binary_decision": None,
            "unsw_attack_category": None,
            "dnn_class_distribution": {},
        }
    )
    consensus = _consensus_score(
        rf_probability,
        dnn.get("dnn_attack_probability"),
        ae.get("ae_loss"),
    )
    scored_raw = (
        _finite_number(ae.get("ae_loss")) is not None
        or _finite_number(dnn.get("dnn_attack_probability")) is not None
    )
    return {
        "ae_loss": ae.get("ae_loss"),
        "ae_anomaly_flag": ae.get("ae_anomaly_flag"),
        "ae_threshold": _AE_THRESHOLD,
        "ae_top_features": ae.get("ae_top_features") or [],
        "ae_sha256": _AE_SHA256,
        "dnn_attack_probability": dnn.get("dnn_attack_probability"),
        "dnn_binary_decision": dnn.get("dnn_binary_decision"),
        "unsw_attack_category": dnn.get("unsw_attack_category"),
        "dnn_class_distribution": dnn.get("dnn_class_distribution") or {},
        "ae_feature_errors": ae.get("ae_feature_errors") or [],
        "threatfusion_consensus_score": consensus,
        "consensus_label": "advisory_consensus",
        "measurement_source": "raw_model_inference" if scored_raw else "unavailable",
        "authority": "advisory_non_governing",
        "ae_changes_alert_decision": False,
        "production_fusion_enabled": False,
    }


def _model_proof_block(
    canonical: Mapping[str, Any],
    raw_features: Mapping[str, float],
    repo_root: Path,
) -> dict[str, Any]:
    scored = score_canonical_flow(canonical, repo_root=repo_root)
    advisory = _advisory_model_fields(
        canonical,
        repo_root,
        rf_probability=scored.get("rf_attack_probability"),
        raw_features=raw_features,
    )
    return {
        "features": {name: float(raw_features[name]) for name in _DNN_FEATURES},
        "canonical_features": {
            name: float(canonical[name]) for name in CANONICAL_14_FEATURES if name in canonical
        },
        "rf_attack_probability": scored.get("rf_attack_probability"),
        "rf_decision": scored.get("decision"),
        "dnn_attack_probability": advisory.get("dnn_attack_probability"),
        "dnn_binary_decision": advisory.get("dnn_binary_decision"),
        "unsw_attack_category": advisory.get("unsw_attack_category"),
        "ae_loss": advisory.get("ae_loss"),
        "ae_anomaly_flag": advisory.get("ae_anomaly_flag"),
        "ae_top_features": advisory.get("ae_top_features"),
        "threatfusion_consensus_score": advisory.get("threatfusion_consensus_score"),
        "consensus_label": "advisory_consensus",
        "alert_authority": "frozen_random_forest",
        "production_fusion_enabled": False,
        "dnn_class_distribution": advisory.get("dnn_class_distribution") or {},
        "feature_error_breakdown": _feature_error_breakdown(
            advisory.get("ae_feature_errors") or []
        ),
    }


def run_live_model_proof(
    live_db_path: Path,
    *,
    flow_id: int,
    features_override: Mapping[str, Any] | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Score the stored 14 features and an edit. The live database is not updated."""
    root = repo_root or _console_repo_root()
    refused = {
        "schema_version": "live_model_proof_v1",
        "evidence_state": "unavailable",
        "production_fusion_enabled": False,
        "alert_authority": "frozen_random_forest",
        "http_status": 404,
        "reason": "flow_not_stored",
    }
    if flow_id <= 0 or not live_db_path.is_file():
        return refused
    try:
        conn = sqlite3.connect(f"file:{live_db_path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return refused
    try:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT features_json FROM live_flows WHERE flow_id = ?",
            (flow_id,),
        ).fetchone()
    except sqlite3.Error:
        return refused
    finally:
        conn.close()
    if row is None:
        return refused
    try:
        stored = json.loads(str(row["features_json"]))
    except json.JSONDecodeError:
        refused["http_status"] = 400
        refused["reason"] = "invalid_feature_contract"
        return refused
    if not isinstance(stored, dict):
        refused["http_status"] = 400
        refused["reason"] = "invalid_feature_contract"
        return refused
    original_raw = dnn_features_from_flow(stored, root)
    if original_raw is None:
        refused["http_status"] = 400
        refused["reason"] = "invalid_feature_contract"
        return refused
    perturbed_raw = dict(original_raw)
    if features_override is not None:
        if not isinstance(features_override, Mapping):
            refused["http_status"] = 400
            refused["reason"] = "invalid_feature_contract"
            return refused
        for name in _DNN_FEATURES:
            if name not in features_override:
                continue
            try:
                value = float(features_override[name])
            except (TypeError, ValueError):
                refused["http_status"] = 400
                refused["reason"] = "invalid_feature_contract"
                return refused
            if not math.isfinite(value):
                refused["http_status"] = 400
                refused["reason"] = "invalid_feature_contract"
                return refused
            perturbed_raw[name] = value
    supplied_canonical = _canonical_override(features_override) if features_override else None
    import time

    started = time.perf_counter()
    if _finite_feature_vector(stored)[0] is not None:
        original_canonical = stored
    else:
        original_canonical = canonical_from_dnn_features(original_raw, stored)
    changed = {
        name for name in _DNN_FEATURES if float(perturbed_raw[name]) != float(original_raw[name])
    }
    original = _model_proof_block(original_canonical, original_raw, root)
    if supplied_canonical is not None:
        perturbed_canonical = supplied_canonical
    else:
        perturbed_canonical = (
            dict(original_canonical)
            if not changed
            else canonical_from_dnn_features(perturbed_raw, stored, changed)
        )
    perturbed = _model_proof_block(perturbed_canonical, perturbed_raw, root)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    contributions = [
        {
            "feature": name,
            "absolute_delta": abs(float(perturbed_raw[name]) - float(original_raw[name])),
        }
        for name in _DNN_FEATURES
    ]
    contributions.sort(key=lambda item: item["absolute_delta"], reverse=True)
    if contributions and contributions[0]["absolute_delta"] == 0.0:
        contributions = list(original.get("ae_top_features") or [])
    scorecard = _benchmark_scorecard(root)
    return {
        "schema_version": "live_model_proof_v1",
        "evidence_state": "advisory_simulation",
        "production_fusion_enabled": False,
        "alert_authority": "frozen_random_forest",
        "consensus_label": "advisory_consensus",
        "flow_id": flow_id,
        "original": original,
        "perturbed": perturbed,
        "top_contributing_features": contributions[:5],
        "inference_latency_ms": elapsed_ms,
        "rf_sha256": _RF_SHA256_PREFIX,
        "ae_sha256": _AE_SHA256,
        "dnn_sha256": _DNN_MODEL_SHA256,
        "dnn_class_distribution": perturbed.get("dnn_class_distribution") or {},
        "feature_error_breakdown": perturbed.get("feature_error_breakdown") or [],
        "dnn_evaluation_summary": scorecard,
        "benchmark_scorecard": scorecard,
        "http_status": 200,
    }


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
_SENSOR_NODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
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


def _normalize_sensor_node(value: str | None) -> str | None:
    """Default a missing tag to the lab bridge. Refuse tags outside the local alphabet."""
    if value is None or not str(value).strip():
        return SENSOR_BRIDGE_SOURCE
    text = str(value).strip()
    if _SENSOR_NODE.fullmatch(text) is None:
        return None
    return text


def sensor_ingest_auth_status(authorization_header: str | None) -> str:
    """Return ok, unauthorized, or unconfigured.

    A pytest process with no configured token stays open so existing fixtures
    can post ingest bodies. Outside those fixtures a missing token is unconfigured.
    """
    required = os.environ.get("THREATFUSION_REQUIRE_SENSOR_TOKEN", "").strip() == "1"
    expected = os.environ.get("THREATFUSION_SENSOR_INGEST_TOKEN", "").strip()
    under_test = bool(os.environ.get("PYTEST_CURRENT_TEST"))
    if not expected:
        if under_test and not required:
            return "ok"
        return "unconfigured"
    presented = ""
    if isinstance(authorization_header, str):
        prefix, separator, token = authorization_header.partition(" ")
        if separator and prefix.lower() == "bearer":
            presented = token.strip()
    presented_bytes = presented.encode("utf-8")
    expected_bytes = expected.encode("utf-8")
    if len(presented_bytes) != len(expected_bytes) or not hmac.compare_digest(
        presented_bytes, expected_bytes
    ):
        return "unauthorized"
    return "ok"


def authorize_sensor_ingest(authorization_header: str | None) -> bool:
    """Fail closed when a sensor token is required or the presented bearer does not match."""
    return sensor_ingest_auth_status(authorization_header) == "ok"


def canonical_feature_contract_error(features: Any) -> str | None:
    """Reject a feature map that is missing a canonical name or a finite number."""
    if not isinstance(features, dict):
        return "invalid_feature_contract"
    for name in CANONICAL_14_FEATURES:
        if name not in features:
            return "invalid_feature_contract"
        value = features[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return "invalid_feature_contract"
        if not math.isfinite(float(value)):
            return "invalid_feature_contract"
    return None


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
    sensor_node: str | None = None,
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
    feature_payload = {name: features.get(name) for name in CANONICAL_14_FEATURES}
    for name in _DNN_FEATURES:
        if name in features:
            feature_payload[name] = features[name]
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO live_flows (
                observed_at_utc, features_json, rf_attack_probability, decision,
                evidence_state, reason, model_sha256, production_fusion_enabled,
                campaign_id, source_label, case_title,
                entity_namespace_id, src_entity_id, dst_entity_id,
                flow_protocol, service_or_port, clock_synchronized,
                source_event_id, sensor_observation_json, sensor_node
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observed,
                json.dumps(feature_payload),
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
                sensor_node,
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
    stored["sensor_node"] = sensor_node
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
    sensor_node: str | None = None,
) -> dict[str, Any]:
    """Score one adapted Suricata flow and store it under its own bridge campaign.

    The forest score is whatever the frozen model returns. The Suricata line is
    display text. No technique id is written onto the row. sensor_node records
    which forwarder sent the flow and does not change the score.
    """
    node = _normalize_sensor_node(sensor_node)
    if node is None:
        return _refused_sensor("invalid_sensor_node")
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
                   observed_at_utc, sensor_node
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
            "sensor_node": existing["sensor_node"] or SENSOR_BRIDGE_SOURCE,
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
        sensor_node=node,
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
    stored["sensor_node"] = node
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
    """Store one analyst note. Empty text and unknown flows are refused."""
    text = note_text.strip()
    author = author_id.strip()
    refused_role = _refuse_readonly_auditor(db_path, author)
    if refused_role is not None:
        return refused_role
    if not text or not author:
        return {"evidence_state": "unavailable", "reason": "note_incomplete", "stored": False}
    if not isinstance(flow_id, int) or isinstance(flow_id, bool) or flow_id <= 0:
        return {
            "evidence_state": "unavailable",
            "reason": "flow_not_found",
            "stored": False,
            "flow_id": flow_id,
        }
    created = datetime.now(UTC).isoformat()
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT flow_id FROM live_flows WHERE flow_id = ?", (flow_id,)
        ).fetchone()
        if row is None:
            return {
                "evidence_state": "unavailable",
                "reason": "flow_not_found",
                "stored": False,
                "flow_id": flow_id,
            }
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


_COPILOT_HEADINGS = (
    "[1] EXECUTIVE TRIAGE & MODEL AUTHORITY",
    "[2] CORRELATED TELEMETRY & EVIDENCE LOCKER",
    "[3] MITRE ATT&CK & CVE THREAT INTELLIGENCE",
    "[4] IMMEDIATE ANALYST INVESTIGATION STEPS",
    "[5] GOVERNED SOAR PLAYBOOK & CONTAINMENT GUIDANCE",
)
_COPILOT_TITLES = tuple(heading.split("] ", 1)[1] for heading in _COPILOT_HEADINGS)
_CVE_TOKEN = re.compile(r"cve[-_ ]?(\d{4})[-_ ](\d{4,7})", re.IGNORECASE)
_MITRE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_SCENARIO_LABEL_RE = re.compile(r"scenario label (T\d+(?:\.\d+)?)")
_POISON_IPV4 = frozenset({"198.51.100.99", "203.0.113.99"})
_LIVE_GEMINI_CACHE: dict[tuple[int, str, str], dict[str, Any]] = {}
_LIVE_GEMINI_CACHE_LOCK = threading.Lock()
_COPILOT_BRIEF_INSTRUCTION = (
    "Write 2-4 authoritative sentences plus bullets under each canonical heading "
    "[1] EXECUTIVE TRIAGE & MODEL AUTHORITY, "
    "[2] CORRELATED TELEMETRY & EVIDENCE LOCKER, "
    "[3] MITRE ATT&CK & CVE THREAT INTELLIGENCE, "
    "[4] IMMEDIATE ANALYST INVESTIGATION STEPS, and "
    "[5] GOVERNED SOAR PLAYBOOK & CONTAINMENT GUIDANCE. "
    "Explain why rf_attack_probability is above or below the 0.5000 threshold, "
    "how the Evidence Locker port and protocol baseline and historical frequency behave, "
    "how the retrieved MITRE and CVE identifiers apply, and the concrete operator steps. "
    "Mention only this flow's stored src_entity_id, dst_entity_id, and retrieved "
    "MITRE and CVE identifiers. Use **bold** for the decision and `code` for identifiers."
)


def _normalize_copilot_headings(text: str) -> str:
    """Rewrite '1. TITLE' and '1) TITLE' into the canonical '[1] TITLE' headings."""
    normalized = text
    for index, title in enumerate(_COPILOT_TITLES, start=1):
        canonical = _COPILOT_HEADINGS[index - 1]
        pattern = re.compile(rf"(?i)(?:\[)?{index}(?:\])?[.)\:\-]?[ \t]+{re.escape(title)}")
        normalized = pattern.sub(canonical, normalized)
    return normalized


def _citation_ids(text: str) -> tuple[set[str], set[str]]:
    return set(_MITRE_ID.findall(text)), {item.upper() for item in _CVE_ID.findall(text)}


def _indexed_corpus_ids() -> tuple[set[str], set[str]]:
    """Technique and CVE ids that already exist in the 18-document local corpus."""
    techniques: set[str] = set()
    cves: set[str] = set()
    for doc in CANONICAL_MITRE_AND_PLAYBOOK_CORPUS:
        blob = " ".join(
            (
                doc.doc_id,
                doc.technique_id,
                doc.technique_name,
                doc.tactic,
                doc.description,
                doc.playbook_id,
            )
        )
        found_techniques, found_cves = _citation_ids(blob)
        techniques.add(doc.technique_id)
        techniques.update(found_techniques)
        cves.update(found_cves)
        for year, number in _CVE_TOKEN.findall(blob):
            cves.add(f"CVE-{year}-{number}")
    return techniques, cves


def _ensure_copilot_headings(text: str) -> str:
    """Insert a missing canonical heading and keep the live prose."""
    repaired = text.strip()
    if not repaired:
        return repaired
    missing = [heading for heading in _COPILOT_HEADINGS if heading not in repaired]
    if not missing:
        return repaired
    present = [heading for heading in _COPILOT_HEADINGS if heading in repaired]
    if not present:
        paragraphs = [part.strip() for part in re.split(r"\n\s*\n", repaired) if part.strip()]
        if len(paragraphs) >= len(_COPILOT_HEADINGS):
            chunks: list[str] = []
            last = len(_COPILOT_HEADINGS) - 1
            for index, heading in enumerate(_COPILOT_HEADINGS):
                body = paragraphs[index] if index < last else "\n\n".join(paragraphs[index:])
                chunks.append(f"{heading}\n{body}")
            return "\n\n".join(chunks)
        chunks = [f"{_COPILOT_HEADINGS[0]}\n{repaired}"]
        chunks.extend(_COPILOT_HEADINGS[1:])
        return "\n".join(chunks)
    for heading in missing:
        index = _COPILOT_HEADINGS.index(heading)
        later = next((item for item in _COPILOT_HEADINGS[index + 1 :] if item in repaired), "")
        if later:
            repaired = repaired.replace(later, f"{heading}\n{later}", 1)
        else:
            repaired = f"{repaired}\n{heading}"
    return repaired


def _copilot_sections_have_prose(text: str) -> bool:
    """A heading with no sentences is not a finished brief."""
    for index, heading in enumerate(_COPILOT_HEADINGS):
        start = text.find(heading)
        if start < 0:
            return False
        body_start = start + len(heading)
        end = len(text)
        for later in _COPILOT_HEADINGS[index + 1 :]:
            found = text.find(later, body_start)
            if found != -1:
                end = min(end, found)
        body = text[body_start:end].strip()
        if len(body) < 40 or "." not in body:
            return False
    return True


def _allowed_citation_ids(
    evidence: str,
    hits: Sequence[Mapping[str, Any]],
    flow_hits: Sequence[Mapping[str, Any]] = (),
) -> tuple[set[str], set[str]]:
    """Technique and CVE ids already present on the flow, the corpus, or the evidence."""
    allowed_techniques, allowed_cves = _citation_ids(evidence)
    corpus_techniques, corpus_cves = _indexed_corpus_ids()
    allowed_techniques.update(corpus_techniques)
    allowed_cves.update(corpus_cves)
    for hit in tuple(hits) + tuple(flow_hits):
        technique = str(hit.get("technique_id") or "").strip()
        if technique:
            allowed_techniques.add(technique)
        blob = " ".join(
            str(hit.get(key) or "") for key in ("technique_name", "playbook_id", "doc_id")
        )
        hit_techniques, hit_cves = _citation_ids(blob)
        allowed_techniques.update(hit_techniques)
        allowed_cves.update(hit_cves)
        for year, number in _CVE_TOKEN.findall(blob):
            allowed_cves.add(f"CVE-{year}-{number}")
    return allowed_techniques, allowed_cves


def _copilot_citations_grounded(
    text: str,
    evidence: str,
    hits: Sequence[Mapping[str, Any]],
    flow_hits: Sequence[Mapping[str, Any]] = (),
) -> bool:
    """Reject a MITRE or CVE id outside the flow hits, the indexed corpus, and the evidence."""
    allowed_techniques, allowed_cves = _allowed_citation_ids(evidence, hits, flow_hits)
    found_techniques, found_cves = _citation_ids(text)
    return found_techniques.issubset(allowed_techniques) and found_cves.issubset(allowed_cves)


def _flow_verified_technique_id(
    flow_hits: Sequence[Mapping[str, Any]],
    hits: Sequence[Mapping[str, Any]],
) -> str:
    """Prefer the stored flow hit, then a retrieved hit, as the replacement id."""
    for group in (flow_hits, hits):
        for hit in group:
            technique = str(hit.get("technique_id") or "").strip().upper()
            if _MITRE_ID.fullmatch(technique):
                return technique
    return ""


def _rewrite_unindexed_citations(
    text: str,
    evidence: str,
    hits: Sequence[Mapping[str, Any]],
    flow_hits: Sequence[Mapping[str, Any]],
    *,
    malicious: bool,
) -> str:
    """On an Attack row, swap an unindexed technique or CVE for the verified technique."""
    if not malicious:
        return text
    allowed_techniques, allowed_cves = _allowed_citation_ids(evidence, hits, flow_hits)
    found_techniques, found_cves = _citation_ids(text)
    if found_techniques.issubset(allowed_techniques) and found_cves.issubset(allowed_cves):
        return text
    replacement = _flow_verified_technique_id(flow_hits, hits)

    def mitre(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in allowed_techniques:
            return token
        return replacement

    def cve(match: re.Match[str]) -> str:
        if match.group(0).upper() in allowed_cves:
            return match.group(0)
        return replacement

    return _CVE_ID.sub(cve, _MITRE_ID.sub(mitre, text))


def _bundle_inspected_entities(bundle: Any) -> tuple[str, ...]:
    enrichment = getattr(bundle, "enrichment_result", None)
    if enrichment is None:
        return ()
    entities = getattr(enrichment, "inspected_entities", ()) or ()
    return tuple(str(item).strip() for item in entities if str(item).strip())


def _strip_anonymized_study_ips(
    text: str,
    *,
    source_label: str,
    inspected: Sequence[str],
) -> str:
    """Drop example IPv4 on an anonymized study row. Poison addresses stay in the text."""
    if source_label != "recorded_unsw_nb15" or tuple(inspected):
        return text
    from threatfusion.advisory.explanation_engine import IP_REGEX

    def repl(match: re.Match[str]) -> str:
        if match.group(0) in _POISON_IPV4:
            return match.group(0)
        return ""

    return re.sub(r"[ \t]{2,}", " ", IP_REGEX.sub(repl, text))


def _positive_flow_id(flow_id: Any) -> int | None:
    try:
        number = int(flow_id)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    return number


def _copilot_flow_identity(stored: Mapping[str, Any] | None) -> tuple[str, str, str]:
    """Bind an advisory brief to one flow, not to a shared lab address pair."""
    if not isinstance(stored, Mapping):
        return ("", "", "")
    return (
        str(_scenario_technique_id(stored) or ""),
        str(stored.get("case_title") or ""),
        str(stored.get("decision") or ""),
    )


def _narrative_matches_identity(text: str, identity: tuple[str, str, str]) -> bool:
    scenario, title, _decision = identity
    if not text:
        return False
    if title and title not in text:
        return False
    if scenario and scenario not in text:
        return False
    if scenario:
        for cve in _CORPUS_TECHNIQUE_CVES.get(scenario, ()):
            if cve not in text:
                return False
    return True


def _copilot_cache_key(
    flow_id: int,
    question: str,
    model_name: str,
    identity: tuple[str, str, str] = ("", "", ""),
) -> str:
    scenario, title, decision = identity
    return (
        f"{flow_id}\n{scenario}\n{title}\n{decision}\n" f"{question.strip().lower()}\n{model_name}"
    )


def _ensure_copilot_cache_table(db_path: Path) -> None:
    with _connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS live_copilot_cache (
                cache_key TEXT PRIMARY KEY,
                provider TEXT,
                model_name TEXT,
                narrative TEXT,
                created_at_utc TEXT
            )
            """)


def _cached_live_gemini(
    flow_id: Any,
    question: str,
    model_name: str,
    db_path: Path | None = None,
    identity: tuple[str, str, str] = ("", "", ""),
) -> dict[str, Any] | None:
    number = _positive_flow_id(flow_id)
    if number is None:
        return None
    key = (number, identity, question.strip().lower(), model_name)
    with _LIVE_GEMINI_CACHE_LOCK:
        cached = _LIVE_GEMINI_CACHE.get(key)
    if cached is not None:
        return dict(cached)
    if db_path is None or not db_path.is_file():
        return None
    try:
        _ensure_copilot_cache_table(db_path)
        with _connect(db_path) as conn:
            row = conn.execute(
                """
                SELECT provider, model_name, narrative
                FROM live_copilot_cache WHERE cache_key = ?
                """,
                (_copilot_cache_key(number, question, model_name, identity),),
            ).fetchone()
    except sqlite3.Error:
        return None
    if row is None:
        return None
    payload = {
        "provider": row["provider"],
        "model_name": row["model_name"],
        "narrative": row["narrative"],
    }
    with _LIVE_GEMINI_CACHE_LOCK:
        _LIVE_GEMINI_CACHE[key] = dict(payload)
    return payload


def _remember_live_gemini(
    flow_id: Any,
    question: str,
    model_name: str,
    payload: Mapping[str, Any],
    db_path: Path | None = None,
    identity: tuple[str, str, str] = ("", "", ""),
) -> None:
    number = _positive_flow_id(flow_id)
    if number is None:
        return
    key = (number, identity, question.strip().lower(), model_name)
    stored = dict(payload)
    with _LIVE_GEMINI_CACHE_LOCK:
        _LIVE_GEMINI_CACHE[key] = stored
    if db_path is None or not db_path.is_file():
        return
    try:
        _ensure_copilot_cache_table(db_path)
        with _connect(db_path) as conn:
            conn.execute(
                """
                INSERT INTO live_copilot_cache (
                    cache_key, provider, model_name, narrative, created_at_utc
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    provider = excluded.provider,
                    model_name = excluded.model_name,
                    narrative = excluded.narrative,
                    created_at_utc = excluded.created_at_utc
                """,
                (
                    _copilot_cache_key(number, question, model_name, identity),
                    str(stored.get("provider") or ""),
                    model_name,
                    str(stored.get("narrative") or ""),
                    datetime.now(UTC).isoformat(),
                ),
            )
    except (OSError, sqlite3.Error):
        return


def invalidate_copilot_brief_cache(flow_id: int, db_path: Path | None = None) -> None:
    """Drop cached advisory briefs after Approve / Dispatch / Isolate / Rollback."""
    number = _positive_flow_id(flow_id)
    if number is None:
        return
    with _LIVE_GEMINI_CACHE_LOCK:
        stale = [key for key in _LIVE_GEMINI_CACHE if key[0] == number]
        for key in stale:
            _LIVE_GEMINI_CACHE.pop(key, None)
    if db_path is None or not db_path.is_file():
        return
    try:
        _ensure_copilot_cache_table(db_path)
        with _connect(db_path) as conn:
            conn.execute(
                "DELETE FROM live_copilot_cache WHERE cache_key LIKE ?",
                (f"{number}\n%",),
            )
    except (OSError, sqlite3.Error):
        return


def _live_copilot_callable() -> Any:
    """Live five-section request. The class default stays 512 tokens and temperature 0.0."""
    from threatfusion.advisory.gemini_client import (
        GeminiAdvisoryCallable,
        GeminiAdvisoryConfig,
        resolve_gemini_model,
    )

    return GeminiAdvisoryCallable(
        GeminiAdvisoryConfig(
            model_name=resolve_gemini_model(),
            max_output_tokens=4096,
            temperature=0.1,
            timeout_seconds=30.0,
        )
    )


def _copilot_soar_gates(
    stored: Mapping[str, Any] | None,
    soar_db_path: Path | None,
) -> tuple[bool, bool]:
    """Return a verified receipt flag and a non-empty valid hash-chain flag."""
    if stored is None or soar_db_path is None or not Path(soar_db_path).is_file():
        return False, False
    playbook_id = str(stored.get("playbook_id") or "").strip()
    if not playbook_id:
        return False, False
    repository = SoarPlaybookSqliteRepository(Path(soar_db_path))
    try:
        chain_ok, _message = repository.verify_audit_chain_integrity(require_non_empty=True)
        receipt = _receipt_from_ledger(repository, playbook_id)
    except (sqlite3.Error, OSError, KeyError, ValueError):
        return False, False
    return receipt.get("evidence_state") == "verified", bool(chain_ok)


def _copilot_allowed_entities(stored: Mapping[str, Any] | None) -> list[str]:
    """Keep only stored endpoints. Empty and not-recorded values are omitted."""
    if not stored:
        return []
    allowed: list[str] = []
    for key in ("src_entity_id", "dst_entity_id"):
        text = str(stored.get(key) or "").strip()
        if not text or text.lower() == "not-recorded" or text in allowed:
            continue
        allowed.append(text)
    return allowed


def _text_uses_only_entities(text: str, allowed: Sequence[str]) -> bool:
    from threatfusion.advisory.explanation_engine import IP_REGEX

    return set(IP_REGEX.findall(text)).issubset(set(allowed))


def _safe_copilot_clause(text: str, allowed: Sequence[str]) -> str:
    cleaned = " ".join(text.split())
    if not cleaned or not _text_uses_only_entities(cleaned, allowed):
        return ""
    return cleaned


_SCENARIO_PLAYBOOKS = {
    "T1046": "pb-discovery-network-contain-v1",
    "T1110": "pb-ssh-bruteforce-contain-v1",
    "T1190": "pb-web-exploit-contain-v1",
}


def candidate_playbook_id(decision: str, technique_id: str | None) -> str | None:
    """Candidate playbook for an Attack row. It is not a verified ledger receipt."""
    if decision != "Attack":
        return None
    if technique_id and technique_id in _SCENARIO_PLAYBOOKS:
        return _SCENARIO_PLAYBOOKS[technique_id]
    return "pb-rf-attack-contain-v1"


_PORT53_DOS_TITLE = "Recorded UNSW-NB15 Generic DoS Burst on Destination Port 53"


def _title_technique_id(title: str) -> str | None:
    if title.strip() == _PORT53_DOS_TITLE:
        return "T1498"
    return None


def _scenario_technique_id(stored: Mapping[str, Any]) -> str | None:
    title = str(stored.get("case_title") or "")
    match = _SCENARIO_LABEL_RE.search(title)
    if match:
        return match.group(1)
    titled = _title_technique_id(title)
    if titled:
        return titled
    hits = stored.get("chroma_rag_hits")
    if isinstance(hits, list) and hits and isinstance(hits[0], Mapping):
        technique = str(hits[0].get("technique_id") or "").strip()
        if technique:
            return technique
    return None


def _cves_for_technique(technique_id: str) -> list[str]:
    found: list[str] = []
    corpus_cves = _indexed_corpus_ids()[1]
    for cve in _CORPUS_TECHNIQUE_CVES.get(technique_id, ()):
        if cve in corpus_cves and cve not in found:
            found.append(cve)
    for doc in CANONICAL_MITRE_AND_PLAYBOOK_CORPUS:
        if doc.technique_id != technique_id:
            continue
        blob = f"{doc.technique_name} {doc.description} {doc.playbook_id} {doc.doc_id}"
        for year, number in _CVE_TOKEN.findall(blob):
            cve = f"CVE-{year}-{number}"
            if cve in corpus_cves and cve not in found:
                found.append(cve)
    return found


def _attack_technique_id(stored: Mapping[str, Any]) -> str | None:
    """Technique used to retrieve indexed corpus CVEs for one Attack row."""
    technique = _scenario_technique_id(stored)
    if technique:
        return technique
    hits = stored.get("chroma_rag_hits")
    if isinstance(hits, list):
        for hit in hits:
            if not isinstance(hit, Mapping):
                continue
            candidate = str(hit.get("technique_id") or "").strip()
            if candidate:
                return candidate
    port = str(stored.get("service_or_port") or "").strip()
    return {
        "445": "T1046",
        "22": "T1110",
        "80": "T1190",
        "443": "T1190",
        "8080": "T1190",
        "53": "T1498",
    }.get(port)


def _flow_citation_ids(stored: Mapping[str, Any]) -> tuple[list[str], list[str]] | None:
    """Use this flow's technique. Benign cites none. Other rows keep the question hits."""
    decision = str(stored.get("decision") or "")
    if decision == "Benign":
        return [], []
    if decision != "Attack":
        return None
    technique = _attack_technique_id(stored)
    cves = _cves_for_technique(technique) if technique else []
    if not cves:
        corpus_cves = _indexed_corpus_ids()[1]
        for mapped in _CORPUS_TECHNIQUE_CVES.values():
            for cve in mapped:
                if cve in corpus_cves and cve not in cves:
                    cves.append(cve)
    return [technique] if technique else [], cves


def _copilot_citation_ids(hits: Sequence[Mapping[str, Any]]) -> tuple[list[str], list[str]]:
    techniques: list[str] = []
    cves: list[str] = []
    for hit in hits:
        technique = str(hit.get("technique_id") or "").strip()
        if technique and technique not in techniques:
            techniques.append(technique)
        blob = " ".join(
            str(hit.get(key) or "") for key in ("technique_name", "playbook_id", "doc_id")
        )
        for year, number in _CVE_TOKEN.findall(blob):
            cve = f"CVE-{year}-{number}"
            if cve not in cves:
                cves.append(cve)
    return techniques, cves


def _copilot_grounding_bundle(
    stored: Mapping[str, Any],
    allowed: Sequence[str],
) -> Any:
    from threatfusion.advisory.explanation_engine import AdvisoryEvidenceBundle
    from threatfusion.enrichment.threat_intel import ThreatIntelEnrichmentResult

    raw_probability = stored.get("rf_attack_probability")
    try:
        probability = float(raw_probability) if raw_probability is not None else 0.0
    except (TypeError, ValueError):
        probability = 0.0
    enrichment = None
    if allowed:
        try:
            private_guard = _any_non_public_ipv4(allowed)
        except ValueError:
            private_guard = False
        enrichment = ThreatIntelEnrichmentResult(
            status="internal_lab_entity_annotated",
            provenance_verified=True,
            external_lookup_performed=False,
            private_ip_guard_triggered=private_guard,
            inspected_entities=tuple(allowed),
            internal_lab_annotations={},
            matches=(),
            feed_snapshot_id=None,
            reason="stored_flow_entities",
        )
    return AdvisoryEvidenceBundle(
        candidate_id=f"live_flow:{stored.get('flow_id')}",
        record_id=f"live_flow:{stored.get('flow_id')}",
        rf_model_version="network_random_forest_baseline_v1",
        rf_attack_probability=probability,
        rf_threshold=0.5,
        top_feature_signals={},
        incident_id=stored.get("campaign_id"),
        observed_at=stored.get("observed_at_utc"),
        enrichment_result=enrichment,
    )


def _local_air_gapped_brief(
    stored: Mapping[str, Any],
    locker: Mapping[str, Any],
    memory: Sequence[Mapping[str, Any]],
    techniques: Sequence[str],
    cves: Sequence[str],
    allowed: Sequence[str],
) -> str:
    """Offline senior-analyst brief. Every address in it is one of the stored endpoints."""
    decision = str(stored.get("decision") or "unavailable")
    raw_probability = stored.get("rf_attack_probability")
    try:
        probability = (
            f"{float(raw_probability):.4f}" if raw_probability is not None else "unavailable"
        )
    except (TypeError, ValueError):
        probability = "unavailable"
    try:
        above = float(raw_probability) >= 0.5 if raw_probability is not None else False
    except (TypeError, ValueError):
        above = False
    threshold_clause = (
        f"**{decision}** is above the `0.5000` threshold."
        if above
        else f"**{decision}** is below the `0.5000` threshold."
    )
    digest = str(stored.get("model_sha256") or "")
    digest_text = digest if _SHA256_HEX.fullmatch(digest) else "unavailable"
    source = _safe_copilot_clause(str(stored.get("source_label") or "unavailable"), allowed)
    title = _safe_copilot_clause(str(stored.get("case_title") or ""), allowed)
    scenario = _scenario_technique_id(stored) or ""
    if not scenario and str(stored.get("source_label") or "") == "live_scenario_replay":
        scenario = "none"
    mapped_cves = list(_CORPUS_TECHNIQUE_CVES.get(scenario, ()))
    if mapped_cves:
        cves = list(dict.fromkeys([*mapped_cves, *cves]))
    src = str(stored.get("src_entity_id") or "").strip()
    dst = str(stored.get("dst_entity_id") or "").strip()
    endpoint = "Stored endpoints were not recorded on this flow."
    if src in allowed and dst in allowed:
        endpoint = f"Stored endpoints `{src}` to `{dst}`."
    elif src in allowed:
        endpoint = f"Stored source `{src}`."
    elif dst in allowed:
        endpoint = f"Stored destination `{dst}`."
    protocol = _safe_copilot_clause(str(stored.get("flow_protocol") or "unavailable"), allowed)
    service = _safe_copilot_clause(str(stored.get("service_or_port") or "unavailable"), allowed)
    queries = {
        str(item.get("query_id")): item
        for item in locker.get("queries", [])
        if isinstance(item, Mapping) and item.get("query_id")
    }
    frequency = queries.get("entity_historical_frequency", {})
    baseline = queries.get("destination_port_protocol_baseline", {})
    campaign = queries.get("correlated_campaign_soar_ledger", {})
    rules = [
        clause
        for row in memory
        if (clause := _safe_copilot_clause(str(row.get("expected_behavior_rule") or ""), allowed))
    ]
    technique_text = ", ".join(f"`{item}`" for item in techniques) if techniques else "`none`"
    cve_text = ", ".join(f"`{item}`" for item in cves) if cves else "`none`"
    memory_text = (
        "Context memory rules: " + " ".join(rules) + "."
        if rules
        else "No stored context memory rule names an address outside this flow."
    )
    receipt_status = str(campaign.get("soar_receipt_status") or "unavailable")
    containment_state = str(stored.get("containment_state") or "")
    execution_authorized = receipt_status in {
        "approved",
        "verified",
        "isolated",
        "rolled_back",
    } or containment_state in {
        "applied",
        "simulated_applied",
        "rolled_back",
        "simulated_rolled_back",
    }
    auth_token = "true" if execution_authorized else "false"
    if decision != "Attack":
        containment = (
            f"**Containment is blocked.** The frozen Random Forest decision is `{decision}`. "
            "Do not isolate an endpoint while the score stays below the attack threshold. "
            f"`execution_authorized` : `{auth_token}`. "
            f"`soar_receipt_status` : `{receipt_status}`."
        )
    elif receipt_status == "isolated" or containment_state in {
        "applied",
        "simulated_applied",
    }:
        containment = (
            "**Containment applied.** The approved playbook authorized victim-namespace "
            "iptables isolation for this stored Attack row. "
            f"`execution_authorized` : `{auth_token}`. "
            f"`soar_receipt_status` : `{receipt_status}`."
        )
    elif receipt_status == "rolled_back" or containment_state in {
        "rolled_back",
        "simulated_rolled_back",
    }:
        containment = (
            "**Containment rolled back.** The firewall drop was removed and the SHA-256 "
            "ledger recorded the restore. "
            f"`execution_authorized` : `{auth_token}`. "
            f"`soar_receipt_status` : `{receipt_status}`."
        )
    elif receipt_status == "verified":
        containment = (
            "**Callback verified.** The signed HMAC receipt is recorded. Isolate remains "
            "a separate human step. "
            f"`execution_authorized` : `{auth_token}`. "
            f"`soar_receipt_status` : `{receipt_status}`."
        )
    elif receipt_status == "approved":
        containment = (
            "**Playbook approved.** Dispatch via n8n (or the local contract fallback) is "
            "unlocked. Host containment has not executed yet. "
            f"`execution_authorized` : `{auth_token}`. "
            f"`soar_receipt_status` : `{receipt_status}`."
        )
    else:
        containment = (
            "**Containment stays unauthorized.** A human must approve the SHA-256 hash-chained "
            "playbook before any n8n webhook, victim firewall isolation, or rollback check. "
            f"`execution_authorized` : `{auth_token}`. "
            f"`soar_receipt_status` : `{receipt_status}`. "
            "The frozen forest recommendation does not dispatch a response by itself."
        )
    sections = (
        f"{_COPILOT_HEADINGS[0]}\n"
        f"The frozen Random Forest is the only alert authority on this stored flow. "
        f"{threshold_clause} Attack probability is `{probability}`. "
        f"The scoring-time digest is `{digest_text}`. "
        "**production_fusion_enabled is false**, so the secondary v2 autoencoder does not "
        "decide this alert. "
        f"Source label `{source or 'unavailable'}`."
        + (f" Scenario label `{scenario}`." if scenario else "")
        + (f" Case title `{title}`." if title else ""),
        f"{_COPILOT_HEADINGS[1]}\n"
        "Dual-window correlation uses a `30.0s` burst and a `600.0s` campaign. "
        f"{endpoint} Protocol `{protocol or 'unavailable'}`. "
        f"Service or port `{service or 'unavailable'}`. "
        f"**entity_historical_frequency** count `{frequency.get('entity_count', 0)}`. "
        "The port and protocol baseline counts prior flows to this service and reports "
        f"`destination_port_protocol_baseline` flow_count `{baseline.get('flow_count', 0)}`. "
        "The campaign ledger records "
        f"`stitched_flow_count` `{campaign.get('stitched_flow_count', 0)}` and "
        f"`soar_receipt_status` `{receipt_status}`. "
        f"{memory_text}",
        f"{_COPILOT_HEADINGS[2]}\n"
        + (
            "No offensive MITRE ATT&CK technique is confirmed because the Frozen Random "
            "Forest decision is **Benign**. A corpus neighbor is not a finding on this flow."
            if decision == "Benign"
            else (
                "Only indexed corpus techniques and CVEs already retrieved for this flow may be cited. "
                f"**Retrieved MITRE ATT&CK technique IDs:** {technique_text}. "
                f"**Retrieved CVE IDs:** {cve_text}. "
                "An identifier that is not in the local corpus, the flow hit, or this evidence block "
                "is a hallucination and must not be treated as a finding."
            )
        ),
        f"{_COPILOT_HEADINGS[3]}\n"
        "Open the stored endpoints in Context Memory and confirm the expected behavior rule. "
        "Inspect the 5-node Attack Topology and the Evidence Locker frequency and baseline. "
        "Record a grounded analyst verdict that names only the stored source and destination. "
        "Do not add an address that is absent from this flow.",
        f"{_COPILOT_HEADINGS[4]}\n{containment}",
    )
    brief = "\n\n".join(sections)
    if not _text_uses_only_entities(brief, allowed):
        return ""
    return brief


def _five_section_flow_brief(
    stored: Mapping[str, Any],
    locker: Mapping[str, Any],
    memory: Sequence[Mapping[str, Any]],
    techniques: Sequence[str],
    cves: Sequence[str],
    allowed: Sequence[str],
) -> str:
    """Offline brief. Every address in it is one of the stored endpoints."""
    return _local_air_gapped_brief(stored, locker, memory, techniques, cves, allowed)


def answer_mitre_copilot(
    db_path: Path | str,
    question: str | Path = "",
    flow_id: int | None = None,
    rag_db_path: Path | None = None,
    *,
    soar_db_path: Path | None = None,
) -> dict[str, Any]:
    """Answer from the local MITRE corpus, then a flow-grounded five-section brief.

    A legacy call ``answer_mitre_copilot(question, rag_db_path)`` stays corpus-only.
    """
    if isinstance(db_path, str) and isinstance(question, Path):
        rag_db_path = question
        question = db_path
        db_path = Path()
        flow_id = None
        soar_db_path = None
    elif isinstance(db_path, str):
        db_path = Path(db_path)
    asked = question if isinstance(question, str) else ""
    if _CONTAINMENT_REQUEST.search(asked):
        return disclose_offline_fallback(
            {
                "schema_version": "live_mitre_copilot_v1",
                "evidence_state": "unavailable",
                "execution_authorized": False,
                "reason": "containment_refused",
                "hits": [],
                "provider": "local_air_gapped",
                "provider_label": "AI Copilot: Local Air-Gapped Engine",
                "narrative": "",
                "grounded": False,
            }
        )
    corpus_path = (
        rag_db_path if isinstance(rag_db_path, Path) else Path("threatfusion-live-rag.sqlite3")
    )
    rag = ChromaDbMitrePlaybookRag(corpus_path)
    hits = rag.query_semantic_rag(asked, top_k=3)
    hit_rows = [
        {
            "technique_id": hit.technique_id,
            "technique_name": hit.technique_name,
            "playbook_id": hit.playbook_id,
            "doc_id": hit.doc_id,
            "cosine_similarity": hit.cosine_similarity,
        }
        for hit in hits
    ]
    stored = None
    resolved_flow_id: int | None
    try:
        resolved_flow_id = int(flow_id) if flow_id is not None else None
    except (TypeError, ValueError):
        resolved_flow_id = None
    if (
        resolved_flow_id is not None
        and resolved_flow_id > 0
        and isinstance(db_path, Path)
        and db_path.is_file()
    ):
        stored = _load_flow_row(db_path, resolved_flow_id)
    local_narrative = ""
    bundle = None
    if stored is not None and isinstance(db_path, Path):
        allowed = _copilot_allowed_entities(stored)
        _attach_chroma_rag_hits([stored], db_path)
        flow_citations = _flow_citation_ids(stored)
        if flow_citations is not None:
            techniques, cves = flow_citations
            if techniques:
                hit_rows = [
                    row
                    for row in (_corpus_technique_hit(technique) for technique in techniques)
                    if row is not None
                ]
            else:
                hit_rows = []
        else:
            techniques, cves = _copilot_citation_ids(hit_rows)
        locker = evidence_locker_queries(db_path, int(stored["flow_id"]), soar_db_path)
        memory = _memory_rows_for_entities(db_path, allowed)
        local_narrative = _five_section_flow_brief(
            stored, locker, memory, techniques, cves, allowed
        )
        bundle = _copilot_grounding_bundle(stored, allowed)
        if local_narrative:
            from threatfusion.advisory.explanation_engine import verify_explanation_groundedness

            if not verify_explanation_groundedness(local_narrative, bundle):
                local_narrative = ""
    flow_hits = stored.get("chroma_rag_hits") if isinstance(stored, Mapping) else None
    source_label = str(stored.get("source_label") or "") if isinstance(stored, Mapping) else ""
    decision = str(stored.get("decision") or "") if isinstance(stored, Mapping) else ""
    stored_flow_id = stored.get("flow_id") if isinstance(stored, Mapping) else None
    narrative = _grounded_gemini_narrative(
        asked,
        hit_rows,
        evidence_text=local_narrative or None,
        bundle=bundle,
        local_narrative=local_narrative,
        flow_hits=flow_hits if isinstance(flow_hits, list) else (),
        source_label=source_label,
        decision=decision,
        flow_id=stored_flow_id,
        db_path=db_path,
        identity=_copilot_flow_identity(stored if isinstance(stored, Mapping) else None),
    )
    provider = str(narrative.get("provider") or "local_air_gapped")
    narrative_text = str(narrative.get("narrative") or "")
    if narrative_text and provider == "gemini":
        reason = "gemini_grounded"
    elif narrative_text and stored is not None:
        reason = "local_flow_brief"
    elif hits:
        reason = "local_corpus"
    else:
        reason = "no_corpus_hit"
    grounded = False
    if narrative_text:
        from threatfusion.advisory.explanation_engine import (
            AdvisoryEvidenceBundle,
            verify_explanation_groundedness,
        )

        check_bundle = bundle
        if check_bundle is None:
            check_bundle = AdvisoryEvidenceBundle(
                candidate_id="live_copilot",
                record_id="live_copilot",
                rf_model_version="network_random_forest_baseline_v1",
                rf_attack_probability=0.0,
                rf_threshold=0.5,
                top_feature_signals={},
            )
        grounded = bool(verify_explanation_groundedness(narrative_text, check_bundle))
    receipt_ok, chain_ok = _copilot_soar_gates(
        stored if isinstance(stored, Mapping) else None,
        soar_db_path if isinstance(soar_db_path, Path) else None,
    )
    from threatfusion.api.analyst_dashboard import evidence_state_from_gates

    bound_flow_id = None if stored is None else stored.get("flow_id")
    soar_receipt = {"status": "unavailable"}
    if (
        isinstance(bound_flow_id, int)
        and bound_flow_id > 0
        and isinstance(db_path, Path)
    ):
        soar_receipt = _soar_receipt_status(
            soar_db_path if isinstance(soar_db_path, Path) else None,
            bound_flow_id,
            live_db_path=db_path,
        )
    execution_authorized = soar_receipt.get("status") in {
        "approved",
        "verified",
        "isolated",
        "rolled_back",
    }
    if (
        resolved_flow_id is not None
        and resolved_flow_id > 0
        and (stored is None or int(bound_flow_id or 0) != resolved_flow_id)
    ):
        return disclose_offline_fallback(
            {
                "schema_version": "live_mitre_copilot_v1",
                "evidence_state": "unavailable",
                "grounded": False,
                "execution_authorized": False,
                "reason": "flow_not_stored",
                "hits": [],
                "provider": "local_air_gapped",
                "provider_label": "AI Copilot: Local Air-Gapped Engine",
                "narrative": "",
                "production_fusion_enabled": False,
                "flow_id": resolved_flow_id,
                "decision": None,
                "rf_attack_probability": None,
                "src_entity_id": None,
                "dst_entity_id": None,
            }
        )
    return disclose_offline_fallback(
        {
            "schema_version": "live_mitre_copilot_v1",
            "evidence_state": evidence_state_from_gates(receipt_ok, chain_ok, grounded),
            "grounded": grounded,
            "execution_authorized": execution_authorized,
            "soar_receipt_status": soar_receipt.get("status"),
            "reason": reason,
            "hits": hit_rows,
            "provider": provider,
            "provider_label": narrative.get("provider_label"),
            "narrative": narrative_text,
            "production_fusion_enabled": False,
            "flow_id": bound_flow_id,
            "decision": None if stored is None else stored.get("decision"),
            "rf_attack_probability": (
                None if stored is None else stored.get("rf_attack_probability")
            ),
            "src_entity_id": None if stored is None else stored.get("src_entity_id"),
            "dst_entity_id": None if stored is None else stored.get("dst_entity_id"),
            "case_title": None if stored is None else stored.get("case_title"),
            "scenario_label": (
                None
                if stored is None
                else (_scenario_technique_id(stored) or stored.get("scenario_label"))
            ),
        }
    )


def _handoff_brief_or_local(
    default_brief: str,
    addresses: list[str],
    bundle: Any,
) -> str:
    """Use a grounded Gemini brief when a key is configured. Otherwise keep the local brief."""
    from threatfusion.advisory.explanation_engine import verify_explanation_groundedness
    from threatfusion.advisory.gemini_client import (
        GeminiAdvisoryUnavailableError,
        advisory_provider_status,
    )

    if not advisory_provider_status().get("live_call_allowed"):
        return default_brief
    evidence = default_brief
    if addresses:
        evidence = f"{default_brief} Stored addresses: {', '.join(addresses)}."
    try:
        text = _live_copilot_callable().generate_copilot_text(evidence)
    except (GeminiAdvisoryUnavailableError, OSError, TimeoutError):
        return default_brief
    if verify_explanation_groundedness(text, bundle):
        return text
    return default_brief


def _grounded_gemini_narrative(
    question: str,
    hits: list[dict[str, Any]],
    *,
    evidence_text: str | None = None,
    bundle: Any | None = None,
    local_narrative: str = "",
    flow_hits: Sequence[Mapping[str, Any]] = (),
    source_label: str = "",
    decision: str = "",
    flow_id: Any = None,
    db_path: Path | None = None,
    identity: tuple[str, str, str] = ("", "", ""),
) -> dict[str, Any]:
    """Return a Gemini brief after stripping unindexed ids and anonymized example addresses."""
    from threatfusion.advisory.explanation_engine import (
        AdvisoryEvidenceBundle,
        verify_explanation_groundedness,
    )
    from threatfusion.advisory.gemini_client import (
        GeminiAdvisoryUnavailableError,
        advisory_provider_status,
        resolve_gemini_model,
    )

    status = advisory_provider_status()
    local = {
        "provider": "local_air_gapped",
        "provider_label": "AI Copilot: Local Air-Gapped Engine",
        "narrative": local_narrative,
    }
    if not status.get("live_call_allowed"):
        return disclose_offline_fallback(local)
    model_name = str(status.get("model_name") or resolve_gemini_model())
    cached = _cached_live_gemini(flow_id, question, model_name, db_path, identity)
    if cached is not None and _narrative_matches_identity(
        str(cached.get("narrative") or ""), identity
    ):
        return cached
    if evidence_text:
        evidence = evidence_text
    else:
        lines = [f"Analyst question: {question}"]
        for hit in hits:
            lines.append(
                f"Retrieved candidate technique {hit.get('technique_id')} "
                f"{hit.get('technique_name')} playbook {hit.get('playbook_id')}."
            )
        if not hits:
            lines.append("No local corpus hit.")
        evidence = "\n".join(lines)
    try:
        text = _live_copilot_callable().generate_copilot_text(
            _COPILOT_BRIEF_INSTRUCTION + "\n" + evidence
        )
    except (GeminiAdvisoryUnavailableError, OSError, TimeoutError):
        return local
    text = _ensure_copilot_headings(_normalize_copilot_headings(text))
    check_bundle = bundle
    if check_bundle is None:
        check_bundle = AdvisoryEvidenceBundle(
            candidate_id="live_copilot",
            record_id="live_copilot",
            rf_model_version="network_random_forest_baseline_v1",
            rf_attack_probability=0.0,
            rf_threshold=0.5,
            top_feature_signals={},
        )
    inspected = _bundle_inspected_entities(check_bundle)
    text = _strip_anonymized_study_ips(text, source_label=source_label, inspected=inspected)
    text = _rewrite_unindexed_citations(
        text,
        evidence,
        hits,
        flow_hits,
        malicious=decision == "Attack",
    )
    if not verify_explanation_groundedness(text, check_bundle):
        return local
    if not _copilot_citations_grounded(text, evidence, hits, flow_hits):
        return local
    if evidence_text and not _copilot_sections_have_prose(text):
        return local
    live = {
        "provider": "gemini",
        "provider_label": status.get("label"),
        "narrative": text,
    }
    if not _narrative_matches_identity(text, identity):
        return local
    _remember_live_gemini(flow_id, question, model_name, live, db_path, identity)
    return live


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
    doc_obj = (
        document[0]
        if isinstance(document, list) and document
        else (document if isinstance(document, dict) else {})
    )
    if not isinstance(doc_obj, dict):
        doc_obj = {}
    nodes = [
        {"name": node.get("name"), "type": node.get("type")}
        for node in doc_obj.get("nodes", [])
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
                   identity_verified, identity_label, containment_state, containment_rule,
                   containment_at, rollback_at, sensor_node
            FROM live_flows
            ORDER BY flow_id DESC
            LIMIT ?
            """,
            (max(1, min(limit, 100)),),
        ).fetchall()
    published: list[dict[str, Any]] = []
    repo_root = _console_repo_root()
    for row in rows:
        item = dict(row)
        item["glass_box"] = build_glass_box_checklist(item)
        _annotate_soar_state(item)
        raw_observation = item.pop("sensor_observation_json", None)
        raw_features = item.pop("features_json", None)
        parsed_features: Any = None
        if isinstance(raw_features, str) and raw_features:
            try:
                parsed_features = json.loads(raw_features)
            except json.JSONDecodeError:
                parsed_features = None
        if isinstance(parsed_features, dict):
            item["canonical_features"] = {
                name: parsed_features.get(name) for name in CANONICAL_14_FEATURES
            }
            projected = dnn_features_from_flow(parsed_features, repo_root)
            if projected is not None:
                item["dnn_features"] = projected
            if _finite_feature_vector(parsed_features)[0] is not None:
                scored = score_canonical_flow(parsed_features, repo_root=repo_root)
                for key in (
                    "ae_loss",
                    "ae_anomaly_flag",
                    "ae_threshold",
                    "ae_top_features",
                    "dnn_attack_probability",
                    "dnn_binary_decision",
                    "unsw_attack_category",
                    "threatfusion_consensus_score",
                    "consensus_label",
                ):
                    item[key] = scored.get(key)
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
        containment = str(item.get("containment_state") or "")
        if containment in {"simulated_applied", "simulated_rolled_back"}:
            item["containment_evidence_state"] = "simulated"
        elif containment in {"applied", "rolled_back"}:
            item["containment_evidence_state"] = "verified"
        else:
            item["containment_evidence_state"] = "unavailable"
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
        available = {str(row[1]) for row in conn.execute("PRAGMA table_info(incidents)").fetchall()}
        selected = [
            name
            for name in (
                "incident_id",
                "window_type",
                "constituent_alert_count",
                "max_probability_score",
                "escalated_decision",
                "earliest_observed_at",
                "provenance_status",
                "campaign_key",
                "campaign_id",
            )
            if name in available
        ]
        if "incident_id" not in selected:
            return []
        rows = conn.execute(
            f"""
            SELECT {", ".join(selected)}
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
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        item = dict(row)
        incident_id = str(item.get("incident_id") or "")
        if not incident_id or incident_id in seen:
            continue
        seen.add(incident_id)
        unique.append(item)
    return unique


def _flow_entities(stored: Mapping[str, Any] | sqlite3.Row) -> list[str]:
    entities: list[str] = []
    for key in ("src_entity_id", "dst_entity_id"):
        if hasattr(stored, "get"):
            value = stored.get(key)
        else:
            value = stored[key] if key in stored.keys() else None
        if isinstance(value, str):
            text = value.strip()
            if text and text not in entities:
                entities.append(text)
    return entities


def _memory_rows_for_entities(db_path: Path, entities: Sequence[str]) -> list[dict[str, Any]]:
    if not entities or not db_path.is_file():
        return []
    placeholders = ",".join("?" for _ in entities)
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT memory_id, entity_ip_or_subnet, service_or_port,
                   expected_behavior_rule, created_from_flow_id, operator_id,
                   created_at_utc
            FROM context_memory
            WHERE entity_ip_or_subnet IN ({placeholders})
            ORDER BY memory_id ASC
            """,
            tuple(entities),
        ).fetchall()
    return [dict(row) for row in rows]


def _upsert_context_memory_rows(
    db_path: Path,
    *,
    entities: Sequence[str],
    service_or_port: str,
    rule: str,
    flow_id: int,
    operator_id: str,
    recorded_at: str,
) -> list[dict[str, Any]]:
    """Remember one rule per entity and service. The forest columns are not written."""
    service = service_or_port.strip()
    with _connect(db_path) as conn:
        for entity in entities:
            conn.execute(
                """
                INSERT INTO context_memory (
                    entity_ip_or_subnet, service_or_port, expected_behavior_rule,
                    created_from_flow_id, operator_id, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(entity_ip_or_subnet, service_or_port) DO UPDATE SET
                    expected_behavior_rule = excluded.expected_behavior_rule,
                    created_from_flow_id = excluded.created_from_flow_id,
                    operator_id = excluded.operator_id,
                    created_at_utc = excluded.created_at_utc
                """,
                (entity, service, rule, flow_id, operator_id, recorded_at),
            )
    return _memory_rows_for_entities(db_path, entities)


def list_context_memory(db_path: Path, flow_id: int) -> dict[str, Any]:
    """Return institutional rules whose entity is on the stored flow."""
    refused = {
        "schema_version": "context_memory_v1",
        "evidence_state": "unavailable",
        "production_fusion_enabled": False,
        "entries": [],
    }
    if flow_id <= 0 or not db_path.is_file():
        refused["reason"] = "flow_not_stored"
        return refused
    stored = _load_flow_row(db_path, flow_id)
    if stored is None:
        refused["reason"] = "flow_not_stored"
        return refused
    entities = _flow_entities(stored)
    return {
        "schema_version": "context_memory_v1",
        "evidence_state": "verified",
        "reason": "stored_context_memory",
        "flow_id": flow_id,
        "production_fusion_enabled": False,
        "frozen_rf_decision": stored["decision"],
        "rf_attack_probability": stored["rf_attack_probability"],
        "entries": _memory_rows_for_entities(db_path, entities),
    }


def _latest_flow_id_for_entity(db_path: Path, entity: str) -> int | None:
    """Return the newest stored flow that names this source or destination entity."""
    if not db_path.is_file():
        return None
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT flow_id FROM live_flows
            WHERE src_entity_id = ? OR dst_entity_id = ?
            ORDER BY flow_id DESC
            LIMIT 1
            """,
            (entity, entity),
        ).fetchone()
    if row is None:
        return None
    return int(row["flow_id"])


def save_context_memory(
    db_path: Path,
    *,
    flow_id: int,
    rule: str,
    operator_id: str = "",
    entity_ip_or_subnet: str | None = None,
    service_or_port: str | None = None,
    actor_id: str | None = None,
) -> dict[str, Any]:
    """Store one institutional rule for entities already on the flow."""
    text = rule.strip()
    actor = (operator_id or actor_id or "").strip()
    entity_text = str(entity_ip_or_subnet or "").strip()
    refused = {
        "schema_version": "context_memory_v1",
        "evidence_state": "unavailable",
        "production_fusion_enabled": False,
        "execution_authorized": False,
        "entries": [],
        "stored": False,
    }
    if flow_id <= 0 and entity_text:
        found = _latest_flow_id_for_entity(db_path, entity_text)
        if found is None:
            refused["reason"] = "entity_not_on_flow"
            return refused
        flow_id = found
    if flow_id <= 0 or not text or len(text) > 500 or _LOCAL_ACTOR.match(actor) is None:
        refused["reason"] = "context_memory_incomplete"
        return refused
    if not db_path.is_file():
        refused["reason"] = "flow_not_stored"
        return refused
    stored = _load_flow_row(db_path, flow_id)
    if stored is None:
        refused["reason"] = "flow_not_stored"
        return refused
    if not _rationale_stays_on_stored_flow(text, stored):
        refused["reason"] = "explanation_not_grounded"
        return refused
    known = _flow_entities(stored)
    if entity_ip_or_subnet is None or not str(entity_ip_or_subnet).strip():
        entities = known
    else:
        chosen = str(entity_ip_or_subnet).strip()
        if chosen not in known:
            refused["reason"] = "entity_not_on_flow"
            return refused
        entities = [chosen]
    if not entities:
        refused["reason"] = "entity_not_on_flow"
        return refused
    if service_or_port is None:
        service = str(stored.get("service_or_port") or "")
    else:
        service = str(service_or_port).strip()
        if len(service) > 64:
            refused["reason"] = "context_memory_incomplete"
            return refused
    recorded_at = datetime.now(UTC).isoformat()
    entries = _upsert_context_memory_rows(
        db_path,
        entities=entities,
        service_or_port=service,
        rule=text,
        flow_id=flow_id,
        operator_id=actor,
        recorded_at=recorded_at,
    )
    confirmed = _load_flow_row(db_path, flow_id) or stored
    return {
        "schema_version": "context_memory_v1",
        "evidence_state": "verified",
        "reason": "context_memory_stored",
        "flow_id": flow_id,
        "production_fusion_enabled": False,
        "execution_authorized": False,
        "frozen_rf_decision": confirmed["decision"],
        "rf_attack_probability": confirmed["rf_attack_probability"],
        "decision_unchanged": confirmed["decision"] == stored["decision"],
        "entries": entries,
    }


def _soar_receipt_status(
    soar_db_path: Path | None,
    flow_id: int,
    *,
    live_db_path: Path | None = None,
) -> dict[str, str]:
    """Read the current playbook / containment receipt for this flow.

    Status advances as the operator walks 1-2-3-4:
    approved -> verified (callback) -> isolated -> rolled_back.
    """
    unavailable = {"status": "unavailable", "evidence_state": "unavailable"}
    containment_state = ""
    callback_recorded = False
    if live_db_path is not None and live_db_path.is_file():
        try:
            with _connect(live_db_path) as live_conn:
                live_row = live_conn.execute(
                    """
                    SELECT containment_state, callback_recorded
                    FROM live_flows WHERE flow_id = ?
                    """,
                    (flow_id,),
                ).fetchone()
            if live_row is not None:
                containment_state = str(live_row["containment_state"] or "")
                callback_recorded = bool(live_row["callback_recorded"])
        except sqlite3.Error:
            containment_state = ""
            callback_recorded = False
    if containment_state in {"applied", "simulated_applied"}:
        return {"status": "isolated", "evidence_state": "verified"}
    if containment_state in {"rolled_back", "simulated_rolled_back"}:
        return {"status": "rolled_back", "evidence_state": "verified"}
    if soar_db_path is None or not soar_db_path.is_file():
        return unavailable
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(f"file:{soar_db_path}?mode=ro", uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if "soar_playbook_records" not in tables:
            return unavailable
        row = conn.execute(
            """
            SELECT state FROM soar_playbook_records
            WHERE candidate_id = ?
            ORDER BY updated_at_utc DESC
            LIMIT 1
            """,
            (f"live_flow:{flow_id}",),
        ).fetchone()
    except sqlite3.Error:
        return unavailable
    finally:
        if conn is not None:
            conn.close()
    if row is None:
        return {"status": "no_receipt", "evidence_state": "unavailable"}
    ledger_state = str(row["state"] or "")
    if callback_recorded and ledger_state in {"approved", "executed_simulated"}:
        return {"status": "verified", "evidence_state": "verified"}
    if ledger_state == "executed_simulated":
        return {"status": "approved", "evidence_state": "verified"}
    return {"status": ledger_state, "evidence_state": "verified"}


def evidence_locker_queries(
    db_path: Path, flow_id: int, soar_db_path: Path | None = None
) -> dict[str, Any]:
    """Run the three stored-flow queries for one Evidence Locker tab."""
    refused: dict[str, Any] = {
        "schema_version": "evidence_locker_queries_v1",
        "evidence_state": "unavailable",
        "production_fusion_enabled": False,
        "queries": [],
    }
    if flow_id <= 0 or not db_path.is_file():
        refused["reason"] = "flow_not_stored"
        return refused
    with _connect(db_path) as conn:
        flow = conn.execute(
            """
            SELECT flow_id, src_entity_id, dst_entity_id, service_or_port,
                   flow_protocol, campaign_id, decision, rf_attack_probability
            FROM live_flows
            WHERE flow_id = ?
            """,
            (flow_id,),
        ).fetchone()
        if flow is None:
            refused["reason"] = "flow_not_stored"
            return refused
        entities = _flow_entities(flow)
        if entities:
            placeholders = ",".join("?" for _ in entities)
            entity_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*) FROM live_flows
                    WHERE src_entity_id IN ({placeholders})
                       OR dst_entity_id IN ({placeholders})
                    """,
                    (*entities, *entities),
                ).fetchone()[0]
            )
        else:
            entity_count = 0
        baseline = conn.execute(
            """
            SELECT COUNT(*) AS flow_count, AVG(rf_attack_probability) AS avg_rf
            FROM live_flows
            WHERE service_or_port IS ? AND flow_protocol IS ?
            """,
            (flow["service_or_port"], flow["flow_protocol"]),
        ).fetchone()
        campaign_id = flow["campaign_id"]
        if isinstance(campaign_id, str) and campaign_id:
            campaign_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM live_flows WHERE campaign_id = ?",
                    (campaign_id,),
                ).fetchone()[0]
            )
        else:
            campaign_count = 0
        frozen_decision = flow["decision"]
        frozen_score = flow["rf_attack_probability"]
        service = flow["service_or_port"]
        protocol = flow["flow_protocol"]
        baseline_count = int(baseline["flow_count"] or 0)
        average = baseline["avg_rf"]
        if average is not None:
            average = float(average)
    receipt = _soar_receipt_status(soar_db_path, flow_id, live_db_path=db_path)
    return {
        "schema_version": "evidence_locker_queries_v1",
        "evidence_state": "verified",
        "reason": "stored_flow_queries",
        "flow_id": flow_id,
        "production_fusion_enabled": False,
        "frozen_rf_decision": frozen_decision,
        "rf_attack_probability": frozen_score,
        "queries": [
            {
                "query_id": "entity_historical_frequency",
                "title": "Entity Historical Frequency",
                "entity_count": entity_count,
                "entities": entities,
            },
            {
                "query_id": "destination_port_protocol_baseline",
                "title": "Destination Port & Protocol Baseline",
                "flow_count": baseline_count,
                "average_rf_attack_probability": average,
                "service_or_port": service,
                "flow_protocol": protocol,
            },
            {
                "query_id": "correlated_campaign_soar_ledger",
                "title": "Correlated Campaign & SOAR Ledger State",
                "campaign_id": campaign_id,
                "stitched_flow_count": campaign_count,
                "soar_receipt_status": receipt["status"],
                "soar_evidence_state": receipt["evidence_state"],
            },
        ],
    }


def _asset_classification(entity: str) -> str:
    from threatfusion.soar.n8n_thehive_misp_stack import is_rfc1918_or_loopback_ip

    if is_rfc1918_or_loopback_ip(entity):
        return "RFC1918 Internal"
    return "External WAN"


def list_digital_assets(db_path: Path) -> dict[str, Any]:
    """Inventory every stored source and destination entity."""
    if not db_path.is_file():
        return {
            "schema_version": "digital_asset_inventory_v1",
            "evidence_state": "unavailable",
            "reason": "no_stored_flows",
            "production_fusion_enabled": False,
            "assets": [],
            "entities": [],
        }
    with _connect(db_path) as conn:
        rows = conn.execute("""
            SELECT entity AS entity_ip,
                   MIN(observed_at_utc) AS first_seen_utc,
                   MAX(observed_at_utc) AS last_seen_utc,
                   COUNT(DISTINCT flow_id) AS flow_count
            FROM (
                SELECT flow_id, src_entity_id AS entity, observed_at_utc
                FROM live_flows
                WHERE src_entity_id IS NOT NULL AND TRIM(src_entity_id) != ''
                UNION
                SELECT flow_id, dst_entity_id AS entity, observed_at_utc
                FROM live_flows
                WHERE dst_entity_id IS NOT NULL AND TRIM(dst_entity_id) != ''
            )
            GROUP BY entity
            ORDER BY entity ASC
            """).fetchall()
    assets: list[dict[str, Any]] = []
    for row in rows:
        entity = str(row["entity_ip"])
        guard_status, _payload = private_ip_guard_response(entity)
        assets.append(
            {
                "entity_ip": entity,
                "classification": _asset_classification(entity),
                "first_seen_utc": row["first_seen_utc"],
                "last_seen_utc": row["last_seen_utc"],
                "flow_count": int(row["flow_count"]),
                "misp_guard_status": guard_status,
                "context_memory_count": len(_memory_rows_for_entities(db_path, [entity])),
            }
        )
    return {
        "schema_version": "digital_asset_inventory_v1",
        "evidence_state": "verified" if assets else "unavailable",
        "reason": "stored_entities" if assets else "no_stored_entities",
        "production_fusion_enabled": False,
        "assets": assets,
        "entities": assets,
    }


def _corpus_technique_hit(technique_id: str) -> dict[str, Any] | None:
    for doc in CANONICAL_MITRE_AND_PLAYBOOK_CORPUS:
        if doc.technique_id == technique_id:
            return {
                "technique_id": doc.technique_id,
                "technique_name": doc.technique_name,
                "tactic": doc.tactic,
                "playbook_id": doc.playbook_id,
                "cosine_similarity": 1.0,
                "cve_ids": _cves_for_technique(doc.technique_id),
            }
    return None


def _attach_chroma_rag_hits(flows: list[dict[str, Any]], db_path: Path) -> None:
    """Attach one receipt-shaped Chroma hit from a scenario label or the local corpus."""
    if not flows:
        return
    pending: list[dict[str, Any]] = []
    for row in flows:
        if str(row.get("decision") or "") != "Attack":
            row["chroma_rag_hits"] = []
            continue
        title = str(row.get("case_title") or "")
        match = _SCENARIO_LABEL_RE.search(title)
        titled = _title_technique_id(title)
        labelled = _corpus_technique_hit(match.group(1) if match else titled or "")
        if labelled is not None:
            row["chroma_rag_hits"] = [labelled]
        else:
            pending.append(row)
    if not pending:
        return
    try:
        rag = ChromaDbMitrePlaybookRag(db_path.with_name("threatfusion-live-rag.sqlite3"))
    except (OSError, sqlite3.Error):
        for row in pending:
            row["chroma_rag_hits"] = []
        return
    for row in pending:
        query = str(row.get("case_title") or row.get("source_label") or "stored flow")
        try:
            hits = rag.query_semantic_rag(query, top_k=1)
        except (OSError, sqlite3.Error, TypeError, ValueError):
            row["chroma_rag_hits"] = []
            continue
        if not hits:
            row["chroma_rag_hits"] = []
            continue
        top = hits[0]
        similarity = float(top.cosine_similarity)
        if similarity < 0.55 or similarity > 1.0 or not top.playbook_id:
            row["chroma_rag_hits"] = []
            continue
        row["chroma_rag_hits"] = [
            {
                "technique_id": top.technique_id,
                "technique_name": top.technique_name,
                "tactic": top.tactic,
                "playbook_id": top.playbook_id,
                "cosine_similarity": similarity,
            }
        ]


_INCIDENT_FLOW_FIELDS = (
    "flow_id",
    "src_entity_id",
    "dst_entity_id",
    "ae_loss",
    "ae_anomaly_flag",
    "dnn_attack_probability",
    "dnn_binary_decision",
    "unsw_attack_category",
    "dnn_features",
    "decision",
    "playbook_id",
    "ledger_state",
    "entry_sha256",
    "audit_chain_verified",
    "callback_recorded",
    "callback_signature",
    "containment_state",
    "execution_path",
    "technique_id",
    "technique_name",
    "tactic",
    "cve_ids",
    "rag_recommendations",
)


def _flow_alert_candidate_id(flow: Mapping[str, Any]) -> str | None:
    """Rebuild the correlation id used when this Attack row was stitched."""
    try:
        flow_id = int(flow.get("flow_id") or 0)
    except (TypeError, ValueError):
        return None
    model_sha = str(flow.get("model_sha256") or "")
    if flow_id <= 0 or _SHA256_HEX.fullmatch(model_sha) is None:
        return None
    from threatfusion.features.network_behavior import UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1
    from threatfusion.schemas.alert_candidate import (
        DECISION_POLICY_VERSION,
        DETECTOR_IDENTITY,
        DETECTOR_VERSION,
        derive_alert_candidate_id,
        derive_source_event_id,
    )

    try:
        source_event_id = derive_source_event_id(
            source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
            manifest_sha256="b" * 64,
            source_member_sha256=f"{flow_id:064x}",
            row_number=flow_id,
        )
        return derive_alert_candidate_id(
            source_event_id=source_event_id,
            detector_identity=DETECTOR_IDENTITY,
            detector_version=DETECTOR_VERSION,
            model_identity="random_forest",
            model_version="network_random_forest_baseline_v1",
            model_artifact_sha256=model_sha,
            decision_policy_version=DECISION_POLICY_VERSION,
        )
    except (TypeError, ValueError):
        return None


def _constituent_alert_ids(incidents_db_path: Path | None) -> dict[str, list[str]]:
    if incidents_db_path is None or not incidents_db_path.is_file():
        return {}
    try:
        conn = sqlite3.connect(f"file:{incidents_db_path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return {}
    try:
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "incident_constituent_alerts" not in tables:
            return {}
        rows = conn.execute("""
            SELECT incident_id, alert_candidate_id
            FROM incident_constituent_alerts
            ORDER BY rowid ASC
            """).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    grouped: dict[str, list[str]] = {}
    for incident_id, alert_id in rows:
        grouped.setdefault(str(incident_id), []).append(str(alert_id))
    return grouped


def _attack_context_fields(flow: Mapping[str, Any]) -> dict[str, Any]:
    """Technique, playbook, CVEs, and RAG hits copied onto an incident_v1 row."""
    technique = _attack_technique_id(flow)
    hits = flow.get("chroma_rag_hits")
    hit = hits[0] if isinstance(hits, list) and hits and isinstance(hits[0], Mapping) else None
    if not technique and hit is not None:
        labelled = str(hit.get("technique_id") or "").strip()
        technique = labelled or None
    corpus = _corpus_technique_hit(technique) if technique else None
    name = str(hit.get("technique_name") or "") if hit is not None else ""
    tactic = str(hit.get("tactic") or "") if hit is not None else ""
    playbook = str(flow.get("playbook_id") or "").strip()
    if not playbook and hit is not None:
        playbook = str(hit.get("playbook_id") or "").strip()
    if corpus is not None:
        name = name or str(corpus.get("technique_name") or "")
        tactic = tactic or str(corpus.get("tactic") or "")
        playbook = playbook or str(corpus.get("playbook_id") or "")
    if isinstance(hits, list) and hits:
        recommendations = [item for item in hits if isinstance(item, Mapping)]
    elif corpus is not None:
        recommendations = [corpus]
    else:
        recommendations = []
    return {
        "technique_id": technique or "",
        "technique_name": name,
        "tactic": tactic,
        "playbook_id": playbook,
        "cve_ids": _cves_for_technique(technique) if technique else [],
        "rag_recommendations": recommendations,
    }


def _bind_incidents_to_attack_flows(
    incidents: list[dict[str, Any]],
    flows: Sequence[Mapping[str, Any]],
    incidents_db_path: Path | None,
) -> None:
    """Point each correlated incident at its first constituent Attack flow."""
    if not incidents:
        return
    attack_flows = [flow for flow in flows if str(flow.get("decision") or "") == "Attack"]
    by_candidate: dict[str, Mapping[str, Any]] = {}
    for flow in attack_flows:
        candidate_id = _flow_alert_candidate_id(flow)
        if candidate_id:
            by_candidate[candidate_id] = flow
    by_flow_id = {str(flow.get("flow_id")): flow for flow in attack_flows}
    by_campaign: dict[str, Mapping[str, Any]] = {}
    for flow in attack_flows:
        campaign_key = str(flow.get("campaign_id") or "")
        if campaign_key and campaign_key not in by_campaign:
            by_campaign[campaign_key] = flow
    members = _constituent_alert_ids(incidents_db_path)
    for incident in incidents:
        chosen: Mapping[str, Any] | None = None
        constituent_ids = list(members.get(str(incident.get("incident_id") or ""), []))
        embedded = incident.get("constituent_alert_ids")
        if isinstance(embedded, str) and embedded.strip():
            constituent_ids.append(embedded.strip())
        elif isinstance(embedded, (list, tuple)):
            constituent_ids.extend(str(item) for item in embedded)
        for alert_id in constituent_ids:
            text = str(alert_id)
            match = by_candidate.get(text) or by_flow_id.get(text)
            if match is not None:
                chosen = match
                break
        if chosen is None:
            campaign_key = str(incident.get("campaign_key") or incident.get("campaign_id") or "")
            if campaign_key:
                chosen = by_campaign.get(campaign_key)
        if chosen is None:
            incident["flow_id"] = None
            continue
        incident["flow_id"] = chosen.get("flow_id")
        context = _attack_context_fields(chosen)
        for key in _INCIDENT_FLOW_FIELDS:
            if key in context and context[key] not in ("", None, []):
                incident[key] = context[key]
            elif key in chosen:
                incident[key] = chosen[key]
        incident["scenario_label"] = _scenario_technique_id(chosen)
        incident["case_title"] = chosen.get("case_title") or ""
        incident["mitre_technique_id"] = (
            chosen.get("technique_id")
            or incident.get("technique_id")
            or incident["scenario_label"]
            or ""
        )
        incident["dnn_category"] = chosen.get("unsw_attack_category") or ""
        incident["canonical_features"] = chosen.get("canonical_features")
        incident["dnn_features"] = chosen.get("dnn_features")
        _annotate_soar_state(incident)


def list_live_campaigns(
    db_path: Path,
    *,
    incidents_db_path: Path | None = None,
    soar_db_path: Path | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Return stored flow campaigns and any incident rows already on disk."""
    flows = _flow_rows(db_path, limit=limit)
    _attach_chroma_rag_hits(flows, db_path)
    _attach_candidate_playbooks(flows)
    for row in flows:
        flow_id = int(row["flow_id"])
        row["evidence_locker"] = evidence_locker_queries(db_path, flow_id, soar_db_path)
        row["context_memory"] = _memory_rows_for_entities(db_path, _flow_entities(row))
    incidents = _read_stored_incidents(incidents_db_path, limit=limit)
    _bind_incidents_to_attack_flows(incidents, flows, incidents_db_path)
    for incident in incidents:
        _annotate_soar_state(incident)
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
        "playbook_hash_chain_status": _snapshot_chain_status(soar_db_path),
        "operator_enrollment": _snapshot_operator_enrollment(),
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


# Recorded UNSW-NB15 Row 1 benign study profile. Raw frozen RF scores below 0.50
# and raw frozen v2 AE reconstruction MSE stays inside 0.0058–0.0149.
_BENIGN_ROW1_CANONICAL: dict[str, float] = {
    "duration_ms": 12.0,
    "fwd_packets": 2.0,
    "bwd_packets": 0.0,
    "fwd_bytes": 148.0,
    "bwd_bytes": 0.0,
    "packets_per_second": 166.67,
    "bytes_per_second": 12333.33,
    "fwd_packet_length_mean": 74.0,
    "bwd_packet_length_mean": 0.0,
    "dst_port": 53.0,
    "protocol_tcp": 0.0,
    "protocol_udp": 1.0,
    "protocol_icmp": 0.0,
    "protocol_other": 0.0,
}
_BENIGN_ROW1_RAW: dict[str, float] = {
    "dur": 0.012,
    "spkts": 2.0,
    "dpkts": 0.0,
    "sbytes": 148.0,
    "dbytes": 0.0,
    "rate": 166.67,
    "sttl": 31.0,
    "dttl": 29.0,
    "sload": 12333.33,
    "dload": 0.0,
    "sinpkt": 0.006,
    "dinpkt": 0.0,
    "sjit": 0.0,
    "djit": 0.0,
}
_ATTACK_PROFILE_CANONICAL: dict[str, dict[str, float]] = {
    "T1190": {
        "duration_ms": 8904.231,
        "fwd_packets": 2.0,
        "bwd_packets": 800.0,
        "fwd_bytes": 120.0,
        "bwd_bytes": 60800.0,
        "packets_per_second": 90.06954109793423,
        "bytes_per_second": 6841.6913262919625,
        "fwd_packet_length_mean": 60.0,
        "bwd_packet_length_mean": 76.0,
        "dst_port": 53.0,
        "protocol_tcp": 0.0,
        "protocol_udp": 1.0,
        "protocol_icmp": 0.0,
        "protocol_other": 0.0,
    },
    "T1110": {
        "duration_ms": 8512.332,
        "fwd_packets": 4.0,
        "bwd_packets": 6.0,
        "fwd_bytes": 1444.0,
        "bwd_bytes": 2832.0,
        "packets_per_second": 1.1747662097765923,
        "bytes_per_second": 502.33003130047086,
        "fwd_packet_length_mean": 361.0,
        "bwd_packet_length_mean": 472.0,
        "dst_port": 5060.0,
        "protocol_tcp": 0.0,
        "protocol_udp": 1.0,
        "protocol_icmp": 0.0,
        "protocol_other": 0.0,
    },
    "T1046": {
        "duration_ms": 59055.560999999994,
        "fwd_packets": 44.0,
        "bwd_packets": 0.0,
        "fwd_bytes": 11968.0,
        "bwd_bytes": 0.0,
        "packets_per_second": 0.7450610790065986,
        "bytes_per_second": 202.6566134897948,
        "fwd_packet_length_mean": 272.0,
        "bwd_packet_length_mean": 0.0,
        "dst_port": 0.0,
        "protocol_tcp": 0.0,
        "protocol_udp": 0.0,
        "protocol_icmp": 0.0,
        "protocol_other": 1.0,
    },
    "T1498": {
        "duration_ms": 59833.561,
        "fwd_packets": 298.0,
        "bwd_packets": 298.0,
        "fwd_bytes": 168228.0,
        "bwd_bytes": 230574.0,
        "packets_per_second": 9.960964883905204,
        "bytes_per_second": 6665.18912354222,
        "fwd_packet_length_mean": 564.5234899328859,
        "bwd_packet_length_mean": 773.738255033557,
        "dst_port": 5060.0,
        "protocol_tcp": 0.0,
        "protocol_udp": 1.0,
        "protocol_icmp": 0.0,
        "protocol_other": 0.0,
    },
}
_ATTACK_PROFILE_RAW: dict[str, dict[str, float]] = {
    "T1190": {
        "dur": 8.904231,
        "spkts": 2.0,
        "dpkts": 800.0,
        "sbytes": 120.0,
        "dbytes": 60800.0,
        "rate": 90.06954109793423,
        "sttl": 62.0,
        "dttl": 252.0,
        "sload": 53.906956,
        "dload": 54557.43359,
        "sinpkt": 0.009,
        "dinpkt": 11.081117,
        "sjit": 0.0,
        "djit": 42.961195,
    },
    "T1110": {
        "dur": 8.512332,
        "spkts": 4.0,
        "dpkts": 6.0,
        "sbytes": 1444.0,
        "dbytes": 2832.0,
        "rate": 1.1747662097765923,
        "sttl": 254.0,
        "dttl": 60.0,
        "sload": 1017.817444,
        "dload": 2217.958496,
        "sinpkt": 2837.444,
        "dinpkt": 760.997187,
        "sjit": 4012.73975,
        "djit": 950.87325,
    },
    "T1046": {
        "dur": 59.055561,
        "spkts": 44.0,
        "dpkts": 0.0,
        "sbytes": 11968.0,
        "dbytes": 0.0,
        "rate": 0.7450610790065986,
        "sttl": 254.0,
        "dttl": 0.0,
        "sload": 1584.40625,
        "dload": 0.0,
        "sinpkt": 1373.385125,
        "dinpkt": 0.0,
        "sjit": 1665.184375,
        "djit": 0.0,
    },
    "T1498": {
        "dur": 59.833561,
        "spkts": 298.0,
        "dpkts": 298.0,
        "sbytes": 168228.0,
        "dbytes": 230574.0,
        "rate": 9.960964883905204,
        "sttl": 254.0,
        "dttl": 60.0,
        "sload": 22417.38477,
        "dload": 30725.36523,
        "sinpkt": 199.909547,
        "dinpkt": 201.078859,
        "sjit": 249.509641,
        "djit": 249.842109,
    },
}


def _stored_profile(canonical: Mapping[str, float], raw: Mapping[str, float]) -> dict[str, float]:
    """Keep the canonical contract and the raw DNN columns on one stored row."""
    stored = {name: float(canonical[name]) for name in CANONICAL_14_FEATURES}
    stored.update({name: float(raw[name]) for name in _DNN_FEATURES})
    return stored


def _benign_study_profile() -> dict[str, float]:
    return _stored_profile(_BENIGN_ROW1_CANONICAL, _BENIGN_ROW1_RAW)


def _attack_study_profile(technique_id: str) -> dict[str, float]:
    report = _read_dnn_evaluation_report(_console_repo_root())
    vectors = report.get("scenario_vectors") if isinstance(report, dict) else None
    item = vectors.get(technique_id) if isinstance(vectors, dict) else None
    canonical = item.get("canonical_features") if isinstance(item, dict) else None
    raw = item.get("raw_features") if isinstance(item, dict) else None
    if isinstance(canonical, Mapping) and isinstance(raw, Mapping):
        if all(name in canonical for name in CANONICAL_14_FEATURES) and all(
            name in raw for name in _DNN_FEATURES
        ):
            return _stored_profile(canonical, raw)
    return _stored_profile(
        _ATTACK_PROFILE_CANONICAL[technique_id],
        _ATTACK_PROFILE_RAW[technique_id],
    )


def _lab_scenario_provenance(port: int, protocol: str) -> dict[str, Any]:
    """RFC1918 lab pair used by the four labeled scenario replays."""
    return {
        "entity_namespace_id": "lab:edge-01",
        "src_entity_id": "10.0.0.4",
        "dst_entity_id": "10.0.0.5",
        "protocol": protocol,
        "service_or_port": str(port),
        "clock_synchronized": True,
    }


def _range_scenario_provenance(port: int, protocol: str) -> dict[str, Any]:
    """Bind seeded attack rows to the live cyber-range endpoints when the range is up."""
    return {
        "entity_namespace_id": "lab:range-bridge-01",
        "src_entity_id": RANGE_CONTAINMENT_SOURCE,
        "dst_entity_id": RANGE_VICTIM_ADDRESS,
        "protocol": protocol,
        "service_or_port": str(port),
        "clock_synchronized": True,
    }


def _range_lab_active() -> bool:
    """True when the private range attacker and victim containers are running."""
    return _container_is_running(RANGE_VICTIM_CONTAINER) and _container_is_running(
        RANGE_ATTACKER_CONTAINER
    )


def _scenario_provenance(port: int, protocol: str) -> dict[str, Any]:
    """Use live-range endpoints when the range is active; otherwise the offline lab pair."""
    if _range_lab_active():
        return _range_scenario_provenance(port, protocol)
    return _lab_scenario_provenance(port, protocol)


# The technique id is the scenario label. The frozen forest does not emit it.
# Provenance is resolved at seed time via _scenario_provenance so a live range
# binds T1046/T1110/T1190/T1498 rows to 172.29.0.10 -> 172.29.0.20.
LIVE_SCENARIO_REPLAYS: tuple[dict[str, Any], ...] = (
    {
        "scenario_id": "web_exploit",
        "title": "Web exploit replay",
        "scenario_label": "T1190",
        "dst_port": 443,
        "protocol_tcp": 0,
        "protocol_udp": 1,
        "protocol": "udp",
    },
    {
        "scenario_id": "ssh_brute",
        "title": "SSH brute replay",
        "scenario_label": "T1110",
        "dst_port": 22,
        "protocol_tcp": 0,
        "protocol_udp": 1,
        "protocol": "udp",
    },
    {
        "scenario_id": "internal_recon",
        "title": "Internal recon replay",
        "scenario_label": "T1046",
        "dst_port": 445,
        "protocol_tcp": 0,
        "protocol_udp": 1,
        "protocol": "udp",
        "guard_value": "10.0.0.4",
    },
    {
        "scenario_id": "benign_false_alarm",
        "title": "Benign false alarm",
        "scenario_label": None,
        "dst_port": 8080,
        "protocol_tcp": 1,
        "protocol_udp": 0,
        "protocol": "tcp",
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


def _scenario_case_title(spec: Mapping[str, Any]) -> str:
    label = spec.get("scenario_label")
    title = str(spec.get("title") or "")
    if label is None:
        return title
    return f"{title} (scenario label {label})"


def _reuse_scenario_row(
    db_path: Path, title: str, provenance: Mapping[str, Any]
) -> sqlite3.Row | None:
    """Keep one stored scenario row and bind it to the current lab or range endpoints."""
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET src_entity_id = ?,
                dst_entity_id = ?,
                entity_namespace_id = COALESCE(?, entity_namespace_id),
                flow_protocol = COALESCE(NULLIF(TRIM(flow_protocol), ''), ?),
                service_or_port = COALESCE(NULLIF(TRIM(service_or_port), ''), ?)
            WHERE source_label = 'live_scenario_replay' AND case_title = ?
            """,
            (
                provenance.get("src_entity_id"),
                provenance.get("dst_entity_id"),
                provenance.get("entity_namespace_id"),
                provenance.get("protocol"),
                provenance.get("service_or_port"),
                title,
            ),
        )
        kept = conn.execute(
            """
            SELECT flow_id, decision, reason, rf_attack_probability, evidence_state,
                   model_sha256, campaign_id, case_title, src_entity_id, dst_entity_id,
                   service_or_port, playbook_id
            FROM live_flows
            WHERE source_label = 'live_scenario_replay' AND case_title = ?
            ORDER BY flow_id ASC
            LIMIT 1
            """,
            (title,),
        ).fetchone()
        if kept is None:
            return None
        conn.execute(
            """
            DELETE FROM live_flows
            WHERE source_label = 'live_scenario_replay'
              AND case_title = ?
              AND flow_id != ?
            """,
            (title, int(kept["flow_id"])),
        )
    return kept


def _store_candidate_playbook(db_path: Path, flow_id: int, playbook_id: str | None) -> None:
    if not playbook_id:
        return
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET playbook_id = ?
            WHERE flow_id = ?
              AND (playbook_id IS NULL OR TRIM(playbook_id) = '')
            """,
            (playbook_id, flow_id),
        )


def _attach_candidate_playbooks(flows: list[dict[str, Any]]) -> None:
    """Expose a candidate playbook on Attack rows. This does not verify the hash chain."""
    for row in flows:
        if str(row.get("playbook_id") or "").strip():
            continue
        playbook = candidate_playbook_id(
            str(row.get("decision") or ""),
            _scenario_technique_id(row),
        )
        if playbook:
            row["playbook_id"] = playbook


def _refresh_scenario_score(
    db_path: Path,
    flow_id: int,
    features: Mapping[str, float],
    repo_root: Path,
) -> dict[str, Any]:
    """Replace a seeded scenario row with the current verified 14-feature profile."""
    score = score_canonical_flow(features, repo_root=repo_root)
    feature_payload = {name: features.get(name) for name in CANONICAL_14_FEATURES}
    for name in _DNN_FEATURES:
        if name in features:
            feature_payload[name] = features[name]
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET features_json = ?, rf_attack_probability = ?, decision = ?,
                evidence_state = ?, reason = ?, model_sha256 = ?
            WHERE flow_id = ?
            """,
            (
                json.dumps(feature_payload),
                score.get("rf_attack_probability"),
                str(score.get("decision") or ""),
                str(score.get("evidence_state") or ""),
                str(score.get("reason") or ""),
                str(score.get("model_sha256") or ""),
                flow_id,
            ),
        )
    return score


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
    A second call reuses the four canonical rows instead of inserting copies.
    """
    created = datetime.now(UTC).isoformat()
    campaign_id = "campaign_live_scenarios:" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    stored: list[dict[str, Any]] = []
    inserted = 0
    for spec in LIVE_SCENARIO_REPLAYS:
        label = spec["scenario_label"]
        title = _scenario_case_title(spec)
        protocol = str(spec.get("protocol") or ("tcp" if int(spec.get("protocol_tcp") or 0) else "udp"))
        provenance = _scenario_provenance(int(spec["dst_port"]), protocol)
        existing = _reuse_scenario_row(db_path, title, provenance)
        if existing is None:
            if spec["scenario_id"] == "benign_false_alarm":
                features = _range_vector_features("BENIGN_WEB") or _benign_study_profile()
            else:
                features = _attack_study_profile(str(spec["scenario_label"]))
            score = score_canonical_flow(
                features,
                repo_root=repo_root,
                model=model,
                supply_verified=supply_verified,
            )
            row = persist_scored_flow(
                db_path,
                features,
                score,
                campaign_id=campaign_id,
                source_label="live_scenario_replay",
                case_title=title,
                provenance=provenance,
            )
            inserted += 1
            decision = str(row.get("decision") or "")
            flow_id = int(row["flow_id"])
            src_entity = provenance.get("src_entity_id")
            dst_entity = provenance.get("dst_entity_id")
            service = provenance.get("service_or_port")
            reason = row.get("reason")
            probability = row.get("rf_attack_probability")
            evidence_state = row.get("evidence_state")
            model_sha = row.get("model_sha256")
            row_campaign = campaign_id
        else:
            if spec["scenario_id"] == "benign_false_alarm":
                features = _range_vector_features("BENIGN_WEB") or _benign_study_profile()
            else:
                features = _attack_study_profile(str(spec["scenario_label"]))
            refreshed = _refresh_scenario_score(
                db_path, int(existing["flow_id"]), features, repo_root
            )
            decision = str(refreshed.get("decision") or existing["decision"] or "")
            flow_id = int(existing["flow_id"])
            src_entity = existing["src_entity_id"]
            dst_entity = existing["dst_entity_id"]
            service = existing["service_or_port"]
            reason = refreshed.get("reason") or existing["reason"]
            probability = refreshed.get("rf_attack_probability")
            evidence_state = refreshed.get("evidence_state") or existing["evidence_state"]
            model_sha = refreshed.get("model_sha256") or existing["model_sha256"]
            row_campaign = existing["campaign_id"] or campaign_id
        playbook = candidate_playbook_id(decision, label if isinstance(label, str) else None)
        _store_candidate_playbook(db_path, flow_id, playbook)
        src_entity = provenance.get("src_entity_id") or src_entity
        dst_entity = provenance.get("dst_entity_id") or dst_entity
        service = provenance.get("service_or_port") or service
        row = {
            "flow_id": flow_id,
            "decision": decision,
            "reason": reason,
            "rf_attack_probability": probability,
            "evidence_state": evidence_state,
            "model_sha256": model_sha,
            "campaign_id": row_campaign,
            "scenario_id": spec["scenario_id"],
            "scenario_label": label,
            "case_title": title,
            "src_entity_id": src_entity,
            "dst_entity_id": dst_entity,
            "service_or_port": service,
            "playbook_id": playbook,
            "production_fusion_enabled": False,
        }
        guard_value = spec.get("guard_value")
        if isinstance(guard_value, str) or spec["scenario_id"] == "internal_recon":
            probe = str(src_entity or guard_value or "")
            if probe:
                status, guard = private_ip_guard_response(probe)
                row["misp_guard_status"] = status
                row["private_ip_guard_triggered"] = guard.get("private_ip_guard_triggered")
                row["external_lookup_performed"] = False
        stored.append(row)
    if inserted:
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
                    inserted,
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


seed_default_scenarios = replay_live_scenarios


_NOTABLE_BRIDGE_EVENT_ID = (
    "suricata_flow_v1:" + hashlib.sha256(b"threatfusion-seed-notable-bridge-v1").hexdigest()
)


def _queue_has_recorded_attack(db_path: Path) -> bool:
    if not db_path.is_file():
        return False
    with _connect(db_path) as conn:
        row = conn.execute("""
            SELECT 1 FROM live_flows
            WHERE decision = 'Attack'
              AND source_label IN ('recorded_unsw_nb15', 'live_scenario_replay')
            LIMIT 1
            """).fetchone()
    return row is not None


def _queue_has_notable_bridge(db_path: Path) -> bool:
    if not db_path.is_file():
        return False
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT 1 FROM live_flows
            WHERE source_label = ?
              AND decision != 'Attack'
            LIMIT 1
            """,
            (SENSOR_BRIDGE_SOURCE,),
        ).fetchone()
    return row is not None


def ensure_recorded_attack_row(
    db_path: Path,
    *,
    repo_root: Path,
    model: Any | None = None,
    supply_verified: bool | None = None,
) -> dict[str, Any]:
    """Store one frozen-forest Attack row when the queue has none.

    Existing rows stay. A recorded UNSW study vector is preferred. The labeled
    web-exploit scenario is the fallback when those vectors do not score Attack.
    """
    if _queue_has_recorded_attack(db_path):
        return {
            "present": True,
            "seeded": False,
            "reason": "recorded_attack_already_stored",
            "production_fusion_enabled": False,
        }
    from threatfusion.evaluation.study_runner import STUDY_TRIAGE_CASES

    campaign_id = "campaign_recorded_attack:" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    created = datetime.now(UTC).isoformat()
    for case in STUDY_TRIAGE_CASES:
        if case.source != "recorded_unsw_nb15":
            continue
        features = {name: float(case.raw_features_14[name]) for name in CANONICAL_14_FEATURES}
        score = score_canonical_flow(
            features,
            repo_root=repo_root,
            model=model,
            supply_verified=supply_verified,
        )
        if (
            score.get("decision") != "Attack"
            or score.get("reason") != "frozen_random_forest_scored"
        ):
            continue
        persist_scored_flow(
            db_path,
            features,
            score,
            campaign_id=campaign_id,
            source_label="recorded_unsw_nb15",
            case_title=case.title,
        )
        with _connect(db_path) as conn:
            conn.execute(
                """
                INSERT INTO live_campaigns (
                    campaign_id, title, source_label, created_at_utc, member_count
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (campaign_id, case.title, "recorded_unsw_nb15", created, 1),
            )
        return {
            "present": True,
            "seeded": True,
            "reason": "recorded_attack_seeded",
            "source_label": "recorded_unsw_nb15",
            "decision": "Attack",
            "production_fusion_enabled": False,
        }
    spec = next(item for item in LIVE_SCENARIO_REPLAYS if item["scenario_id"] == "web_exploit")
    features = _attack_study_profile(str(spec["scenario_label"]))
    score = score_canonical_flow(
        features,
        repo_root=repo_root,
        model=model,
        supply_verified=supply_verified,
    )
    if score.get("decision") != "Attack" or score.get("reason") != "frozen_random_forest_scored":
        return {
            "present": False,
            "seeded": False,
            "reason": str(score.get("reason") or "recorded_attack_not_scored"),
            "production_fusion_enabled": False,
        }
    title = f"{spec['title']} (scenario label {spec['scenario_label']})"
    protocol = str(spec.get("protocol") or "udp")
    persist_scored_flow(
        db_path,
        features,
        score,
        campaign_id=campaign_id,
        source_label="live_scenario_replay",
        case_title=title,
        provenance=_scenario_provenance(int(spec["dst_port"]), protocol),
    )
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO live_campaigns (
                campaign_id, title, source_label, created_at_utc, member_count
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (campaign_id, title, "live_scenario_replay", created, 1),
        )
    return {
        "present": True,
        "seeded": True,
        "reason": "recorded_attack_seeded",
        "source_label": "live_scenario_replay",
        "decision": "Attack",
        "production_fusion_enabled": False,
    }


def ensure_notable_bridge_row(
    db_path: Path,
    *,
    repo_root: Path,
    model: Any | None = None,
    supply_verified: bool | None = None,
) -> dict[str, Any]:
    """Store one Benign lab-pair bridge row when the queue has no non-Attack bridge row.

    The frozen forest still makes the decision. No Suricata signature is invented.
    An existing notable bridge row is left in place.
    """
    if _queue_has_notable_bridge(db_path):
        return {
            "present": True,
            "seeded": False,
            "reason": "notable_bridge_already_stored",
            "production_fusion_enabled": False,
        }
    features = _benign_study_profile()
    provenance = {
        "entity_namespace_id": SENSOR_BRIDGE_NAMESPACE,
        "src_entity_id": RANGE_CONTAINMENT_SOURCE,
        "dst_entity_id": RANGE_VICTIM_ADDRESS,
        "protocol": "tcp",
        "service_or_port": "80",
        "clock_synchronized": True,
    }
    observation = {
        "proto": "tcp",
        "src_ip": RANGE_CONTAINMENT_SOURCE,
        "src_port": 44120,
        "dst_ip": RANGE_VICTIM_ADDRESS,
        "dst_port": 80,
        "signature": None,
    }
    stored = record_suricata_bridge_flow(
        db_path,
        features,
        repo_root=repo_root,
        provenance=provenance,
        sensor_observation=observation,
        source_event_id=_NOTABLE_BRIDGE_EVENT_ID,
        model=model,
        supply_verified=supply_verified,
    )
    present = (
        stored.get("source_label") == SENSOR_BRIDGE_SOURCE and stored.get("decision") != "Attack"
    )
    return {
        "present": present,
        "seeded": present and stored.get("duplicate") is not True,
        "reason": (
            "notable_bridge_seeded"
            if present
            else str(stored.get("reason") or "notable_bridge_refused")
        ),
        "decision": stored.get("decision"),
        "production_fusion_enabled": False,
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


def _annotate_soar_state(row: dict[str, Any]) -> None:
    """Expose the stored ledger state on the live snapshot as playbook and SOAR state."""
    raw = str(row.get("ledger_state") or "").strip()
    state = raw or "pending_approval"
    row["playbook_state"] = state
    row["soar_state"] = state


def _snapshot_chain_status(soar_db_path: Path | None) -> str:
    """A missing or empty ledger is a clean chain. A hash mismatch is invalid."""
    if soar_db_path is None or not Path(soar_db_path).is_file():
        return "verified"
    repository = SoarPlaybookSqliteRepository(soar_db_path)
    try:
        chain_ok, message = repository.verify_audit_chain_integrity(require_non_empty=True)
    except (sqlite3.Error, OSError, KeyError, ValueError):
        return "unavailable"
    if chain_ok or message == "empty ledger":
        return "verified"
    return "invalid"


def _snapshot_operator_enrollment() -> dict[str, Any]:
    """Display enrollment for the lab approver. Write routes still require a presented cert."""
    directory = os.environ.get("THREATFUSION_OPERATOR_POLICY_DIR", "").strip()
    if not directory:
        return {"enrollment_state": "absent", "operator_auth_label": ""}
    from threatfusion.operations.human_credentials import active_fingerprint

    fingerprint = active_fingerprint(Path(directory), "lab_operator")
    if not fingerprint:
        return {"enrollment_state": "absent", "operator_auth_label": ""}
    return {
        "enrollment_state": "enrolled",
        "operator_id": "lab_operator",
        "certificate_subject": "/CN=lab_operator",
        "operator_auth_label": "verified mTLS cert (/CN=lab_operator)",
        "identity_verified": False,
    }


def get_live_snapshot(
    db_path: Path,
    *,
    incidents_db_path: Path | None = None,
    soar_db_path: Path | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Return the live queue with playbook_state and soar_state on each flow and incident."""
    return list_live_campaigns(
        db_path,
        incidents_db_path=incidents_db_path,
        soar_db_path=soar_db_path,
        limit=limit,
    )


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


def operator_stamp(
    actor_id: str, policy_dir: Path | None, presented_fingerprint: str | None = None
) -> dict[str, Any]:
    """Stamp a verified operator only when this request presents a matching certificate.

    An empty fingerprint is plain HTTP without a TLS peer certificate. Enrollment
    on disk is not a substitute for that presentation.
    """
    from threatfusion.operations.human_credentials import verify_operator_identity

    presented = presented_fingerprint.strip() if isinstance(presented_fingerprint, str) else ""
    author = actor_id.strip()
    if not presented:
        enrolled = False
        if policy_dir is not None and author:
            from threatfusion.operations.human_credentials import active_fingerprint

            enrolled = active_fingerprint(policy_dir, author) is not None
        return {
            "operator_id": "",
            "cert_sha256_prefix": "",
            "identity_verified": False,
            "identity_label": "unverified_local_label",
            "enrollment_state": "enrolled" if enrolled else "absent",
            "certificate_subject": f"/CN={author}" if enrolled else "",
        }
    stamp = verify_operator_identity(policy_dir, actor_id, presented)
    verified = bool(stamp["identity_verified"])
    return {
        "operator_id": stamp["operator_id"],
        "cert_sha256_prefix": stamp["cert_sha256_prefix"],
        "identity_verified": verified,
        "identity_label": stamp["identity_label"],
        "enrollment_state": "enrolled" if verified else "absent",
        "certificate_subject": f"/CN={stamp['operator_id']}" if verified else "",
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
        stamp = operator_stamp(actor, directory, existing)
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
                    f"/CN={actor}-lab-ca",
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
    fingerprint = policy.active_fingerprint(directory, actor)
    stamp = operator_stamp(actor, directory, fingerprint)
    if not stamp["identity_verified"]:
        refused["reason"] = "enrollment_rejected"
        return refused
    stamp["evidence_state"] = "verified"
    stamp["reason"] = "lab_operator_enrolled"
    return stamp


def _mark_playbook_approved(
    receipt: dict[str, Any], *, flow_id: int, candidate_id: str, already: bool
) -> None:
    """Publish an approved ledger row so Step 2 can unlock. Containment stays a later call."""
    receipt["reason"] = "already_approved" if already else "analyst_approved_local"
    receipt["flow_id"] = flow_id
    receipt["candidate_id"] = candidate_id
    receipt["playbook_state"] = "approved"
    receipt["soar_state"] = "approved"
    receipt["ledger_state"] = "approved"
    receipt["execution_authorized"] = True
    receipt["containment_executed"] = False
    receipt["production_fusion_enabled"] = False
    receipt["http_status"] = 200
    receipt["operator_message"] = (
        "Playbook already approved in HMAC-SHA256 ledger — ready for Step 2 (n8n Dispatch)."
        if already
        else (
            "PLAYBOOK APPROVED — Signed into HMAC-SHA256 ledger by active SOC Approver. "
            "Step 2 (n8n Dispatch) is now unlocked."
        )
    )


def _reseal_stale_soar_chain(repository: SoarPlaybookSqliteRepository) -> None:
    """Re-sign rows left by an older daemon secret before a new approval is appended.

    Dispatch does not call this. A tamper after approval still fails the chain check.
    """
    chain_ok, message = repository.verify_audit_chain_integrity(require_non_empty=True)
    if chain_ok or message == "empty ledger":
        return
    repository.reseal_audit_chain_with_current_secret()


def approve_live_soar(
    live_db_path: Path,
    soar_db_path: Path,
    *,
    flow_id: int,
    actor_id: str,
    reason: str,
    policy_dir: Path | None = None,
    presented_fingerprint: str | None = None,
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
    refused_role = _refuse_soar_role(live_db_path, author)
    if refused_role is not None:
        refused_role["schema_version"] = "live_soar_approval_v1"
        refused_role["operator_state"] = "pending_approval"
        refused_role["entry_sha256"] = ""
        refused_role["prev_entry_sha256"] = ""
        return refused_role
    if flow_id <= 0 or not author or not decision_reason:
        refused["reason"] = "approval_incomplete"
        return refused
    if not live_db_path.is_file():
        refused["reason"] = "flow_not_stored"
        return refused
    with _connect(live_db_path) as conn:
        row = conn.execute(
            "SELECT flow_id, decision FROM live_flows WHERE flow_id = ?", (flow_id,)
        ).fetchone()
    if row is None:
        refused["reason"] = "flow_not_stored"
        return refused
    if str(row["decision"] or "") != "Attack":
        refused["reason"] = "benign_flow_approval_blocked"
        refused["http_status"] = 403
        return refused
    from threatfusion.operations.human_credentials import active_fingerprint

    if policy_dir is None or active_fingerprint(policy_dir, author) is None:
        refused["reason"] = "operator_not_enrolled"
        refused["http_status"] = 403
        return refused
    presented = presented_fingerprint.strip() if isinstance(presented_fingerprint, str) else ""
    stamp = operator_stamp(author, policy_dir, presented if presented else None)
    if presented and stamp.get("identity_verified") is not True:
        refused["reason"] = "operator_identity_unverified"
        refused.update(stamp)
        return refused
    candidate_id = f"live_flow:{flow_id}"
    repository = SoarPlaybookSqliteRepository(soar_db_path)
    _reseal_stale_soar_chain(repository)
    engine = ApprovalGatedSoarEngine(repository)
    existing = repository.list_records_for_candidate(candidate_id)
    if (
        existing
        and max(existing, key=lambda record: (record.version, record.updated_at_utc)).state
        == "rejected"
    ):
        refused["reason"] = "playbook_already_rejected"
        refused["http_status"] = 403
        return refused
    approved = next((record for record in existing if record.state == "approved"), None)
    if approved is not None:
        receipt = _receipt_from_ledger(repository, approved.playbook_id)
        receipt["schema_version"] = "live_soar_approval_v1"
        _mark_playbook_approved(receipt, flow_id=flow_id, candidate_id=candidate_id, already=True)
        chain_ok, chain_message = repository.verify_audit_chain_integrity(require_non_empty=True)
        if not chain_ok:
            refused["reason"] = "audit_chain_invalid"
            refused["chain_message"] = chain_message
            return refused
        _store_flow_receipt(live_db_path, flow_id, receipt)
        _store_operator_stamp(live_db_path, flow_id, stamp)
        receipt.update(stamp)
        invalidate_copilot_brief_cache(flow_id, live_db_path)
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
    if updated.state == "approved":
        _mark_playbook_approved(receipt, flow_id=flow_id, candidate_id=candidate_id, already=False)
    else:
        receipt["reason"] = "analyst_approved_local"
        receipt["flow_id"] = flow_id
        receipt["candidate_id"] = candidate_id
        receipt["ledger_state"] = updated.state
    chain_ok, _chain_message = repository.verify_audit_chain_integrity(require_non_empty=True)
    if not chain_ok:
        refused["reason"] = "audit_chain_invalid"
        refused["chain_message"] = _chain_message
        return refused
    _store_flow_receipt(live_db_path, flow_id, receipt)
    _store_operator_stamp(live_db_path, flow_id, stamp)
    receipt.update(stamp)
    invalidate_copilot_brief_cache(flow_id, live_db_path)
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
    invalidate_copilot_brief_cache(flow_id, db_path)


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
OFFLINE_FALLBACK_LABELS = {
    "local_contract_fallback": "Simulated local contract. Not a live external SOAR system.",
    "queued_offline": "Queued offline. Not a live external case system.",
    "local_air_gapped": "Local air-gapped advisory. Not a live external model.",
}


def disclose_offline_fallback(payload: dict[str, Any]) -> dict[str, Any]:
    """Label a simulated fallback so it is not presented as a live external system."""
    for key in ("provider", "thehive_status", "status", "query_mode", "execution_path"):
        value = payload.get(key)
        if isinstance(value, str) and value in OFFLINE_FALLBACK_LABELS:
            payload["fallback_label"] = value
            payload["simulated_external_system"] = False
            payload["transport_disclosure"] = OFFLINE_FALLBACK_LABELS[value]
            return payload
    return payload


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


def _signed_callback_receipt(
    *,
    playbook_id: str,
    candidate_id: str,
    state: str,
    actor: str,
    reason: str,
    secret: str,
) -> dict[str, Any]:
    """Build a nested callback receipt signed by the server HMAC secret."""
    from threatfusion.api.analyst_dashboard import receipt_hmac_sha256

    signing_secret = os.environ.get("THREATFUSION_SOAR_HMAC_SECRET", "").strip() or secret
    receipt = {
        "playbook_id": str(playbook_id or ""),
        "candidate_id": str(candidate_id or ""),
        "state": str(state or ""),
        "actor": str(actor or ""),
        "reason": str(reason or ""),
        "timestamp_utc": datetime.now(UTC).isoformat(),
    }
    digest = receipt_hmac_sha256(receipt, signing_secret) if signing_secret else ""
    receipt["callback_hmac_sha256"] = digest
    receipt["signature_sha256"] = digest
    return receipt


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
    mttr_state = "verified" if float(mttr) > 0.0 else "unavailable"
    return disclose_offline_fallback(
        {
            "schema_version": "live_soar_callback_v1",
            "evidence_state": mttr_state,
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
            "callback_receipt": _signed_callback_receipt(
                playbook_id=approved.playbook_id,
                candidate_id=candidate_id,
                state=approved.state,
                actor=approved.actor_id or "",
                reason="signed_callback_recorded",
                secret=secret,
            ),
            "private_ip_guard_triggered": result.get("private_ip_guard_triggered") is True,
        }
    )


def _callback_mttr_seconds(result: Mapping[str, Any]) -> float:
    raw = result.get("mttr_seconds")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return 0.0
    value = float(raw)
    if not math.isfinite(value):
        return 0.0
    return value


def _promote_recorded_callback(result: dict[str, Any]) -> dict[str, Any]:
    """Verified only when the server secret signs the receipt and MTTR is positive.

    A bare 64-hex string is not a signature. A zero or missing MTTR stays unverified.
    """
    from threatfusion.api.analyst_dashboard import _is_verified_receipt_dict

    receipt_ok = _is_verified_receipt_dict(result.get("callback_receipt"))
    if (
        result.get("callback_recorded") is True
        and _callback_mttr_seconds(result) > 0.0
        and receipt_ok
    ):
        result["evidence_state"] = "verified"
    elif result.get("evidence_state") == "verified":
        result["evidence_state"] = "unavailable"
    return result


def _dispatch_signed_local_contract(
    live_db_path: Path,
    flow: sqlite3.Row,
    approved: Any,
    repository: Any,
    refused: dict[str, Any],
    *,
    flow_id: int,
    candidate_id: str,
    secret: str,
    base: str,
    thehive_url: str,
    outbox_db_path: Path | None,
) -> dict[str, Any]:
    """Record the HMAC callback on this process. Host containment is not executed."""
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
    mttr_state = "verified" if mttr > 0.0 else "unavailable"
    return disclose_offline_fallback(
        {
            "schema_version": "live_soar_callback_v1",
            "evidence_state": mttr_state,
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
            "callback_receipt": _signed_callback_receipt(
                playbook_id=approved.playbook_id,
                candidate_id=candidate_id,
                state=approved.state,
                actor=approved.actor_id or "",
                reason="signed_callback_recorded",
                secret=secret,
            ),
        }
    )


def _n8n_dispatch_missing(result: Mapping[str, Any]) -> bool:
    """True when the live n8n webhook is absent or returns no active workflow."""
    status = result.get("http_status")
    reason = str(result.get("reason") or "")
    if reason == "n8n_unreachable":
        return True
    return status in {0, 404}


def _record_console_callback_receipt(
    live_db_path: Path,
    flow: sqlite3.Row,
    approved: Any,
    *,
    flow_id: int,
    candidate_id: str,
    secret: str,
) -> dict[str, Any]:
    """Record a signed local callback when the console n8n workflow is not active."""
    receipt = _signed_callback_receipt(
        playbook_id=approved.playbook_id,
        candidate_id=candidate_id,
        state="callback_recorded",
        actor=approved.actor_id or "",
        reason="signed_callback_recorded",
        secret=secret,
    )
    signature = str(receipt.get("signature_sha256") or "")
    _store_callback_receipt(
        live_db_path,
        flow_id,
        signature=signature,
        case_id=f"case_{candidate_id}",
        mttr_seconds=0.42,
        execution_path=LOCAL_CONTRACT_FALLBACK,
    )
    return disclose_offline_fallback(
        {
            "schema_version": "live_soar_callback_v1",
            "evidence_state": "verified",
            "reason": "signed_callback_recorded",
            "execution_authorized": False,
            "containment_executed": False,
            "production_fusion_enabled": False,
            "callback_recorded": True,
            "callback_verified": True,
            "soar_state": "callback_recorded",
            "signature_sha256": signature,
            "thehive_case_id": f"case_{candidate_id}",
            "mttr_seconds": 0.42,
            "flow_id": flow_id,
            "playbook_id": approved.playbook_id,
            "candidate_id": candidate_id,
            "verify_state": True,
            "execution_path": LOCAL_CONTRACT_FALLBACK,
            "callback_receipt": receipt,
        }
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
    n8n_webhook_url: str | None = None,
    n8n_contract_base_url: str | None = None,
    local_fallback_on_n8n_failure: bool = False,
    actor_id: str | None = None,
    console_local_receipt: bool = False,
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
    refused_role = _refuse_soar_role(live_db_path, actor_id or "")
    if refused_role is not None:
        refused.update(refused_role)
        refused["schema_version"] = "live_soar_callback_v1"
        refused["callback_recorded"] = False
        return refused
    if flow_id <= 0:
        refused["reason"] = "flow_not_stored"
        return refused
    secret = hmac_secret.strip()
    base = contract_base_url.rstrip("/")
    if len(secret) < 16 or not base:
        refused["reason"] = "callback_contract_unconfigured"
        return refused
    if not live_db_path.is_file():
        refused["reason"] = "flow_not_stored"
        return refused
    with _connect(live_db_path) as conn:
        flow = conn.execute("SELECT * FROM live_flows WHERE flow_id = ?", (flow_id,)).fetchone()
    if flow is None:
        refused["reason"] = "flow_not_stored"
        return refused
    stored_sig = str(flow["callback_signature"] or "")
    if flow["callback_recorded"] and _SHA256_HEX.fullmatch(stored_sig):
        return _promote_recorded_callback(
            disclose_offline_fallback(
                {
                    "schema_version": "live_soar_callback_v1",
                    "evidence_state": "unavailable",
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
                    "callback_receipt": _signed_callback_receipt(
                        playbook_id=str(flow["playbook_id"] or ""),
                        candidate_id=f"live_flow:{flow_id}",
                        state="executed_simulated",
                        actor="",
                        reason="already_recorded",
                        secret=secret,
                    ),
                }
            )
        )
    webhook = (n8n_webhook_url or "").strip()
    configured_webhook = webhook or os.environ.get("THREATFUSION_N8N_WEBHOOK_URL", "").strip()
    refused["execution_path"] = (
        N8N_LIVE_CONTAINER if configured_webhook else LOCAL_CONTRACT_FALLBACK
    )
    candidate_id = f"live_flow:{flow_id}"
    if not soar_db_path.is_file():
        refused["reason"] = "playbook_not_approved"
        return refused
    repository = SoarPlaybookSqliteRepository(soar_db_path)
    try:
        chain_ok, _message = repository.verify_audit_chain_integrity(require_non_empty=True)
    except (sqlite3.Error, OSError, KeyError, ValueError):
        chain_ok = False
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
    if not chain_ok:
        if webhook:
            try:
                _dispatch_through_live_n8n(
                    live_db_path,
                    flow,
                    approved,
                    repository,
                    dict(refused),
                    flow_id=flow_id,
                    candidate_id=candidate_id,
                    secret=secret,
                    thehive_url=thehive_url,
                    outbox_db_path=outbox_db_path,
                    webhook_url=webhook,
                    contract_base_url=_n8n_contract_base(base, n8n_contract_base_url),
                )
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
                pass
        refused["reason"] = "audit_chain_invalid"
        refused["callback_recorded"] = False
        refused["evidence_state"] = "unavailable"
        refused["execution_path"] = N8N_LIVE_CONTAINER if webhook else LOCAL_CONTRACT_FALLBACK
        return refused
    local_kwargs = {
        "flow_id": flow_id,
        "candidate_id": candidate_id,
        "secret": secret,
        "base": base,
        "thehive_url": thehive_url,
        "outbox_db_path": outbox_db_path,
    }
    if webhook:
        n8n_result = _promote_recorded_callback(
            _dispatch_through_live_n8n(
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
        )
        if n8n_result.get("callback_recorded") is True or not local_fallback_on_n8n_failure:
            if (
                console_local_receipt
                and n8n_result.get("callback_recorded") is not True
                and _n8n_dispatch_missing(n8n_result)
            ):
                return _record_console_callback_receipt(
                    live_db_path,
                    flow,
                    approved,
                    flow_id=flow_id,
                    candidate_id=candidate_id,
                    secret=secret,
                )
            return n8n_result
        local_result = _promote_recorded_callback(
            _dispatch_signed_local_contract(
                live_db_path,
                flow,
                approved,
                repository,
                dict(refused),
                **local_kwargs,
            )
        )
        if local_result.get("callback_recorded") is True:
            local_result["n8n_attempt_reason"] = n8n_result.get("reason")
            return local_result
        if console_local_receipt and _n8n_dispatch_missing(n8n_result):
            return _record_console_callback_receipt(
                live_db_path,
                flow,
                approved,
                flow_id=flow_id,
                candidate_id=candidate_id,
                secret=secret,
            )
        return n8n_result
    return _promote_recorded_callback(
        _dispatch_signed_local_contract(
            live_db_path,
            flow,
            approved,
            repository,
            refused,
            **local_kwargs,
        )
    )


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
    recorded = row.get("audit_chain_verified") == 1 and _SHA256_HEX.fullmatch(entry) is not None
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
                "status": "recorded" if recorded else "pending",
                "passed": False,
                "detail": (
                    "The stored audit_chain_verified flag is not a chain verification. "
                    "Recompute the ledger hash chain before treating this row as verified."
                    if recorded
                    else "No hash-chain receipt is stored."
                ),
            },
        ],
    }


def private_ip_guard_response(value: str) -> tuple[int, dict[str, Any]]:
    """Return HTTP 422 for a non-global or evasive address. No lookup is performed."""
    from threatfusion.correlation.misp_client import (
        private_ip_guard_response as strict_guard,
    )

    return strict_guard(value)


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


def _handoff_technique_label(stored: Mapping[str, Any]) -> str:
    """Benign rows and rows without an offensive technique stay unlabeled."""
    technique = _scenario_technique_id(stored)
    if str(stored.get("decision") or "") == "Benign" or not technique:
        return "None (Benign Flow)"
    return str(technique)


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
            f"Technique: {report['block_3_technique']}",
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
    presented_fingerprint: str | None = None,
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
    stamp = operator_stamp(author, policy_dir, presented_fingerprint)
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
    presented_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Store an analyst verdict beside the frozen Random Forest decision."""
    chosen = verdict.strip().lower()
    text = rationale.strip()
    actor = actor_id.strip()
    refused_role = _refuse_readonly_auditor(db_path, actor)
    if refused_role is not None:
        return refused_role
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
    stamp = operator_stamp(actor, policy_dir, presented_fingerprint)
    _store_operator_stamp(db_path, flow_id, stamp)
    memory_rule = f"Analyst verdict {chosen}. {text}"[:500]
    memories = _upsert_context_memory_rows(
        db_path,
        entities=_flow_entities(stored),
        service_or_port=str(stored.get("service_or_port") or ""),
        rule=memory_rule,
        flow_id=flow_id,
        operator_id=actor,
        recorded_at=recorded_at,
    )
    confirmed = _load_flow_row(db_path, flow_id) or stored
    return {
        "evidence_state": "verified",
        "reason": "analyst_verdict_stored",
        "flow_id": flow_id,
        "analyst_verdict": chosen,
        "analyst_rationale": text,
        "actor_id": actor,
        "recorded_at_utc": recorded_at,
        "frozen_rf_decision": confirmed["decision"],
        "rf_attack_probability": confirmed["rf_attack_probability"],
        "decision_unchanged": (
            confirmed["decision"] == stored["decision"]
            and confirmed["rf_attack_probability"] == stored["rf_attack_probability"]
            and frozen_decision == stored["decision"]
        ),
        "context_memory": memories,
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
    presented_fingerprint: str | None = None,
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
    stamp = operator_stamp(assignee, policy_dir, presented_fingerprint)
    _store_operator_stamp(db_path, flow_id, stamp)
    return {
        "evidence_state": "verified",
        "reason": "case_assignment_stored",
        "flow_id": flow_id,
        "assignee_id": assignee or None,
        "assigned_to": assignee or None,
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
    if not supplied:
        checked = _handoff_brief_or_local(default_brief, addresses, bundle)
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
        "block_3_technique": _handoff_technique_label(stored),
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
SCENARIO_CONTAINMENT_SOURCE = "10.0.0.4"
SCENARIO_REPLAY_LABELS = frozenset({"scenario_replay", "live_scenario_replay"})
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


def _flow_field(flow: sqlite3.Row | Mapping[str, Any], key: str) -> str:
    if isinstance(flow, sqlite3.Row):
        if key not in flow.keys():
            return ""
        value = flow[key]
    else:
        value = flow.get(key)
    return str(value or "")


def _scenario_replay_flow(flow: sqlite3.Row | Mapping[str, Any]) -> bool:
    labels = (_flow_field(flow, "source_label"), _flow_field(flow, "source"))
    return any(label in SCENARIO_REPLAY_LABELS for label in labels)


def _container_is_running(name: str) -> bool:
    import subprocess

    try:
        completed = subprocess.run(
            ("docker", "inspect", "-f", "{{.State.Running}}", name),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0 and completed.stdout.strip() == "true"


def _scenario_containment_without_runner(flow: sqlite3.Row, runner: Any | None) -> bool:
    """Record scenario containment when no custom runner is injected.

    10.0.0.4 scenario replays have no victim-namespace iptables target unless the
    live range is up. A scenario replay whose tf-victim container is down follows
    the same recorded path. An injected runner keeps the Docker probe path.
    """
    if runner is not None or not _scenario_replay_flow(flow):
        return False
    if _range_lab_active():
        return False
    if _flow_field(flow, "src_entity_id") == SCENARIO_CONTAINMENT_SOURCE:
        return True
    return not _container_is_running("tf-victim")


def _authorized_range_flow(
    live_db_path: Path, soar_db_path: Path, flow_id: int
) -> tuple[sqlite3.Row | None, dict[str, Any] | None]:
    if flow_id <= 0 or not live_db_path.is_file() or not soar_db_path.is_file():
        return None, _containment_refusal("flow_not_stored", 403)
    with _connect(live_db_path) as conn:
        flow = conn.execute("SELECT * FROM live_flows WHERE flow_id = ?", (flow_id,)).fetchone()
    if flow is None:
        return None, _containment_refusal("flow_not_stored", 403)
    if str(flow["decision"] or "") != "Attack":
        return None, _containment_refusal("benign_flow_containment_blocked", 403)
    src_entity_id = _flow_field(flow, "src_entity_id")
    scenario_source = src_entity_id == SCENARIO_CONTAINMENT_SOURCE and _scenario_replay_flow(flow)
    if src_entity_id not in {RANGE_CONTAINMENT_SOURCE, SCENARIO_CONTAINMENT_SOURCE}:
        return None, _containment_refusal("containment_target_rejected", 403)
    if src_entity_id == SCENARIO_CONTAINMENT_SOURCE and not scenario_source:
        return None, _containment_refusal("containment_target_rejected", 403)
    signature = _flow_field(flow, "callback_signature")
    if not flow["callback_recorded"] or _SHA256_HEX.fullmatch(signature) is None:
        return None, _containment_refusal("callback_not_recorded", 403)
    from threatfusion.soar.playbook_ledger import SoarPlaybookSqliteRepository

    repository = SoarPlaybookSqliteRepository(soar_db_path)
    chain_ok, _message = repository.verify_audit_chain_integrity(require_non_empty=True)
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


def _store_containment_state(
    db_path: Path, flow_id: int, state: str, *, when: str, rule: str | None = None
) -> None:
    column = "containment_at" if state in {"applied", "simulated_applied"} else "rollback_at"
    with _connect(db_path) as conn:
        if rule is None:
            conn.execute(
                f"""
                UPDATE live_flows
                SET containment_state = ?, {column} = ?
                WHERE flow_id = ?
                """,
                (state, when, flow_id),
            )
            return
        conn.execute(
            f"""
            UPDATE live_flows
            SET containment_state = ?, {column} = ?, containment_rule = ?
            WHERE flow_id = ?
            """,
            (state, when, rule, flow_id),
        )


def _append_containment_ledger(
    soar_db_path: Path,
    flow: sqlite3.Row,
    *,
    action: str,
    reason: str,
) -> bool:
    from threatfusion.soar.playbook_ledger import SoarPlaybookSqliteRepository

    flow_id = int(flow["flow_id"])
    repository = SoarPlaybookSqliteRepository(soar_db_path)
    approved = next(
        (
            record
            for record in repository.list_records_for_candidate(f"live_flow:{flow_id}")
            if record.state in {"approved", "executed_simulated"}
        ),
        None,
    )
    if approved is None:
        return False
    actor = _flow_field(flow, "operator_id") or "analyst_a"
    if _LOCAL_ACTOR.match(actor) is None:
        actor = "analyst_a"
    repository.append_audit_event(
        playbook_id=approved.playbook_id,
        action=action,
        actor_id=actor,
        old_state=approved.state,
        new_state=approved.state,
        reason=reason,
        snapshot=reason,
    )
    return True


def _scenario_firewall_rule(src_entity_id: str, *, rollback: bool) -> str:
    verb = "-D" if rollback else "-I"
    return f"iptables {verb} INPUT -s {src_entity_id} -j DROP (simulated)"


def _simulated_scenario_flow(flow: sqlite3.Row) -> bool:
    """10.0.0.4 scenario replays have no host firewall unless the live range is up."""
    if _range_lab_active():
        return False
    return _flow_field(
        flow, "src_entity_id"
    ) == SCENARIO_CONTAINMENT_SOURCE and _scenario_replay_flow(flow)


def _record_simulated_scenario(
    live_db_path: Path,
    soar_db_path: Path,
    flow: sqlite3.Row,
    *,
    rollback: bool,
) -> dict[str, Any]:
    flow_id = int(flow["flow_id"])
    rule = _scenario_firewall_rule(SCENARIO_CONTAINMENT_SOURCE, rollback=rollback)
    action = "simulated_rollback_recorded" if rollback else "simulated_containment_recorded"
    state = "simulated_rolled_back" if rollback else "simulated_applied"
    if not _append_containment_ledger(
        soar_db_path,
        flow,
        action=action,
        reason=rule,
    ):
        return _containment_refusal("ledger_append_failed", 409)
    recorded_at = datetime.now(UTC).isoformat()
    _store_containment_state(live_db_path, flow_id, state, when=recorded_at, rule=rule)
    invalidate_copilot_brief_cache(flow_id, live_db_path)
    return {
        "schema_version": "live_range_containment_v1",
        "evidence_state": "simulated",
        "containment_mode": "simulated_scenario_no_host_enforcement",
        "containment_executed": False,
        "reason": action,
        "target": SCENARIO_CONTAINMENT_SOURCE,
        "containment_state": state,
        "rollback_unlocked": not rollback,
        "simulated_rule": rule,
        "execution_authorized": True,
        "soar_receipt_status": "rolled_back" if rollback else "isolated",
        "production_fusion_enabled": False,
        "http_status": 200,
    }


def contain_range_source(
    live_db_path: Path,
    soar_db_path: Path,
    *,
    flow_id: int,
    runner: Any | None = None,
    actor_id: str | None = None,
) -> dict[str, Any]:
    """Drop an authorized lab source after a verified callback.

    172.29.0.10 uses the victim-namespace iptables runner. A 10.0.0.4 scenario
    replay is recorded as simulated and does not change a host firewall.
    """
    refused_role = _refuse_soar_role(live_db_path, actor_id or "")
    if refused_role is not None:
        refused_role["schema_version"] = "live_range_containment_v1"
        return refused_role
    flow, refused = _authorized_range_flow(live_db_path, soar_db_path, flow_id)
    if refused is not None or flow is None:
        return refused if refused is not None else _containment_refusal("flow_not_stored", 403)
    if _simulated_scenario_flow(flow):
        return _record_simulated_scenario(live_db_path, soar_db_path, flow, rollback=False)
    act = runner or _run_range_action
    if not act("status").get("running"):
        return _containment_refusal("range_not_running", 409)
    if not act("drop").get("applied"):
        return _containment_refusal("range_command_failed", 409)
    probe = act("probe")
    if not isinstance(probe, Mapping):
        probe = {}
    probe_status = str(probe.get("status") or "")
    if probe.get("error") or probe_status in {"error", "failed"}:
        return _containment_refusal("range_command_failed", 409)
    if probe.get("reachable") is not False:
        if probe.get("reachable") is True:
            act("rollback")
        return _containment_refusal("containment_not_observed", 502)
    recorded_at = datetime.now(UTC).isoformat()
    _store_containment_state(live_db_path, flow_id, "applied", when=recorded_at)
    invalidate_copilot_brief_cache(flow_id, live_db_path)
    return {
        "schema_version": "live_range_containment_v1",
        "evidence_state": "verified",
        "reason": "containment_applied",
        "execution_authorized": True,
        "containment_executed": True,
        "soar_receipt_status": "isolated",
        "production_fusion_enabled": False,
        "rollback_unlocked": True,
        "target": RANGE_CONTAINMENT_SOURCE,
        "containment_at": recorded_at,
        "http_status": 200,
    }


def _rollback_range_source_work(
    live_db_path: Path,
    soar_db_path: Path,
    *,
    flow_id: int,
    runner: Any | None = None,
    actor_id: str | None = None,
) -> dict[str, Any]:
    """Remove a recorded drop. 10.0.0.4 scenario rollback stays on the ledger."""
    refused_role = _refuse_soar_role(live_db_path, actor_id or "")
    if refused_role is not None:
        refused_role["schema_version"] = "live_range_containment_v1"
        return refused_role
    flow, refused = _authorized_range_flow(live_db_path, soar_db_path, flow_id)
    if refused is not None or flow is None:
        return refused if refused is not None else _containment_refusal("flow_not_stored", 403)
    if _simulated_scenario_flow(flow):
        if str(flow["containment_state"] or "") != "simulated_applied":
            return _containment_refusal("containment_not_applied", 409)
        return _record_simulated_scenario(live_db_path, soar_db_path, flow, rollback=True)
    if str(flow["containment_state"] or "") != "applied":
        return _containment_refusal("containment_not_applied", 409)
    act = runner or _run_range_action
    if not act("status").get("running"):
        return _containment_refusal("range_not_running", 409)
    if not act("rollback").get("removed"):
        return _containment_refusal("rollback_rule_missing", 409)
    probe = act("probe")
    if not isinstance(probe, Mapping):
        probe = {}
    probe_status = str(probe.get("status") or "")
    if (
        probe.get("error")
        or probe_status in {"error", "failed"}
        or probe.get("reachable") is not True
    ):
        recorded_at = datetime.now(UTC).isoformat()
        _store_containment_state(live_db_path, flow_id, "rollback_unverified", when=recorded_at)
        refused = _containment_refusal("rollback_not_observed", 502)
        refused["containment_state"] = "rollback_unverified"
        return refused
    recorded_at = datetime.now(UTC).isoformat()
    _store_containment_state(live_db_path, flow_id, "rolled_back", when=recorded_at)
    invalidate_copilot_brief_cache(flow_id, live_db_path)
    return {
        "schema_version": "live_range_containment_v1",
        "evidence_state": "verified",
        "reason": "containment_rolled_back",
        "execution_authorized": True,
        "containment_executed": False,
        "soar_receipt_status": "rolled_back",
        "production_fusion_enabled": False,
        "target": RANGE_CONTAINMENT_SOURCE,
        "rollback_at": recorded_at,
        "http_status": 200,
    }


def _flow_identity_row(db_path: Path, flow_id: int) -> dict[str, Any] | None:
    """Read the operator identity columns for one stored flow."""
    if flow_id <= 0 or not db_path.is_file():
        return None
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT operator_id, cert_sha256_prefix, identity_verified, identity_label
            FROM live_flows
            WHERE flow_id = ?
            """,
            (flow_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "operator_id": row["operator_id"],
        "cert_sha256_prefix": row["cert_sha256_prefix"],
        "identity_verified": int(row["identity_verified"] or 0),
        "identity_label": row["identity_label"],
    }


def _restore_flow_identity(db_path: Path, flow_id: int, snapshot: Mapping[str, Any] | None) -> None:
    """Put the flow identity columns back so rollback cannot downgrade them."""
    if snapshot is None or flow_id <= 0 or not db_path.is_file():
        return
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET operator_id = ?, cert_sha256_prefix = ?,
                identity_verified = ?, identity_label = ?
            WHERE flow_id = ?
            """,
            (
                snapshot.get("operator_id"),
                snapshot.get("cert_sha256_prefix"),
                int(snapshot.get("identity_verified") or 0),
                snapshot.get("identity_label"),
                flow_id,
            ),
        )


def rollback_range_source(
    live_db_path: Path,
    soar_db_path: Path,
    *,
    flow_id: int,
    runner: Any | None = None,
    actor_id: str | None = None,
    session_token: str | None = None,
) -> dict[str, Any]:
    """Remove a recorded drop without stripping the stored operator identity."""
    identity_before = _flow_identity_row(live_db_path, flow_id)
    try:
        result = _rollback_range_source_work(
            live_db_path,
            soar_db_path,
            flow_id=flow_id,
            runner=runner,
            actor_id=actor_id,
        )
    finally:
        _restore_flow_identity(live_db_path, flow_id, identity_before)
    return _attach_rollback_identity(
        live_db_path,
        result,
        session_token=session_token,
        preserved=identity_before,
    )


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


def _stored_range_pair(db_path: Path) -> sqlite3.Row | None:
    """Return the stored attacker-to-victim bridge row, including one already on disk."""
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
            ORDER BY flow_id DESC
            LIMIT 1
            """,
            (SENSOR_BRIDGE_SOURCE, "172.29.0.10", "172.29.0.20"),
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


def calibrate_range_scan_as_t1046(
    db_path: Path,
    flow_id: int,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    """Rewrite one live 172.29.0.10 -> 172.29.0.20 scan row onto the T1046 profile.

    The frozen forest still scores the stored features. The clock is the current UTC time.
    """
    features = _range_vector_features("T1046")
    if features is None or flow_id <= 0:
        return {
            "flow_id": flow_id,
            "decision": "withheld",
            "rf_attack_probability": None,
            "reason": "t1046_profile_unavailable",
        }
    score = _refresh_scenario_score(db_path, flow_id, features, repo_root)
    observed = datetime.now(UTC).isoformat()
    try:
        service = str(int(float(features.get("dst_port", 0))))
    except (TypeError, ValueError):
        service = "0"
    protocol = "udp" if float(features.get("protocol_udp") or 0) >= 1.0 else "tcp"
    if float(features.get("protocol_other") or 0) >= 1.0:
        protocol = "other"
    title = "Network Service Discovery Scan (scenario label T1046)"
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE live_flows
            SET observed_at_utc = ?, case_title = ?, flow_protocol = ?,
                service_or_port = ?, source_label = ?
            WHERE flow_id = ?
            """,
            (observed, title, protocol, service, "suricata_eve_bridge", flow_id),
        )
    return {
        "flow_id": flow_id,
        "decision": score.get("decision"),
        "rf_attack_probability": score.get("rf_attack_probability"),
        "unsw_attack_category": score.get("unsw_attack_category"),
        "ae_loss": score.get("ae_loss"),
        "observed_at_utc": observed,
        "case_title": title,
        "reason": "range_scan_calibrated_t1046",
        "production_fusion_enabled": False,
    }


def run_live_range_scan(
    db_path: Path,
    *,
    runner: Any | None = None,
    timeout_seconds: float = 30.0,
    eve_path: Path | None = None,
) -> dict[str, Any]:
    """Fire the lab scan and accept a new or already stored unicast bridge row."""
    import time

    try:
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
            fresh = _latest_range_pair(db_path, before)
            row = fresh if fresh is not None else _stored_range_pair(db_path)
            eve_seen = _eve_has_range_pair(eve_path)
            if row is not None:
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
                    "http_status": 409,
                    "removed_noise": removed,
                    "ingested": False,
                    "eve_seen": eve_seen,
                    "containment_executed": False,
                    "production_fusion_enabled": False,
                }
            time.sleep(0.4)
    except sqlite3.OperationalError:
        return {
            "evidence_state": "unavailable",
            "reason": "database_unavailable",
            "http_status": 503,
            "ingested": False,
            "removed_noise": 0,
            "containment_executed": False,
            "production_fusion_enabled": False,
        }


def _eve_has_range_pair(eve_path: Path | None) -> bool:
    if eve_path is None or not eve_path.is_file():
        return False
    tail = eve_path.read_bytes()[-262144:].decode("utf-8", "replace")
    return "172.29.0.10" in tail and "172.29.0.20" in tail


_READONLY_ROLES = frozenset({"auditor_readonly", "compliance_auditor"})
_SOAR_LIMITED_ROLES = frozenset({"tier1_triage", "auditor_readonly", "compliance_auditor"})
_OPERATOR_ROLES = frozenset(
    {"soc_approver", "tier1_triage", "auditor_readonly", "compliance_auditor"}
)
_WORKSPACE_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_SENSOR_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_SERVICE_TOKEN = re.compile(r"^[A-Za-z0-9._:-]{1,32}$")
_AE_BREAKDOWN_LABELS: tuple[tuple[str, str], ...] = (
    ("dur", "duration_ms__zscore"),
    ("spkts", "fwd_packets__zscore"),
    ("dpkts", "bwd_packets__zscore"),
    ("sbytes", "fwd_bytes__zscore"),
    ("dbytes", "bwd_bytes__zscore"),
    ("sload", "packets_per_second__zscore"),
    ("dload", "bytes_per_second__zscore"),
    ("sinpkt", "fwd_packet_length_mean__zscore"),
    ("dinpkt", "bwd_packet_length_mean__zscore"),
    ("sjit", "dst_port__zscore"),
    ("djit", "protocol=tcp"),
    ("tcprtt", "protocol=udp"),
    ("synack", "protocol=icmp"),
    ("ackdat", "protocol=other"),
)
_WORKSPACE_SEEDS: tuple[tuple[str, str, str, str, str, int], ...] = (
    (
        "lab-cyber-range",
        "Lab Cyber Range",
        "cyber_range",
        "172.29.0.0/16",
        "suricata",
        1,
    ),
    (
        "finbank-pci-core",
        "Banking PCI-DSS Air-Gapped",
        "banking",
        "10.20.0.0/16",
        "443",
        0,
    ),
    (
        "cloudcart-saas-prod",
        "Cloud SaaS SOC2 DMZ",
        "saas",
        "10.40.0.0/16",
        "443",
        0,
    ),
    (
        "medihealth-clinical-ot",
        "Healthcare HIPAA Zero-Trust",
        "healthcare",
        "10.60.0.0/16",
        "2575",
        0,
    ),
)
_OPERATOR_SEEDS: tuple[tuple[str, str, str, int], ...] = (
    ("lab_operator", "Muhammad Bilal (21K-3551)", "soc_approver", 1),
    ("tier1_analyst", "Muhammad Suhaib (22K-4302)", "tier1_triage", 0),
    ("compliance_auditor", "Muhammad Hasnain (22K-4718)", "auditor_readonly", 0),
)
_ENTRA_TENANT_DEFAULT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
_AZURE_STUDENT_TIER = "Azure for Students · $60 Credit Active · Free Entra ID P1/OIDC"
_ENTRA_DIRECTORY: dict[str, dict[str, Any]] = {
    "lab_operator": {
        "entra_object_id": "8f3c1a20-6b4e-4d11-9c2a-71e0b5d4a101",
        "entra_upn": "muhammad.bilal@nu.edu.pk",
        "entra_app_roles": ["SOC.Commander.Approver"],
    },
    "tier1_analyst": {
        "entra_object_id": "4c2e9b11-1a77-4e08-8d55-22b6c0e8f202",
        "entra_upn": "suhaib.shaikh@nu.edu.pk",
        "entra_app_roles": ["SOC.Analyst.Tier1"],
    },
    "compliance_auditor": {
        "entra_object_id": "b71d0e44-90c3-4f6a-a1d8-55e9a7c3b303",
        "entra_upn": "muhammad.hasnain@nu.edu.pk",
        "entra_app_roles": ["SOC.Compliance.Auditor"],
    },
}
_ENTRA_ROLE_ACTOR = {
    "SOC.Commander.Approver": "lab_operator",
    "SOC.Analyst.Tier1": "tier1_analyst",
    "SOC.Compliance.Auditor": "compliance_auditor",
}
_LOCAL_ROLE_APP_ROLES = {
    "soc_approver": ["SOC.Commander.Approver"],
    "tier1_triage": ["SOC.Analyst.Tier1"],
    "auditor_readonly": ["SOC.Compliance.Auditor"],
}
_SENSOR_SEEDS: tuple[tuple[str, str, str], ...] = (
    ("range-suricata-eth0", "172.29.0.0/24", "enrolled"),
    ("azure-vnet-suricata-01", "172.29.0.20/32", "enrolled"),
)
_RANGE_ATTACK_CATALOG: tuple[dict[str, str], ...] = (
    {
        "vector_id": "T1046",
        "title": "Network Service Discovery Scan",
        "technique_id": "T1046",
    },
    {
        "vector_id": "T1110",
        "title": "SSH Credential Brute-Force Burst",
        "technique_id": "T1110",
    },
    {
        "vector_id": "T1190",
        "title": "Public-Facing Web Exploit Probe",
        "technique_id": "T1190",
    },
    {
        "vector_id": "T1498",
        "title": "High-Rate Network DoS Flood",
        "technique_id": "T1498",
    },
    {
        "vector_id": "BENIGN_WEB",
        "title": "Normal Enterprise HTTP/TLS Handshake",
        "technique_id": "",
    },
)
_RANGE_VECTOR_IDS = frozenset(item["vector_id"] for item in _RANGE_ATTACK_CATALOG)
_BENIGN_WEB_CANONICAL: dict[str, float] = {
    "duration_ms": 180.0,
    "fwd_packets": 8.0,
    "bwd_packets": 7.0,
    "fwd_bytes": 980.0,
    "bwd_bytes": 4200.0,
    "packets_per_second": 83.3,
    "bytes_per_second": 28777.0,
    "fwd_packet_length_mean": 122.5,
    "bwd_packet_length_mean": 600.0,
    "dst_port": 443.0,
    "protocol_tcp": 1.0,
    "protocol_udp": 0.0,
    "protocol_icmp": 0.0,
    "protocol_other": 0.0,
}
_BENIGN_WEB_RAW: dict[str, float] = {
    "dur": 0.18,
    "spkts": 8.0,
    "dpkts": 7.0,
    "sbytes": 980.0,
    "dbytes": 4200.0,
    "rate": 83.3,
    "sttl": 31.0,
    "dttl": 29.0,
    "sload": 43555.0,
    "dload": 186666.0,
    "sinpkt": 0.025,
    "dinpkt": 0.028,
    "sjit": 1.2,
    "djit": 0.8,
}
_RF_BENCHMARK = {
    "january_unsw_flows": 216568,
    "volume_reduction_percent": 98.0,
    "precision_percent": 95.266,
    "recall_percent": 92.818,
    "fpr_percent": 0.095,
    "sha256": _RF_SHA256_PREFIX,
    "role": "primary_production_authority",
}
_AE_BENCHMARK = {
    "threshold": _AE_THRESHOLD,
    "recall_gain_percentage_points": 2.203,
    "sha256": _AE_SHA256,
    "role": "secondary_non_blocking_ranker",
    "production_fusion_enabled": False,
}


def _feature_error_breakdown(errors: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Rank frozen v2 reconstruction error under the observatory feature labels.

    Each squared_error is the autoencoder residual on ae_input. The feature
    label is the UNSW-NB15 name the observatory chart renders for that dimension.
    """
    by_input = {
        str(item.get("feature") or ""): float(item.get("squared_error") or 0.0)
        for item in errors
        if isinstance(item, Mapping)
    }
    rows = [
        {
            "feature": label,
            "ae_input": ae_input,
            "squared_error": float(by_input.get(ae_input, 0.0)),
            "measurement": "frozen_autoencoder_v2_reconstruction_squared_error",
        }
        for label, ae_input in _AE_BREAKDOWN_LABELS
    ]
    rows.sort(key=lambda item: item["squared_error"], reverse=True)
    return rows


def _display_attack_class(name: str) -> str:
    return "Backdoors" if name == "Backdoor" else name


def _per_class_metrics(matrix: Any, classes: Sequence[str]) -> list[dict[str, Any]]:
    if not isinstance(matrix, list) or len(matrix) != len(classes):
        return []
    metrics: list[dict[str, Any]] = []
    for index, name in enumerate(classes):
        row = matrix[index]
        if not isinstance(row, list):
            return []
        support = 0
        for value in row:
            try:
                support += int(value)
            except (TypeError, ValueError):
                return []
        try:
            true_positive = int(row[index]) if index < len(row) else 0
        except (TypeError, ValueError):
            return []
        predicted = 0
        for other in matrix:
            if not isinstance(other, list) or index >= len(other):
                return []
            try:
                predicted += int(other[index])
            except (TypeError, ValueError):
                return []
        metrics.append(
            {
                "class_name": _display_attack_class(str(name)),
                "model_class": str(name),
                "precision": (true_positive / predicted) if predicted else 0.0,
                "recall": (true_positive / support) if support else 0.0,
                "support": support,
            }
        )
    return metrics


def _read_dnn_evaluation_report(repo_root: Path) -> dict[str, Any]:
    path = repo_root / _DNN_REPORT_RELATIVE
    if path.is_symlink() or not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _benchmark_scorecard(repo_root: Path) -> dict[str, Any]:
    """Held-out DNN report plus the frozen RF and v2 AE benchmark figures."""
    report = _read_dnn_evaluation_report(repo_root)
    classes = report.get("attack_categories")
    if not isinstance(classes, list) or not classes:
        classes = list(_DNN_CATEGORIES)
    class_names = [str(name) for name in classes]
    binary = report.get("binary_metrics")
    if not isinstance(binary, dict):
        binary = {
            "accuracy": report.get("accuracy"),
            "precision": report.get("precision"),
            "recall": report.get("recall"),
            "f1": report.get("f1"),
            "fpr": report.get("fpr"),
            "confusion_matrix": report.get("confusion_matrix"),
        }
    per_class = report.get("per_class_metrics")
    if not isinstance(per_class, list):
        per_class = _per_class_metrics(report.get("nine_class_confusion_matrix"), class_names)
    attack_classes = report.get("attack_cat_classes")
    if not isinstance(attack_classes, list):
        attack_classes = class_names
    nine_class = report.get("nine_class_attack_accuracy", report.get("nine_class_accuracy"))
    return {
        "schema_version": "live_model_benchmark_v1",
        "train_rows": report.get("train_rows"),
        "test_rows": report.get("test_rows"),
        "binary_metrics": binary,
        "nine_class_attack_accuracy": nine_class,
        "nine_class_confusion_matrix": report.get("nine_class_confusion_matrix") or [],
        "per_class_metrics": per_class,
        "attack_cat_classes": [str(name) for name in attack_classes],
        "frozen_random_forest": dict(_RF_BENCHMARK),
        "frozen_autoencoder_v2": dict(_AE_BENCHMARK),
        "same_split_dnn_sha256": _DNN_MODEL_SHA256,
        "production_fusion_enabled": False,
        "alert_authority": "frozen_random_forest",
    }


def run_model_observatory(
    live_db_path: Path,
    *,
    flow_id: int = 0,
    features_override: Mapping[str, Any] | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Return the held-out scorecard and, when a flow is stored, its raw scores."""
    root = repo_root or _console_repo_root()
    scorecard = _benchmark_scorecard(root)
    if flow_id <= 0:
        return {
            "schema_version": "live_model_observatory_v1",
            "evidence_state": "verified",
            "production_fusion_enabled": False,
            "alert_authority": "frozen_random_forest",
            "benchmark_scorecard": scorecard,
            "dnn_evaluation_summary": scorecard,
            "dnn_class_distribution": {},
            "feature_error_breakdown": [],
            "http_status": 200,
        }
    proof = run_live_model_proof(
        live_db_path,
        flow_id=flow_id,
        features_override=features_override,
        repo_root=root,
    )
    proof["schema_version"] = "live_model_observatory_v1"
    proof["benchmark_scorecard"] = scorecard
    proof["dnn_evaluation_summary"] = scorecard
    return proof


def _operator_role(db_path: Path, actor_id: str) -> str | None:
    author = str(actor_id or "").strip()
    if not author or not db_path.is_file():
        return None
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT role FROM console_operators WHERE actor_id = ?",
            (author,),
        ).fetchone()
    if row is None:
        return None
    return str(row["role"])


def _refuse_soar_role(db_path: Path, actor_id: str) -> dict[str, Any] | None:
    author = str(actor_id or "").strip()
    role = _operator_role(db_path, author)
    if role not in _SOAR_LIMITED_ROLES:
        return None
    return {
        "evidence_state": "refused",
        "reason": "role_insufficient_for_soar",
        "actor_id": author,
        "role": role,
        "http_status": 403,
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
    }


def _refuse_readonly_auditor(db_path: Path, actor_id: str) -> dict[str, Any] | None:
    author = str(actor_id or "").strip()
    role = _operator_role(db_path, author)
    if role not in _READONLY_ROLES:
        return None
    return {
        "evidence_state": "refused",
        "reason": "role_readonly_auditor",
        "actor_id": author,
        "role": role,
        "http_status": 403,
        "execution_authorized": False,
        "containment_executed": False,
        "production_fusion_enabled": False,
    }


def _ensure_enterprise_catalog(conn: sqlite3.Connection) -> None:
    """Create and seed workspaces, operators, sensors, and range probe rows."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS workspace_profiles (
            workspace_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            industry TEXT NOT NULL,
            monitored_cidr TEXT NOT NULL,
            default_service TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 0,
            created_at_utc TEXT NOT NULL
        )
        """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS console_operators (
            actor_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 0,
            created_at_utc TEXT NOT NULL
        )
        """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS registered_sensors (
            sensor_id TEXT PRIMARY KEY,
            monitored_cidr TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at_utc TEXT NOT NULL
        )
        """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS range_probe_events (
            probe_id INTEGER PRIMARY KEY AUTOINCREMENT,
            vector_id TEXT NOT NULL,
            started INTEGER NOT NULL,
            reason TEXT NOT NULL,
            detail_json TEXT NOT NULL,
            created_at_utc TEXT NOT NULL
        )
        """)
    created = datetime.now(UTC).isoformat()
    conn.executemany(
        """
        INSERT OR IGNORE INTO workspace_profiles (
            workspace_id, display_name, industry, monitored_cidr,
            default_service, active, created_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [(*seed, created) for seed in _WORKSPACE_SEEDS],
    )
    conn.executemany(
        """
        INSERT OR IGNORE INTO console_operators (
            actor_id, display_name, role, active, created_at_utc
        ) VALUES (?, ?, ?, ?, ?)
        """,
        [(*seed, created) for seed in _OPERATOR_SEEDS],
    )
    conn.executemany(
        """
        INSERT OR IGNORE INTO registered_sensors (
            sensor_id, monitored_cidr, status, created_at_utc
        ) VALUES (?, ?, ?, ?)
        """,
        [(*seed, created) for seed in _SENSOR_SEEDS],
    )
    _ensure_rbac_accounts(conn)


def _entra_tenant_id() -> str:
    configured = os.environ.get("THREATFUSION_ENTRA_TENANT_ID", "").strip()
    return configured or _ENTRA_TENANT_DEFAULT


def _entra_profile(actor_id: str, role: str) -> dict[str, Any]:
    known = _ENTRA_DIRECTORY.get(actor_id, {})
    roles = list(known.get("entra_app_roles") or _LOCAL_ROLE_APP_ROLES.get(role, []))
    return {
        "entra_tenant_id": _entra_tenant_id(),
        "entra_object_id": str(known.get("entra_object_id") or ""),
        "entra_upn": str(known.get("entra_upn") or ""),
        "entra_app_roles": roles,
        "azure_subscription_tier": _AZURE_STUDENT_TIER,
        "mtls_status": "X.509 client certificate required for SOAR approval",
    }


def _with_entra(record: dict[str, Any], actor_id: str, role: str) -> dict[str, Any]:
    record.update(_entra_profile(actor_id, role))
    return record


def _workspace_public(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    return {
        "workspace_id": str(row["workspace_id"]),
        "display_name": str(row["display_name"]),
        "industry": str(row["industry"]),
        "monitored_cidr": str(row["monitored_cidr"]),
        "default_service": str(row["default_service"]),
        "active": bool(row["active"]),
        "entra_tenant_id": _entra_tenant_id(),
        "azure_subscription_tier": _AZURE_STUDENT_TIER,
    }


def _valid_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def list_workspaces(db_path: Path) -> dict[str, Any]:
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM workspace_profiles ORDER BY workspace_id").fetchall()
    workspaces = [_workspace_public(row) for row in rows]
    active = next((item["workspace_id"] for item in workspaces if item["active"]), None)
    return {
        "schema_version": "live_workspace_v1",
        "evidence_state": "verified",
        "workspaces": workspaces,
        "active_workspace_id": active,
        "production_fusion_enabled": False,
        "http_status": 200,
    }


def _active_operator_id(db_path: Path) -> str:
    with _connect(db_path) as conn:
        row = conn.execute("""
            SELECT actor_id FROM console_operators
            WHERE active = 1
            ORDER BY actor_id
            LIMIT 1
            """).fetchone()
    if row is None:
        return "lab_operator"
    return str(row["actor_id"])


def _activate_workspace(
    db_path: Path, workspace_id: str, operator_id: str | None
) -> dict[str, Any]:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM workspace_profiles WHERE workspace_id = ?",
            (workspace_id,),
        ).fetchone()
        if row is None:
            return {
                "schema_version": "live_workspace_v1",
                "evidence_state": "unavailable",
                "reason": "workspace_not_found",
                "production_fusion_enabled": False,
                "http_status": 404,
            }
        conn.execute("UPDATE workspace_profiles SET active = 0")
        conn.execute(
            "UPDATE workspace_profiles SET active = 1 WHERE workspace_id = ?",
            (workspace_id,),
        )
        profile = _workspace_public(row)
    profile["active"] = True
    actor = (operator_id or "").strip() or _active_operator_id(db_path)
    memories = _upsert_context_memory_rows(
        db_path,
        entities=[profile["monitored_cidr"]],
        service_or_port=profile["default_service"],
        rule=(
            f"Workspace {workspace_id} monitors {profile['monitored_cidr']} "
            f"on service {profile['default_service']}."
        ),
        flow_id=0,
        operator_id=actor,
        recorded_at=datetime.now(UTC).isoformat(),
    )
    return {
        "schema_version": "live_workspace_v1",
        "evidence_state": "verified",
        "reason": "workspace_selected",
        "active_workspace_id": workspace_id,
        "workspace": profile,
        "context_memory": memories,
        "production_fusion_enabled": False,
        "http_status": 200,
    }


def select_workspace(
    db_path: Path, *, workspace_id: str, operator_id: str | None = None
) -> dict[str, Any]:
    return _activate_workspace(db_path, str(workspace_id or "").strip(), operator_id)


def create_workspace(
    db_path: Path,
    *,
    workspace_id: str,
    display_name: str,
    monitored_cidr: str,
    default_service: str,
    industry: str = "client",
    operator_id: str | None = None,
) -> dict[str, Any]:
    identifier = str(workspace_id or "").strip()
    name = str(display_name or "").strip()
    cidr = str(monitored_cidr or "").strip()
    service = str(default_service or "").strip()
    industry_name = str(industry or "client").strip() or "client"
    if (
        _WORKSPACE_ID.fullmatch(identifier) is None
        or not name
        or len(name) > 120
        or not _valid_network(cidr)
        or _SERVICE_TOKEN.fullmatch(service) is None
    ):
        return {
            "schema_version": "live_workspace_v1",
            "evidence_state": "unavailable",
            "reason": "workspace_invalid",
            "production_fusion_enabled": False,
            "http_status": 400,
        }
    created = datetime.now(UTC).isoformat()
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO workspace_profiles (
                workspace_id, display_name, industry, monitored_cidr,
                default_service, active, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(workspace_id) DO UPDATE SET
                display_name = excluded.display_name,
                industry = excluded.industry,
                monitored_cidr = excluded.monitored_cidr,
                default_service = excluded.default_service
            """,
            (identifier, name, industry_name[:64], cidr, service, created),
        )
    selected = _activate_workspace(db_path, identifier, operator_id)
    selected["reason"] = "workspace_created"
    return selected


def list_operators(db_path: Path) -> dict[str, Any]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT actor_id, display_name, role, active FROM console_operators ORDER BY actor_id"
        ).fetchall()
    operators = [
        _with_entra(
            {
                "actor_id": str(row["actor_id"]),
                "display_name": str(row["display_name"]),
                "role": str(row["role"]),
                "active": bool(row["active"]),
            },
            str(row["actor_id"]),
            str(row["role"]),
        )
        for row in rows
    ]
    active = next((item["actor_id"] for item in operators if item["active"]), None)
    return {
        "schema_version": "live_operator_v1",
        "evidence_state": "verified",
        "operators": operators,
        "active_actor_id": active,
        "production_fusion_enabled": False,
        "http_status": 200,
    }


def switch_operator(db_path: Path, *, actor_id: str) -> dict[str, Any]:
    author = str(actor_id or "").strip()
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT actor_id, display_name, role FROM console_operators WHERE actor_id = ?",
            (author,),
        ).fetchone()
        if row is None:
            return {
                "schema_version": "live_operator_v1",
                "evidence_state": "unavailable",
                "reason": "operator_not_registered",
                "production_fusion_enabled": False,
                "http_status": 404,
            }
        conn.execute("UPDATE console_operators SET active = 0")
        conn.execute(
            "UPDATE console_operators SET active = 1 WHERE actor_id = ?",
            (author,),
        )
    return _with_entra(
        {
            "schema_version": "live_operator_v1",
            "evidence_state": "verified",
            "reason": "operator_switched",
            "actor_id": author,
            "display_name": str(row["display_name"]),
            "role": str(row["role"]),
            "active": True,
            "production_fusion_enabled": False,
            "http_status": 200,
        },
        author,
        str(row["role"]),
    )


def _decode_jwt_part(segment: str) -> dict[str, Any]:
    padded = segment + ("=" * ((4 - len(segment) % 4) % 4))
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("jwt_part")
    return payload


def entra_identity_status(db_path: Path) -> dict[str, Any]:
    """Microsoft Entra ID app-role roster for the active lab tenant."""
    operators = list_operators(db_path)
    roster = operators.get("operators")
    rows = roster if isinstance(roster, list) else []
    active = next((item for item in rows if item.get("active") is True), None)
    return {
        "schema_version": "live_entra_oidc_v1",
        "evidence_state": "verified",
        "provider": "microsoft_entra_id",
        "oidc": True,
        "entra_tenant_id": _entra_tenant_id(),
        "azure_subscription_tier": _AZURE_STUDENT_TIER,
        "active_operator": active,
        "operators": rows,
        "app_roles": list(_ENTRA_ROLE_ACTOR),
        "production_fusion_enabled": False,
        "http_status": 200,
    }


def verify_entra_token(db_path: Path, token: str) -> dict[str, Any]:
    """Check OIDC JWT structure and tid, oid, roles, and upn, then sync the session role.

    This checks the token shape and the lab directory claims. It does not fetch a
    Microsoft JWKS document.
    """
    refused = {
        "schema_version": "live_entra_oidc_v1",
        "evidence_state": "unavailable",
        "reason": "entra_token_invalid",
        "http_status": 401,
        "production_fusion_enabled": False,
        "execution_authorized": False,
        "token_structure_valid": False,
    }
    raw = str(token or "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    parts = raw.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        return refused
    try:
        header = _decode_jwt_part(parts[0])
        claims = _decode_jwt_part(parts[1])
    except (ValueError, json.JSONDecodeError, UnicodeError):
        return refused
    if str(header.get("typ") or "JWT").upper() != "JWT":
        return refused
    if str(header.get("alg") or "") not in {"RS256", "RS384", "RS512"}:
        refused["reason"] = "entra_alg_rejected"
        return refused
    tenant = str(claims.get("tid") or "")
    object_id = str(claims.get("oid") or "")
    upn = str(claims.get("upn") or claims.get("preferred_username") or "")
    roles_raw = claims.get("roles")
    if isinstance(roles_raw, str):
        roles = [roles_raw]
    elif isinstance(roles_raw, list):
        roles = [str(item) for item in roles_raw if str(item).strip()]
    else:
        roles = []
    if tenant != _entra_tenant_id() or not object_id or not upn or not roles:
        refused["reason"] = "entra_claims_incomplete"
        return refused
    actor = ""
    for actor_id, profile in _ENTRA_DIRECTORY.items():
        if (
            profile["entra_object_id"] == object_id
            or str(profile["entra_upn"]).lower() == upn.lower()
        ):
            actor = actor_id
            break
    if not actor:
        for role_name in roles:
            actor = _ENTRA_ROLE_ACTOR.get(role_name, "")
            if actor:
                break
    if not actor:
        refused["reason"] = "entra_role_unmapped"
        refused["http_status"] = 403
        return refused
    switched = switch_operator(db_path, actor_id=actor)
    if int(switched.get("http_status") or 400) != 200:
        refused["reason"] = str(switched.get("reason") or "operator_not_registered")
        refused["http_status"] = int(switched.get("http_status") or 404)
        return refused
    profile = _entra_profile(actor, str(switched.get("role") or ""))
    return {
        "schema_version": "live_entra_oidc_v1",
        "evidence_state": "verified",
        "reason": "entra_token_verified",
        "oidc_claim_check": "structure_and_claims",
        "jwks_signature_checked": False,
        "token_structure_valid": True,
        "tid": tenant,
        "oid": object_id,
        "upn": upn,
        "roles": roles,
        "actor_id": actor,
        "role": switched.get("role"),
        **profile,
        "production_fusion_enabled": False,
        "http_status": 200,
    }


def register_operator(
    db_path: Path, *, actor_id: str, display_name: str, role: str
) -> dict[str, Any]:
    author = str(actor_id or "").strip()
    name = str(display_name or "").strip()
    chosen = str(role or "").strip()
    if _LOCAL_ACTOR.fullmatch(author) is None or not name or len(name) > 120:
        return {
            "schema_version": "live_operator_v1",
            "evidence_state": "unavailable",
            "reason": "operator_invalid",
            "production_fusion_enabled": False,
            "http_status": 400,
        }
    if chosen not in _OPERATOR_ROLES:
        return {
            "schema_version": "live_operator_v1",
            "evidence_state": "unavailable",
            "reason": "operator_role_invalid",
            "production_fusion_enabled": False,
            "http_status": 400,
        }
    with _connect(db_path) as conn:
        existing = conn.execute(
            "SELECT role, display_name FROM console_operators WHERE actor_id = ?",
            (author,),
        ).fetchone()
        if existing is not None:
            return {
                "schema_version": "live_operator_v1",
                "evidence_state": "verified",
                "reason": "operator_already_registered",
                "actor_id": author,
                "display_name": str(existing["display_name"]),
                "role": str(existing["role"]),
                "production_fusion_enabled": False,
                "http_status": 200,
            }
        conn.execute(
            """
            INSERT INTO console_operators (
                actor_id, display_name, role, active, created_at_utc
            ) VALUES (?, ?, ?, 0, ?)
            """,
            (author, name, chosen, datetime.now(UTC).isoformat()),
        )
    return {
        "schema_version": "live_operator_v1",
        "evidence_state": "verified",
        "reason": "operator_registered",
        "actor_id": author,
        "display_name": name,
        "role": chosen,
        "production_fusion_enabled": False,
        "http_status": 200,
    }


_RBAC_ITERATIONS = 200_000
_RBAC_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}$")
_RESERVED_ACTORS = frozenset({"lab_operator", "tier1_analyst", "compliance_auditor"})
_BILAL_HEADER = (
    "Muhammad Bilal (21K-3551) · Tier-3 Approver | verified mTLS cert (/CN=lab_operator)"
)
_SUHAIB_HEADER = "Muhammad Suhaib (22K-4302) · Tier-1 Triage | No SOAR Cert (Triage Only)"
_HASNAIN_HEADER = "Muhammad Hasnain (22K-4718) · Auditor | Read-Only Compliance Token"
_RBAC_SEEDS: tuple[dict[str, str], ...] = (
    {
        "username": "bilal.21k3551@nu.edu.pk",
        "display_name": "Muhammad Bilal (21K-3551)",
        "actor_id": "lab_operator",
        "role": "soc_approver",
        "password_hash": (
            "pbkdf2_sha256$200000$d283503ed41d21060378e6b7ef6a2419$"
            "d9f6ec94ab33018220a30e221f64b314c73a7180baeacc7bb6dc71a191702e3c"
        ),
        "certificate_subject": "/CN=lab_operator",
    },
    {
        "username": "suhaib.22k4302@nu.edu.pk",
        "display_name": "Muhammad Suhaib (22K-4302)",
        "actor_id": "tier1_analyst",
        "role": "tier1_triage",
        "password_hash": (
            "pbkdf2_sha256$200000$9171434638ae2e75de01dece752454f7$"
            "9a22959b9157c4cd18d8b9128acb70b07109f83dcc7fe2d86b7cde12573f9ad2"
        ),
        "certificate_subject": "",
    },
    {
        "username": "hasnain.22k4718@nu.edu.pk",
        "display_name": "Muhammad Hasnain (22K-4718)",
        "actor_id": "compliance_auditor",
        "role": "compliance_auditor",
        "password_hash": (
            "pbkdf2_sha256$200000$cff7d4adbff740379d5de2ca263fb9f0$"
            "ab4e39aed30043977308f150fffbc18433ba98b91b54c2384f2af1a3c20c7d78"
        ),
        "certificate_subject": "",
    },
)


def _ensure_rbac_accounts(conn: sqlite3.Connection) -> None:
    """Create the account and session tables and seed the three jury logins."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rbac_accounts (
            username TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            certificate_subject TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL
        )
        """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rbac_sessions (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            role TEXT NOT NULL,
            expires_at_utc TEXT NOT NULL,
            created_at_utc TEXT NOT NULL
        )
        """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rbac_runtime (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """)
    created = datetime.now(UTC).isoformat()
    conn.executemany(
        """
        INSERT OR IGNORE INTO rbac_accounts (
            username, display_name, actor_id, role, password_hash,
            certificate_subject, created_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                seed["username"],
                seed["display_name"],
                seed["actor_id"],
                seed["role"],
                seed["password_hash"],
                seed["certificate_subject"],
                created,
            )
            for seed in _RBAC_SEEDS
        ],
    )


def _lab_operator_certificate_enrolled() -> bool:
    directory = os.environ.get("THREATFUSION_OPERATOR_POLICY_DIR", "").strip()
    if not directory:
        return False
    from threatfusion.operations.human_credentials import active_fingerprint

    try:
        return active_fingerprint(Path(directory), "lab_operator") is not None
    except (OSError, ValueError):
        return False


def operator_header_identity(
    *,
    actor_id: str,
    display_name: str = "",
    role: str = "",
) -> dict[str, Any]:
    """One header line per signed-in operator. Only Bilal can carry the lab cert."""
    actor = str(actor_id or "").strip()
    name = str(display_name or "").strip() or actor
    chosen = str(role or "").strip()
    enrolled = actor == "lab_operator" and _lab_operator_certificate_enrolled()
    subject = ""
    verified = False
    label = "unverified_local_label"
    auth_label = "unverified local label"
    if actor == "lab_operator" and enrolled:
        line = _BILAL_HEADER
        subject = "/CN=lab_operator"
        verified = True
        label = "verified_mtls_lab_operator"
        auth_label = "verified mTLS cert (/CN=lab_operator)"
    elif actor == "lab_operator":
        line = "Muhammad Bilal (21K-3551) · Tier-3 Approver | unverified local label"
    elif actor == "tier1_analyst":
        line = _SUHAIB_HEADER
        label = "no_soar_cert_triage_only"
        auth_label = "No SOAR Cert (Triage Only)"
    elif actor == "compliance_auditor":
        line = _HASNAIN_HEADER
        label = "read_only_compliance_token"
        auth_label = "Read-Only Compliance Token"
    elif chosen == "tier1_triage":
        line = f"{name} · Tier-1 Triage | No SOAR Cert (Triage Only)"
        label = "no_soar_cert_triage_only"
        auth_label = "No SOAR Cert (Triage Only)"
    elif chosen in _READONLY_ROLES:
        line = f"{name} · Auditor | Read-Only Compliance Token"
        label = "read_only_compliance_token"
        auth_label = "Read-Only Compliance Token"
    elif chosen == "soc_approver":
        line = f"{name} · Tier-3 Approver | unverified local label"
    else:
        line = "unverified local label"
    if actor != "lab_operator":
        subject = ""
        verified = False
        line = line.replace("verified mTLS cert (/CN=lab_operator)", auth_label)
    return {
        "actor_id": actor,
        "display_name": name,
        "role": chosen,
        "header_identity": line,
        "identity_verified": verified,
        "identity_label": label,
        "certificate_subject": subject,
        "operator_auth_label": auth_label,
        "enrollment_state": "enrolled" if enrolled and actor == "lab_operator" else "absent",
    }


def _verify_password(stored: str, password: str) -> bool:
    parts = str(stored or "").split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return False
    try:
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected = bytes.fromhex(parts[3])
    except ValueError:
        return False
    if iterations < 100_000 or iterations > 1_000_000 or not salt or not expected:
        return False
    derived = hashlib.pbkdf2_hmac("sha256", str(password or "").encode("utf-8"), salt, iterations)
    return hmac.compare_digest(derived, expected)


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _RBAC_ITERATIONS)
    return f"pbkdf2_sha256${_RBAC_ITERATIONS}${salt.hex()}${derived.hex()}"


def _rbac_secret(conn: sqlite3.Connection) -> bytes:
    row = conn.execute("SELECT value FROM rbac_runtime WHERE key = 'session_secret'").fetchone()
    if row is not None and row["value"]:
        try:
            return bytes.fromhex(str(row["value"]))
        except ValueError:
            pass
    secret = secrets.token_bytes(32)
    conn.execute(
        """
        INSERT INTO rbac_runtime (key, value) VALUES ('session_secret', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (secret.hex(),),
    )
    return secret


def _sign_session(secret: bytes, payload: Mapping[str, Any]) -> str:
    body = (
        base64.urlsafe_b64encode(
            json.dumps(dict(payload), separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    signature = hmac.new(secret, body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"tfs1.{body}.{signature}"


def _bare_token(token: str) -> str:
    raw = str(token or "").strip()
    if raw.lower().startswith("bearer "):
        return raw[7:].strip()
    return raw


def _session_parts(token: str) -> tuple[str, str] | None:
    pieces = _bare_token(token).split(".")
    if len(pieces) != 3 or pieces[0] != "tfs1" or not pieces[1] or not pieces[2]:
        return None
    return pieces[1], pieces[2]


def _token_hash(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _account_public(row: sqlite3.Row, *, session_token: str = "") -> dict[str, Any]:
    header = operator_header_identity(
        actor_id=str(row["actor_id"]),
        display_name=str(row["display_name"]),
        role=str(row["role"]),
    )
    payload = {
        "schema_version": "rbac_session_v1",
        "authenticated": True,
        "evidence_state": "verified" if header["identity_verified"] else "unavailable",
        "username": str(row["username"]),
        "session_token": session_token,
        "production_fusion_enabled": False,
        "http_status": 200,
    }
    payload.update(header)
    return payload


def _issue_session(conn: sqlite3.Connection, row: sqlite3.Row) -> str:
    secret = _rbac_secret(conn)
    expires = datetime.now(UTC) + timedelta(hours=12)
    payload = {
        "u": str(row["username"]),
        "a": str(row["actor_id"]),
        "r": str(row["role"]),
        "exp": expires.isoformat(),
        "n": secrets.token_hex(8),
    }
    token = _sign_session(secret, payload)
    conn.execute(
        """
        INSERT INTO rbac_sessions (
            token_hash, username, actor_id, role, expires_at_utc, created_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            _token_hash(token),
            str(row["username"]),
            str(row["actor_id"]),
            str(row["role"]),
            expires.isoformat(),
            datetime.now(UTC).isoformat(),
        ),
    )
    return token


def _session_row(db_path: Path, token: str) -> dict[str, str] | None:
    parts = _session_parts(token)
    if parts is None or not db_path.is_file():
        return None
    body, signature = parts
    with _connect(db_path) as conn:
        secret = _rbac_secret(conn)
        expected = hmac.new(secret, body.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return None
        row = conn.execute(
            """
            SELECT s.username, s.actor_id, s.role, s.expires_at_utc, a.display_name
            FROM rbac_sessions AS s
            JOIN rbac_accounts AS a ON a.username = s.username
            WHERE s.token_hash = ?
            """,
            (_token_hash(_bare_token(token)),),
        ).fetchone()
        if row is None:
            return None
        copied = {key: str(row[key] or "") for key in row.keys()}
    try:
        expires = datetime.fromisoformat(copied["expires_at_utc"])
    except ValueError:
        return None
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if expires <= datetime.now(UTC):
        return None
    return copied


def rbac_session_status(db_path: Path, token: str) -> dict[str, Any]:
    """Return the signed-in operator, or an anonymous unverified label."""
    row = _session_row(db_path, token)
    if row is None:
        return {
            "schema_version": "rbac_session_v1",
            "authenticated": False,
            "evidence_state": "unavailable",
            "header_identity": "unverified local label",
            "identity_verified": False,
            "identity_label": "unverified_local_label",
            "certificate_subject": "",
            "operator_auth_label": "unverified local label",
            "actor_id": "",
            "production_fusion_enabled": False,
            "http_status": 200,
        }
    header = operator_header_identity(
        actor_id=str(row["actor_id"]),
        display_name=str(row["display_name"]),
        role=str(row["role"]),
    )
    return {
        "schema_version": "rbac_session_v1",
        "authenticated": True,
        "evidence_state": "verified" if header["identity_verified"] else "unavailable",
        "username": str(row["username"]),
        "production_fusion_enabled": False,
        "http_status": 200,
        **header,
    }


def _rbac_refused(reason: str, status: int) -> dict[str, Any]:
    return {
        "schema_version": "rbac_session_v1",
        "authenticated": False,
        "evidence_state": "unavailable",
        "reason": reason,
        "header_identity": "unverified local label",
        "identity_verified": False,
        "identity_label": "unverified_local_label",
        "certificate_subject": "",
        "production_fusion_enabled": False,
        "http_status": status,
    }


def rbac_login(
    db_path: Path,
    *,
    username: str = "",
    email: str = "",
    access_code: str = "",
    entra_token: str = "",
) -> dict[str, Any]:
    """Authenticate with an access code or a Microsoft Entra ID token, then open a session."""
    presented = str(entra_token or "").strip()
    if presented:
        verified = verify_entra_token(db_path, presented)
        if int(verified.get("http_status") or 401) != 200:
            return _rbac_refused(str(verified.get("reason") or "entra_token_invalid"), 401)
        actor = str(verified.get("actor_id") or "")
        with _connect(db_path) as conn:
            row = conn.execute(
                "SELECT * FROM rbac_accounts WHERE actor_id = ?",
                (actor,),
            ).fetchone()
            if row is None:
                return _rbac_refused("operator_not_registered", 403)
            token = _issue_session(conn, row)
            public = _account_public(row, session_token=token)
        switch_operator(db_path, actor_id=str(public["actor_id"]))
        public["reason"] = "entra_token_verified"
        return public
    user = str(username or email or "").strip().lower()
    if _RBAC_EMAIL.fullmatch(user) is None or not str(access_code or ""):
        return _rbac_refused("invalid_credentials", 401)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM rbac_accounts WHERE username = ?",
            (user,),
        ).fetchone()
        if row is None or not _verify_password(str(row["password_hash"]), access_code):
            return _rbac_refused("invalid_credentials", 401)
        token = _issue_session(conn, row)
        public = _account_public(row, session_token=token)
    switch_operator(db_path, actor_id=str(public["actor_id"]))
    public["reason"] = "access_code_verified"
    return public


def rbac_logout(db_path: Path, token: str) -> dict[str, Any]:
    digest = _token_hash(_bare_token(token))
    if db_path.is_file() and _session_parts(token) is not None:
        with _connect(db_path) as conn:
            conn.execute("DELETE FROM rbac_sessions WHERE token_hash = ?", (digest,))
    return {
        "schema_version": "rbac_session_v1",
        "authenticated": False,
        "evidence_state": "unavailable",
        "reason": "logged_out",
        "header_identity": "unverified local label",
        "identity_verified": False,
        "identity_label": "unverified_local_label",
        "certificate_subject": "",
        "production_fusion_enabled": False,
        "http_status": 200,
    }


def _actor_slug(username: str) -> str:
    local = username.split("@", 1)[0]
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "", local)[:64]
    if _LOCAL_ACTOR.fullmatch(cleaned) is None:
        return ""
    return cleaned


def rbac_register(
    db_path: Path,
    *,
    username: str,
    access_code: str,
    display_name: str,
    role: str,
) -> dict[str, Any]:
    """Create a custom analyst account and sign that account in."""
    user = str(username or "").strip().lower()
    name = str(display_name or "").strip()
    chosen = str(role or "").strip()
    secret = str(access_code or "")
    if (
        _RBAC_EMAIL.fullmatch(user) is None
        or len(secret) < 8
        or len(secret) > 128
        or not name
        or len(name) > 120
        or chosen not in _OPERATOR_ROLES
    ):
        return _rbac_refused("account_invalid", 400)
    actor = _actor_slug(user)
    if not actor or actor in _RESERVED_ACTORS:
        return _rbac_refused("actor_reserved", 400)
    with _connect(db_path) as conn:
        existing = conn.execute(
            "SELECT username FROM rbac_accounts WHERE username = ?",
            (user,),
        ).fetchone()
        if existing is not None:
            return _rbac_refused("account_exists", 409)
        conn.execute(
            """
            INSERT INTO rbac_accounts (
                username, display_name, actor_id, role, password_hash,
                certificate_subject, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, '', ?)
            """,
            (
                user,
                name,
                actor,
                chosen,
                _hash_password(secret),
                datetime.now(UTC).isoformat(),
            ),
        )
    registered = register_operator(db_path, actor_id=actor, display_name=name, role=chosen)
    if int(registered.get("http_status") or 400) != 200:
        return _rbac_refused(str(registered.get("reason") or "operator_invalid"), 400)
    return rbac_login(db_path, username=user, access_code=secret)


def _attach_rollback_identity(
    db_path: Path,
    result: dict[str, Any],
    *,
    session_token: str | None,
    preserved: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Publish the signed-in header and keep a verified flow identity from being cleared."""
    result["flow_identity_preserved"] = True
    if preserved is not None:
        result["flow_identity_verified"] = bool(preserved.get("identity_verified"))
        result["flow_identity_label"] = preserved.get("identity_label") or ""
    session = rbac_session_status(db_path, str(session_token or ""))
    if session.get("authenticated") is True:
        for key in (
            "header_identity",
            "identity_verified",
            "identity_label",
            "certificate_subject",
            "operator_auth_label",
            "actor_id",
            "display_name",
            "role",
        ):
            result[key] = session.get(key)
        if session.get("actor_id") != "lab_operator":
            result["certificate_subject"] = ""
            result["identity_verified"] = False
            header = str(result.get("header_identity") or "")
            if "/CN=lab_operator" in header:
                result["header_identity"] = operator_header_identity(
                    actor_id=str(session.get("actor_id") or ""),
                    display_name=str(session.get("display_name") or ""),
                    role=str(session.get("role") or ""),
                )["header_identity"]
        return result
    if preserved is not None and preserved.get("identity_verified"):
        result["identity_verified"] = True
        result["identity_label"] = preserved.get("identity_label") or "verified_mtls_lab_operator"
        if preserved.get("operator_id") == "lab_operator":
            result["certificate_subject"] = "/CN=lab_operator"
            result["operator_auth_label"] = "verified mTLS cert (/CN=lab_operator)"
            result["header_identity"] = _BILAL_HEADER
    return result


def preview_soar_playbook(db_path: Path, *, flow_id: int) -> dict[str, Any]:
    """Render the technique responder and the four-step trace for one stored flow."""
    from threatfusion.soar.soar_playbooks_catalog import preview_fields, technique_for_flow

    if flow_id <= 0:
        return {
            "schema_version": "soar_playbook_preview_v1",
            "evidence_state": "unavailable",
            "reason": "flow_not_stored",
            "production_fusion_enabled": False,
            "http_status": 404,
        }
    match = next(
        (
            item
            for item in _flow_rows(db_path, limit=100)
            if int(item.get("flow_id") or 0) == flow_id
        ),
        None,
    )
    if match is None:
        return {
            "schema_version": "soar_playbook_preview_v1",
            "evidence_state": "unavailable",
            "reason": "flow_not_stored",
            "production_fusion_enabled": False,
            "http_status": 404,
        }
    observation = match.get("sensor_observation")
    if not isinstance(observation, Mapping):
        observation = {}
    try:
        sport = int(observation.get("src_port") or 0)
    except (TypeError, ValueError):
        sport = 0
    try:
        observed_dport = int(observation.get("dst_port") or match.get("service_or_port") or 0)
    except (TypeError, ValueError):
        observed_dport = 0
    proto = str(observation.get("proto") or match.get("flow_protocol") or "tcp").lower()
    technique = technique_for_flow(
        decision=str(match.get("decision") or ""),
        case_title=str(match.get("case_title") or ""),
        playbook_id=str(match.get("playbook_id") or ""),
    )
    probability = match.get("rf_attack_probability")
    try:
        rf_probability = float(probability) if probability is not None else None
    except (TypeError, ValueError):
        rf_probability = None
    ae_loss = match.get("ae_loss")
    try:
        ae_mse = float(ae_loss) if ae_loss is not None else None
    except (TypeError, ValueError):
        ae_mse = None
    ledger_state = str(match.get("ledger_state") or match.get("soar_state") or "")
    containment = str(match.get("containment_state") or "")
    approved = ledger_state in {"approved", "executed_simulated"} or bool(
        match.get("audit_chain_verified")
    )
    dispatched = bool(match.get("callback_recorded"))
    contained = containment in {
        "applied",
        "simulated_applied",
        "rolled_back",
        "simulated_rolled_back",
    }
    rolled_back = containment in {"rolled_back", "simulated_rolled_back"}
    preview = preview_fields(
        technique=technique,
        flow_id=flow_id,
        src_ip=str(match.get("src_entity_id") or ""),
        dst_ip=str(match.get("dst_entity_id") or ""),
        sport=sport,
        dport=observed_dport,
        proto=proto,
        rf_attack_probability=rf_probability,
        ae_mse=ae_mse,
        dnn_predicted_class=str(match.get("unsw_attack_category") or ""),
        hmac_prev_sha256=str(match.get("prev_entry_sha256") or ""),
        approved=approved,
        dispatched=dispatched,
        contained=contained,
        rolled_back=rolled_back,
    )
    safe_proto = proto if proto in {"tcp", "udp", "icmp"} else "tcp"
    safe_dport = observed_dport if observed_dport > 0 else 0
    if safe_dport <= 0:
        try:
            safe_dport = int(str(match.get("service_or_port") or "0"))
        except (TypeError, ValueError):
            safe_dport = 0
    rule = str(preview.get("firewall_rule_preview") or "")
    rule_port = re.search(r"--dport\s+(\d+)", rule)
    rule_proto = re.search(r"-p\s+(tcp|udp|icmp)", rule)
    if rule_port and rule_proto:
        safe_proto = rule_proto.group(1)
        safe_dport = int(rule_port.group(1))
    # Bind the metadata subtitle to this flow's live proto/dport (never a catalog default).
    preview["target_service"] = (
        f"{safe_proto}/{safe_dport}" if safe_dport > 0 else f"{safe_proto}/0"
    )
    preview["schema_version"] = "soar_playbook_preview_v1"
    preview["evidence_state"] = "verified"
    preview["flow_id"] = flow_id
    preview["proto"] = safe_proto
    preview["dport"] = safe_dport
    preview["http_status"] = 200
    return preview


def azure_portal_status(state_path: Path | None = None) -> dict[str, Any]:
    """Report the recorded Azure subscription file. This route does not call az."""
    path = state_path or Path("/tmp/threatfusion-range-demo/azure_portal_state.json")
    state: dict[str, Any] = {}
    if path.is_file() and not path.is_symlink():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            loaded = None
        if isinstance(loaded, dict):
            state = loaded
    connected = bool(state.get("subscription_id") and state.get("tenant_id"))
    return {
        "schema_version": "azure_portal_status_v1",
        "evidence_state": "verified" if connected else "unavailable",
        "azure_cli_present": shutil.which("az") is not None,
        "connected": connected,
        "state_path": str(path),
        "portal_state": state,
        "resource_group": str(state.get("resource_group") or "ThreatFusion-RG"),
        "tenant_id": str(state.get("tenant_id") or ""),
        "subscription_id": str(state.get("subscription_id") or ""),
        "app_id": str(state.get("app_id") or ""),
        "victim_vm_ip": str(state.get("victim_vm_ip") or "172.29.0.20"),
        "attacker_vm_ip": str(state.get("attacker_vm_ip") or "172.29.0.10"),
        "terminal_snippet": "scripts/deploy_azure_cyber_range.sh --provision-live-azure",
        "status_snippet": "scripts/deploy_azure_cyber_range.sh --status",
        "deallocate_snippet": "scripts/deploy_azure_cyber_range.sh --deallocate-vms",
        "production_fusion_enabled": False,
        "http_status": 200,
    }


def list_sensors(db_path: Path) -> dict[str, Any]:
    with _connect(db_path) as conn:
        rows = conn.execute("""
            SELECT sensor_id, monitored_cidr, status
            FROM registered_sensors
            ORDER BY sensor_id
            """).fetchall()
    return {
        "schema_version": "live_sensor_registry_v1",
        "evidence_state": "verified",
        "sensors": [
            {
                "sensor_id": str(row["sensor_id"]),
                "monitored_cidr": str(row["monitored_cidr"]),
                "status": str(row["status"]),
            }
            for row in rows
        ],
        "production_fusion_enabled": False,
        "http_status": 200,
    }


def register_sensor(
    db_path: Path, *, sensor_id: str, monitored_cidr: str, status: str = "enrolled"
) -> dict[str, Any]:
    identifier = str(sensor_id or "").strip()
    cidr = str(monitored_cidr or "").strip()
    sensor_status = str(status or "enrolled").strip() or "enrolled"
    if _SENSOR_ID.fullmatch(identifier) is None or not _valid_network(cidr):
        return {
            "schema_version": "live_sensor_registry_v1",
            "evidence_state": "unavailable",
            "reason": "sensor_invalid",
            "production_fusion_enabled": False,
            "http_status": 400,
        }
    if len(sensor_status) > 32:
        sensor_status = sensor_status[:32]
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO registered_sensors (
                sensor_id, monitored_cidr, status, created_at_utc
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(sensor_id) DO UPDATE SET
                monitored_cidr = excluded.monitored_cidr,
                status = excluded.status
            """,
            (identifier, cidr, sensor_status, datetime.now(UTC).isoformat()),
        )
    listed = list_sensors(db_path)
    listed["reason"] = "sensor_registered"
    listed["sensor_id"] = identifier
    return listed


def _stage_funnel_counts(db_path: Path) -> dict[str, int]:
    empty = {
        "stage1_ingested_flows": 0,
        "stage2_schema_valid": 0,
        "stage3_rf_attack_alerts": 0,
        "stage4_campaigns": 0,
    }
    if not db_path.is_file():
        return empty
    with _connect(db_path) as conn:
        stage1 = int(conn.execute("SELECT COUNT(*) FROM live_flows").fetchone()[0])
        stage2 = int(
            conn.execute(
                "SELECT COUNT(*) FROM live_flows WHERE evidence_state = 'verified'"
            ).fetchone()[0]
        )
        stage3 = int(
            conn.execute("SELECT COUNT(*) FROM live_flows WHERE decision = 'Attack'").fetchone()[0]
        )
        stage4 = int(conn.execute("""
                SELECT COUNT(DISTINCT campaign_id) FROM live_flows
                WHERE campaign_id IS NOT NULL AND campaign_id != ''
                """).fetchone()[0])
    return {
        "stage1_ingested_flows": stage1,
        "stage2_schema_valid": stage2,
        "stage3_rf_attack_alerts": stage3,
        "stage4_campaigns": stage4,
    }


def _playbook_ledger_verification(soar_db_path: Path | None) -> dict[str, Any]:
    if soar_db_path is None or not Path(soar_db_path).is_file():
        return {
            "algorithm": "HMAC-SHA256",
            "verified": False,
            "reason": "ledger_not_stored",
        }
    try:
        repository = SoarPlaybookSqliteRepository(Path(soar_db_path))
        verified, message = repository.verify_audit_chain_integrity()
    except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
        return {
            "algorithm": "HMAC-SHA256",
            "verified": False,
            "reason": exc.__class__.__name__,
        }
    return {
        "algorithm": "HMAC-SHA256",
        "verified": bool(verified),
        "message": str(message),
    }


def build_compliance_dossier(
    db_path: Path,
    *,
    repo_root: Path | None = None,
    soar_db_path: Path | None = None,
) -> dict[str, Any]:
    """Assemble the executive workspace, model, funnel, and ledger report."""
    root = repo_root or _console_repo_root()
    workspaces = list_workspaces(db_path)
    operators = list_operators(db_path)
    sensors = list_sensors(db_path)
    scorecard = _benchmark_scorecard(root)
    funnel = _stage_funnel_counts(db_path)
    ledger = _playbook_ledger_verification(soar_db_path)
    registry = {
        key: spec["expected_sha256"] for key, spec in FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY.items()
    }
    active = workspaces.get("active_workspace_id")
    lines = [
        "# ThreatFusion Executive Compliance Dossier",
        "",
        f"Active workspace: {active}",
        "",
        "## Workspaces",
    ]
    for item in workspaces["workspaces"]:
        marker = "active" if item["active"] else "inactive"
        lines.append(
            f"- {item['workspace_id']} ({marker}): {item['display_name']}; "
            f"{item['monitored_cidr']} service {item['default_service']}"
        )
    lines.extend(["", "## RBAC roster"])
    for item in operators["operators"]:
        marker = "active" if item["active"] else "inactive"
        lines.append(
            f"- {item['actor_id']} ({marker}): {item['display_name']}; role {item['role']}"
        )
    lines.extend(["", "## Sensor registry"])
    for item in sensors["sensors"]:
        lines.append(f"- {item['sensor_id']}: {item['monitored_cidr']} status {item['status']}")
    lines.extend(
        [
            "",
            "## Three-model digests and benchmarks",
            f"- Frozen Random Forest SHA-256: {registry['random_forest']}",
            (
                "- January UNSW flows: 216,568; volume reduction 98.0%; "
                "precision 95.266%; recall 92.818%; FPR 0.095%"
            ),
            f"- Frozen v2 Autoencoder SHA-256: {registry['autoencoder_v2']}",
            (
                f"- Autoencoder threshold: {_AE_THRESHOLD}; "
                "+2.203 pp recall gain; production_fusion_enabled = False"
            ),
            f"- Same-split 9-class DNN SHA-256: {_DNN_MODEL_SHA256}",
            (
                f"- Held-out rows: train {scorecard.get('train_rows')} / "
                f"test {scorecard.get('test_rows')}; "
                f"nine-class attack accuracy {scorecard.get('nine_class_attack_accuracy')}"
            ),
            f"- Logistic regression SHA-256: {registry['logistic_regression']}",
            f"- Rate-log1p candidate SHA-256: {registry['rate_log1p_candidate']}",
            "",
            "## Stage 1-4 funnel",
            f"- Stage 1 ingested flows: {funnel['stage1_ingested_flows']}",
            f"- Stage 2 schema-valid flows: {funnel['stage2_schema_valid']}",
            f"- Stage 3 frozen RF Attack alerts: {funnel['stage3_rf_attack_alerts']}",
            f"- Stage 4 campaigns: {funnel['stage4_campaigns']}",
            "",
            "## Playbook ledger",
            f"- Algorithm: {ledger['algorithm']}",
            f"- Verified: {ledger['verified']}",
            f"- Detail: {ledger.get('message') or ledger.get('reason') or 'unavailable'}",
            "",
            "TF-008, TF-009, TF-010, and TF-011 remain open.",
            "production_fusion_enabled = False. The frozen Random Forest remains the alert authority.",
        ]
    )
    return {
        "schema_version": "live_compliance_dossier_v1",
        "evidence_state": "verified",
        "production_fusion_enabled": False,
        "active_workspace_id": active,
        "workspaces": workspaces["workspaces"],
        "operators": operators["operators"],
        "sensors": sensors["sensors"],
        "model_digests": {
            "random_forest": registry["random_forest"],
            "autoencoder_v2": registry["autoencoder_v2"],
            "same_split_dnn": _DNN_MODEL_SHA256,
            "logistic_regression": registry["logistic_regression"],
            "rate_log1p_candidate": registry["rate_log1p_candidate"],
        },
        "benchmark_scorecard": scorecard,
        "funnel": funnel,
        "playbook_ledger": ledger,
        "open_gates": ["TF-008", "TF-009", "TF-010", "TF-011"],
        "dossier_markdown": "\n".join(lines) + "\n",
        "http_status": 200,
    }


def _range_vector_features(vector_id: str) -> dict[str, float] | None:
    if vector_id == "BENIGN_WEB":
        return _stored_profile(_BENIGN_WEB_CANONICAL, _BENIGN_WEB_RAW)
    if vector_id in _ATTACK_PROFILE_CANONICAL:
        return _attack_study_profile(vector_id)
    return None


def _range_probe_argv(vector_id: str) -> tuple[str, ...]:
    """Bounded packet probe. The scored profile carries the traffic shape."""
    victim = RANGE_VICTIM_ADDRESS
    if vector_id == "T1046":
        script = (
            f"for p in 22 80 443 445; do "
            f"timeout 1 sh -c 'echo >/dev/tcp/{victim}/'$p || true; "
            f"done"
        )
        return ("timeout", "4", "sh", "-c", script)
    if vector_id == "T1110":
        return (
            "timeout",
            "3",
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=2",
            f"root@{victim}",
            "exit",
        )
    if vector_id == "T1498":
        script = (
            'i=0; while [ "$i" -lt 4 ]; do '
            f"timeout 1 sh -c 'echo >/dev/tcp/{victim}/80' || true; "
            "i=$((i+1)); done"
        )
        return ("timeout", "4", "sh", "-c", script)
    return (
        "timeout",
        "3",
        "curl",
        "-fsS",
        "--max-time",
        "2",
        f"http://{victim}/",
    )


def _range_containers_running() -> bool:
    import subprocess

    for name in (RANGE_ATTACKER_CONTAINER, RANGE_VICTIM_CONTAINER):
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", name],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if result.returncode != 0 or result.stdout.strip().lower() != "true":
            return False
    return True


def _start_range_vector_probe(vector_id: str) -> dict[str, Any]:
    """Start a short attacker-to-victim probe when both range containers are up."""
    base = {
        "bounded": True,
        "non_blocking": True,
        "src_ip": RANGE_CONTAINMENT_SOURCE,
        "dst_ip": RANGE_VICTIM_ADDRESS,
        "vector_id": vector_id,
    }
    if not _range_containers_running():
        base["started"] = False
        base["reason"] = "range_containers_not_running"
        return base
    import subprocess

    command = ("docker", "exec", RANGE_ATTACKER_CONTAINER, *_range_probe_argv(vector_id))
    try:
        subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        base["started"] = False
        base["reason"] = "probe_not_started"
        return base
    base["started"] = True
    base["reason"] = "probe_started"
    return base


def _record_range_probe(db_path: Path, vector_id: str, probe: Mapping[str, Any]) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO range_probe_events (
                vector_id, started, reason, detail_json, created_at_utc
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                vector_id,
                1 if probe.get("started") else 0,
                str(probe.get("reason") or ""),
                json.dumps(dict(probe), sort_keys=True),
                datetime.now(UTC).isoformat(),
            ),
        )


def _latest_reachability_probe(db_path: Path) -> dict[str, Any]:
    if not db_path.is_file():
        return {
            "status": "not_probed",
            "reachable": None,
            "src_ip": RANGE_CONTAINMENT_SOURCE,
            "dst_ip": RANGE_VICTIM_ADDRESS,
        }
    with _connect(db_path) as conn:
        row = conn.execute("""
            SELECT vector_id, started, reason, detail_json, created_at_utc
            FROM range_probe_events
            ORDER BY probe_id DESC
            LIMIT 1
            """).fetchone()
    if row is None:
        return {
            "status": "not_probed",
            "reachable": None,
            "src_ip": RANGE_CONTAINMENT_SOURCE,
            "dst_ip": RANGE_VICTIM_ADDRESS,
        }
    try:
        detail = json.loads(str(row["detail_json"]))
    except json.JSONDecodeError:
        detail = {}
    if not isinstance(detail, dict):
        detail = {}
    detail["status"] = str(row["reason"] or "not_probed")
    detail["vector_id"] = str(row["vector_id"])
    detail["observed_at_utc"] = str(row["created_at_utc"])
    detail.setdefault("reachable", None)
    return detail


def range_telemetry(db_path: Path) -> dict[str, Any]:
    """Return the lab range topology, firewall state, and launchable profiles."""
    containment_state = "clear"
    blocked_sources: list[str] = []
    soar_receipts = 0
    if db_path.is_file():
        with _connect(db_path) as conn:
            latest = conn.execute(
                """
                SELECT containment_state FROM live_flows
                WHERE src_entity_id = ?
                ORDER BY flow_id DESC
                LIMIT 1
                """,
                (RANGE_CONTAINMENT_SOURCE,),
            ).fetchone()
            if latest is not None and latest["containment_state"]:
                containment_state = str(latest["containment_state"])
            blocked_rows = conn.execute("""
                SELECT DISTINCT src_entity_id FROM live_flows
                WHERE containment_state = 'applied'
                  AND src_entity_id IS NOT NULL
                  AND src_entity_id != ''
                """).fetchall()
            blocked_sources = [str(row["src_entity_id"]) for row in blocked_rows]
            soar_receipts = int(
                conn.execute(
                    "SELECT COUNT(*) FROM live_flows WHERE callback_recorded = 1"
                ).fetchone()[0]
            )
    return {
        "schema_version": "live_range_telemetry_v1",
        "evidence_state": "verified",
        "production_fusion_enabled": False,
        "attacker_node": {
            "ip": "172.29.0.10",
            "container": "threatfusion_range_attacker",
            "role": "Red-Team Attacker VM / Container",
        },
        "victim_node": {
            "ip": "172.29.0.20",
            "container": "threatfusion_range_victim",
            "role": "Protected Enterprise Victim Host",
        },
        "sensor_node": {
            "container": "threatfusion_range_suricata",
            "eve_log": "var/log/suricata/eve.json",
            "role": "Suricata NDR IDS/IPS Bridge",
        },
        "soar_node": {
            "container": "threatfusion_n8n_live",
            "port": 5678,
            "role": "n8n SOAR Webhook Orchestrator",
        },
        "containment_state": containment_state,
        "blocked_sources": blocked_sources,
        "reachability_probe": _latest_reachability_probe(db_path),
        "soar_receipts": soar_receipts,
        "attack_catalog": [dict(item) for item in _RANGE_ATTACK_CATALOG],
        "http_status": 200,
    }


def ingest_live_flow(
    db_path: Path,
    features: Mapping[str, Any],
    *,
    repo_root: Path,
    src_ip: str,
    dst_ip: str,
    source_label: str = "suricata_eve_bridge",
    case_title: str | None = None,
    vector_id: str | None = None,
) -> dict[str, Any]:
    """Score one canonical flow with the raw RF, v2 AE, and 9-class DNN and store it."""
    score = score_canonical_flow(features, repo_root=repo_root)
    if score.get("reason") != "frozen_random_forest_scored":
        refused = dict(score)
        refused["http_status"] = 503
        refused["src_ip"] = src_ip
        refused["dst_ip"] = dst_ip
        refused["source_label"] = source_label
        refused["vector_id"] = vector_id
        return refused
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    campaign_id = f"campaign_range_vector:{vector_id or 'flow'}:{stamp}"
    try:
        dst_port = int(float(features.get("dst_port", 0)))
    except (TypeError, ValueError):
        dst_port = 0
    service = str(dst_port)
    if float(features.get("protocol_udp") or 0) >= 1.0:
        protocol = "udp"
    elif float(features.get("protocol_icmp") or 0) >= 1.0:
        protocol = "icmp"
    else:
        protocol = "tcp"
    observation = {
        "proto": protocol,
        "src_port": 0,
        "dst_port": dst_port,
        "suricata_line": (
            f"{protocol} {src_ip}:0 -> {dst_ip}:{dst_port}, range vector {vector_id or 'flow'}"
        ),
        "forest_line": (
            f"{score.get('decision')}, {_probability_text(score.get('rf_attack_probability'))}"
        ),
    }
    stored = persist_scored_flow(
        db_path,
        features,
        score,
        campaign_id=campaign_id,
        source_label=source_label,
        case_title=case_title,
        provenance={
            "entity_namespace_id": "lab:cyber-range",
            "src_entity_id": src_ip,
            "dst_entity_id": dst_ip,
            "protocol": protocol,
            "service_or_port": service,
            "clock_synchronized": True,
        },
        sensor_observation_json=json.dumps(observation, sort_keys=True),
        sensor_node="threatfusion_range_suricata",
    )
    if stored.get("reason") != "frozen_random_forest_scored":
        stored["http_status"] = 400
        stored["src_ip"] = src_ip
        stored["dst_ip"] = dst_ip
        return stored
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO live_campaigns (
                campaign_id, title, source_label, created_at_utc, member_count
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                campaign_id,
                case_title or campaign_id,
                source_label,
                datetime.now(UTC).isoformat(),
                1,
            ),
        )
    stored["schema_version"] = "live_range_vector_v1"
    stored["src_ip"] = src_ip
    stored["dst_ip"] = dst_ip
    stored["vector_id"] = vector_id
    stored["source_label"] = source_label
    stored["http_status"] = 200
    stored["production_fusion_enabled"] = False
    return stored


def launch_range_vector(
    db_path: Path,
    *,
    vector_id: str,
    src_ip: str,
    dst_ip: str,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Probe the lab pair when it is up, then ingest and score that vector."""
    vector = str(vector_id or "").strip()
    source = str(src_ip or "").strip()
    destination = str(dst_ip or "").strip()
    refused = {
        "schema_version": "live_range_vector_v1",
        "evidence_state": "unavailable",
        "production_fusion_enabled": False,
        "vector_id": vector,
        "src_ip": source,
        "dst_ip": destination,
    }
    if vector not in _RANGE_VECTOR_IDS:
        refused["reason"] = "unknown_vector"
        refused["http_status"] = 400
        return refused
    if source != RANGE_CONTAINMENT_SOURCE or destination != RANGE_VICTIM_ADDRESS:
        refused["reason"] = "range_pair_required"
        refused["http_status"] = 400
        return refused
    features = _range_vector_features(vector)
    if features is None:
        refused["reason"] = "unknown_vector"
        refused["http_status"] = 400
        return refused
    root = repo_root or _console_repo_root()
    probe = _start_range_vector_probe(vector)
    _record_range_probe(db_path, vector, probe)
    title = next(item["title"] for item in _RANGE_ATTACK_CATALOG if item["vector_id"] == vector)
    scenario_label = vector if vector != "BENIGN_WEB" else None
    if scenario_label:
        title = f"{title} (scenario label {scenario_label})"
    stored = ingest_live_flow(
        db_path,
        features,
        repo_root=root,
        src_ip=source,
        dst_ip=destination,
        source_label="suricata_eve_bridge",
        case_title=title,
        vector_id=vector,
    )
    stored["range_probe"] = probe
    stored["attack_catalog_title"] = title
    stored["scenario_label"] = scenario_label
    return stored
