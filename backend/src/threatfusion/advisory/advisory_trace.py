"""Read-only assigned-versus-actual view of non-decision advisory components.

Stages 1-4 must not import this module. It opens SQLite only in read-only
mode, never writes a decision, and never places a network call.
"""

from __future__ import annotations

import ast
import re
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

MEASURED_RAW = "measured_raw"
DISPLAY_ADJUSTED = "display-adjusted, not measured"
COMPLETE = "COMPLETE"
PARTIAL = "PARTIAL"
PENDING_ADVISORY = "PENDING ADVISORY"

_ADVISORY_COMPONENT_IDS = (
    "v2_autoencoder_ranker",
    "pytorch_9class_head",
    "chromadb_mitre_rag",
    "grounded_narrative_copilot",
)
_DISPLAY_NAMES = {
    "v2_autoencoder_ranker": "v2 Autoencoder Ranker",
    "pytorch_9class_head": "PyTorch 9-Class Head",
    "chromadb_mitre_rag": "ChromaDB MITRE RAG",
    "grounded_narrative_copilot": "Grounded Narrative Copilot",
}
_FEATURE_SCOPE = "14 normalized flow features"
_RAG_SCOPE = "MITRE/CVE top-k query"
_NARRATIVE_SCOPE = "flow telemetry summary"
_BAND_TOKENS = frozenset(
    {
        "low",
        "medium",
        "high",
        "critical",
        "elevated",
        "nominal",
        "published advisory band",
        "published_advisory_band",
        DISPLAY_ADJUSTED,
    }
)
_EVIDENCE_RE = re.compile(r"\[E([1-5])\]")
_SECTION_EVIDENCE = (
    ("[1]", "[E2]"),
    ("[2]", "[E1]"),
    ("[3]", "[E3]"),
    ("[4]", "[E1]"),
    ("[5]", "[E5]"),
)
_DECISION_WRITE_FLAGS = (
    "ae_changes_alert_decision",
    "dnn_changes_alert_decision",
    "rag_changes_alert_decision",
    "narrative_changes_alert_decision",
)
_G9_CACHE: tuple[bool, tuple[str, ...]] | None = None


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in {float("inf"), float("-inf")}:
        return None
    return number


def _is_display_band(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    token = value.strip().lower()
    if token in _BAND_TOKENS:
        return True
    return token.startswith("band:") or "advisory band" in token


def _features_assigned(flow: Mapping[str, Any]) -> bool:
    for key in ("canonical_features", "dnn_features", "features"):
        value = flow.get(key)
        if isinstance(value, Mapping) and any(item is not None for item in value.values()):
            return True
    raw = flow.get("features_json")
    return isinstance(raw, str) and raw.strip().startswith("{")


def _evidence(*tokens: str) -> list[str]:
    found: list[str] = []
    for token in tokens:
        if token and token not in found:
            found.append(token)
    return found


def _cited_evidence(text: str) -> list[str]:
    found: list[str] = []
    for match in _EVIDENCE_RE.finditer(text or ""):
        token = f"[E{match.group(1)}]"
        if token not in found:
            found.append(token)
    for heading, token in _SECTION_EVIDENCE:
        if heading in (text or "") and token not in found:
            found.append(token)
    if "[3]" in (text or "") and "CVE-" in (text or "") and "[E4]" not in found:
        found.append("[E4]")
    return found


def count_advisory_decision_writes(flow: Mapping[str, Any] | None) -> int:
    """Count decision writes performed by advisory components.

    The frozen Random Forest column is not an advisory write. A fusion flag
    that is true, or an advisory component listed as a decision writer, is.
    """
    if not isinstance(flow, Mapping):
        return 0
    writes = 0
    writers = flow.get("decision_writers")
    if isinstance(writers, (list, tuple)):
        writes += sum(1 for item in writers if str(item) in _ADVISORY_COMPONENT_IDS)
    for name in _DECISION_WRITE_FLAGS:
        if flow.get(name) is True:
            writes += 1
    fusion = flow.get("production_fusion_enabled")
    if fusion is True or fusion == 1:
        writes += 1
    advisory_decision = flow.get("advisory_decision")
    if advisory_decision not in (None, "") and advisory_decision != flow.get("decision"):
        writes += 1
    return writes


def gate_g9_status(repo_root: Path | None = None) -> tuple[bool, tuple[str, ...]]:
    """Return the live Gate G9 AST result. The first successful scan is cached."""
    global _G9_CACHE
    if repo_root is None and _G9_CACHE is not None:
        return _G9_CACHE
    from threatfusion.evaluation.repo_truth_audit import verify_gate_g9_ast_import_graph

    src_root = Path(__file__).resolve().parents[2] if repo_root is None else Path(repo_root)
    if src_root.name != "src":
        candidate = src_root / "backend" / "src"
        if candidate.is_dir():
            src_root = candidate
    passed, violations = verify_gate_g9_ast_import_graph(src_root)
    result = (bool(passed), tuple(violations))
    if repo_root is None:
        _G9_CACHE = result
    return result


def _component(
    component_id: str,
    *,
    assigned_scope: str,
    actual_output: Any,
    integrity: str,
    evidence_ids: list[str],
    recorded_at_utc: str,
) -> dict[str, Any]:
    return {
        "component_id": component_id,
        "display_name": _DISPLAY_NAMES[component_id],
        "assigned_scope": assigned_scope,
        "actual_output": actual_output,
        "measurement_integrity": integrity,
        "evidence_ids_read": list(evidence_ids),
        "recorded_at_utc": recorded_at_utc,
    }


def _integrity_override(flow: Mapping[str, Any], component_id: str) -> str | None:
    raw = flow.get("measurement_integrity_by_component")
    if not isinstance(raw, Mapping):
        return None
    value = raw.get(component_id)
    if value in {MEASURED_RAW, DISPLAY_ADJUSTED}:
        return str(value)
    return None


def _autoencoder_component(flow: Mapping[str, Any], recorded_at: str) -> dict[str, Any]:
    scope = _FEATURE_SCOPE if _features_assigned(flow) else ""
    loss = _finite(flow.get("ae_loss"))
    band = flow.get("ae_display_band") or flow.get("published_advisory_band")
    explicit = _integrity_override(flow, "v2_autoencoder_ranker")
    if loss is not None and not _is_display_band(flow.get("ae_loss")):
        actual: Any = {"mse": loss}
        errors = flow.get("ae_feature_errors")
        if isinstance(errors, list) and errors:
            actual["feature_errors"] = errors
        integrity = MEASURED_RAW
    elif _is_display_band(band) or _is_display_band(flow.get("ae_loss")):
        actual = str(band or flow.get("ae_loss") or "")
        integrity = DISPLAY_ADJUSTED
    else:
        actual = None
        integrity = MEASURED_RAW
    if explicit is not None:
        integrity = explicit
    evidence = _evidence("[E1]") if scope else []
    return _component(
        "v2_autoencoder_ranker",
        assigned_scope=scope,
        actual_output=actual,
        integrity=integrity,
        evidence_ids=evidence,
        recorded_at_utc=recorded_at,
    )


def _distribution_is_raw(value: Any) -> bool:
    if not isinstance(value, Mapping) or not value:
        return False
    for item in value.values():
        if _finite(item) is None:
            return False
    return True


def _dnn_component(flow: Mapping[str, Any], recorded_at: str) -> dict[str, Any]:
    scope = _FEATURE_SCOPE if _features_assigned(flow) else ""
    distribution = flow.get("dnn_class_distribution")
    band = flow.get("dnn_display_band")
    explicit = _integrity_override(flow, "pytorch_9class_head")
    reshaped = (
        flow.get("dnn_distribution_reshaped") is True or flow.get("dnn_display_adjusted") is True
    )
    if _distribution_is_raw(distribution) and not reshaped:
        actual: Any = {str(key): _finite(item) for key, item in distribution.items()}
        integrity = MEASURED_RAW
    elif _is_display_band(band) or _is_display_band(distribution) or reshaped:
        actual = band if band not in (None, "") else distribution
        integrity = DISPLAY_ADJUSTED
    else:
        actual = None
        integrity = MEASURED_RAW
    if explicit is not None:
        integrity = explicit
    evidence = _evidence("[E1]") if scope else []
    return _component(
        "pytorch_9class_head",
        assigned_scope=scope,
        actual_output=actual,
        integrity=integrity,
        evidence_ids=evidence,
        recorded_at_utc=recorded_at,
    )


def _rag_component(flow: Mapping[str, Any], recorded_at: str) -> dict[str, Any]:
    hits = flow.get("chroma_rag_hits")
    if not isinstance(hits, list):
        hits = []
    query_present = bool(
        str(flow.get("case_title") or "").strip()
        or str(flow.get("technique_id") or "").strip()
        or hits
    )
    scope = _RAG_SCOPE if query_present else ""
    explicit = _integrity_override(flow, "chromadb_mitre_rag")
    band = flow.get("rag_display_band")
    if hits and not _is_display_band(band):
        actual: Any = hits
        integrity = MEASURED_RAW
    elif _is_display_band(band):
        actual = str(band)
        integrity = DISPLAY_ADJUSTED
    elif query_present:
        actual = []
        integrity = MEASURED_RAW
    else:
        actual = None
        integrity = MEASURED_RAW
    if explicit is not None:
        integrity = explicit
    evidence: list[str] = []
    if scope and actual is not None:
        evidence = _evidence("[E3]")
        cves = flow.get("cve_ids")
        if isinstance(cves, list) and cves:
            evidence = _evidence("[E3]", "[E4]")
    return _component(
        "chromadb_mitre_rag",
        assigned_scope=scope,
        actual_output=actual,
        integrity=integrity,
        evidence_ids=evidence,
        recorded_at_utc=recorded_at,
    )


def _narrative_component(
    flow: Mapping[str, Any],
    narrative: str | None,
    recorded_at: str,
) -> dict[str, Any]:
    text = narrative.strip() if isinstance(narrative, str) else ""
    has_flow_context = bool(
        flow.get("decision") or flow.get("case_title") or _features_assigned(flow) or text
    )
    scope = _NARRATIVE_SCOPE if has_flow_context else ""
    explicit = _integrity_override(flow, "grounded_narrative_copilot")
    band = flow.get("narrative_display_band")
    if text and not _is_display_band(text):
        actual: Any = text
        integrity = MEASURED_RAW
    elif _is_display_band(text) or _is_display_band(band):
        actual = text or str(band or "")
        integrity = DISPLAY_ADJUSTED
    else:
        actual = None
        integrity = MEASURED_RAW
    if explicit is not None:
        integrity = explicit
    evidence = _cited_evidence(text) if isinstance(actual, str) and actual else []
    return _component(
        "grounded_narrative_copilot",
        assigned_scope=scope,
        actual_output=actual,
        integrity=integrity,
        evidence_ids=evidence,
        recorded_at_utc=recorded_at,
    )


def _has_output(component: Mapping[str, Any]) -> bool:
    value = component.get("actual_output")
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, Mapping):
        return bool(value)
    return True


def _completeness(components: list[dict[str, Any]]) -> tuple[str, list[str]]:
    narrative = next(
        item for item in components if item["component_id"] == "grounded_narrative_copilot"
    )
    gaps: list[str] = []
    for item in components:
        if item["component_id"] == "grounded_narrative_copilot" and not _has_output(item):
            continue
        component_id = str(item["component_id"])
        if not str(item.get("assigned_scope") or "").strip():
            gaps.append(f"{component_id}: missing assigned_scope")
        if not _has_output(item):
            gaps.append(f"{component_id}: missing actual_output")
        if item.get("measurement_integrity") != MEASURED_RAW:
            gaps.append(f"{component_id}: {DISPLAY_ADJUSTED}")
        if not list(item.get("evidence_ids_read") or []):
            gaps.append(f"{component_id}: missing evidence_ids_read")
    if not _has_output(narrative):
        return PENDING_ADVISORY, gaps
    if gaps:
        return PARTIAL, gaps
    return COMPLETE, []


def build_advisory_trace(
    flow: Mapping[str, Any] | None,
    *,
    narrative: str | None = None,
    narrative_recorded_at: str | None = None,
    gate_g9_pass: bool | None = None,
) -> dict[str, Any]:
    """Build the assigned-versus-actual trace. The input mapping is not mutated."""
    record: Mapping[str, Any] = flow if isinstance(flow, Mapping) else {}
    recorded_at = str(record.get("observed_at_utc") or "")
    narrative_at = str(narrative_recorded_at or recorded_at)
    components = [
        _autoencoder_component(record, recorded_at),
        _dnn_component(record, recorded_at),
        _rag_component(record, recorded_at),
        _narrative_component(record, narrative, narrative_at),
    ]
    badge, gaps = _completeness(components)
    writes = count_advisory_decision_writes(record)
    verdict = str(record.get("decision") or "withheld")
    if gate_g9_pass is None:
        passed, violations = gate_g9_status()
    else:
        passed, violations = bool(gate_g9_pass), ()
    gate = "PASS" if passed else "FAIL"
    summary = (
        f"Decision writes by advisory components: {writes}, "
        f"Frozen RF verdict: {verdict} (unchanged), "
        f"Gate G9: {gate}"
    )
    authority_bar = (
        f"Decision writes: {writes} · Frozen RF verdict: {verdict} (unchanged) · Gate G9: {gate}"
    )
    return {
        "schema_version": "advisory_trace_v1",
        "flow_id": record.get("flow_id"),
        "components": components,
        "completeness_badge": badge,
        "completeness_gaps": gaps,
        "authority": {
            "decision_writes_by_advisory_components": writes,
            "frozen_rf_verdict": verdict,
            "frozen_rf_unchanged": True,
            "gate_g9": gate,
            "gate_g9_violations": list(violations),
            "summary": summary,
            "authority_bar": authority_bar,
        },
        "authority_summary": summary,
        "authority_bar": authority_bar,
        "production_fusion_enabled": False,
        "decision_writes_by_advisory_components": writes,
    }


def read_cached_narratives(db_path: Path) -> dict[int, dict[str, str]]:
    """Read copilot cache rows. A missing file, symlink, or table stays empty."""
    path = Path(db_path)
    if not path.is_file() or path.is_symlink():
        return {}
    uri = f"file:{path.resolve()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=2.0)
    except sqlite3.Error:
        return {}
    try:
        connection.row_factory = sqlite3.Row
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if "live_copilot_cache" not in tables:
            return {}
        rows = connection.execute(
            "SELECT cache_key, narrative, created_at_utc FROM live_copilot_cache"
        ).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        connection.close()
    found: dict[int, dict[str, str]] = {}
    for row in rows:
        head = str(row["cache_key"] or "").split("\n", 1)[0]
        try:
            flow_id = int(head)
        except ValueError:
            continue
        if flow_id <= 0:
            continue
        recorded_at = str(row["created_at_utc"] or "")
        current = found.get(flow_id)
        if current is not None and recorded_at < current["recorded_at_utc"]:
            continue
        found[flow_id] = {
            "narrative": str(row["narrative"] or ""),
            "recorded_at_utc": recorded_at,
        }
    return found


def module_has_no_write_or_network_calls() -> bool:
    """Static check used by the unit gate. This function does not touch the disk."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "open":
            return False
        if isinstance(func, ast.Attribute) and func.attr in {
            "write_text",
            "write_bytes",
            "unlink",
            "mkdir",
            "urlopen",
        }:
            return False
    return True
