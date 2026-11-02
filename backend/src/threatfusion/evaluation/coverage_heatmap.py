"""Read-only ATT&CK and CVE coverage heatmap.

Observed counts come from frozen-RF verified Attack rows. The claimed column is
the static 18-entry mapping. Lab hypotheses stay out unless ``include_lab`` is
true, and they never upgrade ``evidence_state`` to verified.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from threatfusion.evaluation.lab_hunt_runner import (
    FORBIDDEN_PRODUCTION_DB_NAMES,
    LAB_CLASSIFICATION,
    canonical_json,
    verify_lab_hash_chain,
)

COVERAGE_HEATMAP_SCHEMA_VERSION = "attack_coverage_heatmap_v1"
MAPPING_VERSION = "mitre_cve_static_mapping_v1"
FROZEN_RF_SHA256 = "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"

STATIC_MITRE_CVE_MAPPING: tuple[tuple[str, str, str], ...] = (
    ("T1046", "Network Service Discovery", "technique"),
    ("T1190", "Exploit Public-Facing Application", "technique"),
    ("T1498", "Network Denial of Service", "technique"),
    ("T1071.001", "Application Layer Protocol: Web Traffic", "technique"),
    ("T1595", "Active Scanning", "technique"),
    ("T1110", "Brute Force", "technique"),
    ("T1041", "Exfiltration Over C2 Channel", "technique"),
    ("T1021", "Remote Services", "technique"),
    ("T1059", "Command and Scripting Interpreter", "technique"),
    ("T1133", "External Remote Services", "technique"),
    ("CVE-2023-48795", "Terrapin SSH Prefix Truncation", "cve"),
    ("CVE-2023-44487", "HTTP/2 Rapid Reset", "cve"),
    ("CVE-2021-44228", "Log4Shell JNDI RCE", "cve"),
    ("CVE-2023-4966", "CitrixBleed Session Hijack", "cve"),
    ("CVE-2024-3400", "PAN-OS Command Injection", "cve"),
    ("CVE-2023-34362", "MOVEit SQL Injection and Exfiltration", "cve"),
    ("CVE-2023-22515", "Confluence Broken Authentication", "cve"),
    ("CVE-2017-0144", "EternalBlue SMB Remote Exploit", "cve"),
)

_REQUIRED_FLOW_COLUMNS = frozenset(
    {
        "decision",
        "evidence_state",
        "production_fusion_enabled",
        "model_sha256",
        "case_title",
        "source_label",
    }
)


def heatmap_canonical_bytes(payload: dict[str, Any]) -> bytes:
    return canonical_json(payload).encode("utf-8")


def _empty_counts() -> dict[str, int]:
    return {item_id: 0 for item_id, _name, _kind in STATIC_MITRE_CVE_MAPPING}


def _ids_in_text(text: str) -> list[str]:
    if not text:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for item_id, _name, _kind in sorted(
        STATIC_MITRE_CVE_MAPPING, key=lambda item: len(item[0]), reverse=True
    ):
        start = 0
        while True:
            index = text.find(item_id, start)
            if index < 0:
                break
            before = text[index - 1] if index else ""
            after_index = index + len(item_id)
            after = text[after_index] if after_index < len(text) else ""
            if (not before.isalnum()) and (not after.isalnum()):
                if item_id not in seen:
                    seen.add(item_id)
                    found.append(item_id)
                break
            start = index + 1
    return found


def _rf_confirmed_counts(live_db_path: Path | None) -> tuple[dict[str, int], str]:
    counts = _empty_counts()
    if live_db_path is None or not Path(live_db_path).is_file():
        return counts, "live_store_unavailable"
    if Path(live_db_path).name in FORBIDDEN_PRODUCTION_DB_NAMES:
        return counts, "live_store_unavailable"
    uri = Path(live_db_path).resolve().as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return counts, "live_store_unavailable"
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if "live_flows" not in tables:
            return counts, "live_store_unavailable"
        columns = {row[1] for row in connection.execute("PRAGMA table_info(live_flows)")}
        if not _REQUIRED_FLOW_COLUMNS.issubset(columns):
            return counts, "live_store_unavailable"
        rows = connection.execute(
            """
            SELECT decision, evidence_state, production_fusion_enabled, model_sha256,
                   case_title, source_label
            FROM live_flows
            """
        )
        matched = False
        for decision, evidence_state, fusion, model_sha, case_title, source_label in rows:
            if decision != "Attack" or evidence_state != "verified" or int(fusion or 0) != 0:
                continue
            if model_sha != FROZEN_RF_SHA256:
                continue
            if source_label == "lab_hypothesis":
                continue
            text = f"{case_title or ''} {source_label or ''}"
            for item_id in _ids_in_text(text):
                counts[item_id] += 1
                matched = True
        return counts, "verified_rf_rows" if matched else "no_verified_rf_rows"
    except (sqlite3.Error, TypeError, ValueError):
        return _empty_counts(), "live_store_unavailable"
    finally:
        connection.close()


def _lab_counts(lab_chain_path: Path | None, *, include_lab: bool) -> dict[str, int]:
    counts = _empty_counts()
    if not include_lab or lab_chain_path is None:
        return counts
    path = Path(lab_chain_path)
    if path.name in FORBIDDEN_PRODUCTION_DB_NAMES or not verify_lab_hash_chain(path):
        return counts
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return counts
    hypotheses = document.get("hypotheses") if isinstance(document, dict) else None
    if not isinstance(hypotheses, list):
        return counts
    known = set(counts)
    for item in hypotheses:
        if not isinstance(item, dict):
            continue
        if item.get("classification") != LAB_CLASSIFICATION or item.get("alert_created") is not False:
            continue
        technique_id = item.get("technique_id")
        if isinstance(technique_id, str) and technique_id in known:
            counts[technique_id] += 1
    return counts


def build_coverage_heatmap(
    live_db_path: Path | None = None,
    *,
    include_lab: bool = False,
    lab_chain_path: Path | None = None,
) -> dict[str, Any]:
    """Compare RF-confirmed observations with the static mapping table."""
    include = include_lab is True
    rf_counts, reason = _rf_confirmed_counts(live_db_path)
    lab_counts = _lab_counts(lab_chain_path, include_lab=include)
    observed: list[dict[str, Any]] = []
    claimed: list[dict[str, Any]] = []
    cells: list[dict[str, Any]] = []
    for item_id, name, kind in STATIC_MITRE_CVE_MAPPING:
        rf_count = rf_counts[item_id]
        lab_count = lab_counts[item_id] if include else 0
        evidence_state = "verified" if rf_count > 0 else "unavailable"
        observed_count = rf_count + lab_count if include else rf_count
        observed.append(
            {
                "count": observed_count,
                "evidence_state": evidence_state,
                "id": item_id,
                "kind": kind,
                "lab_hypothesis_count": lab_count,
                "name": name,
                "rf_confirmed_count": rf_count,
            }
        )
        claimed.append(
            {
                "claimed": True,
                "evidence_state": "unavailable",
                "id": item_id,
                "kind": kind,
                "mapping_version": MAPPING_VERSION,
                "name": name,
            }
        )
        cells.append(
            {
                "claimed": True,
                "evidence_state": evidence_state,
                "id": item_id,
                "kind": kind,
                "lab_hypothesis_count": lab_count,
                "name": name,
                "observed_count": observed_count,
                "rf_confirmed_count": rf_count,
            }
        )
    return {
        "alert_authority": "frozen_random_forest",
        "cells": cells,
        "claimed": claimed,
        "include_lab": include,
        "mapping_version": MAPPING_VERSION,
        "observed": observed,
        "observed_reason": reason,
        "production_fusion_enabled": False,
        "read_only": True,
        "schema_version": COVERAGE_HEATMAP_SCHEMA_VERSION,
    }
