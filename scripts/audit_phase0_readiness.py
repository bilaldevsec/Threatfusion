"""Audit Phase 0 integrity, report safety, feature leakage, and split readiness."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.datasets.manifests import (  # noqa: E402
    load_dataset_manifest,
    verify_dataset_manifest,
)
from threatfusion.datasets.mordor_profile import EVENT_ID_CATEGORY_LIMIT  # noqa: E402
from threatfusion.datasets.split_policy import (  # noqa: E402
    PHASE0_SPLIT_POLICY,
    DatasetUse,
    SplitAssignment,
)
from threatfusion.features.common_network import (  # noqa: E402
    FLOW_COMMON_V1_FEATURE_NAMES,
    MODEL_INPUT_FEATURE_NAMES,
)
from threatfusion.features.host_behavior import (  # noqa: E402
    HOST_BEHAVIOR_V1_ALLOWED_MODEL_FIELDS,
    HOST_BEHAVIOR_V1_PROHIBITED_MODEL_FIELDS,
)
from threatfusion.features.network_behavior import (  # noqa: E402
    NETWORK_BEHAVIOR_V1_ALLOWED_MODEL_FIELDS,
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
    NETWORK_BEHAVIOR_V1_FORBIDDEN_MODEL_FIELDS,
)

PHASE = "0M"
SCHEMA_VERSION = "phase0_readiness_v1"

QUALITY_KEYS = frozenset(
    {
        "source",
        "completed",
        "total_rows",
        "accepted_count",
        "rejected_count",
        "rejection_rate",
        "rejection_details",
    }
)
CIC_QUALITY_KEYS = QUALITY_KEYS | {
    "source_file",
    "expected_column_count",
    "canonical_label_counts",
    "attack_category_counts",
}
CIC_PROFILE_KEYS = frozenset(
    {
        "dataset",
        "benchmark_role",
        "network_behavior_v1_feature_order",
        "timestamp_semantics",
        "files",
        "combined",
    }
)
UNSW_PROFILE_KEYS = frozenset(
    {
        "completed",
        "total_input_rows",
        "accepted_count",
        "rejected_count",
        "rejection_rate",
        "rejection_details",
        "canonical_label_counts",
        "raw_numeric_label_counts",
        "attack_category_counts",
        "protocol_counts",
        "service_counts",
        "connection_state_counts",
        "blank_optional_attack_category_count",
        "numeric_ranges",
        "earliest_timestamp",
        "latest_timestamp",
        "label_inconsistency_counts",
        "label_inconsistency_examples",
    }
)
MORDOR_PROFILE_KEYS = frozenset(
    {
        "dataset",
        "source_file",
        "classification",
        "completed",
        "total_rows",
        "accepted_count",
        "rejected_count",
        "rejection_rate",
        "rejection_details",
        "event_id_counts",
        "event_id_overflow_count",
        "field_presence_counts",
        "process_event_count",
        "earliest_timestamp",
        "latest_timestamp",
    }
)
SYNTHETIC_PROFILE_KEYS = frozenset(
    {
        "dataset",
        "classification",
        "completed",
        "total_rows",
        "accepted_count",
        "rejected_count",
        "rejection_rate",
        "rejection_details",
        "session_count",
        "sessions",
        "event_type_counts",
        "label_counts",
        "host_behavior_v1_aggregate",
        "quality_gates",
        "training_quality_gates",
    }
)
SYNTHETIC_SESSION_KEYS = frozenset(
    {
        "source_file",
        "completed",
        "total_rows",
        "accepted_count",
        "rejected_count",
        "duration_seconds",
        "event_type_counts",
    }
)
CIC_FILE_PROFILE_KEYS = frozenset(
    {
        "source_file",
        "completed",
        "total_rows",
        "accepted_count",
        "rejected_count",
        "rejection_rate",
        "rejection_details",
        "label_counts",
        "attack_category_counts",
        "protocol_counts",
        "numeric_ranges",
        "earliest_source_timestamp",
        "latest_source_timestamp",
    }
)
CIC_COMBINED_PROFILE_KEYS = CIC_FILE_PROFILE_KEYS - {"source_file"}

FORBIDDEN_REPORT_KEYS = frozenset(
    {
        "row",
        "rows",
        "complete_row",
        "complete_rows",
        "raw_row",
        "raw_rows",
        "raw_value",
        "raw_values",
        "src_ip",
        "dst_ip",
        "source_ip",
        "destination_ip",
        "command_line",
        "username",
        "user",
        "password",
        "secret",
        "process_guid",
    }
)
PROHIBITED_PREDICTOR_FIELDS = frozenset(
    {
        "schema_version",
        "source_dataset",
        "source_file",
        "filename",
        "file_name",
        "source_row_number",
        "row_number",
        "flow_id",
        "event_id",
        "record_id",
        "event_record_id",
        "ingestion_id",
        "provenance_id",
        "__mordor_ingestion_id",
        "process_guid",
        "timestamp",
        "source_timestamp",
        "timestamp_start",
        "timestamp_end",
        "src_ip",
        "dst_ip",
        "host",
        "user",
        "username",
        "command_line",
        "secret",
        "src_port",
        "source_port",
        "label",
        "attack_category",
        "attack_name",
        "mitre_attack_id",
    }
)

IgnoreCheck = Callable[[Path], bool]


@dataclass(frozen=True, slots=True)
class DatasetReportContract:
    """Expected aggregate evidence for one registered dataset."""

    quality_roles: frozenset[str]
    profile_report: str
    excluded_input_basenames: frozenset[str] = frozenset()


REPORT_CONTRACTS: dict[str, DatasetReportContract] = {
    "unsw_nb15": DatasetReportContract(
        quality_roles=frozenset({"raw"}),
        profile_report="unsw_nb15_profile.json",
        excluded_input_basenames=frozenset({"NUSW-NB15_features.csv"}),
    ),
    "cse_cic_ids2018": DatasetReportContract(
        quality_roles=frozenset({"validation"}),
        profile_report="cse_cic_ids2018_profile.json",
    ),
    "mordor": DatasetReportContract(
        quality_roles=frozenset({"test"}),
        profile_report="mordor_profile.json",
    ),
    "synthetic_lab": DatasetReportContract(
        quality_roles=frozenset({"development_fixture"}),
        profile_report="synthetic_lab_profile.json",
    ),
}


def _normalized_field_name(value: str) -> str:
    snake_case = re.sub(r"(?<!^)(?=[A-Z])", "_", value).replace("-", "_")
    return snake_case.casefold()


def _safe_basename(value: str) -> bool:
    return bool(value) and value not in {".", ".."} and Path(value).name == value


def _report_schema_errors(report_name: str, payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return ["report_root_not_object"]
    keys = frozenset(payload)
    errors: list[str] = []
    if report_name.endswith("_quality.json"):
        allowed = CIC_QUALITY_KEYS if "source_file" in payload else QUALITY_KEYS
        if not keys <= allowed:
            errors.append("unapproved_report_keys")
    elif report_name == "cse_cic_ids2018_profile.json":
        if keys != CIC_PROFILE_KEYS:
            errors.append("unapproved_report_keys")
        files = payload.get("files")
        combined = payload.get("combined")
        if not isinstance(files, list) or any(
            not isinstance(item, dict) or frozenset(item) != CIC_FILE_PROFILE_KEYS for item in files
        ):
            errors.append("unapproved_cic_file_profile_keys")
        if not isinstance(combined, dict) or frozenset(combined) != CIC_COMBINED_PROFILE_KEYS:
            errors.append("unapproved_cic_combined_keys")
    elif report_name == "unsw_nb15_profile.json":
        if keys != UNSW_PROFILE_KEYS:
            errors.append("unapproved_report_keys")
    elif report_name == "mordor_profile.json":
        if keys != MORDOR_PROFILE_KEYS:
            errors.append("unapproved_report_keys")
        if (
            payload.get("dataset") != "mordor"
            or payload.get("classification") != "attack_test_only"
        ):
            errors.append("mordor_profile_classification_invalid")
    elif report_name == "synthetic_lab_profile.json":
        if keys != SYNTHETIC_PROFILE_KEYS:
            errors.append("unapproved_report_keys")
        sessions = payload.get("sessions")
        if not isinstance(sessions, list) or any(
            not isinstance(item, dict) or frozenset(item) != SYNTHETIC_SESSION_KEYS
            for item in sessions
        ):
            errors.append("unapproved_synthetic_session_keys")
        quality_gates = payload.get("quality_gates")
        if not isinstance(quality_gates, dict) or frozenset(quality_gates) != {
            "configured",
            "results",
            "passed",
        }:
            errors.append("unapproved_synthetic_quality_gate_keys")
        training_gates = payload.get("training_quality_gates")
        if not isinstance(training_gates, dict) or frozenset(training_gates) != {
            "configured",
            "observed",
            "results",
            "passed",
        }:
            errors.append("unapproved_synthetic_training_gate_keys")
    else:
        errors.append("unknown_report_schema")
    return errors


def _count_arithmetic_errors(payload: Any, report_name: str) -> list[str]:
    """Validate aggregate count types and arithmetic without returning values."""
    if report_name == "cse_cic_ids2018_profile.json" and isinstance(payload, dict):
        payload = payload.get("combined")
    if not isinstance(payload, dict):
        return ["aggregate_counts_missing"]
    total_key = "total_input_rows" if report_name == "unsw_nb15_profile.json" else "total_rows"
    values = (
        payload.get(total_key),
        payload.get("accepted_count"),
        payload.get("rejected_count"),
    )
    if not all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in values
    ):
        return ["aggregate_counts_invalid"]
    total, accepted, rejected = values
    errors: list[str] = []
    if accepted + rejected != total:
        errors.append("aggregate_counts_contradictory")
    rate = payload.get("rejection_rate")
    if not isinstance(rate, (int, float)) or isinstance(rate, bool) or not math.isfinite(rate):
        errors.append("rejection_rate_invalid")
    elif not math.isclose(float(rate), rejected / total if total else 0.0, abs_tol=1e-12):
        errors.append("rejection_rate_contradictory")
    return errors


def _gate_errors(payload: Any, key: str, required_sections: frozenset[str]) -> list[str]:
    if not isinstance(payload, dict):
        return [f"{key}_invalid"]
    gate = payload.get(key)
    if not isinstance(gate, dict) or frozenset(gate) != required_sections:
        return [f"{key}_invalid"]
    results = gate.get("results")
    passed = gate.get("passed")
    if (
        not isinstance(results, dict)
        or not results
        or any(not isinstance(value, bool) for value in results.values())
        or not isinstance(passed, bool)
    ):
        return [f"{key}_invalid"]
    if passed != all(results.values()):
        return [f"{key}_contradictory"]
    return []


def _synthetic_profile_errors(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return ["synthetic_profile_invalid"]
    errors = _gate_errors(payload, "quality_gates", frozenset({"configured", "results", "passed"}))
    errors.extend(
        _gate_errors(
            payload,
            "training_quality_gates",
            frozenset({"configured", "observed", "results", "passed"}),
        )
    )
    sessions = payload.get("sessions")
    session_count = payload.get("session_count")
    if not isinstance(sessions, list) or session_count != len(sessions):
        errors.append("synthetic_session_count_contradictory")
    elif all(isinstance(session, dict) for session in sessions):
        for key in ("total_rows", "accepted_count", "rejected_count"):
            values = [session.get(key) for session in sessions]
            if not all(
                isinstance(value, int) and not isinstance(value, bool) and value >= 0
                for value in values
            ) or payload.get(key) != sum(values):
                errors.append("synthetic_session_totals_contradictory")
                break
    return errors


def _mordor_profile_errors(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return ["mordor_profile_invalid"]
    counts = payload.get("event_id_counts")
    overflow = payload.get("event_id_overflow_count")
    total = payload.get("total_rows")
    if (
        not isinstance(counts, dict)
        or len(counts) > EVENT_ID_CATEGORY_LIMIT
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in counts.values()
        )
        or not isinstance(overflow, int)
        or isinstance(overflow, bool)
        or overflow < 0
        or not isinstance(total, int)
        or sum(counts.values()) + overflow != total
    ):
        return ["mordor_event_id_totals_contradictory"]
    return []


def _string_is_sensitive(value: str) -> bool:
    if value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value):
        return True
    if re.search(r"(?i)(top[-_ ]?secret|password|raw[-_ ]?secret|command[-_ ]?line)", value):
        return True
    for token in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", value):
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        return True
    return False


def _sensitive_content_errors(value: Any) -> set[str]:
    errors: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if _normalized_field_name(str(key)) in FORBIDDEN_REPORT_KEYS:
                errors.add("forbidden_report_key")
            if _string_is_sensitive(str(key)):
                errors.add("sensitive_report_marker")
            errors.update(_sensitive_content_errors(child))
    elif isinstance(value, list):
        for child in value:
            errors.update(_sensitive_content_errors(child))
    elif isinstance(value, str) and _string_is_sensitive(value):
        errors.add("sensitive_report_marker")
    return errors


def inspect_report_payload(report_name: str, payload: Any) -> dict[str, Any]:
    """Check one report without returning any source values."""
    errors = _report_schema_errors(report_name, payload)
    errors.extend(_count_arithmetic_errors(payload, report_name))
    if report_name == "synthetic_lab_profile.json":
        errors.extend(_synthetic_profile_errors(payload))
    elif report_name == "mordor_profile.json":
        errors.extend(_mordor_profile_errors(payload))
    errors.extend(sorted(_sensitive_content_errors(payload)))
    completed = isinstance(payload, dict) and payload.get("completed") is True
    if report_name == "cse_cic_ids2018_profile.json" and isinstance(payload, dict):
        combined = payload.get("combined")
        completed = isinstance(combined, dict) and combined.get("completed") is True
    if not completed:
        errors.append("report_not_completed")
    return {
        "valid": not errors,
        "keys_approved": not any("keys" in error or "schema" in error for error in errors),
        "content_sanitized": not any(
            "sensitive" in error or "forbidden" in error for error in errors
        ),
        "completed": completed,
        "errors": sorted(set(errors)),
    }


def find_prohibited_predictors(
    contracts: Mapping[str, Sequence[str]],
) -> dict[str, list[str]]:
    """Return forbidden predictor names by contract, never feature values."""
    result: dict[str, list[str]] = {}
    for name, fields in contracts.items():
        prohibited = sorted(
            field
            for field in {_normalized_field_name(item) for item in fields}
            if field in PROHIBITED_PREDICTOR_FIELDS
        )
        if prohibited:
            result[name] = prohibited
    return result


def synthetic_baseline_is_ready(
    manifest_verification: Mapping[str, Any], profile: Mapping[str, Any]
) -> bool:
    """Require a final training classification and all training-quality gates."""
    pipeline_gates = profile.get("quality_gates")
    training_gates = profile.get("training_quality_gates")
    return (
        manifest_verification.get("verified") is True
        and profile.get("completed") is True
        and profile.get("classification") == "final_training_baseline"
        and isinstance(pipeline_gates, dict)
        and pipeline_gates.get("passed") is True
        and isinstance(training_gates, dict)
        and training_gates.get("passed") is True
    )


def synthetic_pipeline_is_ready(
    manifest_verification: Mapping[str, Any], profile: Mapping[str, Any]
) -> bool:
    """Require verified inputs and a completed development fixture profile."""
    quality_gates = profile.get("quality_gates")
    return (
        manifest_verification.get("verified") is True
        and profile.get("completed") is True
        and profile.get("classification") == "development_pipeline_fixture"
        and isinstance(quality_gates, dict)
        and quality_gates.get("passed") is True
    )


def _report_totals(payload: dict[str, Any], report_name: str) -> tuple[int, int, int]:
    if report_name == "cse_cic_ids2018_profile.json":
        payload = payload.get("combined", {})
    total_key = "total_input_rows" if "total_input_rows" in payload else "total_rows"
    values = (
        payload.get(total_key),
        payload.get("accepted_count"),
        payload.get("rejected_count"),
    )
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in values):
        return (0, 0, 0)
    return values


def _report_source_basename(payload: dict[str, Any]) -> str | None:
    source_file = payload.get("source_file")
    if isinstance(source_file, str) and _safe_basename(source_file):
        return source_file
    source = payload.get("source")
    if isinstance(source, str):
        candidate = source.rsplit("/", maxsplit=1)[-1]
        if _safe_basename(candidate):
            return candidate
    return None


def _default_ignore_check(project_root: Path) -> IgnoreCheck:
    def ignored(path: Path) -> bool:
        try:
            relative = path.relative_to(project_root)
        except ValueError:
            return False
        result = subprocess.run(
            ["git", "check-ignore", "--quiet", "--", str(relative)],
            cwd=project_root,
            check=False,
        )
        return result.returncode == 0

    return ignored


def _load_reports(report_directory: Path) -> list[tuple[str, Path, dict[str, Any]]]:
    reports: list[tuple[str, Path, dict[str, Any]]] = []
    if not report_directory.is_dir():
        return reports
    for path in sorted(report_directory.glob("*/*.json")):
        try:
            payload: Any = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        reports.append((path.parent.name, path, payload if isinstance(payload, dict) else {}))
    return reports


def run_audit(
    project_root: Path,
    manifest_directory: Path,
    report_directory: Path,
    output_path: Path,
    *,
    predictor_contracts: Mapping[str, Sequence[str]] | None = None,
    ignore_check: IgnoreCheck | None = None,
    split_assignments: tuple[SplitAssignment, ...] | None = None,
) -> dict[str, Any]:
    """Run the read-only checks and write one bounded sanitized audit report."""
    project_root = project_root.resolve()
    ignore_check = ignore_check or _default_ignore_check(project_root)
    blockers: set[str] = set()
    warnings: set[str] = {
        "cic_export_may_be_row_capped",
        "cic_source_timezone_unknown",
        "flow_common_v1_retains_unsw_only_src_port",
        "mordor_contains_only_one_process_event",
    }

    manifest_state: dict[str, dict[str, Any]] = {}
    manifest_rows: dict[str, dict[str, int]] = {}
    manifest_inputs: dict[str, list[tuple[str, str]]] = {}
    registered_paths: list[Path] = []
    for manifest_path in sorted(manifest_directory.glob("*.yaml")):
        safe_manifest_name = manifest_path.name
        try:
            manifest = load_dataset_manifest(manifest_path)
            verification = verify_dataset_manifest(manifest, project_root)
        except (OSError, TypeError, ValueError, yaml.YAMLError):
            blockers.add("manifest_load_or_verification_failed")
            manifest_state[safe_manifest_name] = {
                "verified": False,
                "inputs_exist": False,
                "paths_relative": False,
                "files": [],
            }
            continue

        files: list[dict[str, Any]] = []
        manifest_rows[manifest.name] = {}
        manifest_inputs[manifest.name] = []
        for item, result in zip(manifest.files, verification.files, strict=True):
            relative = not item.path.is_absolute() and ".." not in item.path.parts
            source_path = project_root / item.path
            registered_paths.append(source_path)
            if item.rows is not None:
                manifest_rows[manifest.name][item.path.name] = item.rows
            manifest_inputs[manifest.name].append((item.path.name, item.role))
            files.append(
                {
                    "source_file": item.path.name,
                    "role": item.role,
                    "exists": source_path.is_file(),
                    "path_relative": relative,
                    "checksum_status": result.status.value,
                }
            )
        state = {
            "verified": verification.verified,
            "inputs_exist": all(item["exists"] for item in files),
            "paths_relative": all(item["path_relative"] for item in files),
            "attack_test_only": "attack/test-only" in str(manifest.notes).casefold(),
            "files": files,
        }
        manifest_state[manifest.name] = state
        if not all((state["verified"], state["inputs_exist"], state["paths_relative"])):
            blockers.add("manifest_integrity_gate_failed")

    required_datasets = {"unsw_nb15", "cse_cic_ids2018", "mordor", "synthetic_lab"}
    if not required_datasets <= set(manifest_state):
        blockers.add("required_manifest_missing")

    expected_reports: dict[str, dict[str, str | None]] = {}
    for dataset, contract in REPORT_CONTRACTS.items():
        inputs = [
            basename
            for basename, role in manifest_inputs.get(dataset, [])
            if role in contract.quality_roles and basename not in contract.excluded_input_basenames
        ]
        if not inputs:
            blockers.add("required_report_input_missing")
        if len(inputs) != len(set(inputs)):
            blockers.add("required_report_input_ambiguous")
        expected_reports[dataset] = {
            **{f"{Path(basename).stem}_quality.json": basename for basename in inputs},
            contract.profile_report: None,
        }

    loaded_reports = [
        report
        for report in _load_reports(report_directory)
        if report[1].resolve() != output_path.resolve()
    ]
    loaded_report_counts: dict[tuple[str, str], int] = {}
    for dataset, path, _payload in loaded_reports:
        key = (dataset, path.name)
        loaded_report_counts[key] = loaded_report_counts.get(key, 0) + 1
    missing_reports = [
        (dataset, report_name)
        for dataset, reports in expected_reports.items()
        for report_name in reports
        if loaded_report_counts.get((dataset, report_name), 0) == 0
    ]
    duplicate_reports = [
        key
        for key, count in loaded_report_counts.items()
        if count > 1 and key[0] in expected_reports
    ]
    if missing_reports:
        blockers.add("required_report_missing")
    if duplicate_reports:
        blockers.add("required_report_duplicate")
    quality_totals: dict[str, dict[str, tuple[int, int, int]]] = {}
    for dataset, path, payload in loaded_reports:
        if path.name.endswith("_quality.json"):
            source = _report_source_basename(payload)
            if source is not None:
                quality_totals.setdefault(dataset, {})[source] = _report_totals(payload, path.name)

    report_state: dict[str, list[dict[str, Any]]] = {}
    aggregate_counts: dict[str, dict[str, int]] = {}
    for dataset, path, payload in loaded_reports:
        inspection = inspect_report_payload(path.name, payload)
        total, accepted, rejected = _report_totals(payload, path.name)
        totals_match = accepted + rejected == total
        source = _report_source_basename(payload)
        expected = manifest_rows.get(dataset, {}).get(source or "")
        expected_source = expected_reports.get(dataset, {}).get(path.name, "unexpected")
        expected_report = expected_source != "unexpected"
        if path.name.endswith("_quality.json"):
            totals_match = (
                totals_match and expected_report and source == expected_source and expected == total
            )
        elif path.name == "cse_cic_ids2018_profile.json":
            files = payload.get("files", [])
            expected_sources = {
                value
                for value in expected_reports.get(dataset, {}).values()
                if isinstance(value, str)
            }
            observed_sources = [item.get("source_file") for item in files if isinstance(item, dict)]
            totals_match = (
                totals_match
                and expected_report
                and isinstance(files, list)
                and len(observed_sources) == len(expected_sources)
                and set(observed_sources) == expected_sources
                and all(
                    isinstance(item, dict)
                    and manifest_rows.get(dataset, {}).get(str(item.get("source_file")))
                    == item.get("total_rows")
                    for item in files
                )
            )
        elif path.name == "mordor_profile.json":
            expected_sources = {
                value
                for value in expected_reports.get(dataset, {}).values()
                if isinstance(value, str)
            }
            totals_match = (
                totals_match
                and expected_report
                and source in expected_sources
                and len(expected_sources) == 1
                and expected == total
            )
        elif path.name == "unsw_nb15_profile.json":
            expected_sources = {
                value
                for value in expected_reports.get(dataset, {}).values()
                if isinstance(value, str)
            }
            recorded = quality_totals.get(dataset, {})
            recorded_total = sum(
                recorded[source_name][0]
                for source_name in expected_sources
                if source_name in recorded
            )
            totals_match = (
                totals_match
                and expected_report
                and set(recorded) == expected_sources
                and recorded_total == total
            )
        elif path.name == "synthetic_lab_profile.json":
            sessions = payload.get("sessions", [])
            expected_sources = {
                value
                for value in expected_reports.get(dataset, {}).values()
                if isinstance(value, str)
            }
            observed_sources = [
                item.get("source_file") for item in sessions if isinstance(item, dict)
            ]
            totals_match = (
                totals_match
                and expected_report
                and isinstance(sessions, list)
                and len(observed_sources) == len(expected_sources)
                and set(observed_sources) == expected_sources
                and all(
                    isinstance(item, dict)
                    and manifest_rows.get(dataset, {}).get(str(item.get("source_file")))
                    == item.get("total_rows")
                    for item in sessions
                )
            )

        else:
            totals_match = False

        verified = (
            inspection["valid"]
            and inspection["completed"]
            and inspection["keys_approved"]
            and inspection["content_sanitized"]
            and totals_match
        )
        report_state.setdefault(dataset, []).append(
            {
                "report_file": path.name,
                "verified": verified,
                "expected": expected_report,
                "completed": inspection["completed"],
                "keys_approved": inspection["keys_approved"],
                "content_sanitized": inspection["content_sanitized"],
                "totals_match": totals_match,
                "total_rows": total,
                "accepted_count": accepted,
                "rejected_count": rejected,
            }
        )
        if not verified:
            blockers.add("report_verification_gate_failed")
        if "profile" in path.name or dataset not in aggregate_counts:
            aggregate_counts[dataset] = {
                "total_rows": total,
                "accepted_count": accepted,
                "rejected_count": rejected,
            }

    required_evidence_by_dataset = {
        dataset: all(
            loaded_report_counts.get((dataset, report_name), 0) == 1
            and any(
                item["report_file"] == report_name and item["verified"]
                for item in report_state.get(dataset, [])
            )
            for report_name in reports
        )
        for dataset, reports in expected_reports.items()
    }
    if not all(required_evidence_by_dataset.values()):
        blockers.add("required_report_evidence_failed")

    ignore_targets = [*registered_paths, *(path for _, path, _ in loaded_reports), output_path]
    ignore_targets.extend(
        (
            project_root / "data/interim/phase0_audit.csv",
            project_root / "data/processed/phase0_audit.csv",
            project_root / "data/processed/phase0_audit.parquet",
            project_root / "artifacts/models/phase0_audit.onnx",
            project_root / "artifacts/models/phase0_audit.pkl",
            project_root / "artifacts/models/phase0_audit.joblib",
        )
    )
    ignore_ok = all(ignore_check(path) for path in ignore_targets)
    if not ignore_ok:
        blockers.add("generated_or_raw_paths_not_ignored")

    contracts = predictor_contracts or {
        "cic_unsw_network_behavior_v1": NETWORK_BEHAVIOR_V1_ALLOWED_MODEL_FIELDS,
        "host_behavior_v1": HOST_BEHAVIOR_V1_ALLOWED_MODEL_FIELDS,
    }
    prohibited = find_prohibited_predictors(contracts)
    if prohibited:
        blockers.add("prohibited_predictor_fields_declared")

    common_only = sorted(set(FLOW_COMMON_V1_FEATURE_NAMES) - set(NETWORK_BEHAVIOR_V1_FEATURE_NAMES))
    behavior_only = sorted(
        set(NETWORK_BEHAVIOR_V1_FEATURE_NAMES) - set(FLOW_COMMON_V1_FEATURE_NAMES)
    )
    contract_relationship_documented = common_only == ["src_port"] and not behavior_only
    if not contract_relationship_documented:
        blockers.add("network_feature_contract_relationship_unresolved")

    mordor_manifest = manifest_state.get("mordor", {})
    mordor_files = mordor_manifest.get("files", [])
    mordor_attack_test_only = (
        mordor_manifest.get("attack_test_only") is True
        and bool(mordor_files)
        and all(item.get("role") in {"test", "validation"} for item in mordor_files)
    )
    if not mordor_attack_test_only:
        blockers.add("mordor_not_isolated_as_attack_test_data")

    synthetic_profile = next(
        (
            payload
            for dataset, path, payload in loaded_reports
            if dataset == "synthetic_lab" and path.name == "synthetic_lab_profile.json"
        ),
        {},
    )
    synthetic_manifest = manifest_state.get("synthetic_lab", {})
    synthetic_evidence_verified = required_evidence_by_dataset.get("synthetic_lab", False)
    synthetic_pipeline_fixture_ready = synthetic_evidence_verified and synthetic_pipeline_is_ready(
        synthetic_manifest, synthetic_profile
    )
    synthetic_lab_registered = synthetic_evidence_verified and synthetic_baseline_is_ready(
        synthetic_manifest, synthetic_profile
    )
    if not synthetic_pipeline_fixture_ready:
        blockers.add("benign_synthetic_lab_baseline_missing")
    elif not synthetic_lab_registered:
        blockers.add("synthetic_lab_fixture_not_final_training_data")

    cic_profile = next(
        (
            payload
            for dataset, path, payload in loaded_reports
            if dataset == "cse_cic_ids2018" and path.name == "cse_cic_ids2018_profile.json"
        ),
        {},
    )
    cic_timezone_safe = (
        cic_profile.get("timestamp_semantics") == "timezone-naive; source timezone unknown"
    )
    if not cic_timezone_safe:
        blockers.add("cic_timestamp_timezone_invented_or_unverified")

    source_policy_configured = PHASE0_SPLIT_POLICY.source_aware
    time_policy_configured = all(
        not rule.timestamps_reliable or rule.time_aware for rule in PHASE0_SPLIT_POLICY.rules
    )
    group_policy_configured = (
        PHASE0_SPLIT_POLICY.group_aware and PHASE0_SPLIT_POLICY.enforce_group_exclusivity
    )
    external_policy_configured = all(
        rule.use is DatasetUse.EXTERNAL_EVALUATION
        for rule in PHASE0_SPLIT_POLICY.rules
        if rule.source_dataset in {"cse_cic_ids2018", "mordor"}
    )
    random_policy_configured = not PHASE0_SPLIT_POLICY.allow_ungrouped_random
    configured_sources = {rule.source_dataset for rule in PHASE0_SPLIT_POLICY.rules}
    assignment_status = "not_verified"
    if split_assignments:
        try:
            PHASE0_SPLIT_POLICY.validate_assignments(split_assignments)
        except ValueError:
            assignment_status = "failed"
            blockers.add("split_assignments_invalid")
        else:
            assigned_sources = {assignment.source_dataset for assignment in split_assignments}
            if assigned_sources == configured_sources:
                assignment_status = "verified"
            else:
                assignment_status = "incomplete"
                blockers.add("split_assignments_incomplete")
    else:
        blockers.add("split_assignments_missing")

    split_policy_checks: list[dict[str, Any]] = [
        {
            "check": "source_aware_split",
            "status": "configured" if source_policy_configured else "failed",
            "policy": "keep source datasets distinct and record every source assignment",
        },
        {
            "check": "time_aware_split",
            "status": "configured" if time_policy_configured else "failed",
            "policy": "use chronological splits only where source timestamp semantics are reliable",
        },
        {
            "check": "group_aware_split",
            "status": "configured" if group_policy_configured else "failed",
            "policy": "keep each source file or correlated group in exactly one split",
        },
        {
            "check": "external_test_separation",
            "status": "configured" if external_policy_configured else "failed",
            "policy": "never train on CIC external-validation or Mordor attack/test inputs",
        },
        {
            "check": "random_row_split",
            "status": "configured" if random_policy_configured else "failed",
            "policy": "do not use an ungrouped random row split",
        },
        {
            "check": "split_assignments",
            "status": assignment_status,
            "policy": "verify explicit complete source-group assignments before model work",
        },
    ]
    if any(check["status"] == "failed" for check in split_policy_checks[:-1]):
        blockers.add("leakage_safe_split_policy_invalid")

    datasets = []
    for name in sorted(set(manifest_state) | set(report_state)):
        manifest_result = manifest_state.get(name, {})
        safe_basenames = [item["source_file"] for item in manifest_result.get("files", [])]
        datasets.append(
            {
                "name": name,
                "safe_basenames": safe_basenames,
                "aggregate_counts": aggregate_counts.get(
                    name, {"total_rows": 0, "accepted_count": 0, "rejected_count": 0}
                ),
                "manifest_verification": manifest_result,
                "report_verification": report_state.get(name, []),
                "required_report_evidence_verified": required_evidence_by_dataset.get(name, False),
            }
        )

    leakage_checks = [
        {
            "check": "prohibited_predictors",
            "status": "failed" if prohibited else "passed",
            "fields_by_contract": prohibited,
        },
        {
            "check": "network_contract_parity",
            "status": (
                "documented_separate_contracts" if contract_relationship_documented else "failed"
            ),
            "flow_common_only": common_only,
            "network_behavior_only": behavior_only,
        },
        {
            "check": "cic_timezone_semantics",
            "status": "passed" if cic_timezone_safe else "failed",
        },
        {
            "check": "mordor_attack_test_isolation",
            "status": "passed" if mordor_attack_test_only else "failed",
        },
        {
            "check": "benign_synthetic_lab_baseline",
            "status": (
                "pipeline_fixture_only"
                if synthetic_pipeline_fixture_ready and not synthetic_lab_registered
                else "passed" if synthetic_lab_registered else "failed"
            ),
        },
        {
            "check": "synthetic_training_quality_gates",
            "status": ("passed" if synthetic_lab_registered else "failed"),
        },
        {
            "check": "git_ignore_coverage",
            "status": "passed" if ignore_ok else "failed",
        },
    ]

    payload = {
        "phase": PHASE,
        "schema_version": SCHEMA_VERSION,
        "pipeline_ready": not (
            blockers
            & {
                "manifest_load_or_verification_failed",
                "manifest_integrity_gate_failed",
                "required_manifest_missing",
                "required_report_input_missing",
                "required_report_input_ambiguous",
                "required_report_missing",
                "required_report_duplicate",
                "required_report_evidence_failed",
                "report_verification_gate_failed",
                "benign_synthetic_lab_baseline_missing",
                "generated_or_raw_paths_not_ignored",
                "cic_timestamp_timezone_invented_or_unverified",
            }
        ),
        "training_ready": not blockers,
        "ready_for_training": not blockers,
        "datasets": datasets,
        "feature_contract_summaries": {
            "allowed_unsw_only_flow_common_features": list(MODEL_INPUT_FEATURE_NAMES),
            "allowed_common_network_features_for_cic_unsw": list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES),
            "allowed_host_behavior_v1_features": list(HOST_BEHAVIOR_V1_ALLOWED_MODEL_FIELDS),
            "host_event_contract_status": "host_behavior_v1_aggregate_only",
            "network_prohibited_predictors": sorted(NETWORK_BEHAVIOR_V1_FORBIDDEN_MODEL_FIELDS),
            "host_prohibited_predictors": sorted(HOST_BEHAVIOR_V1_PROHIBITED_MODEL_FIELDS),
            "dst_port_cross_dataset_status": "allowed_behavioral_feature",
            "provenance_fields_never_predictors": sorted(
                PROHIBITED_PREDICTOR_FIELDS
                - {"label", "attack_category", "attack_name", "mitre_attack_id"}
            ),
            "labels_and_attack_names_never_predictors": [
                "label",
                "attack_category",
                "attack_name",
                "mitre_attack_id",
            ],
        },
        "leakage_checks": leakage_checks,
        "split_policy_checks": split_policy_checks,
        "blockers": sorted(blockers),
        "warnings": sorted(warnings),
    }
    payload["training_ready"] = not payload["blockers"]
    payload["ready_for_training"] = payload["training_ready"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _parser() -> argparse.ArgumentParser:
    project_root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=project_root)
    parser.add_argument("--manifest-directory", type=Path, default=project_root / "data/manifests")
    parser.add_argument("--report-directory", type=Path, default=project_root / "artifacts/reports")
    parser.add_argument(
        "--output",
        type=Path,
        default=project_root / "artifacts/reports/phase0/phase0_readiness.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the audit and print only safe status codes and a report basename."""
    args = _parser().parse_args(argv)
    payload = run_audit(
        args.project_root,
        args.manifest_directory,
        args.report_directory,
        args.output,
    )
    print(
        f"pipeline_ready={payload['pipeline_ready']} "
        f"training_ready={payload['training_ready']} "
        f"blockers={payload['blockers']} warnings={payload['warnings']} "
        f"report={args.output.name}"
    )
    return 0 if payload["ready_for_training"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
