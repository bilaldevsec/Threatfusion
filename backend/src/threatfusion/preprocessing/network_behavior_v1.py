"""Train-only preprocessing for the frozen UNSW network development assignment."""

from __future__ import annotations

import csv
import gzip
import importlib.metadata
import json
import math
import platform
import re
import shutil
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from numpy.lib.format import open_memmap
from pydantic import ValidationError

from threatfusion.datasets.adapters.base import SourceRowValidationError
from threatfusion.datasets.adapters.unsw_nb15 import adapt_unsw_row
from threatfusion.datasets.unsw_development_split import (
    ASSIGNMENT_SCHEMA_VERSION,
    ASSIGNMENT_SEED,
)
from threatfusion.datasets.unsw_raw import UnswRawReader
from threatfusion.datasets.unsw_split_preflight import (
    PREFLIGHT_SCHEMA_VERSION,
    RegisteredUnswInputs,
    UnswSplitPreflightError,
    verify_registered_unsw_inputs,
)
from threatfusion.features.network_behavior import (
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
    NETWORK_BEHAVIOR_V1_FEATURES,
    NetworkBehaviorRecord,
    assert_network_behavior_model_fields,
    project_network_behavior,
)
from threatfusion.utils.checksum import sha256_file

PREPROCESSING_SCHEMA_VERSION = "network_behavior_v1_preprocessing_v1"
FIXED_PROTOCOL_CATEGORIES: tuple[str, ...] = ("tcp", "udp", "icmp", "other")
LABEL_MAPPING: dict[str, int] = {"Normal": 0, "Attack": 1}
NUMERIC_FEATURE_NAMES: tuple[str, ...] = tuple(
    feature.name for feature in NETWORK_BEHAVIOR_V1_FEATURES if feature.dtype != "category"
)
CATEGORY_FEATURE_NAMES: tuple[str, ...] = tuple(
    feature.name for feature in NETWORK_BEHAVIOR_V1_FEATURES if feature.dtype == "category"
)
TRANSFORMED_FEATURE_NAMES: tuple[str, ...] = (
    *(f"{name}__zscore" for name in NUMERIC_FEATURE_NAMES),
    *(f"protocol={category}" for category in FIXED_PROTOCOL_CATEGORIES),
)
DEFAULT_BATCH_SIZE = 10_000
DEFAULT_ARTIFACT_BUDGET_BYTES = 2 * 1024**3
DEFAULT_MINIMUM_FREE_BYTES = 2 * 1024**3
NUMERIC_TOLERANCE = 1e-12
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_ASSIGNMENT_HEADER = ("record_id", "group_id", "disposition", "reason")
_DISPOSITIONS = ("train", "validation", "test", "quarantine", "rejected")


class NetworkPreprocessingError(RuntimeError):
    """Sanitized fail-closed preprocessing error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PreprocessingConfig:
    """Bounded resource settings for one immutable output run."""

    batch_size: int = DEFAULT_BATCH_SIZE
    artifact_budget_bytes: int = DEFAULT_ARTIFACT_BUDGET_BYTES
    minimum_free_bytes: int = DEFAULT_MINIMUM_FREE_BYTES

    def __post_init__(self) -> None:
        if self.batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if self.artifact_budget_bytes <= 0:
            raise ValueError("artifact_budget_bytes must be positive")
        if self.minimum_free_bytes < 0:
            raise ValueError("minimum_free_bytes must not be negative")


@dataclass(frozen=True, slots=True)
class AssignmentEvidence:
    """Verified assignment and source binding used by a preprocessing run."""

    inputs: RegisteredUnswInputs
    report: dict[str, Any]
    report_sha256: str
    assignment_path: Path
    assignment_sha256: str
    preflight_report_path: Path
    preflight_report_sha256: str
    total_rows: int


@dataclass(frozen=True, slots=True)
class AssignedRecord:
    """One source row joined to its exact global assignment ordinal."""

    record_id: int
    disposition: str
    flow: NetworkBehaviorRecord | None


@dataclass(frozen=True, slots=True)
class PreprocessingRunResult:
    """Safe aggregate result from a completed full preprocessing run."""

    report_path: Path
    state_path: Path
    train_rows: int
    validation_rows: int
    output_features: int
    elapsed_seconds: float


class _RunningStatistics:
    """Mergeable population moments retaining only fixed-size numeric state."""

    def __init__(self, width: int) -> None:
        self.count = 0
        self.mean = np.zeros(width, dtype=np.float64)
        self.m2 = np.zeros(width, dtype=np.float64)

    def update(self, values: np.ndarray) -> None:
        if values.ndim != 2 or values.shape[1] != self.mean.size:
            raise NetworkPreprocessingError("numeric_batch_shape_invalid")
        if not np.isfinite(values).all():
            raise NetworkPreprocessingError("non_finite_predictor")
        batch_count = values.shape[0]
        if batch_count == 0:
            return
        batch_mean = values.mean(axis=0, dtype=np.float64)
        centered = values - batch_mean
        batch_m2 = np.sum(centered * centered, axis=0, dtype=np.float64)
        if self.count == 0:
            self.count = batch_count
            self.mean = batch_mean
            self.m2 = batch_m2
            return
        combined_count = self.count + batch_count
        delta = batch_mean - self.mean
        self.mean += delta * (batch_count / combined_count)
        self.m2 += batch_m2 + delta * delta * (self.count * batch_count / combined_count)
        self.count = combined_count


@dataclass(frozen=True, slots=True)
class NetworkBehaviorPreprocessor:
    """Serializable z-score and fixed-category encoder for network_behavior_v1."""

    training_row_count: int
    numeric_means: tuple[float, ...]
    numeric_scales: tuple[float, ...]
    zero_variance_features: tuple[str, ...]

    def __post_init__(self) -> None:
        assert_network_behavior_model_fields(NETWORK_BEHAVIOR_V1_FEATURE_NAMES)
        if CATEGORY_FEATURE_NAMES != ("protocol",):
            raise ValueError("network_behavior_v1 categorical specification changed")
        if self.training_row_count <= 0:
            raise ValueError("training_row_count must be positive")
        if len(self.numeric_means) != len(NUMERIC_FEATURE_NAMES) or len(self.numeric_scales) != len(
            NUMERIC_FEATURE_NAMES
        ):
            raise ValueError("numeric state width does not match network_behavior_v1")
        if not all(math.isfinite(value) for value in self.numeric_means):
            raise ValueError("numeric means must be finite")
        if not all(math.isfinite(value) and value > 0 for value in self.numeric_scales):
            raise ValueError("numeric scales must be finite and positive")
        if not set(self.zero_variance_features) <= set(NUMERIC_FEATURE_NAMES):
            raise ValueError("zero-variance feature is outside network_behavior_v1")

    @classmethod
    def fit(
        cls,
        training_records: Iterable[NetworkBehaviorRecord],
        *,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ) -> NetworkBehaviorPreprocessor:
        """Fit numeric moments from the supplied TRAIN-only iterable."""
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        statistics = _RunningStatistics(len(NUMERIC_FEATURE_NAMES))
        batch: list[np.ndarray] = []
        for record in training_records:
            numeric, _ = _validated_projection(record)
            batch.append(numeric)
            if len(batch) >= batch_size:
                statistics.update(np.stack(batch))
                batch.clear()
        if batch:
            statistics.update(np.stack(batch))
        return cls.from_statistics(statistics)

    @classmethod
    def from_statistics(cls, statistics: _RunningStatistics) -> NetworkBehaviorPreprocessor:
        if statistics.count <= 0:
            raise NetworkPreprocessingError("training_partition_empty")
        variances = statistics.m2 / statistics.count
        variances = np.maximum(variances, 0.0)
        raw_scales = np.sqrt(variances)
        zero_mask = raw_scales == 0.0
        scales = np.where(zero_mask, 1.0, raw_scales)
        return cls(
            training_row_count=statistics.count,
            numeric_means=tuple(float(value) for value in statistics.mean),
            numeric_scales=tuple(float(value) for value in scales),
            zero_variance_features=tuple(
                name for name, zero in zip(NUMERIC_FEATURE_NAMES, zero_mask, strict=True) if zero
            ),
        )

    def transform(self, record: NetworkBehaviorRecord) -> np.ndarray:
        """Transform one later record without modifying fitted state."""
        numeric, category = _validated_projection(record)
        result = np.zeros(len(TRANSFORMED_FEATURE_NAMES), dtype=np.float64)
        result[: len(NUMERIC_FEATURE_NAMES)] = (
            numeric - np.asarray(self.numeric_means)
        ) / np.asarray(self.numeric_scales)
        result[len(NUMERIC_FEATURE_NAMES) + FIXED_PROTOCOL_CATEGORIES.index(category)] = 1.0
        if not np.isfinite(result).all():
            raise NetworkPreprocessingError("non_finite_transformed_value")
        return result

    def transform_batch(self, records: Sequence[NetworkBehaviorRecord]) -> np.ndarray:
        """Transform a caller-bounded batch in stable input order."""
        output = np.empty((len(records), len(TRANSFORMED_FEATURE_NAMES)), dtype=np.float64)
        for index, record in enumerate(records):
            output[index] = self.transform(record)
        return output

    def transform_unscaled_matrix_in_place(self, matrix: np.memmap, batch_size: int) -> None:
        """Standardize numeric columns of a disk-backed, already encoded matrix."""
        means = np.asarray(self.numeric_means)
        scales = np.asarray(self.numeric_scales)
        for start in range(0, matrix.shape[0], batch_size):
            stop = min(start + batch_size, matrix.shape[0])
            numeric = matrix[start:stop, : len(NUMERIC_FEATURE_NAMES)]
            if not np.isfinite(numeric).all():
                raise NetworkPreprocessingError("non_finite_predictor")
            numeric[:] = (numeric - means) / scales
            if not np.isfinite(matrix[start:stop]).all():
                raise NetworkPreprocessingError("non_finite_transformed_value")
        matrix.flush()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PREPROCESSING_SCHEMA_VERSION,
            "feature_contract": "network_behavior_v1",
            "input_feature_names": list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES),
            "numeric_feature_names": list(NUMERIC_FEATURE_NAMES),
            "categorical_feature_names": list(CATEGORY_FEATURE_NAMES),
            "fixed_category_vocabularies": {"protocol": list(FIXED_PROTOCOL_CATEGORIES)},
            "learned_category_vocabularies": {},
            "unknown_category_policy": "reject",
            "numeric_transform": "population_zscore",
            "numeric_means": list(self.numeric_means),
            "numeric_scales": list(self.numeric_scales),
            "zero_variance_policy": "scale_by_one",
            "zero_variance_features": list(self.zero_variance_features),
            "non_finite_policy": "reject",
            "training_partition": "train",
            "training_row_count": self.training_row_count,
            "label_mapping": LABEL_MAPPING,
            "transformed_feature_names": list(TRANSFORMED_FEATURE_NAMES),
            "output_dtype": "float64",
            "batch_equivalence_tolerance": NUMERIC_TOLERANCE,
        }

    def save(self, path: Path) -> None:
        _write_json(path, self.to_dict())

    @classmethod
    def load(cls, path: Path) -> NetworkBehaviorPreprocessor:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise NetworkPreprocessingError("fitted_state_unreadable") from exc
        expected_static = {
            "schema_version": PREPROCESSING_SCHEMA_VERSION,
            "feature_contract": "network_behavior_v1",
            "input_feature_names": list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES),
            "numeric_feature_names": list(NUMERIC_FEATURE_NAMES),
            "categorical_feature_names": list(CATEGORY_FEATURE_NAMES),
            "fixed_category_vocabularies": {"protocol": list(FIXED_PROTOCOL_CATEGORIES)},
            "learned_category_vocabularies": {},
            "unknown_category_policy": "reject",
            "numeric_transform": "population_zscore",
            "zero_variance_policy": "scale_by_one",
            "non_finite_policy": "reject",
            "training_partition": "train",
            "label_mapping": LABEL_MAPPING,
            "transformed_feature_names": list(TRANSFORMED_FEATURE_NAMES),
            "output_dtype": "float64",
            "batch_equivalence_tolerance": NUMERIC_TOLERANCE,
        }
        if any(payload.get(key) != value for key, value in expected_static.items()):
            raise NetworkPreprocessingError("fitted_state_contract_mismatch")
        try:
            return cls(
                training_row_count=int(payload["training_row_count"]),
                numeric_means=tuple(float(value) for value in payload["numeric_means"]),
                numeric_scales=tuple(float(value) for value in payload["numeric_scales"]),
                zero_variance_features=tuple(payload["zero_variance_features"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise NetworkPreprocessingError("fitted_state_invalid") from exc


def _validated_projection(record: NetworkBehaviorRecord) -> tuple[np.ndarray, str]:
    values = project_network_behavior(record)
    if len(values) != len(NETWORK_BEHAVIOR_V1_FEATURE_NAMES):
        raise NetworkPreprocessingError("predictor_width_mismatch")
    try:
        numeric = np.asarray(values[: len(NUMERIC_FEATURE_NAMES)], dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise NetworkPreprocessingError("numeric_predictor_invalid") from exc
    if not np.isfinite(numeric).all():
        raise NetworkPreprocessingError("non_finite_predictor")
    category = str(values[-1])
    if category not in FIXED_PROTOCOL_CATEGORIES:
        raise NetworkPreprocessingError("unknown_protocol_category")
    return numeric, category


def encode_binary_label(label: object) -> int:
    """Map the canonical stable binary labels without inference or coercion."""
    try:
        return LABEL_MAPPING[str(label)]
    except KeyError as exc:
        raise NetworkPreprocessingError("unknown_binary_label") from exc


def _read_json(path: Path, error_code: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NetworkPreprocessingError(error_code) from exc
    if not isinstance(payload, dict):
        raise NetworkPreprocessingError(error_code)
    return payload


def _validated_split_counts(report: dict[str, Any]) -> tuple[dict[str, dict[str, int | None]], int]:
    raw_counts = report.get("split_counts")
    if not isinstance(raw_counts, dict) or set(raw_counts) != set(_DISPOSITIONS):
        raise NetworkPreprocessingError("assignment_count_evidence_invalid")
    counts: dict[str, dict[str, int | None]] = {}
    total_rows = 0
    for disposition in _DISPOSITIONS:
        item = raw_counts.get(disposition)
        if not isinstance(item, dict):
            raise NetworkPreprocessingError("assignment_count_evidence_invalid")
        total = item.get("total_count")
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise NetworkPreprocessingError("assignment_count_evidence_invalid")
        benign = item.get("benign_count")
        attack = item.get("attack_count")
        if disposition == "rejected":
            if benign is not None or attack is not None:
                raise NetworkPreprocessingError("assignment_count_evidence_invalid")
        elif (
            not isinstance(benign, int)
            or isinstance(benign, bool)
            or benign < 0
            or not isinstance(attack, int)
            or isinstance(attack, bool)
            or attack < 0
            or benign + attack != total
        ):
            raise NetworkPreprocessingError("assignment_count_evidence_invalid")
        counts[disposition] = {
            "total_count": total,
            "benign_count": benign,
            "attack_count": attack,
        }
        total_rows += total
    return counts, total_rows


def verify_assignment_evidence(
    project_root: Path,
    manifest_path: Path,
    assignment_directory: Path,
    preflight_report_path: Path,
) -> AssignmentEvidence:
    """Verify complete assignment evidence and bind it to registered source hashes."""
    project_root = project_root.resolve()
    assignment_directory = assignment_directory.resolve()
    expected_parent = (project_root / "data/interim/unsw_development_split").resolve()
    if not assignment_directory.is_relative_to(expected_parent):
        raise NetworkPreprocessingError("assignment_directory_outside_data_interim")
    try:
        inputs = verify_registered_unsw_inputs(project_root, manifest_path.resolve())
    except (OSError, ValueError, UnswSplitPreflightError) as exc:
        raise NetworkPreprocessingError("registered_source_verification_failed") from exc
    report_path = assignment_directory / "assignment_report.json"
    assignment_path = assignment_directory / "assignments.csv.gz"
    report = _read_json(report_path, "assignment_report_unreadable")
    preflight_report = _read_json(preflight_report_path.resolve(), "preflight_report_unreadable")
    counts, total_rows = _validated_split_counts(report)
    expected_total = sum(int(item.rows or 0) for item in inputs.raw_files)
    audit = report.get("assignment_audit")
    provenance = report.get("provenance")
    required_audit = {
        "all_accepted_rows_grouped",
        "all_groups_have_one_decision",
        "all_selected_rows_accounted_once",
        "canonical_split_policy_validated_in_bounded_batches",
        "enforced_group_cross_split_count_zero",
        "train_has_benign_and_attack",
        "validation_has_benign_and_attack",
    }
    if (
        report.get("schema_version") != ASSIGNMENT_SCHEMA_VERSION
        or report.get("completed") is not True
        or report.get("creates_final_assignments") is not True
        or report.get("run_scope") != "full"
        or report.get("network_split_status") != "verified"
        or report.get("source_dataset") != "unsw_nb15"
        or report.get("policy", {}).get("seed") != ASSIGNMENT_SEED
        or not isinstance(audit, dict)
        or any(audit.get(name) is not True for name in required_audit)
        or not isinstance(provenance, dict)
        or provenance.get("manifest_sha256") != inputs.manifest_digest
        or provenance.get("preflight_schema_version") != PREFLIGHT_SCHEMA_VERSION
        or provenance.get("registered_raw_files") != [item.path.name for item in inputs.raw_files]
        or total_rows != expected_total
        or audit.get("artifact_row_count") != expected_total
        or audit.get("artifact_file") != assignment_path.name
        or counts["rejected"]["total_count"]
        + sum(int(counts[name]["total_count"] or 0) for name in _DISPOSITIONS[:-1])
        != expected_total
    ):
        raise NetworkPreprocessingError("assignment_evidence_not_complete_or_consistent")
    preflight_checks = preflight_report.get("checks")
    required_preflight_checks = {
        "accounting_reconciled",
        "diagnostics_succeeded",
        "feature_metadata_verified",
        "inputs_fully_exhausted",
        "manifest_verified",
        "working_disk_budget_respected",
    }
    if (
        preflight_report.get("schema_version") != PREFLIGHT_SCHEMA_VERSION
        or preflight_report.get("completed") is not True
        or preflight_report.get("run_scope") != "full"
        or preflight_report.get("creates_assignments") is not False
        or not isinstance(preflight_checks, dict)
        or any(preflight_checks.get(name) is not True for name in required_preflight_checks)
        or preflight_report.get("manifest", {}).get("sha256") != inputs.manifest_digest
        or preflight_report.get("overall", {}).get("total_input_rows") != expected_total
        or preflight_report.get("overall", {}).get("rejected_count")
        != counts["rejected"]["total_count"]
    ):
        raise NetworkPreprocessingError("preflight_evidence_not_complete_or_consistent")
    preflight_hash = sha256_file(preflight_report_path)
    if provenance.get("preflight_report_sha256") != preflight_hash:
        raise NetworkPreprocessingError("preflight_report_hash_mismatch")
    if not assignment_path.is_file():
        raise NetworkPreprocessingError("assignment_archive_missing")
    assignment_hash = sha256_file(assignment_path)
    if audit.get("artifact_sha256") != assignment_hash:
        raise NetworkPreprocessingError("assignment_archive_hash_mismatch")
    return AssignmentEvidence(
        inputs=inputs,
        report=report,
        report_sha256=sha256_file(report_path),
        assignment_path=assignment_path,
        assignment_sha256=assignment_hash,
        preflight_report_path=preflight_report_path.resolve(),
        preflight_report_sha256=preflight_hash,
        total_rows=expected_total,
    )


def _validate_assignment_row(row: list[str], expected_record_id: int) -> tuple[str, str]:
    if len(row) != len(_ASSIGNMENT_HEADER):
        raise NetworkPreprocessingError("assignment_row_shape_invalid")
    record_text, group_id, disposition, reason = row
    try:
        record_id = int(record_text)
    except ValueError as exc:
        raise NetworkPreprocessingError("assignment_record_id_invalid") from exc
    if record_id != expected_record_id:
        raise NetworkPreprocessingError("assignment_record_order_or_coverage_invalid")
    if disposition not in _DISPOSITIONS:
        raise NetworkPreprocessingError("assignment_disposition_invalid")
    if disposition == "rejected":
        if group_id or reason != "source_rejected":
            raise NetworkPreprocessingError("rejected_assignment_invalid")
    else:
        if len(group_id) != 64 or group_id.lower() != group_id:
            raise NetworkPreprocessingError("assignment_group_id_invalid")
        try:
            bytes.fromhex(group_id)
        except ValueError as exc:
            raise NetworkPreprocessingError("assignment_group_id_invalid") from exc
        if disposition == "quarantine":
            if not reason:
                raise NetworkPreprocessingError("quarantine_reason_missing")
        elif reason:
            raise NetworkPreprocessingError("selected_assignment_reason_invalid")
    return disposition, reason


def _adapt_for_assignment(row: dict[str, str]) -> NetworkBehaviorRecord | None:
    try:
        return adapt_unsw_row(row)
    except (SourceRowValidationError, ValidationError, OverflowError, OSError):
        return None


def iter_assigned_source_records(
    project_root: Path,
    evidence: AssignmentEvidence,
    *,
    max_records: int | None = None,
) -> Iterator[AssignedRecord]:
    """Stream an ordinal one-to-one source/assignment join, failing on every mismatch."""
    if max_records is not None and max_records <= 0:
        raise ValueError("max_records must be positive")
    record_id = 0
    with gzip.open(evidence.assignment_path, mode="rt", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        try:
            header = tuple(next(reader))
        except (StopIteration, OSError, EOFError) as exc:
            raise NetworkPreprocessingError("assignment_archive_unreadable") from exc
        if header != _ASSIGNMENT_HEADER:
            raise NetworkPreprocessingError("assignment_header_invalid")
        for item in evidence.inputs.raw_files:
            expected_file_rows = int(item.rows or 0)
            raw_path = (project_root.resolve() / item.path).resolve()
            file_rows = 0
            for row in UnswRawReader(evidence.inputs.feature_names, (raw_path,)):
                record_id += 1
                file_rows += 1
                try:
                    assignment_row = next(reader)
                except StopIteration as exc:
                    raise NetworkPreprocessingError("assignment_archive_truncated") from exc
                disposition, _ = _validate_assignment_row(assignment_row, record_id)
                flow = _adapt_for_assignment(row)
                if (flow is None) != (disposition == "rejected"):
                    raise NetworkPreprocessingError("source_assignment_acceptance_mismatch")
                yield AssignedRecord(record_id, disposition, flow)
                if max_records is not None and record_id >= max_records:
                    return
            if file_rows != expected_file_rows:
                raise NetworkPreprocessingError("registered_source_row_count_mismatch")
        try:
            extra = next(reader)
        except StopIteration:
            extra = None
        if extra is not None or record_id != evidence.total_rows:
            raise NetworkPreprocessingError("assignment_record_order_or_coverage_invalid")


def _unscaled_batch(records: Sequence[NetworkBehaviorRecord]) -> tuple[np.ndarray, np.ndarray]:
    matrix = np.zeros((len(records), len(TRANSFORMED_FEATURE_NAMES)), dtype=np.float64)
    numeric_width = len(NUMERIC_FEATURE_NAMES)
    for index, record in enumerate(records):
        numeric, category = _validated_projection(record)
        matrix[index, :numeric_width] = numeric
        matrix[index, numeric_width + FIXED_PROTOCOL_CATEGORIES.index(category)] = 1.0
    labels = np.asarray([encode_binary_label(record.label) for record in records], dtype=np.uint8)
    return matrix, labels


def _safe_artifact_root(project_root: Path, artifact_root: Path) -> Path:
    resolved = artifact_root.resolve()
    if not resolved.is_relative_to((project_root.resolve() / "data/processed").resolve()):
        raise NetworkPreprocessingError("artifact_root_must_be_under_data_processed")
    return resolved


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _dependency_versions() -> dict[str, str]:
    versions = {"python": platform.python_version(), "numpy": np.__version__}
    for package in ("pandas", "pydantic"):
        versions[package] = importlib.metadata.version(package)
    return versions


def _guard_artifact_space(run_directory: Path, config: PreprocessingConfig) -> None:
    size = sum(path.stat().st_size for path in run_directory.iterdir() if path.is_file())
    if size > config.artifact_budget_bytes:
        raise NetworkPreprocessingError("artifact_budget_exceeded")
    if shutil.disk_usage(run_directory).free < config.minimum_free_bytes:
        raise NetworkPreprocessingError("minimum_free_space_violated")


def _expected_output_bytes(train_rows: int, validation_rows: int) -> int:
    rows = train_rows + validation_rows
    return rows * len(TRANSFORMED_FEATURE_NAMES) * np.dtype(np.float64).itemsize + rows


def _flush_partition_batch(
    records: list[NetworkBehaviorRecord],
    matrix: np.memmap,
    labels: np.memmap,
    offset: int,
    statistics: _RunningStatistics | None,
) -> int:
    if not records:
        return offset
    encoded, encoded_labels = _unscaled_batch(records)
    stop = offset + len(records)
    if stop > matrix.shape[0]:
        raise NetworkPreprocessingError("assignment_partition_count_exceeded")
    matrix[offset:stop] = encoded
    labels[offset:stop] = encoded_labels
    if statistics is not None:
        statistics.update(encoded[:, : len(NUMERIC_FEATURE_NAMES)])
    records.clear()
    return stop


def _verify_matrix(matrix: np.memmap, batch_size: int) -> bool:
    return all(
        np.isfinite(matrix[start : min(start + batch_size, matrix.shape[0])]).all()
        for start in range(0, matrix.shape[0], batch_size)
    )


def _report_counts_match(
    evidence: AssignmentEvidence,
    dispositions: Counter[str],
    labels: dict[str, Counter[int]],
) -> bool:
    expected = evidence.report["split_counts"]
    for disposition in _DISPOSITIONS:
        if dispositions[disposition] != expected[disposition]["total_count"]:
            return False
        if disposition != "rejected" and (
            labels[disposition][0] != expected[disposition]["benign_count"]
            or labels[disposition][1] != expected[disposition]["attack_count"]
        ):
            return False
    return True


def run_unsw_network_preprocessing(
    project_root: Path,
    manifest_path: Path,
    assignment_directory: Path,
    preflight_report_path: Path,
    artifact_root: Path,
    run_id: str,
    config: PreprocessingConfig = PreprocessingConfig(),
    progress: Callable[[int, int], None] | None = None,
) -> PreprocessingRunResult:
    """Fit on complete TRAIN and transform only TRAIN/VALIDATION to disk-backed arrays."""
    started = time.monotonic()
    if not _RUN_ID.fullmatch(run_id):
        raise NetworkPreprocessingError("invalid_run_id")
    project_root = project_root.resolve()
    evidence = verify_assignment_evidence(
        project_root, manifest_path, assignment_directory, preflight_report_path
    )
    artifact_root = _safe_artifact_root(project_root, artifact_root)
    artifact_root.mkdir(parents=True, exist_ok=True)
    run_directory = artifact_root / run_id
    try:
        run_directory.mkdir()
    except FileExistsError as exc:
        raise NetworkPreprocessingError("run_directory_already_exists") from exc
    split_counts = evidence.report["split_counts"]
    train_rows = int(split_counts["train"]["total_count"])
    validation_rows = int(split_counts["validation"]["total_count"])
    if _expected_output_bytes(train_rows, validation_rows) > config.artifact_budget_bytes:
        raise NetworkPreprocessingError("configured_artifact_budget_too_small")
    if shutil.disk_usage(run_directory).free < (
        _expected_output_bytes(train_rows, validation_rows) + config.minimum_free_bytes
    ):
        raise NetworkPreprocessingError("insufficient_free_space")

    temporary_paths = {
        "X_train": run_directory / "X_train.partial.npy",
        "y_train": run_directory / "y_train.partial.npy",
        "X_validation": run_directory / "X_validation.partial.npy",
        "y_validation": run_directory / "y_validation.partial.npy",
    }
    matrices = {
        "train": open_memmap(
            temporary_paths["X_train"],
            mode="w+",
            dtype=np.float64,
            shape=(train_rows, len(TRANSFORMED_FEATURE_NAMES)),
        ),
        "validation": open_memmap(
            temporary_paths["X_validation"],
            mode="w+",
            dtype=np.float64,
            shape=(validation_rows, len(TRANSFORMED_FEATURE_NAMES)),
        ),
    }
    label_arrays = {
        "train": open_memmap(
            temporary_paths["y_train"], mode="w+", dtype=np.uint8, shape=(train_rows,)
        ),
        "validation": open_memmap(
            temporary_paths["y_validation"],
            mode="w+",
            dtype=np.uint8,
            shape=(validation_rows,),
        ),
    }
    buffers: dict[str, list[NetworkBehaviorRecord]] = {"train": [], "validation": []}
    offsets = {"train": 0, "validation": 0}
    dispositions: Counter[str] = Counter()
    labels = {name: Counter() for name in _DISPOSITIONS}
    statistics = _RunningStatistics(len(NUMERIC_FEATURE_NAMES))
    processed = 0
    try:
        for assigned in iter_assigned_source_records(project_root, evidence):
            processed += 1
            dispositions[assigned.disposition] += 1
            if assigned.flow is not None:
                label = encode_binary_label(assigned.flow.label)
                labels[assigned.disposition][label] += 1
            if assigned.disposition in buffers:
                if assigned.flow is None:  # pragma: no cover - guarded by join invariant
                    raise NetworkPreprocessingError("selected_source_record_missing")
                partition = assigned.disposition
                buffers[partition].append(assigned.flow)
                if len(buffers[partition]) >= config.batch_size:
                    offsets[partition] = _flush_partition_batch(
                        buffers[partition],
                        matrices[partition],
                        label_arrays[partition],
                        offsets[partition],
                        statistics if partition == "train" else None,
                    )
            if progress is not None and processed % 250_000 == 0:
                progress(processed, evidence.total_rows)
        for partition in ("train", "validation"):
            offsets[partition] = _flush_partition_batch(
                buffers[partition],
                matrices[partition],
                label_arrays[partition],
                offsets[partition],
                statistics if partition == "train" else None,
            )
        if offsets != {"train": train_rows, "validation": validation_rows}:
            raise NetworkPreprocessingError("assignment_partition_count_mismatch")
        if not _report_counts_match(evidence, dispositions, labels):
            raise NetworkPreprocessingError("assignment_report_count_reconciliation_failed")

        fitted = NetworkBehaviorPreprocessor.from_statistics(statistics)
        state_path = run_directory / "preprocessor_state.json"
        fitted.save(state_path)
        reloaded = NetworkBehaviorPreprocessor.load(state_path)
        if reloaded.to_dict() != fitted.to_dict():
            raise NetworkPreprocessingError("fitted_state_reload_mismatch")
        for partition in ("train", "validation"):
            reloaded.transform_unscaled_matrix_in_place(matrices[partition], config.batch_size)
            label_arrays[partition].flush()
            if not _verify_matrix(matrices[partition], config.batch_size):
                raise NetworkPreprocessingError("non_finite_transformed_value")
        for key, temporary in temporary_paths.items():
            temporary.replace(run_directory / f"{key}.npy")

        configuration = {
            "schema_version": PREPROCESSING_SCHEMA_VERSION,
            "feature_contract": "network_behavior_v1",
            "input_feature_names": list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES),
            "numeric_feature_names": list(NUMERIC_FEATURE_NAMES),
            "categorical_feature_names": list(CATEGORY_FEATURE_NAMES),
            "transformed_feature_names": list(TRANSFORMED_FEATURE_NAMES),
            "transformations": {
                "numeric": "population z-score fitted on train only",
                "protocol": "fixed contract categories one-hot encoded",
                "unknown_categories": "reject",
                "non_finite_values": "reject",
                "zero_variance_numeric": "center and divide by one",
            },
            "excluded_from_predictors": "all fields outside the exact contract allowlist",
            "label_mapping": LABEL_MAPPING,
            "fit_partition": "train",
            "transform_partitions": ["train", "validation"],
            "output_dtype": "float64",
            "batch_size": config.batch_size,
            "artifact_budget_bytes": config.artifact_budget_bytes,
            "minimum_free_bytes": config.minimum_free_bytes,
            "source": {
                "manifest_sha256": evidence.inputs.manifest_digest,
                "registered_raw_files": [
                    {
                        "name": item.path.name,
                        "rows": item.rows,
                        "sha256": item.sha256,
                    }
                    for item in evidence.inputs.raw_files
                ],
            },
            "assignment": {
                "schema_version": ASSIGNMENT_SCHEMA_VERSION,
                "seed": ASSIGNMENT_SEED,
                "report_sha256": evidence.report_sha256,
                "archive_sha256": evidence.assignment_sha256,
                "preflight_report_sha256": evidence.preflight_report_sha256,
            },
            "dependencies": _dependency_versions(),
        }
        configuration_path = run_directory / "preprocessing_config.json"
        _write_json(configuration_path, configuration)
        output_files = {
            name: {
                "sha256": sha256_file(run_directory / f"{name}.npy"),
                "size_bytes": (run_directory / f"{name}.npy").stat().st_size,
            }
            for name in ("X_train", "y_train", "X_validation", "y_validation")
        }
        elapsed = time.monotonic() - started
        report = {
            "schema_version": PREPROCESSING_SCHEMA_VERSION,
            "completed": True,
            "global_training_ready": False,
            "fit_partition": "train",
            "transformed_partitions": ["train", "validation"],
            "input_feature_count": len(NETWORK_BEHAVIOR_V1_FEATURE_NAMES),
            "input_feature_names": list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES),
            "output_feature_count": len(TRANSFORMED_FEATURE_NAMES),
            "output_feature_names": list(TRANSFORMED_FEATURE_NAMES),
            "row_order": "registered raw file order then one-based source row; filtered per split",
            "counts": {
                "train": {
                    "rows": train_rows,
                    "benign": labels["train"][0],
                    "attack": labels["train"][1],
                },
                "validation": {
                    "rows": validation_rows,
                    "benign": labels["validation"][0],
                    "attack": labels["validation"][1],
                },
                "excluded": {
                    name: dispositions[name] for name in ("test", "quarantine", "rejected")
                },
            },
            "shapes": {
                "X_train": [train_rows, len(TRANSFORMED_FEATURE_NAMES)],
                "y_train": [train_rows],
                "X_validation": [validation_rows, len(TRANSFORMED_FEATURE_NAMES)],
                "y_validation": [validation_rows],
            },
            "checks": {
                "assignment_and_source_counts_reconciled": True,
                "assignment_evidence_verified": True,
                "fitted_state_reload_equivalent": True,
                "matrices_finite": True,
                "only_train_influenced_fitted_state": True,
                "test_and_cic_not_transformed": True,
            },
            "hashes": {
                "configuration": sha256_file(configuration_path),
                "fitted_state": sha256_file(state_path),
                "outputs": output_files,
            },
            "runtime_seconds": elapsed,
            "artifact_size_bytes_excluding_report": sum(
                path.stat().st_size for path in run_directory.iterdir() if path.is_file()
            ),
            "limitations": [
                "capture and session provenance remain unresolved",
                "near-duplicate leakage is not assessed",
                "held-out February UNSW and CIC remain untransformed and unevaluated",
                "this preprocessing run does not change global training readiness",
            ],
        }
        report_path = run_directory / "preprocessing_report.json"
        _write_json(report_path, report)
        _guard_artifact_space(run_directory, config)
        return PreprocessingRunResult(
            report_path=report_path,
            state_path=state_path,
            train_rows=train_rows,
            validation_rows=validation_rows,
            output_features=len(TRANSFORMED_FEATURE_NAMES),
            elapsed_seconds=elapsed,
        )
    except Exception as exc:
        code = exc.code if isinstance(exc, NetworkPreprocessingError) else "internal_failure"
        _write_json(
            run_directory / "preprocessing_failure.json",
            {
                "schema_version": PREPROCESSING_SCHEMA_VERSION,
                "completed": False,
                "failure_code": code,
            },
        )
        raise


def smoke_check_unsw_network_preprocessing(
    project_root: Path,
    manifest_path: Path,
    assignment_directory: Path,
    preflight_report_path: Path,
    max_records: int,
) -> dict[str, int]:
    """Boundedly exercise verified joining/projection without creating fitted artifacts."""
    evidence = verify_assignment_evidence(
        project_root.resolve(), manifest_path, assignment_directory, preflight_report_path
    )
    dispositions: Counter[str] = Counter()
    selected = 0
    for assigned in iter_assigned_source_records(
        project_root.resolve(), evidence, max_records=max_records
    ):
        dispositions[assigned.disposition] += 1
        if assigned.disposition in {"train", "validation"}:
            if assigned.flow is None:  # pragma: no cover - guarded by join invariant
                raise NetworkPreprocessingError("selected_source_record_missing")
            _validated_projection(assigned.flow)
            encode_binary_label(assigned.flow.label)
            selected += 1
    return {
        "records_checked": sum(dispositions.values()),
        "selected_records_checked": selected,
        **{name: dispositions[name] for name in _DISPOSITIONS},
    }
