"""Frozen external evaluation of saved network models on registered CIC exports."""

from __future__ import annotations

import importlib.metadata
import json
import platform
import re
import shutil
import subprocess
import time
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Any

import numpy as np
from numpy.lib.format import open_memmap
from threadpoolctl import threadpool_limits

from threatfusion.datasets.adapters.cic_ids2018_benchmark import (
    CIC_APPROVED_ATTACK_LABELS,
    adapt_cic_benchmark_row,
)
from threatfusion.datasets.batch import BatchQualityReport, SourceRow, stream_adapt_rows
from threatfusion.datasets.cic_processed import CIC_PROCESSED_COLUMN_COUNT, CicProcessedReader
from threatfusion.datasets.manifests import load_dataset_manifest, verify_dataset_manifest
from threatfusion.features.network_behavior import (
    CIC_IDS2018_CICFLOWMETER_V3_PROCESSED_REPRESENTATION_V1,
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
    NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
    UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
    UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1,
    NetworkCompatibilityDecision,
    NetworkCompatibilityError,
    NetworkCompatibilityKey,
    decide_network_compatibility,
    require_supported_network_compatibility,
)
from threatfusion.models.network_classical_evaluation import (
    NetworkBaselineError,
    predict_in_batches,
    verify_saved_model,
)
from threatfusion.models.network_logistic_baseline import (
    ATTACK_THRESHOLD,
    calculate_binary_metrics,
    threshold_attack_scores,
    verify_preprocessing_artifacts,
)
from threatfusion.models.network_random_forest_baseline import (
    NESTED_NUMERICAL_THREADS,
    PREDICTION_BATCH_SIZE,
)
from threatfusion.preprocessing.network_behavior_v1 import (
    LABEL_MAPPING,
    PREPROCESSING_SCHEMA_VERSION,
    TRANSFORMED_FEATURE_NAMES,
    NetworkBehaviorPreprocessor,
    encode_binary_label,
)
from threatfusion.utils.checksum import sha256_file

HISTORICAL_CIC_EVALUATION_SCHEMA_VERSION = "cic_classical_external_evaluation_v1"
CIC_EVALUATION_SCHEMA_VERSION = "cic_classical_external_evaluation_v2"
BASELINE_COMMIT = "ba21aa19aa1f6fdadd6445810581b8c291f4cc2b"
DEFAULT_BATCH_SIZE = 10_000
MINIMUM_FREE_BYTES = 2 * 1024**3
MEMORY_RESERVE_BYTES = 1024**3
REJECTION_EXAMPLE_LIMIT = 20
EXPECTED_FILES: dict[str, dict[str, int]] = {
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv": {
        "total": 1_048_575,
        "accepted": 1_048_570,
        "rejected": 5,
    },
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv": {
        "total": 1_048_575,
        "accepted": 1_048_575,
        "rejected": 0,
    },
}
CATEGORY_NAMES: tuple[str, ...] = tuple(sorted(CIC_APPROVED_ATTACK_LABELS))
CATEGORY_CODES = {name: index + 1 for index, name in enumerate(CATEGORY_NAMES)}
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_UNSW_RAW_BASENAMES = tuple(f"UNSW-NB15_{part}.csv" for part in range(1, 5))


@dataclass(frozen=True, slots=True)
class VerifiedCicFile:
    """One manifest-bound CIC file and its completed quality evidence."""

    path: Path
    basename: str
    sha256: str
    total_rows: int
    accepted_rows: int
    rejected_rows: int
    quality_report: dict[str, Any]
    quality_report_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedCicEvidence:
    """Complete registered external-benchmark evidence."""

    manifest_sha256: str
    files: tuple[VerifiedCicFile, ...]
    profile_sha256: str
    source_representation: str


@dataclass(frozen=True, slots=True)
class CicEvaluationResult:
    """Sanitized completed-run result."""

    run_directory: Path
    report_path: Path
    accepted_rows: int
    rejected_rows: int
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class HistoricalCicEvaluation:
    """Readable historical report with completion and current compatibility separated."""

    configuration: dict[str, Any]
    report: dict[str, Any]
    completed: bool
    compatibility: NetworkCompatibilityDecision


def _read_json(path: Path, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NetworkBaselineError(code) from exc
    if not isinstance(value, dict):
        raise NetworkBaselineError(code)
    return value


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def write_cic_failure_status(run_directory: Path, code: str) -> Path:
    """Persist sanitized, explicitly incomplete CIC run evidence."""
    path = run_directory / "evaluation_failure.json"
    _write_json(
        path,
        {
            "schema_version": CIC_EVALUATION_SCHEMA_VERSION,
            "completed": False,
            "failure_code": code,
        },
    )
    return path


def _quality_path(quality_directory: Path, basename: str) -> Path:
    return quality_directory / f"{Path(basename).stem}_quality.json"


def verify_cic_evidence(
    project_root: Path,
    manifest_path: Path,
    quality_directory: Path,
    profile_path: Path,
) -> VerifiedCicEvidence:
    """Verify exactly two registered files plus completed validation/profile evidence."""
    try:
        manifest = load_dataset_manifest(manifest_path)
        verification = verify_dataset_manifest(manifest, project_root)
    except Exception as exc:
        raise NetworkBaselineError("cic_manifest_unreadable") from exc
    if (
        manifest.name != "cse_cic_ids2018"
        or len(manifest.files) != 2
        or not verification.verified
        or [item.path.name for item in manifest.files] != list(EXPECTED_FILES)
    ):
        raise NetworkBaselineError("cic_manifest_evidence_mismatch")
    verified_files: list[VerifiedCicFile] = []
    for registered in manifest.files:
        basename = registered.path.name
        expected = EXPECTED_FILES[basename]
        report_path = _quality_path(quality_directory, basename)
        report = _read_json(report_path, "cic_quality_report_unreadable")
        labels = report.get("canonical_label_counts")
        categories = report.get("attack_category_counts")
        details = report.get("rejection_details")
        if (
            registered.role != "validation"
            or registered.rows != expected["total"]
            or not isinstance(registered.sha256, str)
            or report.get("completed") is not True
            or report.get("source_file") != basename
            or report.get("source") != f"CSE-CIC-IDS2018 benchmark/{basename}"
            or report.get("expected_column_count") != CIC_PROCESSED_COLUMN_COUNT
            or report.get("total_rows") != expected["total"]
            or report.get("accepted_count") != expected["accepted"]
            or report.get("rejected_count") != expected["rejected"]
            or not isinstance(labels, dict)
            or labels.get("Normal", 0) + labels.get("Attack", 0) != expected["accepted"]
            or not isinstance(categories, dict)
            or sum(categories.values()) != labels.get("Attack")
            or not isinstance(details, list)
            or len(details) > REJECTION_EXAMPLE_LIMIT
        ):
            raise NetworkBaselineError("cic_quality_evidence_mismatch")
        verified_files.append(
            VerifiedCicFile(
                path=(project_root / registered.path).resolve(),
                basename=basename,
                sha256=registered.sha256,
                total_rows=expected["total"],
                accepted_rows=expected["accepted"],
                rejected_rows=expected["rejected"],
                quality_report=report,
                quality_report_sha256=sha256_file(report_path),
            )
        )
    profile = _read_json(profile_path, "cic_profile_unreadable")
    combined = profile.get("combined")
    file_profiles = profile.get("files")
    if (
        profile.get("dataset") != "cse_cic_ids2018"
        or profile.get("benchmark_role") != "external_network_benchmark"
        or profile.get("network_behavior_v1_feature_order")
        != list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES)
        or profile.get("timestamp_semantics") != "timezone-naive; source timezone unknown"
        or not isinstance(combined, dict)
        or combined.get("completed") is not True
        or combined.get("total_rows") != sum(item.total_rows for item in verified_files)
        or combined.get("accepted_count") != sum(item.accepted_rows for item in verified_files)
        or combined.get("rejected_count") != sum(item.rejected_rows for item in verified_files)
        or not isinstance(file_profiles, list)
        or [item.get("source_file") for item in file_profiles] != list(EXPECTED_FILES)
    ):
        raise NetworkBaselineError("cic_profile_evidence_mismatch")
    return VerifiedCicEvidence(
        manifest_sha256=sha256_file(manifest_path),
        files=tuple(verified_files),
        profile_sha256=sha256_file(profile_path),
        source_representation=CIC_IDS2018_CICFLOWMETER_V3_PROCESSED_REPRESENTATION_V1,
    )


def transform_cic_records(
    rows: Iterable[SourceRow],
    preprocessor: NetworkBehaviorPreprocessor,
    matrix: np.memmap,
    labels: np.memmap,
    categories: np.memmap,
    expected_report: dict[str, Any],
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> dict[str, Any]:
    """Adapt and transform one file while preserving rejection and output alignment."""
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    quality = BatchQualityReport(
        source=str(expected_report["source"]), rejection_example_limit=REJECTION_EXAMPLE_LIMIT
    )
    canonical_labels: Counter[str] = Counter()
    attack_categories: Counter[str] = Counter()
    buffer: list[Any] = []
    offset = 0

    def flush() -> None:
        nonlocal offset
        if not buffer:
            return
        stop = offset + len(buffer)
        if stop > matrix.shape[0]:
            raise NetworkBaselineError("cic_accepted_count_exceeded")
        matrix[offset:stop] = preprocessor.transform_batch(buffer)
        labels[offset:stop] = np.asarray(
            [encode_binary_label(record.label) for record in buffer], dtype=np.uint8
        )
        categories[offset:stop] = np.asarray(
            [CATEGORY_CODES.get(record.attack_name, 0) for record in buffer], dtype=np.uint8
        )
        offset = stop
        buffer.clear()

    for record in stream_adapt_rows(rows, adapt_cic_benchmark_row, quality):
        canonical_labels[record.label] += 1
        if record.attack_name is not None:
            attack_categories[record.attack_name] += 1
        buffer.append(record)
        if len(buffer) >= batch_size:
            flush()
    flush()
    observed = {
        **quality.to_dict(),
        "source_file": expected_report["source_file"],
        "expected_column_count": CIC_PROCESSED_COLUMN_COUNT,
        "canonical_label_counts": dict(sorted(canonical_labels.items())),
        "attack_category_counts": dict(sorted(attack_categories.items())),
    }
    # Match the persisted JSON representation (notably tuple fields becoming lists).
    observed = json.loads(json.dumps(observed))
    if observed != expected_report or offset != matrix.shape[0]:
        raise NetworkBaselineError("cic_source_validation_reconciliation_failed")
    matrix.flush()
    labels.flush()
    categories.flush()
    return observed


def category_recall(
    labels: np.ndarray, scores: np.ndarray, categories: np.ndarray
) -> dict[str, Any]:
    """Return bounded attack-category support/recall metadata."""
    predictions = threshold_attack_scores(scores)
    output: dict[str, Any] = {}
    for name, code in CATEGORY_CODES.items():
        selected = categories == code
        support = int(np.count_nonzero(selected))
        if support and not np.all(labels[selected] == 1):
            raise NetworkBaselineError("cic_attack_category_label_mismatch")
        output[name] = {
            "support": support,
            "recall": (
                float(np.count_nonzero(predictions[selected] == 1) / support) if support else None
            ),
        }
    return output


def evaluate_file_and_pooled(
    models: tuple[Any, ...],
    matrices: tuple[np.ndarray, ...],
    labels: tuple[np.ndarray, ...],
    categories: tuple[np.ndarray, ...],
    basenames: tuple[str, ...],
    run_directory: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Compute primary per-file and secondary pooled metrics from pooled scores."""
    file_results = {name: {} for name in basenames}
    pooled_results: dict[str, Any] = {}
    total = sum(item.shape[0] for item in labels)
    offsets = np.cumsum([0, *(item.shape[0] for item in labels)])
    pooled_labels = open_memmap(
        run_directory / "pooled_labels.partial.npy", mode="w+", dtype=np.uint8, shape=(total,)
    )
    pooled_categories = open_memmap(
        run_directory / "pooled_categories.partial.npy", mode="w+", dtype=np.uint8, shape=(total,)
    )
    for index, (label_array, category_array) in enumerate(zip(labels, categories, strict=True)):
        pooled_labels[offsets[index] : offsets[index + 1]] = label_array
        pooled_categories[offsets[index] : offsets[index + 1]] = category_array
    for model_evidence in models:
        pooled_scores = open_memmap(
            run_directory / f"{model_evidence.name}_scores.partial.npy",
            mode="w+",
            dtype=np.float64,
            shape=(total,),
        )
        for index, (basename, matrix, label_array, category_array) in enumerate(
            zip(basenames, matrices, labels, categories, strict=True)
        ):
            scores = predict_in_batches(
                model_evidence.model, matrix, batch_size=PREDICTION_BATCH_SIZE
            )
            pooled_scores[offsets[index] : offsets[index + 1]] = scores
            file_results[basename][model_evidence.name] = {
                **calculate_binary_metrics(label_array, scores),
                "attack_categories": category_recall(label_array, scores, category_array),
            }
        pooled_scores.flush()
        pooled_results[model_evidence.name] = {
            **calculate_binary_metrics(pooled_labels, pooled_scores),
            "attack_categories": category_recall(pooled_labels, pooled_scores, pooled_categories),
        }
        del pooled_scores
        (run_directory / f"{model_evidence.name}_scores.partial.npy").unlink()
    for basename, label_array in zip(basenames, labels, strict=True):
        file_results[basename]["always_benign_reference"] = calculate_binary_metrics(
            label_array, np.zeros(label_array.shape[0], dtype=np.float64)
        )
    pooled_results["always_benign_reference"] = calculate_binary_metrics(
        pooled_labels, np.zeros(total, dtype=np.float64)
    )
    del pooled_labels, pooled_categories
    (run_directory / "pooled_labels.partial.npy").unlink()
    (run_directory / "pooled_categories.partial.npy").unlink()
    return file_results, pooled_results


def _resource_evidence(artifact_root: Path, accepted_rows: int) -> dict[str, int]:
    try:
        available = next(
            int(line.split()[1]) * 1024
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()
            if line.startswith("MemAvailable:")
        )
    except (OSError, StopIteration, ValueError, IndexError) as exc:
        raise NetworkBaselineError("available_memory_unreadable") from exc
    matrix_bytes = accepted_rows * len(TRANSFORMED_FEATURE_NAMES) * 8
    disk_outputs = matrix_bytes + accepted_rows * 2
    metric_working = accepted_rows * 8 * 10
    estimated = matrix_bytes + metric_working + 256 * 1024**2
    free = shutil.disk_usage(artifact_root).free
    if available < estimated + MEMORY_RESERVE_BYTES:
        raise NetworkBaselineError("insufficient_memory_for_cic_evaluation")
    if free < disk_outputs + MINIMUM_FREE_BYTES:
        raise NetworkBaselineError("insufficient_disk_for_cic_evaluation")
    return {
        "available_memory_bytes": available,
        "estimated_peak_memory_bytes": estimated,
        "required_memory_with_reserve_bytes": estimated + MEMORY_RESERVE_BYTES,
        "free_disk_bytes": free,
        "required_disk_with_reserve_bytes": disk_outputs + MINIMUM_FREE_BYTES,
    }


def _dependencies() -> dict[str, str]:
    versions = {"python": platform.python_version()}
    for package in ("numpy", "scipy", "scikit-learn", "joblib", "threadpoolctl"):
        versions[package] = importlib.metadata.version(package)
    return versions


def _git_provenance(project_root: Path) -> dict[str, Any]:
    def run(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=project_root, check=True, capture_output=True, text=True
        ).stdout.strip()

    return {
        "baseline_commit": BASELINE_COMMIT,
        "head": run("rev-parse", "HEAD"),
        "working_tree_dirty": bool(run("status", "--porcelain")),
    }


def _compatibility_key_for_verified_inputs(
    preprocessing: Any,
    evidence: VerifiedCicEvidence,
    models: tuple[Any, Any],
) -> NetworkCompatibilityKey:
    configuration = preprocessing.configuration
    source = configuration.get("source")
    registered_files = source.get("registered_raw_files") if isinstance(source, dict) else None
    raw_basenames = (
        tuple(item.get("name") for item in registered_files)
        if isinstance(registered_files, list)
        and all(isinstance(item, dict) for item in registered_files)
        else ()
    )
    fitted_representation = (
        UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1 if raw_basenames == _UNSW_RAW_BASENAMES else None
    )
    exact_requirements = (
        configuration.get("schema_version") == PREPROCESSING_SCHEMA_VERSION
        and configuration.get("feature_contract") == NETWORK_BEHAVIOR_V1_CONTRACT_VERSION
        and configuration.get("input_feature_names") == list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES)
        and configuration.get("transformed_feature_names") == list(TRANSFORMED_FEATURE_NAMES)
        and tuple(item.name for item in models) == ("logistic_regression", "random_forest")
        and all(
            getattr(item.model, "n_features_in_", None) == len(TRANSFORMED_FEATURE_NAMES)
            for item in models
        )
    )
    return NetworkCompatibilityKey(
        source_representation=evidence.source_representation,
        fitted_source_representation=fitted_representation,
        feature_contract_version=configuration.get("feature_contract"),
        model_preprocessing_requirements=(
            UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1 if exact_requirements else None
        ),
    )


def _require_approved_cic_use(
    preprocessing: Any,
    evidence: VerifiedCicEvidence,
    models: tuple[Any, Any],
) -> NetworkCompatibilityDecision:
    """Enforce reviewed representation compatibility before transformation or inference."""
    key = _compatibility_key_for_verified_inputs(preprocessing, evidence, models)
    try:
        return require_supported_network_compatibility(key)
    except NetworkCompatibilityError as exc:
        raise NetworkBaselineError(exc.code) from exc


def _historical_compatibility_key(configuration: dict[str, Any]) -> NetworkCompatibilityKey:
    cic_evidence = configuration.get("cic_evidence")
    files = cic_evidence.get("files") if isinstance(cic_evidence, dict) else None
    basenames = (
        tuple(item.get("basename") for item in files)
        if isinstance(files, list) and all(isinstance(item, dict) for item in files)
        else ()
    )
    source_representation = (
        CIC_IDS2018_CICFLOWMETER_V3_PROCESSED_REPRESENTATION_V1
        if configuration.get("external_dataset") == "cse_cic_ids2018"
        and basenames == tuple(EXPECTED_FILES)
        else None
    )
    preprocessing = configuration.get("preprocessing")
    models = configuration.get("models")
    hashes_present = (
        isinstance(preprocessing, dict)
        and all(
            isinstance(preprocessing.get(name), str)
            and _SHA256.fullmatch(preprocessing[name]) is not None
            for name in ("state_sha256", "configuration_sha256", "report_sha256")
        )
        and isinstance(models, dict)
        and set(models) == {"logistic_regression", "random_forest"}
    )
    exact_requirements = (
        configuration.get("schema_version") == HISTORICAL_CIC_EVALUATION_SCHEMA_VERSION
        and configuration.get("transformed_feature_names") == list(TRANSFORMED_FEATURE_NAMES)
        and hashes_present
    )
    return NetworkCompatibilityKey(
        source_representation=source_representation,
        fitted_source_representation=(
            UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1 if exact_requirements else None
        ),
        feature_contract_version=(
            NETWORK_BEHAVIOR_V1_CONTRACT_VERSION if exact_requirements else None
        ),
        model_preprocessing_requirements=(
            UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1 if exact_requirements else None
        ),
    )


def read_historical_cic_evaluation(run_directory: Path) -> HistoricalCicEvaluation:
    """Read immutable legacy evidence without treating completion as compatibility approval."""
    configuration_path = run_directory / "evaluation_config.json"
    report_path = run_directory / "evaluation_report.json"
    configuration = _read_json(configuration_path, "historical_cic_configuration_unreadable")
    report = _read_json(report_path, "historical_cic_report_unreadable")
    if (
        report.get("schema_version") != HISTORICAL_CIC_EVALUATION_SCHEMA_VERSION
        or report.get("configuration_sha256") != sha256_file(configuration_path)
        or not isinstance(report.get("completed"), bool)
    ):
        raise NetworkBaselineError("historical_cic_evidence_mismatch")
    compatibility = decide_network_compatibility(_historical_compatibility_key(configuration))
    return HistoricalCicEvaluation(
        configuration=configuration,
        report=report,
        completed=report["completed"],
        compatibility=compatibility,
    )


def _verify_common_inputs(
    project_root: Path,
    manifest_path: Path,
    quality_directory: Path,
    profile_path: Path,
    preprocessing_directory: Path,
    logistic_directory: Path,
    forest_directory: Path,
) -> tuple[Any, VerifiedCicEvidence, tuple[Any, Any], NetworkCompatibilityDecision]:
    preprocessing = verify_preprocessing_artifacts(preprocessing_directory)
    evidence = verify_cic_evidence(project_root, manifest_path, quality_directory, profile_path)
    models = (
        verify_saved_model(logistic_directory, preprocessing, name="logistic_regression"),
        verify_saved_model(forest_directory, preprocessing, name="random_forest"),
    )
    compatibility = _require_approved_cic_use(preprocessing, evidence, models)
    return preprocessing, evidence, models, compatibility


def run_cic_smoke(
    *,
    project_root: Path,
    manifest_path: Path,
    quality_directory: Path,
    profile_path: Path,
    preprocessing_directory: Path,
    logistic_directory: Path,
    forest_directory: Path,
    artifact_root: Path,
    run_id: str,
    max_records_per_file: int,
) -> Path:
    """Verify all evidence and bounded feature-only adaptation as a partial smoke."""
    if not _RUN_ID.fullmatch(run_id) or max_records_per_file <= 0:
        raise ValueError("invalid smoke configuration")
    preprocessing, evidence, _, _ = _verify_common_inputs(
        project_root,
        manifest_path,
        quality_directory,
        profile_path,
        preprocessing_directory,
        logistic_directory,
        forest_directory,
    )
    checked = {}
    for item in evidence.files:
        quality = BatchQualityReport(
            source=f"CSE-CIC-IDS2018 benchmark/{item.basename}",
            rejection_example_limit=REJECTION_EXAMPLE_LIMIT,
        )
        for record in stream_adapt_rows(
            islice(CicProcessedReader(item.path), max_records_per_file),
            adapt_cic_benchmark_row,
            quality,
        ):
            preprocessing.state.transform(record)
        checked[item.basename] = {
            "rows_checked": quality.total_rows,
            "accepted": quality.accepted_count,
            "rejected": quality.rejected_count,
        }
    artifact_root.mkdir(parents=True, exist_ok=True)
    run_directory = artifact_root / run_id
    try:
        run_directory.mkdir()
    except FileExistsError as exc:
        raise NetworkBaselineError("run_directory_already_exists") from exc
    report_path = run_directory / "smoke_report.json"
    _write_json(
        report_path,
        {
            "schema_version": CIC_EVALUATION_SCHEMA_VERSION,
            "completed": False,
            "partial": True,
            "purpose": "bounded smoke; not external evaluation",
            "files": checked,
        },
    )
    return report_path


def run_cic_external_evaluation(
    *,
    project_root: Path,
    manifest_path: Path,
    quality_directory: Path,
    profile_path: Path,
    preprocessing_directory: Path,
    logistic_directory: Path,
    forest_directory: Path,
    artifact_root: Path,
    run_id: str,
    batch_size: int = DEFAULT_BATCH_SIZE,
    progress: Callable[[str], None] | None = None,
) -> CicEvaluationResult:
    """Transform both registered CIC files and evaluate only saved estimators."""
    started = time.monotonic()
    if not _RUN_ID.fullmatch(run_id) or batch_size <= 0:
        raise ValueError("invalid evaluation configuration")
    project_root = project_root.resolve()
    artifact_root = artifact_root.resolve()
    allowed = (project_root / "artifacts/reports/network_cic_external_evaluation").resolve()
    if artifact_root != allowed:
        raise NetworkBaselineError("artifact_root_invalid")
    verification_started = time.monotonic()
    preprocessing, evidence, models, compatibility = _verify_common_inputs(
        project_root,
        manifest_path,
        quality_directory,
        profile_path,
        preprocessing_directory,
        logistic_directory,
        forest_directory,
    )
    artifact_root.mkdir(parents=True, exist_ok=True)
    accepted_total = sum(item.accepted_rows for item in evidence.files)
    resources = _resource_evidence(artifact_root, accepted_total)
    verification_seconds = time.monotonic() - verification_started
    run_directory = artifact_root / run_id
    try:
        run_directory.mkdir()
    except FileExistsError as exc:
        raise NetworkBaselineError("run_directory_already_exists") from exc
    protected_hashes = {
        "preprocessor": sha256_file(preprocessing_directory / "preprocessor_state.json"),
        **{item.name: item.model_sha256 for item in models},
    }
    config = {
        "schema_version": CIC_EVALUATION_SCHEMA_VERSION,
        "external_dataset": "cse_cic_ids2018",
        "primary_reporting": "per_file",
        "secondary_reporting": "pooled_recomputed_from_rows_and_scores",
        "label_mapping": LABEL_MAPPING,
        "decision_threshold": {"operator": ">=", "probability": ATTACK_THRESHOLD},
        "transformed_feature_names": list(TRANSFORMED_FEATURE_NAMES),
        "compatibility_decision": compatibility.to_dict(),
        "no_fit_selection_or_tuning": True,
        "cic_evidence": {
            "manifest_sha256": evidence.manifest_sha256,
            "profile_sha256": evidence.profile_sha256,
            "files": [
                {
                    "basename": item.basename,
                    "sha256": item.sha256,
                    "quality_report_sha256": item.quality_report_sha256,
                    "total_rows": item.total_rows,
                    "accepted_rows": item.accepted_rows,
                    "rejected_rows": item.rejected_rows,
                }
                for item in evidence.files
            ],
        },
        "preprocessing": {
            "state_sha256": preprocessing.state_sha256,
            "configuration_sha256": preprocessing.configuration_sha256,
            "report_sha256": preprocessing.report_sha256,
            "reused_without_refit": True,
        },
        "models": {
            item.name: {
                "model_sha256": item.model_sha256,
                "configuration_sha256": item.configuration_sha256,
                "report_sha256": item.report_sha256,
            }
            for item in models
        },
        "dependencies": _dependencies(),
        "interpreter": ".venv/bin/python",
        "code_provenance": _git_provenance(project_root),
        "resource_evidence": resources,
    }
    config_path = run_directory / "evaluation_config.json"
    _write_json(config_path, config)
    try:
        matrices = []
        labels = []
        categories = []
        observed_quality = {}
        transform_started = time.monotonic()
        for index, item in enumerate(evidence.files):
            if progress:
                progress(f"transform:{item.basename}")
            paths = {
                "matrix": run_directory / f"X_cic_{index}.partial.npy",
                "labels": run_directory / f"y_cic_{index}.partial.npy",
                "categories": run_directory / f"categories_cic_{index}.partial.npy",
            }
            matrix = open_memmap(
                paths["matrix"],
                mode="w+",
                dtype=np.float64,
                shape=(item.accepted_rows, len(TRANSFORMED_FEATURE_NAMES)),
            )
            label_array = open_memmap(
                paths["labels"], mode="w+", dtype=np.uint8, shape=(item.accepted_rows,)
            )
            category_array = open_memmap(
                paths["categories"], mode="w+", dtype=np.uint8, shape=(item.accepted_rows,)
            )
            observed_quality[item.basename] = transform_cic_records(
                CicProcessedReader(item.path),
                preprocessing.state,
                matrix,
                label_array,
                category_array,
                item.quality_report,
                batch_size=batch_size,
            )
            if not np.isfinite(matrix).all():
                raise NetworkBaselineError("cic_transformed_matrix_non_finite")
            final_matrix = run_directory / f"X_cic_{index}.npy"
            final_labels = run_directory / f"y_cic_{index}.npy"
            paths["matrix"].replace(final_matrix)
            paths["labels"].replace(final_labels)
            matrices.append(np.load(final_matrix, mmap_mode="r", allow_pickle=False))
            labels.append(np.load(final_labels, mmap_mode="r", allow_pickle=False))
            categories.append(category_array)
        transform_seconds = time.monotonic() - transform_started
        evaluation_started = time.monotonic()
        with threadpool_limits(limits=NESTED_NUMERICAL_THREADS):
            file_metrics, pooled_metrics = evaluate_file_and_pooled(
                models,
                tuple(matrices),
                tuple(labels),
                tuple(categories),
                tuple(item.basename for item in evidence.files),
                run_directory,
            )
        evaluation_seconds = time.monotonic() - evaluation_started
        for index in range(len(evidence.files)):
            del categories[0]
            (run_directory / f"categories_cic_{index}.partial.npy").unlink()
        if protected_hashes["preprocessor"] != sha256_file(
            preprocessing_directory / "preprocessor_state.json"
        ):
            raise NetworkBaselineError("preprocessing_state_changed")
        for item, directory, filename in (
            (models[0], logistic_directory, "logistic_regression.joblib"),
            (models[1], forest_directory, "random_forest.joblib"),
        ):
            if item.model_sha256 != sha256_file(directory / filename):
                raise NetworkBaselineError("saved_model_changed")
        per_file = {}
        for index, item in enumerate(evidence.files):
            per_file[item.basename] = {
                "total_rows": item.total_rows,
                "accepted_rows": item.accepted_rows,
                "rejected_rows": item.rejected_rows,
                "normal_count": int(np.count_nonzero(labels[index] == 0)),
                "attack_count": int(np.count_nonzero(labels[index] == 1)),
                "rejection_details": observed_quality[item.basename]["rejection_details"],
                **file_metrics[item.basename],
            }
        elapsed = time.monotonic() - started
        output_files = [
            run_directory / f"{prefix}_cic_{index}.npy"
            for index in range(len(evidence.files))
            for prefix in ("X", "y")
        ]
        report = {
            "schema_version": CIC_EVALUATION_SCHEMA_VERSION,
            "completed": True,
            "global_training_ready": False,
            "configuration_sha256": sha256_file(config_path),
            "per_file_primary": per_file,
            "pooled_secondary": {
                "accepted_rows": accepted_total,
                "rejected_rows": sum(item.rejected_rows for item in evidence.files),
                "normal_count": sum(value["normal_count"] for value in per_file.values()),
                "attack_count": sum(value["attack_count"] for value in per_file.values()),
                **pooled_metrics,
            },
            "outputs": {
                path.name: {"sha256": sha256_file(path), "size_bytes": path.stat().st_size}
                for path in output_files
            },
            "checks": {
                "registered_inputs_and_validation_evidence_verified": True,
                "compatibility_approved_for_inference": compatibility.approved_for_inference,
                "feature_only_adapter_used": True,
                "preprocessing_state_unchanged_and_not_refit": True,
                "saved_models_unchanged_and_not_refit": True,
                "per_file_rejection_and_output_alignment_reconciled": True,
                "pooled_metrics_recomputed_from_pooled_scores": True,
                "transformed_outputs_finite_and_ordered": True,
            },
            "timings_seconds": {
                "input_verification": verification_seconds,
                "transformation": transform_seconds,
                "evaluation": evaluation_seconds,
                "total": elapsed,
            },
            "resource_controls": {
                **resources,
                "disk_backed_outputs": True,
                "prediction_batch_size": PREDICTION_BATCH_SIZE,
                "numerical_thread_limit": NESTED_NUMERICAL_THREADS,
            },
            "artifact_size_bytes_excluding_report": sum(
                path.stat().st_size for path in run_directory.iterdir() if path.is_file()
            ),
            "limitations": [
                "the acquired files may be row-capped exports",
                "CIC source timezone is unknown",
                "CIC aggregate profiles and labels were known before evaluation",
                "compatibility approval does not establish production readiness or accuracy",
                "results do not establish operational or future-period performance",
                "host training remains blocked and global readiness is unchanged",
            ],
        }
        report_path = run_directory / "evaluation_report.json"
        _write_json(report_path, report)
        return CicEvaluationResult(
            run_directory,
            report_path,
            accepted_total,
            sum(item.rejected_rows for item in evidence.files),
            elapsed,
        )
    except Exception as exc:
        code = exc.code if isinstance(exc, NetworkBaselineError) else "internal_cic_failure"
        write_cic_failure_status(run_directory, code)
        raise
