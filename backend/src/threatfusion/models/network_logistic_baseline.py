"""Frozen supervised network baseline over verified TRAIN/VALIDATION artifacts."""

from __future__ import annotations

import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import time
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from threadpoolctl import threadpool_info, threadpool_limits

from threatfusion.features.network_behavior import NETWORK_BEHAVIOR_V1_FEATURE_NAMES
from threatfusion.preprocessing.network_behavior_v1 import (
    ASSIGNMENT_SCHEMA_VERSION,
    ASSIGNMENT_SEED,
    LABEL_MAPPING,
    PREPROCESSING_SCHEMA_VERSION,
    TRANSFORMED_FEATURE_NAMES,
    NetworkBehaviorPreprocessor,
)
from threatfusion.utils.checksum import sha256_file

BASELINE_SCHEMA_VERSION = "network_logistic_baseline_v1"
MODEL_FILENAME = "logistic_regression.joblib"
MODEL_CONFIG_FILENAME = "model_config.json"
EVALUATION_REPORT_FILENAME = "evaluation_report.json"
ATTACK_THRESHOLD = 0.5
MAX_NUMERICAL_THREADS = 4
MINIMUM_AVAILABLE_MEMORY_RESERVE_BYTES = 1024**3
MINIMUM_FREE_DISK_BYTES = 1024**3
FIT_MEMORY_FIXED_OVERHEAD_BYTES = 256 * 1024**2
RELOAD_SAMPLE_SIZE = 4096
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")

FROZEN_LOGISTIC_PARAMETERS: dict[str, Any] = {
    "penalty": "l2",
    "C": 1.0,
    "solver": "lbfgs",
    "fit_intercept": True,
    "class_weight": None,
    "max_iter": 1000,
    "tol": 1e-4,
}


class NetworkBaselineError(RuntimeError):
    """Sanitized fail-closed baseline error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class VerifiedPreprocessingArtifacts:
    """Memory-mapped, integrity-checked TRAIN/VALIDATION inputs."""

    run_directory: Path
    report: dict[str, Any]
    configuration: dict[str, Any]
    state: NetworkBehaviorPreprocessor
    state_sha256: str
    configuration_sha256: str
    report_sha256: str
    X_train: np.memmap
    y_train: np.memmap
    X_validation: np.memmap
    y_validation: np.memmap


@dataclass(frozen=True, slots=True)
class ResourceEstimate:
    """Conservative pre-fit resource estimate and observed availability."""

    matrix_bytes: int
    estimator_copy_bytes: int
    solver_working_bytes: int
    label_working_bytes: int
    fixed_overhead_bytes: int
    estimated_peak_bytes: int
    available_memory_bytes: int
    required_memory_with_reserve_bytes: int
    free_disk_bytes: int
    minimum_free_disk_bytes: int


@dataclass(frozen=True, slots=True)
class BaselineRunResult:
    """Safe aggregate result for one completed baseline experiment."""

    run_directory: Path
    report_path: Path
    model_path: Path
    completed: bool
    converged: bool
    elapsed_seconds: float


def create_frozen_logistic_regression() -> LogisticRegression:
    """Create the single authorized estimator with no tunable run arguments."""
    installed_syntax = {
        name: value for name, value in FROZEN_LOGISTIC_PARAMETERS.items() if name != "penalty"
    }
    installed_syntax["l1_ratio"] = 0.0
    return LogisticRegression(**installed_syntax)


def effective_logistic_parameters(model: LogisticRegression) -> dict[str, Any]:
    """Return JSON-safe effective parameters from the installed estimator."""
    parameters = model.get_params(deep=False)
    return {name: parameters[name] for name in sorted(parameters)}


def _read_json(path: Path, error_code: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NetworkBaselineError(error_code) from exc
    if not isinstance(payload, dict):
        raise NetworkBaselineError(error_code)
    return payload


def _require_sha256(value: object, error_code: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise NetworkBaselineError(error_code)
    return value


def _verify_finite_matrix(matrix: np.ndarray, batch_size: int = 50_000) -> None:
    for start in range(0, matrix.shape[0], batch_size):
        if not np.isfinite(matrix[start : start + batch_size]).all():
            raise NetworkBaselineError("preprocessed_matrix_non_finite")


def _verify_labels(labels: np.ndarray, benign: int, attack: int) -> None:
    if labels.ndim != 1 or labels.dtype != np.uint8:
        raise NetworkBaselineError("preprocessed_label_array_invalid")
    counts = np.bincount(labels, minlength=2)
    if len(counts) != 2 or int(counts[0]) != benign or int(counts[1]) != attack:
        raise NetworkBaselineError("preprocessed_label_counts_mismatch")


def verify_preprocessing_artifacts(run_directory: Path) -> VerifiedPreprocessingArtifacts:
    """Verify and memory-map the completed preprocessing evidence without refitting it."""
    run_directory = run_directory.resolve()
    report_path = run_directory / "preprocessing_report.json"
    configuration_path = run_directory / "preprocessing_config.json"
    state_path = run_directory / "preprocessor_state.json"
    report = _read_json(report_path, "preprocessing_report_unreadable")
    configuration = _read_json(configuration_path, "preprocessing_config_unreadable")
    checks = report.get("checks")
    expected_checks = {
        "assignment_and_source_counts_reconciled",
        "assignment_evidence_verified",
        "fitted_state_reload_equivalent",
        "matrices_finite",
        "only_train_influenced_fitted_state",
        "test_and_cic_not_transformed",
    }
    counts = report.get("counts")
    if not isinstance(counts, dict) or set(counts) != {"train", "validation", "excluded"}:
        raise NetworkBaselineError("preprocessing_counts_mismatch")
    for partition in ("train", "validation"):
        item = counts.get(partition)
        if (
            not isinstance(item, dict)
            or set(item) != {"rows", "benign", "attack"}
            or any(not isinstance(item[name], int) or item[name] < 0 for name in item)
            or item["benign"] + item["attack"] != item["rows"]
            or item["rows"] <= 0
        ):
            raise NetworkBaselineError("preprocessing_counts_mismatch")
    excluded = counts.get("excluded")
    if (
        not isinstance(excluded, dict)
        or set(excluded) != {"test", "quarantine", "rejected"}
        or any(not isinstance(value, int) or value < 0 for value in excluded.values())
    ):
        raise NetworkBaselineError("preprocessing_counts_mismatch")
    expected_shapes = {
        "X_train": [counts["train"]["rows"], len(TRANSFORMED_FEATURE_NAMES)],
        "y_train": [counts["train"]["rows"]],
        "X_validation": [counts["validation"]["rows"], len(TRANSFORMED_FEATURE_NAMES)],
        "y_validation": [counts["validation"]["rows"]],
    }
    if (
        report.get("schema_version") != PREPROCESSING_SCHEMA_VERSION
        or report.get("completed") is not True
        or report.get("global_training_ready") is not False
        or report.get("fit_partition") != "train"
        or report.get("transformed_partitions") != ["train", "validation"]
        or report.get("input_feature_names") != list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES)
        or report.get("output_feature_names") != list(TRANSFORMED_FEATURE_NAMES)
        or report.get("input_feature_count") != len(NETWORK_BEHAVIOR_V1_FEATURE_NAMES)
        or report.get("output_feature_count") != len(TRANSFORMED_FEATURE_NAMES)
        or report.get("shapes") != expected_shapes
        or not isinstance(checks, dict)
        or any(checks.get(name) is not True for name in expected_checks)
    ):
        raise NetworkBaselineError("preprocessing_report_incomplete_or_inconsistent")

    hashes = report.get("hashes")
    if not isinstance(hashes, dict):
        raise NetworkBaselineError("preprocessing_hash_evidence_missing")
    expected_configuration_hash = _require_sha256(
        hashes.get("configuration"), "preprocessing_configuration_hash_invalid"
    )
    expected_state_hash = _require_sha256(
        hashes.get("fitted_state"), "preprocessing_state_hash_invalid"
    )
    if sha256_file(configuration_path) != expected_configuration_hash:
        raise NetworkBaselineError("preprocessing_configuration_hash_mismatch")
    if sha256_file(state_path) != expected_state_hash:
        raise NetworkBaselineError("preprocessing_state_hash_mismatch")
    state = NetworkBehaviorPreprocessor.load(state_path)
    if state.training_row_count != counts["train"]["rows"]:
        raise NetworkBaselineError("preprocessing_state_training_count_mismatch")

    if (
        configuration.get("schema_version") != PREPROCESSING_SCHEMA_VERSION
        or configuration.get("feature_contract") != "network_behavior_v1"
        or configuration.get("fit_partition") != "train"
        or configuration.get("transform_partitions") != ["train", "validation"]
        or configuration.get("label_mapping") != LABEL_MAPPING
        or configuration.get("input_feature_names") != list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES)
        or configuration.get("transformed_feature_names") != list(TRANSFORMED_FEATURE_NAMES)
        or configuration.get("output_dtype") != "float64"
    ):
        raise NetworkBaselineError("preprocessing_configuration_inconsistent")
    assignment = configuration.get("assignment")
    source = configuration.get("source")
    if (
        not isinstance(assignment, dict)
        or assignment.get("schema_version") != ASSIGNMENT_SCHEMA_VERSION
        or assignment.get("seed") != ASSIGNMENT_SEED
        or not isinstance(source, dict)
        or len(source.get("registered_raw_files", [])) != 4
    ):
        raise NetworkBaselineError("preprocessing_provenance_inconsistent")
    for name in (
        "archive_sha256",
        "preflight_report_sha256",
        "report_sha256",
    ):
        _require_sha256(assignment.get(name), "preprocessing_provenance_hash_invalid")
    _require_sha256(source.get("manifest_sha256"), "preprocessing_provenance_hash_invalid")
    for item in source["registered_raw_files"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("rows"), int)
        ):
            raise NetworkBaselineError("preprocessing_provenance_inconsistent")
        _require_sha256(item.get("sha256"), "preprocessing_provenance_hash_invalid")

    output_hashes = hashes.get("outputs")
    if not isinstance(output_hashes, dict) or set(output_hashes) != set(expected_shapes):
        raise NetworkBaselineError("preprocessing_output_hash_evidence_invalid")
    arrays: dict[str, np.memmap] = {}
    for name, shape in expected_shapes.items():
        path = run_directory / f"{name}.npy"
        item = output_hashes.get(name)
        if not isinstance(item, dict):
            raise NetworkBaselineError("preprocessing_output_hash_evidence_invalid")
        expected_hash = _require_sha256(
            item.get("sha256"), "preprocessing_output_hash_evidence_invalid"
        )
        if not path.is_file() or path.stat().st_size != item.get("size_bytes"):
            raise NetworkBaselineError("preprocessing_output_missing_or_size_mismatch")
        if sha256_file(path) != expected_hash:
            raise NetworkBaselineError("preprocessing_output_hash_mismatch")
        try:
            array = np.load(path, mmap_mode="r", allow_pickle=False)
        except (OSError, ValueError) as exc:
            raise NetworkBaselineError("preprocessing_output_unreadable") from exc
        if list(array.shape) != shape:
            raise NetworkBaselineError("preprocessing_output_shape_mismatch")
        arrays[name] = array
    if arrays["X_train"].dtype != np.float64 or arrays["X_validation"].dtype != np.float64:
        raise NetworkBaselineError("preprocessed_matrix_dtype_mismatch")
    _verify_finite_matrix(arrays["X_train"])
    _verify_finite_matrix(arrays["X_validation"])
    _verify_labels(arrays["y_train"], counts["train"]["benign"], counts["train"]["attack"])
    _verify_labels(
        arrays["y_validation"],
        counts["validation"]["benign"],
        counts["validation"]["attack"],
    )

    return VerifiedPreprocessingArtifacts(
        run_directory=run_directory,
        report=report,
        configuration=configuration,
        state=state,
        state_sha256=expected_state_hash,
        configuration_sha256=expected_configuration_hash,
        report_sha256=sha256_file(report_path),
        X_train=arrays["X_train"],
        y_train=arrays["y_train"],
        X_validation=arrays["X_validation"],
        y_validation=arrays["y_validation"],
    )


def available_memory_bytes() -> int:
    """Read Linux MemAvailable without adding another runtime dependency."""
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError) as exc:
        raise NetworkBaselineError("available_memory_unreadable") from exc
    raise NetworkBaselineError("available_memory_unreadable")


def estimate_fit_resources(
    X_train: np.ndarray,
    y_train: np.ndarray,
    artifact_root: Path,
) -> ResourceEstimate:
    """Conservatively budget mapped input, validation/copy, solver, and labels."""
    matrix_bytes = int(X_train.nbytes)
    estimator_copy_bytes = matrix_bytes
    solver_working_bytes = matrix_bytes * 2
    label_working_bytes = int(y_train.shape[0] * np.dtype(np.float64).itemsize * 2)
    estimated_peak = (
        matrix_bytes
        + estimator_copy_bytes
        + solver_working_bytes
        + label_working_bytes
        + FIT_MEMORY_FIXED_OVERHEAD_BYTES
    )
    available = available_memory_bytes()
    required = estimated_peak + MINIMUM_AVAILABLE_MEMORY_RESERVE_BYTES
    free_disk = shutil.disk_usage(artifact_root).free
    estimate = ResourceEstimate(
        matrix_bytes=matrix_bytes,
        estimator_copy_bytes=estimator_copy_bytes,
        solver_working_bytes=solver_working_bytes,
        label_working_bytes=label_working_bytes,
        fixed_overhead_bytes=FIT_MEMORY_FIXED_OVERHEAD_BYTES,
        estimated_peak_bytes=estimated_peak,
        available_memory_bytes=available,
        required_memory_with_reserve_bytes=required,
        free_disk_bytes=free_disk,
        minimum_free_disk_bytes=MINIMUM_FREE_DISK_BYTES,
    )
    if available < required:
        raise NetworkBaselineError("insufficient_memory_for_full_fit")
    if free_disk < MINIMUM_FREE_DISK_BYTES:
        raise NetworkBaselineError("insufficient_disk_for_model_artifacts")
    return estimate


def attack_probability_column(model: LogisticRegression) -> int:
    """Resolve Attack=1 from fitted classes instead of assuming column position."""
    classes = np.asarray(model.classes_)
    if classes.ndim != 1 or set(classes.tolist()) != {0, 1}:
        raise NetworkBaselineError("model_binary_class_mapping_invalid")
    matches = np.flatnonzero(classes == LABEL_MAPPING["Attack"])
    if matches.size != 1:
        raise NetworkBaselineError("model_attack_probability_column_invalid")
    return int(matches[0])


def attack_probabilities(model: LogisticRegression, matrix: np.ndarray) -> np.ndarray:
    """Return the continuous Attack=1 probability using the verified class column."""
    probabilities = np.asarray(model.predict_proba(matrix), dtype=np.float64)
    if probabilities.ndim != 2 or probabilities.shape[0] != matrix.shape[0]:
        raise NetworkBaselineError("model_probability_shape_invalid")
    scores = probabilities[:, attack_probability_column(model)]
    if not np.isfinite(scores).all() or np.any((scores < 0.0) | (scores > 1.0)):
        raise NetworkBaselineError("model_probability_invalid")
    return scores


def threshold_attack_scores(scores: np.ndarray) -> np.ndarray:
    """Apply the frozen inclusive probability threshold."""
    scores = np.asarray(scores, dtype=np.float64)
    if not np.isfinite(scores).all():
        raise NetworkBaselineError("model_probability_invalid")
    return (scores >= ATTACK_THRESHOLD).astype(np.uint8)


def calculate_binary_metrics(labels: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    """Calculate named binary metrics with explicit zero-denominator behavior."""
    labels = np.asarray(labels)
    scores = np.asarray(scores, dtype=np.float64)
    if labels.ndim != 1 or scores.ndim != 1 or labels.shape != scores.shape:
        raise NetworkBaselineError("evaluation_input_shape_invalid")
    if not np.isin(labels, (0, 1)).all():
        raise NetworkBaselineError("evaluation_label_invalid")
    if not np.isfinite(scores).all():
        raise NetworkBaselineError("model_probability_invalid")
    predictions = threshold_attack_scores(scores)
    positive = labels == 1
    negative = labels == 0
    predicted_positive = predictions == 1
    predicted_negative = predictions == 0
    tp = int(np.count_nonzero(positive & predicted_positive))
    fp = int(np.count_nonzero(negative & predicted_positive))
    tn = int(np.count_nonzero(negative & predicted_negative))
    fn = int(np.count_nonzero(positive & predicted_negative))
    sample_count = labels.size
    positive_count = int(np.count_nonzero(positive))
    negative_count = sample_count - positive_count
    predicted_attack_count = tp + fp

    precision = tp / predicted_attack_count if predicted_attack_count else 0.0
    recall = tp / positive_count if positive_count else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / negative_count if negative_count else 0.0
    specificity = tn / negative_count if negative_count else 0.0
    balanced_accuracy = (recall + specificity) / 2 if positive_count and negative_count else None
    accuracy = (tp + tn) / sample_count if sample_count else 0.0
    average_precision = float(average_precision_score(labels, scores)) if positive_count else 0.0
    roc_auc = float(roc_auc_score(labels, scores)) if positive_count and negative_count else None
    return {
        "sample_count": int(sample_count),
        "normal_count": negative_count,
        "attack_count": positive_count,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "attack_precision": precision,
        "attack_recall": recall,
        "attack_f1": f1,
        "false_positive_rate": false_positive_rate,
        "balanced_accuracy": balanced_accuracy,
        "accuracy": accuracy,
        "average_precision": average_precision,
        "roc_auc": roc_auc,
        "predicted_attack_count": predicted_attack_count,
        "predicted_attack_percentage": (
            100.0 * predicted_attack_count / sample_count if sample_count else 0.0
        ),
        "decision_threshold": ATTACK_THRESHOLD,
        "zero_denominator_policy": {
            "precision_recall_f1_false_positive_rate_accuracy": "return 0.0",
            "average_precision_without_positive_labels": "return 0.0",
            "balanced_accuracy_or_roc_auc_without_both_classes": "return null",
        },
    }


def convergence_details(
    model: LogisticRegression, captured_warnings: Sequence[warnings.WarningMessage]
) -> dict[str, Any]:
    """Separate run completion from conservative convergence evidence."""
    iterations = [int(value) for value in np.asarray(model.n_iter_).ravel()]
    convergence_warnings = [
        item for item in captured_warnings if issubclass(item.category, ConvergenceWarning)
    ]
    reached_limit = any(value >= int(model.max_iter) for value in iterations)
    return {
        "converged": not convergence_warnings and not reached_limit,
        "iteration_count_by_class": iterations,
        "maximum_iterations": int(model.max_iter),
        "reached_iteration_limit": reached_limit,
        "convergence_warning_count": len(convergence_warnings),
        "captured_warning_categories": [item.category.__name__ for item in captured_warnings],
        "captured_warnings": [
            {"category": item.category.__name__, "message": str(item.message)}
            for item in captured_warnings
        ],
    }


def run_synthetic_smoke() -> dict[str, Any]:
    """Exercise only the frozen estimator and metric path on a tiny synthetic fixture."""
    matrix = np.asarray(
        [
            [-2.0, 0.0],
            [-1.0, 0.0],
            [-0.5, 1.0],
            [0.5, 0.0],
            [1.0, 1.0],
            [2.0, 1.0],
        ],
        dtype=np.float64,
    )
    labels = np.asarray([0, 0, 0, 1, 1, 1], dtype=np.uint8)
    model = create_frozen_logistic_regression()
    with threadpool_limits(limits=MAX_NUMERICAL_THREADS):
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            model.fit(matrix, labels)
        scores = attack_probabilities(model, matrix)
    metrics = calculate_binary_metrics(labels, scores)
    if metrics["sample_count"] != 6 or attack_probability_column(model) not in {0, 1}:
        raise NetworkBaselineError("synthetic_smoke_failed")
    return {
        "completed": True,
        "sample_count": 6,
        "convergence": convergence_details(model, captured),
    }


def _dependency_versions() -> dict[str, str]:
    versions = {"python": platform.python_version()}
    for package in ("numpy", "scipy", "scikit-learn", "joblib", "threadpoolctl"):
        versions[package] = importlib.metadata.version(package)
    return versions


def _working_tree_dirty(project_root: Path) -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise NetworkBaselineError("working_tree_status_unavailable")
    return bool(result.stdout.strip())


def _resource_payload(estimate: ResourceEstimate) -> dict[str, int]:
    return {field: int(getattr(estimate, field)) for field in ResourceEstimate.__dataclass_fields__}


def _threadpool_payload() -> list[dict[str, Any]]:
    return [
        {
            "user_api": item.get("user_api"),
            "internal_api": item.get("internal_api"),
            "num_threads": item.get("num_threads"),
            "version": item.get("version"),
        }
        for item in threadpool_info()
    ]


def _safe_artifact_root(project_root: Path, artifact_root: Path) -> Path:
    resolved = artifact_root.resolve()
    allowed = (project_root.resolve() / "artifacts/models").resolve()
    if not resolved.is_relative_to(allowed):
        raise NetworkBaselineError("artifact_root_must_be_under_artifacts_models")
    return resolved


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_network_logistic_baseline(
    project_root: Path,
    preprocessing_run_directory: Path,
    artifact_root: Path,
    run_id: str,
) -> BaselineRunResult:
    """Verify inputs, fit once on TRAIN, and evaluate once on VALIDATION."""
    started = time.monotonic()
    if not _RUN_ID.fullmatch(run_id):
        raise NetworkBaselineError("invalid_run_id")
    project_root = project_root.resolve()
    verify_started = time.monotonic()
    inputs = verify_preprocessing_artifacts(preprocessing_run_directory)
    verification_seconds = time.monotonic() - verify_started
    artifact_root = _safe_artifact_root(project_root, artifact_root)
    artifact_root.mkdir(parents=True, exist_ok=True)
    resources = estimate_fit_resources(inputs.X_train, inputs.y_train, artifact_root)
    smoke_started = time.monotonic()
    smoke = run_synthetic_smoke()
    smoke_seconds = time.monotonic() - smoke_started

    run_directory = artifact_root / run_id
    try:
        run_directory.mkdir()
    except FileExistsError as exc:
        raise NetworkBaselineError("run_directory_already_exists") from exc
    model = create_frozen_logistic_regression()
    configuration = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "experiment_authorization": "explicit_network_only_supervised_baseline",
        "estimator": "sklearn.linear_model.LogisticRegression",
        "frozen_requested_parameters": FROZEN_LOGISTIC_PARAMETERS,
        "installed_version_parameter_translation": {
            "requested": "penalty='l2'",
            "effective_syntax": "default penalty sentinel with l1_ratio=0.0",
            "reason": "scikit-learn 1.9 deprecates the explicit penalty parameter",
        },
        "effective_parameters": effective_logistic_parameters(model),
        "decision_threshold": {
            "positive_label": LABEL_MAPPING["Attack"],
            "positive_name": "Attack",
            "operator": ">=",
            "probability": ATTACK_THRESHOLD,
        },
        "label_mapping": LABEL_MAPPING,
        "fit_partition": "train",
        "evaluation_partition": "validation",
        "prohibited_partitions": ["test", "cic"],
        "preprocessing": {
            "state_sha256": inputs.state_sha256,
            "configuration_sha256": inputs.configuration_sha256,
            "report_sha256": inputs.report_sha256,
            "transformed_feature_names": list(TRANSFORMED_FEATURE_NAMES),
            "transformed_feature_count": len(TRANSFORMED_FEATURE_NAMES),
            "state_reused_without_refit": True,
            "source_provenance": inputs.configuration["source"],
            "assignment_provenance": inputs.configuration["assignment"],
        },
        "training_controls": {
            "class_rebalancing": False,
            "resampling": False,
            "hyperparameter_search": False,
            "calibration": False,
            "feature_selection": False,
            "threshold_tuning": False,
            "numerical_thread_limit": MAX_NUMERICAL_THREADS,
        },
        "resource_estimate": _resource_payload(resources),
        "dependencies": _dependency_versions(),
        "interpreter": os.path.realpath(os.sys.executable),
        "working_tree_dirty_during_training": _working_tree_dirty(project_root),
        "synthetic_smoke": smoke,
    }
    configuration_path = run_directory / MODEL_CONFIG_FILENAME
    _write_json(configuration_path, configuration)

    try:
        fit_started = time.monotonic()
        with threadpool_limits(limits=MAX_NUMERICAL_THREADS):
            threadpools_during_fit = _threadpool_payload()
            with warnings.catch_warnings(record=True) as captured:
                warnings.simplefilter("always")
                model.fit(inputs.X_train, inputs.y_train)
        fit_seconds = time.monotonic() - fit_started
        convergence = convergence_details(model, captured)

        evaluation_started = time.monotonic()
        with threadpool_limits(limits=MAX_NUMERICAL_THREADS):
            logistic_scores = attack_probabilities(model, inputs.X_validation)
        logistic_metrics = calculate_binary_metrics(inputs.y_validation, logistic_scores)
        always_benign_scores = np.zeros(inputs.y_validation.shape[0], dtype=np.float64)
        always_benign_metrics = calculate_binary_metrics(inputs.y_validation, always_benign_scores)
        evaluation_seconds = time.monotonic() - evaluation_started

        model_path = run_directory / MODEL_FILENAME
        joblib.dump(model, model_path, compress=3)
        reloaded = joblib.load(model_path)
        sample_size = min(RELOAD_SAMPLE_SIZE, inputs.X_validation.shape[0])
        with threadpool_limits(limits=MAX_NUMERICAL_THREADS):
            original_sample_scores = attack_probabilities(model, inputs.X_validation[:sample_size])
            reloaded_sample_scores = attack_probabilities(
                reloaded, inputs.X_validation[:sample_size]
            )
        reload_probabilities_equal = bool(
            np.array_equal(original_sample_scores, reloaded_sample_scores)
        )
        reload_predictions_equal = bool(
            np.array_equal(
                threshold_attack_scores(original_sample_scores),
                threshold_attack_scores(reloaded_sample_scores),
            )
        )
        if not reload_probabilities_equal or not reload_predictions_equal:
            raise NetworkBaselineError("saved_model_reload_mismatch")

        elapsed = time.monotonic() - started
        model_hash = sha256_file(model_path)
        report = {
            "schema_version": BASELINE_SCHEMA_VERSION,
            "completed": True,
            "model_converged": convergence["converged"],
            "global_training_ready": False,
            "network_only_authorized_experiment": True,
            "configuration_sha256": sha256_file(configuration_path),
            "model": {
                "filename": MODEL_FILENAME,
                "sha256": model_hash,
                "size_bytes": model_path.stat().st_size,
                "classes": [int(value) for value in model.classes_],
                "attack_probability_column": attack_probability_column(model),
                "coefficient_shape": list(model.coef_.shape),
                "intercept_shape": list(model.intercept_.shape),
            },
            "convergence": convergence,
            "validation": {
                "sample_count": int(inputs.y_validation.shape[0]),
                "normal_count": int(np.count_nonzero(inputs.y_validation == 0)),
                "attack_count": int(np.count_nonzero(inputs.y_validation == 1)),
                "logistic_regression": logistic_metrics,
                "always_benign_reference": always_benign_metrics,
                "average_precision_definition": (
                    "non-interpolated average precision from continuous Attack scores; "
                    "not trapezoidal PR-AUC"
                ),
            },
            "timings_seconds": {
                "input_verification": verification_seconds,
                "synthetic_smoke": smoke_seconds,
                "fit": fit_seconds,
                "validation_evaluation": evaluation_seconds,
                "total": elapsed,
            },
            "resource_controls": {
                **_resource_payload(resources),
                "maximum_numerical_threads": MAX_NUMERICAL_THREADS,
                "threadpools_during_fit": threadpools_during_fit,
                "matrices_memory_mapped": True,
                "full_train_used_without_subsampling": True,
            },
            "reload_verification": {
                "sample_count": sample_size,
                "probabilities_exactly_equal": reload_probabilities_equal,
                "predictions_exactly_equal": reload_predictions_equal,
            },
            "checks": {
                "preprocessing_evidence_verified": True,
                "preprocessing_state_reused_without_refit": True,
                "frozen_configuration_recorded_before_fit": True,
                "train_only_fit": True,
                "validation_only_evaluation": True,
                "test_and_cic_not_accessed": True,
                "saved_model_reload_equivalent": True,
            },
            "artifact_size_bytes_excluding_report": sum(
                path.stat().st_size for path in run_directory.iterdir() if path.is_file()
            ),
            "limitations": [
                "strong class imbalance makes ordinary accuracy misleading",
                "validation is grouped development data, not later-period external testing",
                "feature collisions and conflicting labels remain in the frozen assignment",
                "near-duplicate leakage is not assessed",
                "capture and session provenance remain unresolved",
                "host model training remains blocked",
                "this experiment does not change global training readiness",
            ],
        }
        report_path = run_directory / EVALUATION_REPORT_FILENAME
        _write_json(report_path, report)
        return BaselineRunResult(
            run_directory=run_directory,
            report_path=report_path,
            model_path=model_path,
            completed=True,
            converged=bool(convergence["converged"]),
            elapsed_seconds=elapsed,
        )
    except Exception as exc:
        code = exc.code if isinstance(exc, NetworkBaselineError) else "internal_baseline_failure"
        _write_json(
            run_directory / "baseline_failure.json",
            {
                "schema_version": BASELINE_SCHEMA_VERSION,
                "completed": False,
                "failure_code": code,
            },
        )
        raise
