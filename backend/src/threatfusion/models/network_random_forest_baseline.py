"""Frozen Random Forest baseline over verified network TRAIN/VALIDATION artifacts."""

from __future__ import annotations

import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from threadpoolctl import threadpool_info, threadpool_limits

from threatfusion.models.network_logistic_baseline import (
    ATTACK_THRESHOLD,
    BASELINE_SCHEMA_VERSION as LOGISTIC_SCHEMA_VERSION,
    LABEL_MAPPING,
    MINIMUM_AVAILABLE_MEMORY_RESERVE_BYTES,
    MINIMUM_FREE_DISK_BYTES,
    NetworkBaselineError,
    VerifiedPreprocessingArtifacts,
    attack_probabilities,
    attack_probability_column,
    available_memory_bytes,
    calculate_binary_metrics,
    threshold_attack_scores,
    verify_preprocessing_artifacts,
)
from threatfusion.preprocessing.network_behavior_v1 import TRANSFORMED_FEATURE_NAMES
from threatfusion.utils.checksum import sha256_file

RANDOM_FOREST_SCHEMA_VERSION = "network_random_forest_baseline_v1"
MODEL_FILENAME = "random_forest.joblib"
MODEL_CONFIG_FILENAME = "model_config.json"
EVALUATION_REPORT_FILENAME = "evaluation_report.json"
PREDICTION_BATCH_SIZE = 25_000
RELOAD_SAMPLE_SIZE = 4096
RELOAD_PROBABILITY_ABSOLUTE_TOLERANCE = 1e-15
NESTED_NUMERICAL_THREADS = 1
FIT_MEMORY_FIXED_OVERHEAD_BYTES = 256 * 1024**2
TREE_NODE_BYTES_ESTIMATE = 80
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")

FROZEN_RANDOM_FOREST_PARAMETERS: dict[str, Any] = {
    "n_estimators": 100,
    "criterion": "gini",
    "max_depth": 16,
    "min_samples_split": 2,
    "min_samples_leaf": 5,
    "max_features": "sqrt",
    "bootstrap": True,
    "max_samples": None,
    "class_weight": None,
    "random_state": 42,
    "n_jobs": 4,
    "oob_score": False,
    "warm_start": False,
    "ccp_alpha": 0.0,
}


@dataclass(frozen=True, slots=True)
class RandomForestResourceEstimate:
    """Conservative full-fit memory and artifact-space estimate."""

    matrix_bytes: int
    estimator_input_copy_bytes: int
    parallel_worker_bytes: int
    label_working_bytes: int
    maximum_leaves_per_tree: int
    maximum_nodes_per_tree: int
    estimated_tree_storage_bytes: int
    fixed_overhead_bytes: int
    estimated_peak_bytes: int
    available_memory_bytes: int
    required_memory_with_reserve_bytes: int
    free_disk_bytes: int
    required_disk_with_reserve_bytes: int


@dataclass(frozen=True, slots=True)
class RandomForestRunResult:
    """Safe aggregate result for one completed Random Forest experiment."""

    run_directory: Path
    report_path: Path
    model_path: Path
    elapsed_seconds: float


def create_frozen_random_forest() -> RandomForestClassifier:
    """Create the single authorized forest with no run-time tuning arguments."""
    return RandomForestClassifier(**FROZEN_RANDOM_FOREST_PARAMETERS)


def effective_random_forest_parameters(model: RandomForestClassifier) -> dict[str, Any]:
    """Return every installed-estimator parameter in stable JSON-safe order."""
    parameters = model.get_params(deep=False)
    return {name: parameters[name] for name in sorted(parameters)}


def fit_train_only(
    model: RandomForestClassifier, X_train: np.ndarray, y_train: np.ndarray
) -> RandomForestClassifier:
    """Make the fit boundary explicit: no validation input is accepted."""
    return model.fit(X_train, y_train)


def batched_attack_probabilities(
    model: RandomForestClassifier,
    matrix: np.ndarray,
    *,
    batch_size: int = PREDICTION_BATCH_SIZE,
) -> np.ndarray:
    """Predict bounded batches while preserving exact input row order."""
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    scores = np.empty(matrix.shape[0], dtype=np.float64)
    for start in range(0, matrix.shape[0], batch_size):
        stop = min(start + batch_size, matrix.shape[0])
        scores[start:stop] = attack_probabilities(model, matrix[start:stop])
    return scores


def reload_probabilities_equivalent(first: np.ndarray, second: np.ndarray) -> tuple[bool, float]:
    """Compare parallel forest probabilities within a fixed roundoff-only tolerance."""
    first = np.asarray(first, dtype=np.float64)
    second = np.asarray(second, dtype=np.float64)
    if first.shape != second.shape or not np.isfinite(first).all() or not np.isfinite(second).all():
        return False, float("inf")
    maximum_difference = float(np.max(np.abs(first - second), initial=0.0))
    return (
        bool(
            np.allclose(
                first,
                second,
                rtol=0.0,
                atol=RELOAD_PROBABILITY_ABSOLUTE_TOLERANCE,
            )
        ),
        maximum_difference,
    )


def estimate_random_forest_resources(
    X_train: np.ndarray,
    y_train: np.ndarray,
    artifact_root: Path,
) -> RandomForestResourceEstimate:
    """Budget mapped input, copies/workers, and a depth/leaf-bounded tree upper estimate."""
    matrix_bytes = int(X_train.nbytes)
    input_copy_bytes = matrix_bytes
    label_bytes = int(y_train.shape[0] * np.dtype(np.float64).itemsize * 2)
    worker_bytes = int(FROZEN_RANDOM_FOREST_PARAMETERS["n_jobs"]) * (
        matrix_bytes + int(y_train.shape[0] * np.dtype(np.float64).itemsize)
    )
    leaf_bound_from_depth = 2 ** int(FROZEN_RANDOM_FOREST_PARAMETERS["max_depth"])
    leaf_bound_from_samples = max(
        1,
        y_train.shape[0] // int(FROZEN_RANDOM_FOREST_PARAMETERS["min_samples_leaf"]),
    )
    maximum_leaves = min(leaf_bound_from_depth, leaf_bound_from_samples)
    maximum_nodes = 2 * maximum_leaves - 1
    tree_bytes = (
        int(FROZEN_RANDOM_FOREST_PARAMETERS["n_estimators"])
        * maximum_nodes
        * TREE_NODE_BYTES_ESTIMATE
    )
    estimated_peak = (
        matrix_bytes
        + input_copy_bytes
        + worker_bytes
        + label_bytes
        + tree_bytes
        + FIT_MEMORY_FIXED_OVERHEAD_BYTES
    )
    available = available_memory_bytes()
    required_memory = estimated_peak + MINIMUM_AVAILABLE_MEMORY_RESERVE_BYTES
    free_disk = shutil.disk_usage(artifact_root).free
    required_disk = tree_bytes + MINIMUM_FREE_DISK_BYTES
    estimate = RandomForestResourceEstimate(
        matrix_bytes=matrix_bytes,
        estimator_input_copy_bytes=input_copy_bytes,
        parallel_worker_bytes=worker_bytes,
        label_working_bytes=label_bytes,
        maximum_leaves_per_tree=maximum_leaves,
        maximum_nodes_per_tree=maximum_nodes,
        estimated_tree_storage_bytes=tree_bytes,
        fixed_overhead_bytes=FIT_MEMORY_FIXED_OVERHEAD_BYTES,
        estimated_peak_bytes=estimated_peak,
        available_memory_bytes=available,
        required_memory_with_reserve_bytes=required_memory,
        free_disk_bytes=free_disk,
        required_disk_with_reserve_bytes=required_disk,
    )
    if available < required_memory:
        raise NetworkBaselineError("insufficient_memory_for_random_forest_fit")
    if free_disk < required_disk:
        raise NetworkBaselineError("insufficient_disk_for_random_forest_artifacts")
    return estimate


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


def load_verified_logistic_comparison(
    logistic_run_directory: Path,
    inputs: VerifiedPreprocessingArtifacts,
) -> dict[str, dict[str, Any]]:
    """Load aggregate prior metrics only after exact validation/provenance binding."""
    logistic_run_directory = logistic_run_directory.resolve()
    config_path = logistic_run_directory / "model_config.json"
    report_path = logistic_run_directory / "evaluation_report.json"
    model_path = logistic_run_directory / "logistic_regression.joblib"
    configuration = _read_json(config_path, "logistic_comparison_configuration_unreadable")
    report = _read_json(report_path, "logistic_comparison_report_unreadable")
    preprocessing = configuration.get("preprocessing")
    decision = configuration.get("decision_threshold")
    validation = report.get("validation")
    model = report.get("model")
    if (
        configuration.get("schema_version") != LOGISTIC_SCHEMA_VERSION
        or configuration.get("fit_partition") != "train"
        or configuration.get("evaluation_partition") != "validation"
        or configuration.get("label_mapping") != LABEL_MAPPING
        or not isinstance(preprocessing, dict)
        or preprocessing.get("state_sha256") != inputs.state_sha256
        or preprocessing.get("configuration_sha256") != inputs.configuration_sha256
        or preprocessing.get("report_sha256") != inputs.report_sha256
        or preprocessing.get("transformed_feature_names") != list(TRANSFORMED_FEATURE_NAMES)
        or not isinstance(decision, dict)
        or decision
        != {
            "positive_label": 1,
            "positive_name": "Attack",
            "operator": ">=",
            "probability": ATTACK_THRESHOLD,
        }
        or report.get("schema_version") != LOGISTIC_SCHEMA_VERSION
        or report.get("completed") is not True
        or report.get("global_training_ready") is not False
        or report.get("configuration_sha256") != sha256_file(config_path)
        or not isinstance(validation, dict)
        or validation.get("sample_count") != inputs.y_validation.shape[0]
        or validation.get("normal_count") != int(np.count_nonzero(inputs.y_validation == 0))
        or validation.get("attack_count") != int(np.count_nonzero(inputs.y_validation == 1))
        or not isinstance(model, dict)
        or model.get("filename") != model_path.name
        or not model_path.is_file()
        or model.get("size_bytes") != model_path.stat().st_size
    ):
        raise NetworkBaselineError("logistic_comparison_provenance_mismatch")
    expected_model_hash = _require_sha256(
        model.get("sha256"), "logistic_comparison_model_hash_invalid"
    )
    if sha256_file(model_path) != expected_model_hash:
        raise NetworkBaselineError("logistic_comparison_model_hash_mismatch")
    logistic_metrics = validation.get("logistic_regression")
    reference_metrics = validation.get("always_benign_reference")
    for metrics in (logistic_metrics, reference_metrics):
        if (
            not isinstance(metrics, dict)
            or metrics.get("sample_count") != inputs.y_validation.shape[0]
            or metrics.get("decision_threshold") != ATTACK_THRESHOLD
        ):
            raise NetworkBaselineError("logistic_comparison_metrics_invalid")
    expected_reference = calculate_binary_metrics(
        inputs.y_validation, np.zeros(inputs.y_validation.shape[0], dtype=np.float64)
    )
    if reference_metrics != expected_reference:
        raise NetworkBaselineError("logistic_reference_metrics_mismatch")
    return {
        "logistic_regression": logistic_metrics,
        "always_benign_reference": reference_metrics,
    }


def run_synthetic_random_forest_smoke() -> dict[str, Any]:
    """Exercise the frozen forest, class mapping, and batched path on a tiny fixture."""
    matrix = np.asarray(
        [
            [-3.0, 0.0],
            [-2.0, 1.0],
            [-1.0, 0.0],
            [1.0, 1.0],
            [2.0, 0.0],
            [3.0, 1.0],
        ],
        dtype=np.float64,
    )
    labels = np.asarray([0, 0, 0, 1, 1, 1], dtype=np.uint8)
    model = create_frozen_random_forest()
    with threadpool_limits(limits=NESTED_NUMERICAL_THREADS):
        fit_train_only(model, matrix, labels)
        scores = batched_attack_probabilities(model, matrix, batch_size=2)
    if len(model.estimators_) != 100 or scores.shape != labels.shape:
        raise NetworkBaselineError("random_forest_synthetic_smoke_failed")
    return {
        "completed": True,
        "sample_count": int(labels.size),
        "tree_count": len(model.estimators_),
        "class_mapping": [int(value) for value in model.classes_],
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


def _resource_payload(estimate: RandomForestResourceEstimate) -> dict[str, int]:
    return {
        field: int(getattr(estimate, field))
        for field in RandomForestResourceEstimate.__dataclass_fields__
    }


def _safe_artifact_root(project_root: Path, artifact_root: Path) -> Path:
    resolved = artifact_root.resolve()
    if not resolved.is_relative_to((project_root.resolve() / "artifacts/models").resolve()):
        raise NetworkBaselineError("artifact_root_must_be_under_artifacts_models")
    return resolved


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _tree_summary(model: RandomForestClassifier) -> dict[str, Any]:
    depths = np.asarray([tree.tree_.max_depth for tree in model.estimators_], dtype=np.int64)
    nodes = np.asarray([tree.tree_.node_count for tree in model.estimators_], dtype=np.int64)
    return {
        "actual_tree_count": len(model.estimators_),
        "depth": {
            "minimum": int(depths.min()),
            "maximum": int(depths.max()),
            "mean": float(depths.mean()),
            "median": float(np.median(depths)),
        },
        "node_count": {
            "minimum": int(nodes.min()),
            "maximum": int(nodes.max()),
            "mean": float(nodes.mean()),
            "median": float(np.median(nodes)),
            "total": int(nodes.sum()),
        },
    }


def run_network_random_forest_baseline(
    project_root: Path,
    preprocessing_run_directory: Path,
    logistic_run_directory: Path,
    artifact_root: Path,
    run_id: str,
) -> RandomForestRunResult:
    """Fit once on full TRAIN, evaluate VALIDATION, and compare verified prior metrics."""
    started = time.monotonic()
    if not _RUN_ID.fullmatch(run_id):
        raise NetworkBaselineError("invalid_run_id")
    project_root = project_root.resolve()
    verify_started = time.monotonic()
    inputs = verify_preprocessing_artifacts(preprocessing_run_directory)
    prior_metrics = load_verified_logistic_comparison(logistic_run_directory, inputs)
    verification_seconds = time.monotonic() - verify_started
    artifact_root = _safe_artifact_root(project_root, artifact_root)
    artifact_root.mkdir(parents=True, exist_ok=True)
    resources = estimate_random_forest_resources(inputs.X_train, inputs.y_train, artifact_root)
    smoke_started = time.monotonic()
    smoke = run_synthetic_random_forest_smoke()
    smoke_seconds = time.monotonic() - smoke_started

    run_directory = artifact_root / run_id
    try:
        run_directory.mkdir()
    except FileExistsError as exc:
        raise NetworkBaselineError("run_directory_already_exists") from exc
    model = create_frozen_random_forest()
    configuration = {
        "schema_version": RANDOM_FOREST_SCHEMA_VERSION,
        "experiment_authorization": "explicit_network_only_random_forest_baseline",
        "estimator": "sklearn.ensemble.RandomForestClassifier",
        "frozen_parameters": FROZEN_RANDOM_FOREST_PARAMETERS,
        "effective_parameters": effective_random_forest_parameters(model),
        "decision_threshold": {
            "positive_label": 1,
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
        "comparison": {
            "logistic_run_report_sha256": sha256_file(
                logistic_run_directory / "evaluation_report.json"
            ),
            "same_preprocessing_and_validation_verified": True,
        },
        "training_controls": {
            "external_resampling": False,
            "internal_bootstrap_sampling": True,
            "eligible_training_rows_reduced": False,
            "class_weighting": False,
            "hyperparameter_search": False,
            "calibration": False,
            "feature_selection": False,
            "threshold_tuning": False,
            "forest_workers": 4,
            "nested_numerical_thread_limit": NESTED_NUMERICAL_THREADS,
            "prediction_batch_size": PREDICTION_BATCH_SIZE,
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
        with threadpool_limits(limits=NESTED_NUMERICAL_THREADS):
            threadpools_during_fit = _threadpool_payload()
            fit_train_only(model, inputs.X_train, inputs.y_train)
        fit_seconds = time.monotonic() - fit_started

        evaluation_started = time.monotonic()
        with threadpool_limits(limits=NESTED_NUMERICAL_THREADS):
            forest_scores = batched_attack_probabilities(model, inputs.X_validation)
        forest_metrics = calculate_binary_metrics(inputs.y_validation, forest_scores)
        evaluation_seconds = time.monotonic() - evaluation_started

        model_path = run_directory / MODEL_FILENAME
        joblib.dump(model, model_path, compress=3)
        reloaded = joblib.load(model_path)
        sample_size = min(RELOAD_SAMPLE_SIZE, inputs.X_validation.shape[0])
        sample = inputs.X_validation[:sample_size]
        with threadpool_limits(limits=NESTED_NUMERICAL_THREADS):
            original_scores = batched_attack_probabilities(model, sample, batch_size=1024)
            reloaded_scores = batched_attack_probabilities(reloaded, sample, batch_size=1024)
        probabilities_equal, reload_maximum_difference = reload_probabilities_equivalent(
            original_scores, reloaded_scores
        )
        predictions_equal = bool(
            np.array_equal(
                threshold_attack_scores(original_scores), threshold_attack_scores(reloaded_scores)
            )
        )
        if not probabilities_equal or not predictions_equal:
            raise NetworkBaselineError("saved_random_forest_reload_mismatch")

        elapsed = time.monotonic() - started
        tree_summary = _tree_summary(model)
        report = {
            "schema_version": RANDOM_FOREST_SCHEMA_VERSION,
            "completed": True,
            "global_training_ready": False,
            "network_only_authorized_experiment": True,
            "configuration_sha256": sha256_file(configuration_path),
            "model": {
                "filename": MODEL_FILENAME,
                "sha256": sha256_file(model_path),
                "size_bytes": model_path.stat().st_size,
                "classes": [int(value) for value in model.classes_],
                "attack_probability_column": attack_probability_column(model),
                "tree_summary": tree_summary,
            },
            "validation": {
                "sample_count": int(inputs.y_validation.shape[0]),
                "normal_count": int(np.count_nonzero(inputs.y_validation == 0)),
                "attack_count": int(np.count_nonzero(inputs.y_validation == 1)),
                "random_forest": forest_metrics,
                **prior_metrics,
                "comparison_provenance_verified": True,
                "average_precision_definition": (
                    "non-interpolated average precision from continuous Attack scores; "
                    "not trapezoidal PR-AUC"
                ),
            },
            "timings_seconds": {
                "input_and_comparison_verification": verification_seconds,
                "synthetic_smoke": smoke_seconds,
                "fit": fit_seconds,
                "validation_evaluation": evaluation_seconds,
                "total": elapsed,
            },
            "resource_controls": {
                **_resource_payload(resources),
                "forest_workers": 4,
                "nested_numerical_threads": NESTED_NUMERICAL_THREADS,
                "threadpools_during_fit": threadpools_during_fit,
                "matrices_memory_mapped": True,
                "bounded_prediction_batch_size": PREDICTION_BATCH_SIZE,
                "full_train_used_without_external_subsampling": True,
            },
            "reload_verification": {
                "sample_count": sample_size,
                "probabilities_equivalent_within_tolerance": probabilities_equal,
                "probability_absolute_tolerance": RELOAD_PROBABILITY_ABSOLUTE_TOLERANCE,
                "maximum_absolute_probability_difference": reload_maximum_difference,
                "predictions_exactly_equal": predictions_equal,
            },
            "checks": {
                "preprocessing_evidence_verified": True,
                "preprocessing_state_reused_without_refit": True,
                "logistic_comparison_provenance_verified": True,
                "frozen_configuration_recorded_before_fit": True,
                "train_only_fit": True,
                "validation_only_evaluation": True,
                "test_and_cic_not_accessed": True,
                "saved_model_reload_equivalent": True,
                "actual_tree_count_matches_configuration": (
                    tree_summary["actual_tree_count"]
                    == FROZEN_RANDOM_FOREST_PARAMETERS["n_estimators"]
                ),
            },
            "artifact_size_bytes_excluding_report": sum(
                path.stat().st_size for path in run_directory.iterdir() if path.is_file()
            ),
            "limitations": [
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
        return RandomForestRunResult(
            run_directory=run_directory,
            report_path=report_path,
            model_path=model_path,
            elapsed_seconds=elapsed,
        )
    except Exception as exc:
        code = exc.code if isinstance(exc, NetworkBaselineError) else "internal_forest_failure"
        _write_json(
            run_directory / "baseline_failure.json",
            {
                "schema_version": RANDOM_FOREST_SCHEMA_VERSION,
                "completed": False,
                "failure_code": code,
            },
        )
        raise


def finalize_fitted_random_forest_run(
    project_root: Path,
    preprocessing_run_directory: Path,
    logistic_run_directory: Path,
    run_directory: Path,
) -> RandomForestRunResult:
    """Finalize a saved fitted forest after a roundoff-only exact-reload failure, without refit."""
    started = time.monotonic()
    project_root = project_root.resolve()
    run_directory = run_directory.resolve()
    allowed = (project_root / "artifacts/models/network_random_forest_baseline").resolve()
    if not run_directory.is_relative_to(allowed):
        raise NetworkBaselineError("recovery_run_directory_invalid")
    failure_path = run_directory / "baseline_failure.json"
    failure = _read_json(failure_path, "recovery_failure_evidence_unreadable")
    if (
        failure.get("schema_version") != RANDOM_FOREST_SCHEMA_VERSION
        or failure.get("completed") is not False
        or failure.get("failure_code") != "saved_random_forest_reload_mismatch"
        or (run_directory / EVALUATION_REPORT_FILENAME).exists()
    ):
        raise NetworkBaselineError("recovery_failure_evidence_invalid")

    verification_started = time.monotonic()
    inputs = verify_preprocessing_artifacts(preprocessing_run_directory)
    prior_metrics = load_verified_logistic_comparison(logistic_run_directory, inputs)
    configuration_path = run_directory / MODEL_CONFIG_FILENAME
    configuration = _read_json(configuration_path, "recovery_configuration_unreadable")
    expected_effective = effective_random_forest_parameters(create_frozen_random_forest())
    if (
        configuration.get("schema_version") != RANDOM_FOREST_SCHEMA_VERSION
        or configuration.get("frozen_parameters") != FROZEN_RANDOM_FOREST_PARAMETERS
        or configuration.get("effective_parameters") != expected_effective
        or configuration.get("fit_partition") != "train"
        or configuration.get("evaluation_partition") != "validation"
        or configuration.get("label_mapping") != LABEL_MAPPING
        or configuration.get("decision_threshold")
        != {
            "positive_label": 1,
            "positive_name": "Attack",
            "operator": ">=",
            "probability": ATTACK_THRESHOLD,
        }
        or configuration.get("preprocessing", {}).get("state_sha256") != inputs.state_sha256
        or configuration.get("preprocessing", {}).get("configuration_sha256")
        != inputs.configuration_sha256
        or configuration.get("preprocessing", {}).get("report_sha256") != inputs.report_sha256
        or configuration.get("preprocessing", {}).get("transformed_feature_names")
        != list(TRANSFORMED_FEATURE_NAMES)
    ):
        raise NetworkBaselineError("recovery_configuration_mismatch")
    model_path = run_directory / MODEL_FILENAME
    try:
        model = joblib.load(model_path)
        reloaded = joblib.load(model_path)
    except Exception as exc:
        raise NetworkBaselineError("recovery_model_unreadable") from exc
    if (
        not isinstance(model, RandomForestClassifier)
        or effective_random_forest_parameters(model) != expected_effective
        or len(model.estimators_) != FROZEN_RANDOM_FOREST_PARAMETERS["n_estimators"]
    ):
        raise NetworkBaselineError("recovery_model_configuration_mismatch")
    verification_seconds = time.monotonic() - verification_started

    evaluation_started = time.monotonic()
    with threadpool_limits(limits=NESTED_NUMERICAL_THREADS):
        threadpools_during_evaluation = _threadpool_payload()
        forest_scores = batched_attack_probabilities(model, inputs.X_validation)
    forest_metrics = calculate_binary_metrics(inputs.y_validation, forest_scores)
    evaluation_seconds = time.monotonic() - evaluation_started

    sample_size = min(RELOAD_SAMPLE_SIZE, inputs.X_validation.shape[0])
    sample = inputs.X_validation[:sample_size]
    with threadpool_limits(limits=NESTED_NUMERICAL_THREADS):
        first_scores = batched_attack_probabilities(model, sample, batch_size=1024)
        second_scores = batched_attack_probabilities(reloaded, sample, batch_size=1024)
    probabilities_equivalent, maximum_difference = reload_probabilities_equivalent(
        first_scores, second_scores
    )
    predictions_equal = bool(
        np.array_equal(
            threshold_attack_scores(first_scores), threshold_attack_scores(second_scores)
        )
    )
    if not probabilities_equivalent or not predictions_equal:
        raise NetworkBaselineError("saved_random_forest_reload_mismatch")

    tree_summary = _tree_summary(model)
    initial_wall_interval = max(
        0.0, model_path.stat().st_mtime - configuration_path.stat().st_mtime
    )
    diagnostic_path = run_directory / "initial_exact_reload_failure.json"
    failure_path.replace(diagnostic_path)
    elapsed = time.monotonic() - started
    report = {
        "schema_version": RANDOM_FOREST_SCHEMA_VERSION,
        "completed": True,
        "global_training_ready": False,
        "network_only_authorized_experiment": True,
        "configuration_sha256": sha256_file(configuration_path),
        "model": {
            "filename": MODEL_FILENAME,
            "sha256": sha256_file(model_path),
            "size_bytes": model_path.stat().st_size,
            "classes": [int(value) for value in model.classes_],
            "attack_probability_column": attack_probability_column(model),
            "tree_summary": tree_summary,
        },
        "validation": {
            "sample_count": int(inputs.y_validation.shape[0]),
            "normal_count": int(np.count_nonzero(inputs.y_validation == 0)),
            "attack_count": int(np.count_nonzero(inputs.y_validation == 1)),
            "random_forest": forest_metrics,
            **prior_metrics,
            "comparison_provenance_verified": True,
            "average_precision_definition": (
                "non-interpolated average precision from continuous Attack scores; "
                "not trapezoidal PR-AUC"
            ),
        },
        "timings_seconds": {
            "exact_fit": None,
            "exact_fit_status": (
                "not persisted before the initial exact-reload check failed; model was not refit"
            ),
            "initial_config_to_model_wall_interval": initial_wall_interval,
            "recovery_input_and_comparison_verification": verification_seconds,
            "recovery_validation_evaluation": evaluation_seconds,
            "recovery_total": elapsed,
        },
        "resource_controls": {
            **configuration["resource_estimate"],
            "forest_workers": 4,
            "nested_numerical_threads": NESTED_NUMERICAL_THREADS,
            "threadpools_during_recovery_evaluation": threadpools_during_evaluation,
            "matrices_memory_mapped": True,
            "bounded_prediction_batch_size": PREDICTION_BATCH_SIZE,
            "full_train_used_without_external_subsampling": True,
        },
        "reload_verification": {
            "sample_count": sample_size,
            "probabilities_equivalent_within_tolerance": probabilities_equivalent,
            "probability_absolute_tolerance": RELOAD_PROBABILITY_ABSOLUTE_TOLERANCE,
            "maximum_absolute_probability_difference": maximum_difference,
            "predictions_exactly_equal": predictions_equal,
            "initial_exact_comparison_failed_on_roundoff_only": True,
            "recovered_without_refit": True,
        },
        "checks": {
            "preprocessing_evidence_verified": True,
            "preprocessing_state_reused_without_refit": True,
            "logistic_comparison_provenance_verified": True,
            "frozen_configuration_recorded_before_fit": True,
            "train_only_fit": True,
            "validation_only_evaluation": True,
            "test_and_cic_not_accessed": True,
            "saved_model_reload_equivalent": True,
            "model_refit_during_recovery": False,
            "actual_tree_count_matches_configuration": (
                tree_summary["actual_tree_count"] == FROZEN_RANDOM_FOREST_PARAMETERS["n_estimators"]
            ),
        },
        "artifact_size_bytes_excluding_report": sum(
            path.stat().st_size for path in run_directory.iterdir() if path.is_file()
        ),
        "limitations": [
            "exact fit time was not persisted before the initial strict reload check failed",
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
    return RandomForestRunResult(
        run_directory=run_directory,
        report_path=report_path,
        model_path=model_path,
        elapsed_seconds=elapsed,
    )
