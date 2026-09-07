"""February-only evaluation of saved classical network models."""

from __future__ import annotations

import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import time
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from numpy.lib.format import open_memmap
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from threadpoolctl import threadpool_limits

from threatfusion.models.network_logistic_baseline import (
    ATTACK_THRESHOLD,
    BASELINE_SCHEMA_VERSION,
    NetworkBaselineError,
    attack_probabilities,
    calculate_binary_metrics,
    verify_preprocessing_artifacts,
)
from threatfusion.models.network_random_forest_baseline import (
    NESTED_NUMERICAL_THREADS,
    PREDICTION_BATCH_SIZE,
    RANDOM_FOREST_SCHEMA_VERSION,
    batched_attack_probabilities,
)
from threatfusion.preprocessing.network_behavior_v1 import (
    LABEL_MAPPING,
    TRANSFORMED_FEATURE_NAMES,
    AssignedRecord,
    NetworkBehaviorPreprocessor,
    NetworkPreprocessingError,
    encode_binary_label,
    iter_assigned_source_records,
    verify_assignment_evidence,
)
from threatfusion.utils.checksum import sha256_file

EVALUATION_SCHEMA_VERSION = "unsw_february_classical_evaluation_v1"
EXPECTED_TEST_COUNTS = {"rows": 1_452_844, "normal": 1_153_776, "attack": 299_068}
DEFAULT_BATCH_SIZE = 10_000
MINIMUM_FREE_BYTES = 2 * 1024**3
MEMORY_RESERVE_BYTES = 1024**3
BASELINE_COMMIT = "2528ee8744e06f7a7a8c7e171a7668eb33e4adea"
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class VerifiedSavedModel:
    """A saved estimator bound to its verified training evidence."""

    name: str
    model: LogisticRegression | RandomForestClassifier
    model_sha256: str
    configuration_sha256: str
    report_sha256: str
    validation_metrics: dict[str, Any]


@dataclass(frozen=True, slots=True)
class FebruaryEvaluationResult:
    """Sanitized aggregate result of a completed evaluation."""

    run_directory: Path
    report_path: Path
    test_rows: int
    elapsed_seconds: float


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


def write_failure_status(run_directory: Path, code: str) -> Path:
    """Persist sanitized evidence that a partial run did not complete."""
    path = run_directory / "evaluation_failure.json"
    _write_json(
        path,
        {
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "completed": False,
            "failure_code": code,
        },
    )
    return path


def _hash(value: object, code: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise NetworkBaselineError(code)
    return value


def verify_saved_model(
    run_directory: Path,
    preprocessing: Any,
    *,
    name: str,
) -> VerifiedSavedModel:
    """Verify a known saved baseline and its exact preprocessing/validation binding."""
    specifications = {
        "logistic_regression": (
            BASELINE_SCHEMA_VERSION,
            "logistic_regression.joblib",
            LogisticRegression,
        ),
        "random_forest": (
            RANDOM_FOREST_SCHEMA_VERSION,
            "random_forest.joblib",
            RandomForestClassifier,
        ),
    }
    if name not in specifications:
        raise ValueError("unsupported saved model")
    schema, filename, model_type = specifications[name]
    run_directory = run_directory.resolve()
    config_path = run_directory / "model_config.json"
    report_path = run_directory / "evaluation_report.json"
    model_path = run_directory / filename
    config = _read_json(config_path, f"{name}_configuration_unreadable")
    report = _read_json(report_path, f"{name}_report_unreadable")
    binding = config.get("preprocessing")
    decision = config.get("decision_threshold")
    model_evidence = report.get("model")
    validation = report.get("validation")
    expected_decision = {
        "positive_label": 1,
        "positive_name": "Attack",
        "operator": ">=",
        "probability": ATTACK_THRESHOLD,
    }
    if (
        config.get("schema_version") != schema
        or config.get("fit_partition") != "train"
        or config.get("evaluation_partition") != "validation"
        or config.get("label_mapping") != LABEL_MAPPING
        or decision != expected_decision
        or not isinstance(binding, dict)
        or binding.get("state_sha256") != preprocessing.state_sha256
        or binding.get("configuration_sha256") != preprocessing.configuration_sha256
        or binding.get("report_sha256") != preprocessing.report_sha256
        or binding.get("transformed_feature_names") != list(TRANSFORMED_FEATURE_NAMES)
        or report.get("schema_version") != schema
        or report.get("completed") is not True
        or report.get("configuration_sha256") != sha256_file(config_path)
        or not isinstance(model_evidence, dict)
        or model_evidence.get("filename") != filename
        or not isinstance(validation, dict)
        or validation.get("sample_count") != preprocessing.y_validation.shape[0]
        or validation.get("normal_count") != int(np.count_nonzero(preprocessing.y_validation == 0))
        or validation.get("attack_count") != int(np.count_nonzero(preprocessing.y_validation == 1))
        or not isinstance(validation.get(name), dict)
    ):
        raise NetworkBaselineError(f"{name}_evidence_mismatch")
    expected_model_hash = _hash(model_evidence.get("sha256"), f"{name}_model_hash_invalid")
    if (
        not model_path.is_file()
        or model_path.stat().st_size != model_evidence.get("size_bytes")
        or sha256_file(model_path) != expected_model_hash
    ):
        raise NetworkBaselineError(f"{name}_model_integrity_failure")
    try:
        model = joblib.load(model_path)
    except Exception as exc:
        raise NetworkBaselineError(f"{name}_model_unreadable") from exc
    if not isinstance(model, model_type):
        raise NetworkBaselineError(f"{name}_model_type_mismatch")
    if getattr(model, "n_features_in_", None) != len(TRANSFORMED_FEATURE_NAMES):
        raise NetworkBaselineError(f"{name}_feature_order_mismatch")
    # This validates the fitted classes and the Attack probability column without predicting.
    classes = np.asarray(model.classes_)
    if classes.tolist() != [0, 1]:
        raise NetworkBaselineError(f"{name}_class_mapping_mismatch")
    return VerifiedSavedModel(
        name=name,
        model=model,
        model_sha256=expected_model_hash,
        configuration_sha256=sha256_file(config_path),
        report_sha256=sha256_file(report_path),
        validation_metrics=validation[name],
    )


def transform_test_records(
    records: Iterable[AssignedRecord],
    preprocessor: NetworkBehaviorPreprocessor,
    matrix: np.memmap,
    labels: np.memmap,
    expected_split_counts: dict[str, dict[str, int | None]],
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
    progress: Callable[[int], None] | None = None,
) -> dict[str, Any]:
    """Transform only TEST while reconciling every streamed assignment exactly once."""
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    buffer: list[Any] = []
    offset = 0
    disposition_counts: Counter[str] = Counter()
    label_counts = {name: Counter() for name in expected_split_counts}

    def flush() -> None:
        nonlocal offset
        if not buffer:
            return
        stop = offset + len(buffer)
        if stop > matrix.shape[0]:
            raise NetworkBaselineError("test_assignment_count_exceeded")
        matrix[offset:stop] = preprocessor.transform_batch(buffer)
        labels[offset:stop] = np.asarray(
            [encode_binary_label(record.label) for record in buffer], dtype=np.uint8
        )
        offset = stop
        buffer.clear()

    for processed, assigned in enumerate(records, start=1):
        disposition_counts[assigned.disposition] += 1
        if assigned.flow is not None:
            label_counts[assigned.disposition][encode_binary_label(assigned.flow.label)] += 1
        if assigned.disposition == "test":
            if assigned.flow is None:
                raise NetworkBaselineError("selected_test_record_missing")
            buffer.append(assigned.flow)
            if len(buffer) >= batch_size:
                flush()
        if progress is not None and processed % 250_000 == 0:
            progress(processed)
    flush()
    if offset != matrix.shape[0] or labels.shape[0] != matrix.shape[0]:
        raise NetworkBaselineError("test_assignment_count_mismatch")
    for disposition, expected in expected_split_counts.items():
        if disposition_counts[disposition] != expected.get("total_count"):
            raise NetworkBaselineError("assignment_count_reconciliation_failed")
        if disposition != "rejected" and (
            label_counts[disposition][0] != expected.get("benign_count")
            or label_counts[disposition][1] != expected.get("attack_count")
        ):
            raise NetworkBaselineError("assignment_label_reconciliation_failed")
    matrix.flush()
    labels.flush()
    return {
        "rows": offset,
        "normal": int(label_counts["test"][0]),
        "attack": int(label_counts["test"][1]),
        "dispositions": dict(sorted(disposition_counts.items())),
    }


def predict_in_batches(model: Any, matrix: np.ndarray, *, batch_size: int) -> np.ndarray:
    """Predict Attack probabilities in stable bounded batches without fitting."""
    if isinstance(model, RandomForestClassifier):
        return batched_attack_probabilities(model, matrix, batch_size=batch_size)
    scores = np.empty(matrix.shape[0], dtype=np.float64)
    for start in range(0, matrix.shape[0], batch_size):
        stop = min(start + batch_size, matrix.shape[0])
        scores[start:stop] = attack_probabilities(model, matrix[start:stop])
    return scores


def _dependency_versions() -> dict[str, str]:
    versions = {"python": platform.python_version()}
    for package in ("numpy", "scipy", "scikit-learn", "joblib", "threadpoolctl"):
        versions[package] = importlib.metadata.version(package)
    return versions


def _git_provenance(project_root: Path) -> dict[str, Any]:
    def run(*args: str) -> str:
        result = subprocess.run(
            ["git", *args], cwd=project_root, check=True, capture_output=True, text=True
        )
        return result.stdout.strip()

    return {
        "baseline_commit": BASELINE_COMMIT,
        "head": run("rev-parse", "HEAD"),
        "working_tree_dirty": bool(run("status", "--porcelain")),
    }


def _resource_evidence(artifact_root: Path) -> dict[str, int]:
    try:
        available = next(
            int(line.split()[1]) * 1024
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()
            if line.startswith("MemAvailable:")
        )
    except (OSError, StopIteration, ValueError, IndexError) as exc:
        raise NetworkBaselineError("available_memory_unreadable") from exc
    matrix_bytes = EXPECTED_TEST_COUNTS["rows"] * len(TRANSFORMED_FEATURE_NAMES) * 8
    labels_and_scores = EXPECTED_TEST_COUNTS["rows"] * (1 + 8 * 2)
    metric_working = EXPECTED_TEST_COUNTS["rows"] * 8 * 8
    estimated = matrix_bytes + labels_and_scores + metric_working + 256 * 1024**2
    free = shutil.disk_usage(artifact_root).free
    required_disk = matrix_bytes + EXPECTED_TEST_COUNTS["rows"] + MINIMUM_FREE_BYTES
    if available < estimated + MEMORY_RESERVE_BYTES:
        raise NetworkBaselineError("insufficient_memory_for_february_evaluation")
    if free < required_disk:
        raise NetworkBaselineError("insufficient_disk_for_february_evaluation")
    return {
        "available_memory_bytes": available,
        "estimated_peak_memory_bytes": estimated,
        "required_memory_with_reserve_bytes": estimated + MEMORY_RESERVE_BYTES,
        "free_disk_bytes": free,
        "required_disk_with_reserve_bytes": required_disk,
    }


def run_february_smoke(
    *,
    project_root: Path,
    manifest_path: Path,
    assignment_directory: Path,
    preflight_report_path: Path,
    preprocessing_directory: Path,
    logistic_directory: Path,
    forest_directory: Path,
    artifact_root: Path,
    run_id: str,
    max_records: int,
) -> Path:
    """Verify all evidence and bounded joining, producing explicitly partial evidence."""
    if max_records <= 0 or not _RUN_ID.fullmatch(run_id):
        raise ValueError("invalid smoke configuration")
    inputs = verify_preprocessing_artifacts(preprocessing_directory)
    evidence = verify_assignment_evidence(
        project_root, manifest_path, assignment_directory, preflight_report_path
    )
    verify_saved_model(logistic_directory, inputs, name="logistic_regression")
    verify_saved_model(forest_directory, inputs, name="random_forest")
    checked = Counter()
    for assigned in iter_assigned_source_records(project_root, evidence, max_records=max_records):
        checked[assigned.disposition] += 1
        if assigned.disposition == "test" and assigned.flow is not None:
            inputs.state.transform(assigned.flow)
    artifact_root.mkdir(parents=True, exist_ok=True)
    run_directory = artifact_root / run_id
    try:
        run_directory.mkdir()
    except FileExistsError as exc:
        raise NetworkBaselineError("run_directory_already_exists") from exc
    path = run_directory / "smoke_report.json"
    _write_json(
        path,
        {
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "completed": False,
            "partial": True,
            "purpose": "bounded pre-execution smoke; not February evaluation",
            "records_checked": sum(checked.values()),
            "dispositions": dict(sorted(checked.items())),
            "models_verified": ["logistic_regression", "random_forest"],
        },
    )
    return path


def run_february_evaluation(
    *,
    project_root: Path,
    manifest_path: Path,
    assignment_directory: Path,
    preflight_report_path: Path,
    preprocessing_directory: Path,
    logistic_directory: Path,
    forest_directory: Path,
    artifact_root: Path,
    run_id: str,
    batch_size: int = DEFAULT_BATCH_SIZE,
    progress: Callable[[str, int], None] | None = None,
) -> FebruaryEvaluationResult:
    """Transform February TEST once and evaluate two already-fitted models."""
    started = time.monotonic()
    if not _RUN_ID.fullmatch(run_id) or batch_size <= 0:
        raise ValueError("invalid evaluation configuration")
    project_root = project_root.resolve()
    artifact_root = artifact_root.resolve()
    allowed_root = (project_root / "artifacts/reports/network_classical_evaluation").resolve()
    if artifact_root != allowed_root:
        raise NetworkBaselineError("artifact_root_invalid")
    artifact_root.mkdir(parents=True, exist_ok=True)
    resources = _resource_evidence(artifact_root)

    verification_started = time.monotonic()
    inputs = verify_preprocessing_artifacts(preprocessing_directory)
    evidence = verify_assignment_evidence(
        project_root, manifest_path, assignment_directory, preflight_report_path
    )
    if inputs.configuration.get("assignment") != {
        "schema_version": evidence.report["schema_version"],
        "seed": evidence.report["policy"]["seed"],
        "report_sha256": evidence.report_sha256,
        "archive_sha256": evidence.assignment_sha256,
        "preflight_report_sha256": evidence.preflight_report_sha256,
    }:
        raise NetworkBaselineError("preprocessing_assignment_binding_mismatch")
    logistic = verify_saved_model(logistic_directory, inputs, name="logistic_regression")
    forest = verify_saved_model(forest_directory, inputs, name="random_forest")
    verification_seconds = time.monotonic() - verification_started

    run_directory = artifact_root / run_id
    try:
        run_directory.mkdir()
    except FileExistsError as exc:
        raise NetworkBaselineError("run_directory_already_exists") from exc
    state_path = preprocessing_directory / "preprocessor_state.json"
    state_hash_before = sha256_file(state_path)
    config = {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "evaluation_partition": "test",
        "test_period": "2015-02-18T00:00:00Z/2015-02-19T00:00:00Z",
        "label_mapping": LABEL_MAPPING,
        "decision_threshold": {"operator": ">=", "probability": ATTACK_THRESHOLD},
        "expected_counts": EXPECTED_TEST_COUNTS,
        "transformed_feature_names": list(TRANSFORMED_FEATURE_NAMES),
        "batch_size": batch_size,
        "no_fit_or_selection": True,
        "preprocessing": {
            "state_sha256": inputs.state_sha256,
            "configuration_sha256": inputs.configuration_sha256,
            "report_sha256": inputs.report_sha256,
        },
        "assignment": {
            "report_sha256": evidence.report_sha256,
            "archive_sha256": evidence.assignment_sha256,
            "preflight_report_sha256": evidence.preflight_report_sha256,
        },
        "models": {
            item.name: {
                "model_sha256": item.model_sha256,
                "configuration_sha256": item.configuration_sha256,
                "report_sha256": item.report_sha256,
            }
            for item in (logistic, forest)
        },
        "dependencies": _dependency_versions(),
        "interpreter": os.path.realpath(os.sys.executable),
        "code_provenance": _git_provenance(project_root),
        "resource_evidence": resources,
    }
    config_path = run_directory / "evaluation_config.json"
    _write_json(config_path, config)
    partial_x = run_directory / "X_test.partial.npy"
    partial_y = run_directory / "y_test.partial.npy"
    try:
        matrix = open_memmap(
            partial_x,
            mode="w+",
            dtype=np.float64,
            shape=(EXPECTED_TEST_COUNTS["rows"], len(TRANSFORMED_FEATURE_NAMES)),
        )
        labels = open_memmap(
            partial_y, mode="w+", dtype=np.uint8, shape=(EXPECTED_TEST_COUNTS["rows"],)
        )
        transform_started = time.monotonic()
        counts = transform_test_records(
            iter_assigned_source_records(project_root, evidence),
            inputs.state,
            matrix,
            labels,
            evidence.report["split_counts"],
            batch_size=batch_size,
            progress=(lambda count: progress("transform", count)) if progress else None,
        )
        transform_seconds = time.monotonic() - transform_started
        if counts != {**EXPECTED_TEST_COUNTS, "dispositions": counts["dispositions"]}:
            raise NetworkBaselineError("february_test_counts_mismatch")
        if sha256_file(state_path) != state_hash_before:
            raise NetworkBaselineError("preprocessing_state_changed")
        if not np.isfinite(matrix).all():
            raise NetworkBaselineError("test_matrix_non_finite")
        partial_x.replace(run_directory / "X_test.npy")
        partial_y.replace(run_directory / "y_test.npy")
        matrix = np.load(run_directory / "X_test.npy", mmap_mode="r", allow_pickle=False)
        labels = np.load(run_directory / "y_test.npy", mmap_mode="r", allow_pickle=False)

        evaluation_started = time.monotonic()
        metrics: dict[str, Any] = {}
        with threadpool_limits(limits=NESTED_NUMERICAL_THREADS):
            for item in (logistic, forest):
                if progress:
                    progress(item.name, 0)
                scores = predict_in_batches(item.model, matrix, batch_size=PREDICTION_BATCH_SIZE)
                metrics[item.name] = calculate_binary_metrics(labels, scores)
        metrics["always_benign_reference"] = calculate_binary_metrics(
            labels, np.zeros(labels.shape[0], dtype=np.float64)
        )
        evaluation_seconds = time.monotonic() - evaluation_started
        elapsed = time.monotonic() - started
        report = {
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "completed": True,
            "global_training_ready": False,
            "configuration_sha256": sha256_file(config_path),
            "test": {**counts, **metrics},
            "validation": {
                "logistic_regression": logistic.validation_metrics,
                "random_forest": forest.validation_metrics,
                "provenance_verified": True,
            },
            "outputs": {
                name: {
                    "sha256": sha256_file(run_directory / name),
                    "size_bytes": (run_directory / name).stat().st_size,
                }
                for name in ("X_test.npy", "y_test.npy")
            },
            "checks": {
                "assignment_and_source_counts_reconciled": True,
                "assignment_and_raw_input_binding_verified": True,
                "preprocessing_state_unchanged": True,
                "saved_models_verified_and_not_refit": True,
                "test_only_transformed": True,
                "test_outputs_finite": True,
                "validation_comparison_provenance_verified": True,
                "cic_not_accessed": True,
            },
            "timings_seconds": {
                "input_verification": verification_seconds,
                "test_transformation": transform_seconds,
                "model_evaluation": evaluation_seconds,
                "total": elapsed,
            },
            "resource_controls": {
                **resources,
                "inputs_memory_mapped": True,
                "prediction_batch_size": PREDICTION_BATCH_SIZE,
                "numerical_thread_limit": NESTED_NUMERICAL_THREADS,
            },
            "artifact_size_bytes_excluding_report": sum(
                path.stat().st_size for path in run_directory.iterdir() if path.is_file()
            ),
            "limitations": [
                "February labels and aggregate duplication evidence were known before evaluation",
                "aggregate metrics cannot identify one cause of temporal performance changes",
                "feature collisions and conflicting labels remain in the frozen assignment",
                "near-duplicate leakage and capture/session provenance remain unresolved",
                "future model development must disclose that February results are known",
                "host training remains blocked and global readiness is unchanged",
            ],
        }
        report_path = run_directory / "evaluation_report.json"
        _write_json(report_path, report)
        return FebruaryEvaluationResult(run_directory, report_path, labels.shape[0], elapsed)
    except Exception as exc:
        code = (
            exc.code
            if isinstance(exc, (NetworkBaselineError, NetworkPreprocessingError))
            else "internal_evaluation_failure"
        )
        write_failure_status(run_directory, code)
        raise
