"""One January-only exploratory autoencoder with log1p-compressed rate inputs."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import resource
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
from numpy.lib.format import open_memmap
from threadpoolctl import threadpool_limits

from threatfusion.models.network_autoencoder import (
    ADAM_BETAS,
    ADAM_EPS,
    BATCH_SIZE,
    EPOCHS,
    EXPECTED_COUNTS,
    EXPECTED_FOREST_HASH,
    INPUT_WIDTH,
    LEARNING_RATE,
    QUANTILE,
    SEED,
    benign_train_indices,
    calculate_complementarity,
    calculate_metrics,
    calibrate_threshold,
    configure_deterministic_cpu_runtime,
    fit_frozen_autoencoder,
    load_verified_state,
    save_state_dict,
    score_records_v2,
    threshold_scores,
    verify_autoencoder_inputs,
    verify_reload_equivalence,
    verify_v2_reload_scoring,
)
from threatfusion.models.network_classical_evaluation import verify_saved_model
from threatfusion.models.network_random_forest_baseline import (
    PREDICTION_BATCH_SIZE,
    batched_attack_probabilities,
)
from threatfusion.preprocessing.network_behavior_v1 import (
    LABEL_MAPPING,
    iter_assigned_source_records,
    verify_assignment_evidence,
)
from threatfusion.utils.checksum import sha256_file

SCHEMA_VERSION = "unsw_network_rate_log1p_autoencoder_experiment_v1"
PREPROCESSING_SCHEMA_VERSION = "unsw_network_rate_log1p_preprocessing_v1"
MODEL_IDENTITY = "unsw_network_rate_log1p_benign_autoencoder_v1"
PREPROCESSING_IDENTITY = "unsw_train.rate_log1p_all_train_zscore.14_columns.v1"
SCORE_IDENTITY = "mean_squared_reconstruction_error_14_rate_log1p_float32_per_record_v1"
THRESHOLD_IDENTITY = "unsw_january_benign_higher_p99_rate_log1p_v1"
SCORING_CONTRACT_VERSION = "unsw_autoencoder_per_record_scoring_v2"
FEATURE_NAMES = (
    "duration_ms__zscore",
    "fwd_packets__zscore",
    "bwd_packets__zscore",
    "fwd_bytes__zscore",
    "bwd_bytes__zscore",
    "packets_per_second__log1p__zscore",
    "bytes_per_second__log1p__zscore",
    "fwd_packet_length_mean__zscore",
    "bwd_packet_length_mean__zscore",
    "dst_port__zscore",
    "protocol=tcp",
    "protocol=udp",
    "protocol=icmp",
    "protocol=other",
)
RATE_COLUMNS = (5, 6)
PREPARED_FILES = (
    "train_rates.npy",
    "validation_rates.npy",
    "train_record_ids.npy",
    "validation_record_ids.npy",
)
MAX_RSS_BYTES = 2 * 1024**3
MINIMUM_RESERVE_BYTES = 2 * 1024**3
ARTIFACT_BUDGET_BYTES = 256 * 1024**2
DEADLINE_SECONDS = 3600.0
BASELINE_METRICS = {
    "true_positive": 1988,
    "false_positive": 1628,
    "true_negative": 210582,
    "false_negative": 2370,
    "attack_precision": 0.5497787610619469,
    "attack_recall": 0.4561725562184488,
    "attack_f1": 0.4986205516549649,
    "false_positive_rate": 1628 / 212210,
}
BASELINE_COMPLEMENTARITY = {
    "attack": {
        "both_detected": 1892,
        "autoencoder_only_rf_missed": 96,
        "random_forest_only_ae_missed": 2153,
        "missed_by_both": 217,
    },
    "normal": {
        "both_false_positive": 54,
        "autoencoder_only_added_false_positive": 1574,
        "random_forest_only_false_positive": 147,
        "correctly_unflagged_by_both": 210435,
    },
}


class RateLog1pExperimentError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ExperimentResult:
    report_path: Path
    artifact_identity: str
    passed: bool


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_json_bytes(payload))
    temporary.replace(path)


def _peak_rss_bytes() -> int:
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024


def _available_memory_bytes() -> int:
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise RateLog1pExperimentError("available_memory_unreadable")


def transform_rate_pair(values: np.ndarray) -> np.ndarray:
    values = np.asarray(values, dtype=np.float64)
    if values.shape[-1:] != (2,) or not np.isfinite(values).all() or np.any(values < 0.0):
        raise RateLog1pExperimentError("rate_domain_invalid")
    transformed = np.log1p(values)
    if not np.isfinite(transformed).all():
        raise RateLog1pExperimentError("rate_log1p_non_finite")
    return transformed


def acceptance_gates(complementarity: dict[str, Any], false_positives: int) -> dict[str, Any]:
    attack = complementarity["attack"]
    normal = complementarity["normal"]
    a = int(attack["autoencoder_only_rf_missed"])
    b = int(normal["autoencoder_only_added_false_positive"])
    if b > 0:
        ratio_status = "finite"
        ratio_value: float | None = a / b
        ratio_pass = 40 * a >= 3 * b
    elif a > 0:
        ratio_status = "positive_infinite_not_serialized"
        ratio_value = None
        ratio_pass = True
    else:
        ratio_status = "undefined_zero_over_zero"
        ratio_value = None
        ratio_pass = False
    gates = {
        "ae_only_attacks_at_least_96": {"value": a, "passed": a >= 96},
        "ae_only_benign_false_positives_at_most_1574": {"value": b, "passed": b <= 1574},
        "ratio_at_least_0_075": {
            "numerator": a,
            "denominator": b,
            "value": ratio_value,
            "zero_denominator_status": ratio_status,
            "integer_test": "40*A >= 3*B when B > 0",
            "passed": ratio_pass,
        },
        "total_ae_false_positives_at_most_1628": {
            "value": int(false_positives),
            "passed": int(false_positives) <= 1628,
        },
    }
    gates["all_passed"] = all(item["passed"] for item in gates.values())
    return gates


def prepare_january_rate_inputs(
    *,
    project_root: Path,
    manifest_path: Path,
    assignment_directory: Path,
    preflight_report_path: Path,
    baseline_directory: Path,
    output_directory: Path,
) -> dict[str, Any]:
    """Admit exact raw-derived rates and ordinals; retain no TEST feature or label value."""
    if output_directory.exists():
        raise RateLog1pExperimentError("prepared_directory_already_exists")
    if shutil.disk_usage(output_directory.parent).free < MINIMUM_RESERVE_BYTES + 64 * 1024**2:
        raise RateLog1pExperimentError("insufficient_disk_for_prepared_inputs")
    baseline = verify_autoencoder_inputs(baseline_directory)
    evidence = verify_assignment_evidence(
        project_root, manifest_path, assignment_directory, preflight_report_path
    )
    output_directory.mkdir(parents=True)
    shapes = {
        "train": EXPECTED_COUNTS["train"]["rows"],
        "validation": EXPECTED_COUNTS["validation"]["rows"],
    }
    rates = {
        name: open_memmap(
            output_directory / f"{name}_rates.npy", mode="w+", dtype=np.float64, shape=(rows, 2)
        )
        for name, rows in shapes.items()
    }
    record_ids = {
        name: open_memmap(
            output_directory / f"{name}_record_ids.npy",
            mode="w+",
            dtype=np.int64,
            shape=(rows,),
        )
        for name, rows in shapes.items()
    }
    offsets = {"train": 0, "validation": 0}
    labels = {"train": baseline.y_train, "validation": baseline.y_validation}
    test_rows_seen = 0
    started = time.monotonic()
    try:
        for assigned in iter_assigned_source_records(project_root, evidence):
            if assigned.disposition == "test":
                test_rows_seen += 1
                continue
            if assigned.disposition not in offsets:
                continue
            if assigned.flow is None:
                raise RateLog1pExperimentError("selected_source_record_missing")
            name = assigned.disposition
            index = offsets[name]
            if index >= shapes[name]:
                raise RateLog1pExperimentError("prepared_population_overflow")
            expected_label = LABEL_MAPPING[str(assigned.flow.label)]
            if int(labels[name][index]) != expected_label:
                raise RateLog1pExperimentError("baseline_candidate_row_alignment_mismatch")
            pair = np.asarray(
                [assigned.flow.packets_per_second, assigned.flow.bytes_per_second], dtype=np.float64
            )
            transform_rate_pair(pair)
            rates[name][index] = pair
            record_ids[name][index] = assigned.record_id
            offsets[name] += 1
        if offsets != shapes or test_rows_seen != EXPECTED_COUNTS["test"]["rows"]:
            raise RateLog1pExperimentError("prepared_population_mismatch")
        for array in (*rates.values(), *record_ids.values()):
            array.flush()
        files = {
            name: {
                "sha256": sha256_file(output_directory / name),
                "size_bytes": (output_directory / name).stat().st_size,
            }
            for name in PREPARED_FILES
        }
        report = {
            "schema_version": "unsw_january_rate_input_admission_v1",
            "completed": True,
            "populations": {
                "train": {**EXPECTED_COUNTS["train"], "retained_rate_pairs": offsets["train"]},
                "validation": {
                    **EXPECTED_COUNTS["validation"],
                    "retained_rate_pairs": offsets["validation"],
                },
            },
            "source_formula": {
                "packets_per_second": "(spkts+dpkts)/(duration_ms/1000); zero when duration_ms <= 0",
                "bytes_per_second": "(sbytes+dbytes)/(duration_ms/1000); zero when duration_ms <= 0",
            },
            "assignment": {
                "archive_sha256": evidence.assignment_sha256,
                "report_sha256": evidence.report_sha256,
                "preflight_report_sha256": evidence.preflight_report_sha256,
            },
            "baseline_preprocessing": {
                "state_sha256": baseline.state_sha256,
                "configuration_sha256": baseline.configuration_sha256,
                "report_sha256": baseline.report_sha256,
            },
            "admission_boundary": {
                "full_registered_source_traversal_required_for_global_ordinal_alignment": True,
                "test_rows_seen_for_alignment_only": test_rows_seen,
                "test_features_retained": 0,
                "test_labels_retained": 0,
                "experiment_process_consumes_only_this_january_input_bundle": True,
            },
            "files": files,
            "runtime_seconds": time.monotonic() - started,
            "peak_rss_bytes": _peak_rss_bytes(),
        }
        _write_json(output_directory / "admission_report.json", report)
        manifest = {
            "schema_version": "unsw_january_rate_input_manifest_v1",
            "admission_report_sha256": sha256_file(output_directory / "admission_report.json"),
            "files": files,
        }
        _write_json(output_directory / "input_manifest.json", manifest)
        return report
    except Exception:
        _write_json(
            output_directory / "admission_failure.json",
            {"schema_version": "unsw_january_rate_input_admission_v1", "completed": False},
        )
        raise


def _verify_prepared_inputs(directory: Path) -> tuple[dict[str, Any], dict[str, np.ndarray]]:
    manifest_path = directory / "input_manifest.json"
    report_path = directory / "admission_report.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RateLog1pExperimentError("prepared_manifest_unreadable") from exc
    if (
        manifest.get("schema_version") != "unsw_january_rate_input_manifest_v1"
        or report.get("completed") is not True
        or manifest.get("admission_report_sha256") != sha256_file(report_path)
    ):
        raise RateLog1pExperimentError("prepared_manifest_invalid")
    arrays: dict[str, np.ndarray] = {}
    expected_shapes = {
        "train_rates.npy": (EXPECTED_COUNTS["train"]["rows"], 2),
        "validation_rates.npy": (EXPECTED_COUNTS["validation"]["rows"], 2),
        "train_record_ids.npy": (EXPECTED_COUNTS["train"]["rows"],),
        "validation_record_ids.npy": (EXPECTED_COUNTS["validation"]["rows"],),
    }
    for name, shape in expected_shapes.items():
        path = directory / name
        expected = manifest.get("files", {}).get(name, {})
        if (
            expected.get("sha256") != sha256_file(path)
            or expected.get("size_bytes") != path.stat().st_size
        ):
            raise RateLog1pExperimentError("prepared_input_hash_mismatch")
        array = np.load(path, mmap_mode="r", allow_pickle=False)
        if array.shape != shape or not np.isfinite(array).all():
            raise RateLog1pExperimentError("prepared_input_invalid")
        arrays[name] = array
    if np.any(arrays["train_rates.npy"] < 0) or np.any(arrays["validation_rates.npy"] < 0):
        raise RateLog1pExperimentError("prepared_rate_domain_invalid")
    for name in ("train_record_ids.npy", "validation_record_ids.npy"):
        values = arrays[name]
        if values.dtype != np.int64 or np.any(np.diff(values) <= 0):
            raise RateLog1pExperimentError("prepared_record_order_invalid")
    return manifest, arrays


def _fit_candidate_preprocessing(
    baseline: Any, prepared: dict[str, np.ndarray], directory: Path
) -> dict[str, Any]:
    directory.mkdir()
    train_log = transform_rate_pair(prepared["train_rates.npy"])
    means = train_log.mean(axis=0, dtype=np.float64)
    scales = np.sqrt(np.mean((train_log - means) ** 2, axis=0, dtype=np.float64))
    scales = np.where(scales == 0.0, 1.0, scales)
    if not np.isfinite(means).all() or not np.isfinite(scales).all() or np.any(scales <= 0):
        raise RateLog1pExperimentError("candidate_statistics_invalid")
    outputs: dict[str, Path] = {}
    for name, source, raw_rates in (
        ("train", baseline.X_train, prepared["train_rates.npy"]),
        ("validation", baseline.X_validation, prepared["validation_rates.npy"]),
    ):
        path = directory / f"X_{name}.npy"
        matrix = open_memmap(path, mode="w+", dtype=np.float64, shape=source.shape)
        for start in range(0, source.shape[0], 10_000):
            stop = min(start + 10_000, source.shape[0])
            matrix[start:stop] = source[start:stop]
            matrix[start:stop, RATE_COLUMNS] = (
                transform_rate_pair(raw_rates[start:stop]) - means
            ) / scales
        matrix.flush()
        if not np.isfinite(matrix).all():
            raise RateLog1pExperimentError("candidate_matrix_non_finite")
        unchanged = tuple(index for index in range(INPUT_WIDTH) if index not in RATE_COLUMNS)
        if not np.array_equal(matrix[:, unchanged], source[:, unchanged]):
            raise RateLog1pExperimentError("unchanged_candidate_columns_mismatch")
        outputs[f"X_{name}.npy"] = path
    for name, labels in (("train", baseline.y_train), ("validation", baseline.y_validation)):
        path = directory / f"y_{name}.npy"
        array = open_memmap(path, mode="w+", dtype=np.uint8, shape=labels.shape)
        array[:] = labels
        array.flush()
        outputs[f"y_{name}.npy"] = path
    state = {
        "schema_version": PREPROCESSING_SCHEMA_VERSION,
        "identity": PREPROCESSING_IDENTITY,
        "input_contract": "network_behavior_v1",
        "training_population": {**EXPECTED_COUNTS["train"], "statistics_include_all_labels": True},
        "rate_transform": {
            "features": ["packets_per_second", "bytes_per_second"],
            "operation": "numpy.float64 natural log1p before population z-score",
            "means": means.tolist(),
            "scales": scales.tolist(),
            "zero_duration_input": 0.0,
            "zero_variance_policy": "scale_by_one",
            "missing_negative_non_finite_policy": "reject",
        },
        "other_numeric_columns": "byte-identical baseline TRAIN-only z-scores",
        "protocol_indicators": "byte-identical baseline fixed indicators",
        "feature_order": list(FEATURE_NAMES),
        "output_dtype": "float64",
    }
    _write_json(directory / "preprocessor_state.json", state)
    hashes = {name: sha256_file(path) for name, path in outputs.items()}
    report = {
        "schema_version": PREPROCESSING_SCHEMA_VERSION,
        "completed": True,
        "fit_partition": "train",
        "fit_rows": EXPECTED_COUNTS["train"]["rows"],
        "fit_benign_rows": EXPECTED_COUNTS["train"]["benign"],
        "fit_attack_rows": EXPECTED_COUNTS["train"]["attack"],
        "validation_rows_in_statistics": 0,
        "test_rows_accessed": 0,
        "cic_rows_accessed": 0,
        "hashes": hashes,
    }
    _write_json(directory / "preprocessing_report.json", report)
    return {
        "state": state,
        "state_sha256": sha256_file(directory / "preprocessor_state.json"),
        "report_sha256": sha256_file(directory / "preprocessing_report.json"),
        "hashes": hashes,
        "X_train": np.load(directory / "X_train.npy", mmap_mode="r", allow_pickle=False),
        "X_validation": np.load(directory / "X_validation.npy", mmap_mode="r", allow_pickle=False),
        "y_train": np.load(directory / "y_train.npy", mmap_mode="r", allow_pickle=False),
        "y_validation": np.load(directory / "y_validation.npy", mmap_mode="r", allow_pickle=False),
    }


def _capture_snapshots(run_directory: Path, sources: dict[str, Path]) -> tuple[dict[str, Any], str]:
    files = {}
    for key, source in sources.items():
        data = source.read_bytes()
        filename = f"{key}.snapshot{source.suffix}"
        (run_directory / filename).write_bytes(data)
        files[key] = {
            "filename": filename,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
        }
    manifest = {
        "schema_version": "unsw_rate_log1p_source_provenance_v1",
        "captured_before_fitting": True,
        "files": files,
    }
    path = run_directory / "source_provenance_manifest.json"
    _write_json(path, manifest)
    return manifest, sha256_file(path)


def _verify_candidate_bundle(run_directory: Path) -> str:
    try:
        config = json.loads((run_directory / "experiment_config.json").read_text())
        threshold = json.loads((run_directory / "threshold.json").read_text())
        manifest = json.loads((run_directory / "artifact_manifest.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RateLog1pExperimentError("candidate_bundle_unreadable") from exc
    identities = config.get("identities", {})
    if identities != {
        "model": MODEL_IDENTITY,
        "preprocessing": PREPROCESSING_IDENTITY,
        "score": SCORE_IDENTITY,
        "threshold": THRESHOLD_IDENTITY,
        "scoring_contract": SCORING_CONTRACT_VERSION,
    }:
        raise RateLog1pExperimentError("candidate_bundle_identity_mismatch")
    required = {
        "configuration_sha256": sha256_file(run_directory / "experiment_config.json"),
        "model_state_sha256": sha256_file(run_directory / "autoencoder_state.pt"),
        "threshold_sha256": sha256_file(run_directory / "threshold.json"),
        "source_provenance_manifest_sha256": sha256_file(
            run_directory / "source_provenance_manifest.json"
        ),
    }
    if any(manifest.get(key) != value for key, value in required.items()):
        raise RateLog1pExperimentError("candidate_bundle_hash_mismatch")
    if (
        threshold.get("score_identity") != SCORE_IDENTITY
        or threshold.get("threshold_identity") != THRESHOLD_IDENTITY
    ):
        raise RateLog1pExperimentError("candidate_threshold_identity_mismatch")
    return hashlib.sha256(
        b"threatfusion:rate-log1p-candidate\0" + _json_bytes(manifest)
    ).hexdigest()


def run_experiment(
    *,
    project_root: Path,
    prepared_directory: Path,
    baseline_directory: Path,
    forest_directory: Path,
    preprocessing_directory: Path,
    run_directory: Path,
    protocol_path: Path,
    isolation_evidence: dict[str, Any],
) -> ExperimentResult:
    started = time.monotonic()
    if preprocessing_directory.exists() or run_directory.exists():
        raise RateLog1pExperimentError("fresh_output_directory_required")
    available = _available_memory_bytes()
    free_disk = shutil.disk_usage(run_directory.parent).free
    if available < MINIMUM_RESERVE_BYTES + 768 * 1024**2:
        raise RateLog1pExperimentError("insufficient_memory_before_fit")
    if free_disk < MINIMUM_RESERVE_BYTES + ARTIFACT_BUDGET_BYTES:
        raise RateLog1pExperimentError("insufficient_disk_before_fit")
    configure_deterministic_cpu_runtime()
    prepared_manifest, prepared = _verify_prepared_inputs(prepared_directory)
    baseline = verify_autoencoder_inputs(baseline_directory)
    try:
        forest = verify_saved_model(forest_directory, baseline, name="random_forest")
    except Exception as exc:
        raise RateLog1pExperimentError("frozen_random_forest_verification_failed") from exc
    if forest.model_sha256 != EXPECTED_FOREST_HASH:
        raise RateLog1pExperimentError("frozen_random_forest_hash_mismatch")
    run_directory.mkdir()
    try:
        snapshots, snapshots_sha256 = _capture_snapshots(
            run_directory,
            {
                "protocol": protocol_path,
                "candidate_model": Path(__file__),
                "runner": project_root / "scripts/run_rate_log1p_autoencoder_experiment.py",
                "autoencoder_scorer": project_root
                / "backend/src/threatfusion/models/network_autoencoder.py",
                "baseline_preprocessing": project_root
                / "backend/src/threatfusion/preprocessing/network_behavior_v1.py",
                "unsw_adapter": project_root
                / "backend/src/threatfusion/datasets/adapters/unsw_nb15.py",
                "adapter_base": project_root / "backend/src/threatfusion/datasets/adapters/base.py",
                "random_forest": project_root
                / "backend/src/threatfusion/models/network_random_forest_baseline.py",
            },
        )
        candidate = _fit_candidate_preprocessing(baseline, prepared, preprocessing_directory)
        preprocessor_hashes = {
            "state": candidate["state_sha256"],
            "report": candidate["report_sha256"],
            **candidate["hashes"],
        }
        config = {
            "schema_version": SCHEMA_VERSION,
            "identities": {
                "model": MODEL_IDENTITY,
                "preprocessing": PREPROCESSING_IDENTITY,
                "score": SCORE_IDENTITY,
                "threshold": THRESHOLD_IDENTITY,
                "scoring_contract": SCORING_CONTRACT_VERSION,
            },
            "intervention": "float64 natural log1p on packets_per_second and bytes_per_second only, then all-TRAIN population z-score",
            "feature_order": list(FEATURE_NAMES),
            "architecture": [14, 8, 3, 8, 14],
            "fit": {
                "weight_population": "847837 benign TRAIN rows only",
                "preprocessing_population": "all 865480 TRAIN rows including 17643 attacks",
                "seed": SEED,
                "optimizer": "Adam",
                "learning_rate": LEARNING_RATE,
                "betas": list(ADAM_BETAS),
                "eps": ADAM_EPS,
                "batch_size": BATCH_SIZE,
                "epochs": EPOCHS,
                "shuffle": "deterministic_seeded_each_epoch",
                "loader_workers": 0,
            },
            "threshold_policy": {
                "benign_january_rows": 212210,
                "quantile": QUANTILE,
                "method": "higher",
                "operator": ">",
            },
            "acceptance": {
                "A_minimum": 96,
                "B_maximum": 1574,
                "ratio_integer_test": "40*A >= 3*B",
                "total_false_positive_maximum": 1628,
            },
            "prepared_input_manifest_sha256": sha256_file(
                prepared_directory / "input_manifest.json"
            ),
            "baseline_preprocessing_hashes": {
                "state": baseline.state_sha256,
                "configuration": baseline.configuration_sha256,
                "report": baseline.report_sha256,
            },
            "candidate_preprocessing_hashes": preprocessor_hashes,
            "random_forest": {
                "model_sha256": forest.model_sha256,
                "input_representation": "unchanged frozen baseline matrix",
                "threshold": 0.5,
            },
            "source_provenance_manifest_sha256": snapshots_sha256,
            "runtime": {
                "python": platform.python_version(),
                "torch": torch.__version__,
                "numpy": np.__version__,
                "scikit_learn": importlib.metadata.version("scikit-learn"),
                "platform": platform.platform(),
                "intraop_threads": 4,
                "interop_threads": 1,
                "deterministic_algorithms": torch.are_deterministic_algorithms_enabled(),
            },
            "resource_limits": {
                "peak_rss_bytes": MAX_RSS_BYTES,
                "deadline_seconds": DEADLINE_SECONDS,
                "artifact_bytes": ARTIFACT_BUDGET_BYTES,
                "reserve_bytes": MINIMUM_RESERVE_BYTES,
            },
            "isolation": isolation_evidence,
            "snapshots": snapshots,
        }
        config_path = run_directory / "experiment_config.json"
        _write_json(config_path, config)
        config_sha256 = sha256_file(config_path)
        benign_indices = benign_train_indices(candidate["y_train"], expected_benign=847837)
        model, fit = fit_frozen_autoencoder(candidate["X_train"], candidate["y_train"])
        model_path = run_directory / "autoencoder_state.pt"
        save_state_dict(model_path, model)
        model_sha256 = sha256_file(model_path)
        reloaded = load_verified_state(model_path, model_sha256)
        reload_evidence = verify_reload_equivalence(
            model, reloaded, candidate["X_train"], benign_indices
        )
        scores = score_records_v2(reloaded, candidate["X_validation"], deadline_started=started)
        benign_validation = candidate["y_validation"] == 0
        if int(np.count_nonzero(benign_validation)) != 212210:
            raise RateLog1pExperimentError("validation_benign_population_mismatch")
        threshold_value = calibrate_threshold(scores[benign_validation])
        threshold = {
            "schema_version": "unsw_rate_log1p_threshold_v1",
            "threshold_identity": THRESHOLD_IDENTITY,
            "score_identity": SCORE_IDENTITY,
            "model_sha256": model_sha256,
            "configuration_sha256": config_sha256,
            "calibration_rows": 212210,
            "quantile": QUANTILE,
            "method": "higher",
            "operator": ">",
            "ties": "within_threshold",
            "value": threshold_value,
        }
        _write_json(run_directory / "threshold.json", threshold)
        reload_scoring = verify_v2_reload_scoring(
            model, reloaded, candidate["X_validation"], threshold_value
        )
        with threadpool_limits(limits=1):
            forest_scores = batched_attack_probabilities(
                forest.model, baseline.X_validation, batch_size=PREDICTION_BATCH_SIZE
            )
        ae_predictions = threshold_scores(scores, threshold_value)
        forest_predictions = (forest_scores >= 0.5).astype(np.uint8)
        metrics = calculate_metrics(candidate["y_validation"], scores, threshold_value)
        metrics["score_identity"] = SCORE_IDENTITY
        complementarity = calculate_complementarity(
            candidate["y_validation"], ae_predictions, forest_predictions
        )
        gates = acceptance_gates(complementarity, metrics["false_positive"])
        manifest = {
            "schema_version": "unsw_rate_log1p_artifact_manifest_v1",
            "identities": config["identities"],
            "configuration_sha256": config_sha256,
            "model_state_sha256": model_sha256,
            "threshold_sha256": sha256_file(run_directory / "threshold.json"),
            "source_provenance_manifest_sha256": snapshots_sha256,
            "prepared_input_manifest_sha256": config["prepared_input_manifest_sha256"],
            "candidate_preprocessing_hashes": preprocessor_hashes,
        }
        _write_json(run_directory / "artifact_manifest.json", manifest)
        artifact_identity = _verify_candidate_bundle(run_directory)
        elapsed = time.monotonic() - started
        peak = _peak_rss_bytes()
        deterioration = {
            "overall_recall_change": metrics["attack_recall"] - BASELINE_METRICS["attack_recall"],
            "true_positive_change": metrics["true_positive"] - BASELINE_METRICS["true_positive"],
            "both_detected_attack_change": complementarity["attack"]["both_detected"]
            - BASELINE_COMPLEMENTARITY["attack"]["both_detected"],
            "overall_recall_reduced": metrics["attack_recall"] < BASELINE_METRICS["attack_recall"],
            "attacks_caught_by_both_reduced": complementarity["attack"]["both_detected"]
            < BASELINE_COMPLEMENTARITY["attack"]["both_detected"],
        }
        if elapsed > DEADLINE_SECONDS:
            raise RateLog1pExperimentError("experiment_deadline_exceeded")
        if peak > MAX_RSS_BYTES:
            raise RateLog1pExperimentError("peak_rss_limit_exceeded")
        current_artifacts = sum(
            path.stat().st_size
            for root in (prepared_directory, preprocessing_directory, run_directory)
            for path in root.iterdir()
            if path.is_file()
        )
        if current_artifacts + 1024**2 > ARTIFACT_BUDGET_BYTES:
            raise RateLog1pExperimentError("candidate_artifact_budget_exceeded")
        report = {
            "schema_version": SCHEMA_VERSION,
            "completed": True,
            "disposition": (
                "PASS_experimental_candidate" if gates["all_passed"] else "FAIL_preserve_baseline"
            ),
            "evidence_label": "January calibration-informed adaptively-selected development evidence",
            "artifact_identity": artifact_identity,
            "populations": {
                "train": EXPECTED_COUNTS["train"],
                "validation": EXPECTED_COUNTS["validation"],
            },
            "baseline": {
                "autoencoder": BASELINE_METRICS,
                "complementarity": BASELINE_COMPLEMENTARITY,
            },
            "candidate": {
                "autoencoder": metrics,
                "complementarity": complementarity,
                "acceptance_gates": gates,
            },
            "deterioration": deterioration,
            "fit": {
                "epochs_completed": len(fit.epoch_losses),
                "rows_per_epoch": list(fit.rows_per_epoch),
                "epoch_mean_losses": list(fit.epoch_losses),
                "fit_seconds": fit.fit_seconds,
                "benign_weight_rows": 847837,
                "preprocessing_all_train_rows": 865480,
            },
            "reload_verification": reload_evidence,
            "v2_reload_scoring_verification": reload_scoring,
            "provenance": {
                "configuration_sha256": config_sha256,
                "artifact_manifest_sha256": sha256_file(run_directory / "artifact_manifest.json"),
                "source_provenance_manifest_sha256": snapshots_sha256,
                "prepared_input_manifest": prepared_manifest,
            },
            "isolation": isolation_evidence,
            "resources": {
                "elapsed_seconds": elapsed,
                "peak_rss_bytes": peak,
                "available_memory_before_bytes": available,
                "free_disk_before_bytes": free_disk,
                "rf_batch_size": PREDICTION_BATCH_SIZE,
                "loader_workers": 0,
                "candidate_artifact_bytes_before_report_and_chart": current_artifacts,
            },
            "limitations": [
                "January informed threshold calibration and intervention selection",
                "February was previously inspected but was inaccessible and not evaluated",
                "CIC was inaccessible and not evaluated",
                "passing gates is not independent confirmation, operational acceptance, statistical significance, fusion approval, product approval, or issue closure",
            ],
        }
        _write_json(run_directory / "evaluation_report.json", report)
        total_artifacts = sum(
            path.stat().st_size
            for root in (prepared_directory, preprocessing_directory, run_directory)
            for path in root.iterdir()
            if path.is_file()
        )
        report["resources"]["candidate_artifact_bytes"] = total_artifacts
        report["checks"] = {
            "completed_report_persisted_before_chart": True,
            "candidate_bundle_verified": True,
            "baseline_rf_received_unchanged_matrix": True,
            "candidate_and_rf_label_order_exact": bool(
                np.array_equal(candidate["y_validation"], baseline.y_validation)
            ),
            "february_accessed": False,
            "cic_accessed": False,
        }
        _write_json(run_directory / "evaluation_report.json", report)
        return ExperimentResult(
            run_directory / "evaluation_report.json", artifact_identity, bool(gates["all_passed"])
        )
    except Exception as exc:
        code = getattr(exc, "code", "internal_failure")
        _write_json(
            run_directory / "failure.json",
            {"schema_version": SCHEMA_VERSION, "completed": False, "failure_code": code},
        )
        raise


def render_report(report_path: Path, output_directory: Path) -> tuple[Path, Path]:
    """Render only from a persisted completed report; no fit or score inputs are accepted."""
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("completed") is not True:
        raise RateLog1pExperimentError("completed_report_required_for_render")
    candidate = report["candidate"]["autoencoder"]
    baseline = report["baseline"]["autoencoder"]
    markdown = output_directory / "baseline_vs_candidate.md"
    markdown.write_text(
        "# January baseline versus two-rate log1p candidate\n\n"
        "Calibration-informed, adaptively selected development evidence only.\n\n"
        "| Model | TP | FP | TN | FN | Precision | Recall | F1 | FPR |\n"
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|\n"
        f"| Baseline | {baseline['true_positive']} | {baseline['false_positive']} | {baseline['true_negative']} | {baseline['false_negative']} | {baseline['attack_precision']:.6f} | {baseline['attack_recall']:.6f} | {baseline['attack_f1']:.6f} | {baseline['false_positive_rate']:.6f} |\n"
        f"| Candidate | {candidate['true_positive']} | {candidate['false_positive']} | {candidate['true_negative']} | {candidate['false_negative']} | {candidate['attack_precision']:.6f} | {candidate['attack_recall']:.6f} | {candidate['attack_f1']:.6f} | {candidate['false_positive_rate']:.6f} |\n",
        encoding="utf-8",
    )
    chart = output_directory / "baseline_vs_candidate.svg"
    maximum = max(
        baseline["true_positive"],
        baseline["false_positive"],
        candidate["true_positive"],
        candidate["false_positive"],
    )
    bars = []
    values = [
        ("Baseline TP", baseline["true_positive"], "#4c78a8"),
        ("Candidate TP", candidate["true_positive"], "#72b7b2"),
        ("Baseline FP", baseline["false_positive"], "#e45756"),
        ("Candidate FP", candidate["false_positive"], "#f58518"),
    ]
    for index, (label, value, color) in enumerate(values):
        width = 500 * value / maximum
        y = 45 + index * 55
        bars.append(
            f'<text x="10" y="{y + 18}" font-size="14">{label}</text><rect x="125" y="{y}" width="{width:.2f}" height="24" fill="{color}"/><text x="{135 + width:.2f}" y="{y + 18}" font-size="14">{value}</text>'
        )
    chart.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" width="760" height="290"><text x="10" y="24" font-size="17">January baseline vs rate-log1p candidate (development evidence)</text>'
        + "".join(bars)
        + "</svg>\n",
        encoding="utf-8",
    )
    return markdown, chart
