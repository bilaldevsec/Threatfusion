"""Audit January v2 autoencoder residual contributions against Random Forest."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import os
import resource
import shutil
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

for variable in (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "BLIS_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
    "NUMEXPR_NUM_THREADS",
):
    os.environ[variable] = "1"

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

import numpy as np  # noqa: E402
import torch  # noqa: E402
from threadpoolctl import threadpool_limits  # noqa: E402

from threatfusion.models.network_autoencoder import (  # noqa: E402
    SCORING_CONTRACT_VERSION,
    TrustedAutoencoderBundle,
    _load_verified_autoencoder_detector,
    configure_deterministic_cpu_runtime,
    reconstruction_errors,
)
from threatfusion.models.network_classical_evaluation import verify_saved_model  # noqa: E402
from threatfusion.models.network_logistic_baseline import (  # noqa: E402
    ATTACK_THRESHOLD,
    available_memory_bytes,
)
from threatfusion.models.network_random_forest_baseline import (  # noqa: E402
    PREDICTION_BATCH_SIZE,
    batched_attack_probabilities,
)
from threatfusion.preprocessing.network_behavior_v1 import (  # noqa: E402
    LABEL_MAPPING,
    PREPROCESSING_SCHEMA_VERSION,
    TRANSFORMED_FEATURE_NAMES,
)
from threatfusion.utils.checksum import sha256_file  # noqa: E402

SCHEMA_VERSION = "unsw_january_v2_residual_contribution_audit_v1"
RECOVERY_SCHEMA_VERSION = "unsw_january_v2_residual_contribution_recovery_v1"
ARTIFACT_IDENTITY = "bdb7fc33d5b092566995018b5f83aa66bdb8ce95841d6b8b9021111c9a392a9a"
THRESHOLD = 0.1181361214680695
EXPECTED_ROWS = 216_568
EXPECTED_LABEL_COUNTS = {"normal": 212_210, "attack": 4_358}
EXPECTED_OVERLAP = {
    "attack": {
        "both_detected": 1_892,
        "autoencoder_only_rf_missed": 96,
        "random_forest_only_ae_missed": 2_153,
        "missed_by_both": 217,
    },
    "normal": {
        "both_false_positive": 54,
        "autoencoder_only_added_false_positive": 1_574,
        "random_forest_only_false_positive": 147,
        "correctly_unflagged_by_both": 210_435,
    },
}
EXPECTED_AE_CONFUSION = {
    "true_positive": 1_988,
    "false_positive": 1_628,
    "true_negative": 210_582,
    "false_negative": 2_370,
}
EXPECTED_RF_CONFUSION = {
    "true_positive": 4_045,
    "false_positive": 201,
    "true_negative": 212_009,
    "false_negative": 313,
}
MAX_RSS_BYTES = 2 * 1024**3
MEMORY_RESERVE_BYTES = 2 * 1024**3
DISK_RESERVE_BYTES = 2 * 1024**3
MAX_OUTPUT_BYTES = 32 * 1024**2
DEADLINE_SECONDS = 600.0

V2_FILE_HASHES = {
    "artifact_manifest.json": "c142d3352b406a689b6317f48ae513540076b02ffb2e0fdef9cd3e6a83da1866",
    "autoencoder_config.json": "51d4d664b5e017c5b039a08dc897d63e81a0b1e140eb1bb16457997ffa0727c2",
    "autoencoder_state.pt": "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23",
    "evaluation_report.json": "0ec77eda4a58e40e1b75087bbc5131f39cad54d553771e174ea303bc506c3bef",
    "network_autoencoder.snapshot.py": (
        "bcd2f8077de6cd9edeb3902aea5cb9a64f089111d7233aa6f94ee0257a1542c9"
    ),
    "network_autoencoder_protocol.snapshot.md": (
        "7ebd76b094f48303e45b40c6ff42bbfdbae1256e24c41a265bed6187466be78e"
    ),
    "source_provenance_manifest.json": (
        "d412f390f0d081170917a2e784046239f3e5b14d9a604e1196d2e3cbd3c527a9"
    ),
    "threshold.json": "79bc7f3def3a4ed745fbc85d9cbf36a04f4fb4384de4db065569f81f60c78e3e",
    "train_network_autoencoder.snapshot.py": (
        "1e85861ced0f341598f697387c2826ffdc31ad41d0516755ddff77850a6f6a54"
    ),
}
V2_TRUSTED_BUNDLE = TrustedAutoencoderBundle(
    scoring_contract_version=SCORING_CONTRACT_VERSION,
    configuration_sha256=V2_FILE_HASHES["autoencoder_config.json"],
    model_state_sha256=V2_FILE_HASHES["autoencoder_state.pt"],
    threshold_sha256=V2_FILE_HASHES["threshold.json"],
    manifest_sha256=V2_FILE_HASHES["artifact_manifest.json"],
    report_sha256=V2_FILE_HASHES["evaluation_report.json"],
)
EXPECTED_PREPROCESSING_HASHES = {
    "report": "d1688079b9cbcf521a8b9938ea07b540321e11edd70236452720fbd2f1697e4a",
    "configuration": "70273ec360e0bce88b5ec8311df4b5b8ccbbdbe6c456d8a679528563d477645a",
    "state": "30c955e3931dc010f8b4391a80fc0fbeddd17e14260701c8131d88f95b06ee49",
    "X_validation": "573993809be67edf8a6e5e4b4683d9254e9da4188aca97918d0ceac01ee487d6",
    "y_validation": "38d87b7c7fbf27a59228a2a84f3f4eca4e026acedc4e4aa3626da28292dd467b",
}
FEATURE_GROUPS = {
    "duration": (0,),
    "packet_counts": (1, 2),
    "byte_counts": (3, 4),
    "rates": (5, 6),
    "mean_packet_lengths": (7, 8),
    "destination_port": (9,),
    "protocol_indicators": (10, 11, 12, 13),
}
COHORT_NAMES = (
    "ae_only_attack",
    "ae_only_benign_false_positive",
    "both_detected_attack",
    "neither_rejected_benign",
)
EXPECTED_COHORT_COUNTS = {
    "ae_only_attack": 96,
    "ae_only_benign_false_positive": 1_574,
    "both_detected_attack": 1_892,
    "neither_rejected_benign": 210_435,
}


class ResidualAuditError(RuntimeError):
    """Sanitized fail-closed audit error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class JanuaryInputs:
    X_validation: np.memmap
    y_validation: np.memmap
    preprocessing_evidence: SimpleNamespace


def _read_json(path: Path, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResidualAuditError(code) from exc
    if not isinstance(value, dict):
        raise ResidualAuditError(code)
    return value


def verify_january_inputs(directory: Path) -> JanuaryInputs:
    """Verify only the saved January matrices plus their preprocessing metadata."""
    report_path = directory / "preprocessing_report.json"
    config_path = directory / "preprocessing_config.json"
    state_path = directory / "preprocessor_state.json"
    report = _read_json(report_path, "preprocessing_report_unreadable")
    config = _read_json(config_path, "preprocessing_configuration_unreadable")
    if any(
        sha256_file(path) != EXPECTED_PREPROCESSING_HASHES[name]
        for name, path in (
            ("report", report_path),
            ("configuration", config_path),
            ("state", state_path),
        )
    ):
        raise ResidualAuditError("preprocessing_metadata_hash_mismatch")
    counts = report.get("counts", {}).get("validation", {})
    if (
        report.get("schema_version") != PREPROCESSING_SCHEMA_VERSION
        or report.get("completed") is not True
        or report.get("output_feature_names") != list(TRANSFORMED_FEATURE_NAMES)
        or report.get("shapes", {}).get("X_validation") != [EXPECTED_ROWS, 14]
        or report.get("shapes", {}).get("y_validation") != [EXPECTED_ROWS]
        or counts
        != {
            "rows": EXPECTED_ROWS,
            "benign": EXPECTED_LABEL_COUNTS["normal"],
            "attack": EXPECTED_LABEL_COUNTS["attack"],
        }
        or config.get("schema_version") != PREPROCESSING_SCHEMA_VERSION
        or config.get("fit_partition") != "train"
        or config.get("transform_partitions") != ["train", "validation"]
        or config.get("label_mapping") != LABEL_MAPPING
        or config.get("transformed_feature_names") != list(TRANSFORMED_FEATURE_NAMES)
        or config.get("output_dtype") != "float64"
    ):
        raise ResidualAuditError("preprocessing_contract_mismatch")
    arrays = {}
    for name, dtype, shape in (
        ("X_validation", np.dtype(np.float64), (EXPECTED_ROWS, 14)),
        ("y_validation", np.dtype(np.uint8), (EXPECTED_ROWS,)),
    ):
        path = directory / f"{name}.npy"
        item = report.get("hashes", {}).get("outputs", {}).get(name, {})
        if (
            not path.is_file()
            or path.stat().st_size != item.get("size_bytes")
            or item.get("sha256") != EXPECTED_PREPROCESSING_HASHES[name]
            or sha256_file(path) != EXPECTED_PREPROCESSING_HASHES[name]
        ):
            raise ResidualAuditError("january_input_integrity_failure")
        try:
            array = np.load(path, mmap_mode="r", allow_pickle=False)
        except (OSError, ValueError) as exc:
            raise ResidualAuditError("january_input_unreadable") from exc
        if array.dtype != dtype or array.shape != shape:
            raise ResidualAuditError("january_input_contract_mismatch")
        arrays[name] = array
    if not np.isfinite(arrays["X_validation"]).all():
        raise ResidualAuditError("january_input_non_finite")
    labels = arrays["y_validation"]
    label_counts = np.bincount(labels, minlength=2)
    if label_counts.tolist() != [EXPECTED_LABEL_COUNTS["normal"], EXPECTED_LABEL_COUNTS["attack"]]:
        raise ResidualAuditError("january_label_counts_mismatch")
    evidence = SimpleNamespace(
        state_sha256=EXPECTED_PREPROCESSING_HASHES["state"],
        configuration_sha256=EXPECTED_PREPROCESSING_HASHES["configuration"],
        report_sha256=EXPECTED_PREPROCESSING_HASHES["report"],
        y_validation=labels,
    )
    return JanuaryInputs(arrays["X_validation"], labels, evidence)


def score_and_residuals_v2(
    model: torch.nn.Module,
    matrix: np.ndarray,
    *,
    started: float | None = None,
) -> tuple[np.ndarray, np.ndarray, dict[str, float | bool]]:
    """Use one shape-(1,14) forward per row and retain exact squared residuals."""
    matrix = np.asarray(matrix)
    if matrix.ndim != 2 or matrix.shape[1] != 14 or matrix.dtype != np.float64:
        raise ResidualAuditError("scoring_matrix_invalid")
    scores = np.empty(matrix.shape[0], dtype=np.float64)
    squared = np.empty(matrix.shape, dtype=np.float64)
    maximum_difference = 0.0
    model.eval()
    with torch.inference_mode():
        for index in range(matrix.shape[0]):
            if (
                started is not None
                and index % 1024 == 0
                and time.monotonic() - started > DEADLINE_SECONDS
            ):
                raise ResidualAuditError("audit_deadline_exceeded")
            with np.errstate(over="ignore", invalid="ignore"):
                converted = np.array(matrix[index], dtype=np.float32, copy=True).reshape(1, 14)
            if not np.isfinite(converted).all():
                raise ResidualAuditError("scoring_matrix_out_of_range")
            reconstruction = model(torch.from_numpy(converted)).cpu().numpy()
            score = reconstruction_errors(converted, reconstruction)[0]
            residual = converted.astype(np.float64) - reconstruction.astype(np.float64)
            contribution = residual[0] * residual[0]
            contribution_score = np.sum(contribution, dtype=np.float64) / np.float64(14)
            difference = abs(float(score) - float(contribution_score))
            maximum_difference = max(maximum_difference, difference)
            scores[index] = score
            squared[index] = contribution
    if not np.isfinite(scores).all() or not np.isfinite(squared).all():
        raise ResidualAuditError("residual_non_finite")
    if maximum_difference != 0.0:
        raise ResidualAuditError("score_residual_reconciliation_failure")
    return (
        scores,
        squared,
        {
            "exact": True,
            "absolute_tolerance": 0.0,
            "maximum_absolute_score_difference": maximum_difference,
        },
    )


def calculate_overlap(labels: np.ndarray, ae: np.ndarray, rf: np.ndarray) -> dict[str, Any]:
    labels = np.asarray(labels)
    ae = np.asarray(ae)
    rf = np.asarray(rf)
    if labels.shape != ae.shape or labels.shape != rf.shape or labels.ndim != 1:
        raise ResidualAuditError("cohort_alignment_mismatch")
    if any(not np.isin(values, (0, 1)).all() for values in (labels, ae, rf)):
        raise ResidualAuditError("cohort_values_invalid")
    attack = labels == 1
    normal = labels == 0
    return {
        "attack": {
            "both_detected": int(np.count_nonzero(attack & (ae == 1) & (rf == 1))),
            "autoencoder_only_rf_missed": int(np.count_nonzero(attack & (ae == 1) & (rf == 0))),
            "random_forest_only_ae_missed": int(np.count_nonzero(attack & (ae == 0) & (rf == 1))),
            "missed_by_both": int(np.count_nonzero(attack & (ae == 0) & (rf == 0))),
        },
        "normal": {
            "both_false_positive": int(np.count_nonzero(normal & (ae == 1) & (rf == 1))),
            "autoencoder_only_added_false_positive": int(
                np.count_nonzero(normal & (ae == 1) & (rf == 0))
            ),
            "random_forest_only_false_positive": int(
                np.count_nonzero(normal & (ae == 0) & (rf == 1))
            ),
            "correctly_unflagged_by_both": int(np.count_nonzero(normal & (ae == 0) & (rf == 0))),
        },
    }


def cohort_masks(labels: np.ndarray, ae: np.ndarray, rf: np.ndarray) -> dict[str, np.ndarray]:
    calculate_overlap(labels, ae, rf)
    return {
        "ae_only_attack": (labels == 1) & (ae == 1) & (rf == 0),
        "ae_only_benign_false_positive": (labels == 0) & (ae == 1) & (rf == 0),
        "both_detected_attack": (labels == 1) & (ae == 1) & (rf == 1),
        "neither_rejected_benign": (labels == 0) & (ae == 0) & (rf == 0),
    }


def _distribution(values: np.ndarray) -> dict[str, float | int | None]:
    if values.size == 0:
        return {
            key: None
            for key in (
                "minimum",
                "mean",
                "standard_deviation",
                "p25",
                "median",
                "p75",
                "p90",
                "p95",
                "p99",
                "maximum",
            )
        }
    quantiles = np.quantile(values, [0.25, 0.5, 0.75, 0.9, 0.95, 0.99])
    return {
        "minimum": float(np.min(values)),
        "mean": float(np.mean(values, dtype=np.float64)),
        "standard_deviation": float(np.std(values, dtype=np.float64)),
        "p25": float(quantiles[0]),
        "median": float(quantiles[1]),
        "p75": float(quantiles[2]),
        "p90": float(quantiles[3]),
        "p95": float(quantiles[4]),
        "p99": float(quantiles[5]),
        "maximum": float(np.max(values)),
    }


def aggregate_cohort(mask: np.ndarray, scores: np.ndarray, squared: np.ndarray) -> dict[str, Any]:
    mask = np.asarray(mask, dtype=bool)
    if mask.shape != scores.shape or squared.shape != (scores.size, len(TRANSFORMED_FEATURE_NAMES)):
        raise ResidualAuditError("residual_aggregation_alignment_mismatch")
    count = int(np.count_nonzero(mask))
    feature_sums = np.asarray(
        [np.sum(squared[mask, index], dtype=np.float64) for index in range(squared.shape[1])]
    )
    total = float(np.sum(feature_sums, dtype=np.float64))
    features = []
    for index, name in enumerate(TRANSFORMED_FEATURE_NAMES):
        values = squared[mask, index]
        features.append(
            {
                "index": index + 1,
                "name": name,
                "mean_squared_residual": (
                    float(np.mean(values, dtype=np.float64)) if count else None
                ),
                "median_squared_residual": float(np.median(values)) if count else None,
                "sum_squared_residual": float(feature_sums[index]),
                "fraction_of_total_reconstruction_error": (
                    float(feature_sums[index] / total) if total > 0.0 else None
                ),
            }
        )
    groups = []
    for name, indices in FEATURE_GROUPS.items():
        group_sum = float(np.sum(feature_sums[list(indices)], dtype=np.float64))
        groups.append(
            {
                "name": name,
                "feature_indices": [index + 1 for index in indices],
                "sum_squared_residual": group_sum,
                "fraction_of_total_reconstruction_error": (
                    group_sum / total if total > 0.0 else None
                ),
            }
        )
    return {
        "record_count": count,
        "empty": count == 0,
        "score_distribution": _distribution(scores[mask]),
        "total_squared_residual": total,
        "features": features,
        "groups": groups,
    }


def _confusion(labels: np.ndarray, decisions: np.ndarray) -> dict[str, int]:
    return {
        "true_positive": int(np.count_nonzero((labels == 1) & (decisions == 1))),
        "false_positive": int(np.count_nonzero((labels == 0) & (decisions == 1))),
        "true_negative": int(np.count_nonzero((labels == 0) & (decisions == 0))),
        "false_negative": int(np.count_nonzero((labels == 1) & (decisions == 0))),
    }


def _write_csv(path: Path, cohorts: Mapping[str, dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "cohort",
                "record_count",
                "feature_index",
                "feature_name",
                "mean_squared_residual",
                "median_squared_residual",
                "sum_squared_residual",
                "fraction_of_total_reconstruction_error",
            ),
        )
        writer.writeheader()
        for cohort, result in cohorts.items():
            for feature in result["features"]:
                writer.writerow(
                    {
                        "cohort": cohort,
                        "record_count": result["record_count"],
                        "feature_index": feature["index"],
                        "feature_name": feature["name"],
                        "mean_squared_residual": feature["mean_squared_residual"],
                        "median_squared_residual": feature["median_squared_residual"],
                        "sum_squared_residual": feature["sum_squared_residual"],
                        "fraction_of_total_reconstruction_error": feature[
                            "fraction_of_total_reconstruction_error"
                        ],
                    }
                )


def _escape_xml(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _write_chart(path: Path, cohorts: Mapping[str, dict[str, Any]]) -> None:
    width, height = 1900, 760
    left, top, panel_width, row_height = 250, 80, 395, 42
    colors = ("#2563eb", "#dc2626", "#7c3aed", "#059669")
    maximum = max(
        float(feature["fraction_of_total_reconstruction_error"] or 0.0)
        for result in cohorts.values()
        for feature in result["features"]
    )
    scale_max = max(maximum, 0.01)
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        "<style>text{font-family:system-ui,sans-serif;fill:#172033}.title{font-size:22px;font-weight:700}.head{font-size:15px;font-weight:650}.label{font-size:12px}.tick{font-size:11px;fill:#526070}</style>",
        '<text x="24" y="32" class="title">January v2 AE feature fractions of cohort reconstruction error</text>',
        f'<text x="24" y="55" class="tick">Shared scale: 0 to {scale_max:.1%}; residual attribution is descriptive, not causal.</text>',
    ]
    short_names = [name.replace("__zscore", "") for name in TRANSFORMED_FEATURE_NAMES]
    for row, name in enumerate(short_names):
        y = top + 42 + row * row_height
        lines.append(
            f'<text x="240" y="{y + 12}" text-anchor="end" class="label">{_escape_xml(name)}</text>'
        )
    for panel, (cohort, result) in enumerate(cohorts.items()):
        x = left + panel * panel_width
        count = result["record_count"]
        title = cohort.replace("_", " ")
        lines.append(f'<text x="{x}" y="{top}" class="head">{_escape_xml(title)}</text>')
        lines.append(f'<text x="{x}" y="{top + 20}" class="tick">n={count:,}</text>')
        for row, feature in enumerate(result["features"]):
            y = top + 32 + row * row_height
            fraction = float(feature["fraction_of_total_reconstruction_error"] or 0.0)
            bar_width = 310 * fraction / scale_max
            lines.append(f'<rect x="{x}" y="{y}" width="310" height="1" fill="#d7dde5"/>')
            lines.append(
                f'<rect x="{x}" y="{y + 5}" width="{bar_width:.3f}" height="18" rx="2" fill="{colors[panel]}"/>'
            )
            lines.append(
                f'<text x="{x + bar_width + 5:.3f}" y="{y + 19}" class="tick">{fraction:.1%}</text>'
            )
    lines.append("</svg>")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _recovery_path(output_directory: Path) -> Path:
    return output_directory.parent / f".{output_directory.name}.recovery.json"


def _aggregate_report_sha256(report: Mapping[str, Any]) -> str:
    data = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _write_recovery(path: Path, report: Mapping[str, Any]) -> None:
    """Atomically retain aggregate-only calculations before publication."""
    recovery = {
        "schema_version": RECOVERY_SCHEMA_VERSION,
        "artifact_identity": ARTIFACT_IDENTITY,
        "aggregate_report_sha256": _aggregate_report_sha256(report),
        "aggregate_report": report,
    }
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(
            json.dumps(recovery, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(path)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _load_recovery(path: Path) -> dict[str, Any]:
    recovery = _read_json(path, "recovery_file_unreadable")
    report = recovery.get("aggregate_report")
    if not isinstance(report, dict) or recovery.get(
        "aggregate_report_sha256"
    ) != _aggregate_report_sha256(report):
        raise ResidualAuditError("recovery_integrity_mismatch")
    if (
        recovery.get("schema_version") != RECOVERY_SCHEMA_VERSION
        or recovery.get("artifact_identity") != ARTIFACT_IDENTITY
        or report.get("schema_version") != SCHEMA_VERSION
        or report.get("completed") is not True
        or report.get("artifact_identity") != ARTIFACT_IDENTITY
        or report.get("threshold")
        != {"value": THRESHOLD, "operator": ">", "ties": "within_threshold"}
        or report.get("random_forest_threshold") != {"value": ATTACK_THRESHOLD, "operator": ">="}
        or report.get("population") != {"rows": EXPECTED_ROWS, **EXPECTED_LABEL_COUNTS}
        or report.get("feature_order") != list(TRANSFORMED_FEATURE_NAMES)
        or report.get("feature_groups")
        != {name: [index + 1 for index in indices] for name, indices in FEATURE_GROUPS.items()}
        or report.get("score_residual_reconciliation")
        != {
            "exact": True,
            "absolute_tolerance": 0.0,
            "maximum_absolute_score_difference": 0.0,
        }
        or report.get("confusion")
        != {"autoencoder": EXPECTED_AE_CONFUSION, "random_forest": EXPECTED_RF_CONFUSION}
        or report.get("overlap") != EXPECTED_OVERLAP
        or list(report.get("cohorts", {})) != list(COHORT_NAMES)
        or report.get("resources", {}).get("ae_forward_rows") != EXPECTED_ROWS
        or report.get("resources", {}).get("ae_forward_shape") != [1, 14]
        or report.get("resources", {}).get("rf_prediction_batch_size") != PREDICTION_BATCH_SIZE
        or report.get("resources", {}).get("february_accessed") is not False
        or report.get("resources", {}).get("train_accessed") is not False
        or report.get("resources", {}).get("cic_accessed") is not False
    ):
        raise ResidualAuditError("recovery_contract_mismatch")
    for name in COHORT_NAMES:
        cohort = report["cohorts"].get(name)
        if (
            not isinstance(cohort, dict)
            or cohort.get("record_count") != EXPECTED_COHORT_COUNTS[name]
            or cohort.get("empty") is not False
            or len(cohort.get("features", ())) != len(TRANSFORMED_FEATURE_NAMES)
        ):
            raise ResidualAuditError("recovery_contract_mismatch")
        for index, feature in enumerate(cohort["features"]):
            if (
                feature.get("index") != index + 1
                or feature.get("name") != TRANSFORMED_FEATURE_NAMES[index]
            ):
                raise ResidualAuditError("recovery_contract_mismatch")
    return report


def publish_aggregates(
    output_directory: Path,
    report: Mapping[str, Any],
    *,
    recovery_path: Path,
) -> Path:
    """Retain aggregate recovery evidence, then atomically publish all outputs."""
    if output_directory.exists():
        raise ResidualAuditError("output_directory_exists")
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    _write_recovery(recovery_path, report)
    published_report = copy.deepcopy(report)
    with tempfile.TemporaryDirectory(
        prefix=".residual-audit-publication-", dir=output_directory.parent
    ) as temp:
        temporary = Path(temp)
        aggregate_path = temporary / "aggregate.json"
        _write_csv(temporary / "feature_contributions.csv", published_report["cohorts"])
        _write_chart(temporary / "feature_contributions.svg", published_report["cohorts"])
        output_bytes = -1
        for _ in range(10):
            published_report.setdefault("resources", {})["output_bytes"] = output_bytes
            aggregate_path.write_text(
                json.dumps(published_report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            measured = sum(path.stat().st_size for path in temporary.iterdir() if path.is_file())
            if measured == output_bytes:
                break
            output_bytes = measured
        else:
            raise ResidualAuditError("audit_output_size_unstable")
        if output_bytes > MAX_OUTPUT_BYTES:
            raise ResidualAuditError("audit_output_budget_exceeded")
        temporary.rename(output_directory)
    return output_directory / "aggregate.json"


def _peak_rss_bytes() -> int:
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024


def run_audit(
    *,
    preprocessing_directory: Path,
    autoencoder_directory: Path,
    forest_directory: Path,
    output_directory: Path,
) -> Path:
    started = time.monotonic()
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    recovery_path = _recovery_path(output_directory)
    if recovery_path.is_file():
        report = _load_recovery(recovery_path)
        return publish_aggregates(output_directory, report, recovery_path=recovery_path)
    if output_directory.exists():
        raise ResidualAuditError("output_directory_exists")
    available_memory = available_memory_bytes()
    free_disk = shutil.disk_usage(output_directory.parent).free
    if available_memory < MEMORY_RESERVE_BYTES or free_disk < DISK_RESERVE_BYTES:
        raise ResidualAuditError("audit_resource_preflight_failed")
    inputs = verify_january_inputs(preprocessing_directory)
    configure_deterministic_cpu_runtime()
    detector = _load_verified_autoencoder_detector(
        autoencoder_directory,
        artifact_identity=ARTIFACT_IDENTITY,
        expected=V2_TRUSTED_BUNDLE,
    )
    if detector.threshold != THRESHOLD:
        raise ResidualAuditError("autoencoder_threshold_mismatch")
    saved_ae = _read_json(autoencoder_directory / "evaluation_report.json", "ae_report_unreadable")
    saved_complementarity = saved_ae.get("validation", {}).get("complementarity", {})
    saved_overlap = {label: saved_complementarity.get(label) for label in ("attack", "normal")}
    if saved_overlap != EXPECTED_OVERLAP:
        raise ResidualAuditError("saved_autoencoder_overlap_mismatch")
    forest = verify_saved_model(
        forest_directory,
        inputs.preprocessing_evidence,
        name="random_forest",
    )
    scores, squared, reconciliation = score_and_residuals_v2(
        detector.model, inputs.X_validation, started=started
    )
    ae_decisions = (scores > detector.threshold).astype(np.uint8)
    with threadpool_limits(limits=1):
        rf_scores = batched_attack_probabilities(
            forest.model, inputs.X_validation, batch_size=PREDICTION_BATCH_SIZE
        )
    rf_decisions = (rf_scores >= ATTACK_THRESHOLD).astype(np.uint8)
    labels = np.asarray(inputs.y_validation)
    overlap = calculate_overlap(labels, ae_decisions, rf_decisions)
    ae_confusion = _confusion(labels, ae_decisions)
    rf_confusion = _confusion(labels, rf_decisions)
    if overlap != EXPECTED_OVERLAP:
        raise ResidualAuditError("calculated_overlap_mismatch")
    if ae_confusion != EXPECTED_AE_CONFUSION or rf_confusion != EXPECTED_RF_CONFUSION:
        raise ResidualAuditError("calculated_confusion_mismatch")
    if saved_ae.get("validation", {}).get("autoencoder", {}).get("threshold_counts") != {
        "below": int(np.count_nonzero(scores < THRESHOLD)),
        "equal": int(np.count_nonzero(scores == THRESHOLD)),
        "above": int(np.count_nonzero(scores > THRESHOLD)),
    }:
        raise ResidualAuditError("threshold_count_mismatch")
    masks = cohort_masks(labels, ae_decisions, rf_decisions)
    cohorts = {name: aggregate_cohort(masks[name], scores, squared) for name in COHORT_NAMES}
    if {name: value["record_count"] for name, value in cohorts.items()} != EXPECTED_COHORT_COUNTS:
        raise ResidualAuditError("requested_cohort_count_mismatch")
    elapsed = time.monotonic() - started
    peak_rss = _peak_rss_bytes()
    if elapsed > DEADLINE_SECONDS or peak_rss > MAX_RSS_BYTES:
        raise ResidualAuditError("audit_resource_bound_exceeded")
    report = {
        "schema_version": SCHEMA_VERSION,
        "completed": True,
        "scope": "January VALIDATION calibration-informed development evidence",
        "artifact_identity": ARTIFACT_IDENTITY,
        "threshold": {"value": THRESHOLD, "operator": ">", "ties": "within_threshold"},
        "random_forest_threshold": {"value": ATTACK_THRESHOLD, "operator": ">="},
        "population": {"rows": EXPECTED_ROWS, **EXPECTED_LABEL_COUNTS},
        "feature_order": list(TRANSFORMED_FEATURE_NAMES),
        "feature_groups": {
            name: [index + 1 for index in indices] for name, indices in FEATURE_GROUPS.items()
        },
        "score_residual_reconciliation": reconciliation,
        "confusion": {"autoencoder": ae_confusion, "random_forest": rf_confusion},
        "overlap": overlap,
        "cohorts": cohorts,
        "resources": {
            "preflight_available_memory_bytes": available_memory,
            "preflight_free_disk_bytes": free_disk,
            "elapsed_seconds": elapsed,
            "peak_rss_bytes": peak_rss,
            "ae_forward_rows": EXPECTED_ROWS,
            "ae_forward_shape": [1, 14],
            "rf_prediction_batch_size": PREDICTION_BATCH_SIZE,
            "train_accessed": False,
            "february_accessed": False,
            "cic_accessed": False,
        },
        "interpretation_limits": [
            "Residual contributions explain the frozen autoencoder reconstruction score, not why a network event is malicious.",
            "January is calibration-informed development evidence, not independent evaluation.",
            "The audit does not authorize fusion, threshold changes, architecture changes, or product integration.",
        ],
    }
    return publish_aggregates(output_directory, report, recovery_path=recovery_path)


def _parser() -> argparse.ArgumentParser:
    root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=root)
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=root
        / "artifacts/reports/network_autoencoder_residual_audit/january-v2-vs-rf-f71a5e7",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.project_root.resolve()
    try:
        report = run_audit(
            preprocessing_directory=root
            / "data/processed/unsw_network_preprocessing/full-train-only-0141bde-v1",
            autoencoder_directory=root
            / "artifacts/models/network_autoencoder/full-benign-autoencoder-2a51c94-v2",
            forest_directory=root
            / "artifacts/models/network_random_forest_baseline/full-network-random-forest-6d69c72-v1",
            output_directory=args.output_directory.resolve(),
        )
    except Exception as exc:
        code = exc.code if isinstance(exc, ResidualAuditError) else "audit_failed"
        print(f"residual audit failed code={code}", file=sys.stderr)
        return 1
    print(f"residual audit completed=true report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
