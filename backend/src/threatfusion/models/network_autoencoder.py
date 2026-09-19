"""Frozen benign-only UNSW reconstruction-anomaly baseline."""

from __future__ import annotations

import hashlib
import importlib.metadata
import io
import json
import math
import os
import platform
import random
import re
import resource
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Mapping

import numpy as np
import torch
from sklearn.metrics import average_precision_score, roc_auc_score
from torch import nn
from torch.utils.data import DataLoader, Dataset
from threadpoolctl import threadpool_limits

from threatfusion.models.network_classical_evaluation import verify_saved_model
from threatfusion.models.network_logistic_baseline import (
    NetworkBaselineError,
    VerifiedPreprocessingArtifacts,
    verify_preprocessing_artifacts,
)
from threatfusion.models.network_random_forest_baseline import batched_attack_probabilities
from threatfusion.preprocessing.network_behavior_v1 import LABEL_MAPPING, TRANSFORMED_FEATURE_NAMES
from threatfusion.utils.checksum import sha256_file

HISTORICAL_SCHEMA_VERSION = "unsw_network_benign_autoencoder_v1"
SCHEMA_VERSION = "unsw_network_benign_autoencoder_v2"
MODEL_IDENTITY = "unsw_network_benign_autoencoder_v2"
DETECTOR_IDENTITY = "threatfusion.unsw_network_reconstruction_anomaly"
DETECTOR_VERSION = "v2"
PREPROCESSING_REQUIREMENTS = (
    "unsw_train.network_behavior_v1_preprocessing_v1.14_columns.benign_autoencoder.v2"
)
HISTORICAL_SCORE_IDENTITY = "mean_squared_reconstruction_error_14_v1"
SCORING_CONTRACT_VERSION = "unsw_autoencoder_per_record_scoring_v2"
SCORE_IDENTITY = "mean_squared_reconstruction_error_14_float32_input_per_record_v2"
MODEL_FILENAME = "autoencoder_state.pt"
CONFIG_FILENAME = "autoencoder_config.json"
THRESHOLD_FILENAME = "threshold.json"
MANIFEST_FILENAME = "artifact_manifest.json"
REPORT_FILENAME = "evaluation_report.json"
FAILURE_FILENAME = "failure.json"
PROVENANCE_MANIFEST_FILENAME = "source_provenance_manifest.json"
PROTOCOL_SNAPSHOT_FILENAME = "network_autoencoder_protocol.snapshot.md"
MODEL_SOURCE_SNAPSHOT_FILENAME = "network_autoencoder.snapshot.py"
RUNNER_SOURCE_SNAPSHOT_FILENAME = "train_network_autoencoder.snapshot.py"

INPUT_WIDTH = 14
HIDDEN_WIDTH = 8
BOTTLENECK_WIDTH = 3
TRAINABLE_PARAMETER_COUNT = 305
SEED = 42
BATCH_SIZE = 1024
EPOCHS = 30
LEARNING_RATE = 0.001
ADAM_BETAS = (0.9, 0.999)
ADAM_EPS = 1e-8
QUANTILE = 0.99
PREDICTION_BATCH_SIZE = 25_000
RELOAD_SAMPLE_SIZE = 4096
INTRAOP_THREADS = 4
INTEROP_THREADS = 1
MAX_RSS_BYTES = 2 * 1024**3
MEMORY_RESERVE_BYTES = 2 * 1024**3
DISK_RESERVE_BYTES = 2 * 1024**3
ARTIFACT_BUDGET_BYTES = 256 * 1024**2
DEADLINE_SECONDS = 3600.0
ESTIMATED_PEAK_BYTES = 512 * 1024**2
EXPECTED_COUNTS = {
    "train": {"rows": 865_480, "benign": 847_837, "attack": 17_643},
    "validation": {"rows": 216_568, "benign": 212_210, "attack": 4_358},
    "test": {"rows": 1_452_844, "benign": 1_153_776, "attack": 299_068},
}
EXPECTED_PREPROCESSING_HASHES = {
    "state": "30c955e3931dc010f8b4391a80fc0fbeddd17e14260701c8131d88f95b06ee49",
    "configuration": "70273ec360e0bce88b5ec8311df4b5b8ccbbdbe6c456d8a679528563d477645a",
    "report": "d1688079b9cbcf521a8b9938ea07b540321e11edd70236452720fbd2f1697e4a",
    "X_train": "56563f752bba2c7b01f2fa35c4c6927f90d0c83dd6e06c25c9b23cbf2bd2ca81",
    "y_train": "f12ba5c05db37d5c34bf7f22fa62d41535bdeaab58014bdd3975d50c21a24209",
    "X_validation": "573993809be67edf8a6e5e4b4683d9254e9da4188aca97918d0ceac01ee487d6",
    "y_validation": "38d87b7c7fbf27a59228a2a84f3f4eca4e026acedc4e4aa3626da28292dd467b",
}
EXPECTED_ASSIGNMENT_HASHES = {
    "report_sha256": "6913c1f2ef974d0b969506daf2b091a740fbf0d6b43d231a6f64f30841436857",
    "archive_sha256": "154829274f1a2d594086c6a73db6fce7b585ffeba58632dfce08422c1b187dc9",
    "preflight_report_sha256": ("f805424dc5f39ca41f7b1935b25938307d2e15c18caa008b3a1ca9250b8ab384"),
}
EXPECTED_FOREST_HASH = "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"
EXPECTED_FEBRUARY_HASHES = {
    "configuration": "5e33e84f2fa0086ab0a9b66d7b7e6e6de179a0ce3e7e372919a461a7eed30eb4",
    "report": "17ad32dd54088b70af656c4de5f6972c08ecbb6e213d82b6414de2ca7add1d8e",
    "X_test": "dffc7b0354f3917dd7b3bf912b01366ea5fe138ae03cb3dfaa50642498fcddf4",
    "y_test": "bf49145f228ce49966dec07d23194e1c630d63e58ec4f0f317b8e42460e1b6b6",
}
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ARTIFACT_IDENTITY_DOMAIN = b"threatfusion:autoencoder-artifact\0"
HISTORICAL_ARTIFACT_IDENTITY = "7d982df4f90fd0d3029beb6962b8afdc853cfa3efbeb7d57f58c14a2f92a896f"


class NetworkAutoencoderError(RuntimeError):
    """Sanitized fail-closed autoencoder error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class NetworkAutoencoder(nn.Module):
    """The single frozen 14-8-3-8-14 dense architecture."""

    def __init__(self) -> None:
        super().__init__()
        self.layers = nn.Sequential(
            nn.Linear(INPUT_WIDTH, HIDDEN_WIDTH),
            nn.ReLU(),
            nn.Linear(HIDDEN_WIDTH, BOTTLENECK_WIDTH),
            nn.ReLU(),
            nn.Linear(BOTTLENECK_WIDTH, HIDDEN_WIDTH),
            nn.ReLU(),
            nn.Linear(HIDDEN_WIDTH, INPUT_WIDTH),
        )
        linear_layers = [layer for layer in self.layers if isinstance(layer, nn.Linear)]
        for layer in linear_layers[:-1]:
            nn.init.xavier_uniform_(layer.weight, gain=nn.init.calculate_gain("relu"))
            nn.init.zeros_(layer.bias)
        nn.init.xavier_uniform_(linear_layers[-1].weight, gain=1.0)
        nn.init.zeros_(linear_layers[-1].bias)

    def forward(self, values: torch.Tensor) -> torch.Tensor:
        return self.layers(values)


class _BenignDataset(Dataset[torch.Tensor]):
    def __init__(self, matrix: np.ndarray, indices: np.ndarray) -> None:
        self._matrix = matrix
        self.indices = indices

    def __len__(self) -> int:
        return int(self.indices.size)

    def __getitem__(self, index: int) -> torch.Tensor:
        row = np.array(self._matrix[int(self.indices[index])], dtype=np.float32, copy=True)
        return torch.from_numpy(row)


@dataclass(frozen=True, slots=True)
class FitResult:
    epoch_losses: tuple[float, ...]
    rows_per_epoch: tuple[int, ...]
    fit_seconds: float
    peak_rss_bytes: int


@dataclass(frozen=True, slots=True)
class AutoencoderRunResult:
    run_directory: Path
    report_path: Path
    threshold: float
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class TrustedAutoencoderBundle:
    """Expected bundle bytes supplied by trusted application configuration."""

    scoring_contract_version: str
    configuration_sha256: str
    model_state_sha256: str
    threshold_sha256: str
    manifest_sha256: str
    report_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedAutoencoderDetector:
    """Threshold detector available only after complete v2 bundle verification."""

    model: NetworkAutoencoder
    threshold: float
    artifact_identity: str

    def score(self, matrix: np.ndarray, *, caller_chunk_size: int = 256) -> np.ndarray:
        return score_records_v2(self.model, matrix, caller_chunk_size=caller_chunk_size)

    def detect(self, matrix: np.ndarray, *, caller_chunk_size: int = 256) -> np.ndarray:
        return threshold_scores(
            self.score(matrix, caller_chunk_size=caller_chunk_size), self.threshold
        )


_HISTORICAL_TRUSTED_BUNDLE = TrustedAutoencoderBundle(
    scoring_contract_version=HISTORICAL_SCORE_IDENTITY,
    configuration_sha256="2b904768fc264c7c29965cdd5c93b7535f16737e32fcf84620a09c66ffc5695e",
    model_state_sha256="c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23",
    threshold_sha256="ebe9ef140b89e7e0fc8dc6a74ccb4e1d9a08c7eb25f6460a772c8bae8bfc9fce",
    manifest_sha256="e248bf27def9ad4fe92ccee59e166d6dbeef7bd33dc1da0f2050694ad9e4f3a4",
    report_sha256="ac6f411f1bb29c825e59129a88f79b8d2b96582a79d4e057e9f0a1fd118fe754",
)
APPROVED_AUTOENCODER_BUNDLES: Final[Mapping[str, TrustedAutoencoderBundle]] = MappingProxyType(
    {HISTORICAL_ARTIFACT_IDENTITY: _HISTORICAL_TRUSTED_BUNDLE}
)


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_json_bytes(payload))
    temporary.replace(path)


def _read_json(path: Path, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NetworkAutoencoderError(code) from exc
    if not isinstance(value, dict):
        raise NetworkAutoencoderError(code)
    return value


def _read_json_bytes(data: bytes, code: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkAutoencoderError(code) from exc
    if type(value) is not dict:
        raise NetworkAutoencoderError(code)
    return value


def _regular_file_bytes(path: Path, code: str) -> bytes:
    """Read one bounded regular file without following links or reopening it."""
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_size < 1
            or details.st_size > ARTIFACT_BUDGET_BYTES
        ):
            raise NetworkAutoencoderError(code)
        chunks: list[bytes] = []
        remaining = details.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise NetworkAutoencoderError(code)
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise NetworkAutoencoderError(code)
        return b"".join(chunks)
    except (OSError, ValueError) as exc:
        raise NetworkAutoencoderError(code) from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _verified_bundle_bytes(path: Path, expected_sha256: str, code: str) -> bytes:
    if type(expected_sha256) is not str or _SHA256.fullmatch(expected_sha256) is None:
        raise NetworkAutoencoderError("trusted_bundle_identity_invalid")
    data = _regular_file_bytes(path, code)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise NetworkAutoencoderError(code)
    return data


def _write_snapshot(path: Path, data: bytes) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def _capture_source_provenance(
    run_directory: Path, *, project_root: Path, protocol_path: Path
) -> tuple[dict[str, Any], str]:
    """Persist exact protocol/model/runner bytes before any future fit begins."""
    sources = (
        ("protocol", protocol_path, PROTOCOL_SNAPSHOT_FILENAME),
        ("model_source", Path(__file__).resolve(), MODEL_SOURCE_SNAPSHOT_FILENAME),
        (
            "runner_source",
            (project_root / "scripts/train_network_autoencoder.py").resolve(),
            RUNNER_SOURCE_SNAPSHOT_FILENAME,
        ),
    )
    evidence: dict[str, dict[str, Any]] = {}
    for name, source, snapshot_name in sources:
        data = _regular_file_bytes(source, "source_provenance_unreadable")
        _write_snapshot(run_directory / snapshot_name, data)
        evidence[name] = {
            "filename": snapshot_name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
        }
    manifest = {
        "schema_version": "unsw_autoencoder_source_provenance_v2",
        "captured_before_training": True,
        "files": evidence,
    }
    manifest_path = run_directory / PROVENANCE_MANIFEST_FILENAME
    _write_json(manifest_path, manifest)
    return manifest, sha256_file(manifest_path)


def _peak_rss_bytes() -> int:
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024


def _available_memory_bytes() -> int:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError) as exc:
        raise NetworkAutoencoderError("available_memory_unreadable") from exc
    raise NetworkAutoencoderError("available_memory_unreadable")


def _check_runtime_bound(started: float) -> None:
    if time.monotonic() - started > DEADLINE_SECONDS:
        raise NetworkAutoencoderError("training_deadline_exceeded")
    if _peak_rss_bytes() > MAX_RSS_BYTES:
        raise NetworkAutoencoderError("peak_rss_limit_exceeded")


def configure_deterministic_cpu_runtime() -> None:
    """Enforce the frozen CPU-only deterministic execution boundary."""
    if torch.version.cuda is not None or torch.cuda.is_available():
        raise NetworkAutoencoderError("cpu_only_torch_required")
    torch.set_num_threads(INTRAOP_THREADS)
    if torch.get_num_interop_threads() != INTEROP_THREADS:
        try:
            torch.set_num_interop_threads(INTEROP_THREADS)
        except RuntimeError as exc:
            raise NetworkAutoencoderError("interop_thread_configuration_failed") from exc
    torch.use_deterministic_algorithms(True)
    if not torch.are_deterministic_algorithms_enabled():
        raise NetworkAutoencoderError("deterministic_algorithms_unavailable")


def seed_runtime() -> None:
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)


def create_frozen_autoencoder() -> NetworkAutoencoder:
    model = NetworkAutoencoder().to(device=torch.device("cpu"), dtype=torch.float32)
    if sum(parameter.numel() for parameter in model.parameters()) != TRAINABLE_PARAMETER_COUNT:
        raise NetworkAutoencoderError("architecture_parameter_count_mismatch")
    return model


def benign_train_indices(labels: np.ndarray, *, expected_benign: int) -> np.ndarray:
    """Return only Normal=0 positions after exact binary-label validation."""
    labels = np.asarray(labels)
    if labels.ndim != 1 or labels.dtype != np.uint8 or not np.isin(labels, (0, 1)).all():
        raise NetworkAutoencoderError("training_labels_invalid")
    indices = np.flatnonzero(labels == LABEL_MAPPING["Normal"]).astype(np.int64, copy=False)
    if indices.size != expected_benign:
        raise NetworkAutoencoderError("benign_training_count_mismatch")
    if np.any(labels[indices] != LABEL_MAPPING["Normal"]):
        raise NetworkAutoencoderError("attack_training_record_selected")
    return indices


def validate_matrix(matrix: np.ndarray, *, rows: int, name: str) -> None:
    if matrix.shape != (rows, INPUT_WIDTH) or matrix.dtype != np.float64:
        raise NetworkAutoencoderError(f"{name}_shape_or_dtype_invalid")
    for start in range(0, rows, 50_000):
        if not np.isfinite(matrix[start : start + 50_000]).all():
            raise NetworkAutoencoderError(f"{name}_non_finite")


def validate_feature_order(feature_names: tuple[str, ...] | list[str]) -> None:
    if list(feature_names) != list(TRANSFORMED_FEATURE_NAMES):
        raise NetworkAutoencoderError("feature_order_mismatch")


def verify_autoencoder_inputs(run_directory: Path) -> VerifiedPreprocessingArtifacts:
    inputs = verify_preprocessing_artifacts(run_directory)
    if (
        inputs.state_sha256 != EXPECTED_PREPROCESSING_HASHES["state"]
        or inputs.configuration_sha256 != EXPECTED_PREPROCESSING_HASHES["configuration"]
        or inputs.report_sha256 != EXPECTED_PREPROCESSING_HASHES["report"]
        or inputs.configuration.get("assignment")
        != {
            "schema_version": "unsw_development_split_v1",
            "seed": "threatfusion-unsw-dev-split-v1",
            **EXPECTED_ASSIGNMENT_HASHES,
        }
        or inputs.report.get("counts", {}).get("train") != EXPECTED_COUNTS["train"]
        or inputs.report.get("counts", {}).get("validation") != EXPECTED_COUNTS["validation"]
        or inputs.state.training_row_count != EXPECTED_COUNTS["train"]["rows"]
    ):
        raise NetworkAutoencoderError("preprocessing_protocol_binding_mismatch")
    validate_feature_order(inputs.report.get("output_feature_names", []))
    output_hashes = inputs.report.get("hashes", {}).get("outputs", {})
    if any(
        output_hashes.get(name, {}).get("sha256") != EXPECTED_PREPROCESSING_HASHES[name]
        for name in ("X_train", "y_train", "X_validation", "y_validation")
    ):
        raise NetworkAutoencoderError("processed_input_protocol_hash_mismatch")
    validate_matrix(inputs.X_train, rows=EXPECTED_COUNTS["train"]["rows"], name="train_matrix")
    validate_matrix(
        inputs.X_validation,
        rows=EXPECTED_COUNTS["validation"]["rows"],
        name="validation_matrix",
    )
    return inputs


def fit_frozen_autoencoder(
    matrix: np.ndarray, labels: np.ndarray
) -> tuple[NetworkAutoencoder, FitResult]:
    """Fit exactly 30 epochs using only the verified benign TRAIN view."""
    indices = benign_train_indices(labels, expected_benign=EXPECTED_COUNTS["train"]["benign"])
    dataset = _BenignDataset(matrix, indices)
    generator = torch.Generator(device="cpu")
    generator.manual_seed(SEED)
    loader = DataLoader(
        dataset,
        batch_size=BATCH_SIZE,
        shuffle=True,
        drop_last=False,
        num_workers=0,
        pin_memory=False,
        generator=generator,
    )
    seed_runtime()
    model = create_frozen_autoencoder()
    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=LEARNING_RATE,
        betas=ADAM_BETAS,
        eps=ADAM_EPS,
        weight_decay=0.0,
        amsgrad=False,
    )
    started = time.monotonic()
    losses: list[float] = []
    rows_per_epoch: list[int] = []
    model.train()
    for _epoch in range(EPOCHS):
        loss_sum = 0.0
        rows = 0
        for batch in loader:
            _check_runtime_bound(started)
            batch = batch.to(device="cpu", dtype=torch.float32)
            optimizer.zero_grad(set_to_none=True)
            reconstruction = model(batch)
            loss = torch.mean((reconstruction - batch) ** 2)
            if not bool(torch.isfinite(loss)):
                raise NetworkAutoencoderError("non_finite_training_loss")
            loss.backward()
            optimizer.step()
            batch_rows = int(batch.shape[0])
            loss_sum += float(loss.detach()) * batch_rows
            rows += batch_rows
        if rows != EXPECTED_COUNTS["train"]["benign"]:
            raise NetworkAutoencoderError("incomplete_training_epoch")
        epoch_loss = loss_sum / rows
        if not math.isfinite(epoch_loss):
            raise NetworkAutoencoderError("non_finite_epoch_loss")
        losses.append(epoch_loss)
        rows_per_epoch.append(rows)
        _check_runtime_bound(started)
    fit_seconds = time.monotonic() - started
    return model, FitResult(tuple(losses), tuple(rows_per_epoch), fit_seconds, _peak_rss_bytes())


def reconstruction_errors(matrix: np.ndarray, reconstructions: np.ndarray) -> np.ndarray:
    """Apply the historical/v2 float32-input residual definition to supplied rows."""
    matrix = np.asarray(matrix)
    reconstructions = np.asarray(reconstructions)
    if matrix.ndim != 2 or matrix.shape[1] != INPUT_WIDTH or reconstructions.shape != matrix.shape:
        raise NetworkAutoencoderError("reconstruction_shape_invalid")
    converted_inputs = matrix.astype(np.float32, copy=False)
    converted_reconstructions = reconstructions.astype(np.float32, copy=False)
    residual = converted_inputs.astype(np.float64) - converted_reconstructions.astype(np.float64)
    squared = residual * residual
    scores = np.sum(squared, axis=1, dtype=np.float64) / np.float64(INPUT_WIDTH)
    if not np.isfinite(scores).all() or np.any(scores < 0.0):
        raise NetworkAutoencoderError("reconstruction_score_invalid")
    return scores


def _historical_reconstruction_errors_v1(
    converted_inputs: np.ndarray, reconstructions: np.ndarray
) -> np.ndarray:
    """Retain the executed v1 NumPy mean operation for historical reproduction."""
    converted_inputs = np.asarray(converted_inputs)
    reconstructions = np.asarray(reconstructions)
    if (
        converted_inputs.ndim != 2
        or converted_inputs.shape[1] != INPUT_WIDTH
        or reconstructions.shape != converted_inputs.shape
    ):
        raise NetworkAutoencoderError("reconstruction_shape_invalid")
    residual = converted_inputs.astype(np.float64) - reconstructions.astype(np.float64)
    scores = np.mean(residual * residual, axis=1, dtype=np.float64)
    if not np.isfinite(scores).all() or np.any(scores < 0.0):
        raise NetworkAutoencoderError("reconstruction_score_invalid")
    return scores


def _historical_score_in_batches_v1(
    model: NetworkAutoencoder,
    matrix: np.ndarray,
    *,
    batch_size: int = PREDICTION_BATCH_SIZE,
    deadline_started: float | None = None,
) -> np.ndarray:
    """Reproduce the historical caller-batched scorer for review evidence only."""
    if matrix.ndim != 2 or matrix.shape[1] != INPUT_WIDTH:
        raise NetworkAutoencoderError("scoring_matrix_shape_invalid")
    scores = np.empty(matrix.shape[0], dtype=np.float64)
    model.eval()
    with torch.inference_mode():
        for start in range(0, matrix.shape[0], batch_size):
            if deadline_started is not None:
                _check_runtime_bound(deadline_started)
            stop = min(start + batch_size, matrix.shape[0])
            values = np.array(matrix[start:stop], dtype=np.float32, copy=True)
            tensor = torch.from_numpy(values)
            reconstruction = model(tensor).cpu().numpy()
            scores[start:stop] = _historical_reconstruction_errors_v1(values, reconstruction)
    return scores


def score_records_v2(
    model: NetworkAutoencoder,
    matrix: np.ndarray,
    *,
    caller_chunk_size: int = PREDICTION_BATCH_SIZE,
    deadline_started: float | None = None,
) -> np.ndarray:
    """Score each row with one canonical float32 forward, independent of caller batching."""
    matrix = np.asarray(matrix)
    if (
        matrix.ndim != 2
        or matrix.shape[1] != INPUT_WIDTH
        or matrix.dtype != np.float64
        or not np.isfinite(matrix).all()
    ):
        raise NetworkAutoencoderError("scoring_matrix_invalid")
    if type(caller_chunk_size) is not int or caller_chunk_size < 1:
        raise NetworkAutoencoderError("scoring_chunk_size_invalid")
    scores = np.empty(matrix.shape[0], dtype=np.float64)
    model.eval()
    with torch.inference_mode():
        for chunk_start in range(0, matrix.shape[0], caller_chunk_size):
            if deadline_started is not None:
                _check_runtime_bound(deadline_started)
            chunk_stop = min(chunk_start + caller_chunk_size, matrix.shape[0])
            for index in range(chunk_start, chunk_stop):
                with np.errstate(over="ignore", invalid="ignore"):
                    converted_input = np.array(matrix[index], dtype=np.float32, copy=True).reshape(
                        1, INPUT_WIDTH
                    )
                if not np.isfinite(converted_input).all():
                    raise NetworkAutoencoderError("scoring_matrix_out_of_range")
                reconstruction = model(torch.from_numpy(converted_input)).cpu().numpy()
                scores[index] = reconstruction_errors(converted_input, reconstruction)[0]
    return scores


def score_in_batches(
    model: NetworkAutoencoder,
    matrix: np.ndarray,
    *,
    deadline_started: float | None = None,
) -> np.ndarray:
    """Compatibility name for the current invariant v2 scoring contract."""
    return score_records_v2(model, matrix, deadline_started=deadline_started)


def calibrate_threshold(benign_scores: np.ndarray) -> float:
    scores = np.asarray(benign_scores, dtype=np.float64)
    if scores.ndim != 1 or scores.size == 0 or not np.isfinite(scores).all():
        raise NetworkAutoencoderError("calibration_scores_invalid")
    threshold = float(np.quantile(scores, QUANTILE, method="higher"))
    if not math.isfinite(threshold) or threshold < 0.0:
        raise NetworkAutoencoderError("calibration_threshold_invalid")
    return threshold


def threshold_scores(scores: np.ndarray, threshold: float) -> np.ndarray:
    scores = np.asarray(scores, dtype=np.float64)
    if (
        scores.ndim != 1
        or not np.isfinite(scores).all()
        or not math.isfinite(threshold)
        or threshold < 0.0
    ):
        raise NetworkAutoencoderError("threshold_input_invalid")
    return (scores > threshold).astype(np.uint8)


def threshold_counts(scores: np.ndarray, threshold: float) -> dict[str, int]:
    """Reconcile every finite score below, equal to, or above the strict threshold."""
    decisions = threshold_scores(scores, threshold)
    values = np.asarray(scores, dtype=np.float64)
    counts = {
        "below": int(np.count_nonzero(values < threshold)),
        "equal": int(np.count_nonzero(values == threshold)),
        "above": int(np.count_nonzero(decisions)),
    }
    if sum(counts.values()) != values.size:
        raise NetworkAutoencoderError("threshold_count_mismatch")
    return counts


def calculate_metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, Any]:
    labels = np.asarray(labels)
    scores = np.asarray(scores, dtype=np.float64)
    if labels.ndim != 1 or scores.ndim != 1 or labels.shape != scores.shape:
        raise NetworkAutoencoderError("evaluation_input_shape_invalid")
    if not np.isin(labels, (0, 1)).all() or not np.isfinite(scores).all():
        raise NetworkAutoencoderError("evaluation_input_invalid")
    predictions = threshold_scores(scores, threshold)
    positive = labels == 1
    negative = labels == 0
    predicted_positive = predictions == 1
    tp = int(np.count_nonzero(positive & predicted_positive))
    fp = int(np.count_nonzero(negative & predicted_positive))
    tn = int(np.count_nonzero(negative & ~predicted_positive))
    fn = int(np.count_nonzero(positive & ~predicted_positive))
    positives = tp + fn
    negatives = fp + tn
    predicted = tp + fp
    precision = tp / predicted if predicted else 0.0
    recall = tp / positives if positives else 0.0
    specificity = tn / negatives if negatives else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "sample_count": int(labels.size),
        "normal_count": negatives,
        "attack_count": positives,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "attack_precision": precision,
        "attack_recall": recall,
        "attack_f1": f1,
        "false_positive_rate": fp / negatives if negatives else 0.0,
        "balanced_accuracy": (recall + specificity) / 2 if positives and negatives else None,
        "accuracy": (tp + tn) / labels.size if labels.size else 0.0,
        "average_precision": float(average_precision_score(labels, scores)) if positives else 0.0,
        "roc_auc": float(roc_auc_score(labels, scores)) if positives and negatives else None,
        "predicted_anomaly_count": predicted,
        "predicted_anomaly_percentage": 100.0 * predicted / labels.size if labels.size else 0.0,
        "threshold_counts": threshold_counts(scores, threshold),
        "reconstruction_threshold": threshold,
        "threshold_operator": ">",
        "score_identity": SCORE_IDENTITY,
    }


def verify_v2_reload_scoring(
    before: NetworkAutoencoder,
    after: NetworkAutoencoder,
    matrix: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    """Verify exact saved/reloaded scores and decisions across caller chunk arrangements."""
    sample = np.asarray(matrix[:257])
    scores_before = score_records_v2(before, sample, caller_chunk_size=1)
    scores_after_64 = score_records_v2(after, sample, caller_chunk_size=64)
    scores_after_256 = score_records_v2(after, sample, caller_chunk_size=256)
    decisions_before = threshold_scores(scores_before, threshold)
    if (
        not np.array_equal(scores_before, scores_after_64)
        or not np.array_equal(scores_before, scores_after_256)
        or not np.array_equal(decisions_before, threshold_scores(scores_after_64, threshold))
        or not np.array_equal(decisions_before, threshold_scores(scores_after_256, threshold))
    ):
        raise NetworkAutoencoderError("v2_reload_scoring_mismatch")
    return {
        "sample_count": int(sample.shape[0]),
        "sample_values_sha256": hashlib.sha256(
            sample.astype("<f8", copy=False).tobytes()
        ).hexdigest(),
        "caller_chunk_sizes": [1, 64, 256],
        "scores_exact": True,
        "decisions_exact": True,
        "partial_final_chunks_exercised": True,
    }


def calculate_complementarity(
    labels: np.ndarray, autoencoder_predictions: np.ndarray, forest_predictions: np.ndarray
) -> dict[str, Any]:
    labels = np.asarray(labels)
    ae = np.asarray(autoencoder_predictions)
    forest = np.asarray(forest_predictions)
    if labels.shape != ae.shape or labels.shape != forest.shape or labels.ndim != 1:
        raise NetworkAutoencoderError("complementarity_shape_invalid")
    if (
        not np.isin(labels, (0, 1)).all()
        or not np.isin(ae, (0, 1)).all()
        or not np.isin(forest, (0, 1)).all()
    ):
        raise NetworkAutoencoderError("complementarity_value_invalid")

    attack = labels == 1
    normal = labels == 0
    attack_counts = {
        "both_detected": int(np.count_nonzero(attack & (ae == 1) & (forest == 1))),
        "autoencoder_only_rf_missed": int(np.count_nonzero(attack & (ae == 1) & (forest == 0))),
        "random_forest_only_ae_missed": int(np.count_nonzero(attack & (ae == 0) & (forest == 1))),
        "missed_by_both": int(np.count_nonzero(attack & (ae == 0) & (forest == 0))),
    }
    normal_counts = {
        "both_false_positive": int(np.count_nonzero(normal & (ae == 1) & (forest == 1))),
        "autoencoder_only_added_false_positive": int(
            np.count_nonzero(normal & (ae == 1) & (forest == 0))
        ),
        "random_forest_only_false_positive": int(
            np.count_nonzero(normal & (ae == 0) & (forest == 1))
        ),
        "correctly_unflagged_by_both": int(np.count_nonzero(normal & (ae == 0) & (forest == 0))),
    }
    return {
        "attack": attack_counts,
        "normal": normal_counts,
        "hypothetical_or_rule": {
            "added_true_positives_over_random_forest": attack_counts["autoencoder_only_rf_missed"],
            "added_false_positives_over_random_forest": normal_counts[
                "autoencoder_only_added_false_positive"
            ],
            "not_enabled": True,
        },
    }


def save_state_dict(path: Path, model: NetworkAutoencoder) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    torch.save(model.state_dict(), temporary)
    temporary.replace(path)


def _load_state_bytes(data: bytes) -> NetworkAutoencoder:
    try:
        state = torch.load(io.BytesIO(data), map_location="cpu", weights_only=True)
    except Exception as exc:
        raise NetworkAutoencoderError("model_state_unreadable") from exc
    if not isinstance(state, dict):
        raise NetworkAutoencoderError("model_state_invalid")
    seed_runtime()
    model = create_frozen_autoencoder()
    expected = model.state_dict()
    if set(state) != set(expected):
        raise NetworkAutoencoderError("model_state_keys_mismatch")
    for name, tensor in state.items():
        if (
            type(name) is not str
            or not isinstance(tensor, torch.Tensor)
            or tensor.device.type != "cpu"
            or tensor.dtype != expected[name].dtype
            or tensor.shape != expected[name].shape
            or not bool(torch.isfinite(tensor).all())
        ):
            raise NetworkAutoencoderError("model_state_tensor_invalid")
    model.load_state_dict(state, strict=True)
    model.eval()
    return model


def load_verified_state(path: Path, expected_sha256: str) -> NetworkAutoencoder:
    try:
        if not path.is_file() or path.stat().st_size > ARTIFACT_BUDGET_BYTES:
            raise NetworkAutoencoderError("model_artifact_invalid")
        data = path.read_bytes()
    except OSError as exc:
        raise NetworkAutoencoderError("model_artifact_unreadable") from exc
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise NetworkAutoencoderError("model_artifact_hash_mismatch")
    return _load_state_bytes(data)


def verify_reload_equivalence(
    original: NetworkAutoencoder,
    reloaded: NetworkAutoencoder,
    matrix: np.ndarray,
    benign_indices: np.ndarray,
) -> dict[str, Any]:
    sample_indices = benign_indices[:RELOAD_SAMPLE_SIZE]
    values = np.array(matrix[sample_indices], dtype=np.float32, copy=True)
    with torch.inference_mode():
        tensor = torch.from_numpy(values)
        before = original(tensor).cpu().numpy()
        after = reloaded(tensor).cpu().numpy()
    state_equal = all(
        torch.equal(original.state_dict()[name], reloaded.state_dict()[name])
        for name in original.state_dict()
    )
    scores_before = reconstruction_errors(values, before)
    scores_after = reconstruction_errors(values, after)
    if (
        not state_equal
        or not np.array_equal(before, after)
        or not np.array_equal(scores_before, scores_after)
    ):
        raise NetworkAutoencoderError("model_reload_not_equivalent")
    sample_sha256 = hashlib.sha256(values.astype("<f4", copy=False).tobytes()).hexdigest()
    return {
        "sample_count": int(sample_indices.size),
        "sample_values_sha256": sample_sha256,
        "state_tensors_exact": True,
        "reconstructions_exact": True,
        "scores_exact": True,
    }


def _dependency_versions() -> dict[str, str]:
    versions = {"python": platform.python_version()}
    for package in (
        "torch",
        "numpy",
        "scipy",
        "scikit-learn",
        "joblib",
        "threadpoolctl",
        "pandas",
        "pydantic",
    ):
        versions[package] = importlib.metadata.version(package)
    return versions


def _supported_runtime_identity() -> dict[str, Any]:
    libc_name, libc_version = platform.libc_ver()
    return {
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "torch": torch.__version__,
        "torch_cuda_build": torch.version.cuda,
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "libc": [libc_name, libc_version],
        "byteorder": os.sys.byteorder,
        "device": "cpu",
        "model_arithmetic_dtype": "torch.float32",
    }


def _scoring_contract_payload() -> dict[str, Any]:
    return {
        "version": SCORING_CONTRACT_VERSION,
        "score_identity": SCORE_IDENTITY,
        "input": "finite transformed numpy.float64 record with 14 ordered features",
        "input_conversion": "elementwise IEEE-754 float64 to float32 before reconstruction",
        "model_arithmetic": "PyTorch CPU float32",
        "reconstruction_dtype": "float32",
        "residual_operands": "float64(float32(input)) minus float64(float32(reconstruction))",
        "reduction": "ordered 14-element sum of squared residuals in numpy.float64 divided by 14",
        "evaluation_unit": "one shape-(1,14) record per model forward",
        "threshold_comparison": "Anomaly exactly when score > threshold; equality is within",
    }


def _threshold_policy_payload() -> dict[str, Any]:
    return {
        "calibration_partition": "validation",
        "calibration_label": {"name": "Normal", "value": 0},
        "calibration_rows": EXPECTED_COUNTS["validation"]["benign"],
        "quantile": QUANTILE,
        "method": "higher",
        "operator": ">",
        "ties": "within_threshold",
        "not_operational_false_positive_target": True,
    }


def _trusted_bundle_is_well_formed(expected: TrustedAutoencoderBundle) -> bool:
    return type(expected) is TrustedAutoencoderBundle and all(
        type(value) is str and _SHA256.fullmatch(value) is not None
        for value in (
            expected.configuration_sha256,
            expected.model_state_sha256,
            expected.threshold_sha256,
            expected.manifest_sha256,
            expected.report_sha256,
        )
    )


def _verify_source_provenance_snapshot(
    directory: Path, configuration: dict[str, Any], manifest: dict[str, Any]
) -> None:
    provenance_binding = configuration.get("source_provenance")
    if type(provenance_binding) is not dict:
        raise NetworkAutoencoderError("source_provenance_mismatch")
    provenance_sha256 = provenance_binding.get("manifest_sha256")
    if (
        type(provenance_sha256) is not str
        or _SHA256.fullmatch(provenance_sha256) is None
        or provenance_binding.get("schema_version") != "unsw_autoencoder_source_provenance_v2"
        or provenance_binding.get("captured_before_training") is not True
        or manifest.get("source_provenance_manifest_sha256") != provenance_sha256
    ):
        raise NetworkAutoencoderError("source_provenance_mismatch")
    provenance_bytes = _verified_bundle_bytes(
        directory / PROVENANCE_MANIFEST_FILENAME,
        provenance_sha256,
        "source_provenance_mismatch",
    )
    provenance = _read_json_bytes(provenance_bytes, "source_provenance_mismatch")
    files = provenance.get("files")
    expected_filenames = {
        "protocol": PROTOCOL_SNAPSHOT_FILENAME,
        "model_source": MODEL_SOURCE_SNAPSHOT_FILENAME,
        "runner_source": RUNNER_SOURCE_SNAPSHOT_FILENAME,
    }
    if (
        provenance.get("schema_version") != "unsw_autoencoder_source_provenance_v2"
        or provenance.get("captured_before_training") is not True
        or type(files) is not dict
        or set(files) != set(expected_filenames)
    ):
        raise NetworkAutoencoderError("source_provenance_mismatch")
    for name, filename in expected_filenames.items():
        evidence = files[name]
        if (
            type(evidence) is not dict
            or evidence.get("filename") != filename
            or type(evidence.get("size_bytes")) is not int
            or evidence["size_bytes"] < 1
        ):
            raise NetworkAutoencoderError("source_provenance_mismatch")
        data = _verified_bundle_bytes(
            directory / filename,
            evidence.get("sha256"),
            "source_provenance_mismatch",
        )
        if len(data) != evidence["size_bytes"]:
            raise NetworkAutoencoderError("source_provenance_mismatch")
    if configuration.get("protocol_sha256") != files["protocol"]["sha256"]:
        raise NetworkAutoencoderError("source_provenance_mismatch")


def _load_verified_autoencoder_detector(
    directory: Path,
    *,
    artifact_identity: str,
    expected: TrustedAutoencoderBundle,
) -> VerifiedAutoencoderDetector:
    """Verify one approved v2 bundle completely before deserializing its state."""
    if (
        type(artifact_identity) is not str
        or _SHA256.fullmatch(artifact_identity) is None
        or not _trusted_bundle_is_well_formed(expected)
    ):
        raise NetworkAutoencoderError("trusted_bundle_identity_invalid")
    if expected.scoring_contract_version != SCORING_CONTRACT_VERSION:
        raise NetworkAutoencoderError("autoencoder_scoring_contract_incompatible")
    directory = directory.resolve()
    paths_and_hashes = {
        "configuration": (CONFIG_FILENAME, expected.configuration_sha256),
        "model": (MODEL_FILENAME, expected.model_state_sha256),
        "threshold": (THRESHOLD_FILENAME, expected.threshold_sha256),
        "manifest": (MANIFEST_FILENAME, expected.manifest_sha256),
        "report": (REPORT_FILENAME, expected.report_sha256),
    }
    snapshots = {
        name: _verified_bundle_bytes(
            directory / filename, digest, "autoencoder_bundle_integrity_failure"
        )
        for name, (filename, digest) in paths_and_hashes.items()
    }
    configuration = _read_json_bytes(
        snapshots["configuration"], "autoencoder_configuration_invalid"
    )
    threshold = _read_json_bytes(snapshots["threshold"], "autoencoder_threshold_invalid")
    manifest = _read_json_bytes(snapshots["manifest"], "autoencoder_manifest_invalid")
    report = _read_json_bytes(snapshots["report"], "autoencoder_report_invalid")
    calculated_identity = hashlib.sha256(
        _ARTIFACT_IDENTITY_DOMAIN + snapshots["manifest"]
    ).hexdigest()
    if calculated_identity != artifact_identity:
        raise NetworkAutoencoderError("autoencoder_artifact_identity_mismatch")

    expected_architecture = {
        "widths": [14, 8, 3, 8, 14],
        "hidden_activation": "ReLU",
        "output_activation": "linear",
        "bias": True,
        "trainable_parameters": TRAINABLE_PARAMETER_COUNT,
        "hidden_initialization": "xavier_uniform_relu_gain",
        "output_initialization": "xavier_uniform_linear_gain",
        "bias_initialization": "zero",
    }
    expected_identities = {
        "model": MODEL_IDENTITY,
        "detector": DETECTOR_IDENTITY,
        "detector_version": DETECTOR_VERSION,
        "preprocessing_requirements": PREPROCESSING_REQUIREMENTS,
        "scoring_contract_version": SCORING_CONTRACT_VERSION,
        "score": SCORE_IDENTITY,
    }
    preprocessing = configuration.get("preprocessing")
    if (
        configuration.get("schema_version") != SCHEMA_VERSION
        or configuration.get("identities") != expected_identities
        or configuration.get("architecture") != expected_architecture
        or configuration.get("scoring_contract") != _scoring_contract_payload()
        or configuration.get("threshold_policy") != _threshold_policy_payload()
        or type(preprocessing) is not dict
        or preprocessing.get("feature_order") != list(TRANSFORMED_FEATURE_NAMES)
        or {
            "state": preprocessing.get("state_sha256"),
            "configuration": preprocessing.get("configuration_sha256"),
            "report": preprocessing.get("report_sha256"),
        }
        != {key: EXPECTED_PREPROCESSING_HASHES[key] for key in ("state", "configuration", "report")}
    ):
        raise NetworkAutoencoderError("autoencoder_bundle_binding_mismatch")
    runtime = configuration.get("runtime")
    if (
        configuration.get("dependencies") != _dependency_versions()
        or configuration.get("supported_runtime") != _supported_runtime_identity()
        or type(runtime) is not dict
        or runtime.get("deterministic_algorithms") is not True
        or runtime.get("intraop_threads") != INTRAOP_THREADS
        or runtime.get("interop_threads") != INTEROP_THREADS
        or runtime.get("data_loader_workers") != 0
        or runtime.get("pin_memory") is not False
        or torch.version.cuda is not None
        or torch.cuda.is_available()
        or not torch.are_deterministic_algorithms_enabled()
        or torch.get_num_threads() != INTRAOP_THREADS
        or torch.get_num_interop_threads() != INTEROP_THREADS
    ):
        raise NetworkAutoencoderError("autoencoder_runtime_incompatible")

    threshold_value = threshold.get("threshold")
    if (
        threshold.get("schema_version") != "unsw_autoencoder_threshold_v2"
        or threshold.get("model_sha256") != expected.model_state_sha256
        or threshold.get("configuration_sha256") != expected.configuration_sha256
        or threshold.get("scoring_contract_version") != SCORING_CONTRACT_VERSION
        or threshold.get("score_identity") != SCORE_IDENTITY
        or threshold.get("calibration_partition") != "validation"
        or threshold.get("calibration_label") != "Normal=0"
        or threshold.get("calibration_rows") != EXPECTED_COUNTS["validation"]["benign"]
        or threshold.get("quantile") != QUANTILE
        or threshold.get("method") != "higher"
        or threshold.get("operator") != ">"
        or threshold.get("ties") != "within_threshold"
        or threshold.get("operational_false_positive_target") is not None
        or threshold.get("february_influenced_threshold") is not False
        or threshold.get("cic_influenced_threshold") is not False
        or type(threshold_value) is not float
        or not math.isfinite(threshold_value)
        or threshold_value < 0.0
    ):
        raise NetworkAutoencoderError("autoencoder_threshold_binding_mismatch")
    expected_preprocessing_hashes = {
        "state": preprocessing.get("state_sha256"),
        "configuration": preprocessing.get("configuration_sha256"),
        "report": preprocessing.get("report_sha256"),
    }
    if (
        manifest.get("schema_version") != "unsw_autoencoder_artifact_manifest_v2"
        or manifest.get("identities") != expected_identities
        or manifest.get("configuration_sha256") != expected.configuration_sha256
        or manifest.get("model_state_sha256") != expected.model_state_sha256
        or manifest.get("threshold_sha256") != expected.threshold_sha256
        or manifest.get("preprocessing_hashes") != expected_preprocessing_hashes
    ):
        raise NetworkAutoencoderError("autoencoder_manifest_binding_mismatch")
    _verify_source_provenance_snapshot(directory, configuration, manifest)
    report_model = report.get("model")
    report_threshold = report.get("threshold")
    if (
        report.get("schema_version") != SCHEMA_VERSION
        or report.get("completed") is not True
        or report.get("configuration_sha256") != expected.configuration_sha256
        or type(report_model) is not dict
        or report_model.get("sha256") != expected.model_state_sha256
        or report_model.get("artifact_manifest_sha256") != expected.manifest_sha256
        or report_model.get("artifact_identity") != artifact_identity
        or type(report_threshold) is not dict
        or report_threshold.get("artifact_sha256") != expected.threshold_sha256
        or report_threshold.get("threshold") != threshold_value
        or report_threshold.get("scoring_contract_version") != SCORING_CONTRACT_VERSION
    ):
        raise NetworkAutoencoderError("autoencoder_report_binding_mismatch")
    model = _load_state_bytes(snapshots["model"])
    return VerifiedAutoencoderDetector(model, threshold_value, artifact_identity)


def load_verified_autoencoder_detector(
    directory: Path, *, expected_artifact_identity: str
) -> VerifiedAutoencoderDetector:
    """Load a threshold detector only from the code-owned approved bundle registry."""
    if type(expected_artifact_identity) is not str:
        raise NetworkAutoencoderError("autoencoder_artifact_identity_not_approved")
    expected = APPROVED_AUTOENCODER_BUNDLES.get(expected_artifact_identity)
    if expected is None:
        raise NetworkAutoencoderError("autoencoder_artifact_identity_not_approved")
    if expected_artifact_identity == HISTORICAL_ARTIFACT_IDENTITY:
        raise NetworkAutoencoderError("historical_threshold_incompatible_with_scoring_contract_v2")
    return _load_verified_autoencoder_detector(
        directory,
        artifact_identity=expected_artifact_identity,
        expected=expected,
    )


def _git_provenance(project_root: Path) -> dict[str, Any]:
    def run(*arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    return {
        "head": run("rev-parse", "HEAD"),
        "origin_main": run("rev-parse", "origin/main"),
        "working_tree_dirty": bool(run("status", "--porcelain")),
    }


def _verify_resources(artifact_root: Path) -> dict[str, Any]:
    available = _available_memory_bytes()
    free_disk = shutil.disk_usage(artifact_root).free
    if (
        ESTIMATED_PEAK_BYTES > MAX_RSS_BYTES
        or available < ESTIMATED_PEAK_BYTES + MEMORY_RESERVE_BYTES
    ):
        raise NetworkAutoencoderError("insufficient_memory_for_autoencoder")
    if free_disk < DISK_RESERVE_BYTES + ARTIFACT_BUDGET_BYTES:
        raise NetworkAutoencoderError("insufficient_disk_for_autoencoder")
    return {
        "measurement_method": "Linux /proc/meminfo MemAvailable, shutil.disk_usage, resource.ru_maxrss",
        "available_memory_bytes_before_fit": available,
        "free_disk_bytes_before_fit": free_disk,
        "estimated_peak_bytes": ESTIMATED_PEAK_BYTES,
        "peak_rss_limit_bytes": MAX_RSS_BYTES,
        "memory_reserve_bytes": MEMORY_RESERVE_BYTES,
        "disk_reserve_bytes": DISK_RESERVE_BYTES,
        "artifact_budget_bytes": ARTIFACT_BUDGET_BYTES,
        "deadline_seconds": DEADLINE_SECONDS,
    }


def verify_february_inputs(
    directory: Path, inputs: VerifiedPreprocessingArtifacts, forest_sha256: str
) -> tuple[np.memmap, np.memmap, dict[str, Any]]:
    directory = directory.resolve()
    config_path = directory / "evaluation_config.json"
    report_path = directory / "evaluation_report.json"
    matrix_path = directory / "X_test.npy"
    labels_path = directory / "y_test.npy"
    if (
        sha256_file(config_path) != EXPECTED_FEBRUARY_HASHES["configuration"]
        or sha256_file(report_path) != EXPECTED_FEBRUARY_HASHES["report"]
    ):
        raise NetworkAutoencoderError("february_metadata_hash_mismatch")
    config = _read_json(config_path, "february_configuration_unreadable")
    report = _read_json(report_path, "february_report_unreadable")
    expected_preprocessing = {
        "state_sha256": inputs.state_sha256,
        "configuration_sha256": inputs.configuration_sha256,
        "report_sha256": inputs.report_sha256,
    }
    if (
        config.get("schema_version") != "unsw_february_classical_evaluation_v1"
        or config.get("evaluation_partition") != "test"
        or config.get("expected_counts")
        != {
            "rows": EXPECTED_COUNTS["test"]["rows"],
            "normal": EXPECTED_COUNTS["test"]["benign"],
            "attack": EXPECTED_COUNTS["test"]["attack"],
        }
        or config.get("preprocessing") != expected_preprocessing
        or config.get("transformed_feature_names") != list(TRANSFORMED_FEATURE_NAMES)
        or config.get("assignment") != EXPECTED_ASSIGNMENT_HASHES
        or config.get("models", {}).get("random_forest", {}).get("model_sha256") != forest_sha256
        or report.get("completed") is not True
        or report.get("checks", {}).get("cic_not_accessed") is not True
        or report.get("configuration_sha256") != EXPECTED_FEBRUARY_HASHES["configuration"]
    ):
        raise NetworkAutoencoderError("february_protocol_binding_mismatch")
    for name, path in (("X_test", matrix_path), ("y_test", labels_path)):
        evidence = report.get("outputs", {}).get(f"{name}.npy", {})
        if (
            evidence.get("sha256") != EXPECTED_FEBRUARY_HASHES[name]
            or not path.is_file()
            or path.stat().st_size != evidence.get("size_bytes")
            or sha256_file(path) != EXPECTED_FEBRUARY_HASHES[name]
        ):
            raise NetworkAutoencoderError("february_output_integrity_failure")
    try:
        matrix = np.load(matrix_path, mmap_mode="r", allow_pickle=False)
        labels = np.load(labels_path, mmap_mode="r", allow_pickle=False)
    except (OSError, ValueError) as exc:
        raise NetworkAutoencoderError("february_output_unreadable") from exc
    validate_matrix(matrix, rows=EXPECTED_COUNTS["test"]["rows"], name="test_matrix")
    if labels.shape != (EXPECTED_COUNTS["test"]["rows"],) or labels.dtype != np.uint8:
        raise NetworkAutoencoderError("test_labels_shape_or_dtype_invalid")
    counts = np.bincount(labels, minlength=2)
    if counts.tolist() != [EXPECTED_COUNTS["test"]["benign"], EXPECTED_COUNTS["test"]["attack"]]:
        raise NetworkAutoencoderError("test_label_counts_mismatch")
    return (
        matrix,
        labels,
        {
            "configuration_sha256": EXPECTED_FEBRUARY_HASHES["configuration"],
            "report_sha256": EXPECTED_FEBRUARY_HASHES["report"],
            "X_test_sha256": EXPECTED_FEBRUARY_HASHES["X_test"],
            "y_test_sha256": EXPECTED_FEBRUARY_HASHES["y_test"],
            "historical_result_reused_without_raw_access": True,
        },
    )


def run_synthetic_smoke() -> dict[str, Any]:
    """Exercise the frozen architecture, optimizer, partial batch, score, and safe reload."""
    configure_deterministic_cpu_runtime()
    seed_runtime()
    matrix = np.tile(np.arange(INPUT_WIDTH, dtype=np.float64), (1025, 1)) / 10.0
    labels = np.zeros(1025, dtype=np.uint8)
    original_expected = EXPECTED_COUNTS["train"]["benign"]
    indices = benign_train_indices(labels, expected_benign=1025)
    dataset = _BenignDataset(matrix, indices)
    generator = torch.Generator(device="cpu").manual_seed(SEED)
    loader = DataLoader(
        dataset, batch_size=BATCH_SIZE, shuffle=True, drop_last=False, generator=generator
    )
    model = create_frozen_autoencoder()
    optimizer = torch.optim.Adam(
        model.parameters(), lr=LEARNING_RATE, betas=ADAM_BETAS, eps=ADAM_EPS
    )
    final_batch_sizes: list[int] = []
    for epoch in range(EPOCHS):
        epoch_sizes = []
        for batch in loader:
            optimizer.zero_grad(set_to_none=True)
            reconstruction = model(batch)
            loss = torch.mean((reconstruction - batch) ** 2)
            loss.backward()
            optimizer.step()
            epoch_sizes.append(int(batch.shape[0]))
        if epoch == EPOCHS - 1:
            final_batch_sizes = epoch_sizes
    scores = score_in_batches(model, matrix[:8])
    threshold = calibrate_threshold(scores[:6])
    decisions = threshold_scores(
        np.asarray([threshold, np.nextafter(threshold, math.inf)]), threshold
    )
    with tempfile.TemporaryDirectory(prefix="threatfusion-ae-smoke-") as directory:
        state_path = Path(directory) / MODEL_FILENAME
        save_state_dict(state_path, model)
        model_hash = sha256_file(state_path)
        reloaded = load_verified_state(state_path, model_hash)
        reload_evidence = verify_reload_equivalence(model, reloaded, matrix, indices)
    if (
        original_expected != 847_837
        or final_batch_sizes != [1024, 1]
        or decisions.tolist() != [0, 1]
        or not np.isfinite(scores).all()
        or reload_evidence["state_tensors_exact"] is not True
    ):
        raise NetworkAutoencoderError("synthetic_smoke_failed")
    return {
        "completed": True,
        "not_dataset_evidence": True,
        "epochs": EPOCHS,
        "sample_count": 1025,
        "final_epoch_batch_sizes": final_batch_sizes,
        "architecture_parameters": TRAINABLE_PARAMETER_COUNT,
        "safe_reload_verified": True,
    }


def _artifact_bytes(run_directory: Path) -> int:
    return sum(path.stat().st_size for path in run_directory.iterdir() if path.is_file())


def _write_failure(run_directory: Path, code: str) -> None:
    _write_json(
        run_directory / FAILURE_FILENAME,
        {"schema_version": SCHEMA_VERSION, "completed": False, "failure_code": code},
    )


def run_full_autoencoder(
    *,
    project_root: Path,
    preprocessing_directory: Path,
    forest_directory: Path,
    february_directory: Path,
    artifact_root: Path,
    run_id: str,
    protocol_path: Path,
) -> AutoencoderRunResult:
    """Run the one authorized fit, calibration, and matching aggregate evaluations."""
    total_started = time.monotonic()
    if not _RUN_ID.fullmatch(run_id):
        raise NetworkAutoencoderError("invalid_run_id")
    project_root = project_root.resolve()
    artifact_root = artifact_root.resolve()
    if artifact_root != (project_root / "artifacts/models/network_autoencoder").resolve():
        raise NetworkAutoencoderError("artifact_root_invalid")
    artifact_root.mkdir(parents=True, exist_ok=True)
    resources = _verify_resources(artifact_root)
    configure_deterministic_cpu_runtime()
    verification_started = time.monotonic()
    try:
        inputs = verify_autoencoder_inputs(preprocessing_directory)
        forest = verify_saved_model(forest_directory, inputs, name="random_forest")
    except NetworkBaselineError as exc:
        raise NetworkAutoencoderError(exc.code) from exc
    if forest.model_sha256 != EXPECTED_FOREST_HASH:
        raise NetworkAutoencoderError("random_forest_protocol_hash_mismatch")
    benign_indices = benign_train_indices(
        inputs.y_train, expected_benign=EXPECTED_COUNTS["train"]["benign"]
    )
    verification_seconds = time.monotonic() - verification_started

    run_directory = artifact_root / run_id
    try:
        run_directory.mkdir()
    except FileExistsError as exc:
        raise NetworkAutoencoderError("run_directory_already_exists") from exc
    try:
        source_provenance, source_provenance_sha256 = _capture_source_provenance(
            run_directory,
            project_root=project_root,
            protocol_path=protocol_path,
        )
        configuration = {
            "schema_version": SCHEMA_VERSION,
            "protocol_sha256": source_provenance["files"]["protocol"]["sha256"],
            "identities": {
                "model": MODEL_IDENTITY,
                "detector": DETECTOR_IDENTITY,
                "detector_version": DETECTOR_VERSION,
                "preprocessing_requirements": PREPROCESSING_REQUIREMENTS,
                "scoring_contract_version": SCORING_CONTRACT_VERSION,
                "score": SCORE_IDENTITY,
            },
            "architecture": {
                "widths": [14, 8, 3, 8, 14],
                "hidden_activation": "ReLU",
                "output_activation": "linear",
                "bias": True,
                "trainable_parameters": TRAINABLE_PARAMETER_COUNT,
                "hidden_initialization": "xavier_uniform_relu_gain",
                "output_initialization": "xavier_uniform_linear_gain",
                "bias_initialization": "zero",
            },
            "fit": {
                "partition": "train",
                "eligible_label": {"name": "Normal", "value": 0},
                "eligible_rows": EXPECTED_COUNTS["train"]["benign"],
                "excluded_attack_rows": EXPECTED_COUNTS["train"]["attack"],
                "validation_rows_used_for_weight_fit": 0,
                "test_rows_used_for_weight_fit": 0,
                "cic_rows_used": 0,
                "dtype": "float32",
                "device": "cpu",
                "loss": "mean_squared_error_mean_over_samples_and_14_columns",
                "optimizer": {
                    "name": "Adam",
                    "learning_rate": LEARNING_RATE,
                    "betas": list(ADAM_BETAS),
                    "eps": ADAM_EPS,
                    "weight_decay": 0.0,
                    "amsgrad": False,
                },
                "seed": SEED,
                "batch_size": BATCH_SIZE,
                "epochs": EPOCHS,
                "shuffle": "deterministic_seeded_each_epoch",
                "drop_last": False,
                "early_stopping": False,
                "sweep": False,
            },
            "scoring_contract": _scoring_contract_payload(),
            "threshold_policy": _threshold_policy_payload(),
            "preprocessing": {
                "statistics_population": "all 865480 TRAIN rows including 17643 Attack rows",
                "reused_without_refit": True,
                "state_sha256": inputs.state_sha256,
                "configuration_sha256": inputs.configuration_sha256,
                "report_sha256": inputs.report_sha256,
                "output_hashes": inputs.report["hashes"]["outputs"],
                "feature_order": list(TRANSFORMED_FEATURE_NAMES),
                "assignment": inputs.configuration["assignment"],
            },
            "random_forest_comparison": {
                "model_sha256": forest.model_sha256,
                "configuration_sha256": forest.configuration_sha256,
                "report_sha256": forest.report_sha256,
                "retrained": False,
            },
            "dependencies": _dependency_versions(),
            "supported_runtime": _supported_runtime_identity(),
            "torch_build": {
                "version": torch.__version__,
                "cuda_build": torch.version.cuda,
                "cuda_available": torch.cuda.is_available(),
            },
            "runtime": {
                "platform": platform.platform(),
                "interpreter": os.path.realpath(os.sys.executable),
                "intraop_threads": INTRAOP_THREADS,
                "interop_threads": INTEROP_THREADS,
                "deterministic_algorithms": torch.are_deterministic_algorithms_enabled(),
                "data_loader_workers": 0,
                "pin_memory": False,
            },
            "source_provenance": {
                "schema_version": source_provenance["schema_version"],
                "manifest_sha256": source_provenance_sha256,
                "captured_before_training": True,
            },
            "resource_limits": resources,
            "code_provenance": _git_provenance(project_root),
            "execution_record": {
                "model": "unavailable",
                "reasoning_effort": "unavailable",
                "token_quota": "unavailable",
            },
        }
        config_path = run_directory / CONFIG_FILENAME
        _write_json(config_path, configuration)
        configuration_sha256 = sha256_file(config_path)

        model, fit = fit_frozen_autoencoder(inputs.X_train, inputs.y_train)
        model_path = run_directory / MODEL_FILENAME
        save_state_dict(model_path, model)
        model_sha256 = sha256_file(model_path)
        reloaded = load_verified_state(model_path, model_sha256)
        reload_evidence = verify_reload_equivalence(model, reloaded, inputs.X_train, benign_indices)

        validation_started = time.monotonic()
        validation_scores = score_in_batches(
            reloaded, inputs.X_validation, deadline_started=total_started
        )
        benign_validation = inputs.y_validation == LABEL_MAPPING["Normal"]
        if int(np.count_nonzero(benign_validation)) != EXPECTED_COUNTS["validation"]["benign"]:
            raise NetworkAutoencoderError("validation_benign_count_mismatch")
        threshold = calibrate_threshold(validation_scores[benign_validation])
        threshold_payload = {
            "schema_version": "unsw_autoencoder_threshold_v2",
            "model_sha256": model_sha256,
            "configuration_sha256": configuration_sha256,
            "scoring_contract_version": SCORING_CONTRACT_VERSION,
            "score_identity": SCORE_IDENTITY,
            "calibration_evidence": "January VALIDATION development data, not independent evaluation",
            "calibration_partition": "validation",
            "calibration_label": "Normal=0",
            "calibration_rows": EXPECTED_COUNTS["validation"]["benign"],
            "quantile": QUANTILE,
            "method": "higher",
            "operator": ">",
            "ties": "within_threshold",
            "threshold": threshold,
            "operational_false_positive_target": None,
            "february_influenced_threshold": False,
            "cic_influenced_threshold": False,
        }
        threshold_path = run_directory / THRESHOLD_FILENAME
        _write_json(threshold_path, threshold_payload)
        threshold_sha256 = sha256_file(threshold_path)
        v2_reload_scoring = verify_v2_reload_scoring(
            model, reloaded, inputs.X_validation, threshold
        )

        with threadpool_limits(limits=1):
            validation_forest_scores = batched_attack_probabilities(
                forest.model, inputs.X_validation, batch_size=PREDICTION_BATCH_SIZE
            )
        validation_metrics = calculate_metrics(inputs.y_validation, validation_scores, threshold)
        validation_ae_predictions = threshold_scores(validation_scores, threshold)
        validation_forest_predictions = (validation_forest_scores >= 0.5).astype(np.uint8)
        validation_complementarity = calculate_complementarity(
            inputs.y_validation, validation_ae_predictions, validation_forest_predictions
        )
        validation_seconds = time.monotonic() - validation_started

        february_started = time.monotonic()
        test_matrix, test_labels, february_provenance = verify_february_inputs(
            february_directory, inputs, forest.model_sha256
        )
        test_scores = score_in_batches(reloaded, test_matrix, deadline_started=total_started)
        with threadpool_limits(limits=1):
            test_forest_scores = batched_attack_probabilities(
                forest.model, test_matrix, batch_size=PREDICTION_BATCH_SIZE
            )
        test_metrics = calculate_metrics(test_labels, test_scores, threshold)
        test_ae_predictions = threshold_scores(test_scores, threshold)
        test_forest_predictions = (test_forest_scores >= 0.5).astype(np.uint8)
        test_complementarity = calculate_complementarity(
            test_labels, test_ae_predictions, test_forest_predictions
        )
        february_seconds = time.monotonic() - february_started

        manifest = {
            "schema_version": "unsw_autoencoder_artifact_manifest_v2",
            "identities": configuration["identities"],
            "configuration_sha256": configuration_sha256,
            "model_state_sha256": model_sha256,
            "threshold_sha256": threshold_sha256,
            "source_provenance_manifest_sha256": source_provenance_sha256,
            "preprocessing_hashes": {
                "state": inputs.state_sha256,
                "configuration": inputs.configuration_sha256,
                "report": inputs.report_sha256,
            },
            "assignment_hashes": EXPECTED_ASSIGNMENT_HASHES,
        }
        manifest_path = run_directory / MANIFEST_FILENAME
        _write_json(manifest_path, manifest)
        manifest_sha256 = sha256_file(manifest_path)
        artifact_identity = hashlib.sha256(
            _ARTIFACT_IDENTITY_DOMAIN + manifest_path.read_bytes()
        ).hexdigest()
        total_seconds = time.monotonic() - total_started
        report = {
            "schema_version": SCHEMA_VERSION,
            "completed": True,
            "global_training_ready": False,
            "evidence_labels": {
                "validation": "development_informed_post_calibration",
                "february_test": "later_period_development_informed_previously_inspected_benchmark",
            },
            "configuration_sha256": configuration_sha256,
            "model": {
                "filename": MODEL_FILENAME,
                "sha256": model_sha256,
                "size_bytes": model_path.stat().st_size,
                "trainable_parameters": TRAINABLE_PARAMETER_COUNT,
                "artifact_manifest_sha256": manifest_sha256,
                "artifact_identity": artifact_identity,
            },
            "threshold": {**threshold_payload, "artifact_sha256": threshold_sha256},
            "fit": {
                "eligible_benign_train_rows": EXPECTED_COUNTS["train"]["benign"],
                "excluded_attack_train_rows": EXPECTED_COUNTS["train"]["attack"],
                "validation_rows_used_for_weight_fit": 0,
                "test_rows_used_for_weight_fit": 0,
                "epochs_completed": len(fit.epoch_losses),
                "rows_per_epoch": list(fit.rows_per_epoch),
                "epoch_mean_losses": list(fit.epoch_losses),
                "final_partial_batch_rows": EXPECTED_COUNTS["train"]["benign"] % BATCH_SIZE,
            },
            "validation": {
                "evidence_label": "development_informed_post_calibration",
                "autoencoder": validation_metrics,
                "random_forest": forest.validation_metrics,
                "complementarity": validation_complementarity,
            },
            "february_test": {
                "evidence_label": (
                    "later_period_development_informed_previously_inspected_benchmark"
                ),
                "autoencoder": test_metrics,
                "random_forest": _read_json(
                    february_directory / "evaluation_report.json",
                    "february_report_unreadable",
                )["test"]["random_forest"],
                "complementarity": test_complementarity,
                "provenance": february_provenance,
            },
            "reload_verification": reload_evidence,
            "v2_reload_scoring_verification": v2_reload_scoring,
            "checks": {
                "configuration_frozen_before_training_or_scoring": True,
                "only_benign_train_rows_fit_weights": True,
                "validation_and_test_weight_fit_rows_zero": True,
                "preprocessing_reused_without_refit": True,
                "preprocessing_statistics_used_all_train_rows": True,
                "feature_order_and_split_identities_verified": True,
                "model_state_dict_only_and_weights_only_reload": True,
                "reload_exact_in_locked_cpu_environment": True,
                "per_record_scoring_independent_of_caller_batching": True,
                "source_snapshots_captured_before_training": True,
                "threshold_persisted_before_february_evaluation": True,
                "random_forest_verified_and_not_retrained": True,
                "cic_and_mordor_not_accessed": True,
                "automatic_fusion_not_enabled": True,
            },
            "timings_seconds": {
                "input_and_random_forest_verification": verification_seconds,
                "full_fit": fit.fit_seconds,
                "validation_calibration_evaluation_and_comparison": validation_seconds,
                "february_verification_evaluation_and_comparison": february_seconds,
                "total_runner": total_seconds,
            },
            "resources": {
                **resources,
                "peak_rss_bytes": max(fit.peak_rss_bytes, _peak_rss_bytes()),
                "peak_rss_measurement": "resource.getrusage(RUSAGE_SELF).ru_maxrss on Linux",
                "artifact_bytes_before_report": _artifact_bytes(run_directory),
                "cpu_only": True,
                "torch_intraop_threads": torch.get_num_threads(),
                "torch_interop_threads": torch.get_num_interop_threads(),
                "nested_classical_threads": 1,
            },
            "limitations": [
                "reconstruction error is not attack probability or calibrated confidence",
                "the 99th-percentile policy is development calibration, not an operational target",
                "January validation false positives are measured on threshold-calibration records",
                "February outcomes were previously inspected and are not independent evaluation",
                "exact feature collisions and conflicting labels remain in the frozen assignment",
                "near-duplicate leakage and capture/session provenance remain unresolved",
                "CIC remains unsupported and was not accessed",
                "additional detections do not authorize automatic fusion",
                "TF-008 and TF-009 remain open",
            ],
        }
        report_path = run_directory / REPORT_FILENAME
        _write_json(report_path, report)
        if _artifact_bytes(run_directory) > ARTIFACT_BUDGET_BYTES:
            raise NetworkAutoencoderError("artifact_budget_exceeded")
        return AutoencoderRunResult(run_directory, report_path, threshold, total_seconds)
    except Exception as exc:
        code = getattr(exc, "code", "internal_autoencoder_failure")
        _write_failure(run_directory, code)
        raise
