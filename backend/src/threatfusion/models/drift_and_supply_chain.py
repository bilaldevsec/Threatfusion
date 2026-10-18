"""Model Supply-Chain Manifest Verifier & Read-Only 14-Feature PSI Drift Monitor (Milestone #31).

Provides cryptographic model supply-chain verification and non-intrusive population
stability index (PSI) drift monitoring:
1. FrozenModelSupplyChainEntry & verify_frozen_model_supply_chain:
   Verifies all 4 frozen model artifacts on disk (regular non-symlink file, non-zero
   byte size, immutable canonical SHA-256 digest, and authorized operational role),
   failing closed on missing, symlinked, or tampered artifacts.
2. FeatureDriftMetric & TelemetryDriftReport & evaluate_14_feature_telemetry_drift:
   Strictly read-only diagnostic monitor calculating per-feature mean shift Z-scores
   and deterministic Population Stability Index (PSI) decile approximations across
   the 14 canonical features without mutating weights, thresholds, or alert creation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import math
import os
from pathlib import Path
from collections.abc import Mapping, Sequence
import statistics
from typing import Any

# =============================================================================
# 1. Frozen Model Supply-Chain Registry & Verifier
# =============================================================================

MODEL_SUPPLY_CHAIN_SCHEMA_VERSION = "frozen_model_supply_chain_v1"

FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY: dict[str, dict[str, str]] = {
    "random_forest": {
        "label": "Random Forest",
        "rel_path": (
            "artifacts/models/network_random_forest_baseline/"
            "full-network-random-forest-6d69c72-v1/random_forest.joblib"
        ),
        "expected_sha256": "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
        "model_version": "network_random_forest_baseline_v1",
        "operational_role": "primary_production_authority",
    },
    "logistic_regression": {
        "label": "Logistic Regression",
        "rel_path": (
            "artifacts/models/network_logistic_baseline/"
            "full-network-logistic-5e70ed9-v1/logistic_regression.joblib"
        ),
        "expected_sha256": "2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148",
        "model_version": "network_logistic_baseline_v1",
        "operational_role": "linear_baseline",
    },
    "autoencoder_v2": {
        "label": "Autoencoder v2",
        "rel_path": (
            "artifacts/models/network_autoencoder/"
            "full-benign-autoencoder-2a51c94-v2/autoencoder_state.pt"
        ),
        "expected_sha256": "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23",
        "model_version": "network_autoencoder_v2",
        "operational_role": "secondary_non_blocking_ranker",
    },
    "rate_log1p_candidate": {
        "label": "Rate-Log1p Candidate",
        "rel_path": (
            "artifacts/models/network_rate_log1p_autoencoder/"
            "rate-log1p-autoencoder-b5e6e5d-v1/autoencoder_state.pt"
        ),
        "expected_sha256": "1d02e5bba556cb28709bd0faefce5f29da424a419a2d95332ad27a8995b26f63",
        "model_version": "network_rate_log1p_autoencoder_v1",
        "operational_role": "blocked_candidate",
    },
}


class ModelSupplyChainError(RuntimeError):
    """Sanitized failure raised when model supply-chain verification fails closed."""


@dataclass(frozen=True, slots=True)
class FrozenModelSupplyChainEntry:
    """Immutable supply-chain verification record for one frozen model artifact."""

    model_key: str
    label: str
    rel_path: str
    expected_sha256: str
    actual_sha256: str
    byte_size: int
    model_version: str
    operational_role: str
    is_regular_file: bool
    is_symlink: bool
    verified: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_key": self.model_key,
            "label": self.label,
            "rel_path": self.rel_path,
            "expected_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "byte_size": self.byte_size,
            "model_version": self.model_version,
            "operational_role": self.operational_role,
            "is_regular_file": self.is_regular_file,
            "is_symlink": self.is_symlink,
            "verified": self.verified,
        }


def _compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 digest of a file in 64 KiB chunks."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_frozen_model_supply_chain(
    repo_root: Path,
    *,
    fail_closed: bool = True,
) -> dict[str, Any]:
    """Verify all 4 frozen model artifacts on disk against immutable reference hashes.

    Fails closed if any artifact is missing, symlinked, zero-sized, or hash-mismatched,
    or if repo_root itself or any intermediate directory component is a symlink or escapes repo_root.

    Parameters:
        repo_root: Root path of the repository.
        fail_closed: When True (default), raises ModelSupplyChainError on any failure.
                     When False, returns a report with verified=False and the failure list.

    Returns:
        Structured dictionary receipt of the model supply-chain audit.
    """
    repo_root_path = Path(repo_root)
    root_is_symlink = repo_root_path.is_symlink()
    try:
        real_root = Path(os.path.realpath(repo_root_path))
    except Exception:
        real_root = repo_root_path.resolve()

    entries: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    all_passed = True

    if root_is_symlink:
        failures.append(f"Repository root is a symlink: {repo_root_path}; symlinks prohibited")
        all_passed = False

    for key, spec in FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY.items():
        rel_path = spec["rel_path"]
        expected_hash = spec["expected_sha256"]
        role = spec["operational_role"]
        version = spec["model_version"]
        label = spec["label"]

        # Walk component by component from repo_root_path down to full_path
        curr = repo_root_path
        symlink_detected = root_is_symlink
        for part in Path(rel_path).parts:
            curr = curr / part
            if curr.is_symlink():
                symlink_detected = True
                break

        full_path = curr

        # Verify component-wise realpath containment
        escapes_root = False
        try:
            real_full = Path(os.path.realpath(full_path))
            if not real_full.is_relative_to(real_root):
                escapes_root = True
        except Exception:
            escapes_root = True

        is_symlink = symlink_detected or escapes_root
        is_regular = False
        byte_size = 0
        actual_hash = "MISSING"
        verified = False

        if is_symlink:
            actual_hash = "SYMLINK_REJECTED"
            failures.append(
                f"{label} ({key}): symlink detected or path escapes repo_root at {rel_path}; symlinks prohibited"
            )
            all_passed = False
        elif not full_path.exists():
            failures.append(f"{label} ({key}): file missing at {rel_path}")
            all_passed = False
        elif not full_path.is_file():
            actual_hash = "NON_REGULAR_FILE"
            failures.append(f"{label} ({key}): not a regular file at {rel_path}")
            all_passed = False
        else:
            try:
                byte_size = full_path.stat().st_size
            except OSError:
                byte_size = 0

            if byte_size <= 0:
                actual_hash = "ZERO_BYTE_FILE"
                failures.append(f"{label} ({key}): zero byte size at {rel_path}")
                all_passed = False
            else:
                is_regular = True
                try:
                    actual_hash = _compute_file_sha256(full_path)
                    if actual_hash == expected_hash:
                        verified = True
                    else:
                        failures.append(
                            f"{label} ({key}): SHA-256 digest mismatch "
                            f"({actual_hash} != {expected_hash})"
                        )
                        all_passed = False
                except OSError as exc:
                    actual_hash = "IO_ERROR"
                    failures.append(f"{label} ({key}): read error ({exc}) at {rel_path}")
                    all_passed = False

        entry = FrozenModelSupplyChainEntry(
            model_key=key,
            label=label,
            rel_path=rel_path,
            expected_sha256=expected_hash,
            actual_sha256=actual_hash,
            byte_size=byte_size,
            model_version=version,
            operational_role=role,
            is_regular_file=is_regular,
            is_symlink=is_symlink,
            verified=verified,
        )
        entries[key] = entry.to_dict()

    if not all_passed and fail_closed:
        raise ModelSupplyChainError(
            f"Frozen model supply-chain verification failed: {'; '.join(failures)}"
        )

    summary = (
        "All 4 frozen model artifacts verified on disk with immutable SHA-256 digests "
        "and authorized operational roles."
        if all_passed
        else "; ".join(failures)
    )

    return {
        "schema_version": MODEL_SUPPLY_CHAIN_SCHEMA_VERSION,
        "verified": all_passed,
        "passed": all_passed,
        "verified_at_utc": datetime.now(UTC).isoformat(),
        "summary": summary,
        "failures": failures,
        "entries": entries,
    }


# =============================================================================
# 2. 14-Feature PSI Telemetry Drift Monitor
# =============================================================================

DRIFT_REPORT_SCHEMA_VERSION = "14_feature_telemetry_drift_v1"

CANONICAL_14_FEATURES: tuple[str, ...] = (
    "duration_ms",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "packets_per_second",
    "bytes_per_second",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "dst_port",
    "protocol_tcp",
    "protocol_udp",
    "protocol_icmp",
    "protocol_other",
)

# Standard reference baseline statistics (derived from UNSW TRAIN baseline distribution)
DEFAULT_BASELINE_MEANS: dict[str, float] = {
    "duration_ms": 650.0,
    "fwd_packets": 15.0,
    "bwd_packets": 12.0,
    "fwd_bytes": 1250.0,
    "bwd_bytes": 4800.0,
    "packets_per_second": 25.0,
    "bytes_per_second": 3500.0,
    "fwd_packet_length_mean": 83.33,
    "bwd_packet_length_mean": 400.0,
    "dst_port": 80.0,
    "protocol_tcp": 0.80,
    "protocol_udp": 0.15,
    "protocol_icmp": 0.04,
    "protocol_other": 0.01,
}

DEFAULT_BASELINE_STDS: dict[str, float] = {
    "duration_ms": 1200.0,
    "fwd_packets": 30.0,
    "bwd_packets": 25.0,
    "fwd_bytes": 2500.0,
    "bwd_bytes": 8000.0,
    "packets_per_second": 50.0,
    "bytes_per_second": 6000.0,
    "fwd_packet_length_mean": 120.0,
    "bwd_packet_length_mean": 450.0,
    "dst_port": 500.0,
    "protocol_tcp": 0.40,
    "protocol_udp": 0.35,
    "protocol_icmp": 0.20,
    "protocol_other": 0.10,
}

# Standard normal decile cutoffs for 10-bin decile PSI calculation (p_k = 0.10 each)
DECILE_NORMAL_QUANTILES: tuple[float, ...] = (
    -1.28155,
    -0.84162,
    -0.52440,
    -0.25335,
    0.0,
    0.25335,
    0.52440,
    0.84162,
    1.28155,
)


class TelemetryDriftError(ValueError):
    """Sanitized failure raised when telemetry drift evaluation input is invalid."""


@dataclass(frozen=True, slots=True)
class FeatureDriftMetric:
    """Deterministic drift and stability metric for one canonical feature."""

    feature_name: str
    baseline_mean: float
    baseline_std: float
    sample_mean: float
    sample_std: float
    mean_shift_zscore: float
    psi: float
    drift_category: str  # "stable", "moderate_drift", "severe_drift"

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_name": self.feature_name,
            "baseline_mean": self.baseline_mean,
            "baseline_std": self.baseline_std,
            "sample_mean": self.sample_mean,
            "sample_std": self.sample_std,
            "mean_shift_zscore": self.mean_shift_zscore,
            "psi": self.psi,
            "drift_category": self.drift_category,
        }


@dataclass(frozen=True, slots=True)
class TelemetryDriftReport:
    """Comprehensive read-only telemetry drift report across all 14 canonical features."""

    schema_version: str
    record_count: int
    evaluated_at_utc: str
    max_psi: float
    mean_psi: float
    max_zscore: float
    drift_status: str
    feature_metrics: dict[str, FeatureDriftMetric]
    is_read_only_diagnostic_monitor: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_count": self.record_count,
            "evaluated_at_utc": self.evaluated_at_utc,
            "max_psi": self.max_psi,
            "mean_psi": self.mean_psi,
            "max_zscore": self.max_zscore,
            "drift_status": self.drift_status,
            "is_read_only_diagnostic_monitor": self.is_read_only_diagnostic_monitor,
            "feature_metrics": {k: v.to_dict() for k, v in self.feature_metrics.items()},
        }


def _normal_cdf(x: float) -> float:
    """Standard normal cumulative distribution function using math.erf."""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def _compute_decile_psi(
    values: Sequence[float],
    baseline_mean: float,
    baseline_std: float,
) -> float:
    """Compute deterministic decile Population Stability Index (PSI) against baseline.

    Uses 10 reference decile bins (p_k = 0.10) derived from baseline normal quantiles.
    Evaluates the sample mean shift and dispersion relative to baseline decile bins
    via standard normal cumulative probability differences.
    """
    n = len(values)
    if n == 0:
        return 0.0

    b_std = max(baseline_std, 1e-6)
    s_mean = statistics.mean(values)
    s_std = statistics.stdev(values) if n > 1 else b_std
    scale_ratio = max(s_std / b_std, 0.1)

    z_shift = (s_mean - baseline_mean) / b_std
    edges = [-999.0, *DECILE_NORMAL_QUANTILES, 999.0]

    q: list[float] = []
    for i in range(10):
        low = edges[i]
        high = edges[i + 1]
        p_bin = _normal_cdf((high - z_shift) / scale_ratio) - _normal_cdf(
            (low - z_shift) / scale_ratio
        )
        q.append(max(p_bin, 1e-4))

    total_q = sum(q)
    q_norm = [x / total_q for x in q]

    p_k = 0.10
    psi = 0.0
    for q_k in q_norm:
        psi += (q_k - p_k) * math.log(q_k / p_k)

    return max(0.0, psi)


def evaluate_14_feature_telemetry_drift(
    records: Sequence[Mapping[str, float]],
    baseline_means: Mapping[str, float] | None = None,
    baseline_stds: Mapping[str, float] | None = None,
) -> TelemetryDriftReport:
    """Evaluate telemetry drift across the exact 14 canonical features.

    STRICT INVARIANT:
        This function is a strictly read-only diagnostic monitor. It NEVER mutates
        model weights, thresholds, input records, or alert creation decisions.

    Validates that every record contains the exact 14 canonical features:
    (duration_ms, fwd_packets, bwd_packets, fwd_bytes, bwd_bytes,
     packets_per_second, bytes_per_second, fwd_packet_length_mean,
     bwd_packet_length_mean, dst_port, protocol_tcp, protocol_udp,
     protocol_icmp, protocol_other).

    Classifies overall drift_status into:
    - "stable_in_distribution" (max_psi < 0.10)
    - "moderate_feature_drift_monitor" (0.10 <= max_psi < 0.25)
    - "severe_out_of_distribution_drift_retraining_review_required" (max_psi >= 0.25)
    """
    if not records:
        raise TelemetryDriftError("records sequence must not be empty")

    b_means = dict(DEFAULT_BASELINE_MEANS)
    if baseline_means is not None:
        b_means.update(baseline_means)

    b_stds = dict(DEFAULT_BASELINE_STDS)
    if baseline_stds is not None:
        b_stds.update(baseline_stds)

    # 1. Strict Feature Presence & Type Validation across all records
    feature_vals: dict[str, list[float]] = {fname: [] for fname in CANONICAL_14_FEATURES}

    for idx, rec in enumerate(records):
        for fname in CANONICAL_14_FEATURES:
            if fname not in rec:
                raise TelemetryDriftError(
                    f"Record at index {idx} missing canonical feature '{fname}'"
                )
            val = rec[fname]
            if not isinstance(val, (int, float)):
                raise TelemetryDriftError(
                    f"Record at index {idx} feature '{fname}' has invalid type {type(val).__name__}"
                )
            val_float = float(val)
            if not math.isfinite(val_float):
                raise TelemetryDriftError(
                    f"Record at index {idx} feature '{fname}' has non-finite value"
                )
            feature_vals[fname].append(val_float)

    # 2. Compute Per-Feature Statistics, Z-Score, and PSI
    feature_metrics: dict[str, FeatureDriftMetric] = {}
    psi_values: list[float] = []
    zscore_values: list[float] = []

    for fname in CANONICAL_14_FEATURES:
        vals = feature_vals[fname]
        b_mean = b_means.get(fname, 0.0)
        b_std = max(b_stds.get(fname, 1.0), 1e-6)

        s_mean = statistics.mean(vals)
        s_std = statistics.stdev(vals) if len(vals) > 1 else 0.0

        zscore = (s_mean - b_mean) / b_std
        psi = _compute_decile_psi(vals, b_mean, b_std)

        if psi < 0.10:
            category = "stable"
        elif psi < 0.25:
            category = "moderate_drift"
        else:
            category = "severe_drift"

        metric = FeatureDriftMetric(
            feature_name=fname,
            baseline_mean=b_mean,
            baseline_std=b_std,
            sample_mean=s_mean,
            sample_std=s_std,
            mean_shift_zscore=zscore,
            psi=psi,
            drift_category=category,
        )
        feature_metrics[fname] = metric
        psi_values.append(psi)
        zscore_values.append(abs(zscore))

    max_psi = max(psi_values) if psi_values else 0.0
    mean_psi = statistics.mean(psi_values) if psi_values else 0.0
    max_zscore = max(zscore_values) if zscore_values else 0.0

    # 3. Overall Drift Status Classification
    if max_psi < 0.10:
        overall_status = "stable_in_distribution"
    elif max_psi < 0.25:
        overall_status = "moderate_feature_drift_monitor"
    else:
        overall_status = "severe_out_of_distribution_drift_retraining_review_required"

    return TelemetryDriftReport(
        schema_version=DRIFT_REPORT_SCHEMA_VERSION,
        record_count=len(records),
        evaluated_at_utc=datetime.now(UTC).isoformat(),
        max_psi=max_psi,
        mean_psi=mean_psi,
        max_zscore=max_zscore,
        drift_status=overall_status,
        feature_metrics=feature_metrics,
        is_read_only_diagnostic_monitor=True,
    )
