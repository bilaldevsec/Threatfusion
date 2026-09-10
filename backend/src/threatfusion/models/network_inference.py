"""Fail-closed UNSW-specific inference boundary for frozen classical models."""

from __future__ import annotations

import json
import hashlib
import io
import math
import os
import stat
import time
import uuid
import csv
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from decimal import Decimal
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any

import joblib
import numpy as np
import yaml
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from threatfusion.datasets.adapters.unsw_nb15 import adapt_unsw_row
from threatfusion.datasets.unsw_raw import (
    UNSW_RAW_COLUMN_COUNT,
    map_unsw_raw_values,
    parse_unsw_feature_names,
)
from threatfusion.schemas.dataset_manifest import DatasetManifest
from threatfusion.schemas.flow import NetworkFlow
from threatfusion.schemas.alert_candidate import derive_source_event_id

from threatfusion.features.network_behavior import (
    NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
    UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
    UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1,
    NetworkCompatibilityError,
    NetworkCompatibilityKey,
    project_network_behavior,
    require_supported_network_compatibility,
)
from threatfusion.models.network_logistic_baseline import (
    ATTACK_THRESHOLD,
    attack_probabilities,
    _dependency_versions,
)
from threatfusion.preprocessing.network_behavior_v1 import (
    LABEL_MAPPING,
    PREPROCESSING_SCHEMA_VERSION,
    TRANSFORMED_FEATURE_NAMES,
    NetworkBehaviorPreprocessor,
    NetworkPreprocessingError,
)

INFERENCE_SCHEMA_VERSION = "unsw_network_inference_v1"
MAX_INFERENCE_BATCH_SIZE = 256
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024
PRIMARY_MODEL = "random_forest"
COMPARISON_MODEL = "logistic_regression"

APPROVED_PREPROCESSING_HASHES = {
    "state": "30c955e3931dc010f8b4391a80fc0fbeddd17e14260701c8131d88f95b06ee49",
    "configuration": "70273ec360e0bce88b5ec8311df4b5b8ccbbdbe6c456d8a679528563d477645a",
    "report": "d1688079b9cbcf521a8b9938ea07b540321e11edd70236452720fbd2f1697e4a",
}
APPROVED_UNSW_MANIFEST_HASH = "c6794cab5af9de5bf218989461b2ad673d1a14232688edf46aed1c63bc6e60e1"
APPROVED_MODEL_HASHES = {
    COMPARISON_MODEL: {
        "model": "2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148",
        "configuration": "f8ebe49fb4aaeee482c8f7e5eb509bc7d29cae92b2fbc6df72172e22a248217e",
        "report": "0afe787ccbea3a7f43f3ff69e43d642adaa5d5954039848cd7dfa168b4a85cc8",
    },
    PRIMARY_MODEL: {
        "model": "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
        "configuration": "fffe5e839c28b4e1d216c87ea1db7c675fa1a267ccf450c02869fe41e3bab13f",
        "report": "5e2c0c5e71e2c9d69b2beebd01a234a08f991a24edf90cc006fa3203fc5c3837",
    },
}


class NetworkModelChoice(StrEnum):
    """Explicitly selectable models; comparison is never an automatic fallback."""

    RANDOM_FOREST = PRIMARY_MODEL
    LOGISTIC_REGRESSION = COMPARISON_MODEL


class NetworkInferenceError(RuntimeError):
    """Sanitized boundary error that never includes input values or paths."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, repr=False)
class _NetworkSourceProvenance:
    """Internal pipeline assertion, not a credential or serialized input interface."""

    source_representation: str
    fitted_source_representation: str
    feature_contract_version: str
    model_preprocessing_requirements: str

    @classmethod
    def approved_unsw(cls) -> _NetworkSourceProvenance:
        return cls(
            source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
            fitted_source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
            feature_contract_version=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
            model_preprocessing_requirements=UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1,
        )

    def compatibility_key(self) -> NetworkCompatibilityKey:
        return NetworkCompatibilityKey(
            source_representation=self.source_representation,
            fitted_source_representation=self.fitted_source_representation,
            feature_contract_version=self.feature_contract_version,
            model_preprocessing_requirements=self.model_preprocessing_requirements,
        )


@dataclass(frozen=True, slots=True, repr=False)
class _NetworkInferenceRequest:
    """Immutable internal projection; never accepted by the public raw boundary."""

    provenance: _NetworkSourceProvenance | None
    feature_names: tuple[str, ...]
    feature_values: tuple[object, ...]

    @classmethod
    def from_mapping(
        cls,
        values: Mapping[str, object],
        *,
        provenance: _NetworkSourceProvenance | None,
    ) -> _NetworkInferenceRequest:
        # Only a bounded plain dict: arbitrary Mapping methods may execute caller code.
        if type(values) is not dict or len(values) != len(NETWORK_BEHAVIOR_V1_FEATURE_NAMES):
            raise NetworkInferenceError("feature_mapping_invalid")
        return cls(
            provenance=provenance,
            feature_names=tuple(values),
            feature_values=tuple(values.values()),
        )


@dataclass(frozen=True, slots=True)
class NetworkInferenceResult:
    """Sanitized result safe for an alert boundary."""

    correlation_id: str
    model_identity: str
    model_version: str
    contract_identity: str
    source_representation_identity: str
    attack_probability: float | None
    decision_threshold: float
    predicted_class: str | None
    status: str
    reason: str
    processed_at: str
    latency_ms: float

    def to_dict(self) -> dict[str, object]:
        return {
            "correlation_id": self.correlation_id,
            "model_identity": self.model_identity,
            "model_version": self.model_version,
            "contract_identity": self.contract_identity,
            "source_representation_identity": self.source_representation_identity,
            "attack_probability": self.attack_probability,
            "decision_threshold": self.decision_threshold,
            "predicted_class": self.predicted_class,
            "status": self.status,
            "reason": self.reason,
            "processed_at": self.processed_at,
            "latency_ms": self.latency_ms,
        }


@dataclass(frozen=True, slots=True)
class NetworkInferenceBatchResult:
    """Stable-order, bounded batch results with explicit accounting."""

    received: int
    succeeded: int
    rejected: int
    results: tuple[NetworkInferenceResult, ...]


@dataclass(frozen=True, slots=True, repr=False)
class RegisteredUnswInferenceResult:
    """Safe result bound to one verified registered offline source row."""

    source_event_id: str
    observed_at: datetime
    model_artifact_sha256: str
    inference: NetworkInferenceResult


@dataclass(frozen=True, slots=True)
class _FeatureRecord:
    duration_ms: float
    fwd_packets: int
    bwd_packets: int
    fwd_bytes: int
    bwd_bytes: int
    packets_per_second: float
    bytes_per_second: float
    fwd_packet_length_mean: float
    bwd_packet_length_mean: float
    dst_port: int
    protocol: str


@dataclass(frozen=True, slots=True)
class _LoadedModel:
    estimator: LogisticRegression | RandomForestClassifier
    identity: str
    version: str


@dataclass(frozen=True, slots=True, repr=False)
class _RegisteredUnswMember:
    path: Path
    sha256: str
    rows: int


@dataclass(frozen=True, slots=True, repr=False)
class _RegisteredUnswSource:
    manifest_sha256: str
    feature_names: tuple[str, ...]
    members_by_sha256: Mapping[str, _RegisteredUnswMember]


def _read_json(data: bytes, code: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeError, ValueError):
        raise NetworkInferenceError(code) from None
    if not isinstance(value, dict):
        raise NetworkInferenceError(code)
    return value


def _verified_bytes(path: Path, expected: str, code: str) -> bytes:
    """Bounded regular-file snapshot; hash and decode the SAME bytes, never reopen."""
    limit = MAX_ARTIFACT_BYTES if path.suffix == ".joblib" else MAX_JSON_BYTES
    try:
        # Linux single-node scope. Do not follow a leaf symlink or block on a FIFO.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise NetworkInferenceError(code)
            data = handle.read(limit + 1)
    except OSError:
        raise NetworkInferenceError(code) from None
    if len(data) > limit or hashlib.sha256(data).hexdigest() != expected:
        raise NetworkInferenceError(code)
    return data


def _preprocessing_snapshot(directory: Path) -> dict[str, bytes]:
    paths = {
        "state": directory / "preprocessor_state.json",
        "configuration": directory / "preprocessing_config.json",
        "report": directory / "preprocessing_report.json",
    }
    return {
        name: _verified_bytes(
            path, APPROVED_PREPROCESSING_HASHES[name], f"preprocessing_{name}_hash_mismatch"
        )
        for name, path in paths.items()
    }


def _verify_preprocessor(snapshot: dict[str, bytes]) -> NetworkBehaviorPreprocessor:
    configuration = _read_json(snapshot["configuration"], "preprocessing_configuration_unreadable")
    report = _read_json(snapshot["report"], "preprocessing_report_unreadable")
    source = configuration.get("source", {})
    hashes = report.get("hashes", {})
    if (
        configuration.get("schema_version") != PREPROCESSING_SCHEMA_VERSION
        or configuration.get("feature_contract") != NETWORK_BEHAVIOR_V1_CONTRACT_VERSION
        or configuration.get("input_feature_names") != list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES)
        or configuration.get("transformed_feature_names") != list(TRANSFORMED_FEATURE_NAMES)
        or configuration.get("label_mapping") != LABEL_MAPPING
        or source.get("manifest_sha256") != APPROVED_UNSW_MANIFEST_HASH
        or report.get("completed") is not True
        or hashes.get("fitted_state") != APPROVED_PREPROCESSING_HASHES["state"]
        or hashes.get("configuration") != APPROVED_PREPROCESSING_HASHES["configuration"]
    ):
        raise NetworkInferenceError("preprocessing_provenance_mismatch")
    try:
        return NetworkBehaviorPreprocessor.from_dict(
            _read_json(snapshot["state"], "preprocessing_state_invalid")
        )
    except NetworkPreprocessingError:
        raise NetworkInferenceError("preprocessing_state_invalid") from None


def _model_snapshot(directory: Path, choice: NetworkModelChoice) -> dict[str, bytes]:
    logistic = choice is NetworkModelChoice.LOGISTIC_REGRESSION
    filename = "logistic_regression.joblib" if logistic else "random_forest.joblib"
    paths = {
        "model": directory / filename,
        "configuration": directory / "model_config.json",
        "report": directory / "evaluation_report.json",
    }
    expected = APPROVED_MODEL_HASHES[choice.value]
    return {
        name: _verified_bytes(path, expected[name], f"{choice.value}_{name}_hash_mismatch")
        for name, path in paths.items()
    }


def _verify_model(snapshot: dict[str, bytes], choice: NetworkModelChoice) -> _LoadedModel:
    logistic = choice is NetworkModelChoice.LOGISTIC_REGRESSION
    expected_schema = (
        "network_logistic_baseline_v1" if logistic else "network_random_forest_baseline_v1"
    )
    expected = APPROVED_MODEL_HASHES[choice.value]
    configuration = _read_json(
        snapshot["configuration"], f"{choice.value}_configuration_unreadable"
    )
    report = _read_json(snapshot["report"], f"{choice.value}_report_unreadable")
    if configuration.get("dependencies") != _dependency_versions():
        raise NetworkInferenceError("artifact_runtime_version_mismatch")
    pre = configuration.get("preprocessing", {})
    decision = configuration.get("decision_threshold", {})
    model_evidence = report.get("model", {})
    if (
        configuration.get("schema_version") != expected_schema
        or configuration.get("label_mapping") != LABEL_MAPPING
        or pre.get("state_sha256") != APPROVED_PREPROCESSING_HASHES["state"]
        or pre.get("configuration_sha256") != APPROVED_PREPROCESSING_HASHES["configuration"]
        or pre.get("report_sha256") != APPROVED_PREPROCESSING_HASHES["report"]
        or pre.get("source_provenance", {}).get("manifest_sha256") != APPROVED_UNSW_MANIFEST_HASH
        or pre.get("transformed_feature_names") != list(TRANSFORMED_FEATURE_NAMES)
        or decision
        != {"operator": ">=", "positive_label": 1, "positive_name": "Attack", "probability": 0.5}
        or report.get("schema_version") != expected_schema
        or report.get("completed") is not True
        or report.get("configuration_sha256") != expected["configuration"]
        or model_evidence.get("sha256") != expected["model"]
        or model_evidence.get("classes") != [0, 1]
        or model_evidence.get("attack_probability_column") != 1
    ):
        raise NetworkInferenceError(f"{choice.value}_provenance_mismatch")
    try:
        estimator = joblib.load(io.BytesIO(snapshot["model"]))
    except Exception:
        raise NetworkInferenceError(f"{choice.value}_model_unreadable") from None
    expected_type = LogisticRegression if logistic else RandomForestClassifier
    if (
        not isinstance(estimator, expected_type)
        or estimator.classes_.dtype.kind not in "iu"
        or not np.array_equal(estimator.classes_, np.asarray([0, 1]))
        or estimator.n_features_in_ != len(TRANSFORMED_FEATURE_NAMES)
    ):
        raise NetworkInferenceError(f"{choice.value}_model_invalid")
    return _LoadedModel(estimator, choice.value, expected_schema)


def _feature_record(request: _NetworkInferenceRequest) -> _FeatureRecord:
    if (
        type(request.feature_names) is not tuple
        or len(request.feature_names) != len(NETWORK_BEHAVIOR_V1_FEATURE_NAMES)
        or any(type(name) is not str for name in request.feature_names)
        or request.feature_names != NETWORK_BEHAVIOR_V1_FEATURE_NAMES
    ):
        raise NetworkInferenceError("feature_order_mismatch")
    if type(request.feature_values) is not tuple or len(request.feature_values) != len(
        NETWORK_BEHAVIOR_V1_FEATURE_NAMES
    ):
        raise NetworkInferenceError("feature_value_count_mismatch")
    values = dict(zip(request.feature_names, request.feature_values, strict=True))
    numeric_names = NETWORK_BEHAVIOR_V1_FEATURE_NAMES[:-1]
    converted: dict[str, float] = {}
    for name in numeric_names:
        value = values[name]
        if type(value) not in (int, float):
            raise NetworkInferenceError("predictor_type_invalid")
        try:
            number = float(value)
        except OverflowError:
            raise NetworkInferenceError("numeric_predictor_out_of_range") from None
        if not math.isfinite(number):
            raise NetworkInferenceError("non_finite_predictor")
        if number < 0:
            raise NetworkInferenceError("negative_predictor")
        if type(value) is int and int(number) != value:
            raise NetworkInferenceError("numeric_predictor_precision_loss")
        converted[name] = number
    integer_names = ("fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "dst_port")
    if any(not converted[name].is_integer() for name in integer_names):
        raise NetworkInferenceError("integer_predictor_invalid")
    if converted["dst_port"] > 65535:
        raise NetworkInferenceError("destination_port_out_of_range")
    if converted["fwd_packets"] == 0 and converted["fwd_bytes"] > 0:
        raise NetworkInferenceError("forward_count_byte_inconsistent")
    if converted["bwd_packets"] == 0 and converted["bwd_bytes"] > 0:
        raise NetworkInferenceError("backward_count_byte_inconsistent")
    protocol = values["protocol"]
    if type(protocol) is not str:
        raise NetworkInferenceError("protocol_invalid")
    return _FeatureRecord(
        **{
            name: int(converted[name]) if name in integer_names else converted[name]
            for name in numeric_names
        },
        protocol=protocol,
    )


class _FrozenNetworkPredictor:
    """Trusted internal feature-level implementation, not an application entry point."""

    def __init__(
        self,
        *,
        preprocessing_directory: Path,
        logistic_directory: Path,
        random_forest_directory: Path,
    ) -> None:
        # All nine files must pass before any pickle deserialization, including the
        # explicitly non-fallback comparison model. Later replacements cannot change snapshots.
        preprocessing = _preprocessing_snapshot(preprocessing_directory)
        logistic = _model_snapshot(logistic_directory, NetworkModelChoice.LOGISTIC_REGRESSION)
        forest = _model_snapshot(random_forest_directory, NetworkModelChoice.RANDOM_FOREST)
        self._preprocessor = _verify_preprocessor(preprocessing)
        self._models = {
            NetworkModelChoice.LOGISTIC_REGRESSION: _verify_model(
                logistic, NetworkModelChoice.LOGISTIC_REGRESSION
            ),
            NetworkModelChoice.RANDOM_FOREST: _verify_model(
                forest, NetworkModelChoice.RANDOM_FOREST
            ),
        }

    def infer(
        self,
        request: _NetworkInferenceRequest,
        *,
        model: NetworkModelChoice = NetworkModelChoice.RANDOM_FOREST,
    ) -> NetworkInferenceResult:
        """Infer one record after compatibility and input validation."""
        started = time.perf_counter_ns()
        correlation_id = str(uuid.uuid4())
        if type(model) is not NetworkModelChoice:
            raise NetworkInferenceError("model_not_supported")
        loaded = self._models.get(model)
        if loaded is None:
            raise NetworkInferenceError("model_not_supported")
        source_identity = "unapproved"
        try:
            if type(request) is not _NetworkInferenceRequest:
                raise NetworkInferenceError("request_type_invalid")
            if request.provenance is None:
                raise NetworkInferenceError("provenance_missing")
            if type(request.provenance) is not _NetworkSourceProvenance:
                raise NetworkInferenceError("provenance_type_invalid")
            if any(
                type(value) is not str or len(value) > 256
                for value in (
                    request.provenance.source_representation,
                    request.provenance.fitted_source_representation,
                    request.provenance.feature_contract_version,
                    request.provenance.model_preprocessing_requirements,
                )
            ):
                raise NetworkInferenceError("provenance_type_invalid")
            try:
                require_supported_network_compatibility(request.provenance.compatibility_key())
            except NetworkCompatibilityError as exc:
                raise NetworkInferenceError(exc.code) from exc
            source_identity = UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1
            record = _feature_record(request)
            try:
                transformed = self._preprocessor.transform(record).reshape(1, -1)
            except Exception:
                raise NetworkInferenceError("transformation_failed") from None
            # sklearn's forest casts to float32. Reject overflow BEFORE predict_proba.
            if model is NetworkModelChoice.RANDOM_FOREST and np.any(
                np.abs(transformed) > np.finfo(np.float32).max
            ):
                raise NetworkInferenceError("model_input_out_of_range")
            try:
                score = float(attack_probabilities(loaded.estimator, transformed)[0])
            except Exception:
                raise NetworkInferenceError("model_prediction_failed") from None
            if not math.isfinite(score) or not 0.0 <= score <= 1.0:
                raise NetworkInferenceError("model_probability_invalid")
            predicted = "Attack" if score >= ATTACK_THRESHOLD else "Normal"
            status, reason = "completed", "inference_succeeded"
        except (NetworkInferenceError, NetworkPreprocessingError, ValueError) as exc:
            score = None
            predicted = None
            status = "rejected"
            reason = exc.code if hasattr(exc, "code") else "inference_failed"
        return NetworkInferenceResult(
            correlation_id=correlation_id,
            model_identity=loaded.identity,
            model_version=loaded.version,
            contract_identity=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
            source_representation_identity=source_identity,
            attack_probability=score,
            decision_threshold=ATTACK_THRESHOLD,
            predicted_class=predicted,
            status=status,
            reason=reason,
            processed_at=datetime.now(UTC).isoformat(),
            latency_ms=round((time.perf_counter_ns() - started) / 1_000_000, 6),
        )

    def infer_batch(
        self,
        requests: Iterable[_NetworkInferenceRequest],
        *,
        model: NetworkModelChoice = NetworkModelChoice.RANDOM_FOREST,
    ) -> NetworkInferenceBatchResult:
        """Consume at most 256 streamed records, preserving order and per-record failures."""
        if type(model) is not NetworkModelChoice:
            raise NetworkInferenceError("model_not_supported")
        bounded: list[_NetworkInferenceRequest] = []
        try:
            iterator = iter(requests)
            for _ in range(MAX_INFERENCE_BATCH_SIZE + 1):
                try:
                    request = next(iterator)
                except StopIteration:
                    break
                bounded.append(request)
        except Exception:
            raise NetworkInferenceError("batch_iteration_failed") from None
        if len(bounded) > MAX_INFERENCE_BATCH_SIZE:
            raise NetworkInferenceError("batch_size_exceeded")
        results = tuple(self.infer(request, model=model) for request in bounded)
        succeeded = sum(result.status == "completed" for result in results)
        return NetworkInferenceBatchResult(
            received=len(results),
            succeeded=succeeded,
            rejected=len(results) - succeeded,
            results=results,
        )

    @property
    def audit_provenance(self) -> dict[str, object]:
        """Return non-sensitive immutable identities for audit wiring."""
        return {
            "schema_version": INFERENCE_SCHEMA_VERSION,
            "source_representation": UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
            "feature_contract": NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
            "transformed_feature_names": list(TRANSFORMED_FEATURE_NAMES),
            "preprocessing_hashes": dict(APPROVED_PREPROCESSING_HASHES),
            "model_hashes": {name: dict(value) for name, value in APPROVED_MODEL_HASHES.items()},
            "primary_model": PRIMARY_MODEL,
            "comparison_model": COMPARISON_MODEL,
            "automatic_fallback": False,
            "maximum_batch_size": MAX_INFERENCE_BATCH_SIZE,
        }


def default_artifact_directories(project_root: Path) -> tuple[Path, Path, Path]:
    """Resolve the three immutable approved artifact directories."""
    return (
        project_root / "data/processed/unsw_network_preprocessing/full-train-only-0141bde-v1",
        project_root
        / "artifacts/models/network_logistic_baseline/full-network-logistic-5e70ed9-v1",
        project_root
        / "artifacts/models/network_random_forest_baseline/full-network-random-forest-6d69c72-v1",
    )


def _registered_unsw_source(project_root: Path) -> _RegisteredUnswSource:
    """Verify the pinned manifest/schema and retain its offline member identities."""
    try:
        manifest_bytes = _verified_bytes(
            project_root / "data/manifests/unsw_nb15.yaml",
            APPROVED_UNSW_MANIFEST_HASH,
            "unsw_manifest_invalid",
        )
        manifest = DatasetManifest.model_validate(yaml.safe_load(manifest_bytes))
        metadata = [
            item
            for item in manifest.files
            if item.role == "raw" and item.path.name == "NUSW-NB15_features.csv"
        ]
        if manifest.name != "unsw_nb15" or len(metadata) != 1 or metadata[0].rows != 49:
            raise ValueError
        entry = metadata[0]
        data = _verified_bytes(project_root / entry.path, entry.sha256, "unsw_schema_invalid")
        feature_names = parse_unsw_feature_names(data, path=Path("<registered-schema>"))
        members: dict[str, _RegisteredUnswMember] = {}
        for item in manifest.files:
            if item.role != "raw" or item.path.name == "NUSW-NB15_features.csv":
                continue
            if item.sha256 is None or item.rows is None or item.rows <= 0 or item.sha256 in members:
                raise ValueError
            members[item.sha256] = _RegisteredUnswMember(item.path, item.sha256, item.rows)
        if not members:
            raise ValueError
        return _RegisteredUnswSource(
            manifest_sha256=APPROVED_UNSW_MANIFEST_HASH,
            feature_names=feature_names,
            members_by_sha256=MappingProxyType(members),
        )
    except Exception:
        raise NetworkInferenceError("unsw_registration_invalid") from None


def _registered_unsw_schema(project_root: Path) -> tuple[str, ...]:
    """Retain the focused schema-verification helper used by security tests."""
    return _registered_unsw_source(project_root).feature_names


def _nonnegative_raw_float(text: str) -> float:
    """Check raw sign/finiteness before float conversion can erase a nonzero value."""
    number = Decimal(text)
    if not number.is_finite() or number < 0:
        raise ValueError
    converted = float(text)
    if not math.isfinite(converted) or (number != 0 and converted == 0):
        raise ValueError
    return converted


class UnswNetworkInferenceBoundary:
    """Supported application entry: registered UNSW raw columns to frozen inference.

    Setup arguments and code are trusted. Submission accepts only plain raw string
    lists, never requests, canonical objects, provenance declarations, or capabilities.
    This enforces adaptation, not remote measurement authenticity.
    """

    def __init__(self, *, project_root: Path) -> None:
        self._project_root = project_root.resolve()
        self._registered_source = _registered_unsw_source(self._project_root)
        self._raw_feature_names = self._registered_source.feature_names
        preprocessing, logistic, forest = default_artifact_directories(project_root)
        self._predictor = _FrozenNetworkPredictor(
            preprocessing_directory=preprocessing,
            logistic_directory=logistic,
            random_forest_directory=forest,
        )

    def _adapt_raw(self, raw_values: object) -> tuple[_NetworkInferenceRequest, datetime] | None:
        # Snapshot before advancing caller iteration. Only immutable plain strings
        # survive, with no caller-owned container retained in the internal request.
        if type(raw_values) is not list or len(raw_values) != UNSW_RAW_COLUMN_COUNT:
            return None
        values = tuple(raw_values)
        if any(type(value) is not str or len(value) > 1024 for value in values):
            return None
        try:
            row = map_unsw_raw_values(
                self._raw_feature_names,
                values,
                path=Path("<submission>"),
                row_number=1,
            )
            # Check integral values exactly before the legacy adapter's float
            # parsing, including the binary label needed for a valid raw event.
            for name in ("spkts", "dpkts", "sbytes", "dbytes", "label"):
                number = Decimal(row[name])
                if (
                    not number.is_finite()
                    or number < 0
                    or number > (1 if name == "label" else 2**53)
                    or number != number.to_integral_value()
                ):
                    return None
            duration = _nonnegative_raw_float(row["dur"])
            # Registered raw stime is numeric epoch seconds. Passing the parsed
            # UTC timestamp uses the existing adapter without its generic pandas
            # date fallback, whose warnings can echo untrusted timestamp text.
            start = datetime.fromtimestamp(_nonnegative_raw_float(row["stime"]), tz=UTC)
            flow = adapt_unsw_row(row | {"dur": duration, "stime": start})
            if (
                type(flow) is not NetworkFlow
                or flow.source_dataset != "unsw_nb15"
                or flow.schema_version != "flow_common_v1"
            ):
                return None
            return (
                _NetworkInferenceRequest(
                    provenance=_NetworkSourceProvenance.approved_unsw(),
                    feature_names=NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
                    feature_values=project_network_behavior(flow),
                ),
                flow.timestamp_start,
            )
        except Exception:
            # Adapter/Pydantic/numeric details can include endpoints or raw values.
            return None

    def _prepare(self, raw_values: object) -> _NetworkInferenceRequest | None:
        adapted = self._adapt_raw(raw_values)
        return adapted[0] if adapted is not None else None

    def _registered_row(self, member: _RegisteredUnswMember, row_number: int) -> list[str]:
        candidate = self._project_root / member.path
        parent = candidate.parent.resolve()
        if not parent.is_relative_to(self._project_root):
            raise NetworkInferenceError("registered_event_unavailable")
        path = parent / candidate.name
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as handle:
                initial = os.fstat(handle.fileno())
                if not stat.S_ISREG(initial.st_mode):
                    raise NetworkInferenceError("registered_event_unavailable")
                digest = hashlib.sha256()

                def verified_text_lines() -> Iterable[str]:
                    first = True
                    while raw_line := handle.readline():
                        digest.update(raw_line)
                        encoding = "utf-8-sig" if first else "utf-8"
                        first = False
                        yield raw_line.decode(encoding)

                selected: list[str] | None = None
                count = 0
                for count, values in enumerate(csv.reader(verified_text_lines()), start=1):
                    if count == row_number:
                        selected = list(values)
                after_parse = os.fstat(handle.fileno())
                stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if (
                    any(
                        getattr(initial, field) != getattr(after_parse, field)
                        for field in stable_fields
                    )
                    or digest.hexdigest() != member.sha256
                ):
                    raise NetworkInferenceError("registered_event_unavailable")
        except (OSError, UnicodeError, csv.Error):
            raise NetworkInferenceError("registered_event_unavailable") from None
        if count != member.rows or selected is None:
            raise NetworkInferenceError("registered_event_unavailable")
        return selected

    def infer_registered(
        self,
        *,
        source_member_sha256: str,
        row_number: int,
        model: NetworkModelChoice = NetworkModelChoice.RANDOM_FOREST,
    ) -> RegisteredUnswInferenceResult:
        """Verify, adapt and infer one registered offline UNSW source row."""
        if type(model) is not NetworkModelChoice:
            raise NetworkInferenceError("model_not_supported")
        if (
            type(source_member_sha256) is not str
            or len(source_member_sha256) != 64
            or any(character not in "0123456789abcdef" for character in source_member_sha256)
            or type(row_number) is not int
            or row_number <= 0
        ):
            raise NetworkInferenceError("registered_event_invalid")
        member = self._registered_source.members_by_sha256.get(source_member_sha256)
        if member is None or row_number > member.rows:
            raise NetworkInferenceError("registered_event_invalid")
        adapted = self._adapt_raw(self._registered_row(member, row_number))
        if adapted is None:
            raise NetworkInferenceError("registered_event_rejected")
        request, observed_at = adapted
        source_event_id = derive_source_event_id(
            source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
            manifest_sha256=self._registered_source.manifest_sha256,
            source_member_sha256=member.sha256,
            row_number=row_number,
        )
        result = self._predictor.infer(request, model=model)
        return RegisteredUnswInferenceResult(
            source_event_id=source_event_id,
            observed_at=observed_at,
            model_artifact_sha256=APPROVED_MODEL_HASHES[model.value]["model"],
            inference=result,
        )

    def infer(
        self,
        raw_values: object,
        *,
        model: NetworkModelChoice = NetworkModelChoice.RANDOM_FOREST,
    ) -> NetworkInferenceResult:
        """Adapt one raw 49-column string list and predict without an exposed envelope."""
        return self.infer_batch([raw_values], model=model).results[0]

    def infer_batch(
        self,
        raw_rows: Iterable[object],
        *,
        model: NetworkModelChoice = NetworkModelChoice.RANDOM_FOREST,
    ) -> NetworkInferenceBatchResult:
        """Snapshot/adapt at most 256 rows; iterator failure aborts before prediction."""
        if type(model) is not NetworkModelChoice:
            raise NetworkInferenceError("model_not_supported")
        prepared: list[_NetworkInferenceRequest | None] = []
        oversized = False
        try:
            iterator = iter(raw_rows)
            for index in range(MAX_INFERENCE_BATCH_SIZE + 1):
                try:
                    raw = next(iterator)
                except StopIteration:
                    break
                if index == MAX_INFERENCE_BATCH_SIZE:
                    oversized = True
                    break
                prepared.append(self._prepare(raw))
        except Exception:
            raise NetworkInferenceError("batch_iteration_failed") from None
        if oversized:
            raise NetworkInferenceError("batch_size_exceeded")
        results = tuple(
            (
                replace(self._predictor.infer(None, model=model), reason="raw_input_rejected")
                if request is None
                else self._predictor.infer(request, model=model)
            )
            for request in prepared
        )
        succeeded = sum(result.status == "completed" for result in results)
        return NetworkInferenceBatchResult(
            len(results), succeeded, len(results) - succeeded, results
        )

    @property
    def audit_provenance(self) -> dict[str, object]:
        return self._predictor.audit_provenance
