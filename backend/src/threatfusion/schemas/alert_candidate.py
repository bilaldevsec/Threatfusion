"""Versioned, privacy-minimized actionable alert candidate contract."""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from threatfusion.features.network_behavior import (
    NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
    UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
)

ALERT_CANDIDATE_SCHEMA_VERSION = "alert_candidate_v1"
SOURCE_EVENT_ID_SCHEMA_VERSION = "unsw_registered_source_event_v1"
DETECTOR_IDENTITY = "threatfusion.unsw_network_classifier"
DETECTOR_VERSION = "v1"
DECISION_POLICY_VERSION = "attack_probability_gte_0.5_v1"
_MODEL_VERSIONS = {
    "random_forest": "network_random_forest_baseline_v1",
    "logistic_regression": "network_logistic_baseline_v1",
}


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_source_event_id(value: object) -> bool:
    prefix = f"{SOURCE_EVENT_ID_SCHEMA_VERSION}:"
    return type(value) is str and value.startswith(prefix) and _is_sha256(value[len(prefix) :])


class AlertCandidateError(RuntimeError):
    """Sanitized contract error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _identity_digest(domain: str, parts: tuple[str, ...]) -> str:
    digest = hashlib.sha256(domain.encode("ascii") + b"\0")
    for part in parts:
        encoded = part.encode("utf-8")
        digest.update(struct.pack(">I", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()


def derive_source_event_id(
    *, source_representation: str, manifest_sha256: str, source_member_sha256: str, row_number: int
) -> str:
    """Identify one registered offline row without exposing its filename or values."""
    if (
        source_representation != UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1
        or not _is_sha256(manifest_sha256)
        or not _is_sha256(source_member_sha256)
        or type(row_number) is not int
        or row_number <= 0
    ):
        raise AlertCandidateError("source_event_identity_invalid")
    parts = (
        SOURCE_EVENT_ID_SCHEMA_VERSION,
        source_representation,
        manifest_sha256,
        source_member_sha256,
        str(row_number),
    )
    return (
        f"{SOURCE_EVENT_ID_SCHEMA_VERSION}:{_identity_digest('threatfusion:source-event', parts)}"
    )


def derive_alert_candidate_id(
    *,
    source_event_id: str,
    detector_identity: str,
    detector_version: str,
    model_identity: str,
    model_version: str,
    model_artifact_sha256: str,
    decision_policy_version: str,
) -> str:
    """Identify the stable event/detector/model/policy decision combination."""
    parts = (
        ALERT_CANDIDATE_SCHEMA_VERSION,
        source_event_id,
        detector_identity,
        detector_version,
        model_identity,
        model_version,
        model_artifact_sha256,
        decision_policy_version,
    )
    return f"{ALERT_CANDIDATE_SCHEMA_VERSION}:{_identity_digest('threatfusion:alert-candidate', parts)}"


def _is_plain_text(value: object, *, maximum: int = 256) -> bool:
    return type(value) is str and 0 < len(value) <= maximum


def _is_utc(value: object) -> bool:
    return (
        type(value) is datetime
        and value.tzinfo is not None
        and value.utcoffset() is not None
        and value.utcoffset().total_seconds() == 0
    )


@dataclass(frozen=True, slots=True, repr=False)
class AlertCandidate:
    """Immutable actionable Attack decision; raw evidence is deliberately absent."""

    schema_version: str
    alert_candidate_id: str
    source_event_id: str
    correlation_id: str
    detector_identity: str
    detector_version: str
    model_identity: str
    model_version: str
    model_artifact_sha256: str
    feature_contract_identity: str
    source_representation_identity: str
    observed_at: datetime
    created_at: datetime
    uncalibrated_model_score: float
    decision_threshold: float
    decision_policy_version: str
    decision: str
    inference_status: str
    reason: str

    def __repr__(self) -> str:
        """Avoid placing contract values in diagnostic representations."""
        return "<AlertCandidate>"

    def __post_init__(self) -> None:
        text_values = (
            self.alert_candidate_id,
            self.source_event_id,
            self.correlation_id,
            self.detector_identity,
            self.detector_version,
            self.model_identity,
            self.model_version,
            self.model_artifact_sha256,
            self.feature_contract_identity,
            self.source_representation_identity,
            self.decision_policy_version,
            self.reason,
        )
        if self.schema_version != ALERT_CANDIDATE_SCHEMA_VERSION or not all(
            _is_plain_text(value) for value in text_values
        ):
            raise AlertCandidateError("alert_candidate_invalid")
        if (
            self.detector_identity != DETECTOR_IDENTITY
            or self.detector_version != DETECTOR_VERSION
            or self.model_identity not in _MODEL_VERSIONS
            or self.model_version != _MODEL_VERSIONS.get(self.model_identity)
            or not _is_sha256(self.model_artifact_sha256)
            or self.feature_contract_identity != NETWORK_BEHAVIOR_V1_CONTRACT_VERSION
            or self.source_representation_identity != UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1
            or self.decision_policy_version != DECISION_POLICY_VERSION
            or not _is_source_event_id(self.source_event_id)
            or self.decision != "Attack"
            or self.inference_status != "completed"
            or self.reason != "inference_succeeded"
            or type(self.uncalibrated_model_score) is not float
            or not math.isfinite(self.uncalibrated_model_score)
            or not 0.0 <= self.uncalibrated_model_score <= 1.0
            or type(self.decision_threshold) is not float
            or not math.isfinite(self.decision_threshold)
            or not 0.0 <= self.decision_threshold <= 1.0
            or not _is_utc(self.observed_at)
            or not _is_utc(self.created_at)
        ):
            raise AlertCandidateError("alert_candidate_invalid")
        try:
            if str(UUID(self.correlation_id)) != self.correlation_id:
                raise ValueError
        except (ValueError, AttributeError):
            raise AlertCandidateError("alert_candidate_invalid") from None
        expected = derive_alert_candidate_id(
            source_event_id=self.source_event_id,
            detector_identity=self.detector_identity,
            detector_version=self.detector_version,
            model_identity=self.model_identity,
            model_version=self.model_version,
            model_artifact_sha256=self.model_artifact_sha256,
            decision_policy_version=self.decision_policy_version,
        )
        if self.alert_candidate_id != expected:
            raise AlertCandidateError("alert_candidate_identity_mismatch")

    def to_dict(self) -> dict[str, object]:
        """Return only the contract's deliberately stored, JSON-safe fields."""
        return {
            "schema_version": self.schema_version,
            "alert_candidate_id": self.alert_candidate_id,
            "source_event_id": self.source_event_id,
            "correlation_id": self.correlation_id,
            "detector_identity": self.detector_identity,
            "detector_version": self.detector_version,
            "model_identity": self.model_identity,
            "model_version": self.model_version,
            "model_artifact_sha256": self.model_artifact_sha256,
            "feature_contract_identity": self.feature_contract_identity,
            "source_representation_identity": self.source_representation_identity,
            "observed_at": self.observed_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "uncalibrated_model_score": self.uncalibrated_model_score,
            "decision_threshold": self.decision_threshold,
            "decision_policy_version": self.decision_policy_version,
            "decision": self.decision,
            "inference_status": self.inference_status,
            "reason": self.reason,
        }


def utc_now() -> datetime:
    """Create an aware UTC timestamp for first candidate creation."""
    return datetime.now(UTC)
