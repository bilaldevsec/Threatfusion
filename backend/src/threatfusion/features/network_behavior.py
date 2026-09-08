"""Versioned network inputs and their narrowly scoped compatibility evidence."""

from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from threatfusion.features.common_network import FeatureSpec
from threatfusion.schemas.flow import NetworkFlow
from threatfusion.schemas.network_benchmark import NetworkBenchmarkRecord

NETWORK_BEHAVIOR_V1_FEATURES: tuple[FeatureSpec, ...] = (
    FeatureSpec("duration_ms", "float", "milliseconds", "Observed flow duration."),
    FeatureSpec("fwd_packets", "integer", "count", "Forward packet count."),
    FeatureSpec("bwd_packets", "integer", "count", "Backward packet count."),
    FeatureSpec("fwd_bytes", "integer", "bytes", "Forward byte count."),
    FeatureSpec("bwd_bytes", "integer", "bytes", "Backward byte count."),
    FeatureSpec("packets_per_second", "float", "packets/second", "Bidirectional packet rate."),
    FeatureSpec("bytes_per_second", "float", "bytes/second", "Bidirectional byte rate."),
    FeatureSpec("fwd_packet_length_mean", "float", "bytes", "Mean forward packet length."),
    FeatureSpec("bwd_packet_length_mean", "float", "bytes", "Mean backward packet length."),
    FeatureSpec("dst_port", "integer", "port", "Observed destination transport port."),
    FeatureSpec("protocol", "category", "tcp/udp/icmp/other", "Normalized protocol category."),
)

NETWORK_BEHAVIOR_V1_FEATURE_NAMES: tuple[str, ...] = tuple(
    feature.name for feature in NETWORK_BEHAVIOR_V1_FEATURES
)
NETWORK_BEHAVIOR_V1_CONTRACT_VERSION = "network_behavior_v1"

UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1 = "unsw_nb15.argus.raw_49.transaction_bytes.v1"
CIC_IDS2018_CICFLOWMETER_V3_PROCESSED_REPRESENTATION_V1 = (
    "cse_cic_ids2018.cicflowmeter_v3.processed_80.transport_payload_bytes.v1"
)
UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1 = (
    "unsw_train.network_behavior_v1_preprocessing_v1.14_columns.classical_binary.v1"
)
NETWORK_BEHAVIOR_V1_INCOMPATIBLE_BYTE_FEATURES: tuple[str, ...] = (
    "fwd_bytes",
    "bwd_bytes",
    "bytes_per_second",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
)
NETWORK_COMPATIBILITY_AUDIT_REFERENCE = (
    "docs/network_feature_comparability_audit.md#demonstrated-implementationmapping-defect"
)


class NetworkCompatibilityStatus(StrEnum):
    """Evidence disposition for one exact representation/requirements combination."""

    SUPPORTED_USE = "supported_use"
    DEMONSTRATED_INCOMPATIBILITY = "demonstrated_incompatibility"
    UNKNOWN_COMPATIBILITY = "unknown_compatibility"


@dataclass(frozen=True, slots=True)
class NetworkCompatibilityKey:
    """Actual input, fitted source, contract, and model/preprocessing requirement key."""

    source_representation: str | None
    fitted_source_representation: str | None
    feature_contract_version: str | None
    model_preprocessing_requirements: str | None


@dataclass(frozen=True, slots=True)
class NetworkCompatibilityDecision:
    """Machine-readable compatibility result kept separate from run completion."""

    key: NetworkCompatibilityKey
    status: NetworkCompatibilityStatus
    reason_codes: tuple[str, ...]
    affected_features: tuple[str, ...]
    evidence_reference: str

    @property
    def approved_for_inference(self) -> bool:
        return self.status is NetworkCompatibilityStatus.SUPPORTED_USE

    def to_dict(self) -> dict[str, object]:
        """Return a stable JSON-safe representation for reports and consumers."""
        return {
            "source_representation": self.key.source_representation,
            "fitted_source_representation": self.key.fitted_source_representation,
            "feature_contract_version": self.key.feature_contract_version,
            "model_preprocessing_requirements": self.key.model_preprocessing_requirements,
            "status": self.status.value,
            "approved_for_inference": self.approved_for_inference,
            "reason_codes": list(self.reason_codes),
            "affected_features": list(self.affected_features),
            "evidence_reference": self.evidence_reference,
        }


class NetworkCompatibilityError(RuntimeError):
    """Sanitized failure carrying the non-approved decision that caused it."""

    def __init__(self, decision: NetworkCompatibilityDecision) -> None:
        self.decision = decision
        self.code = decision.reason_codes[0]
        super().__init__(self.code)


def decide_network_compatibility(
    key: NetworkCompatibilityKey,
) -> NetworkCompatibilityDecision:
    """Decide only the two reviewed uses; every other key remains unapproved."""
    supported_key = NetworkCompatibilityKey(
        source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        fitted_source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        feature_contract_version=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
        model_preprocessing_requirements=UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1,
    )
    cic_key = NetworkCompatibilityKey(
        source_representation=CIC_IDS2018_CICFLOWMETER_V3_PROCESSED_REPRESENTATION_V1,
        fitted_source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        feature_contract_version=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
        model_preprocessing_requirements=UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1,
    )
    if key == supported_key:
        return NetworkCompatibilityDecision(
            key=key,
            status=NetworkCompatibilityStatus.SUPPORTED_USE,
            reason_codes=("same_verified_source_representation",),
            affected_features=(),
            evidence_reference="docs/network_preprocessing.md#input-and-leakage-boundary",
        )
    if key == cic_key:
        return NetworkCompatibilityDecision(
            key=key,
            status=NetworkCompatibilityStatus.DEMONSTRATED_INCOMPATIBILITY,
            reason_codes=("cross_source_byte_semantics_incompatible",),
            affected_features=NETWORK_BEHAVIOR_V1_INCOMPATIBLE_BYTE_FEATURES,
            evidence_reference=NETWORK_COMPATIBILITY_AUDIT_REFERENCE,
        )

    if None in (
        key.source_representation,
        key.fitted_source_representation,
        key.feature_contract_version,
        key.model_preprocessing_requirements,
    ):
        reason = "compatibility_evidence_missing"
    elif key.feature_contract_version != NETWORK_BEHAVIOR_V1_CONTRACT_VERSION:
        reason = "feature_contract_version_unrecognized"
    elif key.model_preprocessing_requirements != UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1:
        reason = "model_preprocessing_requirements_unrecognized"
    elif key.fitted_source_representation != UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1:
        reason = "fitted_source_representation_unrecognized"
    else:
        reason = "source_representation_unrecognized"
    return NetworkCompatibilityDecision(
        key=key,
        status=NetworkCompatibilityStatus.UNKNOWN_COMPATIBILITY,
        reason_codes=(reason,),
        affected_features=(),
        evidence_reference="docs/issue_register.md#threatfusion-prioritized-remediation-register",
    )


def require_supported_network_compatibility(
    key: NetworkCompatibilityKey,
) -> NetworkCompatibilityDecision:
    """Return reviewed support or fail closed for incompatible/unknown evidence."""
    decision = decide_network_compatibility(key)
    if not decision.approved_for_inference:
        raise NetworkCompatibilityError(decision)
    return decision


# This tuple and order are the complete predictor allowlist. Projection alone does not grant
# cross-source compatibility; callers must also enforce a NetworkCompatibilityDecision.
NETWORK_BEHAVIOR_V1_ALLOWED_MODEL_FIELDS = NETWORK_BEHAVIOR_V1_FEATURE_NAMES

NETWORK_BEHAVIOR_V1_FORBIDDEN_MODEL_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "source_dataset",
        "source_file",
        "filename",
        "source_row_number",
        "row_number",
        "source_timestamp",
        "flow_id",
        "timestamp_start",
        "timestamp_end",
        "src_ip",
        "dst_ip",
        "src_port",
        "label",
        "attack_category",
        "attack_name",
        "risk_score",
        "event_id",
        "record_id",
        "event_record_id",
        "ingestion_id",
        "__mordor_ingestion_id",
        "process_guid",
        "host",
        "user",
        "username",
        "command_line",
        "secret",
    }
)

NetworkBehaviorRecord: TypeAlias = NetworkFlow | NetworkBenchmarkRecord
NetworkBehaviorValue: TypeAlias = int | float | str


def assert_network_behavior_model_fields(feature_names: tuple[str, ...]) -> None:
    """Reject metadata and any deviation from the versioned predictor contract."""
    forbidden = NETWORK_BEHAVIOR_V1_FORBIDDEN_MODEL_FIELDS.intersection(feature_names)
    if forbidden:
        raise ValueError(f"Forbidden model field(s): {', '.join(sorted(forbidden))}")
    if feature_names != NETWORK_BEHAVIOR_V1_FEATURE_NAMES:
        raise ValueError("model fields must exactly match network_behavior_v1")


def project_network_behavior(record: NetworkBehaviorRecord) -> tuple[NetworkBehaviorValue, ...]:
    """Project a complete flow or feature-only benchmark into the exact model order."""
    return tuple(getattr(record, name) for name in NETWORK_BEHAVIOR_V1_FEATURE_NAMES)
