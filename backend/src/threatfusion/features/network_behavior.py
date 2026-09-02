"""Portable model-input contract shared by complete flows and benchmarks."""

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

NETWORK_BEHAVIOR_V1_FORBIDDEN_MODEL_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "source_dataset",
        "source_file",
        "source_row_number",
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
