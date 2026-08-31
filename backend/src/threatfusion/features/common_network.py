from dataclasses import dataclass
from typing import Literal

FeatureDType = Literal["float", "integer", "category"]


@dataclass(frozen=True)
class FeatureSpec:
    """A single feature definition in the canonical network-flow contract."""

    name: str
    dtype: FeatureDType
    unit: str
    description: str
    required: bool = True


FLOW_COMMON_V1_FEATURES: tuple[FeatureSpec, ...] = (
    FeatureSpec(
        name="duration_ms",
        dtype="float",
        unit="milliseconds",
        description="Flow duration from first observed packet to last observed packet.",
    ),
    FeatureSpec(
        name="fwd_packets",
        dtype="integer",
        unit="count",
        description="Packets sent from source endpoint to destination endpoint.",
    ),
    FeatureSpec(
        name="bwd_packets",
        dtype="integer",
        unit="count",
        description="Packets sent from destination endpoint back to source endpoint.",
    ),
    FeatureSpec(
        name="fwd_bytes",
        dtype="integer",
        unit="bytes",
        description="Payload/packet bytes observed in the forward direction.",
    ),
    FeatureSpec(
        name="bwd_bytes",
        dtype="integer",
        unit="bytes",
        description="Payload/packet bytes observed in the backward direction.",
    ),
    FeatureSpec(
        name="packets_per_second",
        dtype="float",
        unit="packets/second",
        description="Total packet rate across both directions.",
    ),
    FeatureSpec(
        name="bytes_per_second",
        dtype="float",
        unit="bytes/second",
        description="Total byte rate across both directions.",
    ),
    FeatureSpec(
        name="fwd_packet_length_mean",
        dtype="float",
        unit="bytes",
        description="Average packet size in the forward direction.",
    ),
    FeatureSpec(
        name="bwd_packet_length_mean",
        dtype="float",
        unit="bytes",
        description="Average packet size in the backward direction.",
    ),
    FeatureSpec(
        name="src_port",
        dtype="integer",
        unit="port",
        description="Source transport port. ICMP and missing ports use zero.",
    ),
    FeatureSpec(
        name="dst_port",
        dtype="integer",
        unit="port",
        description="Destination transport port. ICMP and missing ports use zero.",
    ),
    FeatureSpec(
        name="protocol",
        dtype="category",
        unit="tcp/udp/icmp/other",
        description="Normalized protocol category.",
    ),
)


FLOW_COMMON_V1_FEATURE_NAMES: tuple[str, ...] = tuple(
    feature.name for feature in FLOW_COMMON_V1_FEATURES
)


MODEL_INPUT_FEATURE_NAMES: tuple[str, ...] = (
    "duration_ms",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "packets_per_second",
    "bytes_per_second",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "src_port",
    "dst_port",
    "protocol",
)


FORBIDDEN_MODEL_FEATURE_NAMES: frozenset[str] = frozenset(
    {
        "source_dataset",
        "label",
        "attack_category",
        "schema_version",
        "flow_id",
        "timestamp_start",
        "timestamp_end",
        "risk_score",
    }
)


def assert_no_forbidden_model_features(feature_names: list[str] | tuple[str, ...]) -> None:
    forbidden = FORBIDDEN_MODEL_FEATURE_NAMES.intersection(feature_names)
    if forbidden:
        names = ", ".join(sorted(forbidden))
        raise ValueError(f"Forbidden model feature(s): {names}")


def get_feature_names() -> tuple[str, ...]:
    return FLOW_COMMON_V1_FEATURE_NAMES
