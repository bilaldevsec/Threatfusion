from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from threatfusion.schemas.flow import NetworkFlow

UTC = timezone.utc


def valid_flow() -> dict:
    return {
        "source_dataset": "unsw_nb15",
        "flow_id": "flow-001",
        "timestamp_start": datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        "timestamp_end": datetime(2026, 1, 1, 12, 0, 1, tzinfo=UTC),
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.5",
        "src_port": 49152,
        "dst_port": 443,
        "protocol": "tcp",
        "duration_ms": 1000.0,
        "fwd_packets": 10,
        "bwd_packets": 8,
        "fwd_bytes": 1200,
        "bwd_bytes": 900,
        "packets_per_second": 18.0,
        "bytes_per_second": 2100.0,
        "fwd_packet_length_mean": 120.0,
        "bwd_packet_length_mean": 112.5,
        "label": "Attack",
        "attack_category": "Exploits",
    }


def test_valid_network_flow_schema() -> None:
    flow = NetworkFlow.model_validate(valid_flow())

    assert flow.schema_version == "flow_common_v1"
    assert flow.source_dataset == "unsw_nb15"
    assert flow.attack_category == "Exploits"


def test_rejects_invalid_time_order() -> None:
    data = valid_flow()
    data["timestamp_end"] = datetime(2026, 1, 1, 11, 59, 59, tzinfo=UTC)

    with pytest.raises(ValidationError):
        NetworkFlow.model_validate(data)


def test_rejects_invalid_bidirectional_bytes() -> None:
    data = valid_flow()
    data["bwd_packets"] = 0
    data["bwd_bytes"] = 900

    with pytest.raises(ValidationError):
        NetworkFlow.model_validate(data)


@pytest.mark.parametrize(
    "field_name",
    [
        "src_port",
        "dst_port",
        "duration_ms",
        "fwd_packets",
        "bwd_packets",
        "fwd_bytes",
        "bwd_bytes",
        "packets_per_second",
        "bytes_per_second",
        "fwd_packet_length_mean",
        "bwd_packet_length_mean",
    ],
)
@pytest.mark.parametrize("bad_bool", [True, False])
def test_rejects_booleans_on_all_numeric_fields(field_name: str, bad_bool: bool) -> None:
    data = valid_flow()
    data[field_name] = bad_bool

    with pytest.raises(ValidationError):
        NetworkFlow.model_validate(data)


@pytest.mark.parametrize(
    "field_name",
    [
        "duration_ms",
        "packets_per_second",
        "bytes_per_second",
        "fwd_packet_length_mean",
        "bwd_packet_length_mean",
    ],
)
@pytest.mark.parametrize("bad_float", [float("inf"), float("-inf"), float("nan"), "inf", "nan"])
def test_rejects_non_finite_float_fields(field_name: str, bad_float: object) -> None:
    data = valid_flow()
    data[field_name] = bad_float

    with pytest.raises(ValidationError):
        NetworkFlow.model_validate(data)
