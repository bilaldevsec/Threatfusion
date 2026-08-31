from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from threatfusion.schemas.flow import NetworkFlow


def valid_flow() -> dict:
    return {
        "source_dataset": "unsw_nb15",
        "flow_id": "flow-001",
        "timestamp_start": datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "timestamp_end": datetime(2026, 1, 1, 12, 0, 1, tzinfo=timezone.utc),
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
    data["timestamp_end"] = datetime(2026, 1, 1, 11, 59, 59, tzinfo=timezone.utc)

    with pytest.raises(ValidationError):
        NetworkFlow.model_validate(data)


def test_rejects_invalid_bidirectional_bytes() -> None:
    data = valid_flow()
    data["bwd_packets"] = 0
    data["bwd_bytes"] = 900

    with pytest.raises(ValidationError):
        NetworkFlow.model_validate(data)
