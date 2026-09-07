from datetime import UTC, datetime

import pytest

from threatfusion.features.host_behavior import (
    HOST_BEHAVIOR_V1_ALLOWED_MODEL_FIELDS,
    HOST_BEHAVIOR_V1_FEATURE_NAMES,
    HOST_BEHAVIOR_V1_PROHIBITED_MODEL_FIELDS,
    HostBehaviorAccumulator,
    assert_host_behavior_model_fields,
)
from threatfusion.features.network_behavior import (
    NETWORK_BEHAVIOR_V1_ALLOWED_MODEL_FIELDS,
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
    NETWORK_BEHAVIOR_V1_FORBIDDEN_MODEL_FIELDS,
    assert_network_behavior_model_fields,
)
from threatfusion.schemas.host_event import HostEvent


def test_cross_dataset_network_allowlist_is_exact_and_deterministic() -> None:
    expected = (
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
        "protocol",
    )

    assert NETWORK_BEHAVIOR_V1_FEATURE_NAMES == expected
    assert NETWORK_BEHAVIOR_V1_ALLOWED_MODEL_FIELDS == expected
    assert "src_port" not in expected
    assert "dst_port" not in NETWORK_BEHAVIOR_V1_FORBIDDEN_MODEL_FIELDS
    assert_network_behavior_model_fields(expected)


def test_host_behavior_allowlist_contains_only_derived_counts() -> None:
    assert HOST_BEHAVIOR_V1_ALLOWED_MODEL_FIELDS == HOST_BEHAVIOR_V1_FEATURE_NAMES
    assert HOST_BEHAVIOR_V1_FEATURE_NAMES == (
        "event_count",
        "process_event_count",
        "network_event_count",
        "authentication_event_count",
        "file_event_count",
        "registry_event_count",
        "privilege_event_count",
        "other_event_count",
        "provider_present_count",
        "process_name_present_count",
        "parent_process_name_present_count",
    )
    assert HOST_BEHAVIOR_V1_PROHIBITED_MODEL_FIELDS.isdisjoint(
        HOST_BEHAVIOR_V1_ALLOWED_MODEL_FIELDS
    )
    assert_host_behavior_model_fields(HOST_BEHAVIOR_V1_FEATURE_NAMES)


@pytest.mark.parametrize(
    "field",
    [
        "event_id",
        "__mordor_ingestion_id",
        "source_file",
        "filename",
        "source_row_number",
        "src_ip",
        "timestamp",
        "command_line",
        "user",
        "secret",
        "process_guid",
        "label",
        "attack_name",
    ],
)
def test_host_behavior_contract_rejects_identity_provenance_and_targets(field: str) -> None:
    with pytest.raises(ValueError, match="Forbidden host model field"):
        assert_host_behavior_model_fields((*HOST_BEHAVIOR_V1_FEATURE_NAMES, field))


def test_host_behavior_projection_uses_presence_and_coarse_type_counts_only() -> None:
    accumulator = HostBehaviorAccumulator()
    accumulator.include(
        HostEvent(
            source_dataset="mordor",
            event_id="fixture.json:1",
            timestamp=datetime(2020, 1, 1, tzinfo=UTC),
            host="sensitive-host",
            user="sensitive-user",
            event_type="process",
            provider="provider-value",
            process_name="process-value",
            command_line="secret command",
            src_ip="192.0.2.1",
            label="Attack",
        )
    )

    assert accumulator.project() == (1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0)
    assert not hasattr(accumulator, "events")
