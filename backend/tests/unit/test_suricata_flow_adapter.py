"""Unit tests for SuricataFlowAdapter (Slide 14 Box 03).

Verifies conversion of Suricata eve.json flow records into the 14 features
required by the trained Random Forest pipeline and binding of EntityProvenanceContract.
"""

from __future__ import annotations

import pytest

from threatfusion.datasets.adapters.base import SourceRowValidationError
from threatfusion.datasets.adapters.suricata_flow import (
    DEFAULT_SURICATA_SENSOR_NAMESPACE,
    SURICATA_FLOW_SOURCE_REPRESENTATION,
    SuricataFlowAdapter,
    SuricataFlowAdaptationResult,
)


def _valid_eve_record(proto: str = "TCP") -> dict[str, object]:
    return {
        "timestamp": "2026-10-15T12:00:00.000000+00:00",
        "flow_id": 987654321012345,
        "event_type": "flow",
        "src_ip": "10.0.0.4",
        "src_port": 44120,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "proto": proto,
        "app_proto": "http",
        "flow": {
            "pkts_toserver": 12,
            "pkts_toclient": 10,
            "bytes_toserver": 1240,
            "bytes_toclient": 8560,
            "start": "2026-10-15T12:00:00.000000+00:00",
            "end": "2026-10-15T12:00:01.500000+00:00",
            "age": 1.5,
            "state": "closed",
            "reason": "shutdown",
        },
    }


def test_suricata_flow_adapter_happy_path() -> None:
    adapter = SuricataFlowAdapter()
    record = _valid_eve_record("TCP")
    result = adapter.adapt_eve_flow_record(record)

    assert isinstance(result, SuricataFlowAdaptationResult)
    assert result.source_event_id.startswith("suricata_flow_v1:")
    assert len(result.features_14) == 14
    CANONICAL_14_FEATURES = [
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
    ]
    for name in CANONICAL_14_FEATURES:
        assert name in result.features_14

    feats = result.features_14
    assert feats["duration_ms"] == 1500.0
    assert feats["fwd_packets"] == 12
    assert feats["bwd_packets"] == 10
    assert feats["fwd_bytes"] == 1240
    assert feats["bwd_bytes"] == 8560
    assert feats["dst_port"] == 80
    assert feats["protocol_tcp"] == 1
    assert feats["protocol_udp"] == 0
    assert feats["protocol_icmp"] == 0
    assert feats["protocol_other"] == 0

    # Rate and mean checks
    # 22 packets / 1.5s = 14.6666...
    assert pytest.approx(feats["packets_per_second"], 0.01) == 22.0 / 1.5
    # 9800 bytes / 1.5s = 6533.333...
    assert pytest.approx(feats["bytes_per_second"], 0.01) == 9800.0 / 1.5
    # Means
    assert pytest.approx(feats["fwd_packet_length_mean"], 0.01) == 1240.0 / 12.0
    assert pytest.approx(feats["bwd_packet_length_mean"], 0.01) == 8560.0 / 10.0

    # Provenance Contract
    contract = result.provenance_contract
    assert contract.is_verified()
    assert contract.entity_namespace_id == DEFAULT_SURICATA_SENSOR_NAMESPACE
    assert contract.src_entity_id == "attacker:10.0.0.4"
    assert contract.dst_entity_id == "victim:10.0.0.5"
    assert contract.src_ip == "10.0.0.4"
    assert contract.dst_ip == "10.0.0.5"
    assert contract.clock_synchronized is True

    # Serialization
    d = result.to_dict()
    assert d["source_representation"] == SURICATA_FLOW_SOURCE_REPRESENTATION
    assert d["features_14"] == feats
    assert str(d["flow"]["src_ip"]) == "10.0.0.4"


def test_suricata_flow_adapter_protocols() -> None:
    adapter = SuricataFlowAdapter()

    # UDP
    res_udp = adapter.adapt_flow_record(_valid_eve_record("UDP"))
    assert res_udp.features_14["protocol_tcp"] == 0
    assert res_udp.features_14["protocol_udp"] == 1
    assert res_udp.features_14["protocol_icmp"] == 0
    assert res_udp.features_14["protocol_other"] == 0

    # ICMP
    res_icmp = adapter.adapt_flow_record(_valid_eve_record("ICMP"))
    assert res_icmp.features_14["protocol_tcp"] == 0
    assert res_icmp.features_14["protocol_udp"] == 0
    assert res_icmp.features_14["protocol_icmp"] == 1
    assert res_icmp.features_14["protocol_other"] == 0

    # Other (e.g. GRE / SCTP / ESP)
    res_other = adapter.adapt_flow_record(_valid_eve_record("GRE"))
    assert res_other.features_14["protocol_tcp"] == 0
    assert res_other.features_14["protocol_udp"] == 0
    assert res_other.features_14["protocol_icmp"] == 0
    assert res_other.features_14["protocol_other"] == 1


def test_suricata_flow_adapter_zero_duration_age_fallback() -> None:
    adapter = SuricataFlowAdapter()
    rec = _valid_eve_record("TCP")
    rec["flow"]["start"] = "2026-10-15T12:00:00.000000+00:00"
    rec["flow"]["end"] = "2026-10-15T12:00:00.000000+00:00"
    rec["flow"]["age"] = 2.4

    result = adapter.adapt_flow_record(rec)
    assert result.features_14["duration_ms"] == 2400.0


def test_suricata_flow_adapter_custom_sensor_namespace() -> None:
    custom_ns = "azure_custom_region:sensor_suricata_09"
    adapter = SuricataFlowAdapter(default_sensor_namespace=custom_ns)
    rec = _valid_eve_record("TCP")
    res = adapter.adapt_flow_record(rec)
    assert res.provenance_contract.entity_namespace_id == custom_ns

    # Override at call site
    call_ns = "azure_override_ns:sensor_override"
    res2 = adapter.adapt_flow_record(rec, sensor_namespace=call_ns)
    assert res2.provenance_contract.entity_namespace_id == call_ns


def test_suricata_flow_adapter_validation_failures() -> None:
    adapter = SuricataFlowAdapter()

    # Non-dict record
    with pytest.raises(SourceRowValidationError, match="must be a JSON dictionary"):
        adapter.adapt_flow_record("not a dict")  # type: ignore[arg-type]

    # Non-flow event_type
    bad_type = _valid_eve_record("TCP")
    bad_type["event_type"] = "alert"
    with pytest.raises(SourceRowValidationError, match="must be 'flow'"):
        adapter.adapt_flow_record(bad_type)

    # Missing flow dictionary
    no_flow = _valid_eve_record("TCP")
    del no_flow["flow"]
    with pytest.raises(SourceRowValidationError, match="required value is missing"):
        adapter.adapt_flow_record(no_flow)

    # End timestamp precedes start timestamp
    bad_times = _valid_eve_record("TCP")
    bad_times["flow"]["start"] = "2026-10-15T12:00:05.000000+00:00"
    bad_times["flow"]["end"] = "2026-10-15T12:00:01.000000+00:00"
    with pytest.raises(SourceRowValidationError, match="end timestamp precedes start timestamp"):
        adapter.adapt_flow_record(bad_times)

    # Malformed IP
    bad_ip = _valid_eve_record("TCP")
    bad_ip["src_ip"] = "999.999.999.999"
    with pytest.raises(SourceRowValidationError, match="must be a valid IP address"):
        adapter.adapt_flow_record(bad_ip)

    # Negative packet count
    bad_pkts = _valid_eve_record("TCP")
    bad_pkts["flow"]["pkts_toserver"] = -1
    with pytest.raises(SourceRowValidationError, match="must be >= 0"):
        adapter.adapt_flow_record(bad_pkts)
