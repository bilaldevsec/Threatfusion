"""ThreatFusion Suricata Flow Adapter (Slide 14 Box 03).

Converts Suricata eve.json flow records from the victim VM sensor into the
exact 14 features required by the trained Random Forest inference pipeline,
binding an explicit EntityProvenanceContract.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from threatfusion.alerts.correlation_engine import EntityProvenanceContract
from threatfusion.datasets.adapters.base import (
    SourceRowValidationError,
    mean_size,
    parse_required_timestamp,
    rate_per_second,
    required_int,
    required_ip,
    required_protocol,
    required_value,
)
from threatfusion.features.network_behavior import (
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
)
from threatfusion.schemas.flow import NetworkFlow

SURICATA_FLOW_ADAPTER_SCHEMA_VERSION = "suricata_flow_adapter_v1"
SURICATA_FLOW_SOURCE_REPRESENTATION = "azure.victim_vm.suricata.eve_flow.v1"
DEFAULT_SURICATA_SENSOR_NAMESPACE = "azure_victim_vm:sensor_suricata_01"


@dataclass(frozen=True, slots=True)
class SuricataFlowAdaptationResult:
    """Deterministic result of adapting a Suricata flow event into 14 features."""

    flow: NetworkFlow
    features_14: dict[str, float | int]
    raw_feature_mapping: dict[str, Any]
    provenance_contract: EntityProvenanceContract
    source_event_id: str

    @property
    def provenance(self) -> EntityProvenanceContract:
        return self.provenance_contract

    @property
    def raw_features(self) -> dict[str, Any]:
        return self.raw_feature_mapping

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_event_id": self.source_event_id,
            "source_representation": SURICATA_FLOW_SOURCE_REPRESENTATION,
            "features_14": self.features_14,
            "raw_feature_mapping": self.raw_feature_mapping,
            "flow": self.flow.model_dump(),
        }


class SuricataFlowAdapter:
    """Extracts and validates the 14 model features from Suricata eve.json flows."""

    def __init__(
        self,
        *,
        default_sensor_namespace: str = DEFAULT_SURICATA_SENSOR_NAMESPACE,
    ) -> None:
        self._default_sensor_namespace = default_sensor_namespace

    def adapt_flow_record(
        self,
        record: dict[str, Any],
        *,
        sensor_namespace: str | None = None,
        clock_synchronized: bool = True,
    ) -> SuricataFlowAdaptationResult:
        """Alias for adapt_eve_flow_record."""
        return self.adapt_eve_flow_record(
            record,
            sensor_namespace=sensor_namespace,
            clock_synchronized=clock_synchronized,
        )

    def adapt_eve_flow_record(
        self,
        record: dict[str, Any],
        *,
        sensor_namespace: str | None = None,
        clock_synchronized: bool = True,
    ) -> SuricataFlowAdaptationResult:
        """Parse one Suricata eve.json (event_type == 'flow') record.

        Extracts the 10 numeric features and 4 one-hot protocol indicators,
        and binds an EntityProvenanceContract for correlation.
        """
        source = "SuricataFlow"
        if not isinstance(record, dict):
            raise SourceRowValidationError(source, "record", "must be a JSON dictionary")

        event_type = record.get("event_type")
        if event_type != "flow":
            raise SourceRowValidationError(
                source, "event_type", f"must be 'flow', got {event_type!r}"
            )

        flow_block = required_value(record, source, "flow")
        if not isinstance(flow_block, dict):
            raise SourceRowValidationError(source, "flow", "must be a dictionary")

        # Extract network flow endpoints
        src_ip = required_ip(record, source, "src_ip")
        dest_ip = required_ip(record, source, "dest_ip")
        src_port = required_int(record, source, "src_port", maximum=65535)
        dest_port = required_int(record, source, "dest_port", maximum=65535)
        proto_str = required_protocol(record, source, "proto")

        # Flow counters
        fwd_packets = required_int(flow_block, source, "pkts_toserver")
        bwd_packets = required_int(flow_block, source, "pkts_toclient")
        fwd_bytes = required_int(flow_block, source, "bytes_toserver")
        bwd_bytes = required_int(flow_block, source, "bytes_toclient")

        # Timestamps and duration
        start_raw = flow_block.get("start") or record.get("timestamp")
        end_raw = flow_block.get("end") or record.get("timestamp")
        if not start_raw:
            raise SourceRowValidationError(source, "flow.start", "missing start timestamp")
        if not end_raw:
            raise SourceRowValidationError(source, "flow.end", "missing end timestamp")

        start_dt = parse_required_timestamp(start_raw, source, "flow.start")
        end_dt = parse_required_timestamp(end_raw, source, "flow.end")
        if end_dt < start_dt:
            raise SourceRowValidationError(
                source, "flow.end", "end timestamp precedes start timestamp"
            )

        duration_sec = (end_dt - start_dt).total_seconds()
        duration_ms = duration_sec * 1000.0
        if duration_ms == 0.0 and "age" in flow_block:
            try:
                age_val = float(flow_block["age"])
                if age_val > 0.0:
                    duration_ms = age_val * 1000.0
            except (ValueError, TypeError):
                pass

        total_packets = fwd_packets + bwd_packets
        total_bytes = fwd_bytes + bwd_bytes

        # Rates and means
        pps = rate_per_second(total_packets, duration_ms)
        bps = rate_per_second(total_bytes, duration_ms)
        fwd_mean = mean_size(fwd_bytes, fwd_packets)
        bwd_mean = mean_size(bwd_bytes, bwd_packets)

        # Build validated canonical NetworkFlow
        flow_id = str(record.get("flow_id", f"{src_ip}:{src_port}-{dest_ip}:{dest_port}"))
        network_flow = NetworkFlow(
            source_dataset="live_sensor",
            flow_id=flow_id,
            timestamp_start=start_dt,
            timestamp_end=end_dt,
            src_ip=src_ip,
            dst_ip=dest_ip,
            src_port=src_port,
            dst_port=dest_port,
            protocol=proto_str,
            duration_ms=duration_ms,
            fwd_packets=fwd_packets,
            bwd_packets=bwd_packets,
            fwd_bytes=fwd_bytes,
            bwd_bytes=bwd_bytes,
            packets_per_second=pps,
            bytes_per_second=bps,
            fwd_packet_length_mean=fwd_mean,
            bwd_packet_length_mean=bwd_mean,
        )

        # Construct the exact 14 model features
        # 10 numeric features + 4 one-hot protocol indicators
        proto_tcp = 1.0 if proto_str == "tcp" else 0.0
        proto_udp = 1.0 if proto_str == "udp" else 0.0
        proto_icmp = 1.0 if proto_str == "icmp" else 0.0
        proto_other = 1.0 if proto_str == "other" else 0.0

        features_14: dict[str, float | int] = {
            "duration_ms": duration_ms,
            "fwd_packets": fwd_packets,
            "bwd_packets": bwd_packets,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "packets_per_second": pps,
            "bytes_per_second": bps,
            "fwd_packet_length_mean": fwd_mean,
            "bwd_packet_length_mean": bwd_mean,
            "dst_port": dest_port,
            "protocol_tcp": proto_tcp,
            "protocol_udp": proto_udp,
            "protocol_icmp": proto_icmp,
            "protocol_other": proto_other,
        }

        # Raw feature mapping for the inference preprocessor
        raw_feature_mapping: dict[str, Any] = {
            "duration_ms": duration_ms,
            "fwd_packets": fwd_packets,
            "bwd_packets": bwd_packets,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "packets_per_second": pps,
            "bytes_per_second": bps,
            "fwd_packet_length_mean": fwd_mean,
            "bwd_packet_length_mean": bwd_mean,
            "dst_port": dest_port,
            "protocol": proto_str,
        }

        # Assert all required network behavior fields are present
        assert set(raw_feature_mapping.keys()) == set(NETWORK_BEHAVIOR_V1_FEATURE_NAMES)

        # Generate deterministic source_event_id
        content_hasher = hashlib.sha256()
        content_hasher.update(
            f"{SURICATA_FLOW_SOURCE_REPRESENTATION}:{flow_id}:{start_dt.isoformat()}:{dest_port}".encode(
                "utf-8"
            )
        )
        source_event_id = f"suricata_flow_v1:{content_hasher.hexdigest()}"

        # Bind EntityProvenanceContract
        ns = sensor_namespace or self._default_sensor_namespace
        provenance = EntityProvenanceContract(
            entity_namespace_id=ns,
            clock_synchronized=clock_synchronized,
            src_entity_id=f"attacker:{src_ip}",
            dst_entity_id=f"victim:{dest_ip}",
            protocol=proto_str,
            service_or_port=str(dest_port),
            observed_at_utc=start_dt.isoformat(),
            validity_start_utc=start_dt.isoformat(),
            validity_end_utc=(end_dt + timedelta(minutes=10)).isoformat(),
            address_reuse_or_nat=False,
            max_clock_skew_seconds=0.0,
            source_mode="authorized_lab_sensor",
            clock_origin="azure_ntp_synchronized",
        )

        return SuricataFlowAdaptationResult(
            flow=network_flow,
            features_14=features_14,
            raw_feature_mapping=raw_feature_mapping,
            provenance_contract=provenance,
            source_event_id=source_event_id,
        )


__all__ = [
    "DEFAULT_SURICATA_SENSOR_NAMESPACE",
    "SURICATA_FLOW_ADAPTER_SCHEMA_VERSION",
    "SURICATA_FLOW_SOURCE_REPRESENTATION",
    "SuricataFlowAdaptationResult",
    "SuricataFlowAdapter",
]
