from typing import Any

from threatfusion.datasets.adapters.base import (
    end_timestamp,
    mean_size,
    parse_required_timestamp,
    rate_per_second,
    required_alias,
    required_float,
    required_int,
    required_ip,
    required_protocol,
    required_string,
)
from threatfusion.schemas.flow import NetworkFlow


def adapt_cic_row(row: dict[str, Any]) -> NetworkFlow:
    source = "CSE-CIC-IDS2018"
    duration_ms = required_float(row, source, "Flow Duration") / 1000.0

    fwd_packets = required_int(row, source, "Tot Fwd Pkts")
    bwd_packets = required_int(row, source, "Tot Bwd Pkts")
    fwd_bytes = required_int(row, source, "TotLen Fwd Pkts")
    bwd_bytes = required_int(row, source, "TotLen Bwd Pkts")

    start = parse_required_timestamp(row.get("Timestamp"), source, "Timestamp")
    end = end_timestamp(start, duration_ms)

    label_raw = required_string(row, source, "Label")
    label = "Normal" if label_raw.lower() == "benign" else "Attack"

    total_packets = fwd_packets + bwd_packets
    total_bytes = fwd_bytes + bwd_bytes

    _, flow_id = required_alias(row, source, ("Flow ID", "flow_id"))

    return NetworkFlow(
        source_dataset="cse_cic_ids2018",
        flow_id=str(flow_id).strip(),
        timestamp_start=start,
        timestamp_end=end,
        src_ip=required_ip(row, source, "Src IP"),
        dst_ip=required_ip(row, source, "Dst IP"),
        src_port=required_int(row, source, "Src Port", maximum=65535),
        dst_port=required_int(row, source, "Dst Port", maximum=65535),
        protocol=required_protocol(row, source, "Protocol"),
        duration_ms=duration_ms,
        fwd_packets=fwd_packets,
        bwd_packets=bwd_packets,
        fwd_bytes=fwd_bytes,
        bwd_bytes=bwd_bytes,
        packets_per_second=rate_per_second(total_packets, duration_ms),
        bytes_per_second=rate_per_second(total_bytes, duration_ms),
        fwd_packet_length_mean=mean_size(fwd_bytes, fwd_packets),
        bwd_packet_length_mean=mean_size(bwd_bytes, bwd_packets),
        label=label,
        attack_category=None if label == "Normal" else label_raw,
    )
