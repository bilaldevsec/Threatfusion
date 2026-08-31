from typing import Any

from threatfusion.datasets.adapters.base import (
    end_timestamp,
    mean_size,
    normalize_protocol,
    parse_timestamp,
    rate_per_second,
    to_float,
    to_int,
)
from threatfusion.schemas.flow import NetworkFlow


def adapt_cic_row(row: dict[str, Any]) -> NetworkFlow:
    duration_ms = to_float(row.get("Flow Duration")) / 1000.0

    fwd_packets = to_int(row.get("Tot Fwd Pkts"))
    bwd_packets = to_int(row.get("Tot Bwd Pkts"))
    fwd_bytes = to_int(row.get("TotLen Fwd Pkts"))
    bwd_bytes = to_int(row.get("TotLen Bwd Pkts"))

    start = parse_timestamp(row.get("Timestamp"))
    end = end_timestamp(start, duration_ms)

    label_raw = str(row.get("Label", "Benign")).strip()
    label = "Normal" if label_raw.lower() == "benign" else "Attack"

    total_packets = fwd_packets + bwd_packets
    total_bytes = fwd_bytes + bwd_bytes

    return NetworkFlow(
        source_dataset="cse_cic_ids2018",
        flow_id=str(row.get("Flow ID", row.get("flow_id", "cic-unknown"))),
        timestamp_start=start,
        timestamp_end=end,
        src_ip=str(row.get("Src IP", "0.0.0.0")),
        dst_ip=str(row.get("Dst IP", "0.0.0.0")),
        src_port=to_int(row.get("Src Port")),
        dst_port=to_int(row.get("Dst Port")),
        protocol=normalize_protocol(row.get("Protocol")),
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
