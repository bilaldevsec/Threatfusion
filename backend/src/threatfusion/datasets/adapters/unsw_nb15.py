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


def adapt_unsw_row(row: dict[str, Any]) -> NetworkFlow:
    duration_ms = to_float(row.get("dur")) * 1000.0

    fwd_packets = to_int(row.get("spkts"))
    bwd_packets = to_int(row.get("dpkts"))
    fwd_bytes = to_int(row.get("sbytes"))
    bwd_bytes = to_int(row.get("dbytes"))

    start = parse_timestamp(row.get("stime") or row.get("timestamp"))
    end = end_timestamp(start, duration_ms)

    total_packets = fwd_packets + bwd_packets
    total_bytes = fwd_bytes + bwd_bytes

    attack_category = row.get("attack_cat")
    attack_category = str(attack_category).strip() if attack_category is not None else None
    if attack_category in {"", "-", "nan", "None"}:
        attack_category = None

    label_value = str(row.get("label", "")).strip()
    label = "Attack" if label_value == "1" else "Normal"

    return NetworkFlow(
        source_dataset="unsw_nb15",
        flow_id=str(row.get("id", row.get("flow_id", "unsw-unknown"))),
        timestamp_start=start,
        timestamp_end=end,
        src_ip=str(row.get("srcip", "0.0.0.0")),
        dst_ip=str(row.get("dstip", "0.0.0.0")),
        src_port=to_int(row.get("sport")),
        dst_port=to_int(row.get("dsport")),
        protocol=normalize_protocol(row.get("proto")),
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
        attack_category=attack_category,
    )
