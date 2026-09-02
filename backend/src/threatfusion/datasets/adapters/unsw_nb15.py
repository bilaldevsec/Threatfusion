import re
from typing import Any

from threatfusion.datasets.adapters.base import (
    SourceRowValidationError,
    end_timestamp,
    mean_size,
    parse_required_timestamp,
    rate_per_second,
    required_alias,
    required_float,
    required_int,
    required_ip,
    required_protocol,
    required_value,
)
from threatfusion.schemas.flow import NetworkFlow

UNSW_REQUIRED_FIELD_ALIASES: tuple[tuple[str, ...], ...] = (
    ("id", "flow_id"),
    ("stime", "timestamp"),
    ("srcip",),
    ("dstip",),
    ("sport",),
    ("dsport",),
    ("proto",),
    ("dur",),
    ("spkts",),
    ("dpkts",),
    ("sbytes",),
    ("dbytes",),
    ("label",),
)

_UNSW_HEXADECIMAL_PORT = re.compile(r"0x[0-9a-f]+", re.IGNORECASE)
_UNSW_DECIMAL_PORT = re.compile(r"[0-9]+")


def _required_unsw_port(row: dict[str, Any], field: str) -> int:
    """Parse strict decimal or official hexadecimal UNSW port representations."""
    source = "UNSW-NB15"
    value = required_value(row, source, field)

    if isinstance(value, str):
        text = value.strip()
        if _UNSW_HEXADECIMAL_PORT.fullmatch(text):
            return required_int({field: int(text, 16)}, source, field, maximum=65535)
        if not _UNSW_DECIMAL_PORT.fullmatch(text):
            raise SourceRowValidationError(source, field, "must be an integer")
    elif not isinstance(value, int) or isinstance(value, bool):
        raise SourceRowValidationError(source, field, "must be an integer")

    return required_int(row, source, field, maximum=65535)


def adapt_unsw_row(row: dict[str, Any]) -> NetworkFlow:
    source = "UNSW-NB15"
    duration_ms = required_float(row, source, "dur") * 1000.0

    fwd_packets = required_int(row, source, "spkts")
    bwd_packets = required_int(row, source, "dpkts")
    fwd_bytes = required_int(row, source, "sbytes")
    bwd_bytes = required_int(row, source, "dbytes")

    timestamp_field, timestamp_value = required_alias(row, source, ("stime", "timestamp"))
    start = parse_required_timestamp(timestamp_value, source, timestamp_field)
    end = end_timestamp(start, duration_ms)

    total_packets = fwd_packets + bwd_packets
    total_bytes = fwd_bytes + bwd_bytes

    attack_category = row.get("attack_cat")
    attack_category = str(attack_category).strip() if attack_category is not None else None
    if attack_category in {"", "-", "nan", "None"}:
        attack_category = None

    label_value = required_int(row, source, "label", maximum=1)
    label = "Attack" if label_value == 1 else "Normal"

    _, flow_id = required_alias(row, source, ("id", "flow_id"))

    return NetworkFlow(
        source_dataset="unsw_nb15",
        flow_id=str(flow_id).strip(),
        timestamp_start=start,
        timestamp_end=end,
        src_ip=required_ip(row, source, "srcip"),
        dst_ip=required_ip(row, source, "dstip"),
        src_port=_required_unsw_port(row, "sport"),
        dst_port=_required_unsw_port(row, "dsport"),
        protocol=required_protocol(row, source, "proto"),
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
