"""Strict feature-only adapter for official processed CSE-CIC-IDS2018 rows."""

from datetime import datetime
from typing import Any

from threatfusion.datasets.adapters.base import (
    SourceRowValidationError,
    mean_size,
    rate_per_second,
    required_float,
    required_int,
    required_protocol,
    required_string,
)
from threatfusion.datasets.cic_processed import (
    CIC_SOURCE_FILE_FIELD,
    CIC_SOURCE_ROW_NUMBER_FIELD,
)
from threatfusion.schemas.network_benchmark import NetworkBenchmarkRecord

CIC_TIMESTAMP_FORMAT = "%d/%m/%Y %H:%M:%S"
CIC_APPROVED_ATTACK_LABELS: frozenset[str] = frozenset(
    {
        "FTP-BruteForce",
        "SSH-Bruteforce",
        "DoS attacks-GoldenEye",
        "DoS attacks-Slowloris",
    }
)


def _parse_cic_local_timestamp(row: dict[str, Any]) -> datetime:
    source = "CSE-CIC-IDS2018 benchmark"
    field = "Timestamp"
    text = required_string(row, source, field)
    try:
        # Source timezone is undocumented; assigning UTC or another zone would invent evidence.
        return datetime.strptime(text, CIC_TIMESTAMP_FORMAT)  # noqa: DTZ007
    except ValueError as exc:
        raise SourceRowValidationError(
            source, field, "must match the approved day/month/year timestamp format"
        ) from exc


def _normalize_cic_label(row: dict[str, Any]) -> tuple[str, str | None]:
    source = "CSE-CIC-IDS2018 benchmark"
    field = "Label"
    raw_label = required_string(row, source, field)
    if raw_label.casefold() == "benign":
        return "Normal", None
    if raw_label in CIC_APPROVED_ATTACK_LABELS:
        return "Attack", raw_label
    raise SourceRowValidationError(source, field, "must be an approved benchmark label")


def adapt_cic_benchmark_row(row: dict[str, Any]) -> NetworkBenchmarkRecord:
    """Adapt one processed CIC row without inventing correlation metadata."""
    source = "CSE-CIC-IDS2018 benchmark"
    duration_ms = required_float(row, source, "Flow Duration") / 1000.0
    fwd_packets = required_int(row, source, "Tot Fwd Pkts")
    bwd_packets = required_int(row, source, "Tot Bwd Pkts")
    fwd_bytes = required_int(row, source, "TotLen Fwd Pkts")
    bwd_bytes = required_int(row, source, "TotLen Bwd Pkts")
    label, attack_name = _normalize_cic_label(row)

    return NetworkBenchmarkRecord(
        source_dataset="cse_cic_ids2018",
        source_file=required_string(row, source, CIC_SOURCE_FILE_FIELD),
        source_row_number=required_int(row, source, CIC_SOURCE_ROW_NUMBER_FIELD, minimum=1),
        source_timestamp=_parse_cic_local_timestamp(row),
        duration_ms=duration_ms,
        fwd_packets=fwd_packets,
        bwd_packets=bwd_packets,
        fwd_bytes=fwd_bytes,
        bwd_bytes=bwd_bytes,
        packets_per_second=rate_per_second(fwd_packets + bwd_packets, duration_ms),
        bytes_per_second=rate_per_second(fwd_bytes + bwd_bytes, duration_ms),
        fwd_packet_length_mean=mean_size(fwd_bytes, fwd_packets),
        bwd_packet_length_mean=mean_size(bwd_bytes, bwd_packets),
        dst_port=required_int(row, source, "Dst Port", maximum=65535),
        protocol=required_protocol(row, source, "Protocol"),
        label=label,
        attack_name=attack_name,
    )
