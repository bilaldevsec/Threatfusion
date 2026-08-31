from datetime import UTC, datetime, timedelta
from typing import Any

import pandas as pd


def to_int(value: Any, default: int = 0) -> int:
    if pd.isna(value):
        return default
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def to_float(value: Any, default: float = 0.0) -> float:
    if pd.isna(value):
        return default
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def mean_size(byte_count: int, packet_count: int) -> float:
    if packet_count <= 0:
        return 0.0
    return byte_count / packet_count


def rate_per_second(total: float, duration_ms: float) -> float:
    if duration_ms <= 0:
        return 0.0
    return float(total) / (duration_ms / 1000.0)


def parse_timestamp(value: Any | None = None) -> datetime:
    if value is None or pd.isna(value):
        return datetime.now(tz=UTC)

    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    text = str(value).strip()

    try:
        if text.replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(text), tz=UTC)
    except (OverflowError, ValueError):
        pass

    parsed = pd.to_datetime(text, errors="coerce", utc=True, dayfirst=True)
    if pd.isna(parsed):
        return datetime.now(tz=UTC)

    return parsed.to_pydatetime()


def end_timestamp(start: datetime, duration_ms: float) -> datetime:
    return start + timedelta(milliseconds=duration_ms)


def normalize_protocol(value: Any) -> str:
    text = str(value).strip().lower()

    if text in {"tcp", "6"}:
        return "tcp"
    if text in {"udp", "17"}:
        return "udp"
    if text in {"icmp", "1"}:
        return "icmp"

    return "other"
