from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from math import isfinite
from typing import Any

import pandas as pd


class SourceRowValidationError(ValueError):
    """Raised when a source row cannot satisfy an adapter's input contract."""

    def __init__(self, source: str, fields: str | tuple[str, ...], reason: str) -> None:
        self.source = source
        self.fields = (fields,) if isinstance(fields, str) else fields
        self.reason = reason
        field_list = ", ".join(self.fields)
        super().__init__(f"{source}: invalid field(s) {field_list}: {reason}")


def required_value(row: dict[str, Any], source: str, field: str) -> Any:
    """Return a present source value, rejecting null and blank values."""
    if field not in row or row[field] is None or pd.isna(row[field]):
        raise SourceRowValidationError(source, field, "required value is missing")
    if isinstance(row[field], str) and not row[field].strip():
        raise SourceRowValidationError(source, field, "required value is blank")
    return row[field]


def required_alias(row: dict[str, Any], source: str, fields: tuple[str, ...]) -> tuple[str, Any]:
    """Return the first non-empty value from a required alias set."""
    for field in fields:
        value = row.get(field)
        if (
            value is not None
            and not pd.isna(value)
            and (
                not isinstance(value, str) or value.strip().lower() not in {"", "-", "none", "nan"}
            )
        ):
            return field, value
    raise SourceRowValidationError(source, fields, "no valid alias value is present")


def required_string(row: dict[str, Any], source: str, field: str) -> str:
    return str(required_value(row, source, field)).strip()


def required_int(
    row: dict[str, Any],
    source: str,
    field: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    value = required_value(row, source, field)
    try:
        number = float(str(value).strip())
        parsed = int(number)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SourceRowValidationError(source, field, "must be an integer") from exc
    if not isfinite(number) or number != parsed:
        raise SourceRowValidationError(source, field, "must be a finite integer")
    if parsed < minimum or (maximum is not None and parsed > maximum):
        bounds = f"between {minimum} and {maximum}" if maximum is not None else f">= {minimum}"
        raise SourceRowValidationError(source, field, f"must be {bounds}")
    return parsed


def required_float(row: dict[str, Any], source: str, field: str, *, minimum: float = 0.0) -> float:
    value = required_value(row, source, field)
    try:
        parsed = float(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise SourceRowValidationError(source, field, "must be numeric") from exc
    if not isfinite(parsed) or parsed < minimum:
        raise SourceRowValidationError(source, field, f"must be finite and >= {minimum}")
    return parsed


def required_ip(row: dict[str, Any], source: str, field: str) -> str:
    value = required_string(row, source, field)
    try:
        ip_address(value)
    except ValueError as exc:
        raise SourceRowValidationError(source, field, "must be a valid IP address") from exc
    return value


def parse_required_timestamp(value: Any, source: str, field: str) -> datetime:
    if value is None or pd.isna(value) or (isinstance(value, str) and not value.strip()):
        raise SourceRowValidationError(source, field, "required timestamp is missing")

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
        raise SourceRowValidationError(source, field, "must be a parseable timestamp")
    return parsed.to_pydatetime()


def required_protocol(row: dict[str, Any], source: str, field: str) -> str:
    value = required_string(row, source, field)
    return normalize_protocol(value)


def mean_size(byte_count: int, packet_count: int) -> float:
    if packet_count <= 0:
        return 0.0
    return byte_count / packet_count


def rate_per_second(total: float, duration_ms: float) -> float:
    if duration_ms <= 0:
        return 0.0
    return float(total) / (duration_ms / 1000.0)


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
