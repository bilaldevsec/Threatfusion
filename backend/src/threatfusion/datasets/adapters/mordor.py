from datetime import UTC, datetime
from typing import Any

import pandas as pd

from threatfusion.schemas.host_event import HostEvent


def _string_or_none(value: Any) -> str | None:
    if value is None or pd.isna(value):
        return None

    text = str(value).strip()
    if text in {"", "-", "None", "nan"}:
        return None

    return text


def _parse_time(value: Any) -> datetime:
    parsed = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(parsed):
        return datetime.now(tz=UTC)
    return parsed.to_pydatetime()


def _classify_event_type(row: dict[str, Any]) -> str:
    event_code = str(row.get("EventID", row.get("event_id", ""))).strip()

    if event_code == "1":
        return "process"
    if event_code == "3":
        return "network"
    if event_code in {"4624", "4625", "4648", "4672"}:
        return "authentication"
    if event_code in {"11", "15"}:
        return "file"
    if event_code in {"12", "13", "14"}:
        return "registry"

    return "other"


def adapt_mordor_row(row: dict[str, Any]) -> HostEvent:
    event_id = _string_or_none(row.get("RecordID")) or _string_or_none(row.get("EventRecordID"))
    if event_id is None:
        event_id = _string_or_none(row.get("event_id")) or "mordor-unknown"

    timestamp = _parse_time(
        row.get("UtcTime")
        or row.get("@timestamp")
        or row.get("TimeCreated")
        or row.get("timestamp")
    )

    return HostEvent(
        source_dataset="mordor",
        event_id=event_id,
        timestamp=timestamp,
        host=_string_or_none(row.get("Computer"))
        or _string_or_none(row.get("host"))
        or "unknown-host",
        user=_string_or_none(row.get("User")) or _string_or_none(row.get("TargetUserName")),
        event_type=_classify_event_type(row),
        provider=_string_or_none(row.get("ProviderName")) or _string_or_none(row.get("Channel")),
        event_code=_string_or_none(row.get("EventID")) or _string_or_none(row.get("event_code")),
        process_name=_string_or_none(row.get("Image")) or _string_or_none(row.get("ProcessName")),
        parent_process_name=_string_or_none(row.get("ParentImage")),
        command_line=_string_or_none(row.get("CommandLine")),
        src_ip=_string_or_none(row.get("SourceIp")) or _string_or_none(row.get("src_ip")),
        dst_ip=_string_or_none(row.get("DestinationIp")) or _string_or_none(row.get("dst_ip")),
        dst_port=_parse_optional_port(row.get("DestinationPort") or row.get("dst_port")),
        file_path=_string_or_none(row.get("TargetFilename"))
        or _string_or_none(row.get("file_path")),
        registry_key=_string_or_none(row.get("TargetObject"))
        or _string_or_none(row.get("registry_key")),
        mitre_attack_id=_string_or_none(row.get("TechniqueID"))
        or _string_or_none(row.get("mitre_attack_id")),
        label=_string_or_none(row.get("label")),
    )


def _parse_optional_port(value: Any) -> int | None:
    if value is None or pd.isna(value):
        return None

    try:
        port = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None

    if port < 0 or port > 65535:
        return None

    return port
