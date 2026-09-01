from typing import Any

import pandas as pd

from threatfusion.datasets.adapters.base import (
    parse_required_timestamp,
    required_alias,
)
from threatfusion.schemas.host_event import HostEvent


def _string_or_none(value: Any) -> str | None:
    if value is None or pd.isna(value):
        return None

    text = str(value).strip()
    if text in {"", "-", "None", "nan"}:
        return None

    return text


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
    source = "Mordor"
    _, event_id_value = required_alias(row, source, ("RecordID", "EventRecordID", "event_id"))
    timestamp_field, timestamp_value = required_alias(
        row, source, ("UtcTime", "@timestamp", "TimeCreated", "timestamp")
    )
    _, host_value = required_alias(row, source, ("Computer", "host"))
    timestamp = parse_required_timestamp(timestamp_value, source, timestamp_field)

    return HostEvent(
        source_dataset="mordor",
        event_id=str(event_id_value).strip(),
        timestamp=timestamp,
        host=str(host_value).strip(),
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
