from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

HostEventSource = Literal["mordor", "live_sysmon", "synthetic_lab"]
HostEventType = Literal[
    "process",
    "network",
    "authentication",
    "file",
    "registry",
    "privilege",
    "other",
]


class HostEvent(BaseModel):
    """Canonical host/security event schema for UEBA and endpoint correlation."""

    schema_version: str = Field(default="host_event_v1")
    source_dataset: HostEventSource

    event_id: str
    timestamp: datetime
    host: str
    user: str | None = None

    event_type: HostEventType
    provider: str | None = None
    event_code: str | None = None

    process_name: str | None = None
    parent_process_name: str | None = None
    command_line: str | None = None

    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)

    file_path: str | None = None
    registry_key: str | None = None

    mitre_attack_id: str | None = None
    label: str | None = None
