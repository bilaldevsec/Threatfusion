"""Versioned, aggregate-only model feature contract for host events."""

from __future__ import annotations

from dataclasses import dataclass, field

from threatfusion.schemas.host_event import HostEvent, HostEventType

HOST_BEHAVIOR_V1_FEATURE_NAMES: tuple[str, ...] = (
    "event_count",
    "process_event_count",
    "network_event_count",
    "authentication_event_count",
    "file_event_count",
    "registry_event_count",
    "privilege_event_count",
    "other_event_count",
    "provider_present_count",
    "process_name_present_count",
    "parent_process_name_present_count",
)

HOST_BEHAVIOR_V1_ALLOWED_MODEL_FIELDS = HOST_BEHAVIOR_V1_FEATURE_NAMES

HOST_BEHAVIOR_V1_PROHIBITED_MODEL_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "source_dataset",
        "source_file",
        "filename",
        "file_name",
        "source_row_number",
        "row_number",
        "event_id",
        "record_id",
        "event_record_id",
        "ingestion_id",
        "provenance_id",
        "__mordor_ingestion_id",
        "process_guid",
        "timestamp",
        "host",
        "user",
        "username",
        "command_line",
        "src_ip",
        "dst_ip",
        "dst_port",
        "file_path",
        "registry_key",
        "mitre_attack_id",
        "label",
        "attack_category",
        "attack_name",
        "secret",
    }
)

_EVENT_COUNT_FIELDS: dict[HostEventType, str] = {
    "process": "process_event_count",
    "network": "network_event_count",
    "authentication": "authentication_event_count",
    "file": "file_event_count",
    "registry": "registry_event_count",
    "privilege": "privilege_event_count",
    "other": "other_event_count",
}


def assert_host_behavior_model_fields(feature_names: tuple[str, ...]) -> None:
    """Require the exact host_behavior_v1 allowlist and reject identity fields."""
    prohibited = HOST_BEHAVIOR_V1_PROHIBITED_MODEL_FIELDS.intersection(feature_names)
    if prohibited:
        raise ValueError(f"Forbidden host model field(s): {', '.join(sorted(prohibited))}")
    if feature_names != HOST_BEHAVIOR_V1_FEATURE_NAMES:
        raise ValueError("model fields must exactly match host_behavior_v1")


@dataclass(slots=True)
class HostBehaviorAccumulator:
    """Reduce a caller-defined event group to non-identifying behavioral counts."""

    counts: dict[str, int] = field(
        default_factory=lambda: {name: 0 for name in HOST_BEHAVIOR_V1_FEATURE_NAMES}
    )

    def include(self, event: HostEvent) -> None:
        """Update fixed-size aggregates without retaining the event or any raw value."""
        self.counts["event_count"] += 1
        self.counts[_EVENT_COUNT_FIELDS[event.event_type]] += 1
        if event.provider is not None:
            self.counts["provider_present_count"] += 1
        if event.process_name is not None:
            self.counts["process_name_present_count"] += 1
        if event.parent_process_name is not None:
            self.counts["parent_process_name_present_count"] += 1

    def project(self) -> tuple[int, ...]:
        """Return aggregate values in the exact versioned feature order."""
        return tuple(self.counts[name] for name in HOST_BEHAVIOR_V1_FEATURE_NAMES)
