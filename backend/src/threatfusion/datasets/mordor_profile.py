"""Bounded, aggregate-only profiling for Mordor NDJSON events."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from threatfusion.datasets.adapters.mordor import adapt_mordor_row
from threatfusion.datasets.batch import BatchQualityReport, SourceRow, stream_adapt_rows
from threatfusion.schemas.host_event import HostEvent

REJECTION_EXAMPLE_LIMIT = 20
EVENT_ID_CATEGORY_LIMIT = 64
SAFE_PRESENCE_FIELDS: tuple[str, ...] = (
    "@timestamp",
    "TimeCreated",
    "UtcTime",
    "timestamp",
    "Hostname",
    "Computer",
    "host",
    "EventID",
    "Image",
    "ProcessName",
    "ParentImage",
    "ProviderName",
    "Channel",
)


def _safe_event_code(value: Any) -> str:
    if isinstance(value, bool):
        return "missing_or_invalid"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value.strip().isdigit():
        return str(int(value.strip()))
    return "missing_or_invalid"


@dataclass(slots=True)
class MordorProfile:
    """Streaming profiling state that never retains source events."""

    source_file: str
    quality: BatchQualityReport = field(init=False)
    event_id_counts: Counter[str] = field(default_factory=Counter)
    event_id_overflow_count: int = 0
    field_presence_counts: Counter[str] = field(default_factory=Counter)
    process_event_count: int = 0
    earliest_timestamp: datetime | None = None
    latest_timestamp: datetime | None = None

    def __post_init__(self) -> None:
        if Path(self.source_file).name != self.source_file:
            raise ValueError("source_file must be a safe basename")
        self.quality = BatchQualityReport(
            source=f"Mordor/{self.source_file}",
            rejection_example_limit=REJECTION_EXAMPLE_LIMIT,
        )

    def observe_source_shape(self, row: SourceRow) -> None:
        """Count only allowlisted structural fields and sanitized event codes."""
        event_code = _safe_event_code(row.get("EventID"))
        if event_code in self.event_id_counts:
            self.event_id_counts[event_code] += 1
        elif len(self.event_id_counts) < EVENT_ID_CATEGORY_LIMIT:
            self.event_id_counts[event_code] = 1
        else:
            self.event_id_overflow_count += 1
        for name in SAFE_PRESENCE_FIELDS:
            if name in row:
                self.field_presence_counts[name] += 1

    def include(self, event: HostEvent) -> None:
        """Update safe aggregates for one accepted canonical event."""
        if event.event_type == "process":
            self.process_event_count += 1
        self.earliest_timestamp = (
            event.timestamp
            if self.earliest_timestamp is None
            else min(self.earliest_timestamp, event.timestamp)
        )
        self.latest_timestamp = (
            event.timestamp
            if self.latest_timestamp is None
            else max(self.latest_timestamp, event.timestamp)
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a completed JSON-safe profile with a fixed key set."""
        if not self.quality.completed:
            raise ValueError("cannot serialize an incomplete Mordor profile")
        return {
            "dataset": "mordor",
            "source_file": self.source_file,
            "classification": "attack_test_only",
            "completed": True,
            "total_rows": self.quality.total_rows,
            "accepted_count": self.quality.accepted_count,
            "rejected_count": self.quality.rejected_count,
            "rejection_rate": self.quality.rejection_rate,
            "rejection_details": [asdict(detail) for detail in self.quality.rejection_details],
            "event_id_counts": dict(sorted(self.event_id_counts.items())),
            "event_id_overflow_count": self.event_id_overflow_count,
            "field_presence_counts": {
                name: self.field_presence_counts[name] for name in SAFE_PRESENCE_FIELDS
            },
            "process_event_count": self.process_event_count,
            "earliest_timestamp": (
                self.earliest_timestamp.isoformat() if self.earliest_timestamp else None
            ),
            "latest_timestamp": (
                self.latest_timestamp.isoformat() if self.latest_timestamp else None
            ),
        }


def profile_mordor_rows(rows: Iterable[SourceRow], source_file: str) -> MordorProfile:
    """Profile a Mordor stream without retaining accepted records or raw rows."""
    profile = MordorProfile(source_file=source_file)

    def adapt_observed_row(row: SourceRow) -> HostEvent:
        profile.observe_source_shape(row)
        return adapt_mordor_row(row)

    for event in stream_adapt_rows(rows, adapt_observed_row, profile.quality):
        profile.include(event)
    return profile


def write_mordor_profile(profile: MordorProfile, path: Path) -> None:
    """Write one completed sanitized profile, creating parent directories."""
    payload = profile.to_dict()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
