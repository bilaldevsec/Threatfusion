"""Bounded-memory profiling for accepted UNSW-NB15 records."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from threatfusion.datasets.adapters.unsw_nb15 import adapt_unsw_row
from threatfusion.datasets.batch import BatchQualityReport, SourceRow, stream_adapt_rows
from threatfusion.schemas.flow import NetworkFlow

INCONSISTENCY_EXAMPLE_LIMIT = 20


@dataclass(frozen=True, slots=True)
class NumericRange:
    """Streaming minimum and maximum for one numeric field."""

    minimum: float | None = None
    maximum: float | None = None

    def include(self, value: float) -> NumericRange:
        """Return the range expanded to include one value."""
        return NumericRange(
            minimum=value if self.minimum is None else min(self.minimum, value),
            maximum=value if self.maximum is None else max(self.maximum, value),
        )


@dataclass(frozen=True, slots=True)
class LabelInconsistencyExample:
    """A bounded, non-sensitive pointer to an inconsistent label row."""

    source_file: str
    row_number: int
    issue: str


@dataclass(frozen=True, slots=True)
class AcceptedUnswRecord:
    """One accepted canonical flow with only the raw categories needed for profiling."""

    flow: NetworkFlow
    raw_label: int
    service: str
    connection_state: str


def _category(value: Any) -> str:
    text = str(value).strip() if value is not None else ""
    return text or "<blank>"


def _adapt_for_profile(row: SourceRow) -> AcceptedUnswRecord:
    flow = adapt_unsw_row(row)
    return AcceptedUnswRecord(
        flow=flow,
        raw_label=int(float(str(row["label"]).strip())),
        service=_category(row.get("service")),
        connection_state=_category(row.get("state")),
    )


def _default_numeric_ranges() -> dict[str, NumericRange]:
    return {
        "duration_ms": NumericRange(),
        "source_bytes": NumericRange(),
        "destination_bytes": NumericRange(),
        "source_packets": NumericRange(),
        "destination_packets": NumericRange(),
        "source_port": NumericRange(),
        "destination_port": NumericRange(),
    }


@dataclass(slots=True)
class UnswProfile:
    """Aggregate state retained during one streaming UNSW profiling pass."""

    quality: BatchQualityReport = field(
        default_factory=lambda: BatchQualityReport(source="UNSW-NB15 full raw profile")
    )
    canonical_label_counts: Counter[str] = field(default_factory=Counter)
    raw_numeric_label_counts: Counter[int] = field(default_factory=Counter)
    attack_category_counts: Counter[str] = field(default_factory=Counter)
    protocol_counts: Counter[str] = field(default_factory=Counter)
    service_counts: Counter[str] = field(default_factory=Counter)
    connection_state_counts: Counter[str] = field(default_factory=Counter)
    blank_optional_attack_category_count: int = 0
    numeric_ranges: dict[str, NumericRange] = field(default_factory=_default_numeric_ranges)
    earliest_timestamp: datetime | None = None
    latest_timestamp: datetime | None = None
    label_inconsistency_counts: Counter[str] = field(default_factory=Counter)
    label_inconsistency_examples: list[LabelInconsistencyExample] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic JSON-safe report containing no raw rows or IP addresses."""
        if not self.quality.completed:
            raise ValueError("cannot serialize an incomplete UNSW profile")
        return {
            "completed": True,
            "total_input_rows": self.quality.total_rows,
            "accepted_count": self.quality.accepted_count,
            "rejected_count": self.quality.rejected_count,
            "rejection_rate": self.quality.rejection_rate,
            "rejection_details": [asdict(detail) for detail in self.quality.rejection_details],
            "canonical_label_counts": dict(sorted(self.canonical_label_counts.items())),
            "raw_numeric_label_counts": {
                str(key): value for key, value in sorted(self.raw_numeric_label_counts.items())
            },
            "attack_category_counts": dict(sorted(self.attack_category_counts.items())),
            "protocol_counts": dict(sorted(self.protocol_counts.items())),
            "service_counts": dict(sorted(self.service_counts.items())),
            "connection_state_counts": dict(sorted(self.connection_state_counts.items())),
            "blank_optional_attack_category_count": self.blank_optional_attack_category_count,
            "numeric_ranges": {
                name: asdict(value) for name, value in sorted(self.numeric_ranges.items())
            },
            "earliest_timestamp": (
                self.earliest_timestamp.isoformat() if self.earliest_timestamp else None
            ),
            "latest_timestamp": (
                self.latest_timestamp.isoformat() if self.latest_timestamp else None
            ),
            "label_inconsistency_counts": dict(sorted(self.label_inconsistency_counts.items())),
            "label_inconsistency_examples": [
                asdict(example) for example in self.label_inconsistency_examples
            ],
        }


def profile_unsw_rows(rows: Iterable[SourceRow]) -> UnswProfile:
    """Profile accepted rows lazily while retaining only aggregates and bounded examples."""
    profile = UnswProfile()
    for accepted in stream_adapt_rows(rows, _adapt_for_profile, profile.quality):
        flow = accepted.flow
        profile.canonical_label_counts[str(flow.label)] += 1
        profile.raw_numeric_label_counts[accepted.raw_label] += 1
        profile.protocol_counts[flow.protocol] += 1
        profile.service_counts[accepted.service] += 1
        profile.connection_state_counts[accepted.connection_state] += 1

        if flow.attack_category is None:
            profile.blank_optional_attack_category_count += 1
        else:
            profile.attack_category_counts[flow.attack_category] += 1

        values: dict[str, float] = {
            "duration_ms": flow.duration_ms,
            "source_bytes": flow.fwd_bytes,
            "destination_bytes": flow.bwd_bytes,
            "source_packets": flow.fwd_packets,
            "destination_packets": flow.bwd_packets,
            "source_port": flow.src_port,
            "destination_port": flow.dst_port,
        }
        for name, value in values.items():
            profile.numeric_ranges[name] = profile.numeric_ranges[name].include(value)

        profile.earliest_timestamp = (
            flow.timestamp_start
            if profile.earliest_timestamp is None
            else min(profile.earliest_timestamp, flow.timestamp_start)
        )
        profile.latest_timestamp = (
            flow.timestamp_start
            if profile.latest_timestamp is None
            else max(profile.latest_timestamp, flow.timestamp_start)
        )

        issue: str | None = None
        if accepted.raw_label == 0 and flow.attack_category is not None:
            issue = "label_0_with_attack_category"
        elif accepted.raw_label == 1 and flow.attack_category is None:
            issue = "label_1_without_attack_category"
        if issue is not None:
            profile.label_inconsistency_counts[issue] += 1
            if len(profile.label_inconsistency_examples) < INCONSISTENCY_EXAMPLE_LIMIT:
                source_file, row_text = flow.flow_id.rsplit(":", maxsplit=1)
                profile.label_inconsistency_examples.append(
                    LabelInconsistencyExample(
                        source_file=f"{source_file}.csv",
                        row_number=int(row_text),
                        issue=issue,
                    )
                )
    return profile


def write_unsw_profile(profile: UnswProfile, path: Path) -> None:
    """Write a completed sanitized profile report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(profile.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
