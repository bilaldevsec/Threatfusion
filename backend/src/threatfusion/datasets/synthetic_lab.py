"""Streaming validation and aggregate profiling for synthetic_lab host events."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from threatfusion.datasets.adapters.base import SourceRowValidationError
from threatfusion.datasets.batch import BatchQualityReport, stream_adapt_rows
from threatfusion.features.host_behavior import HostBehaviorAccumulator
from threatfusion.schemas.host_event import HostEvent, HostEventType

SYNTHETIC_SOURCE_FILE_FIELD = "__synthetic_source_file"
SYNTHETIC_SOURCE_ROW_FIELD = "__synthetic_source_row"
REJECTION_EXAMPLE_LIMIT = 20
EVENT_TYPES: tuple[HostEventType, ...] = (
    "process",
    "network",
    "authentication",
    "file",
    "registry",
    "privilege",
    "other",
)


class SyntheticLabStructureError(ValueError):
    """Sanitized structural failure containing no source values."""

    def __init__(self, source_file: str, row_number: int, issue: str) -> None:
        self.source_file = Path(source_file).name
        self.row_number = row_number
        self.issue = issue
        super().__init__(f"{self.source_file} row {row_number}: {issue}")


@dataclass(frozen=True, slots=True)
class SyntheticLabNdjsonReader:
    """Yield one synthetic host event object at a time with safe provenance."""

    path: Path

    def __iter__(self) -> Iterator[dict[str, Any]]:
        with self.path.open(encoding="utf-8", errors="strict") as handle:
            for row_number, line in enumerate(handle, start=1):
                if not line.strip():
                    raise SyntheticLabStructureError(self.path.name, row_number, "blank_line")
                try:
                    row: Any = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise SyntheticLabStructureError(
                        self.path.name, row_number, "invalid_json"
                    ) from exc
                if not isinstance(row, dict):
                    raise SyntheticLabStructureError(self.path.name, row_number, "non_object_event")
                if SYNTHETIC_SOURCE_FILE_FIELD in row or SYNTHETIC_SOURCE_ROW_FIELD in row:
                    raise SyntheticLabStructureError(
                        self.path.name, row_number, "reserved_provenance_collision"
                    )
                row[SYNTHETIC_SOURCE_FILE_FIELD] = self.path.name
                row[SYNTHETIC_SOURCE_ROW_FIELD] = row_number
                yield row


def adapt_synthetic_lab_row(row: dict[str, Any]) -> HostEvent:
    """Validate one canonical synthetic event and its deterministic provenance."""
    source = "synthetic_lab"
    source_file = row.get(SYNTHETIC_SOURCE_FILE_FIELD)
    row_number = row.get(SYNTHETIC_SOURCE_ROW_FIELD)
    if not isinstance(source_file, str) or Path(source_file).name != source_file:
        raise SourceRowValidationError(
            source, SYNTHETIC_SOURCE_FILE_FIELD, "required value is missing"
        )
    if not isinstance(row_number, int) or isinstance(row_number, bool) or row_number < 1:
        raise SourceRowValidationError(source, SYNTHETIC_SOURCE_ROW_FIELD, "must be an integer")
    event = HostEvent.model_validate(row)
    if event.source_dataset != "synthetic_lab":
        raise SourceRowValidationError(source, "source_dataset", "source row validation failed")
    if event.event_id != f"{source_file}:{row_number}":
        raise SourceRowValidationError(source, "event_id", "source row validation failed")
    if event.label != "Normal":
        raise SourceRowValidationError(source, "label", "source row validation failed")
    return event


@dataclass(frozen=True, slots=True)
class SyntheticLabQualityGates:
    """Configurable minimum evidence required from the development fixture."""

    minimum_sessions: int = 3
    minimum_event_types: int = 7
    minimum_events_per_session: int = 14
    minimum_session_duration_seconds: float = 780.0

    def __post_init__(self) -> None:
        if self.minimum_sessions < 1 or self.minimum_event_types < 1:
            raise ValueError("session and event-type minimums must be positive")
        if self.minimum_events_per_session < 1 or self.minimum_session_duration_seconds < 0:
            raise ValueError("event and duration minimums must be nonnegative")


@dataclass(frozen=True, slots=True)
class SyntheticLabTrainingGates:
    """Project-selected minimum evidence gates for final host-model training."""

    minimum_sessions: int = 5
    minimum_total_events: int = 500
    minimum_events_per_session: int = 50
    minimum_time_span_seconds: float = 7 * 24 * 60 * 60
    minimum_event_type_diversity: int = 7
    reject_artificially_uniform_event_frequencies: bool = True

    def __post_init__(self) -> None:
        if (
            self.minimum_sessions < 1
            or self.minimum_total_events < 1
            or self.minimum_events_per_session < 1
            or self.minimum_event_type_diversity < 1
            or self.minimum_time_span_seconds < 0
        ):
            raise ValueError("training gate minimums must be positive")


@dataclass(slots=True)
class SyntheticSessionProfile:
    """Bounded aggregate state for one independent synthetic session file."""

    source_file: str
    quality: BatchQualityReport = field(init=False)
    event_type_counts: Counter[str] = field(default_factory=Counter)
    label_counts: Counter[str] = field(default_factory=Counter)
    host_behavior: HostBehaviorAccumulator = field(default_factory=HostBehaviorAccumulator)
    earliest_timestamp: datetime | None = None
    latest_timestamp: datetime | None = None

    def __post_init__(self) -> None:
        if Path(self.source_file).name != self.source_file:
            raise ValueError("source_file must be a safe basename")
        self.quality = BatchQualityReport(
            source=f"synthetic_lab/{self.source_file}",
            rejection_example_limit=REJECTION_EXAMPLE_LIMIT,
        )

    def include(self, event: HostEvent) -> None:
        self.event_type_counts[event.event_type] += 1
        self.label_counts[event.label or "Unlabeled"] += 1
        self.host_behavior.include(event)
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

    @property
    def duration_seconds(self) -> float:
        if self.earliest_timestamp is None or self.latest_timestamp is None:
            return 0.0
        return (self.latest_timestamp - self.earliest_timestamp).total_seconds()


def profile_synthetic_session(path: Path) -> SyntheticSessionProfile:
    """Fully consume one session while retaining aggregate state only."""
    profile = SyntheticSessionProfile(path.name)
    rows = SyntheticLabNdjsonReader(path)
    for event in stream_adapt_rows(rows, adapt_synthetic_lab_row, profile.quality):
        profile.include(event)
    return profile


def build_synthetic_profile(
    sessions: Sequence[SyntheticSessionProfile],
    gates: SyntheticLabQualityGates,
    training_gates: SyntheticLabTrainingGates | None = None,
) -> dict[str, Any]:
    """Combine completed session aggregates and evaluate minimum quality gates."""
    event_types: Counter[str] = Counter()
    labels: Counter[str] = Counter()
    rejection_details: list[dict[str, Any]] = []
    session_payloads: list[dict[str, Any]] = []
    for session in sessions:
        if not session.quality.completed:
            raise ValueError("cannot profile an incomplete synthetic_lab session")
        event_types.update(session.event_type_counts)
        labels.update(session.label_counts)
        rejection_details.extend(
            {"source_file": session.source_file, **asdict(detail)}
            for detail in session.quality.rejection_details[
                : max(0, REJECTION_EXAMPLE_LIMIT - len(rejection_details))
            ]
        )
        session_payloads.append(
            {
                "source_file": session.source_file,
                "completed": True,
                "total_rows": session.quality.total_rows,
                "accepted_count": session.quality.accepted_count,
                "rejected_count": session.quality.rejected_count,
                "duration_seconds": session.duration_seconds,
                "event_type_counts": {
                    name: session.event_type_counts[name] for name in EVENT_TYPES
                },
            }
        )

    total = sum(session.quality.total_rows for session in sessions)
    accepted = sum(session.quality.accepted_count for session in sessions)
    rejected = sum(session.quality.rejected_count for session in sessions)
    covered_types = sum(event_types[name] > 0 for name in EVENT_TYPES)
    gate_results = {
        "session_count": len(sessions) >= gates.minimum_sessions,
        "event_type_coverage": covered_types >= gates.minimum_event_types,
        "events_per_session": all(
            session.quality.accepted_count >= gates.minimum_events_per_session
            for session in sessions
        ),
        "time_coverage_per_session": all(
            session.duration_seconds >= gates.minimum_session_duration_seconds
            for session in sessions
        ),
        "normal_labels_only": set(labels) <= {"Normal"} and labels["Normal"] == accepted,
        "all_sessions_completed": all(session.quality.completed for session in sessions),
    }
    training_gates = training_gates or SyntheticLabTrainingGates()
    overall_duration = (
        (
            max(session.latest_timestamp for session in sessions if session.latest_timestamp)
            - min(session.earliest_timestamp for session in sessions if session.earliest_timestamp)
        ).total_seconds()
        if sessions
        and all(session.earliest_timestamp and session.latest_timestamp for session in sessions)
        else 0.0
    )
    positive_event_counts = [event_types[name] for name in EVENT_TYPES if event_types[name] > 0]
    uniform_frequencies = bool(positive_event_counts) and len(set(positive_event_counts)) == 1
    training_gate_results = {
        "session_count": len(sessions) >= training_gates.minimum_sessions,
        "total_events": accepted >= training_gates.minimum_total_events,
        "events_per_session": all(
            session.quality.accepted_count >= training_gates.minimum_events_per_session
            for session in sessions
        ),
        "time_span": overall_duration >= training_gates.minimum_time_span_seconds,
        "event_type_diversity": covered_types >= training_gates.minimum_event_type_diversity,
        "non_uniform_event_frequencies": (
            not uniform_frequencies
            if training_gates.reject_artificially_uniform_event_frequencies
            else True
        ),
    }
    return {
        "dataset": "synthetic_lab",
        "classification": "development_pipeline_fixture",
        "completed": gate_results["all_sessions_completed"],
        "total_rows": total,
        "accepted_count": accepted,
        "rejected_count": rejected,
        "rejection_rate": rejected / total if total else 0.0,
        "rejection_details": rejection_details[:REJECTION_EXAMPLE_LIMIT],
        "session_count": len(sessions),
        "sessions": session_payloads,
        "event_type_counts": {name: event_types[name] for name in EVENT_TYPES},
        "label_counts": {"Normal": labels["Normal"]},
        "host_behavior_v1_aggregate": (
            {
                name: sum(session.host_behavior.counts[name] for session in sessions)
                for name in sessions[0].host_behavior.counts
            }
            if sessions
            else {}
        ),
        "quality_gates": {
            "configured": asdict(gates),
            "results": gate_results,
            "passed": all(gate_results.values()),
        },
        "training_quality_gates": {
            "configured": asdict(training_gates),
            "observed": {
                "total_time_span_seconds": overall_duration,
                "event_type_diversity": covered_types,
                "uniform_event_frequencies": uniform_frequencies,
            },
            "results": training_gate_results,
            "passed": all(training_gate_results.values()),
        },
    }


def write_synthetic_profile(payload: dict[str, Any], path: Path) -> None:
    """Write one completed aggregate-only synthetic baseline profile."""
    if payload.get("completed") is not True:
        raise ValueError("cannot write an incomplete synthetic_lab profile")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
