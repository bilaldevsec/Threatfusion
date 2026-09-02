"""Bounded-memory profiling for accepted CSE-CIC-IDS2018 benchmark records."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from threatfusion.datasets.adapters.cic_ids2018_benchmark import adapt_cic_benchmark_row
from threatfusion.datasets.batch import BatchQualityReport, SourceRow, stream_adapt_rows
from threatfusion.datasets.cic_processed import CicProcessedReader
from threatfusion.features.network_behavior import (
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
    project_network_behavior,
)
from threatfusion.schemas.network_benchmark import NetworkBenchmarkRecord

REJECTION_EXAMPLE_LIMIT = 20
LABELS: tuple[str, ...] = ("Normal", "Attack")
PROTOCOLS: tuple[str, ...] = ("tcp", "udp", "icmp", "other")
NUMERIC_FEATURE_NAMES: tuple[str, ...] = NETWORK_BEHAVIOR_V1_FEATURE_NAMES[:-1]


@dataclass(frozen=True, slots=True)
class NumericRange:
    """Streaming minimum and maximum for one numeric benchmark feature."""

    minimum: int | float | None = None
    maximum: int | float | None = None

    def include(self, value: float) -> NumericRange:
        """Return this range expanded to include one value."""
        return NumericRange(
            minimum=value if self.minimum is None else min(self.minimum, value),
            maximum=value if self.maximum is None else max(self.maximum, value),
        )

    def merge(self, other: NumericRange) -> NumericRange:
        """Return the aggregate of two independently streamed ranges."""
        result = self
        if other.minimum is not None:
            result = result.include(other.minimum)
        if other.maximum is not None:
            result = result.include(other.maximum)
        return result


def _empty_counts(names: Sequence[str]) -> Counter[str]:
    return Counter({name: 0 for name in names})


def _empty_ranges() -> dict[str, NumericRange]:
    return {name: NumericRange() for name in NUMERIC_FEATURE_NAMES}


def _safe_basename(source_file: str) -> str:
    if (
        not source_file
        or source_file in {".", ".."}
        or "/" in source_file
        or "\\" in source_file
        or Path(source_file).name != source_file
    ):
        raise ValueError("source_file must be a safe basename")
    return source_file


@dataclass(slots=True)
class CicFileProfile:
    """Aggregate-only profiling state for one CIC export."""

    source_file: str
    quality: BatchQualityReport = field(init=False)
    label_counts: Counter[str] = field(default_factory=lambda: _empty_counts(LABELS))
    attack_category_counts: Counter[str] = field(default_factory=Counter)
    protocol_counts: Counter[str] = field(default_factory=lambda: _empty_counts(PROTOCOLS))
    numeric_ranges: dict[str, NumericRange] = field(default_factory=_empty_ranges)
    earliest_source_timestamp: datetime | None = None
    latest_source_timestamp: datetime | None = None

    def __post_init__(self) -> None:
        self.source_file = _safe_basename(self.source_file)
        self.quality = BatchQualityReport(
            source=f"CSE-CIC-IDS2018 benchmark/{self.source_file}",
            rejection_example_limit=REJECTION_EXAMPLE_LIMIT,
        )

    def include(self, record: NetworkBenchmarkRecord) -> None:
        """Update aggregates from one accepted record and immediately discard it."""
        self.label_counts[record.label] += 1
        if record.attack_name is not None:
            self.attack_category_counts[record.attack_name] += 1
        self.protocol_counts[record.protocol] += 1

        projected = project_network_behavior(record)
        for name, value in zip(NETWORK_BEHAVIOR_V1_FEATURE_NAMES, projected, strict=True):
            if name != "protocol":
                if not isinstance(value, (int, float)):
                    raise TypeError(f"{name} must be numeric")
                self.numeric_ranges[name] = self.numeric_ranges[name].include(value)

        timestamp = record.source_timestamp
        if timestamp.tzinfo is not None or timestamp.utcoffset() is not None:
            raise ValueError("CIC source timestamps must remain timezone-naive")
        self.earliest_source_timestamp = (
            timestamp
            if self.earliest_source_timestamp is None
            else min(self.earliest_source_timestamp, timestamp)
        )
        self.latest_source_timestamp = (
            timestamp
            if self.latest_source_timestamp is None
            else max(self.latest_source_timestamp, timestamp)
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe per-file profile with no source rows or raw values."""
        if not self.quality.completed:
            raise ValueError("cannot serialize an incomplete CIC file profile")
        return {
            "source_file": self.source_file,
            "completed": True,
            "total_rows": self.quality.total_rows,
            "accepted_count": self.quality.accepted_count,
            "rejected_count": self.quality.rejected_count,
            "rejection_rate": self.quality.rejection_rate,
            "rejection_details": [asdict(detail) for detail in self.quality.rejection_details],
            "label_counts": {name: self.label_counts[name] for name in LABELS},
            "attack_category_counts": dict(sorted(self.attack_category_counts.items())),
            "protocol_counts": {name: self.protocol_counts[name] for name in PROTOCOLS},
            "numeric_ranges": {
                name: asdict(self.numeric_ranges[name]) for name in NUMERIC_FEATURE_NAMES
            },
            "earliest_source_timestamp": (
                self.earliest_source_timestamp.isoformat()
                if self.earliest_source_timestamp is not None
                else None
            ),
            "latest_source_timestamp": (
                self.latest_source_timestamp.isoformat()
                if self.latest_source_timestamp is not None
                else None
            ),
        }


def profile_cic_rows(rows: Iterable[SourceRow], source_file: str) -> CicFileProfile:
    """Profile one row stream while retaining only bounded aggregate state."""
    profile = CicFileProfile(source_file=source_file)
    for record in stream_adapt_rows(rows, adapt_cic_benchmark_row, profile.quality):
        profile.include(record)
    return profile


@dataclass(frozen=True, slots=True)
class CicDatasetProfile:
    """Per-file profiles combined without retaining accepted records."""

    files: tuple[CicFileProfile, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return one deterministic, aggregate-only CIC profile report."""
        file_payloads = [profile.to_dict() for profile in self.files]
        labels = _empty_counts(LABELS)
        attacks: Counter[str] = Counter()
        protocols = _empty_counts(PROTOCOLS)
        ranges = _empty_ranges()
        earliest: datetime | None = None
        latest: datetime | None = None
        rejection_details: list[dict[str, Any]] = []

        for profile, payload in zip(self.files, file_payloads, strict=True):
            labels.update(profile.label_counts)
            attacks.update(profile.attack_category_counts)
            protocols.update(profile.protocol_counts)
            for name in NUMERIC_FEATURE_NAMES:
                ranges[name] = ranges[name].merge(profile.numeric_ranges[name])
            if profile.earliest_source_timestamp is not None:
                earliest = (
                    profile.earliest_source_timestamp
                    if earliest is None
                    else min(earliest, profile.earliest_source_timestamp)
                )
            if profile.latest_source_timestamp is not None:
                latest = (
                    profile.latest_source_timestamp
                    if latest is None
                    else max(latest, profile.latest_source_timestamp)
                )
            for detail in payload["rejection_details"]:
                if len(rejection_details) >= REJECTION_EXAMPLE_LIMIT:
                    break
                rejection_details.append({"source_file": profile.source_file, **detail})

        total_rows = sum(profile.quality.total_rows for profile in self.files)
        accepted_count = sum(profile.quality.accepted_count for profile in self.files)
        rejected_count = sum(profile.quality.rejected_count for profile in self.files)
        return {
            "dataset": "cse_cic_ids2018",
            "benchmark_role": "external_network_benchmark",
            "network_behavior_v1_feature_order": list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES),
            "timestamp_semantics": "timezone-naive; source timezone unknown",
            "files": file_payloads,
            "combined": {
                "completed": all(profile.quality.completed for profile in self.files),
                "total_rows": total_rows,
                "accepted_count": accepted_count,
                "rejected_count": rejected_count,
                "rejection_rate": rejected_count / total_rows if total_rows else 0.0,
                "rejection_details": rejection_details,
                "label_counts": {name: labels[name] for name in LABELS},
                "attack_category_counts": dict(sorted(attacks.items())),
                "protocol_counts": {name: protocols[name] for name in PROTOCOLS},
                "numeric_ranges": {name: asdict(ranges[name]) for name in NUMERIC_FEATURE_NAMES},
                "earliest_source_timestamp": earliest.isoformat() if earliest else None,
                "latest_source_timestamp": latest.isoformat() if latest else None,
            },
        }


def profile_cic_files(paths: Sequence[Path]) -> CicDatasetProfile:
    """Stream-profile complete processed CIC files in the supplied order."""
    return CicDatasetProfile(
        files=tuple(profile_cic_rows(CicProcessedReader(path), path.name) for path in paths)
    )


def write_cic_profile(profile: CicDatasetProfile, path: Path) -> None:
    """Write one completed sanitized CIC profile report."""
    payload = profile.to_dict()
    if payload["combined"]["completed"] is not True:
        raise ValueError("cannot write an incomplete CIC dataset profile")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
