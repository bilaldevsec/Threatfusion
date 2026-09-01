"""Streaming dataset adaptation with bounded data-quality reporting."""

import json
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from pydantic import ValidationError

from threatfusion.datasets.adapters.base import SourceRowValidationError

CanonicalRecord = TypeVar("CanonicalRecord")
SourceRow = dict[str, Any]


@dataclass(frozen=True, slots=True)
class RejectionDetail:
    """Non-sensitive summary of one rejected source row."""

    row_number: int
    fields: tuple[str, ...]
    reason: str


@dataclass(slots=True)
class BatchQualityReport:
    """Mutable accounting state for one streaming adaptation pass."""

    source: str
    rejection_example_limit: int = 20
    completed: bool = False
    total_rows: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    rejection_details: list[RejectionDetail] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.rejection_example_limit < 0:
            raise ValueError("rejection_example_limit must be greater than or equal to zero")

    @property
    def rejection_rate(self) -> float:
        """Return rejected rows as a fraction of all processed rows."""
        if self.total_rows == 0:
            return 0.0
        return self.rejected_count / self.total_rows

    def to_dict(self) -> dict[str, Any]:
        """Build a JSON-safe report without source-row data."""
        return {
            "source": self.source,
            "completed": self.completed,
            "total_rows": self.total_rows,
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "rejection_rate": self.rejection_rate,
            "rejection_details": [asdict(detail) for detail in self.rejection_details],
        }


def stream_adapt_rows(
    rows: Iterable[SourceRow],
    adapter: Callable[[SourceRow], CanonicalRecord],
    report: BatchQualityReport,
) -> Iterator[CanonicalRecord]:
    """Adapt rows lazily while updating bounded rejection accounting."""
    report.completed = False

    def adapt_rows() -> Iterator[CanonicalRecord]:
        for row_number, row in enumerate(rows, start=1):
            report.total_rows += 1
            try:
                record = adapter(row)
            except SourceRowValidationError as exc:
                report.rejected_count += 1
                _sample_rejection(
                    report,
                    RejectionDetail(
                        row_number=row_number,
                        fields=exc.fields,
                        reason=_safe_source_rejection_reason(exc.reason),
                    ),
                )
                continue
            except ValidationError as exc:
                report.rejected_count += 1
                _sample_rejection(report, _pydantic_rejection(row_number, exc))
                continue

            report.accepted_count += 1
            yield record

        report.completed = True

    return adapt_rows()


def write_quality_report(report: BatchQualityReport, path: str | Path) -> None:
    """Write a completed quality report as JSON to a caller-selected path."""
    if not report.completed:
        raise ValueError("cannot write an incomplete quality report")

    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sample_rejection(report: BatchQualityReport, detail: RejectionDetail) -> None:
    if len(report.rejection_details) < report.rejection_example_limit:
        report.rejection_details.append(detail)


_SAFE_SOURCE_REJECTION_REASONS = frozenset(
    {
        "required value is missing",
        "required value is blank",
        "no valid alias value is present",
        "must be an integer",
        "must be a finite integer",
        "must be numeric",
        "must be a valid IP address",
        "required timestamp is missing",
        "must be a parseable timestamp",
    }
)


def _safe_source_rejection_reason(reason: str) -> str:
    if reason in _SAFE_SOURCE_REJECTION_REASONS:
        return reason
    if re.fullmatch(r"must be (?:between .+ and .+|>= .+)", reason):
        return "must be within allowed integer bounds"
    if re.fullmatch(r"must be finite and >= .+", reason):
        return "must be finite and within allowed numeric bounds"
    return "source row validation failed"


def _pydantic_rejection(row_number: int, error: ValidationError) -> RejectionDetail:
    errors = error.errors(include_url=False, include_context=False, include_input=False)
    fields = tuple(dict.fromkeys(".".join(str(part) for part in item["loc"]) for item in errors))
    error_types = tuple(dict.fromkeys(str(item["type"]) for item in errors))
    return RejectionDetail(
        row_number=row_number,
        fields=fields or ("schema",),
        reason=f"schema validation failed ({', '.join(error_types)})",
    )
