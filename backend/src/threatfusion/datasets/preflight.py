"""Bounded-memory CSV compatibility checks before dataset adaptation."""

import csv
from dataclasses import dataclass
from pathlib import Path

MAX_SAMPLE_ROWS = 10


@dataclass(frozen=True)
class CsvPreflightReport:
    """Header, shape, and adapter-compatibility facts for one CSV file."""

    path: Path
    headers: tuple[str, ...]
    missing_required_aliases: tuple[tuple[str, ...], ...]
    row_count: int
    sampled_row_count: int
    sample_rows_well_formed: bool
    ready_for_streaming_adaptation: bool


def preflight_csv(
    path: Path,
    required_field_aliases: tuple[tuple[str, ...], ...],
    *,
    sample_rows: int = MAX_SAMPLE_ROWS,
) -> CsvPreflightReport:
    """Inspect a CSV header, at most ten row shapes, and count rows by streaming."""
    if not 0 <= sample_rows <= MAX_SAMPLE_ROWS:
        raise ValueError(f"sample_rows must be between 0 and {MAX_SAMPLE_ROWS}")

    with path.open(encoding="utf-8-sig", newline="") as csv_file:
        reader = csv.reader(csv_file)
        raw_headers = next(reader, [])
        headers = tuple(header.strip() for header in raw_headers)
        header_set = set(headers)
        missing_aliases = tuple(
            aliases
            for aliases in required_field_aliases
            if not any(alias in header_set for alias in aliases)
        )

        row_count = 0
        sampled_row_count = 0
        sample_rows_well_formed = True
        for row in reader:
            row_count += 1
            if sampled_row_count < sample_rows:
                sampled_row_count += 1
                sample_rows_well_formed &= len(row) == len(headers)

    ready = bool(headers) and not missing_aliases and sample_rows_well_formed
    return CsvPreflightReport(
        path=path,
        headers=headers,
        missing_required_aliases=missing_aliases,
        row_count=row_count,
        sampled_row_count=sampled_row_count,
        sample_rows_well_formed=sample_rows_well_formed,
        ready_for_streaming_adaptation=ready,
    )
