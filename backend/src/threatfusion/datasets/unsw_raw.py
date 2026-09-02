"""Streaming reader for the official headerless UNSW-NB15 raw CSV files."""

import csv
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

UNSW_RAW_COLUMN_COUNT = 49


class UnswStructureIssue(str, Enum):
    """Kinds of structural failure found before source-row adaptation."""

    INVALID_FEATURE_METADATA = "invalid_feature_metadata"
    DUPLICATE_FEATURE_NAME = "duplicate_feature_name"
    WRONG_RAW_COLUMN_COUNT = "wrong_raw_column_count"


class UnswStructureError(ValueError):
    """A safe structural error that never includes complete source-row values."""

    def __init__(
        self,
        path: Path,
        issue: UnswStructureIssue,
        *,
        row_number: int | None = None,
        detail: str,
    ) -> None:
        self.path = path
        self.issue = issue
        self.row_number = row_number
        self.detail = detail
        location = f"{path}"
        if row_number is not None:
            location += f" row {row_number}"
        super().__init__(f"{location}: {issue.value}: {detail}")


def normalize_unsw_feature_name(name: str) -> str:
    """Normalize official names to the lowercase, whitespace-free adapter keys."""
    return "".join(name.strip().lower().split())


def read_unsw_feature_names(path: Path) -> tuple[str, ...]:
    """Read the official ordered feature names, excluding its descriptive header."""
    names: list[str] = []
    seen: set[str] = set()

    with path.open(encoding="cp1252", newline="") as feature_file:
        reader = csv.reader(feature_file)
        next(reader, None)
        for row_number, row in enumerate(reader, start=2):
            if len(row) < 2:
                raise UnswStructureError(
                    path,
                    UnswStructureIssue.INVALID_FEATURE_METADATA,
                    row_number=row_number,
                    detail="feature metadata row must contain a name column",
                )
            name = normalize_unsw_feature_name(row[1])
            if not name:
                raise UnswStructureError(
                    path,
                    UnswStructureIssue.INVALID_FEATURE_METADATA,
                    row_number=row_number,
                    detail="normalized feature name must not be empty",
                )
            if name in seen:
                raise UnswStructureError(
                    path,
                    UnswStructureIssue.DUPLICATE_FEATURE_NAME,
                    row_number=row_number,
                    detail=f"normalized feature name {name!r} is duplicated",
                )
            names.append(name)
            seen.add(name)

    if len(names) != UNSW_RAW_COLUMN_COUNT:
        raise UnswStructureError(
            path,
            UnswStructureIssue.INVALID_FEATURE_METADATA,
            detail=(f"expected {UNSW_RAW_COLUMN_COUNT} unique feature names, found {len(names)}"),
        )
    return tuple(names)


@dataclass(frozen=True, slots=True)
class UnswRawReader:
    """Lazily map official raw values to ordered feature names across files."""

    feature_names: tuple[str, ...]
    raw_files: tuple[Path, ...]

    @classmethod
    def from_feature_file(cls, feature_file: Path, raw_files: Sequence[Path]) -> "UnswRawReader":
        return cls(
            feature_names=read_unsw_feature_names(feature_file),
            raw_files=tuple(raw_files),
        )

    def __post_init__(self) -> None:
        if len(self.feature_names) != UNSW_RAW_COLUMN_COUNT:
            raise UnswStructureError(
                Path("<feature_names>"),
                UnswStructureIssue.INVALID_FEATURE_METADATA,
                detail=(
                    f"expected {UNSW_RAW_COLUMN_COUNT} feature names, "
                    f"found {len(self.feature_names)}"
                ),
            )
        if len(set(self.feature_names)) != len(self.feature_names):
            raise UnswStructureError(
                Path("<feature_names>"),
                UnswStructureIssue.DUPLICATE_FEATURE_NAME,
                detail="normalized feature names must be unique",
            )

    def __iter__(self) -> Iterator[dict[str, str]]:
        for raw_file in self.raw_files:
            with raw_file.open(encoding="utf-8-sig", newline="") as csv_file:
                for row_number, values in enumerate(csv.reader(csv_file), start=1):
                    if len(values) != UNSW_RAW_COLUMN_COUNT:
                        raise UnswStructureError(
                            raw_file,
                            UnswStructureIssue.WRONG_RAW_COLUMN_COUNT,
                            row_number=row_number,
                            detail=(
                                f"expected {UNSW_RAW_COLUMN_COUNT} values, found {len(values)}"
                            ),
                        )
                    row = dict(zip(self.feature_names, values, strict=True))
                    row["flow_id"] = f"{raw_file.stem}:{row_number}"
                    yield row
