"""Constant-memory reader for official processed CSE-CIC-IDS2018 CSV files."""

import csv
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

CIC_PROCESSED_COLUMN_COUNT = 80
CIC_SOURCE_FILE_FIELD = "__source_file"
CIC_SOURCE_ROW_NUMBER_FIELD = "__source_row_number"

CIC_PROCESSED_HEADERS: tuple[str, ...] = (
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Tot",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Tot",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Len",
    "Bwd Header Len",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Pkt Len Min",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Len Var",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "CWE Flag Count",
    "ECE Flag Cnt",
    "Down/Up Ratio",
    "Pkt Size Avg",
    "Fwd Seg Size Avg",
    "Bwd Seg Size Avg",
    "Fwd Byts/b Avg",
    "Fwd Pkts/b Avg",
    "Fwd Blk Rate Avg",
    "Bwd Byts/b Avg",
    "Bwd Pkts/b Avg",
    "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts",
    "Subflow Fwd Byts",
    "Subflow Bwd Pkts",
    "Subflow Bwd Byts",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    "Label",
)


class CicStructureIssue(str, Enum):
    """Sanitized structural failures for processed CIC files."""

    BLANK_HEADER = "blank_header"
    DUPLICATE_HEADER = "duplicate_header"
    INCORRECT_HEADER_COUNT = "incorrect_header_count"
    MISSING_HEADER = "missing_header"
    UNEXPECTED_HEADER = "unexpected_header"
    INCORRECT_ROW_WIDTH = "incorrect_row_width"


class CicStructureError(ValueError):
    """A structural error that never includes raw row contents."""

    def __init__(
        self,
        path: Path,
        issue: CicStructureIssue,
        *,
        row_number: int | None = None,
        detail: str,
    ) -> None:
        self.path = Path(path.name)
        self.issue = issue
        self.row_number = row_number
        self.detail = detail
        location = path.name
        if row_number is not None:
            location += f" row {row_number}"
        super().__init__(f"{location}: {issue.value}: {detail}")


def normalize_cic_header(header: str) -> str:
    """Remove deterministic surrounding whitespace without changing header meaning."""
    return header.strip()


def validate_cic_headers(path: Path, raw_headers: list[str]) -> tuple[str, ...]:
    """Validate the exact official processed-CIC header set."""
    headers = tuple(normalize_cic_header(header) for header in raw_headers)
    if any(not header for header in headers):
        raise CicStructureError(path, CicStructureIssue.BLANK_HEADER, detail="header is blank")
    if len(set(headers)) != len(headers):
        raise CicStructureError(
            path, CicStructureIssue.DUPLICATE_HEADER, detail="header names must be unique"
        )
    if len(headers) != CIC_PROCESSED_COLUMN_COUNT:
        raise CicStructureError(
            path,
            CicStructureIssue.INCORRECT_HEADER_COUNT,
            detail=f"expected {CIC_PROCESSED_COLUMN_COUNT} headers, found {len(headers)}",
        )
    missing = sorted(set(CIC_PROCESSED_HEADERS).difference(headers))
    if missing:
        raise CicStructureError(
            path,
            CicStructureIssue.MISSING_HEADER,
            detail=f"missing required header(s): {', '.join(missing)}",
        )
    unexpected = sorted(set(headers).difference(CIC_PROCESSED_HEADERS))
    if unexpected:
        raise CicStructureError(
            path,
            CicStructureIssue.UNEXPECTED_HEADER,
            detail=f"found {len(unexpected)} unexpected header(s)",
        )
    return headers


@dataclass(frozen=True, slots=True)
class CicProcessedReader:
    """Yield rows lazily; callers retaining a partial iterator must close it."""

    path: Path

    def __iter__(self) -> Iterator[dict[str, str | int]]:
        with self.path.open(encoding="utf-8", errors="strict", newline="") as csv_file:
            reader = csv.reader(csv_file)
            headers = validate_cic_headers(self.path, next(reader, []))
            for row_number, values in enumerate(reader, start=1):
                if len(values) != len(headers):
                    raise CicStructureError(
                        self.path,
                        CicStructureIssue.INCORRECT_ROW_WIDTH,
                        row_number=row_number,
                        detail=f"expected {len(headers)} values, found {len(values)}",
                    )
                row: dict[str, str | int] = dict(zip(headers, values, strict=True))
                row[CIC_SOURCE_FILE_FIELD] = self.path.name
                row[CIC_SOURCE_ROW_NUMBER_FIELD] = row_number
                yield row
