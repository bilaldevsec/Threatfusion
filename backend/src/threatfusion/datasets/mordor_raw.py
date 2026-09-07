"""Constant-memory reader for official Mordor newline-delimited JSON events."""

import json
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

MORDOR_INGESTION_ID_FIELD = "__mordor_ingestion_id"


class MordorStructureIssue(str, Enum):
    """Sanitized structural failures for Mordor NDJSON files."""

    BLANK_LINE = "blank_line"
    INVALID_JSON = "invalid_json"
    NON_OBJECT_EVENT = "non_object_event"
    RESERVED_FIELD_COLLISION = "reserved_field_collision"


class MordorStructureError(ValueError):
    """A structural error that never contains source-event values."""

    def __init__(
        self,
        path: Path,
        issue: MordorStructureIssue,
        *,
        row_number: int,
        detail: str,
    ) -> None:
        self.path = Path(path.name)
        self.issue = issue
        self.row_number = row_number
        self.detail = detail
        super().__init__(f"{path.name} row {row_number}: {issue.value}: {detail}")


@dataclass(frozen=True, slots=True)
class MordorNdjsonReader:
    """Yield Mordor objects lazily with deterministic ingestion provenance."""

    path: Path

    def __iter__(self) -> Iterator[dict[str, Any]]:
        with self.path.open(encoding="utf-8", errors="strict") as source_file:
            for row_number, line in enumerate(source_file, start=1):
                if not line.strip():
                    raise MordorStructureError(
                        self.path,
                        MordorStructureIssue.BLANK_LINE,
                        row_number=row_number,
                        detail="event line must not be blank",
                    )
                try:
                    event: Any = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise MordorStructureError(
                        self.path,
                        MordorStructureIssue.INVALID_JSON,
                        row_number=row_number,
                        detail="event line must contain valid JSON",
                    ) from exc
                if not isinstance(event, dict):
                    raise MordorStructureError(
                        self.path,
                        MordorStructureIssue.NON_OBJECT_EVENT,
                        row_number=row_number,
                        detail="event must be a JSON object",
                    )
                if MORDOR_INGESTION_ID_FIELD in event:
                    raise MordorStructureError(
                        self.path,
                        MordorStructureIssue.RESERVED_FIELD_COLLISION,
                        row_number=row_number,
                        detail="event contains a reserved provenance field",
                    )
                event[MORDOR_INGESTION_ID_FIELD] = f"{self.path.name}:{row_number}"
                yield event
