"""Generate the deterministic benign synthetic_lab development fixture."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.schemas.host_event import HostEventType  # noqa: E402

SESSION_STARTS: tuple[tuple[str, datetime], ...] = (
    ("synthetic-session-01.jsonl", datetime(2026, 1, 5, 9, 0, tzinfo=UTC)),
    ("synthetic-session-02.jsonl", datetime(2026, 1, 6, 13, 0, tzinfo=UTC)),
    ("synthetic-session-03.jsonl", datetime(2026, 1, 7, 17, 0, tzinfo=UTC)),
)
EVENT_SEQUENCE: tuple[HostEventType, ...] = (
    "process",
    "authentication",
    "file",
    "registry",
    "network",
    "privilege",
    "other",
    "process",
    "file",
    "network",
    "authentication",
    "registry",
    "privilege",
    "other",
)


def _event(
    source_file: str, session_number: int, row_number: int, start: datetime
) -> dict[str, object]:
    event_type = EVENT_SEQUENCE[row_number - 1]
    event: dict[str, object] = {
        "schema_version": "host_event_v1",
        "source_dataset": "synthetic_lab",
        "event_id": f"{source_file}:{row_number}",
        "timestamp": (start + timedelta(minutes=row_number - 1)).isoformat(),
        "host": f"synthetic-lab-host-{session_number:02d}",
        "event_type": event_type,
        "provider": "synthetic-windows-provider",
        "label": "Normal",
    }
    if event_type == "process":
        event["process_name"] = "synthetic-benign-process"
        event["parent_process_name"] = "synthetic-benign-parent"
    return event


def generate_baseline(output_directory: Path) -> tuple[Path, ...]:
    """Atomically write deterministic sessions one event at a time."""
    output_directory.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []
    for session_number, (source_file, start) in enumerate(SESSION_STARTS, start=1):
        destination = output_directory / source_file
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=output_directory, delete=False
        ) as handle:
            temporary_path = Path(handle.name)
            for row_number in range(1, len(EVENT_SEQUENCE) + 1):
                handle.write(
                    json.dumps(
                        _event(source_file, session_number, row_number, start),
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n"
                )
        temporary_path.replace(destination)
        outputs.append(destination)
    return tuple(outputs)


def _parser() -> argparse.ArgumentParser:
    project_root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=project_root / "data/raw/synthetic_lab/official",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Generate the baseline and print only safe basenames and event counts."""
    args = _parser().parse_args(argv)
    outputs = generate_baseline(args.output_directory)
    for path in outputs:
        print(f"{path.name}: events={len(EVENT_SEQUENCE)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
