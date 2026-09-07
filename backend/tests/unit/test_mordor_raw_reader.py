import json
from pathlib import Path

import pytest

from threatfusion.datasets.adapters.mordor import adapt_mordor_row
from threatfusion.datasets.mordor_raw import (
    MORDOR_INGESTION_ID_FIELD,
    MordorNdjsonReader,
    MordorStructureError,
    MordorStructureIssue,
)


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_streams_objects_in_order_with_deterministic_ingestion_ids(tmp_path: Path) -> None:
    path = tmp_path / "tiny.json"
    _write_lines(path, [json.dumps({"marker": "first"}), json.dumps({"marker": "second"})])

    rows = MordorNdjsonReader(path)

    assert [row[MORDOR_INGESTION_ID_FIELD] for row in rows] == [
        "tiny.json:1",
        "tiny.json:2",
    ]


def test_reader_and_adapter_accept_official_hostname_shape(tmp_path: Path) -> None:
    path = tmp_path / "tiny.json"
    _write_lines(
        path,
        [
            json.dumps(
                {
                    "@timestamp": "2020-10-29T20:23:24.000Z",
                    "Hostname": "fixture-host",
                    "EventID": 1,
                    "Image": "process-image",
                }
            )
        ],
    )

    event = adapt_mordor_row(next(iter(MordorNdjsonReader(path))))

    assert event.event_id == "tiny.json:1"
    assert event.host == "fixture-host"
    assert event.event_type == "process"


@pytest.mark.parametrize(
    ("line", "issue"),
    [
        ("", MordorStructureIssue.BLANK_LINE),
        ("not-json", MordorStructureIssue.INVALID_JSON),
        ("[]", MordorStructureIssue.NON_OBJECT_EVENT),
        (
            json.dumps({MORDOR_INGESTION_ID_FIELD: "source-controlled"}),
            MordorStructureIssue.RESERVED_FIELD_COLLISION,
        ),
    ],
)
def test_structural_errors_are_sanitized(
    tmp_path: Path, line: str, issue: MordorStructureIssue
) -> None:
    path = tmp_path / "tiny.json"
    path.write_text(line + "\n", encoding="utf-8")

    with pytest.raises(MordorStructureError) as error:
        next(iter(MordorNdjsonReader(path)))

    assert error.value.issue is issue
    assert error.value.path == Path("tiny.json")
    assert error.value.row_number == 1
    assert "source-controlled" not in str(error.value)
    assert str(tmp_path) not in str(error.value)


def test_file_is_opened_lazily(tmp_path: Path) -> None:
    rows = iter(MordorNdjsonReader(tmp_path / "missing.json"))

    assert rows is not None
    with pytest.raises(FileNotFoundError):
        next(rows)
