import csv
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from threatfusion.datasets.cic_processed import (
    CIC_PROCESSED_HEADERS,
    CicProcessedReader,
    CicStructureError,
    CicStructureIssue,
)


def _write(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)


def _values(marker: str = "first") -> list[str]:
    values = ["0"] * len(CIC_PROCESSED_HEADERS)
    values[CIC_PROCESSED_HEADERS.index("Timestamp")] = "14/02/2018 08:31:01"
    values[CIC_PROCESSED_HEADERS.index("Label")] = marker
    return values


def test_normalizes_header_whitespace_and_streams_rows_with_provenance(tmp_path: Path) -> None:
    path = tmp_path / "fixture.csv"
    headers = [f"  {header}  " for header in CIC_PROCESSED_HEADERS]
    _write(path, headers, [_values("first"), _values("second")])

    rows = CicProcessedReader(path)

    assert [(row["Label"], row["__source_row_number"]) for row in rows] == [
        ("first", 1),
        ("second", 2),
    ]
    assert next(iter(CicProcessedReader(path)))["__source_file"] == "fixture.csv"


@pytest.mark.parametrize(
    ("mutate", "issue"),
    [
        (lambda headers: headers.__setitem__(0, ""), CicStructureIssue.BLANK_HEADER),
        (
            lambda headers: headers.__setitem__(-1, headers[0]),
            CicStructureIssue.DUPLICATE_HEADER,
        ),
        (lambda headers: headers.pop(), CicStructureIssue.INCORRECT_HEADER_COUNT),
        (lambda headers: headers.__setitem__(-1, "Not Label"), CicStructureIssue.MISSING_HEADER),
    ],
)
def test_rejects_invalid_headers_safely(
    tmp_path: Path, mutate: Callable[[list[str]], None], issue: CicStructureIssue
) -> None:
    path = tmp_path / "fixture.csv"
    headers = list(CIC_PROCESSED_HEADERS)
    mutate(headers)
    _write(path, headers, [])

    with pytest.raises(CicStructureError) as error:
        next(iter(CicProcessedReader(path)))

    assert error.value.issue is issue


def test_rejects_incorrect_row_width_without_exposing_values(tmp_path: Path) -> None:
    path = tmp_path / "fixture.csv"
    _write(path, list(CIC_PROCESSED_HEADERS), [["sensitive-value"] * 79])

    with pytest.raises(CicStructureError) as error:
        next(iter(CicProcessedReader(path)))

    assert error.value.issue is CicStructureIssue.INCORRECT_ROW_WIDTH
    assert error.value.row_number == 1
    assert "sensitive-value" not in str(error.value)


def test_structural_errors_expose_only_the_source_basename(tmp_path: Path) -> None:
    parent = tmp_path / "private-parent"
    parent.mkdir()
    path = parent / "fixture.csv"
    headers = list(CIC_PROCESSED_HEADERS)
    headers[0] = ""
    _write(path, headers, [])

    with pytest.raises(CicStructureError) as error:
        next(iter(CicProcessedReader(path.absolute())))

    assert error.value.path == Path("fixture.csv")
    assert "private-parent" not in str(error.value)
    assert str(parent) not in str(error.value)


def test_partially_consumed_iterator_can_be_closed_explicitly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "fixture.csv"
    _write(path, list(CIC_PROCESSED_HEADERS), [_values()])
    opened_handles: list[Any] = []
    original_open = Path.open

    def tracking_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        handle = original_open(self, *args, **kwargs)
        opened_handles.append(handle)
        return handle

    monkeypatch.setattr(Path, "open", tracking_open)
    iterator = iter(CicProcessedReader(path))

    next(iterator)
    assert not opened_handles[0].closed
    iterator.close()

    assert opened_handles[0].closed
