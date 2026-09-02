import csv
from pathlib import Path

import pytest

from threatfusion.datasets.unsw_raw import (
    UNSW_RAW_COLUMN_COUNT,
    UnswRawReader,
    UnswStructureError,
    UnswStructureIssue,
    read_unsw_feature_names,
)


def _feature_rows(names: list[str]) -> list[list[str]]:
    return [[str(index), name, "type", "description"] for index, name in enumerate(names, 1)]


def _write_csv(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        csv.writer(csv_file).writerows(rows)


def _write_features(path: Path, names: list[str]) -> None:
    _write_csv(path, [["No.", "Name", "Type", "Description"], *_feature_rows(names)])


def _names() -> list[str]:
    return [f"feature_{index}" for index in range(UNSW_RAW_COLUMN_COUNT)]


def test_reads_official_feature_order_while_ignoring_descriptive_header(tmp_path: Path) -> None:
    path = tmp_path / "features.csv"
    names = _names()
    _write_features(path, names)

    assert read_unsw_feature_names(path) == tuple(names)


def test_normalizes_feature_whitespace_and_case(tmp_path: Path) -> None:
    path = tmp_path / "features.csv"
    names = _names()
    names[:4] = [" SrcIP ", "SLOAD", " Spkts ", "ct_src_ ltm"]
    _write_features(path, names)

    parsed = read_unsw_feature_names(path)

    assert parsed[:4] == ("srcip", "sload", "spkts", "ct_src_ltm")


def test_maps_headerless_values_and_adds_deterministic_flow_id(tmp_path: Path) -> None:
    raw_file = tmp_path / "UNSW-NB15_1.csv"
    values = [f"value-{index}" for index in range(UNSW_RAW_COLUMN_COUNT)]
    _write_csv(raw_file, [values])

    row = next(iter(UnswRawReader(tuple(_names()), (raw_file,))))

    assert row["feature_0"] == "value-0"
    assert row["feature_48"] == "value-48"
    assert row["flow_id"] == "UNSW-NB15_1:1"


def test_preserves_file_and_row_order(tmp_path: Path) -> None:
    first = tmp_path / "UNSW-NB15_1.csv"
    second = tmp_path / "UNSW-NB15_2.csv"
    _write_csv(first, [["first"] * 49, ["second"] * 49])
    _write_csv(second, [["third"] * 49])

    rows = UnswRawReader(tuple(_names()), (first, second))

    assert [(row["flow_id"], row["feature_0"]) for row in rows] == [
        ("UNSW-NB15_1:1", "first"),
        ("UNSW-NB15_1:2", "second"),
        ("UNSW-NB15_2:1", "third"),
    ]


@pytest.mark.parametrize("column_count", [48, 50])
def test_rejects_wrong_raw_row_column_count(tmp_path: Path, column_count: int) -> None:
    raw_file = tmp_path / "UNSW-NB15_1.csv"
    _write_csv(raw_file, [["secret-value"] * column_count])

    with pytest.raises(UnswStructureError) as error:
        next(iter(UnswRawReader(tuple(_names()), (raw_file,))))

    assert error.value.issue is UnswStructureIssue.WRONG_RAW_COLUMN_COUNT
    assert error.value.path == raw_file
    assert error.value.row_number == 1
    assert "secret-value" not in str(error.value)


def test_rejects_invalid_feature_count(tmp_path: Path) -> None:
    path = tmp_path / "features.csv"
    _write_features(path, _names()[:-1])

    with pytest.raises(UnswStructureError) as error:
        read_unsw_feature_names(path)

    assert error.value.issue is UnswStructureIssue.INVALID_FEATURE_METADATA
    assert error.value.row_number is None


def test_rejects_duplicate_normalized_feature_names(tmp_path: Path) -> None:
    path = tmp_path / "features.csv"
    names = _names()
    names[-1] = " FEATURE_0 "
    _write_features(path, names)

    with pytest.raises(UnswStructureError) as error:
        read_unsw_feature_names(path)

    assert error.value.issue is UnswStructureIssue.DUPLICATE_FEATURE_NAME
    assert error.value.row_number == 50


def test_raw_files_are_opened_lazily(tmp_path: Path) -> None:
    raw_file = tmp_path / "UNSW-NB15_1.csv"
    reader = UnswRawReader(tuple(_names()), (raw_file,))

    rows = iter(reader)

    assert rows is not None
    with pytest.raises(FileNotFoundError):
        next(rows)
