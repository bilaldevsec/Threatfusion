import csv
from pathlib import Path

import pytest

from threatfusion.datasets.adapters.unsw_nb15 import UNSW_REQUIRED_FIELD_ALIASES
from threatfusion.datasets.preflight import MAX_SAMPLE_ROWS, preflight_csv


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(headers)
        writer.writerows(rows)


def test_preflight_reports_compatible_csv_without_retaining_all_rows(tmp_path: Path) -> None:
    path = tmp_path / "compatible.csv"
    headers = [aliases[0] for aliases in UNSW_REQUIRED_FIELD_ALIASES]
    _write_csv(path, headers, [[str(index)] * len(headers) for index in range(12)])

    report = preflight_csv(path, UNSW_REQUIRED_FIELD_ALIASES)

    assert report.headers == tuple(headers)
    assert report.missing_required_aliases == ()
    assert report.row_count == 12
    assert report.sampled_row_count == MAX_SAMPLE_ROWS
    assert report.sample_rows_well_formed
    assert report.ready_for_streaming_adaptation


def test_preflight_accepts_adapter_aliases_and_reports_missing_groups(tmp_path: Path) -> None:
    path = tmp_path / "aliases.csv"
    headers = [aliases[0] for aliases in UNSW_REQUIRED_FIELD_ALIASES]
    headers[0] = "flow_id"
    headers[1] = "timestamp"
    headers.remove("srcip")
    _write_csv(path, headers, [["value"] * len(headers)])

    report = preflight_csv(path, UNSW_REQUIRED_FIELD_ALIASES)

    assert report.missing_required_aliases == (("srcip",),)
    assert report.row_count == 1
    assert not report.ready_for_streaming_adaptation


def test_preflight_marks_a_malformed_sample_row_not_ready(tmp_path: Path) -> None:
    path = tmp_path / "malformed.csv"
    _write_csv(path, ["id", "label"], [["1"]])

    report = preflight_csv(path, (("id",), ("label",)))

    assert not report.sample_rows_well_formed
    assert not report.ready_for_streaming_adaptation


def test_preflight_rejects_samples_over_ten_rows(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="between 0 and 10"):
        preflight_csv(tmp_path / "unused.csv", (("id",),), sample_rows=11)
