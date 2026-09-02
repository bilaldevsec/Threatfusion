import csv
import json
from pathlib import Path

import yaml
from scripts.validate_unsw_raw import (
    FEATURE_FILENAME,
    RAW_FILENAMES,
    REJECTION_EXAMPLE_LIMIT,
    run_validation,
    validate_raw_file,
)

from threatfusion.datasets.unsw_raw import UNSW_RAW_COLUMN_COUNT
from threatfusion.utils.checksum import sha256_file


def _feature_names() -> tuple[str, ...]:
    required = [
        "srcip",
        "sport",
        "dstip",
        "dsport",
        "proto",
        "dur",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "stime",
        "attack_cat",
        "label",
    ]
    required.extend(f"unused_{index}" for index in range(UNSW_RAW_COLUMN_COUNT - len(required)))
    return tuple(required)


def _row(*, source_ip: str = "192.0.2.1") -> list[str]:
    values = dict.fromkeys(_feature_names(), "0")
    values.update(
        srcip=source_ip,
        sport="0xc0a8",
        dstip="198.51.100.2",
        dsport="53",
        proto="udp",
        dur="0.25",
        spkts="2",
        dpkts="1",
        sbytes="120",
        dbytes="60",
        stime="1421927414",
        attack_cat="",
        label="0",
    )
    return [values[name] for name in _feature_names()]


def test_validate_raw_file_streams_counts_and_writes_sanitized_report(tmp_path: Path) -> None:
    raw_file = tmp_path / "UNSW-NB15_1.csv"
    with raw_file.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerows([_row(), _row(source_ip="private raw value")])
    report_path = tmp_path / "reports" / "quality.json"

    result = validate_raw_file(raw_file, _feature_names(), report_path)

    assert result.report.total_rows == 2
    assert result.report.accepted_count == 1
    assert result.report.rejected_count == 1
    assert result.report.rejection_example_limit == REJECTION_EXAMPLE_LIMIT
    assert result.size_bytes == raw_file.stat().st_size
    assert result.sha256 == sha256_file(raw_file)
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["rejection_details"] == [
        {"fields": ["srcip"], "reason": "must be a valid IP address", "row_number": 2}
    ]
    assert "private raw value" not in report_path.read_text(encoding="utf-8")
    assert not list(tmp_path.rglob("*.parquet"))
    assert not list(tmp_path.rglob("*.pkl"))


def test_run_validation_updates_existing_manifest_with_fixture_inputs(tmp_path: Path) -> None:
    raw_directory = tmp_path / "data/raw/unsw_nb15/official"
    raw_directory.mkdir(parents=True)
    feature_file = raw_directory / FEATURE_FILENAME
    with feature_file.open("w", encoding="cp1252", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["No.", "Name", "Type", "Description"])
        writer.writerows(
            [index, name, "nominal", "fixture"]
            for index, name in enumerate(_feature_names(), start=1)
        )
    for filename in RAW_FILENAMES:
        with (raw_directory / filename).open("w", encoding="utf-8", newline="") as handle:
            csv.writer(handle).writerow(_row())
    manifest_path = tmp_path / "data/manifests/unsw_nb15.yaml"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        yaml.safe_dump(
            {
                "name": "unsw_nb15",
                "version": "fixture",
                "license_note": "fixture only",
                "files": [
                    {
                        "path": "data/raw/unsw_nb15/existing.csv",
                        "sha256": None,
                        "rows": 3,
                        "role": "sample",
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    results = run_validation(
        project_root=tmp_path,
        raw_directory=raw_directory,
        report_directory=tmp_path / "artifacts/reports",
        manifest_path=manifest_path,
    )

    assert [result.report.total_rows for result in results] == [1, 1, 1, 1]
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    assert [item["path"] for item in manifest["files"]] == [
        "data/raw/unsw_nb15/existing.csv",
        "data/raw/unsw_nb15/official/NUSW-NB15_features.csv",
        *(f"data/raw/unsw_nb15/official/{filename}" for filename in RAW_FILENAMES),
    ]
    assert [item["rows"] for item in manifest["files"][-4:]] == [1, 1, 1, 1]
    assert all(len(item["sha256"]) == 64 for item in manifest["files"][-5:])
