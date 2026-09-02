import csv
import json
from pathlib import Path
from typing import Any

import pytest
from scripts.validate_cic_benchmark import (
    REJECTION_EXAMPLE_LIMIT,
    validate_cic_benchmark_file,
)

from threatfusion.datasets.cic_processed import CIC_PROCESSED_HEADERS
from threatfusion.datasets.manifests import load_dataset_manifest

PROJECT_ROOT = Path(__file__).parents[3]


def _values(label: str, marker: str = "0") -> list[str]:
    values = [marker] * len(CIC_PROCESSED_HEADERS)
    replacements = {
        "Dst Port": "443",
        "Protocol": "6",
        "Timestamp": "14/02/2018 08:31:01",
        "Flow Duration": "1000000",
        "Tot Fwd Pkts": "1",
        "Tot Bwd Pkts": "1",
        "TotLen Fwd Pkts": "100",
        "TotLen Bwd Pkts": "100",
        "Label": label,
    }
    for header, value in replacements.items():
        values[CIC_PROCESSED_HEADERS.index(header)] = value
    return values


def _write_csv(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CIC_PROCESSED_HEADERS)
        writer.writerows(rows)


def test_tracked_manifest_declares_exact_external_validation_subset() -> None:
    manifest = load_dataset_manifest(PROJECT_ROOT / "data/manifests/cse_cic_ids2018.yaml")

    assert manifest.name == "cse_cic_ids2018"
    assert [item.role for item in manifest.files] == ["validation", "validation"]
    assert [item.rows for item in manifest.files] == [1048575, 1048575]
    assert [item.sha256 for item in manifest.files] == [
        "acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147",
        "fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b",
    ]
    assert all(not item.path.is_absolute() for item in manifest.files)
    assert "external feature-benchmark" in str(manifest.notes)


def test_full_consumption_creates_sanitized_bounded_json_report(tmp_path: Path) -> None:
    source_path = tmp_path / "tiny.csv"
    rows = [_values("Benign", marker="sensitive-accepted")]
    rows.extend(_values("TOP-SECRET-LABEL", marker="sensitive-rejected") for _ in range(25))
    rows[0][CIC_PROCESSED_HEADERS.index("Flow IAT Mean")] = "192.0.2.123"
    _write_csv(source_path, rows)
    report_path = tmp_path / "new" / "reports" / "quality.json"

    result = validate_cic_benchmark_file(
        source_path,
        report_path,
        expected_rows=len(rows),
    )

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert result.payload["completed"] is True
    assert payload["completed"] is True
    assert payload["total_rows"] == 26
    assert payload["accepted_count"] == 1
    assert payload["rejected_count"] == 25
    assert payload["canonical_label_counts"] == {"Normal": 1}
    assert len(payload["rejection_details"]) == REJECTION_EXAMPLE_LIMIT
    assert {detail["reason"] for detail in payload["rejection_details"]} == {
        "source row validation failed"
    }
    report_text = report_path.read_text(encoding="utf-8")
    assert "TOP-SECRET-LABEL" not in report_text
    assert "sensitive-accepted" not in report_text
    assert "sensitive-rejected" not in report_text
    assert "192.0.2.123" not in report_text
    assert "443" not in report_text
    assert "14/02/2018 08:31:01" not in report_text
    assert ",".join(rows[0]) not in report_text
    assert str(tmp_path) not in report_text
    assert "src_ip" not in report_text
    assert "dst_ip" not in report_text
    assert not list(tmp_path.rglob("*.parquet"))


def test_unexpected_adapter_exception_propagates(tmp_path: Path) -> None:
    source_path = tmp_path / "tiny.csv"
    _write_csv(source_path, [_values("Benign")])

    def broken_adapter(row: dict[str, Any]) -> Any:
        raise RuntimeError("programming defect")

    with pytest.raises(RuntimeError, match="programming defect"):
        validate_cic_benchmark_file(
            source_path,
            tmp_path / "unused.json",
            expected_rows=1,
            adapter=broken_adapter,
        )

    assert not (tmp_path / "unused.json").exists()
