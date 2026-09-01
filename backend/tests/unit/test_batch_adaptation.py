import json
from typing import Any

import pytest
from pydantic import BaseModel, Field

from threatfusion.datasets.adapters.base import SourceRowValidationError
from threatfusion.datasets.batch import (
    BatchQualityReport,
    stream_adapt_rows,
    write_quality_report,
)


class CanonicalItem(BaseModel):
    identifier: int = Field(gt=0)


def _adapter(row: dict[str, Any]) -> CanonicalItem:
    if "identifier" not in row:
        raise SourceRowValidationError("test-source", "identifier", "required value is missing")
    return CanonicalItem(identifier=row["identifier"])


def test_mixed_rows_yield_valid_records_in_original_order_and_report_counts() -> None:
    rows = [
        {"identifier": 3},
        {"secret": "must-not-leak"},
        {"identifier": 1},
        {"identifier": 0},
        {"identifier": 2},
    ]
    report = BatchQualityReport(source="test-source")

    records = list(stream_adapt_rows(rows, _adapter, report))

    assert [record.identifier for record in records] == [3, 1, 2]
    assert report.total_rows == 5
    assert report.accepted_count == 3
    assert report.rejected_count == 2
    assert report.completed is True
    assert report.rejection_rate == pytest.approx(0.4)
    assert [detail.row_number for detail in report.rejection_details] == [2, 4]


def test_empty_input_has_zero_counts_and_rejection_rate() -> None:
    report = BatchQualityReport(source="test-source")

    assert list(stream_adapt_rows([], _adapter, report)) == []
    assert report.total_rows == 0
    assert report.accepted_count == 0
    assert report.rejected_count == 0
    assert report.rejection_rate == 0.0
    assert report.completed is True


def test_partially_consumed_iterator_is_not_completed() -> None:
    report = BatchQualityReport(source="test-source")
    records = stream_adapt_rows([{"identifier": 1}, {"identifier": 2}], _adapter, report)

    assert report.completed is False
    assert next(records).identifier == 1
    assert report.completed is False


def test_writing_partial_report_raises_value_error(tmp_path: Any) -> None:
    report = BatchQualityReport(source="test-source")
    records = stream_adapt_rows([{"identifier": 1}, {"identifier": 2}], _adapter, report)
    next(records)
    report_path = tmp_path / "quality.json"

    with pytest.raises(ValueError, match="incomplete"):
        write_quality_report(report, report_path)

    assert not report_path.exists()


def test_rejection_sample_limit_does_not_limit_rejected_count() -> None:
    report = BatchQualityReport(source="test-source", rejection_example_limit=2)

    assert list(stream_adapt_rows([{}, {}, {}, {}], _adapter, report)) == []
    assert report.rejected_count == 4
    assert len(report.rejection_details) == 2
    assert [detail.row_number for detail in report.rejection_details] == [1, 2]


def test_pydantic_schema_rejection_records_fields_without_input() -> None:
    report = BatchQualityReport(source="test-source")

    assert (
        list(stream_adapt_rows([{"identifier": 0, "secret": "raw-secret"}], _adapter, report)) == []
    )

    detail = report.rejection_details[0]
    assert detail.fields == ("identifier",)
    assert "greater_than" in detail.reason
    assert "raw-secret" not in json.dumps(report.to_dict())
    assert "secret" not in json.dumps(report.to_dict())


def test_unexpected_adapter_exception_propagates() -> None:
    def broken_adapter(row: dict[str, Any]) -> CanonicalItem:
        raise RuntimeError("programming defect")

    report = BatchQualityReport(source="test-source")

    with pytest.raises(RuntimeError, match="programming defect"):
        list(stream_adapt_rows([{"identifier": 1}], broken_adapter, report))

    assert report.total_rows == 1
    assert report.accepted_count == 0
    assert report.rejected_count == 0
    assert report.completed is False


def test_custom_source_rejection_reason_is_sanitized(tmp_path: Any) -> None:
    def unsafe_adapter(row: dict[str, Any]) -> CanonicalItem:
        raise SourceRowValidationError("test-source", "identifier", "TOP-SECRET custom detail")

    report = BatchQualityReport(source="test-source")
    list(stream_adapt_rows([{"identifier": 1}], unsafe_adapter, report))
    report_path = tmp_path / "quality.json"
    write_quality_report(report, report_path)

    payload = report.to_dict()
    assert payload["rejection_details"][0]["reason"] == "source row validation failed"
    assert "TOP-SECRET" not in json.dumps(payload)
    assert "TOP-SECRET" not in report_path.read_text(encoding="utf-8")


def test_json_report_writes_to_new_parent_directory(tmp_path: Any) -> None:
    report = BatchQualityReport(source="test-source")
    list(stream_adapt_rows([{"identifier": 1}, {}], _adapter, report))
    report_path = tmp_path / "nested" / "quality.json"

    write_quality_report(report, report_path)

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload == {
        "accepted_count": 1,
        "completed": True,
        "rejected_count": 1,
        "rejection_details": [
            {
                "fields": ["identifier"],
                "reason": "required value is missing",
                "row_number": 2,
            }
        ],
        "rejection_rate": 0.5,
        "source": "test-source",
        "total_rows": 2,
    }
    assert 'identifier": 1' not in report_path.read_text(encoding="utf-8")
