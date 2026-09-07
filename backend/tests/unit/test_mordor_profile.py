import json
from pathlib import Path
from typing import Any

from threatfusion.datasets.mordor_profile import (
    EVENT_ID_CATEGORY_LIMIT,
    REJECTION_EXAMPLE_LIMIT,
    SAFE_PRESENCE_FIELDS,
    profile_mordor_rows,
    write_mordor_profile,
)
from threatfusion.datasets.mordor_raw import MORDOR_INGESTION_ID_FIELD


def _row(index: int, **updates: Any) -> dict[str, Any]:
    row = {
        MORDOR_INGESTION_ID_FIELD: f"fixture.json:{index}",
        "@timestamp": f"2020-10-29T20:23:{index:02d}.000Z",
        "Hostname": "fixture-host",
        "EventID": 7,
        "CommandLine": "TOP-SECRET-COMMAND",
        "User": "SECRET-USER",
        "SourceIp": "192.0.2.10",
    }
    row.update(updates)
    return row


def test_profile_has_exact_safe_aggregates_and_timestamp_range() -> None:
    profile = profile_mordor_rows(
        [
            _row(1, EventID=1, Image="process-image"),
            _row(2, EventID="7", TimeCreated="2020-10-29T20:22:00.000Z"),
            _row(3, EventID=3, **{"@timestamp": "2020-10-29T20:25:00.000Z"}),
        ],
        "fixture.json",
    )
    payload = profile.to_dict()

    assert payload["total_rows"] == 3
    assert payload["accepted_count"] == 3
    assert payload["rejected_count"] == 0
    assert payload["completed"] is True
    assert payload["event_id_counts"] == {"1": 1, "3": 1, "7": 1}
    assert payload["event_id_overflow_count"] == 0
    assert payload["process_event_count"] == 1
    assert payload["field_presence_counts"]["EventID"] == 3
    assert tuple(payload["field_presence_counts"]) == SAFE_PRESENCE_FIELDS
    assert payload["earliest_timestamp"] == "2020-10-29T20:23:01+00:00"
    assert payload["latest_timestamp"] == "2020-10-29T20:25:00+00:00"


def test_profile_rejections_are_bounded_and_serialization_is_sanitized(tmp_path: Path) -> None:
    rows = [
        _row(index, Hostname="", secret=f"RAW-SECRET-{index}")
        for index in range(1, REJECTION_EXAMPLE_LIMIT + 6)
    ]
    profile = profile_mordor_rows(rows, "fixture.json")
    report_path = tmp_path / "new" / "reports" / "profile.json"

    write_mordor_profile(profile, report_path)
    payload = json.loads(report_path.read_text(encoding="utf-8"))

    assert payload["rejected_count"] == 25
    assert len(payload["rejection_details"]) == REJECTION_EXAMPLE_LIMIT
    assert set(payload) == {
        "dataset",
        "source_file",
        "classification",
        "completed",
        "total_rows",
        "accepted_count",
        "rejected_count",
        "rejection_rate",
        "rejection_details",
        "event_id_counts",
        "event_id_overflow_count",
        "field_presence_counts",
        "process_event_count",
        "earliest_timestamp",
        "latest_timestamp",
    }
    report_text = report_path.read_text(encoding="utf-8")
    for sensitive in (
        "TOP-SECRET-COMMAND",
        "SECRET-USER",
        "192.0.2.10",
        "RAW-SECRET",
        str(tmp_path),
    ):
        assert sensitive not in report_text
    assert "CommandLine" not in report_text
    assert "SourceIp" not in report_text
    assert "User" not in report_text
    assert json.loads(json.dumps(payload)) == payload


def test_high_cardinality_event_ids_are_bounded_and_reconcile() -> None:
    overflow_rows = 7
    repeated_retained_rows = 3
    rows = [
        _row(index + 1, EventID=10_000 + index)
        for index in range(EVENT_ID_CATEGORY_LIMIT + overflow_rows)
    ]
    rows.extend(
        _row(EVENT_ID_CATEGORY_LIMIT + overflow_rows + index + 1, EventID=10_000)
        for index in range(repeated_retained_rows)
    )

    payload = profile_mordor_rows(rows, "fixture.json").to_dict()

    retained = payload["event_id_counts"]
    assert len(retained) == EVENT_ID_CATEGORY_LIMIT
    assert retained["10000"] == repeated_retained_rows + 1
    assert payload["event_id_overflow_count"] == overflow_rows
    assert sum(retained.values()) + payload["event_id_overflow_count"] == payload["total_rows"]
