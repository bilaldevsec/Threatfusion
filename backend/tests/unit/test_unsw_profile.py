import json
from pathlib import Path
from typing import Any

from threatfusion.datasets.unsw_profile import (
    INCONSISTENCY_EXAMPLE_LIMIT,
    profile_unsw_rows,
    write_unsw_profile,
)


def _row(
    row_number: int,
    *,
    label: str = "0",
    attack_category: str = "",
    source_port: str = "1234",
    timestamp: str = "1421927414",
) -> dict[str, Any]:
    return {
        "flow_id": f"fixture:{row_number}",
        "stime": timestamp,
        "srcip": "192.0.2.1",
        "dstip": "198.51.100.2",
        "sport": source_port,
        "dsport": "53",
        "proto": "udp",
        "dur": "0.25",
        "spkts": "2",
        "dpkts": "1",
        "sbytes": "120",
        "dbytes": "60",
        "service": "dns",
        "state": "CON",
        "attack_cat": attack_category,
        "label": label,
    }


def test_profiles_only_accepted_records_with_streaming_aggregates(tmp_path: Path) -> None:
    rows = [
        _row(1),
        _row(2, label="1", attack_category="Exploits", source_port="0xc0a8"),
        _row(3, source_port="-"),
        _row(4, label="0", attack_category="Generic", timestamp="1421927416"),
        _row(5, label="1", attack_category="-"),
    ]

    profile = profile_unsw_rows(iter(rows))
    payload = profile.to_dict()

    assert payload["total_input_rows"] == 5
    assert payload["accepted_count"] == 4
    assert payload["rejected_count"] == 1
    assert payload["canonical_label_counts"] == {"Attack": 2, "Normal": 2}
    assert payload["raw_numeric_label_counts"] == {"0": 2, "1": 2}
    assert payload["attack_category_counts"] == {"Exploits": 1, "Generic": 1}
    assert payload["blank_optional_attack_category_count"] == 2
    assert payload["protocol_counts"] == {"udp": 4}
    assert payload["service_counts"] == {"dns": 4}
    assert payload["connection_state_counts"] == {"CON": 4}
    assert payload["numeric_ranges"]["duration_ms"] == {
        "minimum": 250.0,
        "maximum": 250.0,
    }
    assert payload["numeric_ranges"]["source_port"] == {
        "minimum": 1234,
        "maximum": 49320,
    }
    assert payload["earliest_timestamp"] == "2015-01-22T11:50:14+00:00"
    assert payload["latest_timestamp"] == "2015-01-22T11:50:16+00:00"
    assert payload["label_inconsistency_counts"] == {
        "label_0_with_attack_category": 1,
        "label_1_without_attack_category": 1,
    }

    report_path = tmp_path / "reports" / "profile.json"
    write_unsw_profile(profile, report_path)
    report_text = report_path.read_text(encoding="utf-8")
    assert json.loads(report_text) == json.loads(json.dumps(payload))
    assert "192.0.2.1" not in report_text
    assert "198.51.100.2" not in report_text
    assert "srcip" not in report_text
    assert "dstip" not in report_text


def test_label_inconsistency_examples_are_bounded_and_sanitized() -> None:
    profile = profile_unsw_rows(
        _row(index, label="1", attack_category="")
        for index in range(1, INCONSISTENCY_EXAMPLE_LIMIT + 6)
    )

    assert profile.label_inconsistency_counts == {"label_1_without_attack_category": 25}
    assert len(profile.label_inconsistency_examples) == INCONSISTENCY_EXAMPLE_LIMIT
    assert profile.label_inconsistency_examples[0].source_file == "fixture.csv"
    assert profile.label_inconsistency_examples[-1].row_number == INCONSISTENCY_EXAMPLE_LIMIT
