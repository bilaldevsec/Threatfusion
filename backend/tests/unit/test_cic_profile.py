import json
from pathlib import Path
from typing import Any

import pytest

from threatfusion.datasets.cic_profile import (
    NUMERIC_FEATURE_NAMES,
    REJECTION_EXAMPLE_LIMIT,
    CicDatasetProfile,
    profile_cic_rows,
    write_cic_profile,
)
from threatfusion.features.network_behavior import NETWORK_BEHAVIOR_V1_FEATURE_NAMES


def _row(row_number: int, **updates: Any) -> dict[str, Any]:
    row = {
        "__source_file": "tiny-fixture.csv",
        "__source_row_number": row_number,
        "Timestamp": "14/02/2018 08:31:01",
        "Dst Port": "443",
        "Protocol": "6",
        "Flow Duration": "2000000",
        "Tot Fwd Pkts": "4",
        "Tot Bwd Pkts": "2",
        "TotLen Fwd Pkts": "400",
        "TotLen Bwd Pkts": "100",
        "Label": "Benign",
        "unused_ip": "192.0.2.10",
        "unused_source_port": "54321",
        "unused_secret": "TOP-SECRET-RAW-VALUE",
    }
    row.update(updates)
    return row


def test_empty_input_has_complete_zeroed_aggregate_profile() -> None:
    profile = profile_cic_rows([], "empty.csv")
    payload = profile.to_dict()

    assert payload["completed"] is True
    assert payload["total_rows"] == 0
    assert payload["accepted_count"] == 0
    assert payload["rejected_count"] == 0
    assert payload["rejection_rate"] == 0.0
    assert payload["label_counts"] == {"Normal": 0, "Attack": 0}
    assert payload["protocol_counts"] == {"tcp": 0, "udp": 0, "icmp": 0, "other": 0}
    assert payload["earliest_source_timestamp"] is None
    assert payload["latest_source_timestamp"] is None
    assert all(
        bounds == {"minimum": None, "maximum": None}
        for bounds in payload["numeric_ranges"].values()
    )


@pytest.mark.parametrize("source_file", ["/tmp/fixture.csv", r"C:\data\fixture.csv"])
def test_source_file_must_be_a_safe_basename(source_file: str) -> None:
    with pytest.raises(ValueError, match="safe basename"):
        profile_cic_rows([], source_file)


def test_mixed_records_have_exact_counts_ranges_and_naive_timestamps() -> None:
    rows = [
        _row(1),
        _row(
            2,
            Label="SSH-Bruteforce",
            Protocol="17",
            Timestamp="14/02/2018 09:45:00",
            **{
                "Dst Port": "53",
                "Flow Duration": "4000000",
                "Tot Fwd Pkts": "8",
                "Tot Bwd Pkts": "4",
                "TotLen Fwd Pkts": "1600",
                "TotLen Bwd Pkts": "800",
            },
        ),
        _row(3, Label="FTP-BruteForce", Protocol="1", Timestamp="14/02/2018 07:00:00"),
        _row(4, Protocol="0"),
        _row(5, Label="UNKNOWN-SENSITIVE-LABEL"),
    ]

    payload = profile_cic_rows(iter(rows), "tiny-fixture.csv").to_dict()

    assert payload["total_rows"] == 5
    assert payload["accepted_count"] == 4
    assert payload["rejected_count"] == 1
    assert payload["label_counts"] == {"Normal": 2, "Attack": 2}
    assert payload["attack_category_counts"] == {
        "FTP-BruteForce": 1,
        "SSH-Bruteforce": 1,
    }
    assert payload["protocol_counts"] == {"tcp": 1, "udp": 1, "icmp": 1, "other": 1}
    assert payload["numeric_ranges"] == {
        "duration_ms": {"minimum": 2000.0, "maximum": 4000.0},
        "fwd_packets": {"minimum": 4, "maximum": 8},
        "bwd_packets": {"minimum": 2, "maximum": 4},
        "fwd_bytes": {"minimum": 400, "maximum": 1600},
        "bwd_bytes": {"minimum": 100, "maximum": 800},
        "packets_per_second": {"minimum": 3.0, "maximum": 3.0},
        "bytes_per_second": {"minimum": 250.0, "maximum": 600.0},
        "fwd_packet_length_mean": {"minimum": 100.0, "maximum": 200.0},
        "bwd_packet_length_mean": {"minimum": 50.0, "maximum": 200.0},
        "dst_port": {"minimum": 53, "maximum": 443},
    }
    assert tuple(payload["numeric_ranges"]) == NUMERIC_FEATURE_NAMES
    assert payload["earliest_source_timestamp"] == "2018-02-14T07:00:00"
    assert payload["latest_source_timestamp"] == "2018-02-14T09:45:00"
    assert "+" not in payload["earliest_source_timestamp"]
    assert payload["rejection_details"] == [
        {"row_number": 5, "fields": ("Label",), "reason": "source row validation failed"}
    ]


def test_rejections_are_bounded_and_report_is_sanitized_json(tmp_path: Path) -> None:
    rows = [
        _row(index, Label=f"SECRET-REJECTED-LABEL-{index}")
        for index in range(1, REJECTION_EXAMPLE_LIMIT + 6)
    ]
    file_profile = profile_cic_rows(rows, "tiny-fixture.csv")
    profile = CicDatasetProfile(files=(file_profile,))
    report_path = tmp_path / "new" / "reports" / "profile.json"

    write_cic_profile(profile, report_path)

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["network_behavior_v1_feature_order"] == list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES)
    assert payload["timestamp_semantics"] == "timezone-naive; source timezone unknown"
    assert payload["combined"]["completed"] is True
    assert payload["combined"]["rejected_count"] == 25
    assert len(payload["combined"]["rejection_details"]) == REJECTION_EXAMPLE_LIMIT
    assert len(payload["files"][0]["rejection_details"]) == REJECTION_EXAMPLE_LIMIT

    report_text = report_path.read_text(encoding="utf-8")
    assert "SECRET-REJECTED-LABEL" not in report_text
    assert "TOP-SECRET-RAW-VALUE" not in report_text
    assert "192.0.2.10" not in report_text
    assert "54321" not in report_text
    assert str(tmp_path) not in report_text
    assert "unused_ip" not in report_text
    assert "unused_source_port" not in report_text
    assert json.loads(json.dumps(payload)) == payload
