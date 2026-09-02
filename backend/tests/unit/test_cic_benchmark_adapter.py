from math import inf, nan
from typing import Any

import pytest
from pydantic import ValidationError

from threatfusion.datasets.adapters.base import SourceRowValidationError
from threatfusion.datasets.adapters.cic_ids2018_benchmark import (
    CIC_APPROVED_ATTACK_LABELS,
    adapt_cic_benchmark_row,
)
from threatfusion.schemas.network_benchmark import NetworkBenchmarkRecord


def _row(**updates: Any) -> dict[str, Any]:
    row = {
        "__source_file": "tiny-fixture.csv",
        "__source_row_number": 7,
        "Timestamp": "14/02/2018 08:31:01",
        "Dst Port": "443",
        "Protocol": "6",
        "Flow Duration": "2500000",
        "Tot Fwd Pkts": "10",
        "Tot Bwd Pkts": "8",
        "TotLen Fwd Pkts": "1200",
        "TotLen Bwd Pkts": "900",
        "Label": "SSH-Bruteforce",
    }
    row.update(updates)
    return row


def test_adapter_converts_units_derives_features_and_retains_metadata() -> None:
    record = adapt_cic_benchmark_row(_row())

    assert isinstance(record, NetworkBenchmarkRecord)
    assert record.schema_version == "network_benchmark_v1"
    assert record.source_file == "tiny-fixture.csv"
    assert record.source_row_number == 7
    assert record.source_timestamp.tzinfo is None
    assert record.duration_ms == 2500.0
    assert record.packets_per_second == pytest.approx(7.2)
    assert record.bytes_per_second == pytest.approx(840.0)
    assert record.fwd_packet_length_mean == 120.0
    assert record.bwd_packet_length_mean == 112.5
    assert record.label == "Attack"
    assert record.attack_name == "SSH-Bruteforce"
    assert not hasattr(record, "flow_id")
    assert not hasattr(record, "src_ip")
    assert not hasattr(record, "dst_ip")
    assert not hasattr(record, "src_port")


@pytest.mark.parametrize(
    ("raw_protocol", "expected"),
    [("6", "tcp"), ("17", "udp"), ("1", "icmp"), ("0", "other")],
)
def test_protocol_normalization(raw_protocol: str, expected: str) -> None:
    assert adapt_cic_benchmark_row(_row(Protocol=raw_protocol)).protocol == expected


@pytest.mark.parametrize("benign_label", ["Benign", "BENIGN", "benign"])
def test_benign_labels_are_normalized(benign_label: str) -> None:
    benign = adapt_cic_benchmark_row(_row(Label=benign_label))

    assert (benign.label, benign.attack_name) == ("Normal", None)


@pytest.mark.parametrize("attack_label", sorted(CIC_APPROVED_ATTACK_LABELS))
def test_every_approved_attack_label_is_normalized_and_retained(attack_label: str) -> None:
    attack = adapt_cic_benchmark_row(_row(Label=attack_label))

    assert (attack.label, attack.attack_name) == ("Attack", attack_label)


@pytest.mark.parametrize("label", [None, nan, "", "   ", "SSH-Brute-force", "Unknown"])
def test_missing_blank_nan_misspelled_and_unknown_labels_are_rejected(label: Any) -> None:
    row = _row(Label=label)
    with pytest.raises(SourceRowValidationError) as error:
        adapt_cic_benchmark_row(row)

    if isinstance(label, str) and label.strip():
        assert label not in str(error.value)

    del row["Label"]
    with pytest.raises(SourceRowValidationError, match="Label"):
        adapt_cic_benchmark_row(row)


def test_ambiguous_official_timestamp_is_parsed_day_first_without_timezone() -> None:
    record = adapt_cic_benchmark_row(_row(Timestamp="01/02/2018 03:04:05"))

    assert record.source_timestamp.isoformat() == "2018-02-01T03:04:05"
    assert record.source_timestamp.tzinfo is None


@pytest.mark.parametrize(
    "timestamp",
    [
        "31/02/2018 08:31:01",
        "2018-02-14T08:31:01",
        "02/14/2018 08:31:01",
        "14/02/2018 08:31:01+00:00",
        "14/02/2018",
        None,
        "",
        "   ",
        nan,
    ],
)
def test_impossible_unsupported_missing_blank_and_nan_timestamps_are_rejected(
    timestamp: Any,
) -> None:
    row = _row(Timestamp=timestamp)
    with pytest.raises(SourceRowValidationError) as error:
        adapt_cic_benchmark_row(row)

    if isinstance(timestamp, str) and timestamp.strip():
        assert timestamp not in str(error.value)

    del row["Timestamp"]
    with pytest.raises(SourceRowValidationError, match="Timestamp"):
        adapt_cic_benchmark_row(row)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Flow Duration", "forever"),
        ("Tot Fwd Pkts", "many"),
        ("TotLen Bwd Pkts", "NaN"),
        ("Dst Port", "65536"),
        ("Timestamp", "not-a-time"),
    ],
)
def test_missing_or_invalid_required_values_are_rejected(field: str, value: str) -> None:
    with pytest.raises(SourceRowValidationError, match=field):
        adapt_cic_benchmark_row(_row(**{field: value}))

    row = _row()
    del row[field]
    with pytest.raises(SourceRowValidationError, match=field):
        adapt_cic_benchmark_row(row)


@pytest.mark.parametrize("value", [-1, nan, inf, -inf, True, ""])
def test_negative_nonfinite_boolean_and_blank_duration_is_rejected(value: Any) -> None:
    with pytest.raises(SourceRowValidationError, match="Flow Duration"):
        adapt_cic_benchmark_row(_row(**{"Flow Duration": value}))


@pytest.mark.parametrize(
    "field",
    ["Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts"],
)
@pytest.mark.parametrize("value", [-1, nan, inf, -inf, 1.5, True, ""])
def test_invalid_packet_and_byte_counts_are_rejected(field: str, value: Any) -> None:
    with pytest.raises(SourceRowValidationError, match=field):
        adapt_cic_benchmark_row(_row(**{field: value}))


@pytest.mark.parametrize(
    ("port", "accepted"), [(-1, False), (0, True), (65535, True), (65536, False)]
)
def test_destination_port_boundaries(port: int, accepted: bool) -> None:
    if accepted:
        assert adapt_cic_benchmark_row(_row(**{"Dst Port": port})).dst_port == port
    else:
        with pytest.raises(SourceRowValidationError, match="Dst Port"):
            adapt_cic_benchmark_row(_row(**{"Dst Port": port}))


@pytest.mark.parametrize("value", [nan, inf, -inf])
@pytest.mark.parametrize(
    "field",
    [
        "duration_ms",
        "packets_per_second",
        "bytes_per_second",
        "fwd_packet_length_mean",
        "bwd_packet_length_mean",
    ],
)
def test_direct_schema_construction_rejects_nonfinite_floats(field: str, value: float) -> None:
    data = adapt_cic_benchmark_row(_row()).model_dump()
    data[field] = value

    with pytest.raises(ValidationError):
        NetworkBenchmarkRecord.model_validate(data)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"fwd_packets": 0, "fwd_bytes": 1}, "fwd_bytes"),
        ({"bwd_packets": 0, "bwd_bytes": 1}, "bwd_bytes"),
    ],
)
def test_direct_schema_enforces_directional_consistency(
    updates: dict[str, int], message: str
) -> None:
    data = adapt_cic_benchmark_row(_row()).model_dump()
    data.update(updates)

    with pytest.raises(ValidationError, match=message):
        NetworkBenchmarkRecord.model_validate(data)


@pytest.mark.parametrize("source_file", ["", "   ", ".", "..", "dir/file.csv", r"dir\file.csv"])
def test_source_file_must_be_a_plain_basename(source_file: str) -> None:
    data = adapt_cic_benchmark_row(_row()).model_dump()
    data["source_file"] = source_file

    with pytest.raises(ValidationError, match="basename"):
        NetworkBenchmarkRecord.model_validate(data)


def test_zero_duration_uses_shared_zero_rate_behavior() -> None:
    record = adapt_cic_benchmark_row(_row(**{"Flow Duration": "0"}))

    assert record.packets_per_second == 0.0
    assert record.bytes_per_second == 0.0


def test_validation_errors_do_not_expose_source_values_or_complete_rows() -> None:
    row = _row(**{"Flow Duration": "TOP-SECRET", "unused": "another-secret"})

    with pytest.raises(SourceRowValidationError) as error:
        adapt_cic_benchmark_row(row)

    message = str(error.value)
    assert "TOP-SECRET" not in message
    assert "another-secret" not in message
