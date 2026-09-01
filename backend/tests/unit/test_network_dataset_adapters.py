import pytest

from threatfusion.datasets.adapters.base import SourceRowValidationError
from threatfusion.datasets.adapters.cic_ids2018 import adapt_cic_row
from threatfusion.datasets.adapters.unsw_nb15 import adapt_unsw_row


def _valid_unsw_row() -> dict[str, str]:
    return {
        "id": "1",
        "stime": "1704110400",
        "srcip": "192.168.1.10",
        "dstip": "10.0.0.5",
        "sport": "49152",
        "dsport": "443",
        "proto": "tcp",
        "dur": "2.0",
        "spkts": "10",
        "dpkts": "8",
        "sbytes": "1200",
        "dbytes": "900",
        "label": "1",
        "attack_cat": "Exploits",
    }


def _valid_cic_row() -> dict[str, str]:
    return {
        "Flow ID": "flow-a",
        "Timestamp": "14/02/2018 08:31:01",
        "Src IP": "172.31.69.25",
        "Dst IP": "18.219.211.138",
        "Src Port": "51524",
        "Dst Port": "22",
        "Protocol": "6",
        "Flow Duration": "3000000",
        "Tot Fwd Pkts": "12",
        "Tot Bwd Pkts": "10",
        "TotLen Fwd Pkts": "1400",
        "TotLen Bwd Pkts": "1800",
        "Label": "SSH-Bruteforce",
    }


def test_unsw_adapter_maps_only_semantic_common_features() -> None:
    flow = adapt_unsw_row(_valid_unsw_row())

    assert flow.source_dataset == "unsw_nb15"
    assert flow.duration_ms == 2000.0
    assert flow.fwd_packets == 10
    assert flow.bwd_packets == 8
    assert flow.fwd_bytes == 1200
    assert flow.bwd_bytes == 900
    assert flow.protocol == "tcp"
    assert flow.label == "Attack"
    assert flow.attack_category == "Exploits"


def test_cic_adapter_converts_microseconds_to_milliseconds() -> None:
    flow = adapt_cic_row(_valid_cic_row())

    assert flow.source_dataset == "cse_cic_ids2018"
    assert flow.duration_ms == 3000.0
    assert flow.fwd_packets == 12
    assert flow.bwd_packets == 10
    assert flow.fwd_bytes == 1400
    assert flow.bwd_bytes == 1800
    assert flow.protocol == "tcp"
    assert flow.label == "Attack"
    assert flow.attack_category == "SSH-Bruteforce"


def test_cic_benign_label_becomes_normal() -> None:
    flow = adapt_cic_row(
        {
            "Flow ID": "flow-benign",
            "Timestamp": "14/02/2018 08:31:01",
            "Src IP": "172.31.69.25",
            "Dst IP": "18.219.211.138",
            "Src Port": "51524",
            "Dst Port": "80",
            "Protocol": "6",
            "Flow Duration": "1000000",
            "Tot Fwd Pkts": "5",
            "Tot Bwd Pkts": "5",
            "TotLen Fwd Pkts": "500",
            "TotLen Bwd Pkts": "700",
            "Label": "Benign",
        }
    )

    assert flow.label == "Normal"
    assert flow.attack_category is None


def test_unsw_missing_required_field_raises_source_validation_error() -> None:
    row = _valid_unsw_row()
    del row["srcip"]

    with pytest.raises(SourceRowValidationError, match=r"UNSW-NB15.*srcip.*missing"):
        adapt_unsw_row(row)


@pytest.mark.parametrize("field,value", [("spkts", "many"), ("stime", "not-a-time")])
def test_unsw_invalid_numeric_or_timestamp_raises(field: str, value: str) -> None:
    row = _valid_unsw_row()
    row[field] = value

    with pytest.raises(SourceRowValidationError, match=rf"UNSW-NB15.*{field}"):
        adapt_unsw_row(row)


def test_unsw_normal_row_may_omit_attack_category() -> None:
    row = _valid_unsw_row()
    row["label"] = "0"
    del row["attack_cat"]

    flow = adapt_unsw_row(row)

    assert flow.label == "Normal"
    assert flow.attack_category is None


def test_cic_missing_required_field_raises_source_validation_error() -> None:
    row = _valid_cic_row()
    del row["Dst IP"]

    with pytest.raises(SourceRowValidationError, match=r"CSE-CIC-IDS2018.*Dst IP.*missing"):
        adapt_cic_row(row)


@pytest.mark.parametrize("field,value", [("Flow Duration", "forever"), ("Timestamp", "not-a-time")])
def test_cic_invalid_numeric_or_timestamp_raises(field: str, value: str) -> None:
    row = _valid_cic_row()
    row[field] = value

    with pytest.raises(SourceRowValidationError, match=rf"CSE-CIC-IDS2018.*{field}"):
        adapt_cic_row(row)


def test_unsw_noncanonical_protocol_becomes_other() -> None:
    row = _valid_unsw_row()
    row["proto"] = "arp"

    assert adapt_unsw_row(row).protocol == "other"


def test_cic_noncanonical_protocol_becomes_other() -> None:
    row = _valid_cic_row()
    row["Protocol"] = "0"

    assert adapt_cic_row(row).protocol == "other"


@pytest.mark.parametrize(
    ("adapter", "row_factory", "field"),
    [
        (adapt_unsw_row, _valid_unsw_row, "proto"),
        (adapt_cic_row, _valid_cic_row, "Protocol"),
    ],
)
def test_blank_protocol_raises_source_validation_error(
    adapter: object, row_factory: object, field: str
) -> None:
    row = row_factory()
    row[field] = "   "

    with pytest.raises(SourceRowValidationError, match=rf"{field}.*blank"):
        adapter(row)


@pytest.mark.parametrize(
    ("field", "value"),
    [("srcip", "not-an-ip"), ("sport", "65536"), ("label", "2")],
)
def test_unsw_invalid_ip_port_or_label_raises(field: str, value: str) -> None:
    row = _valid_unsw_row()
    row[field] = value

    with pytest.raises(SourceRowValidationError, match=rf"UNSW-NB15.*{field}"):
        adapt_unsw_row(row)
