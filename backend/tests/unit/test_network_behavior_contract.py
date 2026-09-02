import csv
from pathlib import Path

import pytest

from threatfusion.datasets.adapters.cic_ids2018_benchmark import adapt_cic_benchmark_row
from threatfusion.datasets.adapters.unsw_nb15 import adapt_unsw_row
from threatfusion.features.network_behavior import (
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
    NETWORK_BEHAVIOR_V1_FORBIDDEN_MODEL_FIELDS,
    assert_network_behavior_model_fields,
    project_network_behavior,
)

FIXTURES = Path(__file__).parents[1] / "fixtures/network"


def _load_one(path: Path) -> dict[str, str]:
    with path.open(encoding="utf-8", newline="") as handle:
        return next(csv.DictReader(handle))


def _cic_benchmark_row(**updates: str | int) -> dict[str, str | int]:
    row: dict[str, str | int] = {
        "__source_file": "fixture.csv",
        "__source_row_number": 1,
        "Timestamp": "01/01/2026 00:00:00",
        "Dst Port": "443",
        "Protocol": "6",
        "Flow Duration": "2500000",
        "Tot Fwd Pkts": "10",
        "Tot Bwd Pkts": "8",
        "TotLen Fwd Pkts": "1200",
        "TotLen Bwd Pkts": "900",
        "Label": "FTP-BruteForce",
    }
    row.update(updates)
    return row


def test_network_behavior_v1_names_and_order_are_exact() -> None:
    assert NETWORK_BEHAVIOR_V1_FEATURE_NAMES == (
        "duration_ms",
        "fwd_packets",
        "bwd_packets",
        "fwd_bytes",
        "bwd_bytes",
        "packets_per_second",
        "bytes_per_second",
        "fwd_packet_length_mean",
        "bwd_packet_length_mean",
        "dst_port",
        "protocol",
    )
    assert "src_port" not in NETWORK_BEHAVIOR_V1_FEATURE_NAMES


def test_equivalent_unsw_and_cic_records_have_the_same_feature_vector() -> None:
    unsw = adapt_unsw_row(_load_one(FIXTURES / "unsw_nb15_common_flow.csv"))
    cic = adapt_cic_benchmark_row(_cic_benchmark_row())

    assert project_network_behavior(unsw) == project_network_behavior(cic)
    assert cic.source_file == "fixture.csv"
    assert cic.source_row_number == 1
    assert cic.source_timestamp.tzinfo is None
    assert cic.attack_name == "FTP-BruteForce"


@pytest.mark.parametrize("field", sorted(NETWORK_BEHAVIOR_V1_FORBIDDEN_MODEL_FIELDS))
def test_metadata_identifiers_ips_provenance_and_labels_are_forbidden(field: str) -> None:
    with pytest.raises(ValueError, match="Forbidden model field"):
        assert_network_behavior_model_fields((*NETWORK_BEHAVIOR_V1_FEATURE_NAMES, field))


def test_model_input_contract_rejects_missing_or_reordered_predictors() -> None:
    with pytest.raises(ValueError, match="exactly match"):
        assert_network_behavior_model_fields(NETWORK_BEHAVIOR_V1_FEATURE_NAMES[:-1])

    reordered = tuple(reversed(NETWORK_BEHAVIOR_V1_FEATURE_NAMES))
    with pytest.raises(ValueError, match="exactly match"):
        assert_network_behavior_model_fields(reordered)
