import csv
from pathlib import Path

import pytest

from threatfusion.datasets.adapters.cic_ids2018_benchmark import adapt_cic_benchmark_row
from threatfusion.datasets.adapters.unsw_nb15 import adapt_unsw_row
from threatfusion.features.network_behavior import (
    CIC_IDS2018_CICFLOWMETER_V3_PROCESSED_REPRESENTATION_V1,
    NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
    NETWORK_BEHAVIOR_V1_FORBIDDEN_MODEL_FIELDS,
    NETWORK_BEHAVIOR_V1_INCOMPATIBLE_BYTE_FEATURES,
    UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
    UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1,
    NetworkCompatibilityError,
    NetworkCompatibilityKey,
    NetworkCompatibilityStatus,
    assert_network_behavior_model_fields,
    decide_network_compatibility,
    project_network_behavior,
    require_supported_network_compatibility,
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


def test_synthetic_equal_values_have_the_same_projection_without_proving_compatibility() -> None:
    unsw = adapt_unsw_row(_load_one(FIXTURES / "unsw_nb15_common_flow.csv"))
    cic = adapt_cic_benchmark_row(_cic_benchmark_row())

    assert project_network_behavior(unsw) == project_network_behavior(cic)
    assert cic.source_file == "fixture.csv"
    assert cic.source_row_number == 1
    assert cic.source_timestamp.tzinfo is None
    assert cic.attack_name == "FTP-BruteForce"


def _compatibility_key(source: str | None) -> NetworkCompatibilityKey:
    return NetworkCompatibilityKey(
        source_representation=source,
        fitted_source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        feature_contract_version=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
        model_preprocessing_requirements=UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1,
    )


def test_verified_unsw_representation_is_supported_without_claiming_readiness() -> None:
    decision = require_supported_network_compatibility(
        _compatibility_key(UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1)
    )

    assert decision.status is NetworkCompatibilityStatus.SUPPORTED_USE
    assert decision.approved_for_inference is True
    assert decision.affected_features == ()


def test_current_cic_representation_has_exact_incompatible_byte_features() -> None:
    decision = decide_network_compatibility(
        _compatibility_key(CIC_IDS2018_CICFLOWMETER_V3_PROCESSED_REPRESENTATION_V1)
    )

    assert decision.status is NetworkCompatibilityStatus.DEMONSTRATED_INCOMPATIBILITY
    assert decision.approved_for_inference is False
    assert decision.reason_codes == ("cross_source_byte_semantics_incompatible",)
    assert (
        decision.affected_features
        == NETWORK_BEHAVIOR_V1_INCOMPATIBLE_BYTE_FEATURES
        == (
            "fwd_bytes",
            "bwd_bytes",
            "bytes_per_second",
            "fwd_packet_length_mean",
            "bwd_packet_length_mean",
        )
    )
    with pytest.raises(NetworkCompatibilityError, match="cross_source_byte_semantics_incompatible"):
        require_supported_network_compatibility(decision.key)


@pytest.mark.parametrize(
    ("key", "reason"),
    [
        (_compatibility_key(None), "compatibility_evidence_missing"),
        (_compatibility_key("unregistered.flow.export.v1"), "source_representation_unrecognized"),
        (
            NetworkCompatibilityKey(
                source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
                fitted_source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
                feature_contract_version="network_behavior_v2",
                model_preprocessing_requirements=UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1,
            ),
            "feature_contract_version_unrecognized",
        ),
        (
            NetworkCompatibilityKey(
                source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
                fitted_source_representation="unverified.training.export.v1",
                feature_contract_version=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
                model_preprocessing_requirements=UNSW_TRAINED_CLASSICAL_REQUIREMENTS_V1,
            ),
            "fitted_source_representation_unrecognized",
        ),
        (
            NetworkCompatibilityKey(
                source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
                fitted_source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
                feature_contract_version=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
                model_preprocessing_requirements="unknown.requirements.v1",
            ),
            "model_preprocessing_requirements_unrecognized",
        ),
    ],
)
def test_missing_unknown_and_mismatched_compatibility_evidence_fails_closed(
    key: NetworkCompatibilityKey, reason: str
) -> None:
    decision = decide_network_compatibility(key)
    assert decision.status is NetworkCompatibilityStatus.UNKNOWN_COMPATIBILITY
    assert decision.approved_for_inference is False
    assert decision.reason_codes == (reason,)
    with pytest.raises(NetworkCompatibilityError, match=reason):
        require_supported_network_compatibility(key)


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
