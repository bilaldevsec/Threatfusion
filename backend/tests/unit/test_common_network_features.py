import pytest

from threatfusion.features.common_network import (
    FLOW_COMMON_V1_FEATURE_NAMES,
    FORBIDDEN_MODEL_FEATURE_NAMES,
    MODEL_INPUT_FEATURE_NAMES,
    assert_no_forbidden_model_features,
    get_feature_names,
)


def test_flow_common_v1_feature_order_is_stable() -> None:
    assert get_feature_names() == FLOW_COMMON_V1_FEATURE_NAMES
    assert FLOW_COMMON_V1_FEATURE_NAMES == (
        "duration_ms",
        "fwd_packets",
        "bwd_packets",
        "fwd_bytes",
        "bwd_bytes",
        "packets_per_second",
        "bytes_per_second",
        "fwd_packet_length_mean",
        "bwd_packet_length_mean",
        "src_port",
        "dst_port",
        "protocol",
    )


def test_model_input_features_do_not_include_labels_or_dataset_id() -> None:
    assert "label" not in MODEL_INPUT_FEATURE_NAMES
    assert "attack_category" not in MODEL_INPUT_FEATURE_NAMES
    assert "source_dataset" not in MODEL_INPUT_FEATURE_NAMES
    assert FORBIDDEN_MODEL_FEATURE_NAMES.isdisjoint(MODEL_INPUT_FEATURE_NAMES)


def test_rejects_forbidden_model_features() -> None:
    with pytest.raises(ValueError, match="source_dataset"):
        assert_no_forbidden_model_features(["duration_ms", "source_dataset"])


def test_all_model_input_features_exist_in_common_contract() -> None:
    assert set(MODEL_INPUT_FEATURE_NAMES).issubset(set(FLOW_COMMON_V1_FEATURE_NAMES))
