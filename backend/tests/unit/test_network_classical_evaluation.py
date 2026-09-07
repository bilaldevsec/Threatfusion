from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import joblib
import numpy as np
import pytest
from numpy.lib.format import open_memmap
from sklearn.linear_model import LogisticRegression

from threatfusion.models.network_classical_evaluation import (
    EVALUATION_SCHEMA_VERSION,
    NetworkBaselineError,
    predict_in_batches,
    transform_test_records,
    verify_saved_model,
    write_failure_status,
)
from threatfusion.models.network_logistic_baseline import (
    ATTACK_THRESHOLD,
    BASELINE_SCHEMA_VERSION,
    calculate_binary_metrics,
    threshold_attack_scores,
)
from threatfusion.preprocessing.network_behavior_v1 import (
    LABEL_MAPPING,
    TRANSFORMED_FEATURE_NAMES,
    AssignedRecord,
    NetworkBehaviorPreprocessor,
)
from threatfusion.utils.checksum import sha256_file


def _record(label: str, value: float = 1.0) -> SimpleNamespace:
    return SimpleNamespace(
        duration_ms=value,
        fwd_packets=1,
        bwd_packets=2,
        fwd_bytes=3,
        bwd_bytes=4,
        packets_per_second=5.0,
        bytes_per_second=6.0,
        fwd_packet_length_mean=7.0,
        bwd_packet_length_mean=8.0,
        dst_port=443,
        protocol="tcp",
        label=label,
    )


def _preprocessor() -> NetworkBehaviorPreprocessor:
    return NetworkBehaviorPreprocessor(
        training_row_count=2,
        numeric_means=(0.0,) * 10,
        numeric_scales=(1.0,) * 10,
        zero_variance_features=(),
    )


def _counts() -> dict[str, dict[str, int | None]]:
    return {
        "train": {"total_count": 1, "benign_count": 1, "attack_count": 0},
        "validation": {"total_count": 1, "benign_count": 0, "attack_count": 1},
        "test": {"total_count": 2, "benign_count": 1, "attack_count": 1},
        "quarantine": {"total_count": 1, "benign_count": 1, "attack_count": 0},
        "rejected": {"total_count": 1, "benign_count": None, "attack_count": None},
    }


def _assigned_records() -> list[AssignedRecord]:
    return [
        AssignedRecord(1, "train", _record("Normal")),
        AssignedRecord(2, "test", _record("Attack", 2.0)),
        AssignedRecord(3, "validation", _record("Attack")),
        AssignedRecord(4, "quarantine", _record("Normal")),
        AssignedRecord(5, "test", _record("Normal", 3.0)),
        AssignedRecord(6, "rejected", None),
    ]


def test_test_only_selection_reconciles_all_assignments_and_preserves_state(
    tmp_path: Path,
) -> None:
    state = _preprocessor()
    before = state.to_dict()
    matrix = open_memmap(
        tmp_path / "X.npy", mode="w+", dtype=np.float64, shape=(2, len(TRANSFORMED_FEATURE_NAMES))
    )
    labels = open_memmap(tmp_path / "y.npy", mode="w+", dtype=np.uint8, shape=(2,))

    result = transform_test_records(
        _assigned_records(), state, matrix, labels, _counts(), batch_size=1
    )

    assert result["rows"] == 2
    assert result["normal"] == result["attack"] == 1
    assert labels.tolist() == [1, 0]
    assert matrix[:, 0].tolist() == [2.0, 3.0]
    assert state.to_dict() == before


def test_assignment_partial_and_label_mismatches_fail(tmp_path: Path) -> None:
    matrix = open_memmap(
        tmp_path / "X.npy", mode="w+", dtype=np.float64, shape=(2, len(TRANSFORMED_FEATURE_NAMES))
    )
    labels = open_memmap(tmp_path / "y.npy", mode="w+", dtype=np.uint8, shape=(2,))
    with pytest.raises(NetworkBaselineError, match="assignment_count_reconciliation_failed"):
        transform_test_records(_assigned_records()[:-1], _preprocessor(), matrix, labels, _counts())

    bad = _counts()
    bad["test"] = {"total_count": 2, "benign_count": 2, "attack_count": 0}
    with pytest.raises(NetworkBaselineError, match="assignment_label_reconciliation_failed"):
        transform_test_records(_assigned_records(), _preprocessor(), matrix, labels, bad)


def test_prediction_batches_preserve_probability_mapping_and_inclusive_threshold() -> None:
    matrix = np.asarray([[-2.0], [-1.0], [1.0], [2.0]])
    labels = np.asarray([0, 0, 1, 1], dtype=np.uint8)
    model = LogisticRegression().fit(matrix, labels)
    direct = model.predict_proba(matrix)[:, list(model.classes_).index(1)]
    np.testing.assert_array_equal(predict_in_batches(model, matrix, batch_size=1), direct)
    assert threshold_attack_scores(np.asarray([0.499999, ATTACK_THRESHOLD])).tolist() == [0, 1]


def _saved_logistic_fixture(root: Path) -> tuple[Path, SimpleNamespace]:
    run = root / "model"
    run.mkdir()
    matrix = np.zeros((4, len(TRANSFORMED_FEATURE_NAMES)), dtype=np.float64)
    matrix[:, 0] = [-2, -1, 1, 2]
    labels = np.asarray([0, 0, 1, 1], dtype=np.uint8)
    model = LogisticRegression().fit(matrix, labels)
    model_path = run / "logistic_regression.joblib"
    joblib.dump(model, model_path)
    preprocessing = SimpleNamespace(
        state_sha256="a" * 64,
        configuration_sha256="b" * 64,
        report_sha256="c" * 64,
        y_validation=labels,
    )
    config = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "fit_partition": "train",
        "evaluation_partition": "validation",
        "label_mapping": LABEL_MAPPING,
        "decision_threshold": {
            "positive_label": 1,
            "positive_name": "Attack",
            "operator": ">=",
            "probability": ATTACK_THRESHOLD,
        },
        "preprocessing": {
            "state_sha256": preprocessing.state_sha256,
            "configuration_sha256": preprocessing.configuration_sha256,
            "report_sha256": preprocessing.report_sha256,
            "transformed_feature_names": list(TRANSFORMED_FEATURE_NAMES),
        },
    }
    config_path = run / "model_config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    metrics = calculate_binary_metrics(labels, model.predict_proba(matrix)[:, 1])
    report = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "completed": True,
        "configuration_sha256": sha256_file(config_path),
        "model": {
            "filename": model_path.name,
            "sha256": sha256_file(model_path),
            "size_bytes": model_path.stat().st_size,
        },
        "validation": {
            "sample_count": 4,
            "normal_count": 2,
            "attack_count": 2,
            "logistic_regression": metrics,
        },
    }
    (run / "evaluation_report.json").write_text(json.dumps(report), encoding="utf-8")
    return run, preprocessing


def test_saved_model_integrity_feature_order_and_reload(tmp_path: Path) -> None:
    run, preprocessing = _saved_logistic_fixture(tmp_path)
    verified = verify_saved_model(run, preprocessing, name="logistic_regression")
    assert verified.name == "logistic_regression"

    config_path = run / "model_config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["preprocessing"]["transformed_feature_names"].reverse()
    config_path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(NetworkBaselineError, match="logistic_regression_evidence_mismatch"):
        verify_saved_model(run, preprocessing, name="logistic_regression")


def test_missing_or_corrupt_saved_model_fails_closed(tmp_path: Path) -> None:
    run, preprocessing = _saved_logistic_fixture(tmp_path)
    (run / "logistic_regression.joblib").write_bytes(b"corrupt")
    with pytest.raises(NetworkBaselineError, match="logistic_regression_model_integrity_failure"):
        verify_saved_model(run, preprocessing, name="logistic_regression")


def test_evaluation_module_has_no_fit_boundary_and_schema_is_frozen() -> None:
    assert EVALUATION_SCHEMA_VERSION == "unsw_february_classical_evaluation_v1"
    assert "fit" not in predict_in_batches.__code__.co_names


def test_failure_status_can_never_claim_completion(tmp_path: Path) -> None:
    path = write_failure_status(tmp_path, "fixture_failure")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload == {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "completed": False,
        "failure_code": "fixture_failure",
    }
