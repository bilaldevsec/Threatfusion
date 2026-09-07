from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import joblib
import numpy as np
import pytest

from threatfusion.models.network_logistic_baseline import (
    ATTACK_THRESHOLD,
    BASELINE_SCHEMA_VERSION as LOGISTIC_SCHEMA_VERSION,
    LABEL_MAPPING,
    NetworkBaselineError,
    attack_probabilities,
    calculate_binary_metrics,
    threshold_attack_scores,
)
from threatfusion.models.network_random_forest_baseline import (
    FROZEN_RANDOM_FOREST_PARAMETERS,
    RANDOM_FOREST_SCHEMA_VERSION,
    batched_attack_probabilities,
    create_frozen_random_forest,
    effective_random_forest_parameters,
    fit_train_only,
    load_verified_logistic_comparison,
    reload_probabilities_equivalent,
    run_synthetic_random_forest_smoke,
)
from threatfusion.preprocessing.network_behavior_v1 import TRANSFORMED_FEATURE_NAMES
from threatfusion.utils.checksum import sha256_file


def _small_training_data() -> tuple[np.ndarray, np.ndarray]:
    normal = np.column_stack((np.linspace(-3.0, -0.1, 20), np.zeros(20)))
    attack = np.column_stack((np.linspace(0.1, 3.0, 20), np.ones(20)))
    return np.vstack((normal, attack)), np.asarray([0] * 20 + [1] * 20, dtype=np.uint8)


def test_frozen_configuration_and_class_threshold_handling() -> None:
    assert RANDOM_FOREST_SCHEMA_VERSION == "network_random_forest_baseline_v1"
    assert FROZEN_RANDOM_FOREST_PARAMETERS == {
        "n_estimators": 100,
        "criterion": "gini",
        "max_depth": 16,
        "min_samples_split": 2,
        "min_samples_leaf": 5,
        "max_features": "sqrt",
        "bootstrap": True,
        "max_samples": None,
        "class_weight": None,
        "random_state": 42,
        "n_jobs": 4,
        "oob_score": False,
        "warm_start": False,
        "ccp_alpha": 0.0,
    }
    matrix, labels = _small_training_data()
    model = fit_train_only(create_frozen_random_forest(), matrix, labels)
    scores = attack_probabilities(model, matrix)

    assert list(model.classes_) == [LABEL_MAPPING["Normal"], LABEL_MAPPING["Attack"]]
    assert effective_random_forest_parameters(model)["n_jobs"] == 4
    assert threshold_attack_scores(np.asarray([0.499999, ATTACK_THRESHOLD])).tolist() == [0, 1]
    assert scores.shape == labels.shape


def test_train_only_fit_accepts_no_validation_inputs() -> None:
    class FitSpy:
        def __init__(self) -> None:
            self.seen: tuple[np.ndarray, np.ndarray] | None = None

        def fit(self, matrix: np.ndarray, labels: np.ndarray) -> FitSpy:
            self.seen = (matrix, labels)
            return self

    train_matrix = np.asarray([[0.0], [1.0]])
    train_labels = np.asarray([0, 1], dtype=np.uint8)
    validation_labels = np.asarray([1, 0], dtype=np.uint8)
    spy = FitSpy()

    fitted = fit_train_only(spy, train_matrix, train_labels)

    assert fitted is spy
    assert spy.seen is not None
    assert spy.seen[0] is train_matrix
    assert spy.seen[1] is train_labels
    assert not np.shares_memory(spy.seen[1], validation_labels)


def test_batched_prediction_and_saved_reload_are_equivalent(tmp_path: Path) -> None:
    matrix, labels = _small_training_data()
    model = fit_train_only(create_frozen_random_forest(), matrix, labels)
    direct = attack_probabilities(model, matrix)
    batched = batched_attack_probabilities(model, matrix, batch_size=7)
    np.testing.assert_array_equal(direct, batched)

    model_path = tmp_path / "forest.joblib"
    joblib.dump(model, model_path)
    reloaded = joblib.load(model_path)
    np.testing.assert_array_equal(
        batched,
        batched_attack_probabilities(reloaded, matrix, batch_size=11),
    )

    equivalent, maximum_difference = reload_probabilities_equivalent(
        np.asarray([0.1, 0.2]), np.asarray([0.1 + 3e-16, 0.2])
    )
    assert equivalent is True
    assert maximum_difference < 1e-15
    assert reload_probabilities_equivalent(np.asarray([0.1]), np.asarray([0.1 + 2e-15]))[0] is False
    np.testing.assert_array_equal(
        threshold_attack_scores(batched),
        threshold_attack_scores(batched_attack_probabilities(reloaded, matrix, batch_size=11)),
    )


def _write_logistic_comparison_fixture(root: Path) -> tuple[Path, SimpleNamespace]:
    run = root / "logistic-run"
    run.mkdir()
    model_path = run / "logistic_regression.joblib"
    model_path.write_bytes(b"fixture model")
    labels = np.asarray([0, 0, 1, 1], dtype=np.uint8)
    reference_metrics = calculate_binary_metrics(labels, np.zeros(labels.size))
    logistic_metrics = calculate_binary_metrics(labels, np.asarray([0.1, 0.2, 0.8, 0.9]))
    inputs = SimpleNamespace(
        state_sha256="a" * 64,
        configuration_sha256="b" * 64,
        report_sha256="c" * 64,
        y_validation=labels,
    )
    configuration = {
        "schema_version": LOGISTIC_SCHEMA_VERSION,
        "fit_partition": "train",
        "evaluation_partition": "validation",
        "label_mapping": LABEL_MAPPING,
        "preprocessing": {
            "state_sha256": inputs.state_sha256,
            "configuration_sha256": inputs.configuration_sha256,
            "report_sha256": inputs.report_sha256,
            "transformed_feature_names": list(TRANSFORMED_FEATURE_NAMES),
        },
        "decision_threshold": {
            "positive_label": 1,
            "positive_name": "Attack",
            "operator": ">=",
            "probability": ATTACK_THRESHOLD,
        },
    }
    config_path = run / "model_config.json"
    config_path.write_text(json.dumps(configuration), encoding="utf-8")
    report = {
        "schema_version": LOGISTIC_SCHEMA_VERSION,
        "completed": True,
        "global_training_ready": False,
        "configuration_sha256": sha256_file(config_path),
        "model": {
            "filename": model_path.name,
            "size_bytes": model_path.stat().st_size,
            "sha256": sha256_file(model_path),
        },
        "validation": {
            "sample_count": 4,
            "normal_count": 2,
            "attack_count": 2,
            "logistic_regression": logistic_metrics,
            "always_benign_reference": reference_metrics,
        },
    }
    (run / "evaluation_report.json").write_text(json.dumps(report), encoding="utf-8")
    return run, inputs


def test_comparison_provenance_and_feature_order_mismatch_fail_closed(tmp_path: Path) -> None:
    run, inputs = _write_logistic_comparison_fixture(tmp_path)
    metrics = load_verified_logistic_comparison(run, inputs)
    assert set(metrics) == {"logistic_regression", "always_benign_reference"}

    config_path = run / "model_config.json"
    configuration = json.loads(config_path.read_text(encoding="utf-8"))
    configuration["preprocessing"]["transformed_feature_names"] = list(
        reversed(TRANSFORMED_FEATURE_NAMES)
    )
    config_path.write_text(json.dumps(configuration), encoding="utf-8")
    with pytest.raises(NetworkBaselineError, match="logistic_comparison_provenance_mismatch"):
        load_verified_logistic_comparison(run, inputs)


def test_synthetic_smoke_uses_all_frozen_trees() -> None:
    smoke = run_synthetic_random_forest_smoke()
    assert smoke == {
        "completed": True,
        "sample_count": 6,
        "tree_count": 100,
        "class_mapping": [0, 1],
    }
