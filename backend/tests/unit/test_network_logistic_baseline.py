import json
import warnings
from pathlib import Path
from types import SimpleNamespace

import joblib
import numpy as np
import pytest
from sklearn.exceptions import ConvergenceWarning

from threatfusion.features.network_behavior import NETWORK_BEHAVIOR_V1_FEATURE_NAMES
from threatfusion.models.network_logistic_baseline import (
    ATTACK_THRESHOLD,
    BASELINE_SCHEMA_VERSION,
    FROZEN_LOGISTIC_PARAMETERS,
    NetworkBaselineError,
    attack_probabilities,
    attack_probability_column,
    calculate_binary_metrics,
    convergence_details,
    create_frozen_logistic_regression,
    run_synthetic_smoke,
    threshold_attack_scores,
    verify_preprocessing_artifacts,
)
from threatfusion.preprocessing.network_behavior_v1 import (
    ASSIGNMENT_SCHEMA_VERSION,
    ASSIGNMENT_SEED,
    LABEL_MAPPING,
    PREPROCESSING_SCHEMA_VERSION,
    TRANSFORMED_FEATURE_NAMES,
    NetworkBehaviorPreprocessor,
)
from threatfusion.utils.checksum import sha256_file


class _ProbabilityModel:
    def __init__(self, classes: list[int], probabilities: list[list[float]]) -> None:
        self.classes_ = np.asarray(classes)
        self._probabilities = np.asarray(probabilities)

    def predict_proba(self, matrix: np.ndarray) -> np.ndarray:
        assert matrix.shape[0] == self._probabilities.shape[0]
        return self._probabilities


def test_attack_probability_column_uses_explicit_label_mapping() -> None:
    model = _ProbabilityModel([1, 0], [[0.8, 0.2], [0.1, 0.9]])
    matrix = np.zeros((2, 1))

    assert LABEL_MAPPING == {"Normal": 0, "Attack": 1}
    assert attack_probability_column(model) == 0
    np.testing.assert_array_equal(attack_probabilities(model, matrix), [0.8, 0.1])

    model.classes_ = np.asarray([0, 2])
    with pytest.raises(NetworkBaselineError, match="model_binary_class_mapping_invalid"):
        attack_probability_column(model)


def test_fixed_threshold_is_inclusive_at_point_five() -> None:
    assert ATTACK_THRESHOLD == 0.5
    np.testing.assert_array_equal(
        threshold_attack_scores(np.asarray([0.0, 0.499999, 0.5, 1.0])),
        [0, 0, 1, 1],
    )


def test_confusion_matrix_and_metrics_are_calculated_from_attack_scores() -> None:
    labels = np.asarray([0, 0, 0, 1, 1, 1], dtype=np.uint8)
    scores = np.asarray([0.1, 0.6, 0.2, 0.9, 0.5, 0.4])

    metrics = calculate_binary_metrics(labels, scores)

    assert metrics["true_positive"] == 2
    assert metrics["false_positive"] == 1
    assert metrics["true_negative"] == 2
    assert metrics["false_negative"] == 1
    assert metrics["attack_precision"] == pytest.approx(2 / 3)
    assert metrics["attack_recall"] == pytest.approx(2 / 3)
    assert metrics["attack_f1"] == pytest.approx(2 / 3)
    assert metrics["false_positive_rate"] == pytest.approx(1 / 3)
    assert metrics["balanced_accuracy"] == pytest.approx(2 / 3)
    assert metrics["accuracy"] == pytest.approx(2 / 3)
    assert metrics["predicted_attack_count"] == 3
    assert metrics["predicted_attack_percentage"] == 50.0
    assert metrics["average_precision"] == pytest.approx(0.8055555555555556)
    assert metrics["roc_auc"] == pytest.approx(7 / 9)


def test_always_benign_and_zero_positive_edge_cases_are_explicit() -> None:
    labels = np.asarray([0, 0, 1, 1], dtype=np.uint8)
    reference = calculate_binary_metrics(labels, np.zeros(4))

    assert reference["true_positive"] == 0
    assert reference["false_positive"] == 0
    assert reference["true_negative"] == 2
    assert reference["false_negative"] == 2
    assert reference["attack_precision"] == 0.0
    assert reference["attack_recall"] == 0.0
    assert reference["attack_f1"] == 0.0
    assert reference["false_positive_rate"] == 0.0
    assert reference["balanced_accuracy"] == 0.5
    assert reference["accuracy"] == 0.5
    assert reference["average_precision"] == 0.5
    assert reference["roc_auc"] == 0.5
    assert reference["predicted_attack_count"] == 0

    no_attacks = calculate_binary_metrics(np.zeros(3, dtype=np.uint8), np.zeros(3))
    assert no_attacks["attack_precision"] == 0.0
    assert no_attacks["attack_recall"] == 0.0
    assert no_attacks["average_precision"] == 0.0
    assert no_attacks["balanced_accuracy"] is None
    assert no_attacks["roc_auc"] is None


def test_validation_labels_cannot_influence_fit() -> None:
    train_matrix = np.asarray([[-2.0], [-1.0], [1.0], [2.0]])
    train_labels = np.asarray([0, 0, 1, 1], dtype=np.uint8)
    validation_matrix = np.asarray([[-0.25], [0.25]])
    first = create_frozen_logistic_regression().fit(train_matrix, train_labels)
    second = create_frozen_logistic_regression().fit(train_matrix, train_labels)

    calculate_binary_metrics(np.asarray([0, 1]), attack_probabilities(first, validation_matrix))
    calculate_binary_metrics(np.asarray([1, 0]), attack_probabilities(second, validation_matrix))

    np.testing.assert_array_equal(first.coef_, second.coef_)
    np.testing.assert_array_equal(first.intercept_, second.intercept_)


def _write_preprocessing_fixture(root: Path) -> Path:
    run = root / "preprocessing-run"
    run.mkdir()
    train_rows = 4
    validation_rows = 2
    X_train = np.arange(train_rows * 14, dtype=np.float64).reshape(train_rows, 14)
    X_validation = np.arange(validation_rows * 14, dtype=np.float64).reshape(validation_rows, 14)
    y_train = np.asarray([0, 0, 1, 1], dtype=np.uint8)
    y_validation = np.asarray([0, 1], dtype=np.uint8)
    arrays = {
        "X_train": X_train,
        "y_train": y_train,
        "X_validation": X_validation,
        "y_validation": y_validation,
    }
    for name, array in arrays.items():
        np.save(run / f"{name}.npy", array, allow_pickle=False)
    state = NetworkBehaviorPreprocessor(
        training_row_count=train_rows,
        numeric_means=(0.0,) * 10,
        numeric_scales=(1.0,) * 10,
        zero_variance_features=(),
    )
    state.save(run / "preprocessor_state.json")
    configuration = {
        "schema_version": PREPROCESSING_SCHEMA_VERSION,
        "feature_contract": "network_behavior_v1",
        "fit_partition": "train",
        "transform_partitions": ["train", "validation"],
        "label_mapping": LABEL_MAPPING,
        "input_feature_names": list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES),
        "transformed_feature_names": list(TRANSFORMED_FEATURE_NAMES),
        "output_dtype": "float64",
        "assignment": {
            "schema_version": ASSIGNMENT_SCHEMA_VERSION,
            "seed": ASSIGNMENT_SEED,
            "archive_sha256": "a" * 64,
            "preflight_report_sha256": "b" * 64,
            "report_sha256": "c" * 64,
        },
        "source": {
            "manifest_sha256": "d" * 64,
            "registered_raw_files": [
                {"name": f"UNSW-NB15_{index}.csv", "rows": 1, "sha256": "e" * 64}
                for index in range(1, 5)
            ],
        },
    }
    config_path = run / "preprocessing_config.json"
    config_path.write_text(json.dumps(configuration), encoding="utf-8")
    counts = {
        "train": {"rows": 4, "benign": 2, "attack": 2},
        "validation": {"rows": 2, "benign": 1, "attack": 1},
        "excluded": {"test": 1, "quarantine": 0, "rejected": 0},
    }
    report = {
        "schema_version": PREPROCESSING_SCHEMA_VERSION,
        "completed": True,
        "global_training_ready": False,
        "fit_partition": "train",
        "transformed_partitions": ["train", "validation"],
        "input_feature_names": list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES),
        "output_feature_names": list(TRANSFORMED_FEATURE_NAMES),
        "input_feature_count": 11,
        "output_feature_count": 14,
        "counts": counts,
        "shapes": {name: list(array.shape) for name, array in arrays.items()},
        "checks": {
            "assignment_and_source_counts_reconciled": True,
            "assignment_evidence_verified": True,
            "fitted_state_reload_equivalent": True,
            "matrices_finite": True,
            "only_train_influenced_fitted_state": True,
            "test_and_cic_not_transformed": True,
        },
        "hashes": {
            "configuration": sha256_file(config_path),
            "fitted_state": sha256_file(run / "preprocessor_state.json"),
            "outputs": {
                name: {
                    "sha256": sha256_file(run / f"{name}.npy"),
                    "size_bytes": (run / f"{name}.npy").stat().st_size,
                }
                for name in arrays
            },
        },
    }
    (run / "preprocessing_report.json").write_text(json.dumps(report), encoding="utf-8")
    return run


def test_preprocessing_integrity_and_feature_order_fail_closed(tmp_path: Path) -> None:
    run = _write_preprocessing_fixture(tmp_path)
    verified = verify_preprocessing_artifacts(run)
    assert verified.X_train.shape == (4, 14)

    report_path = run / "preprocessing_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["output_feature_names"] = list(reversed(report["output_feature_names"]))
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(
        NetworkBaselineError, match="preprocessing_report_incomplete_or_inconsistent"
    ):
        verify_preprocessing_artifacts(run)


def test_saved_model_reload_preserves_probabilities_and_predictions(tmp_path: Path) -> None:
    matrix = np.asarray([[-2.0], [-1.0], [1.0], [2.0]])
    labels = np.asarray([0, 0, 1, 1], dtype=np.uint8)
    model = create_frozen_logistic_regression().fit(matrix, labels)
    path = tmp_path / "model.joblib"
    joblib.dump(model, path)
    reloaded = joblib.load(path)

    np.testing.assert_array_equal(
        attack_probabilities(model, matrix), attack_probabilities(reloaded, matrix)
    )
    np.testing.assert_array_equal(
        threshold_attack_scores(attack_probabilities(model, matrix)),
        threshold_attack_scores(attack_probabilities(reloaded, matrix)),
    )


def test_convergence_warning_is_reported_without_claiming_convergence() -> None:
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        warnings.warn("fixture convergence limit", ConvergenceWarning, stacklevel=1)
    model = SimpleNamespace(n_iter_=np.asarray([1000]), max_iter=1000)

    details = convergence_details(model, captured)

    assert details["converged"] is False
    assert details["reached_iteration_limit"] is True
    assert details["convergence_warning_count"] == 1
    assert details["iteration_count_by_class"] == [1000]


def test_frozen_configuration_and_synthetic_smoke() -> None:
    assert BASELINE_SCHEMA_VERSION == "network_logistic_baseline_v1"
    assert FROZEN_LOGISTIC_PARAMETERS == {
        "penalty": "l2",
        "C": 1.0,
        "solver": "lbfgs",
        "fit_intercept": True,
        "class_weight": None,
        "max_iter": 1000,
        "tol": 1e-4,
    }
    assert run_synthetic_smoke()["completed"] is True
