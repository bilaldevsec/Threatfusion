from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import numpy as np
import pytest
from numpy.lib.format import open_memmap

from threatfusion.datasets.adapters.cic_ids2018_benchmark import adapt_cic_benchmark_row
from threatfusion.models import network_cic_external_evaluation as cic_evaluation
from threatfusion.features.network_behavior import (
    CIC_IDS2018_CICFLOWMETER_V3_PROCESSED_REPRESENTATION_V1,
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
    NETWORK_BEHAVIOR_V1_FORBIDDEN_MODEL_FIELDS,
    NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
    UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
    NetworkCompatibilityStatus,
    project_network_behavior,
)
from threatfusion.models.network_cic_external_evaluation import (
    CATEGORY_CODES,
    CIC_EVALUATION_SCHEMA_VERSION,
    EXPECTED_FILES,
    HISTORICAL_CIC_EVALUATION_SCHEMA_VERSION,
    NetworkBaselineError,
    VerifiedCicEvidence,
    category_recall,
    evaluate_file_and_pooled,
    read_historical_cic_evaluation,
    run_cic_external_evaluation,
    transform_cic_records,
    verify_cic_evidence,
    write_cic_failure_status,
)
from threatfusion.models.network_logistic_baseline import calculate_binary_metrics
from threatfusion.preprocessing.network_behavior_v1 import (
    PREPROCESSING_SCHEMA_VERSION,
    TRANSFORMED_FEATURE_NAMES,
    NetworkBehaviorPreprocessor,
)


def _row(**updates: Any) -> dict[str, Any]:
    row = {
        "__source_file": "fixture.csv",
        "__source_row_number": 1,
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


def _preprocessor() -> NetworkBehaviorPreprocessor:
    return NetworkBehaviorPreprocessor(
        training_row_count=10,
        numeric_means=(0.0,) * 10,
        numeric_scales=(1.0,) * 10,
        zero_variance_features=(),
    )


def _quality_report() -> dict[str, Any]:
    return {
        "source": "CSE-CIC-IDS2018 benchmark/fixture.csv",
        "completed": True,
        "total_rows": 3,
        "accepted_count": 2,
        "rejected_count": 1,
        "rejection_rate": 1 / 3,
        "rejection_details": [
            {
                "row_number": 2,
                "fields": ["Flow Duration"],
                "reason": "must be finite and within allowed numeric bounds",
            }
        ],
        "source_file": "fixture.csv",
        "expected_column_count": 80,
        "canonical_label_counts": {"Attack": 1, "Normal": 1},
        "attack_category_counts": {"SSH-Bruteforce": 1},
    }


def test_feature_only_semantics_exclude_prohibited_fields_and_preserve_state(
    tmp_path: Path,
) -> None:
    assert not NETWORK_BEHAVIOR_V1_FORBIDDEN_MODEL_FIELDS.intersection(
        NETWORK_BEHAVIOR_V1_FEATURE_NAMES
    )
    record = adapt_cic_benchmark_row(_row())
    assert len(project_network_behavior(record)) == 11
    assert not hasattr(record, "src_ip") and not hasattr(record, "src_port")

    state = _preprocessor()
    before = state.to_dict()
    matrix = open_memmap(
        tmp_path / "X.npy", mode="w+", dtype=np.float64, shape=(2, len(TRANSFORMED_FEATURE_NAMES))
    )
    labels = open_memmap(tmp_path / "y.npy", mode="w+", dtype=np.uint8, shape=(2,))
    categories = open_memmap(tmp_path / "c.npy", mode="w+", dtype=np.uint8, shape=(2,))
    rows = [_row(), _row(**{"Flow Duration": "Infinity"}), _row(Label="BENIGN")]
    transform_cic_records(rows, state, matrix, labels, categories, _quality_report(), batch_size=1)

    assert labels.tolist() == [1, 0]
    assert categories.tolist() == [CATEGORY_CODES["SSH-Bruteforce"], 0]
    assert state.to_dict() == before


def test_rejection_or_output_alignment_mismatch_fails_closed(tmp_path: Path) -> None:
    matrix = open_memmap(
        tmp_path / "X.npy", mode="w+", dtype=np.float64, shape=(2, len(TRANSFORMED_FEATURE_NAMES))
    )
    labels = open_memmap(tmp_path / "y.npy", mode="w+", dtype=np.uint8, shape=(2,))
    categories = open_memmap(tmp_path / "c.npy", mode="w+", dtype=np.uint8, shape=(2,))
    with pytest.raises(NetworkBaselineError, match="cic_source_validation_reconciliation_failed"):
        transform_cic_records(
            [_row(), _row(Label="BENIGN")],
            _preprocessor(),
            matrix,
            labels,
            categories,
            _quality_report(),
        )


class _ScoreModel:
    classes_ = np.asarray([0, 1])

    def predict_proba(self, matrix: np.ndarray) -> np.ndarray:
        scores = np.asarray(matrix[:, 0], dtype=np.float64)
        return np.column_stack((1.0 - scores, scores))


def test_per_file_and_pooled_metrics_are_computed_from_rows(tmp_path: Path) -> None:
    matrices = (np.asarray([[0.1], [0.9]]), np.asarray([[0.4], [0.6]]))
    labels = (np.asarray([0, 1], dtype=np.uint8), np.asarray([1, 0], dtype=np.uint8))
    categories = (
        np.asarray([0, CATEGORY_CODES["SSH-Bruteforce"]], dtype=np.uint8),
        np.asarray([CATEGORY_CODES["FTP-BruteForce"], 0], dtype=np.uint8),
    )
    model = SimpleNamespace(name="logistic_regression", model=_ScoreModel())
    per_file, pooled = evaluate_file_and_pooled(
        (model,), matrices, labels, categories, ("first.csv", "second.csv"), tmp_path
    )

    expected = calculate_binary_metrics(
        np.asarray([0, 1, 1, 0], dtype=np.uint8), np.asarray([0.1, 0.9, 0.4, 0.6])
    )
    assert pooled["logistic_regression"]["attack_f1"] == expected["attack_f1"]
    assert per_file["first.csv"]["logistic_regression"]["attack_recall"] == 1.0
    assert pooled["logistic_regression"]["attack_categories"]["FTP-BruteForce"] == {
        "support": 1,
        "recall": 0.0,
    }


def test_batch_boundaries_are_consistent(tmp_path: Path) -> None:
    rows = [_row(), _row(**{"Flow Duration": "Infinity"}), _row(Label="BENIGN")]
    outputs = []
    for batch_size in (1, 10):
        directory = tmp_path / str(batch_size)
        directory.mkdir()
        matrix = open_memmap(
            directory / "X.npy",
            mode="w+",
            dtype=np.float64,
            shape=(2, len(TRANSFORMED_FEATURE_NAMES)),
        )
        labels = open_memmap(directory / "y.npy", mode="w+", dtype=np.uint8, shape=(2,))
        categories = open_memmap(directory / "c.npy", mode="w+", dtype=np.uint8, shape=(2,))
        transform_cic_records(
            rows,
            _preprocessor(),
            matrix,
            labels,
            categories,
            _quality_report(),
            batch_size=batch_size,
        )
        outputs.append(np.asarray(matrix).copy())
    np.testing.assert_array_equal(outputs[0], outputs[1])


def test_partial_corrupt_or_mismatched_cic_evidence_fails(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("not: [valid", encoding="utf-8")
    with pytest.raises(NetworkBaselineError, match="cic_manifest_unreadable"):
        verify_cic_evidence(tmp_path, manifest, tmp_path, tmp_path / "missing.json")


def test_category_metadata_is_sanitized_and_undefined_recall_is_explicit() -> None:
    labels = np.asarray([0, 1], dtype=np.uint8)
    scores = np.asarray([0.1, 0.9])
    categories = np.asarray([0, CATEGORY_CODES["SSH-Bruteforce"]], dtype=np.uint8)
    result = category_recall(labels, scores, categories)
    assert result["SSH-Bruteforce"] == {"support": 1, "recall": 1.0}
    assert result["DoS attacks-GoldenEye"] == {"support": 0, "recall": None}
    assert all("/" not in name and "\\" not in name for name in result)


def test_runner_has_no_fit_call_and_failure_evidence_is_incomplete(tmp_path: Path) -> None:
    assert "fit" not in run_cic_external_evaluation.__code__.co_names
    path = write_cic_failure_status(tmp_path, "fixture_failure")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert CIC_EVALUATION_SCHEMA_VERSION == "cic_classical_external_evaluation_v2"
    assert payload == {
        "schema_version": CIC_EVALUATION_SCHEMA_VERSION,
        "completed": False,
        "failure_code": "fixture_failure",
    }


def _verified_preprocessing_stub() -> SimpleNamespace:
    return SimpleNamespace(
        configuration={
            "schema_version": PREPROCESSING_SCHEMA_VERSION,
            "feature_contract": NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
            "input_feature_names": list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES),
            "transformed_feature_names": list(TRANSFORMED_FEATURE_NAMES),
            "source": {
                "registered_raw_files": [{"name": f"UNSW-NB15_{part}.csv"} for part in range(1, 5)]
            },
        },
        state_sha256="a" * 64,
        configuration_sha256="b" * 64,
        report_sha256="c" * 64,
    )


def test_current_cic_is_rejected_before_transform_prediction_or_run_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preprocessing = _verified_preprocessing_stub()
    evidence = VerifiedCicEvidence(
        manifest_sha256="d" * 64,
        files=(),
        profile_sha256="e" * 64,
        source_representation=CIC_IDS2018_CICFLOWMETER_V3_PROCESSED_REPRESENTATION_V1,
    )
    models = {
        name: SimpleNamespace(
            name=name,
            model=SimpleNamespace(n_features_in_=len(TRANSFORMED_FEATURE_NAMES)),
        )
        for name in ("logistic_regression", "random_forest")
    }
    monkeypatch.setattr(
        cic_evaluation, "verify_preprocessing_artifacts", lambda _path: preprocessing
    )
    monkeypatch.setattr(
        cic_evaluation,
        "verify_cic_evidence",
        lambda *_args: evidence,
    )
    monkeypatch.setattr(
        cic_evaluation,
        "verify_saved_model",
        lambda _path, _preprocessing, *, name: models[name],
    )

    def forbidden_call(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("transformation or prediction started before compatibility approval")

    monkeypatch.setattr(cic_evaluation, "transform_cic_records", forbidden_call)
    monkeypatch.setattr(cic_evaluation, "predict_in_batches", forbidden_call)
    artifact_root = tmp_path / "artifacts/reports/network_cic_external_evaluation"

    with pytest.raises(NetworkBaselineError, match="cross_source_byte_semantics_incompatible"):
        run_cic_external_evaluation(
            project_root=tmp_path,
            manifest_path=tmp_path / "manifest.yaml",
            quality_directory=tmp_path / "quality",
            profile_path=tmp_path / "profile.json",
            preprocessing_directory=tmp_path / "preprocessing",
            logistic_directory=tmp_path / "logistic",
            forest_directory=tmp_path / "forest",
            artifact_root=artifact_root,
            run_id="must-not-exist",
        )

    assert not artifact_root.exists()


def test_historical_completed_report_is_readable_without_compatibility_approval(
    tmp_path: Path,
) -> None:
    run_directory = tmp_path / "historical"
    run_directory.mkdir()
    configuration = {
        "schema_version": HISTORICAL_CIC_EVALUATION_SCHEMA_VERSION,
        "external_dataset": "cse_cic_ids2018",
        "transformed_feature_names": list(TRANSFORMED_FEATURE_NAMES),
        "cic_evidence": {
            "files": [{"basename": basename} for basename in EXPECTED_FILES],
        },
        "preprocessing": {
            "state_sha256": "a" * 64,
            "configuration_sha256": "b" * 64,
            "report_sha256": "c" * 64,
        },
        "models": {"logistic_regression": {}, "random_forest": {}},
    }
    configuration_path = run_directory / "evaluation_config.json"
    configuration_path.write_text(
        json.dumps(configuration, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    report = {
        "schema_version": HISTORICAL_CIC_EVALUATION_SCHEMA_VERSION,
        "completed": True,
        "configuration_sha256": sha256(configuration_path.read_bytes()).hexdigest(),
        "checks": {"semantic_feature_compatibility_verified": True},
    }
    report_path = run_directory / "evaluation_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    before = (configuration_path.read_bytes(), report_path.read_bytes())

    historical = read_historical_cic_evaluation(run_directory)

    assert historical.completed is True
    assert historical.report["checks"]["semantic_feature_compatibility_verified"] is True
    assert (
        historical.compatibility.status is NetworkCompatibilityStatus.DEMONSTRATED_INCOMPATIBILITY
    )
    assert historical.compatibility.approved_for_inference is False
    assert historical.compatibility.key.fitted_source_representation == (
        UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1
    )
    assert before == (configuration_path.read_bytes(), report_path.read_bytes())
