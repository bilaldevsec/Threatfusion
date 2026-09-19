"""Focused tests for January residual cohort alignment and aggregation."""

from __future__ import annotations

import json

import numpy as np
import pytest

import scripts.audit_network_autoencoder_residuals as audit
from scripts.audit_network_autoencoder_residuals import (
    ResidualAuditError,
    aggregate_cohort,
    calculate_overlap,
    cohort_masks,
    publish_aggregates,
)


def _valid_recovery_report() -> dict:
    scores = np.asarray([1.0], dtype=np.float64)
    squared = np.ones((1, 14), dtype=np.float64)
    cohort = aggregate_cohort(np.asarray([True]), scores, squared)
    return {
        "schema_version": audit.SCHEMA_VERSION,
        "completed": True,
        "artifact_identity": audit.ARTIFACT_IDENTITY,
        "threshold": {"value": audit.THRESHOLD, "operator": ">", "ties": "within_threshold"},
        "random_forest_threshold": {"value": audit.ATTACK_THRESHOLD, "operator": ">="},
        "population": {"rows": audit.EXPECTED_ROWS, **audit.EXPECTED_LABEL_COUNTS},
        "feature_order": list(audit.TRANSFORMED_FEATURE_NAMES),
        "feature_groups": {
            name: [index + 1 for index in indices] for name, indices in audit.FEATURE_GROUPS.items()
        },
        "score_residual_reconciliation": {
            "exact": True,
            "absolute_tolerance": 0.0,
            "maximum_absolute_score_difference": 0.0,
        },
        "confusion": {
            "autoencoder": audit.EXPECTED_AE_CONFUSION,
            "random_forest": audit.EXPECTED_RF_CONFUSION,
        },
        "overlap": audit.EXPECTED_OVERLAP,
        "cohorts": {
            name: {**cohort, "record_count": audit.EXPECTED_COHORT_COUNTS[name]}
            for name in audit.COHORT_NAMES
        },
        "resources": {
            "ae_forward_rows": audit.EXPECTED_ROWS,
            "ae_forward_shape": [1, 14],
            "rf_prediction_batch_size": audit.PREDICTION_BATCH_SIZE,
            "train_accessed": False,
            "february_accessed": False,
            "cic_accessed": False,
        },
    }


def test_cohort_alignment_reconciles_all_label_specific_overlap_cells() -> None:
    labels = np.asarray([1, 1, 1, 1, 0, 0, 0, 0], dtype=np.uint8)
    ae = np.asarray([1, 1, 0, 0, 1, 1, 0, 0], dtype=np.uint8)
    rf = np.asarray([1, 0, 1, 0, 1, 0, 1, 0], dtype=np.uint8)

    overlap = calculate_overlap(labels, ae, rf)
    masks = cohort_masks(labels, ae, rf)

    assert overlap == {
        "attack": {
            "both_detected": 1,
            "autoencoder_only_rf_missed": 1,
            "random_forest_only_ae_missed": 1,
            "missed_by_both": 1,
        },
        "normal": {
            "both_false_positive": 1,
            "autoencoder_only_added_false_positive": 1,
            "random_forest_only_false_positive": 1,
            "correctly_unflagged_by_both": 1,
        },
    }
    assert [int(np.count_nonzero(masks[name])) for name in masks] == [1, 1, 1, 1]


def test_cohort_alignment_rejects_shape_or_nonbinary_values() -> None:
    labels = np.asarray([0, 1], dtype=np.uint8)
    with pytest.raises(ResidualAuditError, match="^cohort_alignment_mismatch$"):
        calculate_overlap(labels, np.asarray([0], dtype=np.uint8), labels)
    with pytest.raises(ResidualAuditError, match="^cohort_values_invalid$"):
        calculate_overlap(labels, np.asarray([0, 2], dtype=np.uint8), labels)


def test_residual_aggregation_reports_exact_feature_fractions_and_medians() -> None:
    scores = np.asarray([15.0 / 14.0, 25.0 / 14.0, 1.0], dtype=np.float64)
    squared = np.zeros((3, 14), dtype=np.float64)
    squared[0, :2] = [3.0, 12.0]
    squared[1, :2] = [5.0, 20.0]
    squared[2, 0] = 14.0
    mask = np.asarray([True, True, False])

    result = aggregate_cohort(mask, scores, squared)

    assert result["record_count"] == 2
    assert result["empty"] is False
    assert result["total_squared_residual"] == 40.0
    assert result["features"][0]["mean_squared_residual"] == 4.0
    assert result["features"][0]["median_squared_residual"] == 4.0
    assert result["features"][0]["fraction_of_total_reconstruction_error"] == 0.2
    assert result["features"][1]["fraction_of_total_reconstruction_error"] == 0.8
    assert sum(item["fraction_of_total_reconstruction_error"] for item in result["features"]) == 1.0
    assert sum(item["fraction_of_total_reconstruction_error"] for item in result["groups"]) == 1.0


def test_empty_cohort_is_explicit_and_uses_null_statistics() -> None:
    result = aggregate_cohort(
        np.asarray([False, False]),
        np.asarray([0.1, 0.2], dtype=np.float64),
        np.zeros((2, 14), dtype=np.float64),
    )

    assert result["record_count"] == 0
    assert result["empty"] is True
    assert result["score_distribution"]["median"] is None
    assert all(item["mean_squared_residual"] is None for item in result["features"])
    assert all(
        item["fraction_of_total_reconstruction_error"] is None for item in result["features"]
    )


def test_residual_aggregation_rejects_misaligned_arrays() -> None:
    with pytest.raises(ResidualAuditError, match="^residual_aggregation_alignment_mismatch$"):
        aggregate_cohort(
            np.asarray([True]),
            np.asarray([0.1, 0.2], dtype=np.float64),
            np.zeros((2, 14), dtype=np.float64),
        )


def test_actual_json_csv_and_chart_publication_uses_corrected_feature_fields(tmp_path) -> None:
    scores = np.asarray([1.0], dtype=np.float64)
    squared = np.ones((1, 14), dtype=np.float64)
    cohorts = {"example": aggregate_cohort(np.asarray([True]), scores, squared)}
    report = {"completed": True, "cohorts": cohorts, "resources": {}}
    output = tmp_path / "published"
    recovery = tmp_path / ".recovery.json"

    aggregate_path = publish_aggregates(output, report, recovery_path=recovery)

    published = json.loads(aggregate_path.read_text(encoding="utf-8"))
    assert published["cohorts"]["example"]["features"][0]["index"] == 1
    assert published["cohorts"]["example"]["features"][0]["name"] == "duration_ms__zscore"
    csv_text = (output / "feature_contributions.csv").read_text(encoding="utf-8")
    assert "feature_index,feature_name" in csv_text
    assert "duration_ms__zscore" in csv_text
    assert (output / "feature_contributions.svg").read_text(encoding="utf-8").startswith("<svg")
    assert recovery.is_file()


def test_publication_failure_retains_aggregate_only_recovery_for_retry(
    tmp_path, monkeypatch
) -> None:
    scores = np.asarray([1.0], dtype=np.float64)
    squared = np.ones((1, 14), dtype=np.float64)
    sentinel = "raw-record-secret-must-not-be-retained"
    report = {
        "completed": True,
        "cohorts": {"example": aggregate_cohort(np.asarray([True]), scores, squared)},
        "resources": {},
    }
    output = tmp_path / "published"
    recovery = tmp_path / ".recovery.json"
    original_chart = audit._write_chart

    def fail_chart(*_args, **_kwargs) -> None:
        raise OSError(sentinel)

    monkeypatch.setattr(audit, "_write_chart", fail_chart)
    with pytest.raises(OSError, match=sentinel):
        publish_aggregates(output, report, recovery_path=recovery)

    assert not output.exists()
    recovery_text = recovery.read_text(encoding="utf-8")
    assert sentinel not in recovery_text
    assert "aggregate_report" in recovery_text

    monkeypatch.setattr(audit, "_write_chart", original_chart)
    recovered_report = json.loads(recovery_text)["aggregate_report"]
    aggregate_path = publish_aggregates(output, recovered_report, recovery_path=recovery)
    assert aggregate_path.is_file()
    assert (output / "feature_contributions.csv").is_file()
    assert (output / "feature_contributions.svg").is_file()


def test_run_retries_verified_recovery_without_reopening_scoring_inputs(tmp_path) -> None:
    report = _valid_recovery_report()
    output = tmp_path / "published"
    recovery = audit._recovery_path(output)
    audit._write_recovery(recovery, report)

    aggregate_path = audit.run_audit(
        preprocessing_directory=tmp_path / "must-not-open-preprocessing",
        autoencoder_directory=tmp_path / "must-not-open-autoencoder",
        forest_directory=tmp_path / "must-not-open-forest",
        output_directory=output,
    )

    assert aggregate_path.is_file()
    assert (output / "feature_contributions.csv").is_file()
    assert (output / "feature_contributions.svg").is_file()


def test_recovery_rejects_changed_aggregate_value(tmp_path) -> None:
    recovery = tmp_path / ".recovery.json"
    audit._write_recovery(recovery, _valid_recovery_report())
    payload = json.loads(recovery.read_text(encoding="utf-8"))
    payload["aggregate_report"]["cohorts"]["ae_only_attack"]["total_squared_residual"] += 1.0
    recovery.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ResidualAuditError, match="^recovery_integrity_mismatch$"):
        audit._load_recovery(recovery)


def test_cli_failure_is_nonzero_and_sanitized(tmp_path, monkeypatch, capsys) -> None:
    secret = str(tmp_path / "sensitive-input")

    def fail_audit(**_kwargs):
        raise OSError(secret)

    monkeypatch.setattr(audit, "run_audit", fail_audit)

    assert audit.main(["--project-root", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "residual audit failed code=audit_failed\n"
    assert secret not in captured.err
