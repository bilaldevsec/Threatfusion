from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from threatfusion.models.network_rate_log1p_experiment import (
    RateLog1pExperimentError,
    _fit_candidate_preprocessing,
    _verify_candidate_bundle,
    acceptance_gates,
    render_report,
    transform_rate_pair,
)


def test_rate_log1p_domain_and_zero() -> None:
    np.testing.assert_array_equal(transform_rate_pair(np.asarray([0.0, 0.0])), [0.0, 0.0])
    np.testing.assert_allclose(transform_rate_pair(np.asarray([1.0, 3.0])), np.log1p([1.0, 3.0]))
    for invalid in ([-1.0, 0.0], [float("nan"), 0.0], [float("inf"), 0.0]):
        with pytest.raises(RateLog1pExperimentError, match="rate_domain_invalid"):
            transform_rate_pair(np.asarray(invalid))


def test_acceptance_gates_and_zero_denominator() -> None:
    overlap = {
        "attack": {"autoencoder_only_rf_missed": 119},
        "normal": {"autoencoder_only_added_false_positive": 1574},
    }
    assert acceptance_gates(overlap, 1628)["all_passed"] is True
    overlap["attack"]["autoencoder_only_rf_missed"] = 96
    assert acceptance_gates(overlap, 1628)["all_passed"] is False
    overlap = {
        "attack": {"autoencoder_only_rf_missed": 96},
        "normal": {"autoencoder_only_added_false_positive": 0},
    }
    ratio = acceptance_gates(overlap, 54)["ratio_at_least_0_075"]
    assert ratio["passed"] is True and ratio["value"] is None
    overlap["attack"]["autoencoder_only_rf_missed"] = 0
    assert acceptance_gates(overlap, 54)["ratio_at_least_0_075"]["passed"] is False


def test_candidate_statistics_use_all_train_and_other_columns_are_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threatfusion.models.network_rate_log1p_experiment as experiment

    monkeypatch.setitem(experiment.EXPECTED_COUNTS, "train", {"rows": 3, "benign": 2, "attack": 1})
    monkeypatch.setitem(
        experiment.EXPECTED_COUNTS, "validation", {"rows": 2, "benign": 1, "attack": 1}
    )
    train = np.arange(42, dtype=np.float64).reshape(3, 14)
    validation = np.arange(28, dtype=np.float64).reshape(2, 14)
    baseline = SimpleNamespace(
        X_train=train,
        X_validation=validation,
        y_train=np.asarray([0, 1, 0], dtype=np.uint8),
        y_validation=np.asarray([0, 1], dtype=np.uint8),
    )
    rates = {
        "train_rates.npy": np.asarray([[0.0, 1.0], [3.0, 7.0], [8.0, 15.0]]),
        "validation_rates.npy": np.asarray([[1.0, 3.0], [7.0, 8.0]]),
    }
    candidate = _fit_candidate_preprocessing(baseline, rates, tmp_path / "candidate")
    expected = np.log1p(rates["train_rates.npy"])
    assert candidate["state"]["rate_transform"]["means"] == pytest.approx(expected.mean(axis=0))
    unchanged = tuple(index for index in range(14) if index not in (5, 6))
    np.testing.assert_array_equal(candidate["X_train"][:, unchanged], train[:, unchanged])
    np.testing.assert_array_equal(candidate["y_train"], baseline.y_train)


def test_candidate_bundle_rejects_baseline_identity(tmp_path: Path) -> None:
    identities = {
        "model": "unsw_network_rate_log1p_benign_autoencoder_v1",
        "preprocessing": "unsw_train.rate_log1p_all_train_zscore.14_columns.v1",
        "score": "mean_squared_reconstruction_error_14_rate_log1p_float32_per_record_v1",
        "threshold": "unsw_january_benign_higher_p99_rate_log1p_v1",
        "scoring_contract": "unsw_autoencoder_per_record_scoring_v2",
    }
    config = {"identities": identities}
    threshold = {
        "score_identity": identities["score"],
        "threshold_identity": identities["threshold"],
    }
    for name, value in (
        ("experiment_config.json", config),
        ("threshold.json", threshold),
        ("source_provenance_manifest.json", {}),
    ):
        (tmp_path / name).write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    (tmp_path / "autoencoder_state.pt").write_bytes(b"state")
    from threatfusion.utils.checksum import sha256_file

    manifest = {
        "configuration_sha256": sha256_file(tmp_path / "experiment_config.json"),
        "model_state_sha256": sha256_file(tmp_path / "autoencoder_state.pt"),
        "threshold_sha256": sha256_file(tmp_path / "threshold.json"),
        "source_provenance_manifest_sha256": sha256_file(
            tmp_path / "source_provenance_manifest.json"
        ),
    }
    (tmp_path / "artifact_manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )
    _verify_candidate_bundle(tmp_path)
    config["identities"]["preprocessing"] = "baseline"
    (tmp_path / "experiment_config.json").write_text(
        json.dumps(config, sort_keys=True), encoding="utf-8"
    )
    with pytest.raises(RateLog1pExperimentError, match="candidate_bundle_identity_mismatch"):
        _verify_candidate_bundle(tmp_path)


def test_landlock_denies_non_allowlisted_file(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    denied = tmp_path / "denied"
    allowed.mkdir()
    denied.mkdir()
    target = denied / "february.npy"
    target.write_bytes(b"prohibited")
    code = f"""
from pathlib import Path
from scripts.run_rate_log1p_autoencoder_experiment import _assert_denied, _landlock
e = _landlock([Path('/usr'), Path('/lib'), Path('/lib64'), Path('/etc'), Path('/proc'), Path({str(allowed)!r})], [Path({str(allowed)!r})])
assert e['abi'] >= 3
assert _assert_denied([Path({str(target)!r})])[0]['denied'] is True
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[3],
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("mode", ("prepare", "run"))
def test_closed_historical_runner_rejects_execution_modes(mode: str) -> None:
    runner = (
        Path(__file__).resolve().parents[3] / "scripts/run_rate_log1p_autoencoder_experiment.py"
    )
    result = subprocess.run([sys.executable, str(runner), mode], capture_output=True, check=False)
    assert result.returncode == 1
    assert result.stdout == b""
    assert (
        result.stderr == b"rate-log1p experiment failed code=experiment_closed_blocked_no_reuse\n"
    )


def test_render_requires_persisted_completion_and_never_fits(tmp_path: Path) -> None:
    report = tmp_path / "evaluation_report.json"
    report.write_text(json.dumps({"completed": False}), encoding="utf-8")
    with pytest.raises(RateLog1pExperimentError, match="completed_report_required"):
        render_report(report, tmp_path)
    metrics = {
        "true_positive": 1,
        "false_positive": 2,
        "true_negative": 3,
        "false_negative": 4,
        "attack_precision": 0.1,
        "attack_recall": 0.2,
        "attack_f1": 0.15,
        "false_positive_rate": 0.4,
    }
    report.write_text(
        json.dumps(
            {
                "completed": True,
                "baseline": {"autoencoder": metrics},
                "candidate": {"autoencoder": metrics},
            }
        ),
        encoding="utf-8",
    )
    markdown, chart = render_report(report, tmp_path)
    assert markdown.is_file() and chart.is_file()
