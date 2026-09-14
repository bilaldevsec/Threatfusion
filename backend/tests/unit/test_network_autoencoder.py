from __future__ import annotations

import hashlib
from collections.abc import Callable
from inspect import signature
from pathlib import Path
from typing import Any

import numpy as np
import pytest
import torch

from threatfusion.models import network_autoencoder as autoencoder
from threatfusion.models.network_autoencoder import (
    CONFIG_FILENAME,
    DETECTOR_IDENTITY,
    DETECTOR_VERSION,
    EXPECTED_COUNTS,
    EXPECTED_PREPROCESSING_HASHES,
    HISTORICAL_ARTIFACT_IDENTITY,
    INPUT_WIDTH,
    MANIFEST_FILENAME,
    MODEL_FILENAME,
    MODEL_IDENTITY,
    MODEL_SOURCE_SNAPSHOT_FILENAME,
    PREPROCESSING_REQUIREMENTS,
    PROTOCOL_SNAPSHOT_FILENAME,
    PROVENANCE_MANIFEST_FILENAME,
    QUANTILE,
    RELOAD_SAMPLE_SIZE,
    REPORT_FILENAME,
    RUNNER_SOURCE_SNAPSHOT_FILENAME,
    SCHEMA_VERSION,
    SCORE_IDENTITY,
    SCORING_CONTRACT_VERSION,
    THRESHOLD_FILENAME,
    TRAINABLE_PARAMETER_COUNT,
    NetworkAutoencoderError,
    TrustedAutoencoderBundle,
    _capture_source_provenance,
    _dependency_versions,
    _historical_score_in_batches_v1,
    _json_bytes,
    _load_verified_autoencoder_detector,
    _scoring_contract_payload,
    _supported_runtime_identity,
    _threshold_policy_payload,
    _verify_source_provenance_snapshot,
    benign_train_indices,
    calculate_complementarity,
    calibrate_threshold,
    configure_deterministic_cpu_runtime,
    create_frozen_autoencoder,
    fit_frozen_autoencoder,
    load_verified_state,
    load_verified_autoencoder_detector,
    reconstruction_errors,
    save_state_dict,
    score_records_v2,
    threshold_scores,
    validate_feature_order,
    validate_matrix,
    verify_reload_equivalence,
)
from threatfusion.preprocessing.network_behavior_v1 import TRANSFORMED_FEATURE_NAMES
from threatfusion.utils.checksum import sha256_file

THRESHOLD_TIED_VECTOR = np.asarray(
    [
        0.3162378993934622,
        0.06228789310966456,
        -0.7068639219973236,
        1.1366070057197204,
        1.5844121724656886,
        -0.3221338049050676,
        0.1993909751397427,
        0.12383655659934928,
        0.2269047665713896,
        -1.1049469780574994,
        0.6494895075240973,
        -0.1511677843346963,
        1.9684246853088934,
        1.7962066603918483,
    ],
    dtype=np.float64,
)


@pytest.fixture(scope="module", autouse=True)
def deterministic_cpu() -> None:
    configure_deterministic_cpu_runtime()


def _write_json(path: Path, payload: dict[str, object]) -> str:
    path.write_bytes(_json_bytes(payload))
    return sha256_file(path)


def _build_v2_bundle(
    directory: Path,
    *,
    runtime_identity: dict[str, object] | None = None,
    configuration_mutator: Callable[[dict[str, Any]], None] | None = None,
    threshold_mutator: Callable[[dict[str, Any]], None] | None = None,
    manifest_mutator: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[str, TrustedAutoencoderBundle, dict[str, Any], dict[str, Any]]:
    snapshots = {
        "protocol": (PROTOCOL_SNAPSHOT_FILENAME, b"frozen protocol bytes\n"),
        "model_source": (MODEL_SOURCE_SNAPSHOT_FILENAME, b"frozen model source bytes\n"),
        "runner_source": (RUNNER_SOURCE_SNAPSHOT_FILENAME, b"frozen runner source bytes\n"),
    }
    provenance_files = {}
    for name, (filename, data) in snapshots.items():
        (directory / filename).write_bytes(data)
        provenance_files[name] = {
            "filename": filename,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
        }
    provenance = {
        "schema_version": "unsw_autoencoder_source_provenance_v2",
        "captured_before_training": True,
        "files": provenance_files,
    }
    provenance_sha256 = _write_json(directory / PROVENANCE_MANIFEST_FILENAME, provenance)
    preprocessing_hashes = {
        key: EXPECTED_PREPROCESSING_HASHES[key] for key in ("state", "configuration", "report")
    }
    identities = {
        "model": MODEL_IDENTITY,
        "detector": DETECTOR_IDENTITY,
        "detector_version": DETECTOR_VERSION,
        "preprocessing_requirements": PREPROCESSING_REQUIREMENTS,
        "scoring_contract_version": SCORING_CONTRACT_VERSION,
        "score": SCORE_IDENTITY,
    }
    configuration = {
        "schema_version": SCHEMA_VERSION,
        "protocol_sha256": provenance_files["protocol"]["sha256"],
        "identities": identities,
        "architecture": {
            "widths": [14, 8, 3, 8, 14],
            "hidden_activation": "ReLU",
            "output_activation": "linear",
            "bias": True,
            "trainable_parameters": TRAINABLE_PARAMETER_COUNT,
            "hidden_initialization": "xavier_uniform_relu_gain",
            "output_initialization": "xavier_uniform_linear_gain",
            "bias_initialization": "zero",
        },
        "scoring_contract": _scoring_contract_payload(),
        "threshold_policy": _threshold_policy_payload(),
        "dependencies": _dependency_versions(),
        "supported_runtime": runtime_identity or _supported_runtime_identity(),
        "runtime": {
            "deterministic_algorithms": True,
            "intraop_threads": 4,
            "interop_threads": 1,
            "data_loader_workers": 0,
            "pin_memory": False,
        },
        "preprocessing": {
            "feature_order": list(TRANSFORMED_FEATURE_NAMES),
            "state_sha256": preprocessing_hashes["state"],
            "configuration_sha256": preprocessing_hashes["configuration"],
            "report_sha256": preprocessing_hashes["report"],
        },
        "source_provenance": {
            "schema_version": provenance["schema_version"],
            "manifest_sha256": provenance_sha256,
            "captured_before_training": True,
        },
    }
    if configuration_mutator is not None:
        configuration_mutator(configuration)
    configuration_sha256 = _write_json(directory / CONFIG_FILENAME, configuration)
    torch.manual_seed(42)
    model = create_frozen_autoencoder()
    save_state_dict(directory / MODEL_FILENAME, model)
    model_sha256 = sha256_file(directory / MODEL_FILENAME)
    threshold = {
        "schema_version": "unsw_autoencoder_threshold_v2",
        "model_sha256": model_sha256,
        "configuration_sha256": configuration_sha256,
        "scoring_contract_version": SCORING_CONTRACT_VERSION,
        "score_identity": SCORE_IDENTITY,
        "calibration_partition": "validation",
        "calibration_label": "Normal=0",
        "calibration_rows": EXPECTED_COUNTS["validation"]["benign"],
        "quantile": QUANTILE,
        "method": "higher",
        "operator": ">",
        "ties": "within_threshold",
        "threshold": 1.0,
        "operational_false_positive_target": None,
        "february_influenced_threshold": False,
        "cic_influenced_threshold": False,
    }
    if threshold_mutator is not None:
        threshold_mutator(threshold)
    threshold_sha256 = _write_json(directory / THRESHOLD_FILENAME, threshold)
    manifest = {
        "schema_version": "unsw_autoencoder_artifact_manifest_v2",
        "identities": identities,
        "configuration_sha256": configuration_sha256,
        "model_state_sha256": model_sha256,
        "threshold_sha256": threshold_sha256,
        "source_provenance_manifest_sha256": provenance_sha256,
        "preprocessing_hashes": preprocessing_hashes,
    }
    if manifest_mutator is not None:
        manifest_mutator(manifest)
    manifest_sha256 = _write_json(directory / MANIFEST_FILENAME, manifest)
    manifest_bytes = (directory / MANIFEST_FILENAME).read_bytes()
    artifact_identity = hashlib.sha256(
        b"threatfusion:autoencoder-artifact\0" + manifest_bytes
    ).hexdigest()
    report = {
        "schema_version": SCHEMA_VERSION,
        "completed": True,
        "configuration_sha256": configuration_sha256,
        "model": {
            "sha256": model_sha256,
            "artifact_manifest_sha256": manifest_sha256,
            "artifact_identity": artifact_identity,
        },
        "threshold": {
            **threshold,
            "artifact_sha256": threshold_sha256,
        },
    }
    report_sha256 = _write_json(directory / REPORT_FILENAME, report)
    expected = TrustedAutoencoderBundle(
        scoring_contract_version=SCORING_CONTRACT_VERSION,
        configuration_sha256=configuration_sha256,
        model_state_sha256=model_sha256,
        threshold_sha256=threshold_sha256,
        manifest_sha256=manifest_sha256,
        report_sha256=report_sha256,
    )
    return artifact_identity, expected, configuration, manifest


def test_frozen_architecture_and_parameter_count() -> None:
    torch.manual_seed(42)
    model = create_frozen_autoencoder()
    linear = [layer for layer in model.layers if isinstance(layer, torch.nn.Linear)]
    assert [(layer.in_features, layer.out_features) for layer in linear] == [
        (14, 8),
        (8, 3),
        (3, 8),
        (8, 14),
    ]
    assert sum(parameter.numel() for parameter in model.parameters()) == TRAINABLE_PARAMETER_COUNT
    assert isinstance(model.layers[-1], torch.nn.Linear)


def test_attack_train_records_are_excluded_from_selected_fit_rows() -> None:
    labels = np.asarray([0, 1, 0, 1, 0], dtype=np.uint8)
    indices = benign_train_indices(labels, expected_benign=3)
    assert indices.tolist() == [0, 2, 4]
    assert labels[indices].tolist() == [0, 0, 0]


def test_fit_boundary_has_no_validation_or_test_inputs() -> None:
    assert list(signature(fit_frozen_autoencoder).parameters) == ["matrix", "labels"]


def test_invalid_feature_order_shape_and_non_finite_values_are_rejected() -> None:
    validate_feature_order(TRANSFORMED_FEATURE_NAMES)
    with pytest.raises(NetworkAutoencoderError, match="^feature_order_mismatch$"):
        validate_feature_order(tuple(reversed(TRANSFORMED_FEATURE_NAMES)))
    with pytest.raises(NetworkAutoencoderError, match="^matrix_shape_or_dtype_invalid$"):
        validate_matrix(np.zeros((2, INPUT_WIDTH - 1), dtype=np.float64), rows=2, name="matrix")
    invalid = np.zeros((2, INPUT_WIDTH), dtype=np.float64)
    invalid[1, 3] = np.inf
    with pytest.raises(NetworkAutoencoderError, match="^matrix_non_finite$"):
        validate_matrix(invalid, rows=2, name="matrix")


def test_reconstruction_error_uses_float64_mean_squared_error_over_14_features() -> None:
    values = np.zeros((2, INPUT_WIDTH), dtype=np.float32)
    reconstructions = np.zeros_like(values)
    reconstructions[0, :] = 2.0
    reconstructions[1, 0] = 14.0
    scores = reconstruction_errors(values, reconstructions)
    assert scores.tolist() == [4.0, 14.0]


def test_score_definition_residual_uses_the_float32_converted_input() -> None:
    original = np.full((1, INPUT_WIDTH), 1.00000005, dtype=np.float64)
    reconstruction = np.zeros((1, INPUT_WIDTH), dtype=np.float32)
    score = reconstruction_errors(original, reconstruction)[0]
    original_float64_score = np.mean(original[0] * original[0], dtype=np.float64)
    assert score == 1.0
    assert score != original_float64_score


def test_historical_threshold_tie_reproduces_batch_dependent_decision_and_v2_corrects_it() -> None:
    torch.manual_seed(42)
    model = create_frozen_autoencoder()
    surrounding = np.zeros((256, INPUT_WIDTH), dtype=np.float64)
    mixed = np.vstack((surrounding[:17], THRESHOLD_TIED_VECTOR, surrounding[17:]))
    historical_singleton = _historical_score_in_batches_v1(
        model, THRESHOLD_TIED_VECTOR.reshape(1, -1), batch_size=1
    )[0]
    historical_mixed = _historical_score_in_batches_v1(model, mixed, batch_size=len(mixed))[17]
    historical_lower = min(historical_singleton, historical_mixed)
    historical_higher = max(historical_singleton, historical_mixed)
    assert historical_lower < historical_higher
    assert threshold_scores(
        np.asarray([historical_lower, historical_higher]), historical_lower
    ).tolist() == [0, 1]

    corrected_singleton = score_records_v2(model, THRESHOLD_TIED_VECTOR.reshape(1, -1))[0]
    corrected_mixed = score_records_v2(model, mixed)[17]
    assert corrected_singleton == historical_singleton
    assert corrected_mixed == corrected_singleton
    assert threshold_scores(np.asarray([corrected_mixed]), corrected_singleton)[0] == 0


def test_v2_scores_are_exact_across_caller_chunks_positions_and_partial_chunks() -> None:
    torch.manual_seed(42)
    model = create_frozen_autoencoder()
    rng = np.random.default_rng(20260915)
    rows = rng.normal(size=(11, INPUT_WIDTH)).astype(np.float64)
    baseline = score_records_v2(model, rows, caller_chunk_size=1)
    for chunk_size in (2, 3, 4, 10, 11, 32):
        assert np.array_equal(score_records_v2(model, rows, caller_chunk_size=chunk_size), baseline)
    target = rows[5].copy()
    for position in (0, 5, 10):
        positioned = np.insert(np.delete(rows, 5, axis=0), position, target, axis=0)
        assert score_records_v2(model, positioned, caller_chunk_size=4)[position] == baseline[5]


def test_v2_repeated_identical_vectors_have_identical_scores() -> None:
    torch.manual_seed(42)
    model = create_frozen_autoencoder()
    repeated = np.repeat(THRESHOLD_TIED_VECTOR.reshape(1, -1), 17, axis=0)
    scores = score_records_v2(model, repeated, caller_chunk_size=6)
    assert np.array_equal(scores, np.repeat(scores[:1], len(scores)))


def test_v2_rejects_float32_overflow_before_model_forward() -> None:
    class ModelSpy:
        def eval(self) -> None:
            return None

        def __call__(self, values: torch.Tensor) -> torch.Tensor:
            pytest.fail("out-of-range input reached model forward")

    values = np.full((1, INPUT_WIDTH), 1e100, dtype=np.float64)
    with pytest.raises(NetworkAutoencoderError, match="^scoring_matrix_out_of_range$"):
        score_records_v2(ModelSpy(), values)


def test_higher_quantile_and_strict_threshold_preserve_ties() -> None:
    benign_scores = np.arange(101, dtype=np.float64)
    threshold = calibrate_threshold(benign_scores)
    assert threshold == 99.0
    decisions = threshold_scores(np.asarray([98.0, 99.0, 99.0, 100.0]), threshold)
    assert decisions.tolist() == [0, 0, 0, 1]


def test_state_artifact_integrity_and_exact_reload_equivalence(tmp_path: Path) -> None:
    torch.manual_seed(42)
    model = create_frozen_autoencoder()
    path = tmp_path / "state.pt"
    save_state_dict(path, model)
    expected_hash = sha256_file(path)
    loaded = load_verified_state(path, expected_hash)
    matrix = np.arange(RELOAD_SAMPLE_SIZE * INPUT_WIDTH, dtype=np.float64).reshape(
        RELOAD_SAMPLE_SIZE, INPUT_WIDTH
    )
    indices = np.arange(RELOAD_SAMPLE_SIZE, dtype=np.int64)
    evidence = verify_reload_equivalence(model, loaded, matrix, indices)
    assert evidence["state_tensors_exact"] is True
    score_sample = matrix[:17]
    assert np.array_equal(
        score_records_v2(model, score_sample, caller_chunk_size=4),
        score_records_v2(loaded, score_sample, caller_chunk_size=9),
    )
    damaged = bytearray(path.read_bytes())
    damaged[-1] ^= 1
    path.write_bytes(damaged)
    with pytest.raises(NetworkAutoencoderError, match="^model_artifact_hash_mismatch$"):
        load_verified_state(path, expected_hash)


def test_complementarity_counts_rf_misses_and_added_false_positives() -> None:
    labels = np.asarray([1, 1, 1, 1, 0, 0, 0, 0], dtype=np.uint8)
    autoencoder = np.asarray([1, 1, 0, 0, 1, 1, 0, 0], dtype=np.uint8)
    forest = np.asarray([1, 0, 1, 0, 1, 0, 1, 0], dtype=np.uint8)
    result = calculate_complementarity(labels, autoencoder, forest)
    assert result["attack"] == {
        "both_detected": 1,
        "autoencoder_only_rf_missed": 1,
        "random_forest_only_ae_missed": 1,
        "missed_by_both": 1,
    }
    assert result["normal"]["autoencoder_only_added_false_positive"] == 1
    assert result["hypothetical_or_rule"]["not_enabled"] is True


def test_complete_v2_bundle_is_verified_before_threshold_detection(tmp_path: Path) -> None:
    identity, expected, _, _ = _build_v2_bundle(tmp_path)
    detector = _load_verified_autoencoder_detector(
        tmp_path, artifact_identity=identity, expected=expected
    )
    rows = np.vstack((THRESHOLD_TIED_VECTOR, np.zeros(INPUT_WIDTH))).astype(np.float64)
    assert detector.artifact_identity == identity
    assert np.array_equal(detector.score(rows, caller_chunk_size=1), detector.score(rows))
    assert detector.detect(rows).dtype == np.uint8


def test_public_loader_rejects_self_asserted_unapproved_bundle_identity(tmp_path: Path) -> None:
    identity, _, _, _ = _build_v2_bundle(tmp_path)
    with pytest.raises(
        NetworkAutoencoderError, match="^autoencoder_artifact_identity_not_approved$"
    ):
        load_verified_autoencoder_detector(tmp_path, expected_artifact_identity=identity)


def test_historical_bundle_has_explicit_threshold_contract_incompatibility() -> None:
    directory = Path("artifacts/models/network_autoencoder/full-benign-autoencoder-255c342-v1")
    with pytest.raises(
        NetworkAutoencoderError,
        match="^historical_threshold_incompatible_with_scoring_contract_v2$",
    ):
        load_verified_autoencoder_detector(
            directory, expected_artifact_identity=HISTORICAL_ARTIFACT_IDENTITY
        )


@pytest.mark.parametrize(
    "filename",
    [CONFIG_FILENAME, MODEL_FILENAME, THRESHOLD_FILENAME, MANIFEST_FILENAME, REPORT_FILENAME],
)
def test_bundle_tampering_fails_before_model_use(tmp_path: Path, filename: str) -> None:
    identity, expected, _, _ = _build_v2_bundle(tmp_path)
    path = tmp_path / filename
    path.write_bytes(path.read_bytes() + b"altered")
    with pytest.raises(NetworkAutoencoderError, match="^autoencoder_bundle_integrity_failure$"):
        _load_verified_autoencoder_detector(tmp_path, artifact_identity=identity, expected=expected)


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (
            lambda config: config["architecture"].update({"widths": [14, 7, 3, 8, 14]}),
            "autoencoder_bundle_binding_mismatch",
        ),
        (
            lambda config: config["preprocessing"].update(
                {"feature_order": list(reversed(TRANSFORMED_FEATURE_NAMES))}
            ),
            "autoencoder_bundle_binding_mismatch",
        ),
        (
            lambda config: config["identities"].update({"model": "substituted"}),
            "autoencoder_bundle_binding_mismatch",
        ),
        (
            lambda config: config["scoring_contract"].update({"version": "unknown"}),
            "autoencoder_bundle_binding_mismatch",
        ),
        (
            lambda config: config["preprocessing"].update({"state_sha256": "0" * 64}),
            "autoencoder_bundle_binding_mismatch",
        ),
    ],
)
def test_configuration_contract_and_preprocessing_mismatches_fail_closed(
    tmp_path: Path, mutator: Callable[[dict[str, Any]], None], reason: str
) -> None:
    identity, expected, _, _ = _build_v2_bundle(tmp_path, configuration_mutator=mutator)
    with pytest.raises(NetworkAutoencoderError, match=f"^{reason}$"):
        _load_verified_autoencoder_detector(tmp_path, artifact_identity=identity, expected=expected)


def test_manifest_weight_binding_mismatch_fails_closed(tmp_path: Path) -> None:
    identity, expected, _, _ = _build_v2_bundle(
        tmp_path,
        manifest_mutator=lambda manifest: manifest.update({"model_state_sha256": "0" * 64}),
    )
    with pytest.raises(NetworkAutoencoderError, match="^autoencoder_manifest_binding_mismatch$"):
        _load_verified_autoencoder_detector(tmp_path, artifact_identity=identity, expected=expected)


@pytest.mark.parametrize("field", ["python", "torch", "platform"])
def test_material_runtime_identity_mismatch_fails_closed(tmp_path: Path, field: str) -> None:
    runtime = _supported_runtime_identity()
    runtime[field] = "unsupported"
    identity, expected, _, _ = _build_v2_bundle(tmp_path, runtime_identity=runtime)
    with pytest.raises(NetworkAutoencoderError, match="^autoencoder_runtime_incompatible$"):
        _load_verified_autoencoder_detector(tmp_path, artifact_identity=identity, expected=expected)


@pytest.mark.parametrize(
    ("target", "replacement"),
    [
        ("deterministic", lambda: False),
        ("threads", lambda: 1),
        ("cuda", lambda: True),
    ],
)
def test_incompatible_live_torch_runtime_fails_before_weights_become_usable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    replacement: Callable[[], object],
) -> None:
    identity, expected, _, _ = _build_v2_bundle(tmp_path)

    def forbidden_state_load(data: bytes) -> None:
        pytest.fail("incompatible runtime reached state deserialization")

    monkeypatch.setattr(autoencoder, "_load_state_bytes", forbidden_state_load)
    if target == "deterministic":
        monkeypatch.setattr(torch, "are_deterministic_algorithms_enabled", replacement)
    elif target == "threads":
        monkeypatch.setattr(torch, "get_num_threads", replacement)
    else:
        monkeypatch.setattr(torch.cuda, "is_available", replacement)
    with pytest.raises(NetworkAutoencoderError, match="^autoencoder_runtime_incompatible$"):
        _load_verified_autoencoder_detector(tmp_path, artifact_identity=identity, expected=expected)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda threshold: threshold.update({"configuration_sha256": "0" * 64}),
        lambda threshold: threshold.update({"model_sha256": "0" * 64}),
        lambda threshold: threshold.update({"scoring_contract_version": "unknown"}),
        lambda threshold: threshold.update({"operator": ">="}),
    ],
)
def test_threshold_configuration_and_scoring_bindings_fail_closed(
    tmp_path: Path, mutator: Callable[[dict[str, Any]], None]
) -> None:
    identity, expected, _, _ = _build_v2_bundle(tmp_path, threshold_mutator=mutator)
    with pytest.raises(NetworkAutoencoderError, match="^autoencoder_threshold_binding_mismatch$"):
        _load_verified_autoencoder_detector(tmp_path, artifact_identity=identity, expected=expected)


@pytest.mark.parametrize("kind", ["missing", "altered"])
def test_missing_or_altered_source_snapshot_fails_closed(tmp_path: Path, kind: str) -> None:
    identity, expected, _, _ = _build_v2_bundle(tmp_path)
    path = tmp_path / MODEL_SOURCE_SNAPSHOT_FILENAME
    if kind == "missing":
        path.unlink()
    else:
        path.write_bytes(b"altered source bytes\n")
    with pytest.raises(NetworkAutoencoderError, match="^source_provenance_mismatch$"):
        _load_verified_autoencoder_detector(tmp_path, artifact_identity=identity, expected=expected)


def test_mismatched_source_provenance_binding_fails_closed(tmp_path: Path) -> None:
    _, _, configuration, manifest = _build_v2_bundle(tmp_path)
    mismatched = {
        **configuration,
        "source_provenance": {
            **configuration["source_provenance"],
            "manifest_sha256": "0" * 64,
        },
    }
    with pytest.raises(NetworkAutoencoderError, match="^source_provenance_mismatch$"):
        _verify_source_provenance_snapshot(tmp_path, mismatched, manifest)


def test_future_run_source_capture_preserves_exact_bytes(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    run_directory = tmp_path / "run"
    protocol = project_root / "docs/protocol.md"
    runner = project_root / "scripts/train_network_autoencoder.py"
    protocol.parent.mkdir(parents=True)
    runner.parent.mkdir(parents=True)
    run_directory.mkdir()
    protocol.write_bytes(b"exact protocol before training\n")
    runner.write_bytes(b"exact runner before training\n")
    manifest, digest = _capture_source_provenance(
        run_directory, project_root=project_root, protocol_path=protocol
    )
    assert (run_directory / PROTOCOL_SNAPSHOT_FILENAME).read_bytes() == protocol.read_bytes()
    assert (run_directory / RUNNER_SOURCE_SNAPSHOT_FILENAME).read_bytes() == runner.read_bytes()
    assert (run_directory / MODEL_SOURCE_SNAPSHOT_FILENAME).read_bytes() == Path(
        __import__("threatfusion.models.network_autoencoder", fromlist=["__file__"]).__file__
    ).read_bytes()
    assert digest == sha256_file(run_directory / PROVENANCE_MANIFEST_FILENAME)
    assert manifest["captured_before_training"] is True
