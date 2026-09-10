from __future__ import annotations

from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path

import numpy as np
import pytest

import threatfusion.models.network_inference as inference
from threatfusion.preprocessing.network_behavior_v1 import NetworkBehaviorPreprocessor

from threatfusion.features.network_behavior import (
    CIC_IDS2018_CICFLOWMETER_V3_PROCESSED_REPRESENTATION_V1,
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
)
from threatfusion.models.network_inference import (
    MAX_INFERENCE_BATCH_SIZE,
    NetworkInferenceError,
    _NetworkInferenceRequest,
    NetworkModelChoice,
    _NetworkSourceProvenance,
    _FrozenNetworkPredictor,
    _LoadedModel,
    default_artifact_directories,
)

PROJECT_ROOT = Path(__file__).parents[3]
ARTIFACT_DIRECTORIES = default_artifact_directories(PROJECT_ROOT)
ARTIFACTS_AVAILABLE = all(path.is_dir() for path in ARTIFACT_DIRECTORIES)


def _synthetic_contract_valid_request() -> _NetworkInferenceRequest:
    """Test the private predictor separately; never a supported application input."""
    return _NetworkInferenceRequest(
        provenance=_NetworkSourceProvenance.approved_unsw(),
        feature_names=NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
        feature_values=(100.0, 2, 1, 120, 60, 30.0, 1800.0, 60.0, 60.0, 443, "tcp"),
    )


@pytest.fixture(scope="module")
def artifact_boundary() -> _FrozenNetworkPredictor:
    if not ARTIFACTS_AVAILABLE:
        pytest.skip("ignored frozen model artifacts are unavailable")
    preprocessing, logistic, forest = ARTIFACT_DIRECTORIES
    return _FrozenNetworkPredictor(
        preprocessing_directory=preprocessing,
        logistic_directory=logistic,
        random_forest_directory=forest,
    )


def test_valid_unsw_inference_uses_random_forest_by_default(
    boundary: _FrozenNetworkPredictor,
) -> None:
    result = boundary.infer(_synthetic_contract_valid_request())

    assert result.status == "completed"
    assert result.reason == "inference_succeeded"
    assert result.model_identity == "random_forest"
    assert result.attack_probability is not None
    assert 0.0 <= result.attack_probability <= 1.0
    assert result.predicted_class in {"Normal", "Attack"}
    assert result.decision_threshold == 0.5


@pytest.mark.parametrize(
    ("provenance", "reason"),
    [
        (None, "provenance_missing"),
        (
            replace(_NetworkSourceProvenance.approved_unsw(), source_representation="unknown.v1"),
            "source_representation_unrecognized",
        ),
        (
            replace(
                _NetworkSourceProvenance.approved_unsw(),
                source_representation=CIC_IDS2018_CICFLOWMETER_V3_PROCESSED_REPRESENTATION_V1,
            ),
            "cross_source_byte_semantics_incompatible",
        ),
        (
            replace(
                _NetworkSourceProvenance.approved_unsw(),
                feature_contract_version="network_behavior_v2",
            ),
            "feature_contract_version_unrecognized",
        ),
    ],
)
def test_unapproved_provenance_fails_before_prediction(
    boundary: _FrozenNetworkPredictor,
    provenance: _NetworkSourceProvenance | None,
    reason: str,
) -> None:
    request = replace(_synthetic_contract_valid_request(), provenance=provenance)

    result = boundary.infer(request)

    assert result.status == "rejected"
    assert result.reason == reason
    assert result.attack_probability is None
    assert result.predicted_class is None
    assert result.source_representation_identity == "unapproved"


def test_cic_rejection_precedes_transformation(boundary: _FrozenNetworkPredictor) -> None:
    class TransformSpy:
        called = False

        def transform(self, record: object) -> np.ndarray:
            self.called = True
            raise AssertionError("transform must not run")

    clone = object.__new__(_FrozenNetworkPredictor)
    spy = TransformSpy()
    clone._preprocessor = spy
    clone._models = boundary._models
    request = replace(
        _synthetic_contract_valid_request(),
        provenance=replace(
            _NetworkSourceProvenance.approved_unsw(),
            source_representation=CIC_IDS2018_CICFLOWMETER_V3_PROCESSED_REPRESENTATION_V1,
        ),
    )

    result = clone.infer(request)

    assert result.reason == "cross_source_byte_semantics_incompatible"
    assert spy.called is False


def test_feature_order_mismatch_fails_closed(boundary: _FrozenNetworkPredictor) -> None:
    request = _synthetic_contract_valid_request()
    result = boundary.infer(replace(request, feature_names=tuple(reversed(request.feature_names))))

    assert result.status == "rejected"
    assert result.reason == "feature_order_mismatch"


@pytest.mark.parametrize(
    ("index", "value", "reason"),
    [
        (0, None, "predictor_type_invalid"),
        (0, float("nan"), "non_finite_predictor"),
        (0, float("inf"), "non_finite_predictor"),
        (9, 65536, "destination_port_out_of_range"),
    ],
)
def test_missing_nonfinite_and_out_of_range_values_are_rejected(
    boundary: _FrozenNetworkPredictor, index: int, value: object, reason: str
) -> None:
    request = _synthetic_contract_valid_request()
    values = list(request.feature_values)
    values[index] = value

    result = boundary.infer(replace(request, feature_values=tuple(values)))

    assert result.status == "rejected"
    assert result.reason == reason


def test_batch_is_bounded_and_accounts_for_each_record(
    boundary: _FrozenNetworkPredictor,
) -> None:
    valid = _synthetic_contract_valid_request()
    invalid = replace(valid, feature_values=(*valid.feature_values[:-1], "secret-invalid-protocol"))

    result = boundary.infer_batch(iter((valid, invalid)))

    assert (result.received, result.succeeded, result.rejected) == (2, 1, 1)
    assert [item.status for item in result.results] == ["completed", "rejected"]
    with pytest.raises(NetworkInferenceError, match="batch_size_exceeded"):
        boundary.infer_batch(valid for _ in range(MAX_INFERENCE_BATCH_SIZE + 1))


def test_failure_output_is_sanitized(boundary: _FrozenNetworkPredictor) -> None:
    secret = "10.0.0.9 user-secret /private/input.csv"
    request = _NetworkInferenceRequest(
        provenance=replace(_NetworkSourceProvenance.approved_unsw(), source_representation=secret),
        feature_names=(*NETWORK_BEHAVIOR_V1_FEATURE_NAMES[:-1], secret),
        feature_values=_synthetic_contract_valid_request().feature_values,
    )

    payload = str(boundary.infer(request).to_dict())

    assert secret not in payload
    assert "10.0.0.9" not in payload
    assert "/private/input.csv" not in payload


def test_selected_model_failure_does_not_fall_back(
    boundary: _FrozenNetworkPredictor,
) -> None:
    class BrokenForest:
        classes_ = np.asarray([0, 1])

        def predict_proba(self, matrix: np.ndarray) -> np.ndarray:
            raise RuntimeError("sensitive estimator detail")

    class LogisticSpy:
        classes_ = np.asarray([0, 1])

        def __init__(self) -> None:
            self.called = False

        def predict_proba(self, matrix: np.ndarray) -> np.ndarray:
            self.called = True
            return np.asarray([[0.1, 0.9]])

    clone = object.__new__(_FrozenNetworkPredictor)
    clone._preprocessor = boundary._preprocessor
    spy = LogisticSpy()
    clone._models = {
        NetworkModelChoice.RANDOM_FOREST: _LoadedModel(
            BrokenForest(), "random_forest", "network_random_forest_baseline_v1"
        ),
        NetworkModelChoice.LOGISTIC_REGRESSION: _LoadedModel(
            spy, "logistic_regression", "network_logistic_baseline_v1"
        ),
    }

    result = clone.infer(_synthetic_contract_valid_request())

    assert result.status == "rejected"
    assert result.reason == "model_prediction_failed"
    assert spy.called is False
    assert "sensitive" not in str(result.to_dict())


def test_hash_mismatch_blocks_artifact_loading(tmp_path: Path) -> None:
    if not ARTIFACTS_AVAILABLE:
        pytest.skip("ignored frozen model artifacts are unavailable")
    preprocessing, logistic, forest = ARTIFACT_DIRECTORIES
    copied = tmp_path / "preprocessing"
    copied.mkdir()
    for name in (
        "preprocessor_state.json",
        "preprocessing_config.json",
        "preprocessing_report.json",
    ):
        (copied / name).write_bytes((preprocessing / name).read_bytes())
    with (copied / "preprocessor_state.json").open("ab") as handle:
        handle.write(b"\n")

    with pytest.raises(NetworkInferenceError, match="preprocessing_state_hash_mismatch"):
        _FrozenNetworkPredictor(
            preprocessing_directory=copied,
            logistic_directory=logistic,
            random_forest_directory=forest,
        )


def test_model_hash_mismatch_blocks_loading(tmp_path: Path) -> None:
    if not ARTIFACTS_AVAILABLE:
        pytest.skip("ignored frozen model artifacts are unavailable")
    preprocessing, logistic, forest = ARTIFACT_DIRECTORIES
    copied = tmp_path / "logistic"
    copied.mkdir()
    for name in ("logistic_regression.joblib", "model_config.json", "evaluation_report.json"):
        (copied / name).write_bytes((logistic / name).read_bytes())
    with (copied / "logistic_regression.joblib").open("ab") as handle:
        handle.write(b"x")

    with pytest.raises(NetworkInferenceError, match="logistic_regression_model_hash_mismatch"):
        _FrozenNetworkPredictor(
            preprocessing_directory=preprocessing,
            logistic_directory=copied,
            random_forest_directory=forest,
        )


def test_artifact_reload_preserves_predictions(
    artifact_boundary: _FrozenNetworkPredictor,
) -> None:
    preprocessing, logistic, forest = ARTIFACT_DIRECTORIES
    reloaded = _FrozenNetworkPredictor(
        preprocessing_directory=preprocessing,
        logistic_directory=logistic,
        random_forest_directory=forest,
    )
    request = _synthetic_contract_valid_request()

    for choice in NetworkModelChoice:
        first = artifact_boundary.infer(request, model=choice)
        second = reloaded.infer(request, model=choice)
        assert first.predicted_class == second.predicted_class
        assert first.attack_probability == pytest.approx(second.attack_probability, abs=1e-15)


def test_audit_provenance_contains_no_paths_or_feature_values(
    boundary: _FrozenNetworkPredictor,
) -> None:
    provenance = boundary.audit_provenance

    assert provenance["primary_model"] == "random_forest"
    assert provenance["comparison_model"] == "logistic_regression"
    assert provenance["automatic_fallback"] is False
    assert provenance["maximum_batch_size"] == MAX_INFERENCE_BATCH_SIZE
    assert "/" not in str(provenance)


class _ScoreModel:
    classes_ = np.asarray([1, 0])

    def predict_proba(self, matrix: np.ndarray) -> np.ndarray:
        return np.tile([0.5, 0.5], (len(matrix), 1))


@pytest.fixture
def unit_boundary() -> _FrozenNetworkPredictor:
    """No ignored artifacts or fitting required for adversarial request tests."""
    instance = object.__new__(_FrozenNetworkPredictor)
    instance._preprocessor = NetworkBehaviorPreprocessor(1, (0.0,) * 10, (1.0,) * 10, ())
    instance._models = {
        choice: _LoadedModel(_ScoreModel(), choice.value, "fixture_v1")
        for choice in NetworkModelChoice
    }
    return instance


@pytest.fixture
def boundary(unit_boundary):
    return unit_boundary


@pytest.mark.parametrize("bad", [None, {}, "secret /private/request"])
def test_malformed_request_is_an_ordered_rejection(unit_boundary, bad):
    result = unit_boundary.infer_batch([_synthetic_contract_valid_request(), bad])
    assert (result.received, result.succeeded, result.rejected) == (2, 1, 1)
    assert result.results[1].reason == "request_type_invalid"
    assert "secret" not in str(result)


@pytest.mark.parametrize(
    "field,value",
    [
        ("provenance", {}),
        ("feature_values", None),
        ("feature_names", ["secret"]),
    ],
)
def test_malformed_request_fields_are_sanitized(unit_boundary, field, value):
    result = unit_boundary.infer(replace(_synthetic_contract_valid_request(), **{field: value}))
    assert result.status == "rejected"
    assert "secret" not in str(result.to_dict())


def test_provenance_object_cannot_supply_an_approved_key(unit_boundary):
    class Spoof:
        source_representation = "secret /private/provenance"

        def compatibility_key(self):
            return _NetworkSourceProvenance.approved_unsw().compatibility_key()

    result = unit_boundary.infer(replace(_synthetic_contract_valid_request(), provenance=Spoof()))
    assert result.status == "rejected"
    assert result.source_representation_identity == "unapproved"
    assert "secret" not in str(result.to_dict())


def test_numeric_conversion_overflow_is_a_rejection(unit_boundary):
    request = _synthetic_contract_valid_request()
    result = unit_boundary.infer(
        replace(request, feature_values=(10**1000, *request.feature_values[1:]))
    )
    assert result.status == "rejected"
    assert result.reason == "numeric_predictor_out_of_range"


def test_generator_failure_aborts_before_any_predictions(unit_boundary, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("prediction before iterator completion")

    monkeypatch.setattr(unit_boundary, "infer", forbidden)

    def broken():
        yield _synthetic_contract_valid_request()
        raise RuntimeError("secret /private/source")

    with pytest.raises(NetworkInferenceError, match="^batch_iteration_failed$") as error:
        unit_boundary.infer_batch(broken())
    assert "secret" not in str(error.value)
    assert error.value.__suppress_context__


def test_unhashable_model_selection_is_sanitized(unit_boundary):
    with pytest.raises(NetworkInferenceError, match="^model_not_supported$"):
        unit_boundary.infer(_synthetic_contract_valid_request(), model=[])


def test_verified_model_bytes_are_not_reopened(tmp_path, monkeypatch):
    """A path replacement after verification must never reach pickle decoding."""
    model_bytes = b"verified fixture bytes"
    model_hash = hashlib.sha256(model_bytes).hexdigest()
    pre = inference.APPROVED_PREPROCESSING_HASHES
    config = {
        "dependencies": inference._dependency_versions(),
        "schema_version": "network_logistic_baseline_v1",
        "label_mapping": inference.LABEL_MAPPING,
        "preprocessing": {
            "state_sha256": pre["state"],
            "configuration_sha256": pre["configuration"],
            "report_sha256": pre["report"],
            "source_provenance": {"manifest_sha256": inference.APPROVED_UNSW_MANIFEST_HASH},
            "transformed_feature_names": list(inference.TRANSFORMED_FEATURE_NAMES),
        },
        "decision_threshold": {
            "operator": ">=",
            "positive_label": 1,
            "positive_name": "Attack",
            "probability": 0.5,
        },
    }
    config_bytes = json.dumps(config).encode()
    config_hash = hashlib.sha256(config_bytes).hexdigest()
    report = {
        "schema_version": config["schema_version"],
        "completed": True,
        "configuration_sha256": config_hash,
        "model": {"sha256": model_hash, "classes": [0, 1], "attack_probability_column": 1},
    }
    report_bytes = json.dumps(report).encode()
    hashes = {
        "model": model_hash,
        "configuration": config_hash,
        "report": hashlib.sha256(report_bytes).hexdigest(),
    }
    monkeypatch.setitem(inference.APPROVED_MODEL_HASHES, "logistic_regression", hashes)
    for name, data in (
        ("logistic_regression.joblib", model_bytes),
        ("model_config.json", config_bytes),
        ("evaluation_report.json", report_bytes),
    ):
        (tmp_path / name).write_bytes(data)

    def load_verified(stream):
        (tmp_path / "logistic_regression.joblib").write_bytes(b"replaced untrusted pickle")
        assert isinstance(stream, io.BytesIO), "deserialization reopens a replaceable path"
        assert stream.getvalue() == model_bytes
        model = inference.LogisticRegression()
        model.classes_ = np.asarray([0, 1])
        model.n_features_in_ = 14
        return model

    monkeypatch.setattr(inference.joblib, "load", load_verified)
    snapshot = inference._model_snapshot(tmp_path, NetworkModelChoice.LOGISTIC_REGRESSION)
    inference._verify_model(snapshot, NetworkModelChoice.LOGISTIC_REGRESSION)


@pytest.mark.parametrize(
    "kind", ["missing", "directory", "symlink", "fifo", "truncated", "oversized", "unreadable"]
)
def test_artifact_failures_are_bounded_and_sanitized(tmp_path, monkeypatch, kind):
    path = tmp_path / "secret-artifact.json"
    content = b"verified"
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        target = tmp_path / "target"
        target.write_bytes(content)
        path.symlink_to(target)
    elif kind == "fifo":
        inference.os.mkfifo(path)
    elif kind in {"truncated", "oversized"}:
        path.write_bytes(b"" if kind == "truncated" else b"x" * (inference.MAX_JSON_BYTES + 1))
    elif kind == "unreadable":

        def denied(*args, **kwargs):
            raise PermissionError("secret-artifact")

        monkeypatch.setattr(inference.os, "open", denied)
    with pytest.raises(NetworkInferenceError, match="^artifact_rejected$") as error:
        inference._verified_bytes(path, hashlib.sha256(content).hexdigest(), "artifact_rejected")
    assert "secret" not in str(error.value)


def test_no_deserialization_until_all_bundles_pass(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(inference, "_preprocessing_snapshot", lambda path: {})

    def model_snapshot(path, choice):
        calls.append(choice)
        if choice is NetworkModelChoice.RANDOM_FOREST:
            raise NetworkInferenceError("random_forest_report_hash_mismatch")
        return {}

    def forbidden(*args, **kwargs):
        pytest.fail("deserialized before complete bundle verification")

    monkeypatch.setattr(inference, "_model_snapshot", model_snapshot)
    monkeypatch.setattr(inference.joblib, "load", forbidden)
    with pytest.raises(NetworkInferenceError, match="random_forest_report_hash_mismatch"):
        _FrozenNetworkPredictor(
            preprocessing_directory=tmp_path,
            logistic_directory=tmp_path,
            random_forest_directory=tmp_path,
        )
    assert calls == list(NetworkModelChoice)[::-1]


def test_runtime_version_mismatch_precedes_deserialization(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("deserialized with unsupported runtime")

    monkeypatch.setattr(inference.joblib, "load", forbidden)
    with pytest.raises(NetworkInferenceError, match="artifact_runtime_version_mismatch"):
        inference._verify_model(
            {"configuration": b'{"dependencies": {}}', "report": b"{}", "model": b"not a pickle"},
            NetworkModelChoice.RANDOM_FOREST,
        )


@pytest.mark.parametrize("value", [True, False, "1e1000", float("-inf"), -1, 0.1, 2**53 + 1])
def test_numeric_edge_cases_precede_transformation(unit_boundary, monkeypatch, value):
    class Spy:
        def transform(self, record):
            pytest.fail("invalid input reached transform")

    unit_boundary._preprocessor = Spy()
    request = _synthetic_contract_valid_request()
    result = unit_boundary.infer(
        replace(
            request, feature_values=(request.feature_values[0], value, *request.feature_values[2:])
        )
    )
    assert result.status == "rejected"


def test_forest_float32_overflow_precedes_prediction(unit_boundary, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("float32 overflow reached estimator")

    monkeypatch.setattr(inference, "attack_probabilities", forbidden)
    request = _synthetic_contract_valid_request()
    result = unit_boundary.infer(
        replace(request, feature_values=(1e100, *request.feature_values[1:]))
    )
    assert result.reason == "model_input_out_of_range"


@pytest.mark.parametrize(
    "score,predicted", [(0.499999, "Normal"), (0.5, "Attack"), (0.500001, "Attack")]
)
def test_class_mapping_and_inclusive_threshold(unit_boundary, score, predicted):
    class ReversedClasses(_ScoreModel):
        def predict_proba(self, matrix):
            return np.asarray([[score, 1 - score]])

    unit_boundary._models[NetworkModelChoice.RANDOM_FOREST] = _LoadedModel(
        ReversedClasses(), "random_forest", "fixture_v1"
    )
    result = unit_boundary.infer(_synthetic_contract_valid_request())
    assert result.attack_probability == score
    assert result.predicted_class == predicted


def test_batch_limit_consumes_only_257_without_prediction(unit_boundary, monkeypatch):
    consumed = 0

    def endless():
        nonlocal consumed
        while True:
            consumed += 1
            yield _synthetic_contract_valid_request()

    def forbidden(*args, **kwargs):
        pytest.fail("oversized batch predicted")

    monkeypatch.setattr(unit_boundary, "infer", forbidden)
    with pytest.raises(NetworkInferenceError, match="batch_size_exceeded"):
        unit_boundary.infer_batch(endless())
    assert consumed == 257


def test_mapping_constructor_is_bounded_and_rejects_prohibited_field():
    values = dict(
        zip(NETWORK_BEHAVIOR_V1_FEATURE_NAMES, _synthetic_contract_valid_request().feature_values)
    )
    values["label"] = "secret"
    with pytest.raises(NetworkInferenceError, match="feature_mapping_invalid"):
        _NetworkInferenceRequest.from_mapping(
            values, provenance=_NetworkSourceProvenance.approved_unsw()
        )


def test_result_schema_utc_uuid_and_batch_order(unit_boundary):
    from datetime import datetime
    from uuid import UUID

    good = _synthetic_contract_valid_request()
    bad = replace(good, provenance=None)
    results = unit_boundary.infer_batch([good, bad, good]).results
    assert [item.status for item in results] == ["completed", "rejected", "completed"]
    assert len({UUID(item.correlation_id) for item in results}) == 3
    for result in results:
        assert datetime.fromisoformat(result.processed_at).utcoffset().total_seconds() == 0
        assert result.latency_ms >= 0
        assert set(result.to_dict()) == {
            "correlation_id",
            "model_identity",
            "model_version",
            "contract_identity",
            "source_representation_identity",
            "attack_probability",
            "decision_threshold",
            "predicted_class",
            "status",
            "reason",
            "processed_at",
            "latency_ms",
        }


def test_transform_failure_is_sanitized_and_batch_continues(unit_boundary):
    original = unit_boundary._preprocessor

    class FailOnce:
        called = False

        def transform(self, record):
            if not self.called:
                self.called = True
                raise RuntimeError("secret /private/state")
            return original.transform(record)

    unit_boundary._preprocessor = FailOnce()
    result = unit_boundary.infer_batch([_synthetic_contract_valid_request()] * 2)
    assert (result.received, result.rejected, result.succeeded) == (2, 1, 1)
    assert result.results[0].reason == "transformation_failed"
    assert "secret" not in str(result)


def test_snapshot_preprocessor_reuses_exact_transformation(unit_boundary):
    original = unit_boundary._preprocessor
    reloaded = NetworkBehaviorPreprocessor.from_dict(original.to_dict())
    record = inference._feature_record(_synthetic_contract_valid_request())
    assert np.array_equal(original.transform(record), reloaded.transform(record))
    assert original.to_dict() == reloaded.to_dict()


@pytest.mark.parametrize("bundle", ["preprocessing", "logistic_regression", "random_forest"])
@pytest.mark.parametrize("field", ["configuration", "report", "payload"])
def test_every_related_artifact_is_hash_bound(tmp_path, monkeypatch, bundle, field):
    preprocessing = bundle == "preprocessing"
    payload = "state" if preprocessing else "model"
    filenames = (
        {
            "state": "preprocessor_state.json",
            "configuration": "preprocessing_config.json",
            "report": "preprocessing_report.json",
        }
        if preprocessing
        else {
            "model": f"{bundle}.joblib",
            "configuration": "model_config.json",
            "report": "evaluation_report.json",
        }
    )
    expected = {}
    for key, name in filenames.items():
        data = f"fixture {key}".encode()
        (tmp_path / name).write_bytes(data)
        expected[key] = hashlib.sha256(data).hexdigest()
    if preprocessing:
        monkeypatch.setattr(inference, "APPROVED_PREPROCESSING_HASHES", expected)
    else:
        monkeypatch.setitem(inference.APPROVED_MODEL_HASHES, bundle, expected)
    damaged = payload if field == "payload" else field
    (tmp_path / filenames[damaged]).write_bytes(b"corrupt")
    with pytest.raises(NetworkInferenceError, match=f"{bundle}_{damaged}_hash_mismatch"):
        if preprocessing:
            inference._preprocessing_snapshot(tmp_path)
        else:
            inference._model_snapshot(tmp_path, NetworkModelChoice(bundle))


def test_custom_string_equality_cannot_approve_provenance(unit_boundary):
    class Alias(str):
        def __eq__(self, other):
            return True

    request = replace(
        _synthetic_contract_valid_request(),
        provenance=replace(
            _NetworkSourceProvenance.approved_unsw(), source_representation=Alias("secret")
        ),
    )
    result = unit_boundary.infer(request)
    assert result.reason == "provenance_type_invalid"
    assert result.source_representation_identity == "unapproved"


def test_snapshot_state_survives_source_replacement(tmp_path, monkeypatch, unit_boundary):
    data = json.dumps(unit_boundary._preprocessor.to_dict()).encode()
    path = tmp_path / "state.json"
    path.write_bytes(data)
    verified = inference._verified_bytes(path, hashlib.sha256(data).hexdigest(), "invalid_state")
    path.write_bytes(b"poisoned replacement")
    loaded = NetworkBehaviorPreprocessor.from_dict(inference._read_json(verified, "invalid_state"))
    assert loaded == unit_boundary._preprocessor


def test_no_fit_calls_and_no_mutation_in_bounded_concurrent_inference(unit_boundary, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    def forbidden(*args, **kwargs):
        pytest.fail("inference must not fit")

    monkeypatch.setattr(NetworkBehaviorPreprocessor, "fit", forbidden)
    monkeypatch.setattr(inference.LogisticRegression, "fit", forbidden)
    monkeypatch.setattr(inference.RandomForestClassifier, "fit", forbidden)
    state = unit_boundary._preprocessor.to_dict()
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(unit_boundary.infer, [_synthetic_contract_valid_request()] * 8))
    assert all(result.attack_probability == 0.5 for result in results)
    assert unit_boundary._preprocessor.to_dict() == state


def test_smoke_artifact_error_is_json_only(monkeypatch, capsys):
    from scripts import smoke_unsw_network_inference as smoke

    def denied(*args, **kwargs):
        raise PermissionError("secret /private/artifact")

    monkeypatch.setattr(inference.os, "open", denied)
    assert smoke.main([]) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {
        "status": "failed",
        "reason": "unsw_registration_invalid",
    }
