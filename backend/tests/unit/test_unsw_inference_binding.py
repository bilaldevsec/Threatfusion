"""Raw application-boundary regressions; synthetic rows and no fitted artifacts."""

from dataclasses import FrozenInstanceError, asdict, replace
from copy import copy, deepcopy
import hashlib
import json
import pickle
import warnings
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
import yaml

import threatfusion.models.network_inference as inference
from threatfusion.datasets.adapters.unsw_nb15 import adapt_unsw_row
from threatfusion.features.network_behavior import (
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
    UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
)
from threatfusion.preprocessing.network_behavior_v1 import NetworkBehaviorPreprocessor
from threatfusion.schemas.flow import NetworkFlow

RAW_NAMES = tuple(
    "srcip sport dstip dsport proto state dur sbytes dbytes sttl dttl sloss dloss service "
    "sload dload spkts dpkts swin dwin stcpb dtcpb smeansz dmeansz trans_depth res_bdy_len "
    "sjit djit stime ltime sintpkt dintpkt tcprtt synack ackdat is_sm_ips_ports ct_state_ttl "
    "ct_flw_http_mthd is_ftp_login ct_ftp_cmd ct_srv_src ct_srv_dst ct_dst_ltm ct_src_ltm "
    "ct_src_dport_ltm ct_dst_sport_ltm ct_dst_src_ltm attack_cat label".split()
)


def raw_row(**updates):
    values = dict.fromkeys(RAW_NAMES, "0")
    values.update(
        srcip="192.0.2.1",
        dstip="198.51.100.2",
        sport="1234",
        dsport="443",
        proto="tcp",
        dur="0.1",
        sbytes="120",
        dbytes="60",
        spkts="2",
        dpkts="1",
        stime="1421928000",
        ltime="1421928001",
        attack_cat="private-category",
    )
    values.update(updates)
    return [values[name] for name in RAW_NAMES]


class PredictorSpy:
    classes_ = np.asarray([0, 1])

    def __init__(self):
        self.calls = []

    def predict_proba(self, matrix):
        self.calls.append(matrix.copy())
        return np.asarray([[0.25, 0.75]])


@pytest.fixture
def registered_root(tmp_path, monkeypatch):
    """Test-only trust anchors for small metadata, never production bypass options."""
    metadata = b"No.,Name,Type,Description\n" + b"".join(
        f"{index},{name},type,fixture\n".encode() for index, name in enumerate(RAW_NAMES, 1)
    )
    (tmp_path / "NUSW-NB15_features.csv").write_bytes(metadata)
    manifest = yaml.safe_dump(
        {
            "name": "unsw_nb15",
            "version": "fixture",
            "license_note": "fixture",
            "files": [
                {
                    "path": "NUSW-NB15_features.csv",
                    "role": "raw",
                    "rows": 49,
                    "sha256": hashlib.sha256(metadata).hexdigest(),
                }
            ],
        }
    ).encode()
    path = tmp_path / "data/manifests/unsw_nb15.yaml"
    path.parent.mkdir(parents=True)
    path.write_bytes(manifest)
    monkeypatch.setattr(
        inference, "APPROVED_UNSW_MANIFEST_HASH", hashlib.sha256(manifest).hexdigest()
    )
    return tmp_path


@pytest.fixture
def boundary(registered_root, monkeypatch):
    spy = PredictorSpy()
    monkeypatch.setattr(inference, "_preprocessing_snapshot", lambda path: {})
    monkeypatch.setattr(inference, "_model_snapshot", lambda path, choice: {})
    monkeypatch.setattr(
        inference,
        "_verify_preprocessor",
        lambda snapshot: NetworkBehaviorPreprocessor(1, (0.0,) * 10, (1.0,) * 10, ()),
    )
    monkeypatch.setattr(
        inference,
        "_verify_model",
        lambda snapshot, choice: inference._LoadedModel(spy, choice.value, "fixture_v1"),
    )
    return inference.UnswNetworkInferenceBoundary(project_root=registered_root), spy


def test_raw_input_uses_shared_reader_adapter_projection_and_internal_source(boundary, monkeypatch):
    public, spy = boundary
    seen = []
    original = inference.adapt_unsw_row

    def adapt(row):
        seen.append(tuple(row))
        return original(row)

    monkeypatch.setattr(inference, "adapt_unsw_row", adapt)
    result = public.infer(json.loads(json.dumps(raw_row())))
    assert result.status == "completed"
    assert result.source_representation_identity == UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1
    assert seen == [(*RAW_NAMES, "flow_id")]
    np.testing.assert_array_equal(
        spy.calls[0], [[100, 2, 1, 120, 60, 30, 1800, 60, 60, 443, 1, 0, 0, 0]]
    )


@pytest.mark.parametrize(
    "kind", ["manual", "serialized", "duck", "subclass", "dict", "cic", "unknown", "canonical"]
)
def test_claimed_provenance_and_approved_objects_cannot_enter_public_path(boundary, kind):
    public, spy = boundary
    request = inference._NetworkInferenceRequest(
        inference._NetworkSourceProvenance.approved_unsw(),
        NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
        (100.0, 2, 1, 120, 60, 30.0, 1800.0, 60.0, 60.0, 443, "tcp"),
    )

    class RequestSubclass(inference._NetworkInferenceRequest):
        pass

    substitutes = {
        "manual": request,
        "serialized": asdict(request),
        "duck": SimpleNamespace(**asdict(request)),
        "subclass": RequestSubclass(
            request.provenance, request.feature_names, request.feature_values
        ),
        "dict": dict(zip(RAW_NAMES, raw_row())) | {"source_representation": "approved"},
        "cic": {"source": "cse_cic_ids2018", "raw_values": raw_row()},
        "unknown": {"source": "secret /private/source", "raw_values": raw_row()},
        "canonical": adapt_unsw_row(dict(zip(RAW_NAMES, raw_row())) | {"flow_id": "fixture"}),
    }
    result = public.infer(substitutes[kind])
    assert result.reason == "raw_input_rejected"
    assert result.source_representation_identity == "unapproved"
    assert spy.calls == []


def test_list_and_scalar_subclasses_are_rejected_without_running_custom_code(boundary):
    public, spy = boundary

    class ListSubclass(list):
        def __iter__(self):
            pytest.fail("custom row iteration executed")

    class StringSubclass(str):
        def __str__(self):
            pytest.fail("custom scalar conversion executed")

    for row in (ListSubclass(raw_row()), raw_row(dur=StringSubclass("0.1"))):
        assert public.infer(row).reason == "raw_input_rejected"
    assert spy.calls == []


def test_snapshot_is_immutable_and_input_mutation_cannot_replace_predictors(boundary):
    public, spy = boundary
    row = raw_row()
    request = public._prepare(row)
    assert request.feature_names == NETWORK_BEHAVIOR_V1_FEATURE_NAMES
    with pytest.raises(FrozenInstanceError):
        request.feature_values = ()
    with pytest.raises(FrozenInstanceError):
        request.provenance.source_representation = "unknown"
    with pytest.raises(TypeError):
        request.feature_values[0] = 0
    assert "120" not in repr(request)
    assert UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1 not in repr(request.provenance)

    def mutate_after_adaptation():
        yield row
        row[:] = raw_row(sbytes="240", label="1", attack_cat="changed")
        yield row

    batch = public.infer_batch(mutate_after_adaptation())
    assert batch.succeeded == 2
    assert [matrix[0, 3] for matrix in spy.calls] == [120, 240]
    assert request.feature_values[3] == 120


def test_labels_categories_endpoints_and_raw_derived_fields_are_not_predictors(boundary):
    public, spy = boundary
    public.infer(raw_row())
    public.infer(
        raw_row(
            label="1",
            attack_cat="secret /private/category",
            srcip="203.0.113.5",
            sport="42",
            sload="999999",
            smeansz="999999",
        )
    )
    np.testing.assert_array_equal(*spy.calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("dur", "NaN"),
        ("dur", "inf"),
        ("dur", "1e300"),
        ("dur", "-1"),
        ("dur", "1e-320"),
        ("dur", None),
        ("dur", True),
        ("dur", "x" * 1025),
        ("spkts", "many"),
        ("spkts", "9007199254740993"),
        ("spkts", "1e999"),
        ("spkts", "0.1"),
        ("sbytes", "-1"),
        ("sbytes", "NaN"),
        ("dsport", "65536"),
        ("srcip", "secret-invalid-ip"),
        ("label", "2"),
        ("stime", "1e999"),
        ("proto", ""),
        ("spkts", "0"),
    ],
)
def test_malformed_raw_values_never_call_predictor(boundary, field, value):
    public, spy = boundary
    result = public.infer(raw_row(**{field: value}))
    assert result.status == "rejected"
    assert result.attack_probability is None
    assert spy.calls == []


def test_demonstrates_historical_integer_rounding_is_blocked_here(boundary):
    public, spy = boundary
    row = raw_row(spkts="9007199254740993")
    legacy = adapt_unsw_row(dict(zip(RAW_NAMES, row)) | {"flow_id": "fixture"})
    assert legacy.fwd_packets == 9007199254740992
    assert public.infer(row).reason == "raw_input_rejected"
    assert spy.calls == []


@pytest.mark.parametrize("kind", ["duck", "subclass", "cic", "contract", "exception"])
def test_adapter_failures_or_substitute_events_never_predict(boundary, monkeypatch, kind):
    public, spy = boundary
    real = adapt_unsw_row(dict(zip(RAW_NAMES, raw_row())) | {"flow_id": "fixture"})

    class FlowSubclass(NetworkFlow):
        pass

    def adapt(row):
        if kind == "exception":
            raise RuntimeError("192.0.2.1 secret /private/adapter")
        return {
            "duck": SimpleNamespace(**real.model_dump()),
            "subclass": FlowSubclass(**real.model_dump()),
            "cic": real.model_copy(update={"source_dataset": "cse_cic_ids2018"}),
            "contract": real.model_copy(update={"schema_version": "unknown"}),
        }[kind]

    monkeypatch.setattr(inference, "adapt_unsw_row", adapt)
    assert public.infer(raw_row()).reason == "raw_input_rejected"
    assert spy.calls == []


@pytest.mark.parametrize("kind", ["order", "contract"])
def test_internal_contract_regression_is_still_blocked_before_prediction(
    boundary, monkeypatch, kind
):
    public, spy = boundary
    prepared = public._prepare(raw_row())
    if kind == "order":
        prepared = replace(prepared, feature_names=tuple(reversed(prepared.feature_names)))
    else:
        prepared = replace(
            prepared, provenance=replace(prepared.provenance, feature_contract_version="unknown")
        )
    monkeypatch.setattr(public, "_prepare", lambda row: prepared)
    assert public.infer(raw_row()).status == "rejected"
    assert spy.calls == []


def test_mixed_batch_preserves_order_and_accounting(boundary):
    public, spy = boundary
    batch = public.infer_batch(
        [raw_row(), {"secret": "path"}, raw_row(sbytes="240"), raw_row(label="2")]
    )
    assert (batch.received, batch.succeeded, batch.rejected) == (4, 2, 2)
    assert [result.status for result in batch.results] == ["completed", "rejected"] * 2
    assert [matrix[0, 3] for matrix in spy.calls] == [120, 240]


@pytest.mark.parametrize("size", [0, 1, 256, 257])
def test_batch_boundaries(boundary, size):
    public, spy = boundary
    if size > 256:
        with pytest.raises(inference.NetworkInferenceError, match="^batch_size_exceeded$"):
            public.infer_batch([raw_row()] * size)
        assert spy.calls == []
    else:
        assert public.infer_batch([raw_row()] * size).received == size
        assert len(spy.calls) == size


def test_iterator_failure_and_endless_iterator_abort_without_predictions(boundary):
    public, spy = boundary

    def broken():
        yield raw_row()
        raise RuntimeError("192.0.2.1 secret /private/input")

    with pytest.raises(inference.NetworkInferenceError, match="^batch_iteration_failed$") as error:
        public.infer_batch(broken())
    assert error.value.__suppress_context__
    assert "secret" not in str(error.value)
    consumed = []

    def endless():
        while True:
            consumed.append(1)
            yield None

    with pytest.raises(inference.NetworkInferenceError, match="^batch_size_exceeded$"):
        public.infer_batch(endless())
    assert len(consumed) == 257
    assert spy.calls == []


def test_outputs_and_errors_do_not_echo_sensitive_input(boundary, capsys):
    public, _ = boundary
    outputs = [
        public.infer(raw_row()),
        public.infer(raw_row(srcip="secret /private/input")),
        public.infer({"source": "private-provenance", "features": [123456789]}),
    ]
    text = json.dumps([result.to_dict() for result in outputs]) + repr(outputs)
    for sensitive in (
        "192.0.2.1",
        "198.51.100.2",
        "/private",
        "secret",
        "private-category",
        "private-provenance",
        "123456789",
        "feature_values",
        "flow_id",
    ):
        assert sensitive not in text
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("file", ["data/manifests/unsw_nb15.yaml", "NUSW-NB15_features.csv"])
def test_registration_integrity_failure_precedes_model_loading(registered_root, monkeypatch, file):
    (registered_root / file).write_bytes(b"secret /private/modified")

    def forbidden(*args, **kwargs):
        pytest.fail("model loading reached after registration failure")

    monkeypatch.setattr(inference, "_preprocessing_snapshot", forbidden)
    with pytest.raises(inference.NetworkInferenceError, match="^unsw_registration_invalid$"):
        inference.UnswNetworkInferenceBoundary(project_root=registered_root)


def test_schema_decodes_the_verified_snapshot(registered_root, monkeypatch):
    original = inference.parse_unsw_feature_names

    def replace_after_hash(data, *, path):
        (registered_root / "NUSW-NB15_features.csv").write_bytes(b"untrusted replacement")
        return original(data, path=path)

    monkeypatch.setattr(inference, "parse_unsw_feature_names", replace_after_hash)
    assert inference._registered_unsw_schema(registered_root) == RAW_NAMES


def test_real_registered_schema_matches_fixture_when_available():
    root = Path(__file__).parents[3]
    if not (root / "data/raw/unsw_nb15/official/NUSW-NB15_features.csv").is_file():
        pytest.skip("ignored registered metadata unavailable")
    assert inference._registered_unsw_schema(root) == RAW_NAMES


@pytest.mark.parametrize("width", [0, 11, 48, 50, 80])
def test_feature_vectors_wrong_raw_width_and_cic_width_never_predict(boundary, width):
    public, spy = boundary
    assert public.infer(["0"] * width).reason == "raw_input_rejected"
    assert spy.calls == []


def test_invalid_model_selection_precedes_adaptation_even_for_empty_batch(boundary, monkeypatch):
    public, spy = boundary

    def forbidden(row):
        pytest.fail("invalid model reached adaptation")

    monkeypatch.setattr(public, "_prepare", forbidden)
    for rows in ([], [raw_row()]):
        with pytest.raises(inference.NetworkInferenceError, match="^model_not_supported$"):
            public.infer_batch(rows, model=[])
    assert spy.calls == []


def test_public_path_preserves_model_failure_no_fallback(boundary, monkeypatch):
    public, spy = boundary

    class BrokenForest:
        classes_ = np.asarray([0, 1])

        def predict_proba(self, matrix):
            raise RuntimeError("secret /private/model")

    public._predictor._models[inference.NetworkModelChoice.RANDOM_FOREST] = inference._LoadedModel(
        BrokenForest(), "random_forest", "fixture_v1"
    )
    result = public.infer(raw_row())
    assert result.reason == "model_prediction_failed"
    assert spy.calls == []
    assert "secret" not in repr(result)


def test_real_frozen_bundle_through_public_raw_path_when_available():
    root = Path(__file__).parents[3]
    if (
        not all(path.is_dir() for path in inference.default_artifact_directories(root))
        or not (root / "data/raw/unsw_nb15/official/NUSW-NB15_features.csv").is_file()
    ):
        pytest.skip("ignored frozen bundles or metadata unavailable")
    public = inference.UnswNetworkInferenceBoundary(project_root=root)
    result = public.infer(raw_row())
    assert result.status == "completed"
    assert result.model_identity == "random_forest"
    assert result.source_representation_identity == UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1


@pytest.mark.parametrize(
    "field,value",
    [
        ("dur", "1e-999"),
        ("dur", "-1e-999"),
        ("label", "1.0000000000000001"),
        ("label", "1e-999"),
        ("label", "-1e-999"),
    ],
)
def test_raw_rounding_cannot_turn_invalid_numbers_into_approved_input(boundary, field, value):
    public, spy = boundary
    result = public.infer(raw_row(**{field: value}))
    assert result.reason == "raw_input_rejected"
    assert result.source_representation_identity == "unapproved"
    assert result.attack_probability is None
    assert spy.calls == []


def test_raw_timestamp_cannot_invoke_warning_leaking_generic_date_parser(boundary, capsys):
    public, spy = boundary
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = public.infer(raw_row(stime="2026-01-01 00:00:00 XYZ"))
    assert caught == []
    assert result.reason == "raw_input_rejected"
    assert result.source_representation_identity == "unapproved"
    assert spy.calls == []
    assert capsys.readouterr() == ("", "")


def test_corrected_numeric_validation_preserves_exact_values_and_rejects_loss(boundary):
    public, spy = boundary
    # Equivalent spellings retain the adapter's numeric semantics, including
    # Unicode decimal digits; ports keep their separate decimal/hex grammar.
    for spelling in ("2", "+2", " 2 ", "2e0", "2.000", "٢", "0_2"):
        spy.calls.clear()
        assert public.infer(raw_row(spkts=spelling, label="1.0")).status == "completed"
        assert len(spy.calls) == 1
        assert spy.calls[0][0, 1] == 2
    for value in (2**53 - 1, 2**53):
        spy.calls.clear()
        assert public.infer(raw_row(spkts=str(value))).status == "completed"
        assert spy.calls[0][0, 1] == value
    for invalid in (
        str(2**53 + 1),
        str(2**53 + 2),
        str(2**63 - 1),
        str(-(2**63)),
        "9" * 1024,
        "0" * 1025,
        "1e999999999",
        "NaN",
        "Infinity",
        "-Infinity",
        "1e-999",
        "2.0000000000000001",
        "1__0",
        "²",
    ):
        spy.calls.clear()
        assert public.infer(raw_row(spkts=invalid)).reason == "raw_input_rejected"
        assert spy.calls == []
    for invalid in ("1__0", "1_.0", "NaN", "-Infinity", "1e999", "1e-999"):
        spy.calls.clear()
        assert public.infer(raw_row(dur=invalid)).reason == "raw_input_rejected"
        assert spy.calls == []


def test_zero_duration_and_numeric_epoch_remain_supported_without_date_fallback(boundary):
    public, spy = boundary
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = public.infer(raw_row(dur="0", stime="1421928000.25"))
    assert result.status == "completed"
    assert caught == []
    assert len(spy.calls) == 1
    assert spy.calls[0][0, 0] == spy.calls[0][0, 5] == spy.calls[0][0, 6] == 0


def test_copied_or_pickled_internal_requests_are_not_public_inputs(boundary):
    public, spy = boundary
    request = public._prepare(raw_row())
    # Only a locally created fixture is unpickled; no untrusted pickle loading is offered.
    for substitute in (
        copy(request),
        deepcopy(request),
        pickle.loads(pickle.dumps(request)),
        pickle.dumps(request),
    ):
        assert public.infer(substitute).reason == "raw_input_rejected"
    assert spy.calls == []


def test_failure_after_256_prepared_rows_still_aborts_all_predictions(boundary):
    public, spy = boundary

    def delayed_failure():
        for _ in range(256):
            yield raw_row()
        raise ValueError("private delayed iterator detail")

    with pytest.raises(inference.NetworkInferenceError, match="^batch_iteration_failed$"):
        public.infer_batch(delayed_failure())
    assert spy.calls == []
