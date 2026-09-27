"""Retained evidence fixtures only: no model loading, inference or artifact access."""

from dataclasses import replace

import pytest

from threatfusion.api import alert_explanation as explanation
from threatfusion.api.analyst_dashboard import _parse_detail
from threatfusion.api.analyst_view_model import _evidence
from threatfusion.models.network_inference import APPROVED_MODEL_HASHES
from threatfusion.schemas.alert_candidate import derive_alert_candidate_id
from backend.tests.unit.test_analyst_view_model import _candidate, _setup


def approved_candidate():
    candidate = _candidate(1)
    digest = APPROVED_MODEL_HASHES["random_forest"]["model"]
    return replace(
        candidate,
        model_artifact_sha256=digest,
        alert_candidate_id=derive_alert_candidate_id(
            source_event_id=candidate.source_event_id,
            detector_identity=candidate.detector_identity,
            detector_version=candidate.detector_version,
            model_identity=candidate.model_identity,
            model_version=candidate.model_version,
            model_artifact_sha256=digest,
            decision_policy_version=candidate.decision_policy_version,
        ),
    )


def test_factual_result_and_binding():
    evidence = _evidence(approved_candidate())
    result = explanation.explanation_for(evidence)
    assert result["status"] == "available"
    assert "0.75" in result["summary"]
    assert "inclusive threshold 0.5" in result["summary"]
    assert result["alert_candidate_id"] == evidence["alert_candidate_id"]
    changed = {**evidence, "uncalibrated_model_score": 0.9}
    assert explanation.validate_explanation(result, changed)["status"] == "unavailable"
    assert (
        explanation.validate_explanation(
            {**result, "summary": "<script>invented</script>"}, evidence
        )["status"]
        == "unavailable"
    )
    assert explanation.validate_explanation(None, evidence)["status"] == "unavailable"
    assert (
        explanation.validate_explanation({**result, "schema_version": "future_v2"}, evidence)[
            "status"
        ]
        == "unavailable"
    )
    assert (
        explanation.explanation_for({**evidence, "uncalibrated_model_score": 0.5})["status"]
        == "available"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("model_artifact_sha256", "a" * 64),
        ("alert_candidate_id", "alert_candidate_v1:" + "0" * 64),
        ("decision_threshold", 0.6),
        ("uncalibrated_model_score", 0.49),
        ("decision", "Normal"),
        ("model_identity", "logistic_regression"),
        ("source_representation_identity", "unknown"),
    ],
)
def test_unsupported_evidence_unavailable(field, value):
    evidence = {**_evidence(approved_candidate()), field: value}
    assert explanation.explanation_for(evidence)["status"] == "unavailable"


def test_failure_isolated_from_persisted_detail(tmp_path, monkeypatch):
    candidates, _, _, _, registry, view = _setup(tmp_path)
    capability = registry.issue_for_trusted_actor("queue.viewer")
    before = view.get_alert(capability, candidates[0].alert_candidate_id)

    def fail(_):
        raise RuntimeError("private-storage-secret")

    monkeypatch.setattr(explanation, "generate_explanation", fail)
    after = view.get_alert(capability, candidates[0].alert_candidate_id)
    assert before == after
    assert "private-storage-secret" not in str(after)
    assert _parse_detail(after).explanation["status"] == "unavailable"
