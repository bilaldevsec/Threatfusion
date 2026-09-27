"""Versioned factual presentation of retained evidence; never performs inference."""

import hashlib
import json
import math

from threatfusion.models.network_inference import APPROVED_MODEL_HASHES
from threatfusion.schemas.alert_candidate import (
    DECISION_POLICY_VERSION,
    DETECTOR_IDENTITY,
    DETECTOR_VERSION,
    derive_alert_candidate_id,
)

EXPLANATION_VERSION = "alert_explanation_v1"
LIMITATIONS = (
    "Feature attribution: unavailable (feature values and attribution not retained). "
    "Causal explanation: unavailable (no causal evidence retained). "
    "Source details: unavailable (opaque source ID; endpoints not retained). "
    "Stored artifact identity is checked against the approved RF registry; "
    "artifact bytes and original input are not reverified here."
)


def unavailable(evidence: dict[str, object]) -> dict[str, object]:
    """Fixed, sanitized fallback bound to the same displayed evidence."""
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return {
        "schema_version": EXPLANATION_VERSION,
        "alert_candidate_id": evidence["alert_candidate_id"],
        "evidence_sha256": digest,
        "status": "unavailable",
        "summary": "Explanation unavailable: supported retained evidence could not be verified.",
        "limitations": LIMITATIONS,
    }


def generate_explanation(evidence: dict[str, object]) -> dict[str, object]:
    result = unavailable(evidence)
    score = evidence["uncalibrated_model_score"]
    expected_id = derive_alert_candidate_id(
        source_event_id=evidence["source_event_id"],
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256=APPROVED_MODEL_HASHES["random_forest"]["model"],
        decision_policy_version=DECISION_POLICY_VERSION,
    )
    if not (
        evidence["alert_candidate_id"] == expected_id
        and evidence["model_identity"] == "random_forest"
        and evidence["model_version"] == "network_random_forest_baseline_v1"
        and evidence["model_artifact_sha256"] == APPROVED_MODEL_HASHES["random_forest"]["model"]
        and evidence["feature_contract_identity"] == "network_behavior_v1"
        and evidence["source_representation_identity"]
        == "unsw_nb15.argus.raw_49.transaction_bytes.v1"
        and evidence["decision_policy_version"] == DECISION_POLICY_VERSION
        and evidence["decision_threshold"] == 0.5
        and evidence["decision"] == "Attack"
        and type(score) in (int, float)
        and math.isfinite(score)
        and 0.5 <= score <= 1.0
    ):
        return result
    return {
        **result,
        "status": "available",
        "summary": (
            f"Stored frozen-RF score {score!r} meets the inclusive threshold 0.5, "
            "consistent with the stored Attack decision. This uncalibrated score "
            "is not a calibrated attack probability, severity, or causal explanation."
        ),
    }


def explanation_for(evidence: dict[str, object]) -> dict[str, object]:
    """Optional explanation failure must not suppress detection or analyst state."""
    try:
        return generate_explanation(evidence)
    except Exception:
        return unavailable(evidence)


def validate_explanation(raw: object, evidence: dict[str, object]) -> dict[str, object]:
    """Only exact versioned factual results bound to this evidence may be displayed."""
    fallback = unavailable(evidence)
    if type(raw) is dict and raw == explanation_for(evidence):
        return raw
    return fallback
