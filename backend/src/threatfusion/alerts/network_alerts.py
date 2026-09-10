"""Attack-only alert creation from the trusted registered UNSW inference path."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from threatfusion.db.alert_repository import AlertCandidateRepository, AlertInsertResult
from threatfusion.models.network_inference import (
    NetworkInferenceError,
    NetworkModelChoice,
    RegisteredUnswInferenceResult,
    UnswNetworkInferenceBoundary,
)
from threatfusion.schemas.alert_candidate import (
    ALERT_CANDIDATE_SCHEMA_VERSION,
    DECISION_POLICY_VERSION,
    DETECTOR_IDENTITY,
    DETECTOR_VERSION,
    AlertCandidate,
    AlertCandidateError,
    derive_alert_candidate_id,
    utc_now,
)


@dataclass(frozen=True, slots=True)
class AlertWorkflowResult:
    """Sanitized integration disposition without raw input or inference internals."""

    disposition: str
    reason: str
    persistence: AlertInsertResult | None


def build_alert_candidate(
    registered: RegisteredUnswInferenceResult, *, created_at: datetime | None = None
) -> AlertCandidate:
    """Create an actionable candidate only from a successful registered Attack result."""
    if type(registered) is not RegisteredUnswInferenceResult:
        raise AlertCandidateError("registered_inference_required")
    result = registered.inference
    if (
        result.status != "completed"
        or result.reason != "inference_succeeded"
        or result.predicted_class != "Attack"
        or result.attack_probability is None
    ):
        raise AlertCandidateError("inference_not_actionable")
    created = utc_now() if created_at is None else created_at
    candidate_id = derive_alert_candidate_id(
        source_event_id=registered.source_event_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity=result.model_identity,
        model_version=result.model_version,
        model_artifact_sha256=registered.model_artifact_sha256,
        decision_policy_version=DECISION_POLICY_VERSION,
    )
    return AlertCandidate(
        schema_version=ALERT_CANDIDATE_SCHEMA_VERSION,
        alert_candidate_id=candidate_id,
        source_event_id=registered.source_event_id,
        correlation_id=result.correlation_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity=result.model_identity,
        model_version=result.model_version,
        model_artifact_sha256=registered.model_artifact_sha256,
        feature_contract_identity=result.contract_identity,
        source_representation_identity=result.source_representation_identity,
        observed_at=registered.observed_at,
        created_at=created,
        uncalibrated_model_score=float(result.attack_probability),
        decision_threshold=float(result.decision_threshold),
        decision_policy_version=DECISION_POLICY_VERSION,
        decision="Attack",
        inference_status="completed",
        reason="inference_succeeded",
    )


def infer_and_persist_registered_attack(
    boundary: UnswNetworkInferenceBoundary,
    repository: AlertCandidateRepository,
    *,
    source_member_sha256: str,
    row_number: int,
    model: NetworkModelChoice = NetworkModelChoice.RANDOM_FOREST,
    created_at: datetime | None = None,
) -> AlertWorkflowResult:
    """Run the trusted offline path and atomically persist only an Attack candidate."""
    try:
        registered = boundary.infer_registered(
            source_member_sha256=source_member_sha256,
            row_number=row_number,
            model=model,
        )
    except NetworkInferenceError as exc:
        return AlertWorkflowResult("not_actionable", exc.code, None)
    if (
        registered.inference.status != "completed"
        or registered.inference.predicted_class != "Attack"
    ):
        return AlertWorkflowResult("not_actionable", registered.inference.reason, None)
    candidate = build_alert_candidate(registered, created_at=created_at)
    persisted = repository.insert(candidate)
    return AlertWorkflowResult(persisted.disposition, persisted.reason, persisted)
