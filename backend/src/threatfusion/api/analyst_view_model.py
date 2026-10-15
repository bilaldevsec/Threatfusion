"""Internal, capability-gated alert view model; no network authentication here."""

from __future__ import annotations

from threatfusion.api.alert_explanation import explanation_for
from threatfusion.db.analyst_state_repository import AnalystStateRepository
from threatfusion.schemas.alert_candidate import AlertCandidate
from threatfusion.schemas.analyst_state import (
    AnalystAlertDetail,
    AnalystAlertListItem,
    AnalystCapability,
    AnalystStateError,
    AnalystStateSnapshot,
    AnalystTransitionEvent,
    AnalystTransitionResult,
)

VIEW_SCHEMA_VERSION = "analyst_alert_view_v1"
_PUBLIC_ERRORS = frozenset(
    {
        "analyst_not_authorized",
        "alert_candidate_id_invalid",
        "alert_candidate_not_found",
        "list_limit_invalid",
        "list_offset_invalid",
        "analyst_state_version_invalid",
        "analyst_target_state_invalid",
        "analyst_transition_id_invalid",
        "analyst_rationale_invalid",
        "analyst_state_version_conflict",
        "analyst_transition_identity_conflict",
        "analyst_transition_invalid",
    }
)


class AnalystViewError(RuntimeError):
    """A fixed public-safe code, with no exception or storage details."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _PUBLIC_ERRORS else "analyst_view_unavailable"
        super().__init__(self.code)


def _evidence(candidate: AlertCandidate) -> dict[str, object]:
    return {
        "alert_candidate_id": candidate.alert_candidate_id,
        "source_event_id": candidate.source_event_id,
        "observed_at": candidate.observed_at.isoformat(),
        "created_at": candidate.created_at.isoformat(),
        "source_representation_identity": candidate.source_representation_identity,
        "feature_contract_identity": candidate.feature_contract_identity,
        "model_identity": candidate.model_identity,
        "model_version": candidate.model_version,
        "model_artifact_sha256": candidate.model_artifact_sha256,
        "uncalibrated_model_score": candidate.uncalibrated_model_score,
        "decision_threshold": candidate.decision_threshold,
        "decision_policy_version": candidate.decision_policy_version,
        "decision": candidate.decision,
    }


def _state(state: AnalystStateSnapshot) -> dict[str, object]:
    return {
        "state": state.state,
        "version": state.version,
        "updated_at": state.updated_at.isoformat() if state.updated_at else None,
        "updated_by": state.updated_by,
        "last_transition_id": state.last_transition_id,
    }


def _event(event: AnalystTransitionEvent) -> dict[str, object]:
    return {
        "transition_id": event.transition_id,
        "sequence": event.sequence,
        "from_state": event.from_state,
        "to_state": event.to_state,
        "actor_id": event.actor_id,
        "rationale": event.rationale,
        "transitioned_at": event.transitioned_at.isoformat(),
    }


def _item(item: AnalystAlertListItem | AnalystAlertDetail) -> dict[str, object]:
    return {
        "detection_evidence": _evidence(item.candidate),
        "analyst_state": _state(item.analyst_state),
    }


class AnalystAlertViewModel:
    """Format authorized repository results for a future authenticated adapter.

    Capabilities must come from trusted in-process code. This class does not accept
    actor IDs, roles, headers, certificates, or JSON as authentication evidence.
    """

    def __init__(
        self,
        repository: AnalystStateRepository,
        *,
        incident_repository: object | None = None,
    ) -> None:
        if type(repository) is not AnalystStateRepository:
            raise AnalystViewError("analyst_view_unavailable")
        self._repository = repository
        self._incident_repository = incident_repository

    def list_alerts(
        self, capability: AnalystCapability, *, limit: int = 50, offset: int = 0
    ) -> dict[str, object]:
        try:
            items = self._repository.list_alerts(capability, limit=limit, offset=offset)
            return {
                "schema_version": VIEW_SCHEMA_VERSION,
                "limit": limit,
                "offset": offset,
                "items": [_item(item) for item in items],
            }
        except AnalystStateError as error:
            raise AnalystViewError(error.code) from None
        except Exception:
            raise AnalystViewError("analyst_view_unavailable") from None

    def get_alert(
        self, capability: AnalystCapability, alert_candidate_id: str
    ) -> dict[str, object] | None:
        try:
            detail = self._repository.get_alert(capability, alert_candidate_id)
            if detail is None:
                return None

            incident = None
            if self._incident_repository is not None and hasattr(
                self._incident_repository, "get_incident_for_alert"
            ):
                incident = self._incident_repository.get_incident_for_alert(alert_candidate_id)

            if incident is not None:
                correlation_meta = {
                    "incident_id": str(incident.incident_id),
                    "correlation_mode": str(incident.correlation_mode),
                    "window_type": str(incident.window_type),
                    "correlation_rule_id": str(incident.correlation_rule_id),
                    "constituent_alert_count": int(incident.constituent_alert_count),
                    "provenance_status": str(incident.provenance_status),
                    "explanation": (
                        "Correlated within 30s burst window."
                        if incident.window_type == "burst_30s"
                        else (
                            "Correlated within 10m campaign window."
                            if incident.window_type == "campaign_600s"
                            else "Preserved as verified singleton incident."
                        )
                    ),
                }
            else:
                from threatfusion.alerts.correlation_engine import derive_incident_id

                inc_id = derive_incident_id(
                    "corr_singleton_unverified_provenance_v1", (alert_candidate_id,)
                )
                correlation_meta = {
                    "incident_id": inc_id,
                    "correlation_mode": "singleton_unverified_provenance",
                    "window_type": "none",
                    "correlation_rule_id": "corr_singleton_unverified_provenance_v1",
                    "constituent_alert_count": 1,
                    "provenance_status": "unverified_provenance",
                    "explanation": (
                        "UNSW-NB15 raw telemetry lacks authenticated entity endpoints "
                        "and synchronized clocks; preserved as singleton incident."
                    ),
                }

            return {
                "schema_version": VIEW_SCHEMA_VERSION,
                **_item(detail),
                "analyst_history": [_event(event) for event in detail.transitions],
                "explanation": explanation_for(_evidence(detail.candidate)),
                "incident_correlation": correlation_meta,
            }
        except AnalystStateError as error:
            raise AnalystViewError(error.code) from None
        except Exception:
            raise AnalystViewError("analyst_view_unavailable") from None

    def transition(
        self,
        capability: AnalystCapability,
        *,
        alert_candidate_id: str,
        expected_version: int,
        to_state: str,
        transition_id: str,
        rationale: str,
    ) -> dict[str, object]:
        try:
            result: AnalystTransitionResult = self._repository.transition(
                capability,
                alert_candidate_id=alert_candidate_id,
                expected_version=expected_version,
                to_state=to_state,
                transition_id=transition_id,
                rationale=rationale,
            )
            return {
                "schema_version": VIEW_SCHEMA_VERSION,
                "disposition": result.disposition,
                "alert_candidate_id": alert_candidate_id,
                "analyst_state": _state(result.analyst_state),
                "analyst_transition": _event(result.transition),
            }
        except AnalystStateError as error:
            raise AnalystViewError(error.code) from None
        except Exception:
            raise AnalystViewError("analyst_view_unavailable") from None
