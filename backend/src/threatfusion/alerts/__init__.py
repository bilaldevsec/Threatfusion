"""Trusted alert-candidate construction and correlation engine."""

from threatfusion.alerts.correlation_engine import (
    BURST_WINDOW_SECONDS,
    CAMPAIGN_WINDOW_SECONDS,
    MAX_ALLOWABLE_CLOCK_SKEW_SECONDS,
    AlertReductionSummary,
    CorrelatableAlert,
    CorrelationSafetyError,
    EntityProvenanceContract,
    IncidentCorrelationResult,
    IncidentRecord,
    IncidentSqliteRepository,
    MemberJustification,
    compute_alert_reduction_metrics,
    correlate_alert_candidates,
    derive_incident_id,
)
from threatfusion.alerts.network_alerts import (
    AlertWorkflowResult,
    build_alert_candidate,
    infer_and_persist_registered_attack,
)

__all__ = [
    "AlertWorkflowResult",
    "build_alert_candidate",
    "infer_and_persist_registered_attack",
    "BURST_WINDOW_SECONDS",
    "CAMPAIGN_WINDOW_SECONDS",
    "MAX_ALLOWABLE_CLOCK_SKEW_SECONDS",
    "AlertReductionSummary",
    "CorrelatableAlert",
    "CorrelationSafetyError",
    "EntityProvenanceContract",
    "IncidentCorrelationResult",
    "IncidentRecord",
    "IncidentSqliteRepository",
    "MemberJustification",
    "compute_alert_reduction_metrics",
    "correlate_alert_candidates",
    "derive_incident_id",
]
