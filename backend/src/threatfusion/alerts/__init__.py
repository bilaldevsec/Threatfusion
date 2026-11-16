"""Trusted alert-candidate construction and correlation engine."""

from __future__ import annotations

import importlib
from typing import Any

_EXPORTS: dict[str, str] = {
    "AlertWorkflowResult": "threatfusion.alerts.network_alerts",
    "build_alert_candidate": "threatfusion.alerts.network_alerts",
    "infer_and_persist_registered_attack": "threatfusion.alerts.network_alerts",
    "BURST_WINDOW_SECONDS": "threatfusion.alerts.correlation_engine",
    "CAMPAIGN_WINDOW_SECONDS": "threatfusion.alerts.correlation_engine",
    "MAX_ALLOWABLE_CLOCK_SKEW_SECONDS": "threatfusion.alerts.correlation_engine",
    "AlertReductionSummary": "threatfusion.alerts.correlation_engine",
    "CorrelatableAlert": "threatfusion.alerts.correlation_engine",
    "CorrelationSafetyError": "threatfusion.alerts.correlation_engine",
    "EntityProvenanceContract": "threatfusion.alerts.correlation_engine",
    "IncidentCorrelationResult": "threatfusion.alerts.correlation_engine",
    "IncidentRecord": "threatfusion.alerts.correlation_engine",
    "IncidentSqliteRepository": "threatfusion.alerts.correlation_engine",
    "MemberJustification": "threatfusion.alerts.correlation_engine",
    "compute_alert_reduction_metrics": "threatfusion.alerts.correlation_engine",
    "correlate_alert_candidates": "threatfusion.alerts.correlation_engine",
    "derive_incident_id": "threatfusion.alerts.correlation_engine",
}


def __getattr__(name: str) -> Any:
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module_name), name)
    globals()[name] = value
    return value


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
