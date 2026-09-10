"""Trusted alert-candidate construction and local workflow integration."""

from threatfusion.alerts.network_alerts import (
    AlertWorkflowResult,
    build_alert_candidate,
    infer_and_persist_registered_attack,
)

__all__ = [
    "AlertWorkflowResult",
    "build_alert_candidate",
    "infer_and_persist_registered_attack",
]
