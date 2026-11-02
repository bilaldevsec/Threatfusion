"""ThreatFusion API Layer Package.

Dashboard exports stay lazy so importing a Stage 3 worker does not load
advisory or analyst-dashboard modules into ``sys.modules``.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "AlertNoiseReductionFunnel",
    "AnalystDashboardAuthenticationError",
    "AnalystDashboardClient",
    "AnalystDashboardError",
    "AnalystDashboardUnavailableError",
    "DashboardAlertDetail",
    "DashboardAlertQueue",
    "DashboardAlertSummary",
    "DashboardIncidentSummary",
    "DashboardSnapshot",
    "DashboardTransitionRecord",
    "TriageQueueCardView",
    "_is_verified_receipt_dict",
    "build_five_tab_investigation_inspector",
    "compute_alert_noise_reduction_funnel",
    "load_frontend_unicorn_bundle",
    "render_dashboard_html",
    "verify_audit_chain_integrity",
    "verify_explanation_groundedness",
    "verify_frontend_asset_bundle",
]

_DASHBOARD_EXPORTS = frozenset(__all__)


def __getattr__(name: str) -> Any:
    if name not in _DASHBOARD_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from threatfusion.api import analyst_dashboard

    value = getattr(analyst_dashboard, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | _DASHBOARD_EXPORTS)
