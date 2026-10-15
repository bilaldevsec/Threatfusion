"""Dataset and source provenance adapters."""

from typing import TYPE_CHECKING

from threatfusion.datasets.adapters.base import SourceRowValidationError

if TYPE_CHECKING:
    from threatfusion.datasets.adapters.provenance_sources import (
        AdaptedProvenanceRecord,
        AuthorizedLabSensorAdapter,
        MordorScenarioAdapter,
        RegisteredSensorManifest,
        SensorRegistration,
    )
    from threatfusion.datasets.adapters.suricata_flow import (
        DEFAULT_SURICATA_SENSOR_NAMESPACE,
        SURICATA_FLOW_ADAPTER_SCHEMA_VERSION,
        SURICATA_FLOW_SOURCE_REPRESENTATION,
        SuricataFlowAdaptationResult,
        SuricataFlowAdapter,
    )

__all__ = [
    "AdaptedProvenanceRecord",
    "AuthorizedLabSensorAdapter",
    "DEFAULT_SURICATA_SENSOR_NAMESPACE",
    "MordorScenarioAdapter",
    "RegisteredSensorManifest",
    "SURICATA_FLOW_ADAPTER_SCHEMA_VERSION",
    "SURICATA_FLOW_SOURCE_REPRESENTATION",
    "SensorRegistration",
    "SourceRowValidationError",
    "SuricataFlowAdaptationResult",
    "SuricataFlowAdapter",
]


def __getattr__(name: str):
    if name in {
        "AdaptedProvenanceRecord",
        "AuthorizedLabSensorAdapter",
        "MordorScenarioAdapter",
        "RegisteredSensorManifest",
        "SensorRegistration",
    }:
        from threatfusion.datasets.adapters import provenance_sources

        return getattr(provenance_sources, name)
    if name in {
        "DEFAULT_SURICATA_SENSOR_NAMESPACE",
        "SURICATA_FLOW_ADAPTER_SCHEMA_VERSION",
        "SURICATA_FLOW_SOURCE_REPRESENTATION",
        "SuricataFlowAdaptationResult",
        "SuricataFlowAdapter",
    }:
        from threatfusion.datasets.adapters import suricata_flow

        return getattr(suricata_flow, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
