"""Validated, fail-closed provenance-bearing adapters for Mordor and Authorized Lab Sensors.

Implements Phase P3 of docs/GEMINI_PROJECT_MASTER.md:
1. MordorScenarioAdapter: Normalizes supported Mordor host/security scenario records with explicit
   source_mode = "scenario_replay", scenario_id, entity_namespace_id (scoped to specific scenario),
   entity endpoints, validity interval, clock origin/synchronization, and clock skew.
2. AuthorizedLabSensorAdapter: Normalizes registered lab sensor events with explicit
   source_mode = "authorized_lab_sensor", enforcing allowlisted RegisteredSensorManifest membership,
   strict replay/duplicate source_event_id detection, and strict separation between dataset/scenario replay
   and live/lab sensors.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from threatfusion.alerts.correlation_engine import EntityProvenanceContract
from threatfusion.datasets.adapters.base import (
    SourceRowValidationError,
    normalize_protocol,
    parse_required_timestamp,
    required_alias,
    required_string,
)
from threatfusion.datasets.mordor_raw import MORDOR_INGESTION_ID_FIELD


@dataclass(frozen=True, slots=True)
class SensorRegistration:
    """Pre-registered lab sensor configuration in an allowlisted manifest."""

    sensor_id: str
    entity_namespace_id: str
    clock_synchronized: bool = True
    max_clock_skew_seconds: float = 0.0
    privacy_redaction_policy: str = "strict_rfc1918_internal"
    address_reuse_or_nat: bool = False
    validity_start_utc: str | None = None
    validity_end_utc: str | None = None
    entity_role: str = "lab_sensor"


class RegisteredSensorManifest:
    """Allowlist manifest of authorized lab sensors."""

    def __init__(self, sensors: Sequence[SensorRegistration] | None = None) -> None:
        self._sensors: dict[str, SensorRegistration] = {}
        if sensors:
            for s in sensors:
                self.register(s)

    def register(self, sensor: SensorRegistration) -> None:
        if not sensor.sensor_id or not sensor.sensor_id.strip():
            raise ValueError("sensor_id cannot be blank")
        if not sensor.entity_namespace_id or not sensor.entity_namespace_id.strip():
            raise ValueError("entity_namespace_id cannot be blank")
        self._sensors[sensor.sensor_id] = sensor

    def get(self, sensor_id: str) -> SensorRegistration | None:
        return self._sensors.get(sensor_id)

    def is_registered(self, sensor_id: str) -> bool:
        return sensor_id in self._sensors


@dataclass(frozen=True, slots=True)
class AdaptedProvenanceRecord:
    """Normalized record packaging source identity, provenance descriptor, and raw payload."""

    source_event_id: str
    source_mode: str  # "scenario_replay" or "authorized_lab_sensor"
    observed_at_utc: str
    provenance: EntityProvenanceContract
    raw_payload: Mapping[str, Any]


class MordorScenarioAdapter:
    """Adapter for Mordor host/security events bound to a specific scenario capture."""

    def __init__(
        self,
        scenario_id: str,
        *,
        default_entity_role: str = "workstation",
        clock_origin: str = "utc_event_log",
        clock_synchronized: bool = True,
        max_clock_skew_seconds: float = 0.0,
        address_reuse_or_nat: bool = False,
        validity_start_utc: str | None = None,
        validity_end_utc: str | None = None,
    ) -> None:
        if not scenario_id or not scenario_id.strip():
            raise ValueError("scenario_id cannot be blank")
        self.scenario_id = scenario_id.strip()
        self.entity_namespace_id = f"mordor:{self.scenario_id}"
        self.default_entity_role = default_entity_role
        self.clock_origin = clock_origin
        self.clock_synchronized = clock_synchronized
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self.address_reuse_or_nat = address_reuse_or_nat
        self.validity_start_utc = validity_start_utc
        self.validity_end_utc = validity_end_utc

    def adapt(self, row: dict[str, Any]) -> AdaptedProvenanceRecord:
        source = "Mordor"

        # Explicit mode check
        if "source_mode" in row and row["source_mode"] != "scenario_replay":
            raise SourceRowValidationError(
                source,
                "source_mode",
                f"expected scenario_replay, got {row['source_mode']}",
            )

        # Event ID
        _, event_id_val = required_alias(
            row,
            source,
            (
                "RecordID",
                "EventRecordID",
                "event_id",
                "source_event_id",
                MORDOR_INGESTION_ID_FIELD,
            ),
        )
        source_event_id = str(event_id_val).strip()

        # Timestamp
        ts_field, ts_val = required_alias(
            row,
            source,
            ("UtcTime", "@timestamp", "TimeCreated", "timestamp", "observed_at_utc"),
        )
        dt = parse_required_timestamp(ts_val, source, ts_field)
        observed_at_iso = dt.isoformat()

        # Endpoint identification
        src_id: str | None = None
        for k in ("SourceIp", "src_ip", "Computer", "host", "Hostname"):
            val = row.get(k)
            if val is not None and str(val).strip() not in {"", "-", "None", "nan"}:
                src_id = str(val).strip()
                break

        dst_id: str | None = None
        for k in (
            "DestinationIp",
            "dst_ip",
            "Image",
            "ProcessName",
            "TargetFilename",
            "file_path",
            "TargetObject",
            "registry_key",
            "TargetUserName",
            "User",
        ):
            val = row.get(k)
            if val is not None and str(val).strip() not in {"", "-", "None", "nan"}:
                dst_id = str(val).strip()
                break

        # Fallback if host-internal activity: use host/computer as destination if missing
        if dst_id is None and src_id is not None:
            dst_id = f"{src_id}:local_process"

        if not src_id or not dst_id:
            raise SourceRowValidationError(
                source,
                ("src_entity_id", "dst_entity_id"),
                "unable to resolve both source and destination entity identifiers",
            )

        # Protocol and service/port
        proto_raw = row.get("Protocol") or row.get("protocol") or "other"
        protocol = normalize_protocol(proto_raw)

        port_val = (
            row.get("DestinationPort")
            or row.get("dst_port")
            or row.get("service_or_port")
            or row.get("Port")
        )
        service_or_port = str(port_val).strip() if port_val is not None else None

        # Build contract
        provenance = EntityProvenanceContract(
            entity_namespace_id=self.entity_namespace_id,
            clock_synchronized=self.clock_synchronized,
            src_entity_id=src_id,
            dst_entity_id=dst_id,
            protocol=protocol,
            service_or_port=service_or_port,
            observed_at_utc=observed_at_iso,
            validity_start_utc=self.validity_start_utc,
            validity_end_utc=self.validity_end_utc,
            address_reuse_or_nat=self.address_reuse_or_nat,
            max_clock_skew_seconds=self.max_clock_skew_seconds,
            source_mode="scenario_replay",
            entity_role=self.default_entity_role,
            clock_origin=self.clock_origin,
        )

        return AdaptedProvenanceRecord(
            source_event_id=source_event_id,
            source_mode="scenario_replay",
            observed_at_utc=observed_at_iso,
            provenance=provenance,
            raw_payload=row,
        )

    def adapt_provenance(self, row: dict[str, Any]) -> EntityProvenanceContract:
        return self.adapt(row).provenance


class AuthorizedLabSensorAdapter:
    """Adapter for real or lab sensor telemetry gated by RegisteredSensorManifest."""

    def __init__(self, manifest: RegisteredSensorManifest) -> None:
        self.manifest = manifest
        self._seen_source_event_ids: set[str] = set()

    def adapt(self, row: dict[str, Any]) -> AdaptedProvenanceRecord:
        source = "AuthorizedLabSensor"

        # Explicit mode check: reject attempts to masquerade dataset/scenario replay as lab sensor
        if "source_mode" in row and row["source_mode"] in {
            "scenario_replay",
            "dataset_replay",
        }:
            raise SourceRowValidationError(
                source,
                "source_mode",
                f"cannot submit {row['source_mode']} to AuthorizedLabSensorAdapter",
            )

        # Allowlisted sensor check
        sensor_id = required_string(row, source, "sensor_id")
        sensor_reg = self.manifest.get(sensor_id)
        if sensor_reg is None:
            raise SourceRowValidationError(
                source,
                "sensor_id",
                f"unregistered or unallowlisted sensor_id: '{sensor_id}'",
            )

        # Source event ID & replay/duplicate detection
        source_event_id = required_string(row, source, "source_event_id")
        if source_event_id in self._seen_source_event_ids:
            raise SourceRowValidationError(
                source,
                "source_event_id",
                f"duplicate/replay source_event_id rejected: '{source_event_id}'",
            )
        self._seen_source_event_ids.add(source_event_id)

        # Timestamp
        ts_field, ts_val = required_alias(
            row, source, ("observed_at_utc", "timestamp", "event_time")
        )
        dt = parse_required_timestamp(ts_val, source, ts_field)
        observed_at_iso = dt.isoformat()

        # Endpoints
        src_id = required_string(row, source, "src_entity_id")
        dst_id = required_string(row, source, "dst_entity_id")

        # Protocol and service
        proto_raw = row.get("protocol", "other")
        protocol = normalize_protocol(proto_raw)

        port_val = row.get("service_or_port") or row.get("dst_port")
        service_or_port = str(port_val).strip() if port_val is not None else None

        # Build contract bound to sensor registration
        provenance = EntityProvenanceContract(
            entity_namespace_id=sensor_reg.entity_namespace_id,
            clock_synchronized=sensor_reg.clock_synchronized,
            src_entity_id=src_id,
            dst_entity_id=dst_id,
            protocol=protocol,
            service_or_port=service_or_port,
            observed_at_utc=observed_at_iso,
            validity_start_utc=sensor_reg.validity_start_utc,
            validity_end_utc=sensor_reg.validity_end_utc,
            address_reuse_or_nat=sensor_reg.address_reuse_or_nat,
            max_clock_skew_seconds=sensor_reg.max_clock_skew_seconds,
            source_mode="authorized_lab_sensor",
            entity_role=sensor_reg.entity_role,
            clock_origin="ntp_synchronized_lab_clock",
        )

        return AdaptedProvenanceRecord(
            source_event_id=source_event_id,
            source_mode="authorized_lab_sensor",
            observed_at_utc=observed_at_iso,
            provenance=provenance,
            raw_payload=row,
        )

    def adapt_provenance(self, row: dict[str, Any]) -> EntityProvenanceContract:
        return self.adapt(row).provenance
