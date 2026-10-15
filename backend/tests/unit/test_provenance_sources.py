"""Unit tests for MordorScenarioAdapter and AuthorizedLabSensorAdapter (Phase P3)."""

import pytest

from threatfusion.datasets.adapters.base import SourceRowValidationError
from threatfusion.datasets.adapters.provenance_sources import (
    AuthorizedLabSensorAdapter,
    MordorScenarioAdapter,
    RegisteredSensorManifest,
    SensorRegistration,
)


def test_mordor_scenario_adapter_valid_network_event():
    """MordorScenarioAdapter normalizes valid Mordor network events into verified provenance."""
    adapter = MordorScenarioAdapter(
        scenario_id="apt29_eval_day1",
        default_entity_role="workstation",
        clock_origin="utc_event_log",
        clock_synchronized=True,
        max_clock_skew_seconds=0.0,
    )

    row = {
        "EventID": "3",
        "RecordID": "10452",
        "UtcTime": "2026-03-15T14:30:00.000Z",
        "Computer": "WORKSTATION-01.corp.local",
        "SourceIp": "192.168.1.105",
        "DestinationIp": "10.0.0.50",
        "DestinationPort": "443",
        "Protocol": "tcp",
    }

    record = adapter.adapt(row)
    assert record.source_mode == "scenario_replay"
    assert record.source_event_id == "10452"
    assert record.observed_at_utc == "2026-03-15T14:30:00+00:00"

    prov = record.provenance
    assert prov.entity_namespace_id == "mordor:apt29_eval_day1"
    assert prov.clock_synchronized is True
    assert prov.src_entity_id == "192.168.1.105"
    assert prov.dst_entity_id == "10.0.0.50"
    assert prov.protocol == "tcp"
    assert prov.service_or_port == "443"
    assert prov.max_clock_skew_seconds == 0.0
    assert prov.source_mode == "scenario_replay"
    assert prov.is_verified() is True


def test_mordor_scenario_adapter_valid_process_event():
    """MordorScenarioAdapter normalizes host process events using computer and process target."""
    adapter = MordorScenarioAdapter("apt29_eval_day1")

    row = {
        "EventID": "1",
        "EventRecordID": "5001",
        "@timestamp": "2026-03-15T14:35:10Z",
        "Computer": "DC01.corp.local",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "User": "CORP\\Administrator",
    }

    record = adapter.adapt(row)
    prov = record.provenance
    assert prov.src_entity_id == "DC01.corp.local"
    assert prov.dst_entity_id == "C:\\Windows\\System32\\cmd.exe"
    assert prov.is_verified() is True


def test_mordor_scenario_adapter_rejections():
    """MordorScenarioAdapter strictly rejects invalid timestamps, missing endpoints, and wrong mode."""
    adapter = MordorScenarioAdapter("test_scenario")

    # Invalid timestamp
    with pytest.raises(SourceRowValidationError) as exc:
        adapter.adapt(
            {
                "EventID": "1",
                "RecordID": "100",
                "UtcTime": "not-a-valid-date",
                "Computer": "HOST1",
            }
        )
    assert "timestamp" in exc.value.reason.lower()

    # Missing endpoints
    with pytest.raises(SourceRowValidationError) as exc:
        adapter.adapt(
            {
                "EventID": "1",
                "RecordID": "101",
                "UtcTime": "2026-03-15T14:00:00Z",
            }
        )
    assert "unable to resolve" in exc.value.reason.lower()

    # Wrong source mode
    with pytest.raises(SourceRowValidationError) as exc:
        adapter.adapt(
            {
                "EventID": "1",
                "RecordID": "102",
                "UtcTime": "2026-03-15T14:00:00Z",
                "Computer": "HOST1",
                "source_mode": "dataset_replay",
            }
        )
    assert "expected scenario_replay" in exc.value.reason.lower()

    # Blank scenario ID
    with pytest.raises(ValueError):
        MordorScenarioAdapter("")


def test_authorized_lab_sensor_adapter_valid():
    """AuthorizedLabSensorAdapter admits registered sensors and produces verified provenance."""
    manifest = RegisteredSensorManifest(
        [
            SensorRegistration(
                sensor_id="sensor-alpha",
                entity_namespace_id="campus-edge-dmz",
                clock_synchronized=True,
                max_clock_skew_seconds=0.5,
                privacy_redaction_policy="strict_rfc1918_internal",
            )
        ]
    )

    adapter = AuthorizedLabSensorAdapter(manifest)

    row = {
        "sensor_id": "sensor-alpha",
        "source_event_id": "lab_ev_001",
        "observed_at_utc": "2026-10-15T10:00:00Z",
        "src_entity_id": "10.0.1.10",
        "dst_entity_id": "10.0.2.20",
        "protocol": "tcp",
        "service_or_port": "8080",
    }

    record = adapter.adapt(row)
    assert record.source_mode == "authorized_lab_sensor"
    assert record.source_event_id == "lab_ev_001"
    prov = record.provenance
    assert prov.entity_namespace_id == "campus-edge-dmz"
    assert prov.clock_synchronized is True
    assert prov.max_clock_skew_seconds == 0.5
    assert prov.is_verified() is True


def test_authorized_lab_sensor_adapter_rejections():
    """AuthorizedLabSensorAdapter rejects unregistered sensors, duplicate event IDs, and masquerade attempts."""
    manifest = RegisteredSensorManifest(
        [
            SensorRegistration(
                sensor_id="sensor-alpha",
                entity_namespace_id="campus-edge-dmz",
            )
        ]
    )

    adapter = AuthorizedLabSensorAdapter(manifest)

    # 1. Unregistered sensor
    with pytest.raises(SourceRowValidationError) as exc:
        adapter.adapt(
            {
                "sensor_id": "unregistered-rogue-sensor",
                "source_event_id": "lab_ev_002",
                "observed_at_utc": "2026-10-15T10:00:00Z",
                "src_entity_id": "10.0.1.10",
                "dst_entity_id": "10.0.2.20",
            }
        )
    assert "unregistered or unallowlisted" in exc.value.reason.lower()

    # 2. Duplicate / replay source_event_id
    valid_row = {
        "sensor_id": "sensor-alpha",
        "source_event_id": "lab_ev_dup_check",
        "observed_at_utc": "2026-10-15T10:00:00Z",
        "src_entity_id": "10.0.1.10",
        "dst_entity_id": "10.0.2.20",
    }
    adapter.adapt(valid_row)  # First call succeeds

    with pytest.raises(SourceRowValidationError) as exc:
        adapter.adapt(valid_row)  # Second call with same source_event_id fails
    assert "duplicate/replay" in exc.value.reason.lower()

    # 3. Masquerade check: submitting scenario_replay to lab sensor adapter
    with pytest.raises(SourceRowValidationError) as exc:
        adapter.adapt(
            {
                "sensor_id": "sensor-alpha",
                "source_event_id": "lab_ev_masq",
                "source_mode": "scenario_replay",
                "observed_at_utc": "2026-10-15T10:00:00Z",
                "src_entity_id": "10.0.1.10",
                "dst_entity_id": "10.0.2.20",
            }
        )
    assert "cannot submit scenario_replay" in exc.value.reason.lower()
