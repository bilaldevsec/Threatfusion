"""Unit tests for the provenance-gated dual-window correlation engine (TF-008)."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from threatfusion.alerts.correlation_engine import (
    CorrelatableAlert,
    CorrelationSafetyError,
    EntityProvenanceContract,
    IncidentRecord,
    IncidentSqliteRepository,
    compute_alert_reduction_metrics,
    correlate_alert_candidates,
    derive_incident_id,
)
from threatfusion.schemas.alert_candidate import (
    ALERT_CANDIDATE_SCHEMA_VERSION,
    DECISION_POLICY_VERSION,
    DETECTOR_IDENTITY,
    DETECTOR_VERSION,
    AlertCandidate,
    derive_alert_candidate_id,
    derive_source_event_id,
)


def _make_candidate(
    index: int,
    *,
    score: float = 0.85,
    decision: str = "Attack",
    observed_at: datetime | None = None,
) -> AlertCandidate:
    source_id = derive_source_event_id(
        source_representation="unsw_nb15.argus.raw_49.transaction_bytes.v1",
        manifest_sha256="b" * 64,
        source_member_sha256=f"{index:064x}",
        row_number=index,
    )
    obs = (
        observed_at
        if observed_at is not None
        else datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC) + timedelta(seconds=index)
    )
    return AlertCandidate(
        schema_version=ALERT_CANDIDATE_SCHEMA_VERSION,
        alert_candidate_id=derive_alert_candidate_id(
            source_event_id=source_id,
            detector_identity=DETECTOR_IDENTITY,
            detector_version=DETECTOR_VERSION,
            model_identity="random_forest",
            model_version="network_random_forest_baseline_v1",
            model_artifact_sha256="a" * 64,
            decision_policy_version=DECISION_POLICY_VERSION,
        ),
        source_event_id=source_id,
        correlation_id=str(uuid4()),
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256="a" * 64,
        feature_contract_identity="network_behavior_v1",
        source_representation_identity="unsw_nb15.argus.raw_49.transaction_bytes.v1",
        observed_at=obs,
        created_at=obs + timedelta(seconds=1),
        uncalibrated_model_score=score,
        decision_threshold=0.5,
        decision_policy_version=DECISION_POLICY_VERSION,
        decision=decision,
        inference_status="completed",
        reason="inference_succeeded",
    )


def test_unsw_fail_closed_singleton_guarantee():
    """10 distinct UNSW-NB15 alerts produce 10 separate singleton incidents with zero false merges."""
    alerts = [_make_candidate(i) for i in range(1, 11)]

    # Provenance is unverified (missing namespace, clock_synchronized=False)
    unverified_prov = EntityProvenanceContract(
        entity_namespace_id=None,
        clock_synchronized=False,
        src_entity_id="192.168.1.100",
        dst_entity_id="192.168.1.1",
        protocol="tcp",
        service_or_port="80",
    )
    correlatable = [CorrelatableAlert(a, unverified_prov) for a in alerts]

    incidents, summary = correlate_alert_candidates(correlatable)

    assert len(incidents) == 10
    assert summary.total_alerts == 10
    assert summary.total_incidents == 10
    assert summary.reduction_ratio == 0.0
    assert summary.critical_retention_ratio == 1.0

    for inc in incidents:
        assert inc.correlation_mode == "singleton_unverified_provenance"
        assert inc.window_type == "none"
        assert inc.constituent_alert_count == 1
        assert inc.provenance_status == "unverified_provenance"
        assert inc.entity_namespace_id is None


def test_burst_window_correlation_30s():
    """20 authenticated sensor burst alerts within 30s collapse into 1 incident with 95% reduction."""
    base_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
    alerts = [
        _make_candidate(i, score=0.70 + (i * 0.01), observed_at=base_time + timedelta(seconds=i))
        for i in range(1, 21)
    ]

    prov = EntityProvenanceContract(
        entity_namespace_id="prod-sensor-karachi-01",
        clock_synchronized=True,
        src_entity_id="10.0.1.50",
        dst_entity_id="10.0.1.1",
        protocol="tcp",
        service_or_port="443",
    )
    correlatable = [CorrelatableAlert(a, prov) for a in alerts]

    incidents, summary = correlate_alert_candidates(correlatable)

    assert len(incidents) == 1
    assert summary.total_alerts == 20
    assert summary.total_incidents == 1
    assert summary.reduction_ratio == pytest.approx(0.95, rel=1e-3)
    assert summary.critical_retention_ratio == 1.0

    inc = incidents[0]
    assert inc.correlation_mode == "burst_correlated"
    assert inc.window_type == "burst_30s"
    assert inc.correlation_rule_id == "corr_burst_5tuple_30s_v1"
    assert inc.entity_namespace_id == "prod-sensor-karachi-01"
    assert inc.constituent_alert_count == 20
    # Preserves highest severity / score
    assert inc.max_probability_score == pytest.approx(0.90, rel=1e-3)
    assert inc.escalated_decision == "Attack"
    assert inc.provenance_status == "verified_entity_bearing"


def test_campaign_window_correlation_600s():
    """Multi-port alerts between same host pair within 480s correlate under campaign_600s; 601s starts new incident."""
    base_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
    cand1 = _make_candidate(1, score=0.80, observed_at=base_time)
    cand2 = _make_candidate(2, score=0.85, observed_at=base_time + timedelta(seconds=120))
    cand3 = _make_candidate(3, score=0.92, observed_at=base_time + timedelta(seconds=480))
    cand4 = _make_candidate(4, score=0.88, observed_at=base_time + timedelta(seconds=601))

    prov_base = {
        "entity_namespace_id": "corp-lan-hq",
        "clock_synchronized": True,
        "src_entity_id": "host-alpha",
        "dst_entity_id": "host-beta",
    }
    p1 = EntityProvenanceContract(**prov_base, protocol="tcp", service_or_port="22")
    p2 = EntityProvenanceContract(**prov_base, protocol="tcp", service_or_port="80")
    p3 = EntityProvenanceContract(**prov_base, protocol="tcp", service_or_port="443")
    p4 = EntityProvenanceContract(**prov_base, protocol="tcp", service_or_port="8080")

    correlatable = [
        CorrelatableAlert(cand1, p1),
        CorrelatableAlert(cand2, p2),
        CorrelatableAlert(cand3, p3),
        CorrelatableAlert(cand4, p4),
    ]

    incidents, summary = correlate_alert_candidates(correlatable)

    assert len(incidents) == 2
    assert summary.total_alerts == 4
    assert summary.total_incidents == 2
    assert summary.reduction_ratio == 0.5
    assert summary.critical_retention_ratio == 1.0

    # Incident 1: campaign grouping alerts 1, 2, 3 (span 480s <= 600s)
    inc1 = incidents[0]
    assert inc1.correlation_mode == "campaign_correlated"
    assert inc1.window_type == "campaign_600s"
    assert inc1.correlation_rule_id == "corr_campaign_entity_pair_600s_v1"
    assert inc1.constituent_alert_count == 3
    assert set(inc1.constituent_alert_ids) == {
        cand1.alert_candidate_id,
        cand2.alert_candidate_id,
        cand3.alert_candidate_id,
    }
    assert inc1.max_probability_score == pytest.approx(0.92, rel=1e-3)

    # Incident 2: Alert 4 at 601s starts new incident
    inc2 = incidents[1]
    assert inc2.constituent_alert_count == 1
    assert inc2.constituent_alert_ids == (cand4.alert_candidate_id,)


def test_cross_namespace_isolation():
    """Identical IPs/ports across different namespaces never correlate together."""
    base_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
    cand_a1 = _make_candidate(1, observed_at=base_time)
    cand_a2 = _make_candidate(2, observed_at=base_time + timedelta(seconds=5))
    cand_b1 = _make_candidate(3, observed_at=base_time + timedelta(seconds=2))
    cand_b2 = _make_candidate(4, observed_at=base_time + timedelta(seconds=7))

    p_a = EntityProvenanceContract(
        entity_namespace_id="datacenter-europe",
        clock_synchronized=True,
        src_entity_id="10.10.0.5",
        dst_entity_id="10.10.0.1",
        protocol="tcp",
        service_or_port="443",
    )
    p_b = EntityProvenanceContract(
        entity_namespace_id="datacenter-asia",
        clock_synchronized=True,
        src_entity_id="10.10.0.5",
        dst_entity_id="10.10.0.1",
        protocol="tcp",
        service_or_port="443",
    )

    correlatable = [
        CorrelatableAlert(cand_a1, p_a),
        CorrelatableAlert(cand_a2, p_a),
        CorrelatableAlert(cand_b1, p_b),
        CorrelatableAlert(cand_b2, p_b),
    ]

    incidents, summary = correlate_alert_candidates(correlatable)

    assert len(incidents) == 2
    assert summary.total_alerts == 4
    assert summary.total_incidents == 2
    assert summary.reduction_ratio == 0.5

    namespaces = {inc.entity_namespace_id for inc in incidents}
    assert namespaces == {"datacenter-europe", "datacenter-asia"}


def test_100_percent_critical_scenario_retention_gate():
    """CorrelationSafetyError is raised if any critical alert is missing or decision downgraded."""
    cand1 = _make_candidate(1, score=0.85, decision="Attack")
    cand2 = _make_candidate(2, score=0.90, decision="Attack")

    inc = IncidentRecord(
        schema_version="incident_record_v1",
        incident_id="incident_v1:test_inc",
        correlation_mode="burst_correlated",
        window_type="burst_30s",
        correlation_rule_id="corr_burst_5tuple_30s_v1",
        entity_namespace_id="test_ns",
        constituent_alert_ids=(cand1.alert_candidate_id,),  # cand2 is missing!
        constituent_alert_count=1,
        max_probability_score=0.85,
        escalated_decision="Attack",
        earliest_observed_at=cand1.observed_at.isoformat(),
        latest_observed_at=cand1.observed_at.isoformat(),
        provenance_status="verified_entity_bearing",
        created_at=datetime.now(UTC).isoformat(),
    )

    with pytest.raises(CorrelationSafetyError, match="critical_alert_dropped"):
        compute_alert_reduction_metrics([cand1, cand2], [inc])


def test_sqlite_incident_repository_crud(tmp_path):
    """Transactional SQLite repository verifies schema, atomic insertion, and lookups."""
    db_path = tmp_path / "incidents.sqlite3"
    repo = IncidentSqliteRepository(db_path)

    cand1 = _make_candidate(1)
    cand2 = _make_candidate(2)
    inc_id = derive_incident_id(
        "corr_burst_5tuple_30s_v1",
        (cand1.alert_candidate_id, cand2.alert_candidate_id),
    )

    inc = IncidentRecord(
        schema_version="incident_record_v1",
        incident_id=inc_id,
        correlation_mode="burst_correlated",
        window_type="burst_30s",
        correlation_rule_id="corr_burst_5tuple_30s_v1",
        entity_namespace_id="sensor-prod-1",
        constituent_alert_ids=(cand1.alert_candidate_id, cand2.alert_candidate_id),
        constituent_alert_count=2,
        max_probability_score=0.88,
        escalated_decision="Attack",
        earliest_observed_at=cand1.observed_at.isoformat(),
        latest_observed_at=cand2.observed_at.isoformat(),
        provenance_status="verified_entity_bearing",
        created_at=datetime.now(UTC).isoformat(),
    )

    repo.insert(inc)
    # Idempotent retry
    repo.insert(inc)

    assert repo.count_incidents() == 1
    loaded = repo.get_incident(inc_id)
    assert loaded is not None
    assert loaded.incident_id == inc_id
    assert loaded.constituent_alert_count == 2
    assert set(loaded.constituent_alert_ids) == {
        cand1.alert_candidate_id,
        cand2.alert_candidate_id,
    }

    # Lookup by constituent alert candidate ID
    by_alert1 = repo.get_incident_for_alert(cand1.alert_candidate_id)
    assert by_alert1 is not None
    assert by_alert1.incident_id == inc_id

    by_alert2 = repo.get_incident_for_alert(cand2.alert_candidate_id)
    assert by_alert2 is not None
    assert by_alert2.incident_id == inc_id

    # Non-existent alert
    assert repo.get_incident_for_alert("alert_candidate_v1:nonexistent") is None

    # Listing
    listed = repo.list_incidents(limit=10)
    assert len(listed) == 1
    assert listed[0].incident_id == inc_id
