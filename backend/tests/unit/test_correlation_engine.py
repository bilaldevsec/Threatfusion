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


def test_out_of_order_and_late_arrival_determinism():
    """Shuffled and late-arriving alerts produce identical incident groupings as chronological arrival."""
    base_t = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
    cand1 = _make_candidate(1, score=0.81, observed_at=base_t)
    cand2 = _make_candidate(2, score=0.82, observed_at=base_t + timedelta(seconds=10))
    cand3 = _make_candidate(3, score=0.83, observed_at=base_t + timedelta(seconds=20))
    cand4 = _make_candidate(4, score=0.84, observed_at=base_t + timedelta(seconds=45))

    prov = EntityProvenanceContract(
        entity_namespace_id="sensor-alpha",
        clock_synchronized=True,
        src_entity_id="10.1.1.1",
        dst_entity_id="10.1.1.2",
        protocol="tcp",
        service_or_port="443",
    )

    # In-order run: cand1, cand2, cand3 (burst), cand4 (separate)
    in_order = [CorrelatableAlert(c, prov) for c in [cand1, cand2, cand3, cand4]]
    inc_in_order, _ = correlate_alert_candidates(in_order)

    # Out-of-order run: cand4, cand2, cand1, cand3
    out_of_order = [CorrelatableAlert(c, prov) for c in [cand4, cand2, cand1, cand3]]
    inc_out_of_order, _ = correlate_alert_candidates(out_of_order)

    assert len(inc_in_order) == len(inc_out_of_order)
    for inc_a, inc_b in zip(inc_in_order, inc_out_of_order, strict=True):
        assert inc_a.incident_id == inc_b.incident_id
        assert inc_a.constituent_alert_ids == inc_b.constituent_alert_ids
        assert inc_a.correlation_mode == inc_b.correlation_mode


def test_exact_boundary_times_burst_and_campaign():
    """Exact boundary values: Δt=30.0s included in burst; Δt=30.001s excluded. Δt=600.0s included in campaign; Δt=600.001s excluded."""
    base_t = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)

    # Burst boundary check: 30.0s vs 30.001s
    cand_b0 = _make_candidate(10, score=0.8, observed_at=base_t)
    cand_b30 = _make_candidate(11, score=0.8, observed_at=base_t + timedelta(seconds=30.0))
    prov_burst = EntityProvenanceContract(
        entity_namespace_id="sensor-boundary",
        clock_synchronized=True,
        src_entity_id="192.168.1.1",
        dst_entity_id="192.168.1.2",
        protocol="tcp",
        service_or_port="80",
    )
    inc_burst_30, _ = correlate_alert_candidates(
        [CorrelatableAlert(cand_b0, prov_burst), CorrelatableAlert(cand_b30, prov_burst)]
    )
    assert len(inc_burst_30) == 1
    assert inc_burst_30[0].correlation_mode == "burst_correlated"
    assert inc_burst_30[0].constituent_alert_count == 2

    # Exceeding burst boundary by 1ms (30.001s): must NOT form a burst incident
    # Different destination port so they fall through to campaign or singleton
    prov_b_port1 = EntityProvenanceContract(
        entity_namespace_id="sensor-boundary",
        clock_synchronized=True,
        src_entity_id="192.168.1.10",
        dst_entity_id="192.168.1.20",
        protocol="tcp",
        service_or_port="80",
    )
    prov_b_port2 = EntityProvenanceContract(
        entity_namespace_id="sensor-boundary",
        clock_synchronized=True,
        src_entity_id="192.168.1.10",
        dst_entity_id="192.168.1.20",
        protocol="tcp",
        service_or_port="80",
    )
    cand_ex0 = _make_candidate(13, score=0.8, observed_at=base_t)
    cand_ex30 = _make_candidate(14, score=0.8, observed_at=base_t + timedelta(seconds=30.001))
    inc_ex_30, _ = correlate_alert_candidates(
        [CorrelatableAlert(cand_ex0, prov_b_port1), CorrelatableAlert(cand_ex30, prov_b_port2)]
    )
    # Because dt > 30s, burst pass does not group them.
    # But because they share host pair and dt <= 600s, they collapse into campaign_600s!
    assert len(inc_ex_30) == 1
    assert inc_ex_30[0].correlation_mode == "campaign_correlated"
    assert inc_ex_30[0].window_type == "campaign_600s"

    # Campaign boundary check: 600.0s vs 600.001s
    cand_c0 = _make_candidate(15, score=0.8, observed_at=base_t)
    cand_c600 = _make_candidate(16, score=0.8, observed_at=base_t + timedelta(seconds=600.0))
    prov_c1 = EntityProvenanceContract(
        entity_namespace_id="sensor-boundary-c",
        clock_synchronized=True,
        src_entity_id="10.0.0.1",
        dst_entity_id="10.0.0.2",
        protocol="tcp",
        service_or_port="80",
    )
    prov_c2 = EntityProvenanceContract(
        entity_namespace_id="sensor-boundary-c",
        clock_synchronized=True,
        src_entity_id="10.0.0.1",
        dst_entity_id="10.0.0.2",
        protocol="tcp",
        service_or_port="443",
    )
    inc_c_600, _ = correlate_alert_candidates(
        [CorrelatableAlert(cand_c0, prov_c1), CorrelatableAlert(cand_c600, prov_c2)]
    )
    assert len(inc_c_600) == 1
    assert inc_c_600[0].correlation_mode == "campaign_correlated"

    # Exceeding campaign boundary by 1ms (600.001s): MUST split into 2 singleton incidents
    cand_c600_plus = _make_candidate(17, score=0.8, observed_at=base_t + timedelta(seconds=600.001))
    inc_c_split, _ = correlate_alert_candidates(
        [CorrelatableAlert(cand_c0, prov_c1), CorrelatableAlert(cand_c600_plus, prov_c2)]
    )
    assert len(inc_c_split) == 2
    assert inc_c_split[0].correlation_mode == "singleton_verified_provenance"
    assert inc_c_split[1].correlation_mode == "singleton_verified_provenance"


def test_same_timestamp_unrelated_entities_never_merge():
    """Two alerts occurring at the exact same millisecond with different endpoints never merge."""
    same_time = datetime(2026, 10, 15, 12, 0, 0, 123456, tzinfo=UTC)
    cand1 = _make_candidate(20, score=0.85, observed_at=same_time)
    cand2 = _make_candidate(21, score=0.88, observed_at=same_time)

    prov1 = EntityProvenanceContract(
        entity_namespace_id="sensor-shared",
        clock_synchronized=True,
        src_entity_id="10.0.0.1",
        dst_entity_id="10.0.0.2",
        protocol="tcp",
        service_or_port="80",
    )
    prov2 = EntityProvenanceContract(
        entity_namespace_id="sensor-shared",
        clock_synchronized=True,
        src_entity_id="192.168.100.5",
        dst_entity_id="192.168.100.6",
        protocol="tcp",
        service_or_port="80",
    )

    incidents, summary = correlate_alert_candidates(
        [CorrelatableAlert(cand1, prov1), CorrelatableAlert(cand2, prov2)]
    )
    assert len(incidents) == 2
    assert summary.reduction_ratio == 0.0
    assert incidents[0].correlation_mode == "singleton_verified_provenance"
    assert incidents[1].correlation_mode == "singleton_verified_provenance"


def test_address_reuse_and_nat_fails_closed():
    """Alerts bearing address_reuse_or_nat=True fail closed to singleton_unverified_provenance."""
    cand = _make_candidate(30, score=0.90)
    prov_nat = EntityProvenanceContract(
        entity_namespace_id="sensor-nat",
        clock_synchronized=True,
        src_entity_id="10.0.0.1",
        dst_entity_id="10.0.0.2",
        protocol="tcp",
        service_or_port="80",
        address_reuse_or_nat=True,  # Unmapped NAT
    )

    incidents, _ = correlate_alert_candidates([CorrelatableAlert(cand, prov_nat)])
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.correlation_mode == "singleton_unverified_provenance"
    assert inc.provenance_status == "nat_address_reuse_ambiguous"
    assert inc.member_justifications[cand.alert_candidate_id].provenance_summary == (
        "nat_address_reuse_ambiguous"
    )


def test_entity_validity_interval_enforcement():
    """Alerts with timestamps outside [validity_start_utc, validity_end_utc] fail closed."""
    v_start = "2026-10-15T12:00:00+00:00"
    v_end = "2026-10-15T13:00:00+00:00"

    # Within interval -> verified
    t_inside = datetime(2026, 10, 15, 12, 30, 0, tzinfo=UTC)
    cand_in = _make_candidate(40, observed_at=t_inside)
    prov_in = EntityProvenanceContract(
        entity_namespace_id="sensor-validity",
        clock_synchronized=True,
        src_entity_id="10.0.0.1",
        dst_entity_id="10.0.0.2",
        protocol="tcp",
        service_or_port="80",
        observed_at_utc=t_inside.isoformat(),
        validity_start_utc=v_start,
        validity_end_utc=v_end,
    )
    inc_in, _ = correlate_alert_candidates([CorrelatableAlert(cand_in, prov_in)])
    assert inc_in[0].provenance_status == "verified_entity_bearing"

    # Outside interval (too early) -> rejected
    t_early = datetime(2026, 10, 15, 11, 59, 59, tzinfo=UTC)
    cand_early = _make_candidate(41, observed_at=t_early)
    prov_early = EntityProvenanceContract(
        entity_namespace_id="sensor-validity",
        clock_synchronized=True,
        src_entity_id="10.0.0.1",
        dst_entity_id="10.0.0.2",
        protocol="tcp",
        service_or_port="80",
        observed_at_utc=t_early.isoformat(),
        validity_start_utc=v_start,
        validity_end_utc=v_end,
    )
    inc_early, _ = correlate_alert_candidates([CorrelatableAlert(cand_early, prov_early)])
    assert inc_early[0].provenance_status == "outside_entity_validity_interval"


def test_clock_skew_tolerance_boundary():
    """max_clock_skew_seconds <= 5.0 is tolerated; > 5.0 fails closed to singleton."""
    cand = _make_candidate(50)

    # 5.0s skew: tolerated
    prov_5s = EntityProvenanceContract(
        entity_namespace_id="sensor-skew",
        clock_synchronized=True,
        src_entity_id="10.0.0.1",
        dst_entity_id="10.0.0.2",
        protocol="tcp",
        service_or_port="80",
        max_clock_skew_seconds=5.0,
    )
    inc_5s, _ = correlate_alert_candidates([CorrelatableAlert(cand, prov_5s)])
    assert inc_5s[0].provenance_status == "verified_entity_bearing"

    # 5.1s skew: rejected
    prov_51s = EntityProvenanceContract(
        entity_namespace_id="sensor-skew",
        clock_synchronized=True,
        src_entity_id="10.0.0.1",
        dst_entity_id="10.0.0.2",
        protocol="tcp",
        service_or_port="80",
        max_clock_skew_seconds=5.1,
    )
    inc_51s, _ = correlate_alert_candidates([CorrelatableAlert(cand, prov_51s)])
    assert inc_51s[0].provenance_status == "clock_skew_exceeded"


def test_candidate_deduplication_vs_grouping():
    """Repeated submissions of the exact same candidate collapse cleanly without inflating counts."""
    base_t = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
    cand1 = _make_candidate(60, observed_at=base_t)
    cand2 = _make_candidate(61, observed_at=base_t + timedelta(seconds=5))

    prov = EntityProvenanceContract(
        entity_namespace_id="sensor-dedup",
        clock_synchronized=True,
        src_entity_id="10.0.0.1",
        dst_entity_id="10.0.0.2",
        protocol="tcp",
        service_or_port="80",
    )

    # 5 copies of cand1 and 5 copies of cand2 (total 10 items)
    input_alerts = [CorrelatableAlert(cand1, prov)] * 5 + [CorrelatableAlert(cand2, prov)] * 5

    incidents, summary = correlate_alert_candidates(input_alerts)
    # Deduplication collapses to 2 unique alerts, which correlate into 1 burst incident
    assert summary.total_alerts == 2
    assert summary.total_incidents == 1
    assert len(incidents) == 1
    assert incidents[0].constituent_alert_count == 2
    assert set(incidents[0].constituent_alert_ids) == {
        cand1.alert_candidate_id,
        cand2.alert_candidate_id,
    }
