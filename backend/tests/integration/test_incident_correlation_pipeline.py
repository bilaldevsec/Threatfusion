"""Integration tests for the incident correlation pipeline and dashboard surfacing (TF-008)."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from threatfusion.alerts.correlation_engine import (
    CorrelatableAlert,
    EntityProvenanceContract,
    IncidentSqliteRepository,
    correlate_alert_candidates,
)
from threatfusion.api.analyst_dashboard import (
    DashboardAlertQueue,
    DashboardAlertSummary,
    DashboardSnapshot,
    _parse_detail,
    render_dashboard_html,
)
from threatfusion.api.analyst_view_model import AnalystAlertViewModel
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.analyst_state_repository import (
    AnalystAuthorizationRegistry,
    AnalystStateRepository,
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
from threatfusion.schemas.analyst_state import AnalystRegistryEntry


def _make_candidate(
    index: int,
    *,
    score: float = 0.88,
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
        else datetime(2026, 10, 15, 14, 0, 0, tzinfo=UTC) + timedelta(seconds=index)
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


def test_incident_correlation_pipeline_and_view_model(tmp_path: Path):
    """Correlate authenticated burst alerts, persist incidents, and surface in AnalystAlertViewModel."""
    alerts_db = tmp_path / "alerts.sqlite3"
    states_db = tmp_path / "states.sqlite3"
    incidents_db = tmp_path / "incidents.sqlite3"

    alert_repo = AlertCandidateRepository(alerts_db)
    registry = AnalystAuthorizationRegistry((AnalystRegistryEntry("analyst_1", "analyst"),))
    state_repo = AnalystStateRepository(states_db, alert_repo, registry)
    incident_repo = IncidentSqliteRepository(incidents_db)

    # Ingest 3 burst alerts
    base_t = datetime(2026, 10, 15, 14, 30, 0, tzinfo=UTC)
    cands = [
        _make_candidate(i, score=0.80 + (i * 0.05), observed_at=base_t + timedelta(seconds=i * 2))
        for i in range(1, 4)
    ]
    for c in cands:
        alert_repo.insert(c)

    prov = EntityProvenanceContract(
        entity_namespace_id="edge-router-01",
        clock_synchronized=True,
        src_entity_id="192.168.10.55",
        dst_entity_id="10.0.0.1",
        protocol="tcp",
        service_or_port="80",
    )
    correlatable = [CorrelatableAlert(c, prov) for c in cands]

    incidents, summary = correlate_alert_candidates(correlatable)
    assert len(incidents) == 1
    assert summary.total_alerts == 3
    assert summary.total_incidents == 1
    assert summary.reduction_ratio == pytest.approx(0.6667, rel=1e-3)
    assert summary.critical_retention_ratio == 1.0

    incident_repo.insert(incidents[0])

    # Wire view model with incident_repository
    cap = registry.issue_for_trusted_actor("analyst_1")
    view_model = AnalystAlertViewModel(state_repo, incident_repository=incident_repo)

    # Check alert detail for constituent alert
    detail = view_model.get_alert(cap, cands[0].alert_candidate_id)
    assert detail is not None
    assert "incident_correlation" in detail
    corr = detail["incident_correlation"]
    assert corr["incident_id"] == incidents[0].incident_id
    assert corr["correlation_mode"] == "burst_correlated"
    assert corr["window_type"] == "burst_30s"
    assert corr["constituent_alert_count"] == 3
    assert corr["provenance_status"] == "verified_entity_bearing"


def test_dashboard_surfacing_unsw_and_correlated_incidents(tmp_path: Path):
    """Verify that both raw UNSW singleton alerts and correlated alerts render cleanly in HTML dashboard."""
    # 1. Correlated burst alert detail
    correlated_payload = {
        "detection_evidence": {
            "alert_candidate_id": "alert_candidate_v1:" + "a" * 64,
            "source_event_id": "unsw_registered_source_event_v1:" + "1" * 64,
            "observed_at": "2026-10-15T14:30:00+00:00",
            "created_at": "2026-10-15T14:30:01+00:00",
            "source_representation_identity": "unsw_nb15.argus.raw_49.transaction_bytes.v1",
            "feature_contract_identity": "network_behavior_v1",
            "model_identity": "random_forest",
            "model_version": "network_random_forest_baseline_v1",
            "model_artifact_sha256": "f" * 64,
            "uncalibrated_model_score": 0.95,
            "decision_threshold": 0.5,
            "decision_policy_version": "attack_probability_gte_0.5_v1",
            "decision": "Attack",
        },
        "analyst_state": {
            "state": "new",
            "version": 0,
            "updated_at": None,
            "updated_by": None,
            "last_transition_id": None,
        },
        "analyst_history": [],
        "explanation": {
            "status": "factual_inference_evidence_only",
            "summary": "Frozen Random Forest scored uncalibrated probability 0.9500.",
        },
        "incident_correlation": {
            "incident_id": "incident_v1:" + "c" * 64,
            "correlation_mode": "burst_correlated",
            "window_type": "burst_30s",
            "correlation_rule_id": "corr_burst_5tuple_30s_v1",
            "constituent_alert_count": 5,
            "provenance_status": "verified_entity_bearing",
            "explanation": "Correlated within 30s burst window.",
        },
    }

    parsed_detail = _parse_detail(correlated_payload)
    assert parsed_detail.incident_correlation is not None
    assert parsed_detail.incident_correlation.correlation_mode == "burst_correlated"
    assert parsed_detail.incident_correlation.constituent_alert_count == 5

    summary_item = DashboardAlertSummary(
        alert_candidate_id="alert_candidate_v1:" + "a" * 64,
        source_event_id="unsw_registered_source_event_v1:" + "1" * 64,
        observed_at="2026-10-15T14:30:00+00:00",
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        uncalibrated_model_score=0.95,
        decision_threshold=0.5,
        decision="Attack",
        state="new",
        version=0,
    )
    queue = DashboardAlertQueue(items=(summary_item,), total_loaded=1, limit=50, offset=0)
    snapshot = DashboardSnapshot(queue=queue, selected=parsed_detail, status="active")

    html_out = render_dashboard_html(snapshot, actor_role="analyst")

    # Assert that Incident Correlation & Provenance section is rendered
    assert "Incident Correlation &amp; Provenance" in html_out
    assert "burst_correlated" in html_out
    assert "burst_30s" in html_out
    assert "corr_burst_5tuple_30s_v1" in html_out
    assert "verified_entity_bearing" in html_out
    assert "Constituent Alerts:</b> 5" in html_out
    assert "Correlated within 30s burst window." in html_out

    # 2. Raw UNSW default singleton rendering
    unsw_payload = {
        "detection_evidence": {
            "alert_candidate_id": "alert_candidate_v1:" + "b" * 64,
            "source_event_id": "unsw_registered_source_event_v1:" + "2" * 64,
            "observed_at": "2026-10-15T14:31:00+00:00",
            "created_at": "2026-10-15T14:31:01+00:00",
            "source_representation_identity": "unsw_nb15.argus.raw_49.transaction_bytes.v1",
            "feature_contract_identity": "network_behavior_v1",
            "model_identity": "random_forest",
            "model_version": "network_random_forest_baseline_v1",
            "model_artifact_sha256": "f" * 64,
            "uncalibrated_model_score": 0.82,
            "decision_threshold": 0.5,
            "decision_policy_version": "attack_probability_gte_0.5_v1",
            "decision": "Attack",
        },
        "analyst_state": {
            "state": "new",
            "version": 0,
            "updated_at": None,
            "updated_by": None,
            "last_transition_id": None,
        },
        "analyst_history": [],
    }
    unsw_parsed = _parse_detail(unsw_payload)
    assert unsw_parsed.incident_correlation is not None
    assert unsw_parsed.incident_correlation.correlation_mode == "singleton_unverified_provenance"
    assert unsw_parsed.incident_correlation.provenance_status == "unverified_provenance"

    snapshot_unsw = DashboardSnapshot(queue=queue, selected=unsw_parsed, status="active")
    html_unsw = render_dashboard_html(snapshot_unsw, actor_role="viewer")

    assert "Incident Correlation &amp; Provenance" in html_unsw
    assert "singleton_unverified_provenance" in html_unsw
    assert "unverified_provenance" in html_unsw
    assert "UNSW-NB15 raw telemetry lacks authenticated entity endpoints" in html_unsw


def test_incident_grouping_correction_and_replay_safety(tmp_path: Path):
    """Audited grouping correction splits an alert into a new incident with idempotent UUIDv4 replay safety."""
    from threatfusion.alerts.correlation_engine import CorrelationSafetyError

    incidents_db = tmp_path / "incidents.sqlite3"
    incident_repo = IncidentSqliteRepository(incidents_db)

    base_t = datetime(2026, 10, 15, 14, 30, 0, tzinfo=UTC)
    cands = [
        _make_candidate(i, score=0.80 + (i * 0.05), observed_at=base_t + timedelta(seconds=i * 2))
        for i in range(1, 4)
    ]
    prov = EntityProvenanceContract(
        entity_namespace_id="sensor-split-test",
        clock_synchronized=True,
        src_entity_id="10.0.0.1",
        dst_entity_id="10.0.0.2",
        protocol="tcp",
        service_or_port="80",
    )
    correlatable = [CorrelatableAlert(c, prov) for c in cands]
    incidents, _ = correlate_alert_candidates(correlatable)
    assert len(incidents) == 1
    assert incidents[0].constituent_alert_count == 3
    orig_incident_id = incidents[0].incident_id

    incident_repo.insert(incidents[0])

    # Analyst performs manual grouping correction on candidate 2
    cand2_id = cands[1].alert_candidate_id
    req_id = str(uuid4())

    split_inc = incident_repo.correct_incident_grouping(
        cand2_id,
        actor_id="analyst_lead_karachi",
        reason="Candidate 2 is a separate scanner probe; manual split into standalone incident",
        correction_request_id=req_id,
    )

    assert split_inc is not None
    assert split_inc.incident_id != orig_incident_id
    assert split_inc.constituent_alert_count == 1
    assert split_inc.constituent_alert_ids == (cand2_id,)
    assert split_inc.correlation_mode == "manual_correction_split"
    assert split_inc.provenance_status == "manual_corrected"

    # Original incident constituent count decreased to 2
    orig_reloaded = incident_repo.get_incident(orig_incident_id)
    assert orig_reloaded is not None
    assert orig_reloaded.constituent_alert_count == 2
    assert cand2_id not in orig_reloaded.constituent_alert_ids
    assert cands[0].alert_candidate_id in orig_reloaded.constituent_alert_ids
    assert cands[2].alert_candidate_id in orig_reloaded.constituent_alert_ids

    # Idempotent replay of exact same correction_request_id
    replay_inc = incident_repo.correct_incident_grouping(
        cand2_id,
        actor_id="analyst_lead_karachi",
        reason="Candidate 2 is a separate scanner probe; manual split into standalone incident",
        correction_request_id=req_id,
    )
    assert replay_inc.incident_id == split_inc.incident_id

    # Conflict check: same correction_request_id with different actor
    with pytest.raises(CorrelationSafetyError, match="correction_request_conflict"):
        incident_repo.correct_incident_grouping(
            cand2_id,
            actor_id="rogue_actor",
            reason="conflicting correction",
            correction_request_id=req_id,
        )

    # Audit log verification
    corrections = incident_repo.get_grouping_corrections(cand2_id)
    assert len(corrections) == 1
    assert corrections[0]["correction_request_id"] == req_id
    assert corrections[0]["alert_candidate_id"] == cand2_id
    assert corrections[0]["actor_id"] == "analyst_lead_karachi"
    assert corrections[0]["target_incident_id"] == split_inc.incident_id
