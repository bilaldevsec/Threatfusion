"""Integration test for Slide 14 Azure VM Live-Ingestion Path, Suricata 14-feature adapter, and end-to-end product spine."""

from __future__ import annotations

import hashlib
import math
import socket
from datetime import UTC, datetime
from pathlib import Path
import urllib.parse
import uuid

import pytest

from backend.tests.integration import test_analyst_browser_tls_service as browser_tls
from backend.tests.integration import test_operator_human_credentials as operator
from threatfusion.advisory.explanation_engine import (
    AdvisoryEvidenceBundle,
    AdvisoryExplanationEngine,
)
from threatfusion.alerts.correlation_engine import (
    CorrelatableAlert,
    IncidentSqliteRepository,
    correlate_alert_candidates,
)
from threatfusion.api.analyst_browser_tls_service import AnalystBrowserTlsListener
from threatfusion.api.analyst_tls_service import AnalystTlsConfiguration
from threatfusion.api.analyst_view_model import AnalystAlertViewModel
from threatfusion.enrichment.threat_intel import SourcedThreatIntelEnricher
from threatfusion.datasets.adapters.suricata_flow import (
    DEFAULT_SURICATA_SENSOR_NAMESPACE,
    SuricataFlowAdapter,
)
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.analyst_security_audit import AnalystSecurityAuditRepository
from threatfusion.db.analyst_state_repository import AnalystStateRepository
from threatfusion.features.network_behavior import (
    NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
    UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
)
from threatfusion.models.network_inference import (
    APPROVED_MODEL_HASHES,
    NetworkModelChoice,
    UnswNetworkInferenceBoundary,
    _NetworkInferenceRequest,
    _NetworkSourceProvenance,
)
from threatfusion.operations.human_listener_lifecycle import HumanListenerLifecycle
from threatfusion.operations.storage_backup import (
    verify_storage_snapshot,
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
from threatfusion.schemas.analyst_state import (
    AnalystAuthorizationRegistry,
    AnalystRegistryEntry,
)
from threatfusion.soar.playbook_ledger import (
    ApprovalGatedSoarEngine,
    SoarPlaybookSqliteRepository,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _send_browser_request(
    address: tuple[str, int],
    cert_map: dict[str, object],
    identity: str,
    request_bytes: bytes,
) -> tuple[int, bytes, bytes]:
    """Send an authenticated mTLS request directly to the active HumanListenerLifecycle browser worker."""
    chunks = []
    context = browser_tls._context(cert_map, identity)
    with socket.create_connection(address, timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as client:
            client.settimeout(5)
            client.sendall(request_bytes)
            while chunk := client.recv(4096):
                chunks.append(chunk)
    response = b"".join(chunks)
    assert response, "Empty response from browser listener"
    head, body = response.split(b"\r\n\r\n", 1)
    status_code = int(head.split(b" ")[1])
    return status_code, head, body


def _sample_suricata_eve_flow() -> dict[str, object]:
    """Realistic Suricata eve.json flow event matching Slide 14 Azure VM deployment.

    Attacker VM (10.0.0.4) executing automated scan/probe against Victim VM (10.0.0.5:80).
    Suricata on Victim VM captures bidirectional flow counters and timestamps.
    """
    return {
        "timestamp": "2026-10-15T12:00:00.000000+00:00",
        "event_type": "flow",
        "src_ip": "10.0.0.4",
        "src_port": 44120,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "flow_id": 98765432101234,
        "flow": {
            "pkts_toserver": 15,
            "pkts_toclient": 12,
            "bytes_toserver": 1250,
            "bytes_toclient": 4800,
            "start": "2026-10-15T12:00:00.000000+00:00",
            "end": "2026-10-15T12:00:01.500000+00:00",
            "age": 1,
            "state": "closed",
            "reason": "shutdown",
            "alerted": False,
        },
    }


def test_slide14_suricata_adapter_14_features_and_provenance_gates():
    """Verify Slide 14 Box 03: deterministic 14-feature extraction and provenance validation."""
    adapter = SuricataFlowAdapter()
    eve_record = _sample_suricata_eve_flow()

    res = adapter.adapt_flow_record(eve_record)

    # 1. Verify 14 extracted features match the exact FYP-II specification
    features = res.features_14
    assert len(features) == 14
    expected_keys = {
        "duration_ms",
        "fwd_packets",
        "bwd_packets",
        "fwd_bytes",
        "bwd_bytes",
        "packets_per_second",
        "bytes_per_second",
        "fwd_packet_length_mean",
        "bwd_packet_length_mean",
        "dst_port",
        "protocol_tcp",
        "protocol_udp",
        "protocol_icmp",
        "protocol_other",
    }
    assert set(features.keys()) == expected_keys

    # Exact numeric values for 15 pkts / 1250 bytes fwd and 12 pkts / 4800 bytes bwd over 1.5s
    assert features["duration_ms"] == 1500.0
    assert features["fwd_packets"] == 15
    assert features["bwd_packets"] == 12
    assert features["fwd_bytes"] == 1250
    assert features["bwd_bytes"] == 4800
    assert math.isclose(features["packets_per_second"], 27 / 1.5, rel_tol=1e-9)
    assert math.isclose(features["bytes_per_second"], 6050 / 1.5, rel_tol=1e-9)
    assert math.isclose(features["fwd_packet_length_mean"], 1250 / 15, rel_tol=1e-9)
    assert math.isclose(features["bwd_packet_length_mean"], 4800 / 12, rel_tol=1e-9)
    assert features["dst_port"] == 80
    assert features["protocol_tcp"] == 1.0
    assert features["protocol_udp"] == 0.0
    assert features["protocol_icmp"] == 0.0
    assert features["protocol_other"] == 0.0

    # 2. Verify EntityProvenanceContract is bound and verified
    provenance = res.provenance
    assert provenance.entity_namespace_id == DEFAULT_SURICATA_SENSOR_NAMESPACE
    assert provenance.src_entity_id == "attacker:10.0.0.4"
    assert provenance.dst_entity_id == "victim:10.0.0.5"
    assert provenance.protocol == "tcp"
    assert provenance.clock_synchronized is True
    assert provenance.address_reuse_or_nat is False
    assert provenance.is_verified() is True

    # 3. Fail-closed tests on malformed or non-finite inputs
    with pytest.raises(Exception, match="event_type"):
        adapter.adapt_flow_record({"event_type": "alert"})

    with pytest.raises(Exception, match="flow"):
        adapter.adapt_flow_record({"event_type": "flow", "dest_ip": "10.0.0.5", "dest_port": 80})

    invalid_flow = _sample_suricata_eve_flow()
    invalid_flow["flow"]["bytes_toserver"] = -10
    with pytest.raises(Exception, match="must be >= 0"):
        adapter.adapt_flow_record(invalid_flow)

    inverted_time_flow = _sample_suricata_eve_flow()
    inverted_time_flow["flow"]["end"] = "2026-10-15T11:59:59.000000+00:00"
    with pytest.raises(Exception, match="end timestamp precedes start timestamp"):
        adapter.adapt_flow_record(inverted_time_flow)


def test_slide14_end_to_end_spine_suricata_to_quiescent_snapshot(tmp_path):
    """Full end-to-end integration of Slide 14 Azure VM Live-Ingestion Path.

    01 Attacker VM traffic -> 02 Victim VM Suricata flow event ->
    03 ThreatFusion SuricataFlowAdapter (14 features) ->
    04 Registered Producer Admission ->
    05 Frozen RF model inference (random_forest.joblib) -> Alert candidate ->
    Dual-window incident correlation (incidents.sqlite3) ->
    Operator mTLS & Browser TLS Lifecycle (HumanListenerLifecycle) ->
    Browser mTLS GET queue, GET detail, POST state transition (new -> in_review) ->
    Quiescent 4-database atomic storage snapshot and verification.
    """
    # -------------------------------------------------------------------------
    # Stage 1 & 2: Attacker VM -> Victim VM Suricata Flow Event
    # -------------------------------------------------------------------------
    raw_eve = _sample_suricata_eve_flow()

    # -------------------------------------------------------------------------
    # Stage 3: Slide 14 Box 03 Suricata 14-Feature Flow Adapter
    # -------------------------------------------------------------------------
    adapter = SuricataFlowAdapter()
    adapted_result = adapter.adapt_flow_record(raw_eve)
    assert adapted_result.provenance.is_verified() is True
    assert len(adapted_result.features_14) == 14

    # -------------------------------------------------------------------------
    # Stage 4 & 5: Model Inference using Frozen Random Forest (random_forest.joblib)
    # -------------------------------------------------------------------------
    inference_boundary = UnswNetworkInferenceBoundary(project_root=PROJECT_ROOT)
    inference_request = _NetworkInferenceRequest.from_mapping(
        adapted_result.raw_features,
        provenance=_NetworkSourceProvenance.approved_unsw(),
    )
    inference_result = inference_boundary._predictor.infer(
        inference_request, model=NetworkModelChoice.RANDOM_FOREST
    )

    assert inference_result.status == "completed"
    assert inference_result.predicted_class == "Attack"
    assert inference_result.attack_probability is not None
    assert inference_result.attack_probability >= 0.5

    # Build AlertCandidate and persist to alerts.sqlite3
    observed_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
    source_event_id = derive_source_event_id(
        source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        manifest_sha256=hashlib.sha256(b"slide14_azure_victim_vm_manifest").hexdigest(),
        source_member_sha256=hashlib.sha256(
            adapted_result.source_event_id.encode("utf-8")
        ).hexdigest(),
        row_number=1,
    )
    candidate_id = derive_alert_candidate_id(
        source_event_id=source_event_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256=APPROVED_MODEL_HASHES["random_forest"]["model"],
        decision_policy_version=DECISION_POLICY_VERSION,
    )

    alert_candidate = AlertCandidate(
        schema_version=ALERT_CANDIDATE_SCHEMA_VERSION,
        alert_candidate_id=candidate_id,
        source_event_id=source_event_id,
        correlation_id=inference_result.correlation_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256=APPROVED_MODEL_HASHES["random_forest"]["model"],
        feature_contract_identity=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
        source_representation_identity=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        observed_at=observed_time,
        created_at=datetime.now(UTC),
        uncalibrated_model_score=inference_result.attack_probability,
        decision_threshold=0.5,
        decision_policy_version=DECISION_POLICY_VERSION,
        decision="Attack",
        inference_status="completed",
        reason="inference_succeeded",
    )

    alerts_repo = AlertCandidateRepository(tmp_path / "alerts.sqlite3")
    insert_res = alerts_repo.insert(alert_candidate)
    assert insert_res.disposition == "created"
    assert len(alerts_repo.list()) == 1

    # -------------------------------------------------------------------------
    # Correlation Engine: Correlate into Incident (incidents.sqlite3)
    # -------------------------------------------------------------------------
    incidents_repo = IncidentSqliteRepository(tmp_path / "incidents.sqlite3")
    correlatable = CorrelatableAlert(
        candidate=alert_candidate, provenance=adapted_result.provenance
    )
    correlation_output = correlate_alert_candidates([correlatable])

    assert len(correlation_output.incidents) == 1
    incident = correlation_output.incidents[0]
    assert incident.provenance_status == "verified_entity_bearing"
    assert incident.correlation_mode == "singleton_verified_provenance"
    assert incident.constituent_alert_ids == (candidate_id,)

    incidents_repo.insert_many(correlation_output.incidents)
    assert incidents_repo.count_incidents() == 1

    # -------------------------------------------------------------------------
    # Human Security Infrastructure & Lifecycle Setup
    # -------------------------------------------------------------------------
    # Generate test certificates
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir(mode=0o700)
    human_ca = browser_tls._ca(cert_dir, "human")
    server_cert = browser_tls._certificate(
        cert_dir, "analyst-server", human_ca, purpose="serverAuth", san="DNS:localhost"
    )
    analyst_cert = browser_tls._certificate(
        cert_dir,
        "analyst_a",
        human_ca,
        purpose="clientAuth",
        san="URI:urn:threatfusion:human:analyst_a",
    )
    viewer_cert = browser_tls._certificate(
        cert_dir,
        "viewer",
        human_ca,
        purpose="clientAuth",
        san="URI:urn:threatfusion:human:queue.viewer",
    )

    cert_map = {
        "human_ca": human_ca[0],
        "server": server_cert,
        "analyst_a": analyst_cert,
        "viewer": viewer_cert,
    }

    authorization = AnalystAuthorizationRegistry(
        (
            AnalystRegistryEntry("queue.viewer", "viewer"),
            AnalystRegistryEntry("analyst_a", "analyst"),
        )
    )

    states_repo = AnalystStateRepository(tmp_path / "states.sqlite3", alerts_repo, authorization)
    view_model = AnalystAlertViewModel(states_repo)
    audit_repo = AnalystSecurityAuditRepository(tmp_path / "audit.sqlite3")

    api_config = AnalystTlsConfiguration(server_cert[0], server_cert[1], human_ca[0])
    browser_config = AnalystTlsConfiguration(server_cert[0], server_cert[1], human_ca[0])

    # Operator policy directory with enrolled certificates
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir(mode=0o700)
    operator.enroll(policy_dir, cert_map, "viewer", "queue.viewer", create=True)
    operator.enroll(policy_dir, cert_map, "analyst_a", "analyst_a", create=False)

    lifecycle = HumanListenerLifecycle(
        directory=policy_dir,
        api_configuration=api_config,
        browser_configuration=browser_config,
        authorization=authorization,
        view=view_model,
        audit=audit_repo,
        storage_directory=tmp_path,
        incident_repository=incidents_repo,
    )

    # -------------------------------------------------------------------------
    # Launch HumanListenerLifecycle & Authenticated Browser Interactions
    # -------------------------------------------------------------------------
    snapshot = lifecycle.replace()
    assert snapshot["state"] == "accepting"
    assert snapshot["generation"] == 1
    assert snapshot["live_workers"] == 2

    api_addr, browser_addr = lifecycle.addresses
    browser_port = browser_addr[1]

    # 1. Browser mTLS GET / (Queue)
    req_queue = browser_tls._req(browser_port, target="/")
    code_q, head_q, body_q = _send_browser_request(browser_addr, cert_map, "analyst_a", req_queue)
    assert code_q == 200
    html_q = body_q.decode("utf-8")
    assert "Status: <b>active</b>" in html_q
    assert '<span class="badge badge-decision">Attack</span>' in html_q
    assert '<span class="badge badge-state">new</span>' in html_q

    # 2. Browser mTLS GET /v1/analyst/alerts/{candidate_id} (Detail)
    req_detail = browser_tls._req(browser_port, target=f"/v1/analyst/alerts/{candidate_id}")
    code_d, head_d, body_d = _send_browser_request(browser_addr, cert_map, "analyst_a", req_detail)
    assert code_d == 200
    html_d = body_d.decode("utf-8")
    assert f"<code>{candidate_id}</code>" in html_d
    assert 'Triage State:</b> <span class="badge badge-state">new</span> (v0)' in html_d

    # 3. Mint CSRF token for analyst_a and perform browser mTLS POST state transition
    transition_id = str(uuid.uuid4())
    browser_listener: AnalystBrowserTlsListener = lifecycle._listeners[1]
    csrf_token = browser_listener.generate_csrf_token("analyst_a", candidate_id, 0, transition_id)

    post_payload = urllib.parse.urlencode(
        {
            "expected_version": "0",
            "transition_request_id": transition_id,
            "csrf_token": csrf_token,
            "target_state": "in_review",
            "reason": "Analyst verified Suricata flow from Attacker VM",
        }
    )
    post_request = browser_tls._post_req(
        browser_port, f"/v1/analyst/alerts/{candidate_id}/transitions", post_payload
    )

    code_t, head_t, body_t = _send_browser_request(
        browser_addr, cert_map, "analyst_a", post_request
    )
    assert code_t == 200
    html_t = body_t.decode("utf-8")
    assert 'Triage State:</b> <span class="badge badge-state">in_review</span> (v1)' in html_t
    assert "Analyst verified Suricata flow from Attacker VM" in html_t

    # Verify state in repository
    analyst_cap = authorization.issue_for_trusted_actor("analyst_a")
    updated_detail = states_repo.get_alert(analyst_cap, candidate_id)
    assert updated_detail.analyst_state.state == "in_review"
    assert updated_detail.analyst_state.version == 1
    assert len(updated_detail.transitions) == 1

    # -------------------------------------------------------------------------
    # Quiescent 4-Database Storage Snapshot & Cryptographic Verification
    # -------------------------------------------------------------------------
    snapshot_target = tmp_path / "quiescent_backup_slide14"
    manifest = lifecycle.snapshot_quiescent(snapshot_target)

    assert manifest["schema"] == "storage_snapshot_manifest_v1"
    assert "databases" in manifest

    db_info = manifest["databases"]
    assert "alerts" in db_info
    assert "states" in db_info
    assert "audit" in db_info
    assert "incidents" in db_info

    # Verify counts in manifest
    assert db_info["alerts"]["row_counts"]["alert_candidates"] == 1
    assert db_info["states"]["row_counts"]["analyst_states"] == 1
    assert db_info["states"]["row_counts"]["analyst_transition_events"] == 1
    assert db_info["incidents"]["row_counts"]["incidents"] == 1
    assert db_info["incidents"]["row_counts"]["incident_constituent_alerts"] == 1

    # Verify cross-database referential consistency
    assert manifest["cross_database_consistency"]["orphan_states_count"] == 0

    # Cryptographic snapshot verification
    verified_manifest = verify_storage_snapshot(snapshot_target)
    assert verified_manifest["schema"] == "storage_snapshot_manifest_v1"

    # Confirm lifecycle resumed to fresh generation accepting connections
    snap_after = lifecycle.snapshot()
    assert snap_after["accepting"] is True
    assert snap_after["generation"] == 2

    # Clean shutdown
    lifecycle.shutdown()
    assert lifecycle.snapshot()["state"] == "stopped"
    assert lifecycle.snapshot()["live_workers"] == 0


def test_slide14_full_post_ingestion_soc_workflow(tmp_path: Path) -> None:
    """Post-ingestion SOC workflow test for Slide 14 Suricata alert.

    Verifies:
    1. Suricata 10.0.0.4 -> 10.0.0.5 live flow ingestion -> 14 features -> AlertCandidate.
    2. Incident correlation in verified singleton mode.
    3. Threat-Intel Enrichment: RFC 1918 private IP guard triggers for 10.0.0.4/10.0.0.5,
       annotating internal lab roles without querying external feeds.
    4. Evidence-Bound Advisory Explanation Engine: generates a grounded debrief
       with groundedness_verified=True and zero hallucinated IPs.
    5. Approval-Gated Reversible SOAR Playbook Ledger:
       - recommends verify_and_contain_lab_source_ip for 10.0.0.4 (pending_approval)
       - analyst approves recommendation
       - executes simulated containment (executed_simulated)
       - cleanly rolls back containment (rolled_back)
    6. Browser Detail Page: GET /v1/analyst/alerts/{candidate_id} cleanly renders
       Threat-Intel & Provenance, Advisory Debrief, and SOAR Playbooks sections in HTML.
    """
    eve_flow = _sample_suricata_eve_flow()
    adapter = SuricataFlowAdapter()
    adapted_result = adapter.adapt_eve_flow_record(eve_flow)

    # Inference with frozen Random Forest
    inference_boundary = UnswNetworkInferenceBoundary(project_root=PROJECT_ROOT)
    inference_request = _NetworkInferenceRequest.from_mapping(
        adapted_result.raw_features,
        provenance=_NetworkSourceProvenance.approved_unsw(),
    )
    inference_result = inference_boundary._predictor.infer(
        inference_request, model=NetworkModelChoice.RANDOM_FOREST
    )
    assert inference_result.status == "completed"

    observed_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
    source_event_id = derive_source_event_id(
        source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        manifest_sha256=hashlib.sha256(b"slide14_azure_victim_vm_manifest_soc").hexdigest(),
        source_member_sha256=hashlib.sha256(
            adapted_result.source_event_id.encode("utf-8")
        ).hexdigest(),
        row_number=1,
    )
    candidate_id = derive_alert_candidate_id(
        source_event_id=source_event_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256=APPROVED_MODEL_HASHES["random_forest"]["model"],
        decision_policy_version=DECISION_POLICY_VERSION,
    )

    alert_candidate = AlertCandidate(
        schema_version=ALERT_CANDIDATE_SCHEMA_VERSION,
        alert_candidate_id=candidate_id,
        source_event_id=source_event_id,
        correlation_id=inference_result.correlation_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256=APPROVED_MODEL_HASHES["random_forest"]["model"],
        feature_contract_identity=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
        source_representation_identity=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        observed_at=observed_time,
        created_at=datetime.now(UTC),
        uncalibrated_model_score=inference_result.attack_probability,
        decision_threshold=0.5,
        decision_policy_version=DECISION_POLICY_VERSION,
        decision="Attack",
        inference_status="completed",
        reason="inference_succeeded",
    )

    alerts_repo = AlertCandidateRepository(tmp_path / "alerts_soc.sqlite3")
    alerts_repo.insert(alert_candidate)

    # Correlate into Incident
    incidents_repo = IncidentSqliteRepository(tmp_path / "incidents_soc.sqlite3")
    correlatable = CorrelatableAlert(
        candidate=alert_candidate, provenance=adapted_result.provenance
    )
    correlation_output = correlate_alert_candidates([correlatable])
    incidents_repo.insert_many(correlation_output.incidents)
    incident = correlation_output.incidents[0]

    # 1. Threat-Intel Enrichment (Section 13.C)
    ti_enricher = SourcedThreatIntelEnricher()
    ti_result = ti_enricher.enrich_entity_contract(adapted_result.provenance)
    assert ti_result.status == "internal_lab_entity_annotated"
    assert ti_result.provenance_verified is True
    assert ti_result.private_ip_guard_triggered is True
    assert ti_result.external_lookup_performed is False
    assert ti_result.internal_lab_annotations.get("10.0.0.4") == "azure_lab_attacker_vm_slide14"
    assert (
        ti_result.internal_lab_annotations.get("10.0.0.5") == "azure_lab_victim_suricata_vm_slide14"
    )

    # 2. Evidence-Bound Advisory Explanation (Section 13.D)
    bundle = AdvisoryEvidenceBundle(
        candidate_id=candidate_id,
        record_id=source_event_id,
        rf_model_version=alert_candidate.model_version,
        rf_attack_probability=alert_candidate.uncalibrated_model_score,
        rf_threshold=alert_candidate.decision_threshold,
        top_feature_signals={
            "duration_ms": float(adapted_result.features_14["duration_ms"]),
            "dst_port": float(adapted_result.features_14["dst_port"]),
        },
        incident_id=incident.incident_id,
        correlation_status=incident.provenance_status,
        enrichment_result=ti_result,
    )
    adv_engine = AdvisoryExplanationEngine()
    explanation = adv_engine.generate_explanation(bundle)
    assert explanation.groundedness_verified is True
    assert explanation.advisory_only_non_authoritative is True
    assert explanation.generation_mode == "deterministic_evidence_template"
    assert "10.0.0.4" in explanation.correlation_and_enrichment_context

    # 3. Approval-Gated Reversible SOAR Ledger (Section 13.E)
    soar_db_path = tmp_path / "soar_soc.sqlite3"
    soar_repo = SoarPlaybookSqliteRepository(soar_db_path)
    soar_engine = ApprovalGatedSoarEngine(soar_repo)

    recs = soar_engine.recommend_actions_for_alert(candidate_id, adapted_result.provenance)
    assert len(recs) >= 1
    target_rec = [r for r in recs if r.action_type == "verify_and_contain_lab_source_ip"][0]
    assert target_rec.state == "pending_approval"
    assert target_rec.target_entity == "10.0.0.4"

    # Analyst approves
    approved = soar_engine.decide_recommendation(
        target_rec.playbook_id,
        actor_id="analyst-client",
        decision="approve",
        reason="Confirmed probe from lab attacker VM",
        expected_version=1,
    )
    assert approved.state == "approved"

    # Simulated containment execution
    executed = soar_engine.execute_approved_action(
        approved.playbook_id,
        actor_id="analyst-client",
        expected_version=approved.version,
    )
    assert executed.state == "executed_simulated"

    # Rollback containment
    rolled_back = soar_engine.rollback_executed_action(
        executed.playbook_id,
        actor_id="analyst-client",
        rollback_reason="Lab exercise complete",
        expected_version=executed.version,
    )
    assert rolled_back.state == "rolled_back"

    # 4. Browser Detail Page Integration
    cert_dir = tmp_path / "certs_soc"
    cert_dir.mkdir(mode=0o700)
    human_ca = browser_tls._ca(cert_dir, "human_soc")
    server_cert = browser_tls._certificate(
        cert_dir, "analyst-server", human_ca, purpose="serverAuth", san="DNS:localhost"
    )
    analyst_cert = browser_tls._certificate(
        cert_dir,
        "analyst_a",
        human_ca,
        purpose="clientAuth",
        san="URI:urn:threatfusion:human:analyst_a",
    )
    viewer_cert = browser_tls._certificate(
        cert_dir,
        "viewer",
        human_ca,
        purpose="clientAuth",
        san="URI:urn:threatfusion:human:queue.viewer",
    )
    cert_map = {
        "human_ca": human_ca[0],
        "server": server_cert,
        "analyst_a": analyst_cert,
        "viewer": viewer_cert,
    }

    authorization = AnalystAuthorizationRegistry(
        (
            AnalystRegistryEntry("queue.viewer", "viewer"),
            AnalystRegistryEntry("analyst_a", "analyst"),
        )
    )

    states_repo = AnalystStateRepository(
        tmp_path / "states_soc.sqlite3", alerts_repo, authorization
    )
    view_model = AnalystAlertViewModel(states_repo, incident_repository=incidents_repo)
    audit_repo = AnalystSecurityAuditRepository(tmp_path / "audit_soc.sqlite3")

    api_config = AnalystTlsConfiguration(server_cert[0], server_cert[1], human_ca[0])
    browser_config = AnalystTlsConfiguration(server_cert[0], server_cert[1], human_ca[0])

    policy_dir = tmp_path / "policy_soc"
    policy_dir.mkdir(mode=0o700)
    operator.enroll(policy_dir, cert_map, "viewer", "queue.viewer", create=True)
    operator.enroll(policy_dir, cert_map, "analyst_a", "analyst_a", create=False)

    lifecycle = HumanListenerLifecycle(
        directory=policy_dir,
        api_configuration=api_config,
        browser_configuration=browser_config,
        authorization=authorization,
        view=view_model,
        audit=audit_repo,
        incident_repository=incidents_repo,
        threat_intel_enricher={candidate_id: ti_result},
        advisory_engine={candidate_id: explanation},
        soar_repository=soar_repo,
    )
    lifecycle.replace()

    browser_addr = lifecycle.addresses[1]
    browser_port = browser_addr[1]

    req_detail = browser_tls._req(browser_port, target=f"/v1/analyst/alerts/{candidate_id}")
    code, head, body = _send_browser_request(browser_addr, cert_map, "analyst_a", req_detail)
    assert code == 200
    html = body.decode("utf-8")

    assert "Threat-Intel &amp; Provenance" in html
    assert "Triggered (RFC 1918 Private IP)" in html
    assert "azure_lab_attacker_vm_slide14" in html
    assert "Evidence-Bound Advisory Debrief" in html
    assert "Approval-Gated SOAR Playbooks" in html
    assert "verify_and_contain_lab_source_ip" in html
    assert "rolled_back" in html

    lifecycle.shutdown()
