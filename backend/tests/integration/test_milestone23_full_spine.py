"""End-to-End Integration Test for Milestone #23 Complete Product Spine.

Exercises the full chain across:
1. Slide 14 Suricata Flow Ingestion -> 14 features -> EntityProvenanceContract.
2. Frozen RF baseline inference -> AlertCandidate generation.
3. Provenance-gated temporal correlation -> Incident persistence.
4. Sourced Threat-Intel Enrichment (Section 13.C) with RFC1918 private-IP guard.
5. Missing-Data Aware Multi-Signal Dynamic Risk Scoring.
6. Evidence-Bound Advisory Debrief (Section 13.D) with anti-hallucination groundedness.
7. Approval-Gated Reversible SOAR Ledger (Section 13.E) propose -> approve -> execute -> rollback.
8. Offline Retraining Feedback Ledger (TF-007) with byte-identical model verification.
9. Canonical Evaluation Pack Rev2 (AI-FYP-2006) and Section 8 fusion_disabled invariant.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from threatfusion.advisory.explanation_engine import (
    AdvisoryEvidenceBundle,
    AdvisoryExplanationEngine,
    verify_explanation_groundedness,
)
from threatfusion.alerts.correlation_engine import (
    CorrelatableAlert,
    IncidentSqliteRepository,
    correlate_alert_candidates,
)
from threatfusion.datasets.adapters.suricata_flow import SuricataFlowAdapter
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.retraining_feedback_ledger import (
    OfflineRetrainingFeedbackRepository,
    verify_frozen_models_unmodified,
)
from threatfusion.enrichment.threat_intel import (
    SourcedThreatIntelEnricher,
)
from threatfusion.features.network_behavior import (
    NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
    UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
)
from threatfusion.models.canonical_evaluation import (
    CANONICAL_EVALUATION_PACK_REV2,
    PROJECT_IDENTIFIER,
    assert_fusion_disabled_invariant,
    execute_production_inference_guard,
    get_canonical_evaluation_pack_rev2,
    is_fusion_enabled,
)
from threatfusion.models.multi_signal_risk import (
    SignalObservation,
    compute_dynamic_risk_score,
)
from threatfusion.models.network_inference import (
    APPROVED_MODEL_HASHES,
    NetworkModelChoice,
    UnswNetworkInferenceBoundary,
    _NetworkInferenceRequest,
    _NetworkSourceProvenance,
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
from threatfusion.soar.playbook_ledger import (
    ApprovalGatedSoarEngine,
    SoarPlaybookSqliteRepository,
    SoarStateTransitionError,
)


def test_milestone23_complete_product_spine() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        # -------------------------------------------------------------
        # Stage 1: Slide 14 Suricata Ingestion
        # -------------------------------------------------------------
        eve_flow_event = {
            "timestamp": "2026-10-16T12:00:00.000000+00:00",
            "event_type": "flow",
            "src_ip": "10.0.0.4",
            "src_port": 54322,
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
                "start": "2026-10-16T12:00:00.000000+00:00",
                "end": "2026-10-16T12:00:01.500000+00:00",
                "age": 1,
                "state": "closed",
                "reason": "shutdown",
                "alerted": False,
            },
        }

        adapter = SuricataFlowAdapter(
            default_sensor_namespace="azure-suricata-edge-01",
        )
        adapted_res = adapter.adapt_flow_record(eve_flow_event)
        features_14 = adapted_res.features_14
        assert len(features_14) == 14
        assert adapted_res.provenance.clock_synchronized is True
        assert adapted_res.provenance.entity_namespace_id == "azure-suricata-edge-01"

        # -------------------------------------------------------------
        # Stage 2: Frozen RF Inference & Alert Persistence
        # -------------------------------------------------------------
        inference_boundary = UnswNetworkInferenceBoundary(project_root=repo_root)
        inference_request = _NetworkInferenceRequest.from_mapping(
            adapted_res.raw_features,
            provenance=_NetworkSourceProvenance.approved_unsw(),
        )
        infer_res = inference_boundary._predictor.infer(
            inference_request, model=NetworkModelChoice.RANDOM_FOREST
        )

        assert infer_res.status == "completed"
        assert infer_res.predicted_class == "Attack"
        assert infer_res.attack_probability is not None
        assert infer_res.attack_probability >= 0.50

        observed_time = datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC)
        source_event_id = derive_source_event_id(
            source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
            manifest_sha256=hashlib.sha256(b"slide14_azure_victim_vm_manifest").hexdigest(),
            source_member_sha256=hashlib.sha256(
                adapted_res.source_event_id.encode("utf-8")
            ).hexdigest(),
            row_number=1,
        )
        cand_id = derive_alert_candidate_id(
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
            alert_candidate_id=cand_id,
            source_event_id=source_event_id,
            correlation_id=infer_res.correlation_id,
            detector_identity=DETECTOR_IDENTITY,
            detector_version=DETECTOR_VERSION,
            model_identity="random_forest",
            model_version="network_random_forest_baseline_v1",
            model_artifact_sha256=APPROVED_MODEL_HASHES["random_forest"]["model"],
            feature_contract_identity=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
            source_representation_identity=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
            observed_at=observed_time,
            created_at=datetime.now(UTC),
            uncalibrated_model_score=infer_res.attack_probability,
            decision_threshold=0.5,
            decision_policy_version=DECISION_POLICY_VERSION,
            decision="Attack",
            inference_status="completed",
            reason="inference_succeeded",
        )

        alerts_db = tmp_path / "alerts.sqlite3"
        alert_repo = AlertCandidateRepository(alerts_db)
        insert_status = alert_repo.insert(alert_candidate)
        assert insert_status.disposition == "created"
        assert len(alert_repo.list()) == 1

        # -------------------------------------------------------------
        # Stage 3: Provenance-Gated Temporal Correlation
        # -------------------------------------------------------------
        incidents_db = tmp_path / "incidents.sqlite3"
        incidents_repo = IncidentSqliteRepository(incidents_db)

        correlatable = CorrelatableAlert(
            candidate=alert_candidate, provenance=adapted_res.provenance
        )
        correlation_output = correlate_alert_candidates([correlatable])
        assert len(correlation_output.incidents) == 1
        incident = correlation_output.incidents[0]
        assert incident.entity_namespace_id == "azure-suricata-edge-01"
        assert incident.escalated_decision == "Attack"
        incidents_repo.insert_many(correlation_output.incidents)
        assert incidents_repo.count_incidents() == 1

        # -------------------------------------------------------------
        # Stage 4: Sourced Threat-Intel Enrichment (Section 13.C)
        # -------------------------------------------------------------
        enricher = SourcedThreatIntelEnricher()
        enrichment_result = enricher.enrich_entity_contract(adapted_res.provenance)
        assert enrichment_result.provenance_verified is True
        assert enrichment_result.private_ip_guard_triggered is True
        assert enrichment_result.external_lookup_performed is False
        assert enrichment_result.status == "internal_lab_entity_annotated"
        assert "10.0.0.4" in enrichment_result.internal_lab_annotations

        # -------------------------------------------------------------
        # Stage 5: Missing-Data Dynamic Risk Scoring (Phase P5)
        # -------------------------------------------------------------
        threat_intel_signal = SignalObservation(
            slot="threat_intel_ioc",
            status="AVAILABLE",
            score=0.75,
            metadata={"status": enrichment_result.status},
        )
        dynamic_risk = compute_dynamic_risk_score(
            {
                "supervised_rf": infer_res.attack_probability,
                "threat_intel_ioc": threat_intel_signal,
            }
        )
        assert dynamic_risk.dynamic_risk_score >= 50.0
        assert dynamic_risk.severity_level in {"medium", "high", "critical"}
        assert "threat_intel_ioc" in dynamic_risk.available_signals
        assert "autoencoder_v2_reconstruction" in dynamic_risk.unavailable_signals

        # -------------------------------------------------------------
        # Stage 6: Evidence-Bound Advisory Debrief (Section 13.D)
        # -------------------------------------------------------------
        bundle = AdvisoryEvidenceBundle(
            candidate_id=cand_id,
            record_id=adapted_res.source_event_id,
            rf_model_version="full-network-random-forest-6d69c72-v1",
            rf_attack_probability=infer_res.attack_probability,
            rf_threshold=0.50,
            top_feature_signals=features_14,
            ae_v2_reconstruction_error=None,
            incident_id=incident.incident_id,
            correlation_status="corr_burst_5tuple_30s_v1",
            enrichment_result=enrichment_result,
        )

        explanation = AdvisoryExplanationEngine.generate_explanation(bundle)
        assert explanation.advisory_only_non_authoritative is True
        assert explanation.groundedness_verified is True
        assert verify_explanation_groundedness(explanation, bundle) is True
        assert "full-network-random-forest-6d69c72-v1" in explanation.detection_rationale

        # -------------------------------------------------------------
        # Stage 7: Approval-Gated Reversible SOAR Ledger (Section 13.E)
        # -------------------------------------------------------------
        soar_db = tmp_path / "soar.sqlite3"
        soar_repo = SoarPlaybookSqliteRepository(soar_db)
        soar_engine = ApprovalGatedSoarEngine(soar_repo)

        recommendations = soar_engine.recommend_actions_for_alert(
            candidate_id=cand_id,
            provenance=adapted_res.provenance,
        )
        assert len(recommendations) >= 1
        first_rec = recommendations[0]
        assert first_rec.state == "pending_approval"
        assert first_rec.version == 1

        # 7b. Attempting unapproved execution fails closed
        with pytest.raises(SoarStateTransitionError):
            soar_engine.execute_approved_action(
                playbook_id=first_rec.playbook_id,
                actor_id="unauthorized_actor",
                expected_version=1,
            )

        # 7c. Authorized analyst approves
        approved_rec = soar_engine.decide_recommendation(
            playbook_id=first_rec.playbook_id,
            actor_id="analyst-bilal",
            decision="approve",
            reason="Verified lab attacker IP 10.0.0.4 with high attack probability.",
            expected_version=1,
        )
        assert approved_rec.state == "approved"
        assert approved_rec.version == 2

        # 7d. Execution succeeds
        executed_rec = soar_engine.execute_approved_action(
            playbook_id=first_rec.playbook_id,
            actor_id="analyst-bilal",
            expected_version=2,
        )
        assert executed_rec.state == "executed_simulated"
        assert executed_rec.version == 3

        # 7e. Reversible Rollback succeeds
        rolled_back_rec = soar_engine.rollback_executed_action(
            playbook_id=first_rec.playbook_id,
            actor_id="analyst-bilal",
            rollback_reason="Lab containment exercise concluded; restoring state.",
            expected_version=3,
        )
        assert rolled_back_rec.state == "rolled_back"
        assert rolled_back_rec.version == 4

        # Verify audit entries
        audit_entries = soar_repo.list_audit_entries(first_rec.playbook_id)
        assert len(audit_entries) >= 4

        # -------------------------------------------------------------
        # Stage 8: Offline Retraining Feedback Ledger (TF-007)
        # -------------------------------------------------------------
        feedback_db = tmp_path / "retraining_feedback.sqlite3"
        feedback_repo = OfflineRetrainingFeedbackRepository(feedback_db, repo_root=repo_root)
        feedback_repo.record_feedback(
            transition_request_id="a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d",
            alert_candidate_id=cand_id,
            stored_detector_decision="Attack",
            stored_score=infer_res.attack_probability,
            analyst_verified_outcome="confirmed_threat",
            actor_id="analyst-bilal",
        )
        # Verify frozen model checksums are intact
        rf_sha, ae_sha = verify_frozen_models_unmodified(repo_root=repo_root)
        assert rf_sha == "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"
        assert ae_sha == "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23"

        # -------------------------------------------------------------
        # Stage 9: Canonical Evaluation Pack Rev2 & Section 8 Invariant
        # -------------------------------------------------------------
        pack = get_canonical_evaluation_pack_rev2()
        assert pack.project_identifier == PROJECT_IDENTIFIER
        assert pack.project_id == "AI-FYP-2006"
        assert pack.fusion_disabled is True
        assert is_fusion_enabled() is False
        assert_fusion_disabled_invariant()
        assert CANONICAL_EVALUATION_PACK_REV2.project_id == "AI-FYP-2006"
        assert (
            execute_production_inference_guard("random_forest") == "frozen_random_forest_approved"
        )
