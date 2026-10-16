"""Unit tests for Evidence-Bound Advisory Debrief Engine and Approval-Gated SOAR Ledger."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from threatfusion.advisory.explanation_engine import (
    AdvisoryEvidenceBundle,
    AdvisoryExplanationEngine,
    EvidenceBoundExplanation,
    verify_explanation_groundedness,
)
from threatfusion.alerts.correlation_engine import EntityProvenanceContract
from threatfusion.enrichment.threat_intel import ThreatIntelEnrichmentResult
from threatfusion.soar.playbook_ledger import (
    ApprovalGatedSoarEngine,
    SoarOptimisticConcurrencyError,
    SoarPlaybookSqliteRepository,
    SoarStateTransitionError,
)


class TestAdvisoryExplanationEngine:
    """Test evidence groundedness, anti-hallucination, and deterministic fallback."""

    def test_deterministic_template_generation_and_groundedness(self) -> None:
        """Deterministic explanation is 100% grounded and adheres to Section 8 invariant."""
        bundle = AdvisoryEvidenceBundle(
            candidate_id="alert_candidate_v1:4c785c6418ff70c92a635785f5954355b6222f324d1314565b624affe771a8f7",
            record_id="rec_unsw_0021",
            rf_model_version="full-network-random-forest-6d69c72-v1",
            rf_attack_probability=0.824988,
            rf_threshold=0.50,
            top_feature_signals={"sbytes": 1054.0, "dbytes": 2048.0, "rate": 45.2},
            ae_v2_reconstruction_error=0.1542,
            ae_v2_threshold=0.118136,
            incident_id="incident_v1:89abef",
            correlation_status="corr_burst_5tuple_30s_v1",
            enrichment_result=ThreatIntelEnrichmentResult(
                status="internal_lab_entity_annotated",
                provenance_verified=True,
                external_lookup_performed=False,
                private_ip_guard_triggered=True,
                inspected_entities=("10.0.0.4", "10.0.0.5"),
                internal_lab_annotations={"10.0.0.4": "azure_lab_attacker_vm_slide14"},
                matches=(),
                feed_snapshot_id=None,
                reason="Annotated lab entities",
            ),
        )

        explanation = AdvisoryExplanationEngine.generate_explanation(bundle)

        assert explanation.advisory_only_non_authoritative is True
        assert explanation.generation_mode == "deterministic_evidence_template"
        assert explanation.groundedness_verified is True
        assert verify_explanation_groundedness(explanation, bundle) is True
        assert (
            "0.8250" in explanation.detection_rationale
            or "0.824988" in explanation.detection_rationale
            or "0.825" in explanation.detection_rationale
        )
        assert "full-network-random-forest-6d69c72-v1" in explanation.detection_rationale
        assert "fusion_disabled per Section 8" in explanation.complementarity_and_fusion_note

    def test_flow_only_ip_hallucination_rejected(self) -> None:
        """If bundle has no inspected entities (flow-only), any hallucinated IP in text fails groundedness."""
        bundle = AdvisoryEvidenceBundle(
            candidate_id="alert_candidate_v1:unsw_flow_only",
            record_id="rec_unsw_flow_01",
            rf_model_version="full-network-random-forest-6d69c72-v1",
            rf_attack_probability=0.75,
            rf_threshold=0.50,
            top_feature_signals={"dur": 1.25},
            enrichment_result=None,  # Flow-only, NO inspected entities
        )

        # Deterministic generation contains ZERO IPs
        clean_exp = AdvisoryExplanationEngine.generate_explanation(bundle)
        assert clean_exp.groundedness_verified is True
        assert verify_explanation_groundedness(clean_exp, bundle) is True

        # Now simulate an LLM that hallucinates an IP address
        hallucinated_exp = EvidenceBoundExplanation(
            candidate_id=bundle.candidate_id,
            generation_mode="verified_local_llm_advisory",
            advisory_only_non_authoritative=True,
            summary_headline="Malicious probe detected",
            detection_rationale="The Random Forest model full-network-random-forest-6d69c72-v1 scored 0.7500.",
            complementarity_and_fusion_note="Authority rests on Random Forest; fusion is disabled.",
            correlation_and_enrichment_context="Attacker at 192.168.1.100 probed the host.",  # Hallucinated IP!
            recommended_analyst_checks=("Check logs",),
            cited_evidence_keys=(
                "candidate_id",
                "record_id",
                "rf_model_version",
                "rf_attack_probability",
                "rf_threshold",
            ),
            groundedness_verified=True,
        )

        assert verify_explanation_groundedness(hallucinated_exp, bundle) is False

        # AdvisoryExplanationEngine falls back to deterministic template when LLM hallucinates
        safe_fallback = AdvisoryExplanationEngine.generate_explanation(
            bundle,
            optional_llm_callable=lambda b: hallucinated_exp,
        )
        assert safe_fallback.generation_mode == "deterministic_evidence_template"
        assert "192.168.1.100" not in safe_fallback.correlation_and_enrichment_context

    def test_llm_exception_falls_back_to_deterministic(self) -> None:
        """When optional LLM callable raises, safely falls back to deterministic template."""
        bundle = AdvisoryEvidenceBundle(
            candidate_id="alert_candidate_v1:test_err",
            record_id="rec_test",
            rf_model_version="full-network-random-forest-6d69c72-v1",
            rf_attack_probability=0.88,
            rf_threshold=0.50,
            top_feature_signals={"rate": 100.0},
        )

        def failing_llm(b: AdvisoryEvidenceBundle) -> EvidenceBoundExplanation:
            raise RuntimeError("LLM service timeout")

        explanation = AdvisoryExplanationEngine.generate_explanation(
            bundle,
            optional_llm_callable=failing_llm,
        )
        assert explanation.generation_mode == "deterministic_evidence_template"
        assert explanation.groundedness_verified is True


class TestApprovalGatedSoarLedger:
    """Test full SOAR lifecycle: recommend -> approve -> execute -> rollback."""

    def test_full_soar_safety_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "soar.sqlite3"
            repo = SoarPlaybookSqliteRepository(db_path)
            engine = ApprovalGatedSoarEngine(repo)

            provenance = EntityProvenanceContract(
                entity_namespace_id="azure_lab:suricata_live_v1",
                clock_synchronized=True,
                src_entity_id="10.0.0.4",
                dst_entity_id="10.0.0.5",
                protocol="tcp",
                service_or_port="80",
            )
            candidate_id = "alert_candidate_v1:soar_test_01"

            # Step 1: Recommendation (never auto-executed!)
            recommendations = engine.recommend_actions_for_alert(candidate_id, provenance)
            assert len(recommendations) >= 1
            containment_action = [
                r for r in recommendations if r.action_type == "verify_and_contain_lab_source_ip"
            ][0]
            assert containment_action.state == "pending_approval"
            assert containment_action.version == 1
            assert containment_action.target_entity == "10.0.0.4"

            # Step 2 Violation: Attempting to execute unapproved action MUST raise SoarStateTransitionError
            with pytest.raises(SoarStateTransitionError, match="explicitly 'approved'"):
                engine.execute_approved_action(
                    containment_action.playbook_id,
                    actor_id="analyst-client",
                    expected_version=1,
                )

            # Optimistic concurrency conflict on decision
            with pytest.raises(SoarOptimisticConcurrencyError, match="expected version 99"):
                engine.decide_recommendation(
                    containment_action.playbook_id,
                    actor_id="analyst-client",
                    decision="approve",
                    reason="Confirmed malicious probe in Azure lab",
                    expected_version=99,
                )

            # Step 2: Analyst Approval
            approved = engine.decide_recommendation(
                containment_action.playbook_id,
                actor_id="analyst-client",
                decision="approve",
                reason="Confirmed malicious probe in Azure lab",
                expected_version=1,
            )
            assert approved.state == "approved"
            assert approved.version == 2
            assert approved.actor_id == "analyst-client"

            # Step 3: Simulated Execution
            executed = engine.execute_approved_action(
                approved.playbook_id,
                actor_id="analyst-client",
                expected_version=2,
            )
            assert executed.state == "executed_simulated"
            assert executed.version == 3
            assert executed.pre_action_snapshot is not None
            assert executed.execution_evidence is not None

            # Attempting to execute again fails
            with pytest.raises(SoarStateTransitionError):
                engine.execute_approved_action(
                    executed.playbook_id,
                    actor_id="analyst-client",
                    expected_version=3,
                )

            # Step 4: Reversible Rollback
            rolled_back = engine.rollback_executed_action(
                executed.playbook_id,
                actor_id="analyst-client",
                rollback_reason="Investigation concluded; restoring normal lab traffic",
                expected_version=3,
            )
            assert rolled_back.state == "rolled_back"
            assert rolled_back.version == 4
            assert (
                rolled_back.rollback_reason
                == "Investigation concluded; restoring normal lab traffic"
            )

            # Verify audit trail
            audit_events = repo.list_audit_events(containment_action.playbook_id)
            assert len(audit_events) == 4
            actions = [e["action"] for e in audit_events]
            assert actions == [
                "recommend_action",
                "analyst_approve",
                "execute_simulated_action",
                "rollback_action",
            ]
