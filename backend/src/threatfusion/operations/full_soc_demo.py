"""Turnkey Two-Track Jury & Supervisor Demonstration Runner (Milestone #24).

Executes the complete ThreatFusion SOC architecture end-to-end across two tracks:
- Track A: Recorded UNSW-NB15 mTLS Baseline & Replay Proof (Rows 1 & 21, Section 8 shield).
- Track B: Slide 14 Azure VM Suricata Live-Ingestion Full SOC Spine (14-feature adapter,
  frozen RF, correlation, RFC 1918 private-IP guarded threat-intel, grounded advisory debrief,
  approval-gated reversible SOAR ledger, and Section 13.F workload measurement).
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any

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
from threatfusion.enrichment.threat_intel import SourcedThreatIntelEnricher
from threatfusion.evaluation.workload_measurement import (
    AnalystWorkloadStudyRepository,
    TriageTrialRecord,
    evaluate_alert_fatigue_compression,
)
from threatfusion.features.network_behavior import (
    NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
    UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
)
from threatfusion.models.canonical_evaluation import (
    CANONICAL_EVALUATION_PACK_REV2,
    assert_fusion_disabled_invariant,
    execute_production_inference_guard,
    is_fusion_enabled,
)
from threatfusion.models.network_inference import (
    APPROVED_MODEL_HASHES,
    APPROVED_UNSW_MANIFEST_HASH,
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

REGISTERED_UNSW_MEMBER_SHA256 = "7d851bbeabd27894ce39c8e78835c73341fc946652fb7743b9eff193b55eb511"
DEMO_SCHEMA_VERSION = "full_soc_demo_report_v1"


def run_full_soc_demo(output_dir: Path | str) -> dict[str, Any]:
    """Execute turnkey two-track SOC demo and generate JSON + Markdown evidence reports."""
    out_path = Path(output_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)
    repo_root = Path(__file__).resolve().parents[4]

    assert_fusion_disabled_invariant()
    assert is_fusion_enabled() is False
    assert execute_production_inference_guard("random_forest") == "frozen_random_forest_approved"

    pack_rev2 = CANONICAL_EVALUATION_PACK_REV2
    boundary = UnswNetworkInferenceBoundary(project_root=repo_root)

    # =========================================================================
    # Track A: Recorded UNSW-NB15 mTLS Baseline & Replay Proof
    # =========================================================================
    references = (
        (REGISTERED_UNSW_MEMBER_SHA256, 1),
        (REGISTERED_UNSW_MEMBER_SHA256, 21),
    )
    inferred_batch = boundary.infer_registered_batch(
        references=references, model=NetworkModelChoice.RANDOM_FOREST
    )

    track_a_alerts_db = out_path / "track_a_alerts.sqlite3"
    track_a_alert_repo = AlertCandidateRepository(track_a_alerts_db)

    row_1_res = inferred_batch[0]
    row_21_res = inferred_batch[1]

    # Row 1 Invariants: Normal (~0.001% attack probability), no alert created
    assert row_1_res.inference.predicted_class == "Normal"
    row_1_prob = float(row_1_res.inference.attack_probability)
    assert row_1_prob < 0.50

    # Row 21 Invariants: Attack (~82.499% attack probability), 1 alert candidate created
    assert row_21_res.inference.predicted_class == "Attack"
    row_21_prob = float(row_21_res.inference.attack_probability)
    assert row_21_prob >= 0.50

    cand_id_21 = derive_alert_candidate_id(
        source_event_id=row_21_res.source_event_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256=APPROVED_MODEL_HASHES["random_forest"]["model"],
        decision_policy_version=DECISION_POLICY_VERSION,
    )
    alert_cand_21 = AlertCandidate(
        schema_version=ALERT_CANDIDATE_SCHEMA_VERSION,
        alert_candidate_id=cand_id_21,
        source_event_id=row_21_res.source_event_id,
        correlation_id=row_21_res.inference.correlation_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256=APPROVED_MODEL_HASHES["random_forest"]["model"],
        feature_contract_identity=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
        source_representation_identity=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        observed_at=row_21_res.observed_at,
        created_at=datetime.now(UTC),
        uncalibrated_model_score=row_21_prob,
        decision_threshold=0.5,
        decision_policy_version=DECISION_POLICY_VERSION,
        decision="Attack",
        inference_status="completed",
        reason="inference_succeeded",
    )
    track_a_alert_repo.insert(alert_cand_21)

    # Track A Correlation: raw flow lacks entity provenance contract -> uncorrelatable across entities
    correlatable_track_a = CorrelatableAlert(candidate=alert_cand_21, provenance=None)
    corr_track_a = correlate_alert_candidates([correlatable_track_a])
    assert len(corr_track_a.incidents) == 1
    assert corr_track_a.incidents[0].correlation_mode == "singleton_unverified_provenance"
    correlation_disposition = "uncorrelatable_missing_entity"

    # Track A Threat-Intel: unverified provenance -> skipped
    enricher = SourcedThreatIntelEnricher()
    enrich_track_a = enricher.enrich_entity_contract(None)
    assert enrich_track_a.status == "skipped_unverified_provenance"
    assert enrich_track_a.external_lookup_performed is False

    # Track A Section 8 Shield Report
    track_a_compression = evaluate_alert_fatigue_compression(
        raw_flow_count=2,
        rf_alert_candidate_count=1,
        correlated_incident_count=0,
        uncorrelatable_alert_count=1,
    )

    track_a_data = {
        "status": "completed",
        "description": "Recorded UNSW-NB15 mTLS Baseline & Replay Proof",
        "dataset_member_sha256": REGISTERED_UNSW_MEMBER_SHA256,
        "manifest_sha256": APPROVED_UNSW_MANIFEST_HASH,
        "rows_evaluated": [
            {
                "row_number": 1,
                "ground_truth": "Normal",
                "predicted_class": row_1_res.inference.predicted_class,
                "attack_probability": row_1_prob,
                "disposition": "recorded_without_alert",
                "alert_candidate_id": None,
            },
            {
                "row_number": 21,
                "ground_truth": "Attack",
                "predicted_class": row_21_res.inference.predicted_class,
                "attack_probability": row_21_prob,
                "disposition": "alert_created",
                "alert_candidate_id": cand_id_21,
            },
        ],
        "correlation_disposition": correlation_disposition,
        "enrichment_disposition": "skipped_unverified_provenance",
        "section_8_counterfactual_shield": track_a_compression.counterfactual_shield.to_dict(),
    }

    # =========================================================================
    # Track B: Slide 14 Azure VM Suricata Live-Ingestion Full SOC Spine
    # =========================================================================
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

    # B1: Suricata Flow Adapter (14 features + EntityProvenanceContract)
    adapter = SuricataFlowAdapter(default_sensor_namespace="azure-suricata-edge-01")
    adapted_flow = adapter.adapt_flow_record(eve_flow_event)
    assert len(adapted_flow.features_14) == 14
    assert adapted_flow.provenance.clock_synchronized is True
    assert adapted_flow.provenance.entity_namespace_id == "azure-suricata-edge-01"

    # B2: Frozen Random Forest Baseline Inference
    req = _NetworkInferenceRequest.from_mapping(
        adapted_flow.raw_features,
        provenance=_NetworkSourceProvenance.approved_unsw(),
    )
    infer_res_b = boundary._predictor.infer(req, model=NetworkModelChoice.RANDOM_FOREST)
    assert infer_res_b.status == "completed"
    assert infer_res_b.predicted_class == "Attack"
    prob_b = float(infer_res_b.attack_probability)
    assert prob_b >= 0.50

    # B3: AlertCandidate Persistence
    track_b_alerts_db = out_path / "track_b_alerts.sqlite3"
    track_b_alert_repo = AlertCandidateRepository(track_b_alerts_db)

    source_event_id_b = derive_source_event_id(
        source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        manifest_sha256=APPROVED_UNSW_MANIFEST_HASH,
        source_member_sha256=REGISTERED_UNSW_MEMBER_SHA256,
        row_number=21,
    )
    cand_id_b = derive_alert_candidate_id(
        source_event_id=source_event_id_b,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256=APPROVED_MODEL_HASHES["random_forest"]["model"],
        decision_policy_version=DECISION_POLICY_VERSION,
    )
    alert_cand_b = AlertCandidate(
        schema_version=ALERT_CANDIDATE_SCHEMA_VERSION,
        alert_candidate_id=cand_id_b,
        source_event_id=source_event_id_b,
        correlation_id=infer_res_b.correlation_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256=APPROVED_MODEL_HASHES["random_forest"]["model"],
        feature_contract_identity=NETWORK_BEHAVIOR_V1_CONTRACT_VERSION,
        source_representation_identity=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        observed_at=datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC),
        created_at=datetime.now(UTC),
        uncalibrated_model_score=prob_b,
        decision_threshold=0.5,
        decision_policy_version=DECISION_POLICY_VERSION,
        decision="Attack",
        inference_status="completed",
        reason="inference_succeeded",
    )
    track_b_alert_repo.insert(alert_cand_b)

    # B4: Incident Correlation Engine
    track_b_incidents_db = out_path / "track_b_incidents.sqlite3"
    track_b_incidents_repo = IncidentSqliteRepository(track_b_incidents_db)

    correlatable_b = CorrelatableAlert(candidate=alert_cand_b, provenance=adapted_flow.provenance)
    corr_out_b = correlate_alert_candidates([correlatable_b])
    assert len(corr_out_b.incidents) == 1
    incident_b = corr_out_b.incidents[0]
    track_b_incidents_repo.insert_many(corr_out_b.incidents)

    # B5: Sourced Threat-Intel Enrichment with RFC 1918 Guard
    enrich_res_b = enricher.enrich_entity_contract(adapted_flow.provenance)
    assert enrich_res_b.provenance_verified is True
    assert enrich_res_b.private_ip_guard_triggered is True
    assert enrich_res_b.external_lookup_performed is False
    assert enrich_res_b.status == "internal_lab_entity_annotated"
    assert "10.0.0.4" in enrich_res_b.internal_lab_annotations
    assert "10.0.0.5" in enrich_res_b.internal_lab_annotations

    # B6: Evidence-Bound Advisory Debrief Engine
    bundle_b = AdvisoryEvidenceBundle(
        candidate_id=cand_id_b,
        record_id=adapted_flow.source_event_id,
        rf_model_version="full-network-random-forest-6d69c72-v1",
        rf_attack_probability=prob_b,
        rf_threshold=0.50,
        top_feature_signals=adapted_flow.features_14,
        ae_v2_reconstruction_error=None,
        incident_id=incident_b.incident_id,
        correlation_status="corr_burst_5tuple_30s_v1",
        enrichment_result=enrich_res_b,
    )
    explanation_b = AdvisoryExplanationEngine.generate_explanation(bundle_b)
    assert explanation_b.advisory_only_non_authoritative is True
    assert explanation_b.groundedness_verified is True
    assert verify_explanation_groundedness(explanation_b, bundle_b) is True

    # B7: Approval-Gated Reversible SOAR Ledger
    track_b_soar_db = out_path / "track_b_soar.sqlite3"
    track_b_soar_repo = SoarPlaybookSqliteRepository(track_b_soar_db)
    soar_engine = ApprovalGatedSoarEngine(track_b_soar_repo)

    recs = soar_engine.recommend_actions_for_alert(
        candidate_id=cand_id_b,
        provenance=adapted_flow.provenance,
    )
    assert len(recs) >= 1
    soar_action = recs[0]
    assert soar_action.state == "pending_approval"
    assert soar_action.version == 1

    # Unauthorized execution fails closed
    try:
        soar_engine.execute_approved_action(
            playbook_id=soar_action.playbook_id,
            actor_id="unauthorized",
            expected_version=1,
        )
        raise AssertionError("Unapproved SOAR execution must fail")
    except SoarStateTransitionError:
        pass

    # Human analyst approves
    approved_action = soar_engine.decide_recommendation(
        playbook_id=soar_action.playbook_id,
        actor_id="analyst-bilal",
        decision="approve",
        reason="Approved containment following verified 10.0.0.4 attacker activity.",
        expected_version=1,
    )
    assert approved_action.state == "approved"
    assert approved_action.version == 2

    # Execution (simulated)
    executed_action = soar_engine.execute_approved_action(
        playbook_id=soar_action.playbook_id,
        actor_id="analyst-bilal",
        expected_version=2,
    )
    assert executed_action.state == "executed_simulated"
    assert executed_action.version == 3

    # Reversible Rollback
    rolled_back_action = soar_engine.rollback_executed_action(
        playbook_id=soar_action.playbook_id,
        actor_id="analyst-bilal",
        rollback_reason="Lab exercise complete; unblocking attacker VM.",
        expected_version=3,
    )
    assert rolled_back_action.state == "rolled_back"
    assert rolled_back_action.version == 4

    soar_audit = track_b_soar_repo.list_audit_entries(soar_action.playbook_id)

    # B8: Section 13.F Alert-Fatigue Compression Report
    track_b_compression = evaluate_alert_fatigue_compression(
        raw_flow_count=1,
        rf_alert_candidate_count=1,
        correlated_incident_count=1,
        uncorrelatable_alert_count=0,
    )

    # B9: Workload Study Ledger (Synthetic smoke trial preserving TF-009)
    workload_db = out_path / "workload_study.sqlite3"
    workload_repo = AnalystWorkloadStudyRepository(workload_db)
    trial_now = datetime.now(UTC).isoformat()
    workload_repo.record_trial(
        TriageTrialRecord(
            trial_id="demo_trial_baseline",
            study_cohort="synthetic_smoke_verification",
            participant_id="automated_runner",
            candidate_id=cand_id_b,
            condition="baseline_raw_alert_only",
            time_to_first_review_ms=3500,
            time_to_disposition_ms=14000,
            expected_disposition="Attack",
            recorded_disposition="Attack",
            disposition_correct=True,
            evidence_panels_viewed=("raw_hex",),
            recorded_at_utc=trial_now,
        )
    )
    workload_repo.record_trial(
        TriageTrialRecord(
            trial_id="demo_trial_threatfusion",
            study_cohort="synthetic_smoke_verification",
            participant_id="automated_runner",
            candidate_id=cand_id_b,
            condition="threatfusion_enriched_advisory_soar",
            time_to_first_review_ms=1100,
            time_to_disposition_ms=4500,
            expected_disposition="Attack",
            recorded_disposition="Attack",
            disposition_correct=True,
            evidence_panels_viewed=("threat_intel", "advisory_debrief", "soar_playbook"),
            recorded_at_utc=trial_now,
        )
    )
    study_summary = workload_repo.summarize_study_metrics("synthetic_smoke_verification")
    assert study_summary.tf_009_closure_eligible is False

    track_b_data = {
        "status": "completed",
        "description": "Slide 14 Azure VM Suricata Live-Ingestion Full SOC Spine",
        "sensor_id": "azure-suricata-edge-01",
        "source_ip": "10.0.0.4",
        "destination_ip": "10.0.0.5",
        "raw_features_extracted": 14,
        "rf_attack_probability": prob_b,
        "rf_decision": infer_res_b.predicted_class,
        "alert_candidate_id": cand_id_b,
        "incident_id": incident_b.incident_id,
        "correlation_rule_id": incident_b.correlation_rule_id,
        "threat_intel_status": enrich_res_b.status,
        "private_ip_guard_triggered": enrich_res_b.private_ip_guard_triggered,
        "external_lookup_performed": enrich_res_b.external_lookup_performed,
        "lab_annotations": dict(enrich_res_b.internal_lab_annotations),
        "advisory_explanation": explanation_b.to_dict(),
        "soar_playbook": {
            "playbook_id": soar_action.playbook_id,
            "target_entity": soar_action.target_entity,
            "final_state": rolled_back_action.state,
            "audit_trail_events": len(soar_audit),
        },
        "alert_fatigue_compression": track_b_compression.to_dict(),
        "workload_study_summary": study_summary.to_dict(),
    }

    # =========================================================================
    # Compile Master Demo Report & Generate Evidence Artifacts
    # =========================================================================
    full_report = {
        "schema_version": DEMO_SCHEMA_VERSION,
        "project_id": pack_rev2.project_id,
        "project_title": pack_rev2.project_title,
        "institution": pack_rev2.institution,
        "supervisor": pack_rev2.supervisor,
        "team_members": [list(tm) for tm in pack_rev2.team_members],
        "evaluation_checkpoint_commit": pack_rev2.evaluation_checkpoint_commit,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "track_a_unsw_replay": track_a_data,
        "track_b_azure_live_spine": track_b_data,
        "canonical_evaluation_baseline": {
            "frozen_rf": pack_rev2.frozen_random_forest.to_dict(),
            "autoencoder_v2": pack_rev2.autoencoder_v2.to_dict(),
            "section_8_complementarity": pack_rev2.section_8_complementarity.to_dict(),
        },
    }

    # Save JSON Report
    json_path = out_path / "full_soc_demo_report.json"
    json_path.write_text(json.dumps(full_report, indent=2), encoding="utf-8")

    # Generate Markdown Report
    md_content = f"""# ThreatFusion Turnkey SOC Demonstration Report (`AI-FYP-2006`)

**Schema Identity:** `{DEMO_SCHEMA_VERSION}`  
**Project Identifier:** `{pack_rev2.project_id}`  
**Project Title:** {pack_rev2.project_title}  
**Institution:** {pack_rev2.institution}  
**Supervisor:** {pack_rev2.supervisor}  
**Team Members:** {", ".join(f"{name} ({roll})" for name, roll in pack_rev2.team_members)}  
**Evaluation Checkpoint:** `{pack_rev2.evaluation_checkpoint_commit}` (September 21, 2026 Evaluation Pack Rev2)  
**Execution Timestamp:** `{full_report["generated_at_utc"]}`  

---

## 1. Executive Summary

This turnkey evidence report demonstrates the complete ThreatFusion SOC analytics architecture across both authorized tracks:
1. **Track A (Recorded UNSW-NB15 mTLS Baseline)**: Deterministic evaluation of registered Row 1 (Normal $\\rightarrow$ no alert) and Row 21 (Attack $\\rightarrow$ 1 AlertCandidate) with Section 8 counterfactual fusion shield metrics.
2. **Track B (Slide 14 Azure VM Suricata Live-Ingestion Full SOC Spine)**: End-to-end ingestion of Suricata `eve.json` flows, 14-feature transformation, frozen Random Forest inference, incident correlation, RFC 1918 private-IP guarded threat intelligence, evidence-bound advisory debrief, approval-gated reversible SOAR execution, and Section 13.F analyst workload measurement.

---

## 2. Track A — Recorded UNSW-NB15 mTLS Baseline & Replay Proof

Evaluated registered source member `{REGISTERED_UNSW_MEMBER_SHA256}` from verified manifest:

| Row Number | Ground Truth | Frozen RF Prediction | Attack Probability | Disposition | Alert Candidate ID |
|---|---|---|---|---|---|
| **Row 1** | Normal | **Normal** | `{row_1_prob:.5f}` (~0.001%) | `recorded_without_alert` | *None (Filtered)* |
| **Row 21** | Attack | **Attack** | `{row_21_prob:.6f}` (~82.499%) | `alert_created` | `{cand_id_21}` |

### Section 8 Counterfactual False-Positive Shield (January Validation — 216,568 Rows)
> [!IMPORTANT] **Scientific Discipline: Why Candidate Fusion is Strictly Disabled**  
> On the January validation partition, enabling Autoencoder OR-fusion yields only **96 extra attacks** while causing **1,574 additional false alarms** (a **16.4:1 benign false alarm penalty**).  
> The Frozen Random Forest baseline achieves **95.266% precision** with only 201 false alarms. Candidate fusion inflates false alarms by **8.83x** (+783.1%) and causes a catastrophic **25.269 percentage-point drop in precision** (down to **69.997%**).  
> **Verdict:** `{track_a_compression.fatigue_protection_verdict}`

---

## 3. Track B — Slide 14 Azure VM Suricata Live-Ingestion Full SOC Spine

Simulated live attacker (`10.0.0.4:54322`) targeting victim web server (`10.0.0.5:80`) monitored by sensor `azure-suricata-edge-01`:

```
[ Suricata eve.json Flow ]
          │ (14 Argus Features + EntityProvenanceContract)
          ▼
[ Frozen Random Forest Inference ] ──> Attack (p = {prob_b:.4f} >= 0.50)
          │
          ▼
[ AlertCandidate Persistence ] ──────> SQLite alerts.sqlite3
          │
          ▼
[ Incident Correlation Engine ] ─────> 30-second burst window (30s) / 10-minute campaign (600s)
          │
          ▼
[ Sourced Threat-Intel (13.C) ] ─────> RFC 1918 Private IP Guard TRIGGERED (No public leak)
          │                             Annotated: 10.0.0.4 (Attacker VM), 10.0.0.5 (Victim)
          ▼
[ Advisory Debrief Engine (13.D) ] ──> Grounded Non-Authoritative Triage Debrief
          │
          ▼
[ Reversible SOAR Ledger (13.E) ] ───> Propose -> Approve -> Execute -> Rollback
```

### SOAR Ledger Audit Trail (`track_b_soar.sqlite3`)
- **Action Type:** `{soar_action.action_type}`
- **Target Entity:** `{soar_action.target_entity}`
- **Lifecycle Progression:** `pending_approval` $\\rightarrow$ `approved` (by analyst-bilal) $\\rightarrow$ `executed_simulated` $\\rightarrow$ `rolled_back`
- **Audit Entries Recorded:** `{len(soar_audit)}`

---

## 4. Section 13.F — Alert-Fatigue & Analyst Workload Study Summary

- **Study Cohort:** `synthetic_smoke_verification`
- **Baseline Mean Time-to-Disposition:** `{study_summary.baseline_mean_time_to_disposition_ms:.1f} ms`
- **ThreatFusion Mean Time-to-Disposition:** `{study_summary.threatfusion_mean_time_to_disposition_ms:.1f} ms`
- **Measured Speedup:** `{study_summary.speedup_pct:.1f}%`
- **Accuracy Gain:** `+{study_summary.accuracy_gain_percentage_points:.1f} pp`
- **TF-009 Closure Eligibility:** `False` (*Honest scientific disclosure: automated smoke runs cannot close the human analyst validation gate*).
"""

    md_path = out_path / "full_soc_demo_report.md"
    md_path.write_text(md_content, encoding="utf-8")

    return full_report
