"""Consolidated authoritative unit tests for B.L.A.S.T. Architecture Hardening (Milestone #28 & #29).

Covers:
1. Resilient Suricata EVE stream ingestion with mixed corrupted JSON, non-flow events,
   schema-invalid flows, and valid attack flows without crashing or halting stream processing.
2. Dead-letter quarantine record serialization and max dead-letter cap behavior.
3. CloudBudgetKillSwitchPolicy deterministic behavior ($5.00 shutoff, negative/NaN/Inf spend fail-closed, $2.50 normal).
4. CLI execution for run_cloud_suricata_forwarder.py (JSON, text, budget check, file input).
5. Outage-isolated GeminiAdvisoryCallable defaults, prompt serialization, flow-only empty IPs,
   grounded generation ("verified_local_llm_advisory"), anti-hallucination rejection of uncited keys
   and hallucinated IPs ("203.0.113.99"), missing API key, transport timeouts, and detection loop immutability.
6. Analyst dashboard HTML rendering data-blast-ui-tier="unicorn-progressive-disclosure-v1",
   secondary unfused v2 autoencoder badge, and on-disk SOP existence for Unicorn SOC and BLAST 3-layer architecture.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

import pytest

from threatfusion.advisory import (
    AdvisoryEvidenceBundle,
    AdvisoryExplanationEngine,
    GeminiAdvisoryCallable,
    GeminiAdvisoryConfig,
    GeminiAdvisoryUnavailableError,
    build_grounded_gemini_prompt,
    verify_explanation_groundedness,
)
from threatfusion.api.analyst_dashboard import (
    DashboardAlertDetail,
    DashboardAlertQueue,
    DashboardSnapshot,
    render_dashboard_html,
)
from threatfusion.enrichment.threat_intel import ThreatIntelEnrichmentResult
from threatfusion.operations.cloud_live_telemetry import (
    CloudBudgetKillSwitchPolicy,
    DeadLetterQuarantineRecord,
    SuricataStreamBatchReport,
    evaluate_budget_kill_switch,
    process_suricata_eve_stream_resilient,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import run_cloud_suricata_forwarder as forwarder_cli  # noqa: E402


def _make_valid_suricata_flow(
    *,
    src_ip: str = "10.0.0.4",
    dest_ip: str = "10.0.0.5",
    src_port: int = 44120,
    dest_port: int = 80,
    proto: str = "TCP",
    pkts_toserver: int = 15,
    pkts_toclient: int = 12,
    bytes_toserver: int = 1250,
    bytes_toclient: int = 4800,
    start: str = "2026-10-18T10:00:00.000000+00:00",
    end: str = "2026-10-18T10:00:01.500000+00:00",
) -> dict[str, Any]:
    """Helper creating a schema-valid Suricata eve.json flow event."""
    return {
        "timestamp": start,
        "event_type": "flow",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "app_proto": "http",
        "flow_id": 98765432101234,
        "flow": {
            "pkts_toserver": pkts_toserver,
            "pkts_toclient": pkts_toclient,
            "bytes_toserver": bytes_toserver,
            "bytes_toclient": bytes_toclient,
            "start": start,
            "end": end,
            "age": 1.5,
            "state": "closed",
            "reason": "shutdown",
            "alerted": False,
        },
    }


class TestBlastResilienceAndCloudBudgetKillSwitch:
    """Tests for resilient ingestion and $0 cloud budget kill-switch."""

    def test_stream_ingestion_resilience_and_quarantine_counters(self) -> None:
        """Stream with mixed corrupted JSON, stats/dns events, invalid schemas, and valid flows produces exact counters."""
        flow_1 = json.dumps(_make_valid_suricata_flow(src_port=10001))
        flow_2 = json.dumps(_make_valid_suricata_flow(src_port=10002))

        # Non-flow events (stats, dns)
        stats_event = json.dumps(
            {
                "timestamp": "2026-10-18T10:00:00+00:00",
                "event_type": "stats",
                "stats": {"uptime": 120},
            }
        )
        dns_event = json.dumps(
            {
                "timestamp": "2026-10-18T10:00:00+00:00",
                "event_type": "dns",
                "dns": {"query": "example.com"},
            }
        )

        # Corrupted JSON lines
        corrupted_json_1 = "   {truncated_json_object: true, "
        corrupted_json_2 = "NOT_JSON_AT_ALL!!!"

        # Non-dict JSON
        non_dict_json = "[1, 2, 3]"

        # Schema-invalid flow events (bad IP, negative packets)
        bad_ip_flow = json.dumps(_make_valid_suricata_flow(src_ip="999.999.999.999"))
        negative_pkts_flow = json.dumps(_make_valid_suricata_flow(pkts_toserver=-5))

        stream = [
            "",  # Ignored blank
            flow_1,  # Valid flow 1
            "   \n",  # Ignored blank
            stats_event,  # Non-flow skipped 1
            corrupted_json_1,  # Dead letter 1: malformed_json_line
            dns_event,  # Non-flow skipped 2
            flow_2,  # Valid flow 2
            non_dict_json,  # Dead letter 2: schema_validation_failed
            bad_ip_flow,  # Dead letter 3: schema_validation_failed
            corrupted_json_2,  # Dead letter 4: malformed_json_line
            negative_pkts_flow,  # Dead letter 5: schema_validation_failed
        ]

        report = process_suricata_eve_stream_resilient(stream, max_dead_letters=10)

        # Verify exact counters without raising
        assert report.total_lines_read == 11
        assert report.non_flow_events_skipped == 2
        assert report.valid_flows_adapted == 2
        assert report.dead_letter_count == 5
        assert len(report.dead_letter_records) == 5
        assert len(report.adapted_results) == 2

        # Verify dead letter records structure
        codes = [r.error_code for r in report.dead_letter_records]
        assert codes == [
            "malformed_json_line",
            "schema_validation_failed",
            "schema_validation_failed",
            "malformed_json_line",
            "schema_validation_failed",
        ]

    def test_dead_letter_quarantine_record_and_report_serialization(self) -> None:
        """Verify DeadLetterQuarantineRecord and SuricataStreamBatchReport dictionary serialization."""
        record = DeadLetterQuarantineRecord(
            line_number=42,
            error_code="schema_validation_failed",
            error_detail="Invalid destination port",
            raw_excerpt='{"dest_port": 99999}',
            recorded_at_utc="2026-10-18T10:00:00.000000+00:00",
        )
        d = record.to_dict()
        assert d["line_number"] == 42
        assert d["error_code"] == "schema_validation_failed"
        assert d["raw_excerpt"] == '{"dest_port": 99999}'

        report = SuricataStreamBatchReport(
            total_lines_read=10,
            non_flow_events_skipped=3,
            valid_flows_adapted=5,
            dead_letter_count=2,
            dead_letter_records=(record,),
            adapted_results=(),
            provenance_verified_count=5,
        )
        rd = report.to_dict()
        assert rd["total_lines_read"] == 10
        assert rd["valid_flows_adapted"] == 5
        assert rd["provenance_verified_count"] == 5
        assert rd["dead_letter_count"] == 2
        assert len(rd["dead_letter_records"]) == 1

    def test_process_suricata_eve_stream_clock_unsynced_and_cap(self) -> None:
        """Verify stream processor handles unsynchronized clocks and enforces max_dead_letters cap."""
        valid_flow = json.dumps(_make_valid_suricata_flow())
        bad_line = "{bad"

        lines = [bad_line] * 10 + [valid_flow]

        report = process_suricata_eve_stream_resilient(
            lines,
            sensor_namespace="test-sensor-02",
            clock_synced=False,
            max_dead_letters=3,
        )

        assert report.total_lines_read == 11
        assert report.valid_flows_adapted == 1
        assert report.provenance_verified_count == 0
        assert report.dead_letter_count == 10
        assert len(report.dead_letter_records) == 3

    def test_cloud_budget_kill_switch_policy_thresholds(self) -> None:
        """CloudBudgetKillSwitchPolicy triggers detach_billing=True at $5.00 and on negative spend, False at $2.50."""
        policy = CloudBudgetKillSwitchPolicy()

        # At $5.00: Must trigger hard shutoff
        res_500 = evaluate_budget_kill_switch(5.00, policy)
        assert res_500["should_detach_billing"] is True
        assert res_500["kill_switch_triggered"] is True
        assert res_500["status"] == "triggered_threshold_exceeded"
        assert res_500["gross_spend_usd"] == 5.00
        assert res_500["remaining_safe_budget_usd"] == 0.0

        # Beyond $5.00 (e.g. $7.25): Must trigger hard shutoff
        res_725 = evaluate_budget_kill_switch(7.25, policy)
        assert res_725["should_detach_billing"] is True
        assert res_725["kill_switch_triggered"] is True

        # At $2.50: Safe budget, should NOT detach
        res_250 = evaluate_budget_kill_switch(2.50, policy)
        assert res_250["should_detach_billing"] is False
        assert res_250["kill_switch_triggered"] is False
        assert res_250["status"] == "normal"
        assert res_250["gross_spend_usd"] == 2.50
        assert res_250["remaining_safe_budget_usd"] == 2.50

        # At $0.00: Safe budget
        res_zero = evaluate_budget_kill_switch(0.00, policy)
        assert res_zero["should_detach_billing"] is False
        assert res_zero["remaining_safe_budget_usd"] == 5.00

        # Negative spend (e.g. -$0.01, -$5.00): Fail-closed immediately on corrupted telemetry
        res_neg = evaluate_budget_kill_switch(-0.01, policy)
        assert res_neg["should_detach_billing"] is True
        assert res_neg["kill_switch_triggered"] is True
        assert res_neg["status"] == "triggered_fail_closed"
        assert "Fail-closed: malformed or negative spend" in res_neg["reason"]

    def test_evaluate_budget_kill_switch_malformed_nan_inf_spend(self) -> None:
        """Verify fail-closed handling on NaN and Inf spend amounts."""
        policy = CloudBudgetKillSwitchPolicy()

        res_nan = evaluate_budget_kill_switch(float("nan"), policy)
        assert res_nan["should_detach_billing"] is True
        assert res_nan["status"] == "triggered_fail_closed"

        res_inf = evaluate_budget_kill_switch(float("inf"), policy)
        assert res_inf["should_detach_billing"] is True
        assert res_inf["status"] == "triggered_fail_closed"

    def test_forwarder_cli_budget_check_json_and_text(self, capsys: pytest.CaptureFixture) -> None:
        """Verify forwarder CLI --budget-check in JSON and text formats."""
        code_json = forwarder_cli.main(["--budget-check", "3.00", "--format", "json"])
        assert code_json == 0
        captured_json = capsys.readouterr().out
        data = json.loads(captured_json)
        assert data["status"] == "success"
        assert data["budget_kill_switch"]["should_detach_billing"] is False
        assert data["budget_kill_switch"]["gross_spend_usd"] == 3.0

        code_text = forwarder_cli.main(["--budget-check", "5.25", "--format", "text"])
        assert code_text == 0
        captured_text = capsys.readouterr().out
        assert "ThreatFusion Cloud Suricata EVE Live Telemetry Forwarder Report" in captured_text
        assert "Should Detach Billing:   True" in captured_text
        assert "Gross Spend:             $5.25 USD" in captured_text

        code_fail = forwarder_cli.main(["--budget-check", "6.00", "--fail-on-kill-switch"])
        assert code_fail == 2
        captured_fail = capsys.readouterr().out
        data_fail = json.loads(captured_fail)
        assert data_fail["budget_kill_switch"]["should_detach_billing"] is True

    def test_forwarder_cli_file_input(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """Verify forwarder CLI file stream ingestion."""
        test_file = tmp_path / "suricata_test.json"
        valid_record = _make_valid_suricata_flow(src_port=55110)
        test_file.write_text(f"{json.dumps(valid_record)}\n{{invalid_json\n", encoding="utf-8")

        code = forwarder_cli.main(
            [
                str(test_file),
                "--sensor-namespace",
                "cli-test-sensor",
                "--format",
                "json",
            ]
        )
        assert code == 0
        captured = capsys.readouterr().out
        res = json.loads(captured)
        report = res["telemetry_batch_report"]
        assert report["total_lines_read"] == 2
        assert report["valid_flows_adapted"] == 1
        assert report["dead_letter_count"] == 1
        assert len(report["dead_letter_records"]) == 1
        assert report["dead_letter_records"][0]["error_code"] == "malformed_json_line"


class TestGeminiAdvisoryGroundednessAndOutageIsolation:
    """Tests for outage-isolated Gemini Advisory Engine and Anti-Hallucination verification."""

    @pytest.fixture
    def bundle_for_advisory(self) -> AdvisoryEvidenceBundle:
        return AdvisoryEvidenceBundle(
            candidate_id="alert_cand_m28_01",
            record_id="rec_suricata_flow_42",
            rf_model_version="full-network-random-forest-6d69c72-v1",
            rf_attack_probability=0.8850,
            rf_threshold=0.50,
            top_feature_signals={"sbytes": 2048.0, "dbytes": 8192.0, "rate": 65.0},
            ae_v2_reconstruction_error=0.135,
            ae_v2_threshold=0.118136,
            incident_id="incident_m28_burst_01",
            correlation_status="corr_burst_5tuple_30s_v1",
            enrichment_result=ThreatIntelEnrichmentResult(
                status="internal_lab_entity_annotated",
                provenance_verified=True,
                external_lookup_performed=False,
                private_ip_guard_triggered=True,
                inspected_entities=("10.0.0.4", "10.0.0.5"),
                internal_lab_annotations={"10.0.0.4": "azure_lab_attacker_vm"},
                matches=(),
                feed_snapshot_id=None,
                reason="Internal lab annotated entity",
            ),
            observed_at="2026-10-18T10:00:00Z",
        )

    def test_gemini_config_defaults_and_endpoint_url(self) -> None:
        """Verify GeminiAdvisoryConfig default fields and parameterized URL formulation."""
        config = GeminiAdvisoryConfig()
        assert config.model_name == "gemini-2.5-flash"
        assert config.timeout_seconds == 5.0
        assert config.max_output_tokens == 512
        assert config.api_key_env_var == "GEMINI_API_KEY"

        url = config.get_endpoint_url("secret_test_key")
        assert "gemini-2.5-flash" in url
        assert "key=secret_test_key" in url

    def test_build_grounded_gemini_prompt_serialization(
        self, bundle_for_advisory: AdvisoryEvidenceBundle
    ) -> None:
        """Verify prompt builder embeds only verified bundle attributes with anti-hallucination rules."""
        prompt = build_grounded_gemini_prompt(bundle_for_advisory)

        assert "alert_cand_m28_01" in prompt
        assert "rec_suricata_flow_42" in prompt
        assert "2026-10-18T10:00:00Z" in prompt
        assert "full-network-random-forest-6d69c72-v1" in prompt
        assert "0.8850" in prompt
        assert "10.0.0.4" in prompt
        assert "10.0.0.5" in prompt
        assert "NO IP ADDRESS HALLUCINATIONS" in prompt
        assert "SECTION 8 INVARIANT" in prompt
        assert "PURE JSON ONLY" in prompt

    def test_build_grounded_gemini_prompt_flow_only_empty_ips(self) -> None:
        """Verify prompt builder handles flow-only bundles without enrichment cleanly."""
        flow_only_bundle = AdvisoryEvidenceBundle(
            candidate_id="alert_candidate_v1:flow_only_01",
            record_id="rec_unsw_flow_99",
            rf_model_version="full-network-random-forest-6d69c72-v1",
            rf_attack_probability=0.7600,
            rf_threshold=0.50,
            top_feature_signals={"dur": 0.45, "rate": 22.0},
            enrichment_result=None,
        )
        prompt = build_grounded_gemini_prompt(flow_only_bundle)

        assert "alert_candidate_v1:flow_only_01" in prompt
        assert '"allowed_ip_entities": []' in prompt
        assert "Entity provenance unverified; no IP addresses inspected" in prompt

    def test_gemini_advisory_succeeds_on_grounded_mock_json(
        self, bundle_for_advisory: AdvisoryEvidenceBundle
    ) -> None:
        """GeminiAdvisoryCallable succeeds on grounded mock JSON returning verified_local_llm_advisory."""

        def grounded_transport(endpoint_url: str, payload: dict[str, Any]) -> dict[str, Any]:
            response_json = {
                "summary_headline": "SOC Triage Debrief: Candidate alert_cand_m28_01",
                "detection_rationale": (
                    "The frozen Random Forest model (full-network-random-forest-6d69c72-v1) "
                    "scored 0.8850, exceeding the 0.50 decision threshold."
                ),
                "complementarity_and_fusion_note": (
                    "Production alert authority rests solely on Random Forest. "
                    "Production fusion is disabled per Section 8."
                ),
                "correlation_and_enrichment_context": (
                    "Consolidated in incident_m28_burst_01 under corr_burst_5tuple_30s_v1. "
                    "Inspected entities: 10.0.0.4, 10.0.0.5."
                ),
                "recommended_analyst_checks": [
                    "Inspect port 80 listener on 10.0.0.5",
                    "Verify packet capture on 10.0.0.4",
                ],
                "cited_evidence_keys": [
                    "candidate_id",
                    "record_id",
                    "rf_model_version",
                    "rf_attack_probability",
                    "rf_threshold",
                    "correlation_status",
                    "incident_id",
                    "entity:10.0.0.4",
                    "entity:10.0.0.5",
                ],
            }
            return {
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": json.dumps(response_json)}],
                        }
                    }
                ]
            }

        client = GeminiAdvisoryCallable(transport_callable=grounded_transport)
        explanation = AdvisoryExplanationEngine.generate_explanation(
            bundle_for_advisory,
            optional_llm_callable=client,
        )

        assert explanation.generation_mode == "verified_local_llm_advisory"
        assert explanation.advisory_only_non_authoritative is True
        assert explanation.groundedness_verified is True
        assert "0.8850" in explanation.detection_rationale
        assert "10.0.0.4" in explanation.correlation_and_enrichment_context
        assert "full-network-random-forest-6d69c72-v1" in explanation.detection_rationale

    def test_gemini_advisory_falls_back_when_hallucinated_ip_injected(
        self, bundle_for_advisory: AdvisoryEvidenceBundle
    ) -> None:
        """When hallucinated IP (203.0.113.99) is injected, AdvisoryExplanationEngine falls back to deterministic template."""

        def hallucinating_transport(endpoint_url: str, payload: dict[str, Any]) -> dict[str, Any]:
            response_json = {
                "summary_headline": "SOC Triage Debrief: Candidate alert_cand_m28_01",
                "detection_rationale": "Model full-network-random-forest-6d69c72-v1 scored 0.8850.",
                "complementarity_and_fusion_note": "Production alert authority on Random Forest; fusion is disabled.",
                "correlation_and_enrichment_context": "Attacker observed from external IP 203.0.113.99 targeting host.",
                "recommended_analyst_checks": ["Block 203.0.113.99 on firewall"],
                "cited_evidence_keys": [
                    "candidate_id",
                    "record_id",
                    "rf_model_version",
                    "rf_attack_probability",
                ],
            }
            return {
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": json.dumps(response_json)}],
                        }
                    }
                ]
            }

        client = GeminiAdvisoryCallable(transport_callable=hallucinating_transport)
        raw_exp = client(bundle_for_advisory)

        # Groundedness verifier MUST reject the hallucinated IP
        assert verify_explanation_groundedness(raw_exp, bundle_for_advisory) is False

        # Explanation engine MUST catch and fall back to deterministic template
        safe_exp = AdvisoryExplanationEngine.generate_explanation(
            bundle_for_advisory,
            optional_llm_callable=client,
        )
        assert safe_exp.generation_mode == "deterministic_evidence_template"
        assert safe_exp.groundedness_verified is True
        assert "203.0.113.99" not in safe_exp.correlation_and_enrichment_context

    def test_llm_uncited_evidence_key_rejected_and_falls_back(
        self, bundle_for_advisory: AdvisoryEvidenceBundle
    ) -> None:
        """When an uncited or disallowed evidence key is returned, engine falls back to deterministic template."""

        def invalid_key_transport(endpoint_url: str, payload: dict[str, Any]) -> dict[str, Any]:
            response_json = {
                "summary_headline": "Probe detected",
                "detection_rationale": "Model full-network-random-forest-6d69c72-v1 scored 0.8850.",
                "complementarity_and_fusion_note": "Authority on Random Forest; fusion is disabled.",
                "correlation_and_enrichment_context": "Correlation context ok.",
                "recommended_analyst_checks": ["Check logs"],
                "cited_evidence_keys": [
                    "candidate_id",
                    "unapproved_external_telemetry_source",
                ],
            }
            return {
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": json.dumps(response_json)}],
                        }
                    }
                ]
            }

        client = GeminiAdvisoryCallable(transport_callable=invalid_key_transport)
        candidate_exp = client(bundle_for_advisory)
        assert verify_explanation_groundedness(candidate_exp, bundle_for_advisory) is False

        safe_exp = AdvisoryExplanationEngine.generate_explanation(
            bundle_for_advisory,
            optional_llm_callable=client,
        )
        assert safe_exp.generation_mode == "deterministic_evidence_template"

    def test_gemini_advisory_falls_back_when_api_key_missing(
        self, monkeypatch: pytest.MonkeyPatch, bundle_for_advisory: AdvisoryEvidenceBundle
    ) -> None:
        """When GEMINI_API_KEY is unset, client raises GeminiAdvisoryUnavailableError and engine falls back cleanly."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        client = GeminiAdvisoryCallable()

        with pytest.raises(GeminiAdvisoryUnavailableError, match="unset or empty"):
            client(bundle_for_advisory)

        safe_exp = AdvisoryExplanationEngine.generate_explanation(
            bundle_for_advisory,
            optional_llm_callable=client,
        )
        assert safe_exp.generation_mode == "deterministic_evidence_template"
        assert safe_exp.groundedness_verified is True

    def test_gemini_advisory_falls_back_when_transport_times_out(
        self, bundle_for_advisory: AdvisoryEvidenceBundle
    ) -> None:
        """When transport callable raises TimeoutError, client raises GeminiAdvisoryUnavailableError and engine falls back cleanly."""

        def timeout_transport(endpoint_url: str, payload: dict[str, Any]) -> dict[str, Any]:
            raise TimeoutError("REST request timed out after 5.0 seconds")

        client = GeminiAdvisoryCallable(transport_callable=timeout_transport)

        with pytest.raises(GeminiAdvisoryUnavailableError, match="timed out"):
            client(bundle_for_advisory)

        safe_exp = AdvisoryExplanationEngine.generate_explanation(
            bundle_for_advisory,
            optional_llm_callable=client,
        )
        assert safe_exp.generation_mode == "deterministic_evidence_template"
        assert safe_exp.groundedness_verified is True

    def test_outage_isolation_preserves_detection_loop_integrity(
        self, bundle_for_advisory: AdvisoryEvidenceBundle
    ) -> None:
        """Verifies that whether Gemini succeeds, errors, or hallucinates, primary detection is untouched."""
        orig_prob = bundle_for_advisory.rf_attack_probability
        orig_threshold = bundle_for_advisory.rf_threshold
        orig_candidate_id = bundle_for_advisory.candidate_id

        client = GeminiAdvisoryCallable(
            transport_callable=lambda u, p: {
                "candidates": [{"content": {"parts": [{"text": "invalid json"}]}}]
            }
        )

        safe_exp = AdvisoryExplanationEngine.generate_explanation(
            bundle_for_advisory,
            optional_llm_callable=client,
        )

        assert safe_exp.generation_mode == "deterministic_evidence_template"
        assert bundle_for_advisory.rf_attack_probability == orig_prob
        assert bundle_for_advisory.rf_threshold == orig_threshold
        assert bundle_for_advisory.candidate_id == orig_candidate_id


class TestUnicornSOCInterfaceVisualHierarchy:
    """Tests for Unicorn Progressive Disclosure and Section 8 badge in Analyst Dashboard HTML & SOP documentation."""

    def test_analyst_dashboard_html_renders_unicorn_tier_and_unfused_ae_badge(self) -> None:
        """Analyst dashboard detail card renders data-blast-ui-tier and secondary unfused AE badge."""
        detail = DashboardAlertDetail(
            alert_candidate_id="alert_cand_m28_unicorn_01",
            source_event_id="src_event_unicorn_01",
            observed_at="2026-10-18T10:00:00Z",
            created_at="2026-10-18T10:00:01Z",
            source_representation_identity="azure.victim_vm.suricata.eve_flow.v1",
            feature_contract_identity="network_behavior_v1",
            model_identity="network_random_forest",
            model_version="full-network-random-forest-6d69c72-v1",
            model_artifact_sha256="bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
            uncalibrated_model_score=0.9125,
            decision_threshold=0.50,
            decision_policy_version="rf_baseline_v1",
            decision="attack",
            state="new",
            version=0,
            updated_at=None,
            updated_by=None,
            last_transition_id=None,
            history=(),
        )

        queue = DashboardAlertQueue(items=(), total_loaded=0, limit=10, offset=0)
        snapshot = DashboardSnapshot(queue=queue, selected=detail, status="active")

        html = render_dashboard_html(snapshot)

        # 1. Tier 1 / Progressive Disclosure Card Attribute
        assert 'data-blast-ui-tier="unicorn-progressive-disclosure-v1"' in html

        # 2. Tier 2 Secondary Anomaly Indicator Badge (Section 8 fusion disabled)
        assert "badge-secondary-anomaly" in html
        assert (
            "Secondary Anomaly Indicator (Unfused v2 Autoencoder — Section 8 Fusion Disabled)"
            in html
        )

        # 3. CSS styling for the secondary anomaly badge
        assert ".badge-secondary-anomaly" in html

    def test_soc_unicorn_interface_sop_exists_and_covers_all_tiers(self) -> None:
        """Verify design_guidelines/soc_unicorn_interface_sop.md exists and specifies the 3-Tier standard."""
        sop_file = REPO_ROOT / "design_guidelines" / "soc_unicorn_interface_sop.md"
        assert sop_file.exists(), "design_guidelines/soc_unicorn_interface_sop.md must exist"

        content = sop_file.read_text(encoding="utf-8")
        assert "SOP-UX-SOC-001" in content
        assert 'data-blast-ui-tier="unicorn-progressive-disclosure-v1"' in content
        assert "95.266%" in content
        assert "0.095%" in content
        assert "16.3958" in content or "16.4:1" in content
        assert "full-network-random-forest-6d69c72-v1" in content
        assert "full-benign-autoencoder-2a51c94-v2" in content
        assert "badge-secondary-anomaly" in content
        assert "cited_evidence_keys" in content
        assert "pending_approval" in content
        assert "executed_simulated" in content
        assert "rolled_back" in content
        assert (
            "TF-008" in content
            and "TF-009" in content
            and "TF-010" in content
            and "TF-011" in content
        )

    def test_blast_3layer_architecture_sop_exists_and_documents_all_layers(self) -> None:
        """Verify docs/blast_3layer_architecture_sop.md exists and documents the 3 deterministic layers."""
        sop_file = REPO_ROOT / "docs" / "blast_3layer_architecture_sop.md"
        assert sop_file.exists(), "docs/blast_3layer_architecture_sop.md must exist"

        content = sop_file.read_text(encoding="utf-8")
        assert "SOP-ARCH-BLAST-001" in content
        assert "Layer 1: Architecture SOPs & Constitutional Policies" in content
        assert "Layer 2: Deterministic Pipeline Navigation" in content
        assert "Layer 3: Atomic Deterministic Tools" in content
        assert "production_fusion_enabled = False" in content
        assert "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9" in content
        assert "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23" in content
        assert "cited_evidence_keys" in content
        assert "Deterministic Template Fallback" in content
        assert "SuricataFlowAdapter" in content
