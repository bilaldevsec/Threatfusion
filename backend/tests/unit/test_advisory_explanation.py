"""Unit tests for Outage-Isolated Gemini Advisory Client and Grounded Debrief Engine.

Enforces Section 13.D of ThreatFusion:
- Grounded prompt formulation serializing only verified evidence.
- Anti-hallucination verification (IP guards, exact RF probability/version, Section 8 invariant).
- Outage isolation: Network errors, timeouts, missing API keys, or invalid JSON fail closed
  to deterministic evidence template.
- Detection loop isolation: Primary detection scores and alerts remain completely unmodified.
"""

from __future__ import annotations

import json
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
from threatfusion.enrichment.threat_intel import ThreatIntelEnrichmentResult


@pytest.fixture
def sample_bundle_with_enrichment() -> AdvisoryEvidenceBundle:
    return AdvisoryEvidenceBundle(
        candidate_id="alert_candidate_v1:9f8e7d6c5b4a",
        record_id="rec_unsw_0042",
        rf_model_version="full-network-random-forest-6d69c72-v1",
        rf_attack_probability=0.824988,
        rf_threshold=0.50,
        top_feature_signals={"sbytes": 1024.0, "dbytes": 4096.0, "rate": 50.0},
        ae_v2_reconstruction_error=0.142,
        ae_v2_threshold=0.118136,
        incident_id="incident_v1:123456",
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


@pytest.fixture
def sample_flow_only_bundle() -> AdvisoryEvidenceBundle:
    return AdvisoryEvidenceBundle(
        candidate_id="alert_candidate_v1:flow_only_01",
        record_id="rec_unsw_flow_99",
        rf_model_version="full-network-random-forest-6d69c72-v1",
        rf_attack_probability=0.7600,
        rf_threshold=0.50,
        top_feature_signals={"dur": 0.45, "rate": 22.0},
        enrichment_result=None,
    )


def test_gemini_config_defaults_and_endpoint_url() -> None:
    config = GeminiAdvisoryConfig()
    assert config.model_name == "gemini-2.5-flash"
    assert config.timeout_seconds == 5.0
    assert config.max_output_tokens == 512
    assert config.api_key_env_var == "GEMINI_API_KEY"

    url = config.get_endpoint_url("secret_test_key")
    assert "gemini-2.5-flash" in url
    assert "key=secret_test_key" in url


def test_build_grounded_gemini_prompt_serialization(
    sample_bundle_with_enrichment: AdvisoryEvidenceBundle,
) -> None:
    prompt = build_grounded_gemini_prompt(sample_bundle_with_enrichment)

    assert "alert_candidate_v1:9f8e7d6c5b4a" in prompt
    assert "rec_unsw_0042" in prompt
    assert "2026-10-18T10:00:00Z" in prompt
    assert "full-network-random-forest-6d69c72-v1" in prompt
    assert "0.8250" in prompt
    assert "10.0.0.4" in prompt
    assert "10.0.0.5" in prompt
    assert "NO IP ADDRESS HALLUCINATIONS" in prompt
    assert "SECTION 8 INVARIANT" in prompt
    assert "PURE JSON ONLY" in prompt


def test_build_grounded_gemini_prompt_flow_only_empty_ips(
    sample_flow_only_bundle: AdvisoryEvidenceBundle,
) -> None:
    prompt = build_grounded_gemini_prompt(sample_flow_only_bundle)

    assert "alert_candidate_v1:flow_only_01" in prompt
    assert '"allowed_ip_entities": []' in prompt
    assert "Entity provenance unverified; no IP addresses inspected" in prompt


def test_missing_or_empty_api_key_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    sample_bundle_with_enrichment: AdvisoryEvidenceBundle,
) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    client = GeminiAdvisoryCallable()

    with pytest.raises(GeminiAdvisoryUnavailableError, match="unset or empty"):
        client(sample_bundle_with_enrichment)

    # AdvisoryExplanationEngine automatically falls back to deterministic template
    safe_exp = AdvisoryExplanationEngine.generate_explanation(
        sample_bundle_with_enrichment,
        optional_llm_callable=client,
    )
    assert safe_exp.generation_mode == "deterministic_evidence_template"
    assert safe_exp.groundedness_verified is True


def test_mock_transport_success_returns_verified_llm_advisory(
    sample_bundle_with_enrichment: AdvisoryEvidenceBundle,
) -> None:
    def valid_transport(endpoint_url: str, payload: dict[str, Any]) -> dict[str, Any]:
        response_json = {
            "summary_headline": "SOC Triage Debrief: Candidate 9f8e7d6c5b4a",
            "detection_rationale": (
                "The frozen Random Forest model (full-network-random-forest-6d69c72-v1) "
                "scored 0.8250, exceeding threshold 0.50."
            ),
            "complementarity_and_fusion_note": (
                "Production alert authority rests solely on Random Forest. "
                "Production fusion is disabled per Section 8."
            ),
            "correlation_and_enrichment_context": (
                "Correlation status corr_burst_5tuple_30s_v1. Inspected entities: 10.0.0.4, 10.0.0.5."
            ),
            "recommended_analyst_checks": [
                "Verify sensor capture tap on 10.0.0.4",
                "Review surrounding flow events",
            ],
            "cited_evidence_keys": [
                "candidate_id",
                "record_id",
                "rf_model_version",
                "rf_attack_probability",
                "rf_threshold",
                "correlation_status",
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

    client = GeminiAdvisoryCallable(transport_callable=valid_transport)
    explanation = AdvisoryExplanationEngine.generate_explanation(
        sample_bundle_with_enrichment,
        optional_llm_callable=client,
    )

    assert explanation.generation_mode == "verified_local_llm_advisory"
    assert explanation.advisory_only_non_authoritative is True
    assert explanation.groundedness_verified is True
    assert "0.8250" in explanation.detection_rationale
    assert "10.0.0.4" in explanation.correlation_and_enrichment_context


def test_mock_transport_failure_falls_back_to_deterministic(
    sample_bundle_with_enrichment: AdvisoryEvidenceBundle,
) -> None:
    def failing_transport(endpoint_url: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise TimeoutError("Gemini API connection timed out after 5.0 seconds")

    client = GeminiAdvisoryCallable(transport_callable=failing_transport)

    with pytest.raises(GeminiAdvisoryUnavailableError, match="timed out"):
        client(sample_bundle_with_enrichment)

    safe_exp = AdvisoryExplanationEngine.generate_explanation(
        sample_bundle_with_enrichment,
        optional_llm_callable=client,
    )
    assert safe_exp.generation_mode == "deterministic_evidence_template"
    assert safe_exp.groundedness_verified is True


def test_llm_hallucinated_ip_rejected_and_falls_back(
    sample_flow_only_bundle: AdvisoryEvidenceBundle,
) -> None:
    def hallucinating_transport(endpoint_url: str, payload: dict[str, Any]) -> dict[str, Any]:
        response_json = {
            "summary_headline": "Probe detected",
            "detection_rationale": "Model full-network-random-forest-6d69c72-v1 scored 0.7600.",
            "complementarity_and_fusion_note": "Authority on Random Forest; fusion is disabled.",
            "correlation_and_enrichment_context": "Attacker IP 198.51.100.22 scanned host.",  # Hallucinated!
            "recommended_analyst_checks": ["Check logs"],
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
    candidate_exp = client(sample_flow_only_bundle)
    assert verify_explanation_groundedness(candidate_exp, sample_flow_only_bundle) is False

    safe_exp = AdvisoryExplanationEngine.generate_explanation(
        sample_flow_only_bundle,
        optional_llm_callable=client,
    )
    assert safe_exp.generation_mode == "deterministic_evidence_template"
    assert "198.51.100.22" not in safe_exp.correlation_and_enrichment_context


def test_llm_uncited_evidence_key_rejected_and_falls_back(
    sample_bundle_with_enrichment: AdvisoryEvidenceBundle,
) -> None:
    def invalid_key_transport(endpoint_url: str, payload: dict[str, Any]) -> dict[str, Any]:
        response_json = {
            "summary_headline": "Probe detected",
            "detection_rationale": "Model full-network-random-forest-6d69c72-v1 scored 0.8250.",
            "complementarity_and_fusion_note": "Authority on Random Forest; fusion is disabled.",
            "correlation_and_enrichment_context": "Correlation context ok.",
            "recommended_analyst_checks": ["Check logs"],
            "cited_evidence_keys": [
                "candidate_id",
                "unapproved_external_telemetry_source",
            ],  # Invalid key!
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
    candidate_exp = client(sample_bundle_with_enrichment)
    assert verify_explanation_groundedness(candidate_exp, sample_bundle_with_enrichment) is False

    safe_exp = AdvisoryExplanationEngine.generate_explanation(
        sample_bundle_with_enrichment,
        optional_llm_callable=client,
    )
    assert safe_exp.generation_mode == "deterministic_evidence_template"


def test_outage_isolation_preserves_detection_loop_integrity(
    sample_bundle_with_enrichment: AdvisoryEvidenceBundle,
) -> None:
    """Verifies that whether Gemini succeeds, errors, or hallucinates, primary detection is untouched."""
    orig_prob = sample_bundle_with_enrichment.rf_attack_probability
    orig_threshold = sample_bundle_with_enrichment.rf_threshold
    orig_candidate_id = sample_bundle_with_enrichment.candidate_id

    client = GeminiAdvisoryCallable(
        transport_callable=lambda u, p: {
            "candidates": [{"content": {"parts": [{"text": "invalid json"}]}}]
        }
    )

    safe_exp = AdvisoryExplanationEngine.generate_explanation(
        sample_bundle_with_enrichment,
        optional_llm_callable=client,
    )

    assert safe_exp.generation_mode == "deterministic_evidence_template"
    # Ensure bundle immutability and zero leakage to detection loop
    assert sample_bundle_with_enrichment.rf_attack_probability == orig_prob
    assert sample_bundle_with_enrichment.rf_threshold == orig_threshold
    assert sample_bundle_with_enrichment.candidate_id == orig_candidate_id
