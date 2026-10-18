"""Outage-Isolated Gemini Advisory Client Outside the Primary Detection Loop.

Enforces Section 13.D of ThreatFusion:
- Non-authoritative advisory SOC triage debrief generation using Google Gemini.
- Strictly outside the primary detection loop: never alters Random Forest
  attack probability, decision threshold, or alert candidate creation.
- Evidence groundedness: Only verified bundle fields are serialized into the prompt.
- Strict anti-hallucination instruction: No uninspected IP addresses, exact model
  version and probability match, Section 8 invariant (fusion disabled) affirmation,
  and citation keys strictly bounded to allowed evidence keys.
- Complete outage isolation: If GEMINI_API_KEY is unset, or if network/HTTP/timeout/JSON
  errors occur, raises GeminiAdvisoryUnavailableError so AdvisoryExplanationEngine
  fails closed to the deterministic evidence template.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from threatfusion.advisory.explanation_engine import (
    AdvisoryEvidenceBundle,
    EvidenceBoundExplanation,
)


@dataclass(frozen=True, slots=True)
class GeminiAdvisoryConfig:
    """Configuration for Gemini Advisory debrief client."""

    model_name: str = "gemini-2.5-flash"
    timeout_seconds: float = 5.0
    max_output_tokens: int = 512
    api_key_env_var: str = "GEMINI_API_KEY"
    endpoint_url_template: str = (
        "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
    )

    def get_endpoint_url(self, api_key: str) -> str:
        """Format the REST endpoint URL with the target model and API key."""
        return self.endpoint_url_template.format(model=self.model_name, key=api_key)


class GeminiAdvisoryUnavailableError(RuntimeError):
    """Raised when Gemini Advisory LLM service is unavailable, misconfigured, or unparseable."""


def build_grounded_gemini_prompt(bundle: AdvisoryEvidenceBundle) -> str:
    """Build a strictly grounded prompt for Gemini advisory debrief generation.

    Serializes ONLY verified factual fields from the bundle:
    - candidate_id, record_id, observed_at
    - rf_model_version, rf_attack_probability, rf_threshold, rf_decision
    - correlation info (incident_id, correlation_status) if present
    - threat intel enrichment info if present
    - top feature signals
    - autoencoder residual (advisory only)
    - allowed evidence keys and allowed IP entities
    """
    observed_at = getattr(bundle, "observed_at", None) or "unspecified_flow_timestamp"
    rf_decision = "attack" if bundle.rf_attack_probability >= bundle.rf_threshold else "benign"
    rf_prob_str = f"{bundle.rf_attack_probability:.4f}"
    allowed_keys = sorted(bundle.get_allowed_evidence_keys())

    inspected_entities: list[str] = []
    if bundle.enrichment_result and bundle.enrichment_result.inspected_entities:
        inspected_entities = list(bundle.enrichment_result.inspected_entities)

    correlation_data: dict[str, Any] = {
        "correlation_status": bundle.correlation_status,
        "incident_id": bundle.incident_id,
    }

    if bundle.enrichment_result is not None:
        enrichment_data: dict[str, Any] = {
            "status": bundle.enrichment_result.status,
            "reason": bundle.enrichment_result.reason,
            "provenance_verified": bundle.enrichment_result.provenance_verified,
            "private_ip_guard_triggered": bundle.enrichment_result.private_ip_guard_triggered,
            "external_lookup_performed": bundle.enrichment_result.external_lookup_performed,
            "inspected_entities": inspected_entities,
            "internal_lab_annotations": dict(bundle.enrichment_result.internal_lab_annotations),
        }
    else:
        enrichment_data = {
            "status": "uninspected_flow_only",
            "reason": "Entity provenance unverified; no IP addresses inspected.",
            "inspected_entities": [],
        }

    evidence_payload: dict[str, Any] = {
        "candidate_id": bundle.candidate_id,
        "record_id": bundle.record_id,
        "observed_at": str(observed_at),
        "rf_model_version": bundle.rf_model_version,
        "rf_attack_probability": rf_prob_str,
        "rf_threshold": f"{bundle.rf_threshold:.2f}",
        "rf_decision": rf_decision,
        "top_feature_signals": dict(bundle.top_feature_signals),
        "ae_v2_reconstruction_error": bundle.ae_v2_reconstruction_error,
        "ae_v2_threshold": bundle.ae_v2_threshold,
        "correlation": correlation_data,
        "threat_intel_enrichment": enrichment_data,
        "allowed_evidence_keys": allowed_keys,
        "allowed_ip_entities": inspected_entities,
    }

    evidence_json = json.dumps(evidence_payload, indent=2)

    prompt = f"""You are an evidence-bound advisory cybersecurity debrief assistant for ThreatFusion SOC analysts.
Your debrief is strictly advisory and non-authoritative.

CRITICAL GROUNDEDNESS & ANTI-HALLUCINATION RULES:
1. PURE JSON ONLY: Output MUST be a single valid JSON object. Do NOT wrap in markdown code fences, do NOT include backticks (```), and do NOT add explanatory text or preamble.
2. NO IP ADDRESS HALLUCINATIONS: You must NEVER invent, mention, or reference ANY IP address that is not explicitly listed in allowed_ip_entities: {json.dumps(inspected_entities)}. If allowed_ip_entities is empty, you must NOT include ANY IPv4 or IPv6 address anywhere in any field of your response.
3. EXACT MODEL VERSION & PROBABILITY: In 'detection_rationale', you MUST state the exact Random Forest model version "{bundle.rf_model_version}" and the exact attack probability "{rf_prob_str}".
4. SECTION 8 INVARIANT (FUSION DISABLED): In 'complementarity_and_fusion_note', you MUST affirm that production alert authority rests solely with the frozen Random Forest model ("{bundle.rf_model_version}") and that production fusion is strictly disabled ("fusion_disabled per Section 8" or "fusion is disabled") due to the empirical false-positive penalty (16.4:1 benign FP penalty on January UNSW validation). The autoencoder residual is advisory only. Both "Random Forest" and "fusion" and "disabled" must appear.
5. CITED EVIDENCE KEYS: In 'cited_evidence_keys', every entry MUST be selected strictly from the allowed_evidence_keys list: {json.dumps(allowed_keys)}. Do not invent keys.

REQUIRED JSON OUTPUT FORMAT:
{{
  "summary_headline": "<string: concise SOC triage headline>",
  "detection_rationale": "<string: factual detection rationale citing {bundle.rf_model_version} and probability {rf_prob_str}>",
  "complementarity_and_fusion_note": "<string: affirming production alert authority rests with Random Forest and fusion is disabled>",
  "correlation_and_enrichment_context": "<string: correlation status and inspected entities context>",
  "recommended_analyst_checks": ["<string: triage check 1>", "<string: triage check 2>", "<string: triage check 3>"],
  "cited_evidence_keys": ["<key1>", "<key2>", ...]
}}

VERIFIED EVIDENCE BUNDLE:
{evidence_json}
"""
    return prompt


class GeminiAdvisoryCallable:
    """Outage-isolated Gemini advisory debrief callable outside the primary detection loop.

    Guarantees:
    - Never modifies rf_attack_probability, threshold, or alert candidate creation.
    - Uses only Python stdlib (urllib.request, json, os).
    - If unconfigured, timed out, HTTP error, or unparseable, raises GeminiAdvisoryUnavailableError.
    - Returns an EvidenceBoundExplanation with generation_mode="verified_local_llm_advisory"
      and advisory_only_non_authoritative=True, for verification by AdvisoryExplanationEngine.
    """

    def __init__(
        self,
        config: GeminiAdvisoryConfig | None = None,
        *,
        transport_callable: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self.config = config if config is not None else GeminiAdvisoryConfig()
        self._transport_callable = transport_callable

    def __call__(self, bundle: AdvisoryEvidenceBundle) -> EvidenceBoundExplanation:
        """Generate an advisory explanation from bundle using Gemini REST API."""
        if self._transport_callable is None:
            api_key = os.environ.get(self.config.api_key_env_var, "").strip()
            if not api_key:
                raise GeminiAdvisoryUnavailableError(
                    f"Gemini API key environment variable '{self.config.api_key_env_var}' is unset or empty."
                )
        else:
            api_key = os.environ.get(self.config.api_key_env_var, "").strip() or "mock-api-key"

        endpoint_url = self.config.get_endpoint_url(api_key)
        prompt_text = build_grounded_gemini_prompt(bundle)

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt_text}],
                }
            ],
            "generationConfig": {
                "temperature": 0.0,
                "maxOutputTokens": self.config.max_output_tokens,
                "responseMimeType": "application/json",
            },
        }

        if self._transport_callable is not None:
            try:
                response_dict = self._transport_callable(endpoint_url, payload)
            except Exception as exc:
                raise GeminiAdvisoryUnavailableError(f"Transport callable failed: {exc}") from exc
        else:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                endpoint_url,
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                    raw_body = resp.read().decode("utf-8")
                    response_dict = json.loads(raw_body)
            except urllib.error.HTTPError as exc:
                raise GeminiAdvisoryUnavailableError(
                    f"Gemini API HTTP error {exc.code}: {exc.reason}"
                ) from exc
            except urllib.error.URLError as exc:
                raise GeminiAdvisoryUnavailableError(
                    f"Gemini API network error: {exc.reason}"
                ) from exc
            except (TimeoutError, OSError) as exc:
                raise GeminiAdvisoryUnavailableError(
                    f"Gemini API request timed out or OS error: {exc}"
                ) from exc
            except json.JSONDecodeError as exc:
                raise GeminiAdvisoryUnavailableError(
                    f"Gemini API response was not valid JSON: {exc}"
                ) from exc
            except Exception as exc:
                raise GeminiAdvisoryUnavailableError(
                    f"Unexpected error calling Gemini API: {exc}"
                ) from exc

        if not isinstance(response_dict, dict):
            raise GeminiAdvisoryUnavailableError(
                f"Invalid Gemini response: expected dict, got {type(response_dict).__name__}"
            )

        candidates = response_dict.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise GeminiAdvisoryUnavailableError("Gemini response contains no candidates.")

        first_candidate = candidates[0]
        if not isinstance(first_candidate, dict):
            raise GeminiAdvisoryUnavailableError(
                "First candidate in Gemini response is not a dict."
            )

        content = first_candidate.get("content")
        if not isinstance(content, dict):
            raise GeminiAdvisoryUnavailableError("Candidate content is missing or not a dict.")

        parts = content.get("parts")
        if not isinstance(parts, list) or not parts:
            raise GeminiAdvisoryUnavailableError("Candidate content parts list is empty.")

        first_part = parts[0]
        if not isinstance(first_part, dict):
            raise GeminiAdvisoryUnavailableError("First content part is not a dict.")

        raw_text = first_part.get("text", "")
        if not isinstance(raw_text, str) or not raw_text.strip():
            raise GeminiAdvisoryUnavailableError("Candidate content part contains empty text.")

        cleaned_text = raw_text.strip()
        if cleaned_text.startswith("```"):
            lines = cleaned_text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            cleaned_text = "\n".join(lines).strip()

        try:
            parsed = json.loads(cleaned_text)
        except json.JSONDecodeError as exc:
            raise GeminiAdvisoryUnavailableError(
                f"Model response text could not be parsed as JSON: {exc}"
            ) from exc

        if not isinstance(parsed, dict):
            raise GeminiAdvisoryUnavailableError(
                f"Model response JSON is not an object: got {type(parsed).__name__}"
            )

        summary_headline = str(parsed.get("summary_headline", "")).strip()
        detection_rationale = str(parsed.get("detection_rationale", "")).strip()
        complementarity_and_fusion_note = str(
            parsed.get("complementarity_and_fusion_note", "")
        ).strip()
        correlation_and_enrichment_context = str(
            parsed.get("correlation_and_enrichment_context", "")
        ).strip()

        raw_checks = parsed.get("recommended_analyst_checks", [])
        if isinstance(raw_checks, list):
            recommended_checks = tuple(str(c).strip() for c in raw_checks if str(c).strip())
        elif isinstance(raw_checks, str) and raw_checks.strip():
            recommended_checks = (raw_checks.strip(),)
        else:
            recommended_checks = ()

        raw_keys = parsed.get("cited_evidence_keys", [])
        if isinstance(raw_keys, list):
            cited_keys = tuple(str(k).strip() for k in raw_keys if str(k).strip())
        elif isinstance(raw_keys, str) and raw_keys.strip():
            cited_keys = (raw_keys.strip(),)
        else:
            cited_keys = ()

        return EvidenceBoundExplanation(
            candidate_id=bundle.candidate_id,
            generation_mode="verified_local_llm_advisory",
            advisory_only_non_authoritative=True,
            summary_headline=summary_headline,
            detection_rationale=detection_rationale,
            complementarity_and_fusion_note=complementarity_and_fusion_note,
            correlation_and_enrichment_context=correlation_and_enrichment_context,
            recommended_analyst_checks=recommended_checks,
            cited_evidence_keys=cited_keys,
            groundedness_verified=True,
        )
