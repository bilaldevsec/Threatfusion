"""Evidence-Bound Advisory Explanation Engine.

Enforces Section 13.D of ThreatFusion:
- Groundedness & Anti-Hallucination: Citations must map strictly to evidence.
- IP Guard on Flow Records: Zero IP addresses may appear if not inspected in provenance.
- Section 8 Invariant: Production alert authority rests solely on frozen Random Forest;
  fusion remains disabled per the 16.4:1 benign-FP penalty.
- Deterministic Fallback: Automatically falls back to a 100% grounded template if
  an optional LLM callable fails or generates ungrounded claims.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from threatfusion.enrichment.threat_intel import ThreatIntelEnrichmentResult

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class AdvisoryGroundednessError(RuntimeError):
    """Raised when an advisory explanation violates evidence groundedness rules."""


@dataclass(frozen=True, slots=True)
class AdvisoryEvidenceBundle:
    """Immutable collection of factual evidence for generating an advisory debrief."""

    candidate_id: str
    record_id: str
    rf_model_version: str
    rf_attack_probability: float
    rf_threshold: float
    top_feature_signals: Mapping[str, float]
    ae_v2_reconstruction_error: float | None = None
    ae_v2_threshold: float = 0.1181361214680695
    incident_id: str | None = None
    correlation_status: str = "uncorrelatable_missing_entity"
    enrichment_result: ThreatIntelEnrichmentResult | None = None
    observed_at: str | None = None

    def get_allowed_evidence_keys(self) -> set[str]:
        keys = {
            "candidate_id",
            "record_id",
            "rf_model_version",
            "rf_attack_probability",
            "rf_threshold",
            "correlation_status",
            "ae_v2_threshold",
        }
        for k in self.top_feature_signals:
            keys.add(k)
        if self.ae_v2_reconstruction_error is not None:
            keys.add("ae_v2_reconstruction_error")
        if self.incident_id:
            keys.add("incident_id")
        if self.enrichment_result:
            keys.add("enrichment_status")
            keys.add("enrichment_reason")
            for ip in self.enrichment_result.inspected_entities:
                keys.add(f"entity:{ip}")
        if self.observed_at is not None:
            keys.add("observed_at")
        return keys


@dataclass(frozen=True, slots=True)
class EvidenceBoundExplanation:
    """Structured advisory triage explanation with strict non-authoritative bounds."""

    candidate_id: str
    generation_mode: str  # "deterministic_evidence_template" | "verified_local_llm_advisory"
    advisory_only_non_authoritative: bool
    summary_headline: str
    detection_rationale: str
    complementarity_and_fusion_note: str
    correlation_and_enrichment_context: str
    recommended_analyst_checks: tuple[str, ...]
    cited_evidence_keys: tuple[str, ...]
    groundedness_verified: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "generation_mode": self.generation_mode,
            "advisory_only_non_authoritative": self.advisory_only_non_authoritative,
            "summary_headline": self.summary_headline,
            "detection_rationale": self.detection_rationale,
            "complementarity_and_fusion_note": self.complementarity_and_fusion_note,
            "correlation_and_enrichment_context": self.correlation_and_enrichment_context,
            "recommended_analyst_checks": list(self.recommended_analyst_checks),
            "cited_evidence_keys": list(self.cited_evidence_keys),
            "groundedness_verified": self.groundedness_verified,
        }


def verify_explanation_groundedness(
    explanation: EvidenceBoundExplanation,
    bundle: AdvisoryEvidenceBundle,
) -> bool:
    """Validate that an advisory explanation strictly adheres to anti-hallucination rules.

    Checks:
    1. advisory_only_non_authoritative is True.
    2. Every cited key exists in allowed evidence dictionary.
    3. Stated RF probability and model version match bundle.
    4. Any IP address in text is actually in bundle.enrichment_result.inspected_entities.
    5. complementarity_and_fusion_note affirms production authority rests on frozen RF.
    """
    if explanation.advisory_only_non_authoritative is not True:
        return False

    allowed_keys = bundle.get_allowed_evidence_keys()
    for cited in explanation.cited_evidence_keys:
        if cited not in allowed_keys:
            return False

    # Check model version and probability references
    if bundle.rf_model_version not in explanation.detection_rationale:
        return False

    # Format check for rf probability (e.g. 0.825 or 0.8249 or 82.5%)
    rf_prob_str = f"{bundle.rf_attack_probability:.4f}"
    rf_prob_short = f"{bundle.rf_attack_probability:.3f}"
    if (
        rf_prob_str not in explanation.detection_rationale
        and rf_prob_short not in explanation.detection_rationale
    ):
        return False

    # IP address hallucination check across all text fields
    all_text = " ".join(
        [
            explanation.summary_headline,
            explanation.detection_rationale,
            explanation.complementarity_and_fusion_note,
            explanation.correlation_and_enrichment_context,
            " ".join(explanation.recommended_analyst_checks),
        ]
    )

    found_ips = set(IP_REGEX.findall(all_text))
    allowed_ips: set[str] = set()
    if bundle.enrichment_result and bundle.enrichment_result.inspected_entities:
        allowed_ips = set(bundle.enrichment_result.inspected_entities)

    # Any found IP not in allowed_ips is an ungrounded hallucination
    if not found_ips.issubset(allowed_ips):
        return False

    # Section 8 Invariant check
    fusion_note = explanation.complementarity_and_fusion_note.lower()
    if "random forest" not in fusion_note or "fusion" not in fusion_note:
        return False
    if "disabled" not in fusion_note:
        return False

    return True


class AdvisoryExplanationEngine:
    """Generates 100% evidence-bound advisory explanations with deterministic fallback."""

    @classmethod
    def generate_explanation(
        cls,
        bundle: AdvisoryEvidenceBundle,
        optional_llm_callable: (
            Callable[[AdvisoryEvidenceBundle], EvidenceBoundExplanation] | None
        ) = None,
    ) -> EvidenceBoundExplanation:
        """Generate an advisory explanation.

        If optional_llm_callable is provided, attempts generation and verifies groundedness.
        If callable is None, raises an error, or fails verification, safely falls back
        to the deterministic template.
        """
        if optional_llm_callable is not None:
            try:
                candidate_exp = optional_llm_callable(bundle)
                if isinstance(candidate_exp, EvidenceBoundExplanation):
                    if verify_explanation_groundedness(candidate_exp, bundle):
                        return candidate_exp
            except Exception:
                pass  # Fall back closed to deterministic template

        return cls._generate_deterministic_template(bundle)

    @classmethod
    def _generate_deterministic_template(
        cls,
        bundle: AdvisoryEvidenceBundle,
    ) -> EvidenceBoundExplanation:
        candidate_short = bundle.candidate_id.split(":")[-1][:12]
        headline = (
            f"Advisory SOC Triage Debrief: Alert candidate {candidate_short} "
            f"({bundle.rf_model_version})"
        )

        top_signals_summary = ", ".join(
            f"{k}={v:.4f}" if isinstance(v, float) else f"{k}={v}"
            for k, v in list(bundle.top_feature_signals.items())[:5]
        )
        if not top_signals_summary:
            top_signals_summary = "standard feature vector profile"

        rationale = (
            f"The frozen Random Forest model ({bundle.rf_model_version}) produced an "
            f"attack probability of {bundle.rf_attack_probability:.4f}, exceeding the "
            f"operational detection threshold of {bundle.rf_threshold:.2f}. "
            f"Prominent feature indicators: {top_signals_summary}."
        )

        fusion_note = (
            f"Production alert authority rests solely with the frozen Random Forest "
            f"({bundle.rf_model_version}). Automatic RF+AE fusion is strictly disabled "
            f"(fusion_disabled per Section 8) due to the empirical 16.4:1 benign false-positive "
            f"penalty (1,574 additional FPs for 96 attacks on January UNSW validation). "
            f"Autoencoder residual is advisory only."
        )

        # Context: mention IPs ONLY if verified in enrichment_result.inspected_entities
        context_parts = [f"Correlation status: {bundle.correlation_status}."]
        if bundle.incident_id:
            context_parts.append(f"Linked to incident {bundle.incident_id}.")

        if bundle.enrichment_result:
            context_parts.append(f"Enrichment status: {bundle.enrichment_result.status}.")
            if bundle.enrichment_result.inspected_entities:
                inspected_str = ", ".join(bundle.enrichment_result.inspected_entities)
                context_parts.append(f"Inspected entities: {inspected_str}.")
            if bundle.enrichment_result.private_ip_guard_triggered:
                context_parts.append("Private IP guard active; public external queries suppressed.")
        else:
            context_parts.append("Entity provenance unverified; no IP addresses inspected.")

        correlation_context = " ".join(context_parts)

        checks = (
            "Verify network segment and sensor provenance on upstream tap.",
            "Review surrounding flow events within the 30-second burst window.",
            "Assess potential benign administrative activity before initiating containment.",
        )

        cited_keys = [
            "candidate_id",
            "record_id",
            "rf_model_version",
            "rf_attack_probability",
            "rf_threshold",
            "correlation_status",
            "ae_v2_threshold",
        ]
        for k in list(bundle.top_feature_signals.keys())[:5]:
            cited_keys.append(k)
        if bundle.incident_id:
            cited_keys.append("incident_id")
        if bundle.enrichment_result:
            cited_keys.append("enrichment_status")
            cited_keys.append("enrichment_reason")
            for ip in bundle.enrichment_result.inspected_entities:
                cited_keys.append(f"entity:{ip}")

        return EvidenceBoundExplanation(
            candidate_id=bundle.candidate_id,
            generation_mode="deterministic_evidence_template",
            advisory_only_non_authoritative=True,
            summary_headline=headline,
            detection_rationale=rationale,
            complementarity_and_fusion_note=fusion_note,
            correlation_and_enrichment_context=correlation_context,
            recommended_analyst_checks=checks,
            cited_evidence_keys=tuple(cited_keys),
            groundedness_verified=True,
        )
