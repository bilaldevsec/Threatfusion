"""ThreatFusion evidence-bound advisory debrief subpackage."""

from threatfusion.advisory.explanation_engine import (
    AdvisoryEvidenceBundle,
    AdvisoryExplanationEngine,
    AdvisoryGroundednessError,
    EvidenceBoundExplanation,
    verify_explanation_groundedness,
)
from threatfusion.advisory.gemini_client import (
    GeminiAdvisoryCallable,
    GeminiAdvisoryConfig,
    GeminiAdvisoryUnavailableError,
    build_grounded_gemini_prompt,
)

__all__ = [
    "AdvisoryEvidenceBundle",
    "AdvisoryExplanationEngine",
    "AdvisoryGroundednessError",
    "EvidenceBoundExplanation",
    "GeminiAdvisoryCallable",
    "GeminiAdvisoryConfig",
    "GeminiAdvisoryUnavailableError",
    "build_grounded_gemini_prompt",
    "verify_explanation_groundedness",
]
