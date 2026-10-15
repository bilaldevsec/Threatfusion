"""ThreatFusion machine learning and deep learning models subpackage."""

from threatfusion.models.jury_traceability import (
    JURY_DATASET_DISPOSITIONS,
    JURY_MODEL_FAMILY_DISPOSITIONS,
    JURY_TRACEABILITY_SCHEMA_VERSION,
    JuryDatasetDisposition,
    JuryModelFamilyDisposition,
    JuryTraceabilityError,
    JuryTraceabilityVerificationResult,
    verify_jury_traceability_completeness,
)
from threatfusion.models.multi_signal_risk import (
    CANONICAL_SIGNAL_SLOTS,
    DEFAULT_SIGNAL_WEIGHTS,
    DETECTOR_ABLATION_REPORT_SCHEMA_VERSION,
    DYNAMIC_RISK_ASSESSMENT_SCHEMA_VERSION,
    DetectorAblationReport,
    DetectorMetrics,
    DynamicRiskAssessment,
    MultiSignalRiskError,
    SignalObservation,
    compute_dynamic_risk_score,
    evaluate_detector_ablation,
)

__all__ = [
    "CANONICAL_SIGNAL_SLOTS",
    "DEFAULT_SIGNAL_WEIGHTS",
    "DETECTOR_ABLATION_REPORT_SCHEMA_VERSION",
    "DYNAMIC_RISK_ASSESSMENT_SCHEMA_VERSION",
    "DetectorAblationReport",
    "DetectorMetrics",
    "DynamicRiskAssessment",
    "JURY_DATASET_DISPOSITIONS",
    "JURY_MODEL_FAMILY_DISPOSITIONS",
    "JURY_TRACEABILITY_SCHEMA_VERSION",
    "JuryDatasetDisposition",
    "JuryModelFamilyDisposition",
    "JuryTraceabilityError",
    "JuryTraceabilityVerificationResult",
    "MultiSignalRiskError",
    "SignalObservation",
    "compute_dynamic_risk_score",
    "evaluate_detector_ablation",
    "verify_jury_traceability_completeness",
]
