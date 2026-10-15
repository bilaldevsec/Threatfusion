"""Jury Requirements Traceability Registry (TF-010).

Maintains an immutable, authoritative, verifiable matrix of all jury-approved
dataset dispositions and model family dispositions, resolving TF-010.
Enforces non-substitution invariants, leakage boundaries, and artifact checksum
verification.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threatfusion.db.retraining_feedback_ledger import (
    FROZEN_AE_EXPECTED_SHA256,
    FROZEN_AE_RELATIVE_PATH,
    FROZEN_RF_EXPECTED_SHA256,
    FROZEN_RF_RELATIVE_PATH,
    OfflineRetrainingFeedbackRepository,
    RetrainingFeedbackError,
    RetrainingFeedbackRecord,
    verify_frozen_models_unmodified,
)

JURY_TRACEABILITY_SCHEMA_VERSION = "jury_traceability_matrix_v1"

# Approved dataset identifiers
DATASET_UNSW_NB15 = "UNSW-NB15"
DATASET_CIC_IDS2017 = "CIC-IDS2017"
DATASET_CSE_CIC_IDS2018_SUBSET = "CSE-CIC-IDS2018_subset"
DATASET_MORDOR_SCENARIOS = "Mordor_scenarios"
DATASET_SYNTHETIC_UEBA = "Synthetic_UEBA"
DATASET_AUTHORIZED_LAB_SENSOR = "Authorized_Lab_Sensor"

REQUIRED_JURY_DATASETS: tuple[str, ...] = (
    DATASET_UNSW_NB15,
    DATASET_CIC_IDS2017,
    DATASET_CSE_CIC_IDS2018_SUBSET,
    DATASET_MORDOR_SCENARIOS,
    DATASET_SYNTHETIC_UEBA,
    DATASET_AUTHORIZED_LAB_SENSOR,
)

# Approved model family identifiers
FAMILY_LOGISTIC_REGRESSION = "Logistic_Regression"
FAMILY_RANDOM_FOREST = "Random_Forest"
FAMILY_AUTOENCODER_V2 = "Autoencoder_v2"
FAMILY_RATE_LOG1P_CANDIDATE = "Rate_Log1p_Candidate"
FAMILY_HEURISTIC_STATISTICAL_SIGNALS = "Heuristic_Statistical_Signals"

REQUIRED_JURY_MODEL_FAMILIES: tuple[str, ...] = (
    FAMILY_LOGISTIC_REGRESSION,
    FAMILY_RANDOM_FOREST,
    FAMILY_AUTOENCODER_V2,
    FAMILY_RATE_LOG1P_CANDIDATE,
    FAMILY_HEURISTIC_STATISTICAL_SIGNALS,
)

# Checksums for preserved baselines and blocked candidates
FROZEN_LOGISTIC_RELATIVE_PATH = "artifacts/models/network_logistic_baseline/full-network-logistic-5e70ed9-v1/logistic_regression.joblib"
FROZEN_LOGISTIC_EXPECTED_SHA256 = "2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148"

BLOCKED_RATE_LOG1P_RELATIVE_PATH = "artifacts/models/network_rate_log1p_autoencoder/rate-log1p-autoencoder-b5e6e5d-v1/autoencoder_state.pt"
BLOCKED_RATE_LOG1P_EXPECTED_SHA256 = (
    "1d02e5bba556cb28709bd0faefce5f29da424a419a2d95332ad27a8995b26f63"
)


class JuryTraceabilityError(RuntimeError):
    """Sanitized boundary error for jury traceability matrix."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class JuryDatasetDisposition:
    """Immutable disposition and governance record for one dataset source."""

    identifier: str
    role: str
    disposition_status: str
    temporal_split_isolation: bool
    artifact_reference: str
    contract_reference: str
    leakage_boundary: str
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "role": self.role,
            "disposition_status": self.disposition_status,
            "temporal_split_isolation": self.temporal_split_isolation,
            "artifact_reference": self.artifact_reference,
            "contract_reference": self.contract_reference,
            "leakage_boundary": self.leakage_boundary,
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class JuryModelFamilyDisposition:
    """Immutable disposition and boundary record for one model family."""

    family: str
    disposition_status: str
    model_artifact_path: str | None
    expected_sha256: str | None
    contract_reference: str
    evaluation_boundary: str
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "disposition_status": self.disposition_status,
            "model_artifact_path": self.model_artifact_path,
            "expected_sha256": self.expected_sha256,
            "contract_reference": self.contract_reference,
            "evaluation_boundary": self.evaluation_boundary,
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class JuryTraceabilityVerificationResult:
    """Verification outcome asserting zero gaps in jury traceability matrix."""

    schema_version: str
    is_complete: bool
    verified_at_utc: str
    verified_datasets: tuple[str, ...]
    verified_model_families: tuple[str, ...]
    artifact_checksums_verified: bool
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "is_complete": self.is_complete,
            "verified_at_utc": self.verified_at_utc,
            "verified_datasets": list(self.verified_datasets),
            "verified_model_families": list(self.verified_model_families),
            "artifact_checksums_verified": self.artifact_checksums_verified,
            "details": self.details,
        }


JURY_DATASET_DISPOSITIONS: dict[str, JuryDatasetDisposition] = {
    DATASET_UNSW_NB15: JuryDatasetDisposition(
        identifier=DATASET_UNSW_NB15,
        role="registered_baseline_network_dataset",
        disposition_status="APPROVED_BASELINE",
        temporal_split_isolation=True,
        artifact_reference="artifacts/data/unsw-nb15/",
        contract_reference="network_behavior_v1",
        leakage_boundary=(
            "Strict temporal split isolation (Jan 2015 train/val vs Feb 2015 test); "
            "cross-split capture duplicate risk recorded under TF-006; "
            "Feb outcome development-informing under TF-007."
        ),
        notes="Frozen baseline network dataset with 42 Argus features.",
    ),
    DATASET_CIC_IDS2017: JuryDatasetDisposition(
        identifier=DATASET_CIC_IDS2017,
        role="cross_source_evaluation_candidate",
        disposition_status="BLOCKED_SEMANTIC_MISMATCH",
        temporal_split_isolation=False,
        artifact_reference="docs/network_feature_comparability_audit.md",
        contract_reference="network_behavior_v1",
        leakage_boundary=(
            "Blocked for direct 42-feature cross-evaluation due to 5-byte-layer semantic "
            "mismatch and extractor divergence (Argus vs CICFlowMeter) per TF-001, TF-006, TF-012."
        ),
        notes="Preserved as negative comparability finding; direct evaluation rejected.",
    ),
    DATASET_CSE_CIC_IDS2018_SUBSET: JuryDatasetDisposition(
        identifier=DATASET_CSE_CIC_IDS2018_SUBSET,
        role="future_network_telemetry_source",
        disposition_status="REQUIRES_ISOLATED_ADAPTER",
        temporal_split_isolation=True,
        artifact_reference="docs/GEMINI_PROJECT_MASTER.md#section-9",
        contract_reference="cse_cic_ids2018_adapter_contract_v1",
        leakage_boundary=(
            "Requires isolated schema adapter; cannot consume UNSW weights without "
            "explicit common byte-layer mapping and holdout protocol."
        ),
        notes="Planned Phase P3 secondary network telemetry source.",
    ),
    DATASET_MORDOR_SCENARIOS: JuryDatasetDisposition(
        identifier=DATASET_MORDOR_SCENARIOS,
        role="host_security_event_correlation_replay",
        disposition_status="APPROVED_REPLAY_ADAPTER",
        temporal_split_isolation=False,
        artifact_reference="backend/src/threatfusion/datasets/adapters/provenance_sources.py",
        contract_reference="mordor_scenario_event_v1",
        leakage_boundary=(
            "Attack/test-only host telemetry. Cannot train anomaly/UEBA models due to "
            "zero benign baseline (TF-004). Dedicated MordorScenarioAdapter enforces replay contract."
        ),
        notes="Valid for correlation testing and analyst investigation, not host anomaly training.",
    ),
    DATASET_SYNTHETIC_UEBA: JuryDatasetDisposition(
        identifier=DATASET_SYNTHETIC_UEBA,
        role="controlled_behavioral_fallback",
        disposition_status="LABELED_SYNTHETIC_FALLBACK",
        temporal_split_isolation=True,
        artifact_reference="docs/phase_0p_synthetic_training_readiness.md",
        contract_reference="synthetic_ueba_event_v1",
        leakage_boundary=(
            "Must remain strictly labeled synthetic; cannot establish real-world host "
            "detection performance (TF-004)."
        ),
        notes="Fixture and integration pipeline verification only.",
    ),
    DATASET_AUTHORIZED_LAB_SENSOR: JuryDatasetDisposition(
        identifier=DATASET_AUTHORIZED_LAB_SENSOR,
        role="operational_source_path",
        disposition_status="APPROVED_SENSOR_ADAPTER",
        temporal_split_isolation=True,
        artifact_reference="backend/src/threatfusion/datasets/adapters/provenance_sources.py",
        contract_reference="authorized_lab_sensor_event_v1",
        leakage_boundary=(
            "Requires explicit sensor registration, cryptographic mTLS identity, "
            "schema compatibility check, and clock-skew bounds (AuthorizedLabSensorAdapter)."
        ),
        notes="Demonstrable end-to-end collection path for live/lab environments.",
    ),
}

JURY_MODEL_FAMILY_DISPOSITIONS: dict[str, JuryModelFamilyDisposition] = {
    FAMILY_LOGISTIC_REGRESSION: JuryModelFamilyDisposition(
        family=FAMILY_LOGISTIC_REGRESSION,
        disposition_status="PRESERVED_LINEAR_BASELINE",
        model_artifact_path=FROZEN_LOGISTIC_RELATIVE_PATH,
        expected_sha256=FROZEN_LOGISTIC_EXPECTED_SHA256,
        contract_reference="network_logistic_baseline_v1",
        evaluation_boundary="Linear comparison baseline. Cannot be silently removed or substituted.",
        notes="Preserved linear baseline model.",
    ),
    FAMILY_RANDOM_FOREST: JuryModelFamilyDisposition(
        family=FAMILY_RANDOM_FOREST,
        disposition_status="FROZEN_PRODUCTION_BASELINE",
        model_artifact_path=FROZEN_RF_RELATIVE_PATH,
        expected_sha256=FROZEN_RF_EXPECTED_SHA256,
        contract_reference="network_random_forest_baseline_v1",
        evaluation_boundary="Primary production inference detector. Drives alerts and correlation. Frozen weights.",
        notes="Frozen production baseline model.",
    ),
    FAMILY_AUTOENCODER_V2: JuryModelFamilyDisposition(
        family=FAMILY_AUTOENCODER_V2,
        disposition_status="EXPERIMENTAL_UNFUSED_ADVISORY",
        model_artifact_path=FROZEN_AE_RELATIVE_PATH,
        expected_sha256=FROZEN_AE_EXPECTED_SHA256,
        contract_reference="network_autoencoder_v2",
        evaluation_boundary=(
            "PyTorch reconstruction anomaly model trained on benign January UNSW rows. "
            "Calibrated threshold. Retained as unfused advisory signal; not approved for automatic containment."
        ),
        notes="Experimental unfused reconstruction autoencoder.",
    ),
    FAMILY_RATE_LOG1P_CANDIDATE: JuryModelFamilyDisposition(
        family=FAMILY_RATE_LOG1P_CANDIDATE,
        disposition_status="BLOCKED_PRESERVE_BASELINE",
        model_artifact_path=BLOCKED_RATE_LOG1P_RELATIVE_PATH,
        expected_sha256=BLOCKED_RATE_LOG1P_EXPECTED_SHA256,
        contract_reference="network_rate_log1p_autoencoder_v1",
        evaluation_boundary=(
            "Blocked: preparation accessed February 2015 split rows, all four numerical gates failed (ratio 0.028). "
            "Retained as negative evidence only."
        ),
        notes="Blocked experimental candidate.",
    ),
    FAMILY_HEURISTIC_STATISTICAL_SIGNALS: JuryModelFamilyDisposition(
        family=FAMILY_HEURISTIC_STATISTICAL_SIGNALS,
        disposition_status="ENRICHMENT_SIGNALS",
        model_artifact_path=None,
        expected_sha256=None,
        contract_reference="heuristic_signals_v1",
        evaluation_boundary="Payload entropy, periodic beaconing, and threat intel IOC enrichments. Auxiliary signals in dynamic risk scoring.",
        notes="Rule-based and heuristic enrichment signals.",
    ),
}


def _find_repo_root(hint: Path | None = None) -> Path:
    if hint is not None:
        return hint.resolve()
    current = Path(__file__).resolve().parent
    for parent in (current, *current.parents):
        if (parent / ".git").exists() or (parent / "artifacts").exists():
            return parent
    return Path("/home/muhammad-bilal/projects/threatfusion-gemini")


def _compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_jury_traceability_completeness(
    repo_root: Path | None = None,
    *,
    verify_checksums: bool = True,
) -> JuryTraceabilityVerificationResult:
    """Assert completeness of the jury requirements traceability registry.

    Verifies that every required dataset and model family has an explicit, non-empty
    disposition, artifact/contract reference, and leakage/evaluation boundary.
    Optionally validates artifact SHA-256 digests against disk.
    """
    root = _find_repo_root(repo_root)

    # 1. Verify datasets
    missing_datasets = [d for d in REQUIRED_JURY_DATASETS if d not in JURY_DATASET_DISPOSITIONS]
    if missing_datasets:
        raise JuryTraceabilityError(f"missing_jury_datasets:{','.join(missing_datasets)}")

    for d_id in REQUIRED_JURY_DATASETS:
        d = JURY_DATASET_DISPOSITIONS[d_id]
        if (
            not d.disposition_status
            or not d.artifact_reference
            or not d.contract_reference
            or not d.leakage_boundary
        ):
            raise JuryTraceabilityError(f"incomplete_dataset_disposition:{d_id}")

    # 2. Verify model families
    missing_families = [
        f for f in REQUIRED_JURY_MODEL_FAMILIES if f not in JURY_MODEL_FAMILY_DISPOSITIONS
    ]
    if missing_families:
        raise JuryTraceabilityError(f"missing_jury_model_families:{','.join(missing_families)}")

    for f_id in REQUIRED_JURY_MODEL_FAMILIES:
        fam = JURY_MODEL_FAMILY_DISPOSITIONS[f_id]
        if not fam.disposition_status or not fam.contract_reference or not fam.evaluation_boundary:
            raise JuryTraceabilityError(f"incomplete_model_family_disposition:{f_id}")

    checksum_details: dict[str, str] = {}
    if verify_checksums:
        for f_id in REQUIRED_JURY_MODEL_FAMILIES:
            fam = JURY_MODEL_FAMILY_DISPOSITIONS[f_id]
            if fam.model_artifact_path is not None and fam.expected_sha256 is not None:
                artifact_file = root / fam.model_artifact_path
                if not artifact_file.exists():
                    raise JuryTraceabilityError(
                        f"model_artifact_file_missing:{fam.model_artifact_path}"
                    )
                actual_sha = _compute_sha256(artifact_file)
                if actual_sha != fam.expected_sha256:
                    raise JuryTraceabilityError(f"model_artifact_sha256_mismatch:{f_id}")
                checksum_details[f_id] = actual_sha

    return JuryTraceabilityVerificationResult(
        schema_version=JURY_TRACEABILITY_SCHEMA_VERSION,
        is_complete=True,
        verified_at_utc=datetime.now(UTC).isoformat(),
        verified_datasets=REQUIRED_JURY_DATASETS,
        verified_model_families=REQUIRED_JURY_MODEL_FAMILIES,
        artifact_checksums_verified=verify_checksums,
        details={
            "datasets_count": len(REQUIRED_JURY_DATASETS),
            "model_families_count": len(REQUIRED_JURY_MODEL_FAMILIES),
            "verified_checksums": checksum_details,
        },
    )


__all__ = [
    "DATASET_AUTHORIZED_LAB_SENSOR",
    "DATASET_CIC_IDS2017",
    "DATASET_CSE_CIC_IDS2018_SUBSET",
    "DATASET_MORDOR_SCENARIOS",
    "DATASET_SYNTHETIC_UEBA",
    "DATASET_UNSW_NB15",
    "FAMILY_AUTOENCODER_V2",
    "FAMILY_HEURISTIC_STATISTICAL_SIGNALS",
    "FAMILY_LOGISTIC_REGRESSION",
    "FAMILY_RANDOM_FOREST",
    "FAMILY_RATE_LOG1P_CANDIDATE",
    "JURY_DATASET_DISPOSITIONS",
    "JURY_MODEL_FAMILY_DISPOSITIONS",
    "JURY_TRACEABILITY_SCHEMA_VERSION",
    "JuryDatasetDisposition",
    "JuryModelFamilyDisposition",
    "JuryTraceabilityError",
    "JuryTraceabilityVerificationResult",
    "OfflineRetrainingFeedbackRepository",
    "REQUIRED_JURY_DATASETS",
    "REQUIRED_JURY_MODEL_FAMILIES",
    "RetrainingFeedbackError",
    "RetrainingFeedbackRecord",
    "verify_frozen_models_unmodified",
    "verify_jury_traceability_completeness",
]
