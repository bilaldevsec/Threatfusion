"""Comprehensive Unit Tests for Milestone #31.

Tests:
1. verify_frozen_model_supply_chain:
   - Passes on live repo and verifies all 4 frozen model artifacts with authorized roles.
   - Fails closed on missing artifact.
   - Fails closed on symlinked artifact.
   - Fails closed on corrupted SHA-256 artifact.
2. evaluate_14_feature_telemetry_drift:
   - Validates input shape, missing features, non-finite values, and empty sequences.
   - Classifies in-distribution flows as 'stable_in_distribution' (max_psi < 0.10).
   - Classifies moderately shifted flows as 'moderate_feature_drift_monitor' (0.10 <= max_psi < 0.25).
   - Classifies extreme shifted flows as 'severe_out_of_distribution_drift_retraining_review_required' (max_psi >= 0.25).
   - Strictly read-only: proves input records are never mutated.
3. evaluate_independent_holdout_dataset:
   - Computes exact confusion matrix counts (tp, fp, tn, fn) at 0.5 threshold.
   - Computes deterministic 95% bootstrap confidence intervals for recall and precision.
   - Flags all 3 inspected development splits with protocol_violation_inspected_split=True.
   - Programmatically blocks TF-008 closure on synthetic smoke fixtures and sample sizes < 1000.
4. run_full_soc_demo & analyst_dashboard:
   - Verifies Track B includes soar_audit_chain_verified=True, triage_queue_ranking, and telemetry_drift_status.
   - Verifies alert detail HTML renders SOAR audit chain badge and queue priority rank indicator.
"""

from __future__ import annotations

import copy
from pathlib import Path
import pytest

from threatfusion.api.analyst_dashboard import (
    DashboardAlertDetail,
    DashboardAlertQueue,
    DashboardSnapshot,
    render_dashboard_html,
)
from threatfusion.evaluation.independent_holdout_protocol import (
    INSPECTED_DEVELOPMENT_DATASET_IDS,
    evaluate_independent_holdout_dataset,
)
from threatfusion.models.drift_and_supply_chain import (
    CANONICAL_14_FEATURES,
    DEFAULT_BASELINE_MEANS,
    DEFAULT_BASELINE_STDS,
    FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY,
    ModelSupplyChainError,
    TelemetryDriftError,
    evaluate_14_feature_telemetry_drift,
    verify_frozen_model_supply_chain,
)
from threatfusion.operations.full_soc_demo import run_full_soc_demo

REPO_ROOT: Path = Path(__file__).resolve().parents[3]

# =============================================================================
# 1. Model Supply-Chain Verifier Tests
# =============================================================================


def test_verify_frozen_model_supply_chain_passes_on_live_repo() -> None:
    """Live repository satisfies all 4 frozen model artifact checks."""
    report = verify_frozen_model_supply_chain(REPO_ROOT)

    assert report["verified"] is True
    assert len(report["failures"]) == 0
    assert len(report["entries"]) == 4

    rf = report["entries"]["random_forest"]
    assert rf["operational_role"] == "primary_production_authority"
    assert rf["model_version"] == "network_random_forest_baseline_v1"
    assert rf["verified"] is True
    assert rf["byte_size"] > 0
    assert rf["is_regular_file"] is True
    assert rf["is_symlink"] is False

    lr = report["entries"]["logistic_regression"]
    assert lr["operational_role"] == "linear_baseline"
    assert lr["model_version"] == "network_logistic_baseline_v1"
    assert lr["verified"] is True

    ae = report["entries"]["autoencoder_v2"]
    assert ae["operational_role"] == "secondary_non_blocking_ranker"
    assert ae["model_version"] == "network_autoencoder_v2"
    assert ae["verified"] is True

    candidate = report["entries"]["rate_log1p_candidate"]
    assert candidate["operational_role"] == "blocked_candidate"
    assert candidate["model_version"] == "network_rate_log1p_autoencoder_v1"
    assert candidate["verified"] is True


def test_verify_frozen_model_supply_chain_fails_closed_on_missing_artifact(tmp_path: Path) -> None:
    """Missing model artifact raises ModelSupplyChainError and reports verified=False."""
    # Empty temporary repo root lacks all 4 artifacts
    with pytest.raises(ModelSupplyChainError, match="verification failed"):
        verify_frozen_model_supply_chain(tmp_path, fail_closed=True)

    rep = verify_frozen_model_supply_chain(tmp_path, fail_closed=False)
    assert rep["verified"] is False
    assert len(rep["failures"]) == 4


def test_verify_frozen_model_supply_chain_fails_closed_on_symlinked_artifact(
    tmp_path: Path,
) -> None:
    """Symlinked artifact is rejected with fail-closed violation."""
    repo_root = Path(__file__).resolve().parents[3]
    # Replicate artifact structure in tmp_path with a symlink for Random Forest
    for key, spec in FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY.items():
        rel = spec["rel_path"]
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        live_file = repo_root / rel
        if key == "random_forest":
            # Create a symlink pointing to live file
            target.symlink_to(live_file)
        else:
            target.write_bytes(live_file.read_bytes())

    with pytest.raises(ModelSupplyChainError, match="symlink detected"):
        verify_frozen_model_supply_chain(tmp_path, fail_closed=True)

    rep = verify_frozen_model_supply_chain(tmp_path, fail_closed=False)
    assert rep["verified"] is False
    assert any("symlink detected" in f for f in rep["failures"])


def test_verify_frozen_model_supply_chain_fails_closed_on_intermediate_dir_symlink(
    tmp_path: Path,
) -> None:
    """Replacing an intermediate directory (artifacts/models) with a symlink fails closed."""
    repo_root = Path(__file__).resolve().parents[3]
    real_external = tmp_path / "external_models"
    real_external.mkdir(parents=True, exist_ok=True)

    # Copy files into external directory
    for key, spec in FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY.items():
        rel = spec["rel_path"]
        sub_rel = Path(rel).relative_to("artifacts/models")
        dest = real_external / sub_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((repo_root / rel).read_bytes())

    # In fake_root, create artifacts/ then symlink models -> real_external
    fake_root = tmp_path / "fake_repo"
    (fake_root / "artifacts").mkdir(parents=True, exist_ok=True)
    (fake_root / "artifacts" / "models").symlink_to(real_external, target_is_directory=True)

    with pytest.raises(ModelSupplyChainError, match="symlink detected"):
        verify_frozen_model_supply_chain(fake_root, fail_closed=True)

    rep = verify_frozen_model_supply_chain(fake_root, fail_closed=False)
    assert rep["verified"] is False
    assert rep["passed"] is False
    assert any("symlink detected" in f for f in rep["failures"])


def test_verify_frozen_model_supply_chain_fails_closed_on_tampered_artifact(tmp_path: Path) -> None:
    """Corrupted/tampered artifact SHA-256 fails closed."""
    repo_root = Path(__file__).resolve().parents[3]
    for key, spec in FROZEN_MODEL_SUPPLY_CHAIN_REGISTRY.items():
        rel = spec["rel_path"]
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        live_file = repo_root / rel
        if key == "autoencoder_v2":
            # Tamper with the autoencoder bytes
            target.write_bytes(b"corrupted_tampered_state_data")
        else:
            target.write_bytes(live_file.read_bytes())

    with pytest.raises(ModelSupplyChainError, match="SHA-256 digest mismatch"):
        verify_frozen_model_supply_chain(tmp_path, fail_closed=True)

    rep = verify_frozen_model_supply_chain(tmp_path, fail_closed=False)
    assert rep["verified"] is False
    assert any("Autoencoder v2" in f and "mismatch" in f for f in rep["failures"])


# =============================================================================
# 2. 14-Feature PSI Telemetry Drift Monitor Tests
# =============================================================================


def test_evaluate_14_feature_telemetry_drift_validates_inputs() -> None:
    """Empty records, missing features, and non-finite numbers fail closed."""
    with pytest.raises(TelemetryDriftError, match="must not be empty"):
        evaluate_14_feature_telemetry_drift([])

    # Missing dst_port
    bad_rec = {k: 1.0 for k in CANONICAL_14_FEATURES if k != "dst_port"}
    with pytest.raises(TelemetryDriftError, match="missing canonical feature 'dst_port'"):
        evaluate_14_feature_telemetry_drift([bad_rec])

    # Non-finite float (inf)
    inf_rec = {k: 1.0 for k in CANONICAL_14_FEATURES}
    inf_rec["duration_ms"] = float("inf")
    with pytest.raises(TelemetryDriftError, match="non-finite value"):
        evaluate_14_feature_telemetry_drift([inf_rec])


def test_evaluate_14_feature_telemetry_drift_classifies_in_distribution() -> None:
    """In-distribution flow record achieves stable_in_distribution status (max_psi < 0.10)."""
    clean_rec = dict(DEFAULT_BASELINE_MEANS)
    report = evaluate_14_feature_telemetry_drift([clean_rec])

    assert report.is_read_only_diagnostic_monitor is True
    assert report.drift_status == "stable_in_distribution"
    assert report.max_psi < 0.10
    assert report.record_count == 1
    assert len(report.feature_metrics) == 14

    for name, metric in report.feature_metrics.items():
        assert metric.feature_name == name
        assert metric.drift_category == "stable"
        assert metric.psi < 0.10


def test_evaluate_14_feature_telemetry_drift_classifies_moderate_drift() -> None:
    """Moderate shift (+0.35 std) produces moderate_feature_drift_monitor (0.10 <= max_psi < 0.25)."""
    mod_rec = {
        k: DEFAULT_BASELINE_MEANS[k] + 0.35 * DEFAULT_BASELINE_STDS[k]
        for k in CANONICAL_14_FEATURES
    }
    report = evaluate_14_feature_telemetry_drift([mod_rec])

    assert report.drift_status == "moderate_feature_drift_monitor"
    assert 0.10 <= report.max_psi < 0.25


def test_evaluate_14_feature_telemetry_drift_classifies_severe_drift() -> None:
    """Extreme out-of-distribution values trigger severe_out_of_distribution_drift_retraining_review_required."""
    extreme_rec = {
        k: DEFAULT_BASELINE_MEANS[k] + 3.0 * DEFAULT_BASELINE_STDS[k] for k in CANONICAL_14_FEATURES
    }
    report = evaluate_14_feature_telemetry_drift([extreme_rec])

    assert report.drift_status == "severe_out_of_distribution_drift_retraining_review_required"
    assert report.max_psi >= 0.25


def test_evaluate_14_feature_telemetry_drift_is_strictly_read_only() -> None:
    """Proves input record sequence is never mutated or reordered."""
    original = [
        {k: float(idx * 10 + 1) for idx, k in enumerate(CANONICAL_14_FEATURES)},
        {k: float(idx * 5 + 2) for idx, k in enumerate(CANONICAL_14_FEATURES)},
    ]
    cloned = copy.deepcopy(original)

    report = evaluate_14_feature_telemetry_drift(original)
    assert original == cloned
    assert report.is_read_only_diagnostic_monitor is True


# =============================================================================
# 3. TF-008 Independent Holdout Evaluation Harness Tests
# =============================================================================


def test_evaluate_independent_holdout_flags_inspected_development_splits() -> None:
    """Any evaluation targeting January or February UNSW splits triggers protocol violation."""
    for split_id in INSPECTED_DEVELOPMENT_DATASET_IDS:
        rep = evaluate_independent_holdout_dataset(
            dataset_id=split_id,
            dataset_sha256="0" * 64,
            y_true=[1, 0, 1, 0],
            rf_probabilities=[0.9, 0.1, 0.85, 0.15],
            is_synthetic_smoke_fixture=False,
        )
        assert rep.protocol_violation_inspected_split is True
        assert rep.tf_008_closure_eligible is False
        assert "Protocol violation" in rep.closure_eligibility_rationale


def test_evaluate_independent_holdout_blocks_closure_on_synthetic_fixtures() -> None:
    """Automated integration smoke fixtures are barred from closing TF-008."""
    rep = evaluate_independent_holdout_dataset(
        dataset_id="cse_cic_ids2018_holdout_sample",
        dataset_sha256="1" * 64,
        y_true=[1, 0] * 600,
        rf_probabilities=[0.8, 0.2] * 600,
        is_synthetic_smoke_fixture=True,
    )
    assert rep.protocol_violation_inspected_split is False
    assert rep.tf_008_closure_eligible is False
    assert "Synthetic smoke fixture" in rep.closure_eligibility_rationale


def test_evaluate_independent_holdout_blocks_closure_on_small_samples() -> None:
    """Sample sizes under 1000 fail statistical significance gate."""
    rep = evaluate_independent_holdout_dataset(
        dataset_id="cse_cic_ids2018_holdout_sample",
        dataset_sha256="2" * 64,
        y_true=[1, 0] * 100,  # 200 samples < 1000
        rf_probabilities=[0.8, 0.2] * 100,
        is_synthetic_smoke_fixture=False,
    )
    assert rep.protocol_violation_inspected_split is False
    assert rep.tf_008_closure_eligible is False
    assert "required for statistically significant" in rep.closure_eligibility_rationale


def test_evaluate_independent_holdout_validates_bootstrap_iterations() -> None:
    """bootstrap_iterations < 1 or non-int raises ValueError; < 200 blocks TF-008 closure."""
    with pytest.raises(ValueError, match="bootstrap_iterations must be an integer >= 1"):
        evaluate_independent_holdout_dataset(
            dataset_id="cse_cic_ids2018_holdout_test",
            dataset_sha256="4" * 64,
            y_true=[1, 0] * 10,
            rf_probabilities=[0.8, 0.2] * 10,
            bootstrap_iterations=0,
        )

    with pytest.raises(ValueError, match="bootstrap_iterations must be an integer >= 1"):
        evaluate_independent_holdout_dataset(
            dataset_id="cse_cic_ids2018_holdout_test",
            dataset_sha256="4" * 64,
            y_true=[1, 0] * 10,
            rf_probabilities=[0.8, 0.2] * 10,
            bootstrap_iterations=-1,
        )

    with pytest.raises(ValueError, match="bootstrap_iterations must be an integer >= 1"):
        evaluate_independent_holdout_dataset(
            dataset_id="cse_cic_ids2018_holdout_test",
            dataset_sha256="4" * 64,
            y_true=[1, 0] * 10,
            rf_probabilities=[0.8, 0.2] * 10,
            bootstrap_iterations=True,  # type: ignore[arg-type]
        )

    # bootstrap_iterations=50 (< 200) blocks TF-008 closure even when N >= 1000 and non-synthetic
    rep = evaluate_independent_holdout_dataset(
        dataset_id="cse_cic_ids2018_holdout_test",
        dataset_sha256="4" * 64,
        y_true=[1, 0] * 600,
        rf_probabilities=[0.8, 0.2] * 600,
        is_synthetic_smoke_fixture=False,
        bootstrap_iterations=50,
    )
    assert rep.total_samples == 1200
    assert rep.tf_008_closure_eligible is False
    assert "Bootstrap iterations 50 < 200" in rep.closure_eligibility_rationale


def test_evaluate_independent_holdout_validates_dataset_sha256_and_rf_model_identity() -> None:
    """Empty dataset_sha256 raises ValueError; non-hex or mismatched RF model blocks closure."""
    # Empty / whitespace raises ValueError
    with pytest.raises(ValueError, match="dataset_sha256 must be a non-empty string"):
        evaluate_independent_holdout_dataset(
            dataset_id="cse_cic_ids2018_holdout_test",
            dataset_sha256="",
            y_true=[1, 0] * 10,
            rf_probabilities=[0.8, 0.2] * 10,
        )

    with pytest.raises(ValueError, match="dataset_sha256 must be a non-empty string"):
        evaluate_independent_holdout_dataset(
            dataset_id="cse_cic_ids2018_holdout_test",
            dataset_sha256="   ",
            y_true=[1, 0] * 10,
            rf_probabilities=[0.8, 0.2] * 10,
        )

    # Invalid / non-hex sha256 marks dataset_sha256_valid=False and blocks closure
    rep_non_hex = evaluate_independent_holdout_dataset(
        dataset_id="cse_cic_ids2018_holdout_test",
        dataset_sha256="not_a_valid_64_hex_hash",
        y_true=[1, 0] * 600,
        rf_probabilities=[0.8, 0.2] * 600,
        is_synthetic_smoke_fixture=False,
        bootstrap_iterations=200,
    )
    assert rep_non_hex.dataset_sha256_valid is False
    assert rep_non_hex.tf_008_closure_eligible is False
    assert "not a valid 64-character hexadecimal" in rep_non_hex.closure_eligibility_rationale

    # Inspected split sha256 marks dataset_sha256_valid=False and blocks closure
    rep_inspected_sha = evaluate_independent_holdout_dataset(
        dataset_id="unseen_id_but_inspected_data",
        dataset_sha256="bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
        y_true=[1, 0] * 600,
        rf_probabilities=[0.8, 0.2] * 600,
        is_synthetic_smoke_fixture=False,
        bootstrap_iterations=200,
    )
    assert rep_inspected_sha.dataset_sha256_valid is False
    assert rep_inspected_sha.tf_008_closure_eligible is False
    assert (
        "matches a known inspected development split digest"
        in rep_inspected_sha.closure_eligibility_rationale
    )

    # Mismatched rf_model_version or rf_model_sha256 blocks closure
    rep_bad_rf = evaluate_independent_holdout_dataset(
        dataset_id="cse_cic_ids2018_holdout_test",
        dataset_sha256="5" * 64,
        y_true=[1, 0] * 600,
        rf_probabilities=[0.8, 0.2] * 600,
        is_synthetic_smoke_fixture=False,
        bootstrap_iterations=200,
        rf_model_version="unauthorized-rf-v2",
        rf_model_sha256="6" * 64,
    )
    assert rep_bad_rf.rf_model_identity_valid is False
    assert rep_bad_rf.tf_008_closure_eligible is False
    assert "Random Forest model identity mismatch" in rep_bad_rf.closure_eligibility_rationale

    # Calling with repo_root=None sets rf_supply_chain_verified=False and blocks closure
    rep_none_root = evaluate_independent_holdout_dataset(
        dataset_id="cse_cic_ids2018_holdout_test",
        dataset_sha256="5" * 64,
        y_true=[1, 0] * 600,
        rf_probabilities=[0.8, 0.2] * 600,
        is_synthetic_smoke_fixture=False,
        bootstrap_iterations=200,
        repo_root=None,
    )
    assert rep_none_root.rf_supply_chain_verified is False
    assert rep_none_root.tf_008_closure_eligible is False
    assert (
        "repo_root was not provided; on-disk frozen model supply-chain verification is mandatory for TF-008 closure"
        in rep_none_root.closure_eligibility_rationale
    )


def test_evaluate_independent_holdout_computes_exact_confusion_and_bootstrap_cis() -> None:
    """Computes exact metrics and deterministic 95% bootstrap confidence intervals."""
    # Construct 1200 samples (meets >= 1000 threshold)
    # 600 attacks, 600 normals
    # 540 attacks detected (TP=540, FN=60)
    # 30 false alarms (FP=30, TN=570)
    y_true = [1] * 600 + [0] * 600
    rf_probs = [0.8] * 540 + [0.2] * 60 + [0.7] * 30 + [0.1] * 570

    rep = evaluate_independent_holdout_dataset(
        dataset_id="cse_cic_ids2018_holdout_authenticated_v1",
        dataset_sha256="3" * 64,
        y_true=y_true,
        rf_probabilities=rf_probs,
        is_synthetic_smoke_fixture=False,
        bootstrap_iterations=200,
        random_seed=42,
        repo_root=REPO_ROOT,
    )

    assert rep.total_samples == 1200
    assert rep.tp == 540
    assert rep.fn == 60
    assert rep.fp == 30
    assert rep.tn == 570
    assert rep.precision_pct == round((540 / 570) * 100.0, 3)  # 94.737%
    assert rep.recall_pct == round((540 / 600) * 100.0, 3)  # 90.000%
    assert rep.dataset_sha256_valid is True
    assert rep.rf_model_identity_valid is True
    assert rep.rf_supply_chain_verified is True
    assert rep.protocol_violation_inspected_split is False
    assert rep.tf_008_closure_eligible is True

    # Check that bootstrap intervals bracket the point estimates
    prec_low, prec_high = rep.precision_ci_95
    rec_low, rec_high = rep.recall_ci_95
    assert prec_low <= rep.precision_pct <= prec_high
    assert rec_low <= rep.recall_pct <= rec_high


# =============================================================================
# 4. Turnkey Full SOC Demo & Analyst Dashboard Integration Tests
# =============================================================================


def test_run_full_soc_demo_incorporates_soar_chain_queue_ranker_and_drift(
    tmp_path: Path,
) -> None:
    """run_full_soc_demo incorporates M30 SOAR chain, AE queue ranker, and M31 drift monitor."""
    report = run_full_soc_demo(tmp_path)
    tb = report["track_b_azure_live_spine"]

    # 1. SOAR hash chain integrity verification
    assert tb["soar_audit_chain_verified"] is True
    assert tb["soar_audit_chain_entry_count"] >= 4
    assert isinstance(tb["soar_audit_chain_head_sha256"], str)
    assert len(tb["soar_audit_chain_head_sha256"]) == 64

    # 2. Non-Fused AE queue priority ranking
    assert len(tb["triage_queue_ranking"]) == 1
    rank_item = tb["triage_queue_ranking"][0]
    assert rank_item["queue_priority_rank"] == 1
    assert "priority_rationale" in rank_item
    assert "Burst Size=27" in rank_item["priority_rationale"]

    # 3. 14-Feature PSI Telemetry Drift
    assert "telemetry_drift_status" in tb
    drift_rep = tb["telemetry_drift_status"]
    assert "drift_status" in drift_rep
    assert drift_rep["record_count"] == 1
    assert len(drift_rep["feature_metrics"]) == 14

    # 4. File receipts
    json_file = tmp_path / "full_soc_demo_report.json"
    md_file = tmp_path / "full_soc_demo_report.md"
    assert json_file.is_file()
    assert md_file.is_file()

    md_text = md_file.read_text(encoding="utf-8")
    assert "Cryptographic Audit Chain Integrity:" in md_text
    assert "High-Leverage M30 Non-Fused AE Queue Priority Ranking" in md_text
    assert "Milestone #31 14-Feature PSI Telemetry Drift Monitor" in md_text


def test_analyst_dashboard_renders_soar_audit_chain_badge_and_queue_rank() -> None:
    """Analyst dashboard alert detail HTML renders SOAR hash chain badge and queue rank indicator."""
    detail = DashboardAlertDetail(
        alert_candidate_id="alert_cand_m31_unicorn_01",
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

    # 1. SOAR Cryptographic Audit Chain Badge
    assert "badge-soar-chain" in html
    assert "SOAR Cryptographic Audit Chain: VERIFIED (SHA-256 Hash-Linked)" in html

    # 2. Non-Fused Queue Priority Rank Indicator
    assert "badge-queue-rank" in html
    assert "Non-Fused Queue Priority Rank" in html
