"""Unit tests for Canonical Evaluation Pack Rev2 (AI-FYP-2006) and Section 8 fusion_disabled invariant."""

from __future__ import annotations

import pytest

from threatfusion.models.canonical_evaluation import (
    CANONICAL_EVALUATION_PACK_REV2,
    CANONICAL_EVALUATION_SCHEMA_VERSION,
    PROJECT_TITLE,
    SECTION_8_FUSION_DISABLED_POLICY,
    CanonicalEvaluationPackRev2,
    FusionDisabledError,
    assert_fusion_disabled_invariant,
    execute_production_inference_guard,
    get_canonical_evaluation_pack_rev2,
    is_fusion_enabled,
)


def test_canonical_evaluation_pack_metadata_and_constants() -> None:
    pack = get_canonical_evaluation_pack_rev2()
    assert isinstance(pack, CanonicalEvaluationPackRev2)
    assert pack.schema_version == CANONICAL_EVALUATION_SCHEMA_VERSION
    assert pack.project_id == "AI-FYP-2006"
    assert pack.project_identifier == "AI-FYP-2006"
    assert pack.project_title == PROJECT_TITLE
    assert "FAST-NUCES Karachi" in pack.institution
    assert pack.supervisor == "Sir Sameer Faisal"
    assert pack.team_members == (
        ("Muhammad Bilal", "21K-3551"),
        ("Muhammad Suhaib Shaikh", "22K-4302"),
        ("Muhammad Hasnain", "22K-4718"),
    )
    assert pack.evaluation_checkpoint_commit == "6a36dcd9af17bf509977bcf966f2ace72644d5b2"
    assert pack.fusion_disabled is True
    assert is_fusion_enabled() is False
    assert CANONICAL_EVALUATION_PACK_REV2.project_id == "AI-FYP-2006"


def test_dataset_populations_exact_numbers() -> None:
    pop = get_canonical_evaluation_pack_rev2().populations
    assert pop.train_total_rows == 865480
    assert pop.train_benign_rows == 847837
    assert pop.train_attack_rows == 17643
    assert pop.january_validation_total_rows == 216568
    assert pop.january_validation_attack_rows == 4358
    assert pop.january_validation_benign_rows == 212210
    assert pop.february_benchmark_total_rows == 1452844


def test_frozen_random_forest_exact_metrics() -> None:
    rf = get_canonical_evaluation_pack_rev2().frozen_random_forest
    assert rf.model_version == "full-network-random-forest-6d69c72-v1"
    assert rf.population_rows == 216568
    assert rf.tp == 4045
    assert rf.fp == 201
    assert rf.tn == 212009
    assert rf.fn == 313
    assert rf.precision_pct == 95.266
    assert rf.recall_pct == 92.818
    assert rf.f1_pct == 94.026
    assert rf.fpr_pct == 0.095
    assert rf.demo_row_1_attack_probability == 0.00001
    assert rf.demo_row_21_attack_probability == 0.8249883171915375


def test_corrected_autoencoder_v2_exact_metrics() -> None:
    ae = get_canonical_evaluation_pack_rev2().autoencoder_v2
    assert ae.architecture == "14->8->3->8->14"
    assert ae.threshold == 0.1181361214680695
    # January
    assert ae.january_total_rows == 216568
    assert ae.january_tp == 1988
    assert ae.january_fp == 1628
    assert ae.january_tn == 210582
    assert ae.january_fn == 2370
    assert ae.january_precision_pct == 54.978
    assert ae.january_recall_pct == 45.617
    assert ae.january_f1_pct == 49.862
    assert ae.january_fpr_pct == 0.767
    # February
    assert ae.february_total_rows == 1452844
    assert ae.february_tp == 248531
    assert ae.february_fp == 25934
    assert ae.february_tn == 1127842
    assert ae.february_fn == 50537
    assert ae.february_precision_pct == 90.551
    assert ae.february_recall_pct == 83.102
    assert ae.february_f1_pct == 86.667
    assert ae.february_fpr_pct == 2.248


def test_section_8_complementarity_and_residual_audit() -> None:
    pack = get_canonical_evaluation_pack_rev2()
    comp = pack.section_8_complementarity
    assert comp.ae_only_additional_attacks_january == 96
    assert comp.ae_only_additional_benign_fps_january == 1574
    assert comp.benign_fps_per_additional_attack == 16.395833333333332
    assert comp.production_fusion_enabled is False

    audit = pack.january_residual_audit
    assert audit.audit_label == "january-v2-record-concentration-b5e6e5d"
    assert audit.rates_group_pooled_error_pct_ae_only_attacks == 93.784
    assert audit.rates_group_pooled_error_pct_ae_only_benign_fps == 38.748
    assert audit.top_158_benign_fp_whole_record_error_pct == 69.938
    assert audit.top_158_benign_fp_rate_group_error_pct == 95.676

    blocked = pack.blocked_candidate
    assert blocked.candidate_version == "rate-log1p-autoencoder-b5e6e5d-v1"
    assert blocked.disposition == "BLOCKED_preserve_baseline"
    assert blocked.ae_only_attacks == 59
    assert blocked.ae_only_benign_fps == 2080
    assert blocked.total_ae_fps == 2122
    assert blocked.tp == 945
    assert blocked.recall_pct == 21.684
    assert blocked.fpr_pct == 1.000


def test_legacy_fyp1_superseded_summary() -> None:
    legacy = get_canonical_evaluation_pack_rev2().legacy_superseded
    assert legacy.superseded_by_fyp2_eval_pack_rev2 is True
    assert legacy.rf_binary_accuracy_pct == 89.77
    assert legacy.rf_binary_f1_pct == 91.31
    assert legacy.deck_multimodal_fusion_accuracy_pct == 94.95
    assert legacy.deck_multimodal_fusion_f1_pct == 96.30


def test_section_8_fusion_disabled_invariant() -> None:
    assert "production_fusion_enabled = False" in SECTION_8_FUSION_DISABLED_POLICY
    assert_fusion_disabled_invariant()

    # Inference guard allows approved baseline
    res = execute_production_inference_guard("random_forest")
    assert res == "frozen_random_forest_approved"

    # Inference guard strictly blocks fusion modes
    with pytest.raises(FusionDisabledError) as exc_info:
        execute_production_inference_guard("decision_fusion")
    assert "blocked_pending_corrected_split_verification" in str(exc_info.value)

    with pytest.raises(FusionDisabledError):
        execute_production_inference_guard("candidate_fusion")

    with pytest.raises(FusionDisabledError):
        execute_production_inference_guard("fused_dl")


def test_pack_to_dict_serialization() -> None:
    pack = get_canonical_evaluation_pack_rev2()
    d = pack.to_dict()
    assert d["schema_version"] == "canonical_evaluation_pack_v2"
    assert d["project_id"] == "AI-FYP-2006"
    assert d["fusion_disabled"] is True
    assert d["frozen_random_forest"]["precision_pct"] == 95.266
    assert d["section_8_complementarity"]["benign_fps_per_additional_attack"] == 16.395833333333332
    assert d["legacy_superseded"]["superseded_by_fyp2_eval_pack_rev2"] is True
