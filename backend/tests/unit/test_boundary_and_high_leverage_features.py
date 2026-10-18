"""Unit tests for Milestone #30: Boundary Preflight, Recall Labeling, SOAR Audit Trail, AE Queue Ranker, and Gate G9 AST Check."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile

import pytest

from threatfusion.evaluation.boundary_preflight import (
    CANONICAL_ACTIVE_WORKSPACE,
    CANONICAL_PROTECTED_WORKSPACE,
    BoundaryPreflightReport,
    check_b0_non_overlap,
    check_b1_cwd_isolation,
    check_b2_symlinks,
    check_b3_venv,
    check_b4_git_metadata,
    check_b5_code_config,
    run_boundary_preflight,
)
from threatfusion.evaluation.repo_truth_audit import (
    GATE_G9_FORBIDDEN_IMPORT_PATTERNS,
    GATE_G9_STAGE_1_TO_4_MODULES,
    verify_gate_g9_ast_import_graph,
)
from threatfusion.evaluation.workload_measurement import evaluate_alert_fatigue_compression
from threatfusion.models.canonical_evaluation import CANONICAL_EVALUATION_PACK_REV2
from threatfusion.models.multi_signal_risk import (
    CANONICAL_V2_AE_THRESHOLD,
    rank_rf_alerts_for_triage_queue,
)
from threatfusion.soar.playbook_ledger import (
    SOAR_AUDIT_GENESIS_HASH,
    SoarPlaybookSqliteRepository,
    compute_soar_audit_entry_hash,
)


class TestBoundaryPreflight:
    """Test deterministic boundary preflight B0-B5 checks."""

    def test_live_boundary_preflight_passes(self) -> None:
        """Live workspace passes all B0-B5 deterministic boundary checks."""
        report = run_boundary_preflight()
        assert isinstance(report, BoundaryPreflightReport)
        assert report.passed is True, f"Boundary preflight failed with findings: {report.findings}"
        assert len(report.findings) == 0
        assert report.active_path == str(CANONICAL_ACTIVE_WORKSPACE.resolve())

    def test_check_b0_and_b1_isolation(self) -> None:
        """Check B0 non-overlap and B1 CWD containment logic."""
        passed, issues = check_b0_non_overlap(
            CANONICAL_ACTIVE_WORKSPACE.resolve(),
            CANONICAL_PROTECTED_WORKSPACE.resolve(),
        )
        assert passed is True
        assert len(issues) == 0

        # Sub-path overlap
        passed_fail, issues_fail = check_b0_non_overlap(
            CANONICAL_PROTECTED_WORKSPACE.resolve(),
            CANONICAL_PROTECTED_WORKSPACE.resolve(),
        )
        assert passed_fail is False
        assert len(issues_fail) == 1

        # CWD containment
        b1_pass, b1_issues = check_b1_cwd_isolation(
            CANONICAL_ACTIVE_WORKSPACE.resolve(),
            CANONICAL_PROTECTED_WORKSPACE.resolve(),
            cwd=CANONICAL_ACTIVE_WORKSPACE,
        )
        assert b1_pass is True
        assert len(b1_issues) == 0

    def test_preflight_no_false_positive_on_gemini_suffix(self) -> None:
        """Check B5 negative lookahead does NOT trigger on 'threatfusion-gemini'."""
        with tempfile.TemporaryDirectory() as td:
            temp_dir = Path(td)
            code_file = temp_dir / "valid_code.py"
            code_file.write_text(
                'WORKSPACE = "/home/muhammad-bilal/projects/threatfusion-gemini/backend"\n',
                encoding="utf-8",
            )
            passed, findings = check_b5_code_config(active_path=temp_dir)
            assert passed is True
            assert len(findings) == 0

    def test_preflight_fails_on_forbidden_literal_leak(self) -> None:
        """Check B5 triggers when code references protected workspace path."""
        with tempfile.TemporaryDirectory() as td:
            temp_dir = Path(td)
            code_file = temp_dir / "leaky_code.py"
            forbidden_str = "/home/muhammad-bilal/projects/threat" + "fusion/backend"
            code_file.write_text(f'REF = "{forbidden_str}"\n', encoding="utf-8")
            passed, findings = check_b5_code_config(active_path=temp_dir)
            assert passed is False
            assert len(findings) == 1
            assert "B5: Code/config file 'leaky_code.py' contains literal reference" in findings[0]

    def test_preflight_fails_on_simulated_pth_leak(self) -> None:
        """Check B3 triggers when site-packages has a .pth file referencing protected workspace."""
        with tempfile.TemporaryDirectory() as td:
            temp_venv = Path(td) / "test-venv"
            site_packages = temp_venv / "lib" / "python3.12" / "site-packages"
            site_packages.mkdir(parents=True)
            pth_file = site_packages / "leak.pth"
            leak_path = "/home/muhammad-bilal/projects/threat" + "fusion"
            pth_file.write_text(f"{leak_path}\n", encoding="utf-8")

            passed, findings = check_b3_venv(
                venv_path=temp_venv,
                active_rp=CANONICAL_ACTIVE_WORKSPACE.resolve(),
                protected_rp=CANONICAL_PROTECTED_WORKSPACE.resolve(),
            )
            assert passed is False
            assert len(findings) == 1
            assert "B3: Virtualenv file" in findings[0]
            assert "contains reference to protected workspace" in findings[0]

    def test_preflight_fails_on_simulated_git_alternates_leak(self) -> None:
        """Check B4 triggers when .git/objects/info/alternates references protected repo."""
        with tempfile.TemporaryDirectory() as td:
            temp_repo = Path(td)
            git_info = temp_repo / ".git" / "objects" / "info"
            git_info.mkdir(parents=True)
            alternates = git_info / "alternates"
            leak_path = "/home/muhammad-bilal/projects/threat" + "fusion/.git/objects"
            alternates.write_text(f"{leak_path}\n", encoding="utf-8")

            passed, findings = check_b4_git_metadata(
                active_path=temp_repo,
                protected_rp=CANONICAL_PROTECTED_WORKSPACE.resolve(),
            )
            assert passed is False
            assert len(findings) == 1
            assert "B4: Git alternates" in findings[0]
            assert "references protected workspace" in findings[0]

    def test_preflight_fails_on_symlink_escape(self) -> None:
        """Check B2 triggers when workspace contains a symlink pointing outside."""
        with tempfile.TemporaryDirectory() as td:
            temp_repo = Path(td) / "active_repo"
            outside_dir = Path(td) / "outside"
            temp_repo.mkdir()
            outside_dir.mkdir()
            target_file = outside_dir / "target.txt"
            target_file.write_text("outside data", encoding="utf-8")

            symlink_path = temp_repo / "escape_link"
            symlink_path.symlink_to(target_file)

            passed, findings = check_b2_symlinks(
                active_path=temp_repo,
                active_rp=temp_repo.resolve(),
                protected_rp=CANONICAL_PROTECTED_WORKSPACE.resolve(),
            )
            assert passed is False
            assert len(findings) == 1
            assert "B2: Symlink 'escape_link' escapes active workspace" in findings[0]


class TestRecallLabelingHarmonization:
    """Test Workstream 2 recall labeling: +2.203 pp recall gain vs +2.373% relative TP increase."""

    def test_counterfactual_fusion_metrics_labeling(self) -> None:
        """CounterfactualFusionShieldMetrics provides exact +2.203 pp and +2.373% values."""
        report = evaluate_alert_fatigue_compression(
            raw_flow_count=100,
            rf_alert_candidate_count=10,
            correlated_incident_count=2,
            uncorrelatable_alert_count=1,
        )
        metrics = report.counterfactual_shield
        rf = CANONICAL_EVALUATION_PACK_REV2.frozen_random_forest
        assert rf.recall_pct == 92.818
        assert metrics.counterfactual_fused_recall_pct == 95.021
        assert metrics.recall_gain_percentage_points == 2.203
        assert metrics.relative_attack_gain_pct == 2.373
        assert metrics.rf_only_true_positives == 4045
        assert metrics.counterfactual_fused_true_positives == 4141
        assert metrics.counterfactual_fused_true_positives - metrics.rf_only_true_positives == 96

    def test_canonical_evaluation_section8_labeling(self) -> None:
        """Canonical Evaluation Pack Rev2 Section 8 complementarity provides exact recall metrics."""
        sec8 = CANONICAL_EVALUATION_PACK_REV2.section_8_complementarity
        rf = CANONICAL_EVALUATION_PACK_REV2.frozen_random_forest
        assert sec8.counterfactual_fused_recall_pct == 95.021
        assert sec8.recall_gain_percentage_points == 2.203
        assert sec8.relative_attack_gain_pct == 2.373
        assert sec8.ae_only_additional_attacks_january == 96
        assert rf.tp == 4045


class TestTamperEvidentSoarAuditTrail:
    """Test Workstream 3 tamper-evident hash-chained SOAR audit trail."""

    def test_valid_audit_chain_lifecycle(self) -> None:
        """Valid audit event insertions maintain unbroken cryptographic hash chain."""
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "test_soar.sqlite3"
            repo = SoarPlaybookSqliteRepository(db_path)

            # Genesis verification on empty database
            is_valid, msg = repo.verify_audit_chain_integrity()
            assert is_valid is True
            assert "verified: 0 entries" in msg

            # Append 3 audit events
            e1 = repo.append_audit_event(
                playbook_id="pb_001",
                action="recommend_action",
                actor_id="system",
                old_state="none",
                new_state="pending_approval",
                reason="Auto-recommendation",
            )
            assert e1.prev_entry_sha256 == SOAR_AUDIT_GENESIS_HASH
            assert len(e1.entry_sha256) == 64

            e2 = repo.append_audit_event(
                playbook_id="pb_001",
                action="approve_action",
                actor_id="analyst_alice",
                old_state="pending_approval",
                new_state="approved",
                reason="Verified malicious traffic",
            )
            assert e2.prev_entry_sha256 == e1.entry_sha256

            e3 = repo.append_audit_event(
                playbook_id="pb_001",
                action="execute_action",
                actor_id="analyst_alice",
                old_state="approved",
                new_state="executed",
                reason="Playbook dispatched",
            )
            assert e3.prev_entry_sha256 == e2.entry_sha256

            # Verify entire chain
            is_valid, msg = repo.verify_audit_chain_integrity()
            assert is_valid is True
            assert "verified: 3 entries" in msg

            # Verify single playbook filter
            is_valid, msg = repo.verify_audit_chain_integrity(playbook_id="pb_001")
            assert is_valid is True

    def test_audit_chain_tamper_detection_sql_update(self) -> None:
        """Direct SQL UPDATE of audit entry data breaks cryptographic chain verification."""
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "test_soar.sqlite3"
            repo = SoarPlaybookSqliteRepository(db_path)

            repo.append_audit_event(
                playbook_id="pb_001",
                action="recommend_action",
                actor_id="system",
                old_state="none",
                new_state="pending_approval",
            )
            repo.append_audit_event(
                playbook_id="pb_001",
                action="approve_action",
                actor_id="analyst_alice",
                old_state="pending_approval",
                new_state="approved",
            )

            # Adversarial SQL tampering on row 1
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    "UPDATE soar_audit_events SET actor_id = 'adversary_attacker' WHERE rowid = 1"
                )
                conn.commit()

            is_valid, msg = repo.verify_audit_chain_integrity()
            assert is_valid is False
            assert "broken at row index" in msg
            assert "!=" in msg

    def test_audit_chain_tamper_detection_sql_delete(self) -> None:
        """Adversarial row deletion breaks cryptographic hash chaining."""
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "test_soar.sqlite3"
            repo = SoarPlaybookSqliteRepository(db_path)

            for i in range(1, 4):
                repo.append_audit_event(
                    playbook_id=f"pb_00{i}",
                    action="recommend_action",
                    actor_id="system",
                    old_state="none",
                    new_state="pending_approval",
                )

            # Delete middle event (rowid 2)
            with sqlite3.connect(db_path) as conn:
                conn.execute("DELETE FROM soar_audit_events WHERE rowid = 2")
                conn.commit()

            is_valid, msg = repo.verify_audit_chain_integrity()
            assert is_valid is False
            assert "broken at row index" in msg
            assert "prev_entry_sha256" in msg

    def test_compute_soar_audit_entry_hash(self) -> None:
        """Verify deterministic hashing utility produces 64-char sha256."""
        h = compute_soar_audit_entry_hash(
            event_id="test_ev",
            playbook_id="test_pb",
            action="test_act",
            actor_id="test_actor",
            old_state="none",
            new_state="pending",
            reason=None,
            snapshot=None,
            timestamp_utc="2026-10-18T00:00:00Z",
            prev_entry_sha256=SOAR_AUDIT_GENESIS_HASH,
        )
        assert len(h) == 64


class TestNonFusedAeQueuePriorityRanker:
    """Test Workstream 3 non-fused AE queue priority ranker."""

    def test_canonical_v2_ae_threshold(self) -> None:
        """Verify canonical v2 AE threshold is exactly 0.1181361214680695."""
        assert CANONICAL_V2_AE_THRESHOLD == 0.1181361214680695

    def test_rank_rf_alerts_filters_sub_threshold(self) -> None:
        """Alerts with rf_attack_probability < 0.5 are filtered out."""
        alerts = [
            {"candidate_id": "c1", "rf_attack_probability": 0.499, "ae_reconstruction_error": 0.5},
            {"candidate_id": "c2", "rf_attack_probability": 0.500, "ae_reconstruction_error": 0.1},
            {"candidate_id": "c3", "rf_attack_probability": 0.850, "ae_reconstruction_error": 0.2},
        ]
        ranked = rank_rf_alerts_for_triage_queue(alerts, production_fusion_enabled=False)
        assert len(ranked) == 2
        candidate_ids = {a["candidate_id"] for a in ranked}
        assert candidate_ids == {"c2", "c3"}

    def test_rank_rf_alerts_priority_ordering(self) -> None:
        """Triage queue orders by burst size, then AE anomaly ratio, then RF probability."""
        alerts = [
            {
                "candidate_id": "burst_heavy",
                "rf_attack_probability": 0.60,
                "ae_reconstruction_error": 0.15,
                "burst_packet_count": 50,
            },
            {
                "candidate_id": "ae_high_anomaly",
                "rf_attack_probability": 0.60,
                "ae_reconstruction_error": 0.35,  # Ratio ~ 2.96x
                "burst_packet_count": 10,
            },
            {
                "candidate_id": "ae_normal",
                "rf_attack_probability": 0.60,
                "ae_reconstruction_error": 0.12,  # Ratio ~ 1.02x
                "burst_packet_count": 10,
            },
            {
                "candidate_id": "ae_high_anomaly_high_rf",
                "rf_attack_probability": 0.95,
                "ae_reconstruction_error": 0.35,  # Ratio ~ 2.96x
                "burst_packet_count": 10,
            },
        ]
        ranked = rank_rf_alerts_for_triage_queue(alerts, production_fusion_enabled=False)
        assert len(ranked) == 4

        # Rank 1 must be burst_heavy (burst size 50 vs 10)
        assert ranked[0]["candidate_id"] == "burst_heavy"
        assert ranked[0]["queue_priority_rank"] == 1

        # Rank 2 must be ae_high_anomaly_high_rf (same burst 10, same high AE ratio ~2.96, higher RF 0.95 vs 0.60)
        assert ranked[1]["candidate_id"] == "ae_high_anomaly_high_rf"
        assert ranked[1]["queue_priority_rank"] == 2

        # Rank 3 must be ae_high_anomaly (same burst 10, same high AE ratio ~2.96, lower RF 0.60)
        assert ranked[2]["candidate_id"] == "ae_high_anomaly"
        assert ranked[2]["queue_priority_rank"] == 3

        # Rank 4 must be ae_normal (same burst 10, lower AE ratio ~1.02)
        assert ranked[3]["candidate_id"] == "ae_normal"
        assert ranked[3]["queue_priority_rank"] == 4

        # Verify rationale string attached
        for r in ranked:
            assert "priority_rationale" in r
            assert "RF Prob=" in r["priority_rationale"]

    def test_rank_rf_alerts_raises_on_fusion_enabled(self) -> None:
        """Fails closed if production_fusion_enabled is True."""
        alerts = [{"candidate_id": "c1", "rf_attack_probability": 0.9}]
        with pytest.raises(ValueError, match="production_fusion_enabled must remain False"):
            rank_rf_alerts_for_triage_queue(alerts, production_fusion_enabled=True)


class TestGateG9AstImportGraph:
    """Test Workstream 4 Gate G9 AST Detection Import-Graph Check."""

    def test_live_gate_g9_ast_import_graph_passes(self) -> None:
        """Live codebase Stage 1-4 detection pipeline contains zero forbidden advisory imports."""
        src_root = Path(__file__).resolve().parents[2] / "src"
        passed, violations = verify_gate_g9_ast_import_graph(src_root)
        assert passed is True, f"Gate G9 failed on live codebase: {violations}"
        assert len(violations) == 0

    def test_gate_g9_constants(self) -> None:
        """Verify Gate G9 constants definition."""
        assert "threatfusion.advisory" in GATE_G9_FORBIDDEN_IMPORT_PATTERNS
        assert "gemini_client" in GATE_G9_FORBIDDEN_IMPORT_PATTERNS
        assert "explanation_engine" in GATE_G9_FORBIDDEN_IMPORT_PATTERNS

    def test_gate_g9_detects_forbidden_import(self) -> None:
        """Gate G9 AST verifier detects forbidden import 'threatfusion.advisory'."""
        with tempfile.TemporaryDirectory() as td:
            temp_src = Path(td)
            for rel_mod in GATE_G9_STAGE_1_TO_4_MODULES:
                mod_path = temp_src / rel_mod
                mod_path.parent.mkdir(parents=True, exist_ok=True)
                if "suricata_flow.py" in rel_mod:
                    mod_path.write_text(
                        "import threatfusion.advisory.gemini_client\n", encoding="utf-8"
                    )
                else:
                    mod_path.write_text("# clean module\n", encoding="utf-8")

            passed, violations = verify_gate_g9_ast_import_graph(temp_src)
            assert passed is False
            assert len(violations) >= 1
            assert any("threatfusion.advisory" in v for v in violations)

    def test_gate_g9_detects_forbidden_from_import(self) -> None:
        """Gate G9 AST verifier detects forbidden from-import 'gemini_client'."""
        with tempfile.TemporaryDirectory() as td:
            temp_src = Path(td)
            for rel_mod in GATE_G9_STAGE_1_TO_4_MODULES:
                mod_path = temp_src / rel_mod
                mod_path.parent.mkdir(parents=True, exist_ok=True)
                if "correlation_engine.py" in rel_mod:
                    mod_path.write_text(
                        "from threatfusion.advisory.explanation_engine import AdvisoryEvidenceBundle\n",
                        encoding="utf-8",
                    )
                else:
                    mod_path.write_text("# clean module\n", encoding="utf-8")

            passed, violations = verify_gate_g9_ast_import_graph(temp_src)
            assert passed is False
            assert len(violations) >= 1
            assert any("explanation_engine" in v for v in violations)
