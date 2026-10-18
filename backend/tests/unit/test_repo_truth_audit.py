"""Unit tests for Deterministic Zero-Trust Repository Truth Audit Gate."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType

import pytest

from threatfusion.evaluation.repo_truth_audit import (
    CANONICAL_PROJECT_RELEASE_READINESS,
    EXPECTED_MODEL_DIGESTS,
    REPO_TRUTH_AUDIT_SCHEMA_VERSION,
    _check_2_frozen_model_invariance,
    _verify_module_origin,
    run_repository_truth_audit,
)


class TestRepoTruthAudit:
    """Test ground-truth verification of live repository reality and fail-closed security gates."""

    def test_live_repository_truth_audit_passes(self) -> None:
        """Live repository passes all 7 deterministic ground-truth checks."""
        report = run_repository_truth_audit()

        assert report.audit_version == REPO_TRUTH_AUDIT_SCHEMA_VERSION
        assert report.all_checks_passed is True
        assert len(report.checks) == 7

        # Every individual check must pass
        for c in report.checks:
            assert c.passed is True, f"Check {c.check_id} ({c.name}) failed: {c.summary}"

        # Git state checks
        assert report.git_branch == "gemini/product-20260924"
        assert len(report.git_head_sha) == 40

        # Frozen model digest checks
        assert report.model_digests["random_forest"]["matched"] is True
        assert (
            report.model_digests["random_forest"]["actual_sha256"]
            == "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"
        )
        assert report.model_digests["logistic_regression"]["matched"] is True
        assert report.model_digests["autoencoder_v2"]["matched"] is True
        assert report.model_digests["rate_log1p_candidate"]["matched"] is True

        # Receipt banner checks
        banner = report.render_receipt_banner()
        assert "ALL 7 ZERO-TRUST CHECKS PASSED" in banner
        assert len(report.receipt_digest) == 64

        # Dictionary serialization
        report_dict = report.to_dict()
        assert report_dict["all_checks_passed"] is True
        assert len(report_dict["checks"]) == 7

    def test_audit_fails_closed_when_tf009_marked_resolved(self) -> None:
        """Tampering with issue_register.md to prematurely mark TF-009 as resolved fails closed."""
        repo_root = Path(__file__).resolve().parents[3]
        real_register = repo_root / "docs" / "issue_register.md"
        real_text = real_register.read_text(encoding="utf-8")

        lines = real_text.splitlines()
        tampered_lines = []
        for line in lines:
            if line.strip().startswith("| TF-009 |"):
                # Replace the trailing '| open |' with '| resolved |'
                parts = line.split("|")
                parts[7] = " resolved "
                tampered_lines.append("|".join(parts))
            else:
                tampered_lines.append(line)
        tampered_text = "\n".join(tampered_lines)

        with tempfile.TemporaryDirectory() as td:
            tampered_path = Path(td) / "issue_register.md"
            tampered_path.write_text(tampered_text, encoding="utf-8")

            report = run_repository_truth_audit(
                repo_root=repo_root, issue_register_path=tampered_path
            )

            assert report.all_checks_passed is False
            c7 = [c for c in report.checks if c.check_id == 7][0]
            assert c7.passed is False
            assert "TF-009 is marked 'resolved'" in c7.summary or any(
                "TF-009 is marked 'resolved'" in f for f in c7.details.get("failures", [])
            )
            assert "AUDIT FAILED" in report.render_receipt_banner()

    def test_audit_fails_closed_when_tf010_scope_drifted(self) -> None:
        """Altering TF-010 canonical scope/keywords in issue_register.md fails closed."""
        repo_root = Path(__file__).resolve().parents[3]
        real_register = repo_root / "docs" / "issue_register.md"
        real_text = real_register.read_text(encoding="utf-8")

        lines = real_text.splitlines()
        tampered_lines = []
        for line in lines:
            if line.strip().startswith("| TF-010 |"):
                # Replace with generic drifted row omitting 'jury rubric' and 'FAST-NUCES'
                tampered_lines.append(
                    "| TF-010 | P1 / high | Generic unverified evaluation claims | Scope description here | Next action steps | Detailed closure test | open |"
                )
            else:
                tampered_lines.append(line)
        tampered_text = "\n".join(tampered_lines)

        with tempfile.TemporaryDirectory() as td:
            tampered_path = Path(td) / "issue_register.md"
            tampered_path.write_text(tampered_text, encoding="utf-8")

            report = run_repository_truth_audit(
                repo_root=repo_root, issue_register_path=tampered_path
            )

            assert report.all_checks_passed is False
            c7 = [c for c in report.checks if c.check_id == 7][0]
            assert c7.passed is False
            assert any(
                "Canonical field mismatch for TF-010" in f for f in c7.details.get("failures", [])
            )

    def test_repo_truth_audit_rejects_keyword_preserving_scope_alteration(self) -> None:
        """Modifying a TF-010 cell while retaining 'rubric' and 'FAST-NUCES' keywords fails Check 7 closed."""
        repo_root = Path(__file__).resolve().parents[3]
        real_register = repo_root / "docs" / "issue_register.md"
        real_text = real_register.read_text(encoding="utf-8")

        lines = real_text.splitlines()
        tampered_lines = []
        for line in lines:
            if line.strip().startswith("| TF-010 |"):
                parts = line.split("|")
                parts[4] = " Altered scope control and FAST-NUCES jury rubric compliance "
                tampered_lines.append("|".join(parts))
            else:
                tampered_lines.append(line)
        tampered_text = "\n".join(tampered_lines)

        with tempfile.TemporaryDirectory() as td:
            tampered_path = Path(td) / "issue_register.md"
            tampered_path.write_text(tampered_text, encoding="utf-8")

            report = run_repository_truth_audit(
                repo_root=repo_root, issue_register_path=tampered_path
            )

            assert report.all_checks_passed is False
            c7 = [c for c in report.checks if c.check_id == 7][0]
            assert c7.passed is False
            assert any(
                "Canonical field mismatch for TF-010" in f for f in c7.details.get("failures", [])
            )

    def test_repo_truth_audit_rejects_duplicate_issue_rows(self) -> None:
        """Appending a duplicate | TF-010 | row in issue_register.md fails Check 7 closed."""
        repo_root = Path(__file__).resolve().parents[3]
        real_register = repo_root / "docs" / "issue_register.md"
        real_text = real_register.read_text(encoding="utf-8")

        # Duplicate the TF-010 row
        dup_row = (
            "| TF-010 | P1 / high | **Duplicate TF-010 Entry.** | Scope description | "
            "Next action details | Closure test specifications | open |"
        )
        tampered_text = real_text + "\n" + dup_row + "\n"

        with tempfile.TemporaryDirectory() as td:
            tampered_path = Path(td) / "issue_register.md"
            tampered_path.write_text(tampered_text, encoding="utf-8")

            report = run_repository_truth_audit(
                repo_root=repo_root, issue_register_path=tampered_path
            )

            assert report.all_checks_passed is False
            c7 = [c for c in report.checks if c.check_id == 7][0]
            assert c7.passed is False
            assert any(
                "Duplicate issue ID detected in issue_register.md: TF-010" in f
                for f in c7.details.get("failures", [])
            )

    def test_repo_truth_audit_rejects_contradictory_tf010_resolved_in_docs(self) -> None:
        """Contradictory claim of 'TF-010 resolved' in project_status or GEMINI_PROJECT_MASTER fails Check 7."""
        repo_root = Path(__file__).resolve().parents[3]

        with tempfile.TemporaryDirectory() as td:
            tampered_status = Path(td) / "project_status.md"
            tampered_status.write_text(
                "# Status\n\n### 2026-10-16 — Phase P5: Registry (TF-010 Resolved)\nAll items completed.\n",
                encoding="utf-8",
            )

            report = run_repository_truth_audit(
                repo_root=repo_root, project_status_path=tampered_status
            )

            assert report.all_checks_passed is False
            c7 = [c for c in report.checks if c.check_id == 7][0]
            assert c7.passed is False
            assert any(
                "Contradictory 'TF-010 resolved' claim detected" in f
                for f in c7.details.get("failures", [])
            )

    def test_repo_truth_audit_fails_closed_when_model_artifact_is_directory_or_symlink(
        self,
    ) -> None:
        """Directory or symlink in place of frozen model artifact fails Check 2 cleanly without unhandled exception."""
        with tempfile.TemporaryDirectory() as td:
            fake_root = Path(td)
            rf_rel = EXPECTED_MODEL_DIGESTS["random_forest"]["rel_path"]
            rf_full = fake_root / rf_rel
            rf_full.parent.mkdir(parents=True, exist_ok=True)

            # Case A: Model artifact path is a directory
            rf_full.mkdir(parents=True, exist_ok=True)

            c2, digests = _check_2_frozen_model_invariance(fake_root)
            assert c2.passed is False
            assert digests["random_forest"]["actual_sha256"] == "NON_REGULAR_OR_SYMLINK"
            assert "not a regular file" in c2.summary or "missing" in c2.summary

            # Case B: Model artifact path is a symlink
            rf_full.rmdir()
            target_dummy = fake_root / "dummy.txt"
            target_dummy.write_text("dummy", encoding="utf-8")
            os.symlink(target_dummy, rf_full)

            c2_sym, digests_sym = _check_2_frozen_model_invariance(fake_root)
            assert c2_sym.passed is False
            assert digests_sym["random_forest"]["actual_sha256"] == "NON_REGULAR_OR_SYMLINK"
            assert "symlink" in c2_sym.summary

    def test_repo_truth_audit_detects_shadowed_module_origin(self) -> None:
        """Module resolved outside workspace backend/src is detected and rejected."""
        repo_root = Path(__file__).resolve().parents[3]
        expected_src = repo_root / "backend" / "src"

        # Valid module inside workspace
        import threatfusion.models.canonical_evaluation as valid_mod

        ok_valid, msg_valid = _verify_module_origin(valid_mod, expected_src)
        assert ok_valid is True
        assert msg_valid == "OK"

        # Shadowed module with __file__ outside workspace
        shadowed_mod = ModuleType("threatfusion.shadowed")
        shadowed_mod.__file__ = "/usr/local/lib/python3.11/dist-packages/threatfusion/shadowed.py"

        ok_shadowed, msg_shadowed = _verify_module_origin(shadowed_mod, expected_src)
        assert ok_shadowed is False
        assert "outside expected workspace source root" in msg_shadowed

        # Module without __file__ attribute
        no_file_mod = ModuleType("threatfusion.no_file")
        ok_no_file, msg_no_file = _verify_module_origin(no_file_mod, expected_src)
        assert ok_no_file is False
        assert "lacks __file__ attribute" in msg_no_file

    def test_audit_fails_closed_when_workspace_root_invalid(self) -> None:
        """Executing from an untrusted workspace root fails Check 1 immediately."""
        fake_root = Path("/tmp/untrusted_threatfusion_workspace")
        report = run_repository_truth_audit(repo_root=fake_root)

        assert report.all_checks_passed is False
        c1 = [c for c in report.checks if c.check_id == 1][0]
        assert c1.passed is False
        assert "Workspace path mismatch" in c1.summary

    def test_audit_fails_closed_on_missing_model_files(self) -> None:
        """Missing model file in candidate directory fails Check 2."""
        with tempfile.TemporaryDirectory() as td:
            empty_root = Path(td)
            c2, digests = _check_2_frozen_model_invariance(empty_root)
            assert c2.passed is False
            assert "missing" in c2.summary.lower()

    def test_cli_runner_script_execution(self) -> None:
        """CLI script scripts/audit_repo_truth.py executes with exit 0 and supports --json flag."""
        repo_root = Path(__file__).resolve().parents[3]
        script_path = repo_root / "scripts" / "audit_repo_truth.py"

        # Test human-readable banner exit 0
        proc_banner = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        )
        assert proc_banner.returncode == 0
        assert "ALL 7 ZERO-TRUST CHECKS PASSED" in proc_banner.stdout
        assert (
            "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9" in proc_banner.stdout
        )

        # Test --json flag
        proc_json = subprocess.run(
            [sys.executable, str(script_path), "--json"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        )
        assert proc_json.returncode == 0
        payload = json.loads(proc_json.stdout)
        assert payload["audit_version"] == REPO_TRUTH_AUDIT_SCHEMA_VERSION
        assert payload["all_checks_passed"] is True
        assert len(payload["checks"]) == 7

    def test_audit_fails_closed_when_correlation_windows_tampered(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tampering with correlation engine BURST_WINDOW_SECONDS or CAMPAIGN_WINDOW_SECONDS fails Check 6."""
        import threatfusion.alerts.correlation_engine as ce

        monkeypatch.setattr(ce, "BURST_WINDOW_SECONDS", 45.0)
        report = run_repository_truth_audit()
        assert report.all_checks_passed is False
        c6 = [c for c in report.checks if c.check_id == 6][0]
        assert c6.passed is False
        assert any(
            "Pillar 4 BURST_WINDOW_SECONDS mismatch" in f for f in c6.details.get("failures", [])
        )

    def test_audit_fails_closed_when_unicorn_sop_missing(self) -> None:
        """Missing design_guidelines/soc_unicorn_interface_sop.md fails Check 5 closed."""
        repo_root = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory() as td:
            fake_root = Path(td)
            # Create minimal structure without design_guidelines
            expected_src = repo_root / "backend" / "src"
            from threatfusion.evaluation.repo_truth_audit import (
                _check_5_no_duplicate_package_regression,
            )

            c5 = _check_5_no_duplicate_package_regression(fake_root, expected_src)
            assert c5.passed is False
            assert any(
                "Missing required architecture SOP file: design_guidelines/soc_unicorn_interface_sop.md"
                in f
                for f in c5.details.get("failures", [])
            )

    def test_audit_fails_closed_when_budget_kill_switch_probe_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tampering with evaluate_budget_kill_switch to return False at $5.00 fails Check 6."""
        import threatfusion.operations.cloud_live_telemetry as clt

        monkeypatch.setattr(
            clt,
            "evaluate_budget_kill_switch",
            lambda spend, policy=None: {"should_detach_billing": False},
        )
        report = run_repository_truth_audit()
        assert report.all_checks_passed is False
        c6 = [c for c in report.checks if c.check_id == 6][0]
        assert c6.passed is False
        assert any(
            "M28 evaluate_budget_kill_switch(5.0) should_detach_billing is not True" in f
            for f in c6.details.get("failures", [])
        )

    def test_repo_truth_audit_rejects_unexpected_symlink_in_backend_tree(self) -> None:
        """Creating an unexpected symlink inside the backend tree causes Check 1 to fail closed and report NO-GO."""
        with tempfile.TemporaryDirectory() as td:
            fake_root = Path(td).resolve()
            # Initialize a minimal git repository
            subprocess.run(["git", "init"], cwd=fake_root, capture_output=True, check=True)
            subprocess.run(
                ["git", "config", "user.name", "Test Auditor"],
                cwd=fake_root,
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "auditor@example.com"],
                cwd=fake_root,
                capture_output=True,
                check=True,
            )

            # Create backend/tests/unit directory structure and real file
            target_dir = fake_root / "backend" / "tests" / "unit"
            target_dir.mkdir(parents=True, exist_ok=True)
            real_file = target_dir / "sample.py"
            real_file.write_text("# dummy\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=fake_root, capture_output=True, check=True)
            subprocess.run(
                ["git", "commit", "-m", "init"],
                cwd=fake_root,
                capture_output=True,
                check=True,
            )

            # Create an unexpected symlink inside backend/tests/unit/
            symlink_path = target_dir / "symlink_sample.py"
            symlink_path.symlink_to(real_file)

            # Run audit on fake_root
            report = run_repository_truth_audit(repo_root=fake_root)

            assert report.decision_verdict == "NO-GO"
            assert report.repository_integrity_decision == "NO-GO"
            assert report.all_checks_passed is False
            assert "Check 1" in report.failed_check_ids
            c1 = [c for c in report.checks if c.check_id == 1][0]
            assert c1.passed is False
            assert "Unexpected symlink detected in workspace tree:" in c1.summary
            assert len(c1.details.get("detected_symlinks", [])) > 0
            assert any("symlink_sample.py" in s for s in c1.details.get("detected_symlinks", []))

    def test_repo_truth_audit_rejects_symlink_anywhere_in_repo_boundary(self) -> None:
        """Symlink injection at root-level, inside scripts/, or on repo_root itself triggers repository_integrity_decision == 'NO-GO'."""
        with tempfile.TemporaryDirectory() as td:
            fake_root = Path(td).resolve()
            subprocess.run(["git", "init"], cwd=fake_root, capture_output=True, check=True)
            subprocess.run(
                ["git", "config", "user.name", "Test Auditor"],
                cwd=fake_root,
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "auditor@example.com"],
                cwd=fake_root,
                capture_output=True,
                check=True,
            )

            # Base files
            scripts_dir = fake_root / "scripts"
            scripts_dir.mkdir(parents=True, exist_ok=True)
            real_script = scripts_dir / "real_script.py"
            real_script.write_text("# script\n", encoding="utf-8")
            root_real = fake_root / "root_file.txt"
            root_real.write_text("root\n", encoding="utf-8")

            subprocess.run(["git", "add", "."], cwd=fake_root, capture_output=True, check=True)
            subprocess.run(
                ["git", "commit", "-m", "init"],
                cwd=fake_root,
                capture_output=True,
                check=True,
            )

            # Case A: Symlink in scripts/
            script_symlink = scripts_dir / "evil_script_symlink.py"
            script_symlink.symlink_to(real_script)
            rep_a = run_repository_truth_audit(repo_root=fake_root)
            assert rep_a.repository_integrity_decision == "NO-GO"
            assert rep_a.decision_verdict == "NO-GO"
            assert "Check 1" in rep_a.failed_check_ids
            c1_a = [c for c in rep_a.checks if c.check_id == 1][0]
            assert any(
                "scripts/evil_script_symlink.py" in s
                for s in c1_a.details.get("detected_symlinks", [])
            )
            script_symlink.unlink()

            # Case B: Root-level symlink
            root_symlink = fake_root / "evil_root_symlink.py"
            root_symlink.symlink_to(root_real)
            rep_b = run_repository_truth_audit(repo_root=fake_root)
            assert rep_b.repository_integrity_decision == "NO-GO"
            assert rep_b.decision_verdict == "NO-GO"
            assert "Check 1" in rep_b.failed_check_ids
            c1_b = [c for c in rep_b.checks if c.check_id == 1][0]
            assert any(
                "evil_root_symlink.py" in s for s in c1_b.details.get("detected_symlinks", [])
            )
            root_symlink.unlink()

            # Case C: repo_root itself is a symlink
            symlink_repo_root = Path(td) / "symlink_repo_root"
            symlink_repo_root.symlink_to(fake_root)
            rep_c = run_repository_truth_audit(repo_root=symlink_repo_root)
            assert rep_c.repository_integrity_decision == "NO-GO"
            assert rep_c.decision_verdict == "NO-GO"
            assert "Check 1" in rep_c.failed_check_ids
            c1_c = [c for c in rep_c.checks if c.check_id == 1][0]
            assert "Repository root is a symlink" in c1_c.summary
            symlink_repo_root.unlink()

    def test_repo_truth_audit_controlled_valid_fixture_and_scientific_disclosures(
        self,
    ) -> None:
        """Valid repository produces repository_integrity_decision == 'GO', project_release_readiness == BOUNDED_PROTOTYPE_OPEN_EXTERNAL_GATES_TF008_TO_TF011, and 4 unresolved risks."""
        report = run_repository_truth_audit()
        assert report.decision_verdict == "GO"
        assert report.repository_integrity_decision == "GO"
        assert report.project_release_readiness == CANONICAL_PROJECT_RELEASE_READINESS
        assert (
            report.project_release_readiness
            == "BOUNDED_PROTOTYPE_OPEN_EXTERNAL_GATES_TF008_TO_TF011"
        )
        assert report.failed_check_ids == ()
        assert report.all_checks_passed is True
        assert len(report.unresolved_risks) == 4
        assert "TF-008 (open):" in report.unresolved_risks[0]
        assert "TF-009 (open):" in report.unresolved_risks[1]
        assert "TF-010 (open):" in report.unresolved_risks[2]
        assert "TF-011 (open):" in report.unresolved_risks[3]
