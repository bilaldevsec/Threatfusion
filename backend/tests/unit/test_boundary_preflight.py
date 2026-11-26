"""B6 runtime import isolation. A stand-in directory represents the protected repo."""

from __future__ import annotations

from pathlib import Path
import os

from threatfusion.evaluation.boundary_preflight import (
    CANONICAL_ACTIVE_WORKSPACE,
    WALK_SKIP_DIRS,
    check_b2_symlinks,
    check_b4_git_metadata,
    check_b5_code_config,
    check_b6_runtime_import_isolation,
    run_boundary_preflight,
)


def test_b6_fails_when_pythonpath_points_at_protected_stand_in(tmp_path: Path) -> None:
    stand_in = tmp_path / "protected_stand_in"
    stand_in.mkdir()
    active = CANONICAL_ACTIVE_WORKSPACE.resolve()
    module_file = active / "backend" / "src" / "threatfusion" / "__init__.py"
    passed, findings = check_b6_runtime_import_isolation(
        active_rp=active,
        protected_rp=stand_in.resolve(),
        pythonpath=str(stand_in),
        runtime_sys_path=(str(active),),
        module_file=module_file,
    )
    assert passed is False
    assert any(item.startswith("B6: PYTHONPATH entry ") for item in findings)

    report = run_boundary_preflight(
        protected=stand_in,
        pythonpath=str(stand_in),
        runtime_sys_path=(str(active),),
        module_file=module_file,
    )
    assert report.checks["B6"]["passed"] is False
    assert report.decision_verdict == "NO-GO"
    assert report.passed is False


def test_b6_passes_when_pythonpath_is_unset() -> None:
    active = CANONICAL_ACTIVE_WORKSPACE.resolve()
    module_file = active / "backend" / "src" / "threatfusion" / "__init__.py"
    passed, findings = check_b6_runtime_import_isolation(
        active_rp=active,
        protected_rp=Path("/tmp/threatfusion-b6-absent-stand-in"),
        pythonpath="",
        runtime_sys_path=(str(active),),
        module_file=module_file,
    )
    assert passed is True
    assert findings == []

    report = run_boundary_preflight(pythonpath="", module_file=module_file)
    assert report.checks["B6"]["passed"] is True
    assert report.decision_verdict == "GO"
    assert report.passed is True


def test_b2_and_b5_scan_data_and_artifacts_directories(tmp_path: Path) -> None:
    assert "data" not in WALK_SKIP_DIRS
    assert "artifacts" not in WALK_SKIP_DIRS

    active = tmp_path / "active_ws"
    protected = tmp_path / "protected_ws"
    active.mkdir()
    protected.mkdir()
    secret = protected / "secret.txt"
    secret.write_text("secret", encoding="utf-8")

    data_dir = active / "data"
    artifacts_dir = active / "artifacts"
    data_dir.mkdir()
    artifacts_dir.mkdir()

    (data_dir / "bad_symlink.txt").symlink_to(secret)
    (artifacts_dir / "bad_config.json").write_text(
        f'{{"ref": "{protected.resolve()}"}}', encoding="utf-8"
    )

    b2_ok, b2_issues = check_b2_symlinks(active, active.resolve(), protected.resolve())
    assert b2_ok is False
    assert any("data/bad_symlink.txt" in issue for issue in b2_issues)

    b5_ok, b5_issues = check_b5_code_config(active, protected_rp=protected.resolve())
    assert b5_ok is False
    assert any("artifacts/bad_config.json" in issue for issue in b5_issues)


def test_run_boundary_preflight_detects_symlinked_active_root(tmp_path: Path) -> None:
    protected = tmp_path / "protected_ws"
    protected.mkdir()
    sym_active = tmp_path / "sym_active"
    sym_active.symlink_to(protected)

    active_real = CANONICAL_ACTIVE_WORKSPACE.resolve()
    module_file = active_real / "backend" / "src" / "threatfusion" / "__init__.py"
    report = run_boundary_preflight(
        active=sym_active,
        protected=protected,
        cwd=sym_active,
        pythonpath="",
        runtime_sys_path=(str(active_real),),
        module_file=module_file,
    )
    assert report.checks["B2"]["passed"] is False
    assert any("is a symlink into protected workspace" in f for f in report.findings)

    # Also verify inner symlinks are still detected when active root itself is a symlink
    real_active = tmp_path / "real_active"
    real_active.mkdir()
    outside = tmp_path / "outside_target"
    outside.write_text("x", encoding="utf-8")
    (real_active / "inner_escape").symlink_to(outside)
    sym_alias = tmp_path / "sym_alias"
    sym_alias.symlink_to(real_active)

    b2_ok, b2_issues = check_b2_symlinks(
        sym_alias, Path(os.path.realpath(sym_alias)), protected.resolve()
    )
    assert b2_ok is False
    assert any("inner_escape" in issue for issue in b2_issues)


def test_b4_detects_dot_git_symlink_and_worktree_pointer_file(tmp_path: Path) -> None:
    protected = tmp_path / "threatfusion"
    (protected / ".git" / "worktrees" / "wt1").mkdir(parents=True)

    # Case 1: .git is a symlink into protected
    repo_sym = tmp_path / "repo_sym"
    repo_sym.mkdir()
    (repo_sym / ".git").symlink_to(protected / ".git")
    b4_sym_ok, b4_sym_issues = check_b4_git_metadata(repo_sym, protected.resolve())
    assert b4_sym_ok is False
    assert any(".git' symlink" in issue for issue in b4_sym_issues)

    # Case 2: .git is a worktree pointer file with relative gitdir resolving into protected
    repo_wt = tmp_path / "repo_wt"
    repo_wt.mkdir()
    (repo_wt / ".git").write_text("gitdir: ../threatfusion/.git/worktrees/wt1\n", encoding="utf-8")
    b4_wt_ok, b4_wt_issues = check_b4_git_metadata(repo_wt, protected.resolve())
    assert b4_wt_ok is False
    assert any("worktree pointer '.git'" in issue for issue in b4_wt_issues)
