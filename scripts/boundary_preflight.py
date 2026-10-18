"""Deterministic Zero-Trust Boundary Preflight Guard (B0 through B5).

Enforces Protocol 0 strict reference isolation:
- B0: Active and protected realpaths do not overlap.
- B1: Current working directory resolves inside active and outside protected.
- B2: Workspace contains no symlinks pointing into protected or escaping active.
- B3: Virtualenv contains no references (*.pth, direct_url.json, *.egg-link, etc.) or symlinks to protected.
- B4: Git metadata (.git/objects/info/alternates, worktrees, config) contains no reference to protected.
- B5: Runtime code and config files (.py, .toml, .json, etc.) contain no literal references to protected.

Exit Codes:
- 0: GO (0 findings, boundary fully secure)
- 2: NO-GO (findings > 0, boundary violation detected)
- 3: UNEXPECTED EXCEPTION (fail-closed boundary fault)
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

CANONICAL_ACTIVE_WORKSPACE = Path("/home/muhammad-bilal/projects/threatfusion-gemini")
CANONICAL_PROTECTED_WORKSPACE = Path("/home/muhammad-bilal/projects/threatfusion")

EXEMPT_B5_FILES: frozenset[str] = frozenset(
    {
        "scripts/boundary_preflight.py",
        "backend/src/threatfusion/evaluation/boundary_preflight.py",
        "backend/src/threatfusion/evaluation/repo_truth_audit.py",
        "backend/tests/unit/test_repo_truth_audit.py",
        "backend/tests/unit/test_boundary_and_high_leverage_features.py",
    }
)

B5_CODE_CONFIG_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".toml",
        ".cfg",
        ".ini",
        ".json",
        ".yaml",
        ".yml",
        ".sh",
        ".env",
        ".pth",
        ".py",
        ".service",
        ".conf",
    }
)

WALK_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "threatfusion-venv",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "data",
        "artifacts",
    }
)


@dataclass(frozen=True, slots=True)
class BoundaryPreflightReport:
    """Deterministic Boundary Preflight Audit Report."""

    active_path: str
    protected_path: str
    venv_path: str | None
    timestamp_utc: str
    passed: bool
    findings: tuple[str, ...]
    checks: dict[str, Any]
    decision_verdict: str = "NO-GO"

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_path": self.active_path,
            "protected_path": self.protected_path,
            "venv_path": self.venv_path,
            "timestamp_utc": self.timestamp_utc,
            "passed": self.passed,
            "findings": list(self.findings),
            "checks": self.checks,
            "decision_verdict": self.decision_verdict,
        }

    def render_banner(self) -> str:
        lines = [
            "=" * 80,
            "          THREATFUSION PROTOCOL 0 DETERMINISTIC BOUNDARY PREFLIGHT",
            "=" * 80,
            f"Active Workspace:     {self.active_path}",
            f"Protected Reference:  {self.protected_path}",
            f"Virtual Environment:  {self.venv_path or 'None (skipped)'}",
            f"Audit Timestamp UTC:  {self.timestamp_utc}",
            "",
            "-" * 80,
            "BOUNDARY CHECKS (B0 THROUGH B5):",
            "-" * 80,
        ]
        for check_id in ("B0", "B1", "B2", "B3", "B4", "B5"):
            chk = self.checks.get(check_id, {})
            tag = "[PASS]" if chk.get("passed", False) else "[FAIL]"
            name = chk.get("name", check_id)
            summary = chk.get("summary", "")
            lines.append(f" {tag} Check {check_id}: {name}")
            lines.append(f"        {summary}")

        lines.extend(
            [
                "",
                "-" * 80,
                f"TOTAL FINDINGS: {len(self.findings)}",
            ]
        )
        if self.findings:
            lines.append("VIOLATION DETAILS:")
            for finding in self.findings:
                lines.append(f" • [FAIL] {finding}")
        lines.extend(
            [
                "-" * 80,
                f"BOUNDARY DECISION VERDICT: {self.decision_verdict}",
                "=" * 80,
            ]
        )
        return "\n".join(lines)


def check_b0_non_overlap(active_rp: Path, protected_rp: Path) -> tuple[bool, list[str]]:
    """Check B0: Active and protected realpaths do not overlap."""
    passed = True
    issues: list[str] = []
    if active_rp == protected_rp:
        passed = False
        issues.append(
            f"B0: Active workspace '{active_rp}' equals protected workspace '{protected_rp}'"
        )
    elif active_rp.is_relative_to(protected_rp):
        passed = False
        issues.append(
            f"B0: Active workspace '{active_rp}' is contained within protected workspace '{protected_rp}'"
        )
    elif protected_rp.is_relative_to(active_rp):
        passed = False
        issues.append(
            f"B0: Protected workspace '{protected_rp}' is contained within active workspace '{active_rp}'"
        )
    return passed, issues


def check_b1_cwd_isolation(
    active_rp: Path, protected_rp: Path, cwd: Path | None = None
) -> tuple[bool, list[str]]:
    """Check B1: Current working directory resolves inside active and outside protected."""
    passed = True
    issues: list[str] = []
    cwd_rp = Path(os.path.realpath(cwd if cwd is not None else Path.cwd()))
    if not cwd_rp.is_relative_to(active_rp):
        passed = False
        issues.append(
            f"B1: Current working directory '{cwd_rp}' is outside active workspace '{active_rp}'"
        )
    if cwd_rp.is_relative_to(protected_rp):
        passed = False
        issues.append(
            f"B1: Current working directory '{cwd_rp}' resolves inside protected workspace '{protected_rp}'"
        )
    return passed, issues


def check_b2_symlinks(
    active_path: Path, active_rp: Path, protected_rp: Path
) -> tuple[bool, list[str]]:
    """Check B2: Workspace contains no symlinks pointing into protected or escaping active."""
    passed = True
    issues: list[str] = []
    if Path(active_path).is_symlink():
        target = Path(os.path.realpath(active_path))
        if target.is_relative_to(protected_rp):
            passed = False
            issues.append(
                f"B2: Active workspace root '{active_path}' is a symlink into protected workspace '{target}'"
            )

    if active_path.exists():
        for root_dir, dirs, files in os.walk(active_path, followlinks=False):
            dirs[:] = [d for d in dirs if d not in WALK_SKIP_DIRS]
            for entry in dirs + [f for f in files if f not in WALK_SKIP_DIRS]:
                p = Path(root_dir) / entry
                if p.is_symlink():
                    try:
                        target_rp = Path(os.path.realpath(p))
                        if target_rp.is_relative_to(protected_rp):
                            passed = False
                            rel = p.relative_to(active_path)
                            issues.append(
                                f"B2: Symlink '{rel}' resolves into protected workspace: '{target_rp}'"
                            )
                        elif not target_rp.is_relative_to(active_rp):
                            passed = False
                            rel = p.relative_to(active_path)
                            issues.append(
                                f"B2: Symlink '{rel}' escapes active workspace: '{target_rp}'"
                            )
                    except Exception as e:
                        passed = False
                        issues.append(f"B2: Failed to resolve symlink '{p}': {e}")
    return passed, issues


def check_b3_venv(
    venv_path: Path | None,
    active_rp: Path,
    protected_rp: Path,
    prot_re: re.Pattern | None = None,
) -> tuple[bool, list[str]]:
    """Check B3: Virtualenv contains no references (*.pth, direct_url.json, *.egg-link, etc.) or symlinks to protected."""
    passed = True
    issues: list[str] = []
    if prot_re is None:
        prot_re = re.compile(re.escape(str(protected_rp)) + r"(?![\w\-])")

    if venv_path is not None and venv_path.is_dir():
        for root_dir, dirs, files in os.walk(venv_path, followlinks=False):
            for entry in dirs + files:
                p = Path(root_dir) / entry
                if p.is_symlink():
                    try:
                        sym_target = Path(os.path.realpath(p))
                        if sym_target.is_relative_to(protected_rp) or prot_re.search(
                            str(sym_target)
                        ):
                            passed = False
                            rel = p.relative_to(venv_path)
                            issues.append(
                                f"B3: Virtualenv symlink '{rel}' points into protected workspace: '{sym_target}'"
                            )
                    except Exception as e:
                        passed = False
                        issues.append(f"B3: Failed to inspect venv symlink '{p}': {e}")

            for f in files:
                if (
                    f.endswith(".pth")
                    or f == "direct_url.json"
                    or f.endswith(".egg-link")
                    or f.startswith("__editable__")
                ):
                    p = Path(root_dir) / f
                    try:
                        content = p.read_text(encoding="utf-8", errors="ignore")
                        if prot_re.search(content):
                            passed = False
                            rel = p.relative_to(venv_path)
                            issues.append(
                                f"B3: Virtualenv file '{rel}' contains reference to protected workspace"
                            )
                    except Exception as e:
                        passed = False
                        issues.append(f"B3: Failed to read venv config '{p}': {e}")
    return passed, issues


def check_b4_git_metadata(
    active_path: Path,
    protected_rp: Path,
    prot_re: re.Pattern | None = None,
) -> tuple[bool, list[str]]:
    """Check B4: Git metadata (.git/objects/info/alternates, worktrees, config) contains no reference to protected."""
    passed = True
    issues: list[str] = []
    if prot_re is None:
        prot_re = re.compile(re.escape(str(protected_rp)) + r"(?![\w\-])")

    git_dir = active_path / ".git"
    if git_dir.is_dir():
        # 1. alternates
        alternates = git_dir / "objects" / "info" / "alternates"
        if alternates.is_file():
            try:
                alt_content = alternates.read_text(encoding="utf-8", errors="ignore")
                if prot_re.search(alt_content):
                    passed = False
                    issues.append(
                        f"B4: Git alternates '{alternates}' references protected workspace: {alt_content.strip()}"
                    )
            except Exception as e:
                passed = False
                issues.append(f"B4: Failed reading git alternates: {e}")

        # 2. worktrees gitdir
        worktrees_dir = git_dir / "worktrees"
        if worktrees_dir.is_dir():
            for root_dir, _dirs, files in os.walk(worktrees_dir):
                if "gitdir" in files:
                    gitdir_p = Path(root_dir) / "gitdir"
                    try:
                        gd_content = gitdir_p.read_text(encoding="utf-8", errors="ignore")
                        if prot_re.search(gd_content):
                            passed = False
                            issues.append(
                                f"B4: Worktree gitdir '{gitdir_p}' references protected workspace: {gd_content.strip()}"
                            )
                    except Exception as e:
                        passed = False
                        issues.append(f"B4: Failed reading worktree gitdir '{gitdir_p}': {e}")

        # 3. config
        config_p = git_dir / "config"
        if config_p.is_file():
            try:
                cfg_content = config_p.read_text(encoding="utf-8", errors="ignore")
                if prot_re.search(cfg_content):
                    passed = False
                    issues.append("B4: Git config (.git/config) references protected workspace")
            except Exception as e:
                passed = False
                issues.append(f"B4: Failed reading git config: {e}")

    return passed, issues


def check_b5_code_config(
    active_path: Path,
    prot_re: re.Pattern | None = None,
    protected_rp: Path | None = None,
) -> tuple[bool, list[str]]:
    """Check B5: Runtime code and config files (.py, .toml, .json, etc.) contain no literal references to protected."""
    passed = True
    issues: list[str] = []
    if prot_re is None:
        if protected_rp is None:
            protected_rp = CANONICAL_PROTECTED_WORKSPACE.resolve()
        prot_re = re.compile(re.escape(str(protected_rp)) + r"(?![\w\-])")

    if active_path.exists():
        for root_dir, dirs, files in os.walk(active_path, followlinks=False):
            dirs[:] = [d for d in dirs if d not in WALK_SKIP_DIRS]
            for f in files:
                p = Path(root_dir) / f
                try:
                    rel_p = str(p.relative_to(active_path))
                except ValueError:
                    rel_p = str(p)

                # Explicitly exempt governance documentation (*.md) and boundary enforcement modules/tests
                if p.suffix == ".md" or rel_p in EXEMPT_B5_FILES:
                    continue

                if p.suffix in B5_CODE_CONFIG_EXTENSIONS:
                    try:
                        content = p.read_text(encoding="utf-8", errors="ignore")
                        if prot_re.search(content):
                            passed = False
                            issues.append(
                                f"B5: Code/config file '{rel_p}' contains literal reference to protected workspace"
                            )
                    except Exception as e:
                        passed = False
                        issues.append(f"B5: Failed to scan file '{rel_p}': {e}")
    return passed, issues


def run_boundary_preflight(
    active: Path | str | None = None,
    protected: Path | str | None = None,
    venv: Path | str | None = None,
    cwd: Path | str | None = None,
) -> BoundaryPreflightReport:
    """Execute deterministic boundary preflight checks B0 through B5.

    Uses realpath containment and regex lookahead to prevent false triggers
    on substring prefixes like 'threatfusion-gemini'.
    """
    timestamp_utc = datetime.now(UTC).isoformat()
    findings: list[str] = []
    checks: dict[str, Any] = {}

    # Resolve paths
    active_path = Path(active).resolve() if active is not None else CANONICAL_ACTIVE_WORKSPACE
    protected_path = (
        Path(protected).resolve() if protected is not None else CANONICAL_PROTECTED_WORKSPACE
    )

    active_rp = Path(os.path.realpath(active_path))
    protected_rp = Path(os.path.realpath(protected_path))

    # Compile lookahead regex: matches protected path NOT followed by word-char or hyphen
    prot_re = re.compile(re.escape(str(protected_rp)) + r"(?![\w\-])")

    # Resolve venv path
    venv_path: Path | None = None
    if venv is not None:
        venv_path = Path(venv).resolve()
    else:
        candidate_venv = active_path / "threatfusion-venv"
        if candidate_venv.is_dir():
            venv_path = candidate_venv.resolve()

    # B0
    b0_passed, b0_issues = check_b0_non_overlap(active_rp, protected_rp)
    findings.extend(b0_issues)
    checks["B0"] = {
        "name": "Active / Protected Workspace Non-Overlap",
        "passed": b0_passed,
        "summary": (
            "Active and protected workspaces are strictly non-overlapping."
            if b0_passed
            else "; ".join(b0_issues)
        ),
    }

    # B1
    cwd_p = Path(cwd) if cwd is not None else Path.cwd()
    b1_passed, b1_issues = check_b1_cwd_isolation(active_rp, protected_rp, cwd=cwd_p)
    findings.extend(b1_issues)
    checks["B1"] = {
        "name": "Current Working Directory Isolation",
        "passed": b1_passed,
        "summary": (
            f"CWD '{os.path.realpath(cwd_p)}' is contained in active and isolated from protected."
            if b1_passed
            else "; ".join(b1_issues)
        ),
    }

    # B2
    b2_passed, b2_issues = check_b2_symlinks(active_path, active_rp, protected_rp)
    findings.extend(b2_issues)
    checks["B2"] = {
        "name": "Workspace Symlink Non-Escape Check",
        "passed": b2_passed,
        "summary": (
            "Zero escaping or protected-bound symlinks detected in active workspace."
            if b2_passed
            else "; ".join(b2_issues[:3])
        ),
    }

    # B3
    b3_passed, b3_issues = check_b3_venv(venv_path, active_rp, protected_rp, prot_re)
    findings.extend(b3_issues)
    checks["B3"] = {
        "name": "Virtualenv Configuration & Symlink Isolation",
        "passed": b3_passed,
        "summary": (
            f"Virtualenv '{venv_path.name}' verified clean with zero protected references."
            if (venv_path and b3_passed)
            else ("Virtualenv not found or skipped." if not venv_path else "; ".join(b3_issues[:3]))
        ),
    }

    # B4
    b4_passed, b4_issues = check_b4_git_metadata(active_path, protected_rp, prot_re)
    findings.extend(b4_issues)
    checks["B4"] = {
        "name": "Git Metadata (.git) Isolation Check",
        "passed": b4_passed,
        "summary": (
            "Git repository metadata (.git) verified isolated from protected workspace."
            if b4_passed
            else "; ".join(b4_issues[:3])
        ),
    }

    # B5
    b5_passed, b5_issues = check_b5_code_config(active_path, prot_re, protected_rp)
    findings.extend(b5_issues)
    checks["B5"] = {
        "name": "Runtime Code & Configuration Non-Leakage Check",
        "passed": b5_passed,
        "summary": (
            "Zero literal references to protected workspace in code or configuration files."
            if b5_passed
            else f"{len(b5_issues)} files contained forbidden references: {', '.join(b5_issues[:3])}"
        ),
    }

    all_passed = (
        b0_passed
        and b1_passed
        and b2_passed
        and b3_passed
        and b4_passed
        and b5_passed
        and len(findings) == 0
    )
    decision_verdict = "GO" if all_passed else "NO-GO"

    return BoundaryPreflightReport(
        active_path=str(active_path),
        protected_path=str(protected_path),
        venv_path=str(venv_path) if venv_path else None,
        timestamp_utc=timestamp_utc,
        passed=all_passed,
        findings=tuple(findings),
        checks=checks,
        decision_verdict=decision_verdict,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for boundary preflight."""
    parser = argparse.ArgumentParser(
        description="ThreatFusion Protocol 0 Zero-Trust Boundary Preflight Guard (B0-B5)"
    )
    parser.add_argument(
        "--active",
        type=Path,
        default=None,
        help="Path to active workspace (defaults to current canonical repo root)",
    )
    parser.add_argument(
        "--protected",
        type=Path,
        default=None,
        help="Path to protected reference workspace (defaults to canonical protected repo root)",
    )
    parser.add_argument(
        "--venv",
        type=Path,
        default=None,
        help="Path to virtual environment to scan for leaks (defaults to active / 'threatfusion-venv')",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON audit report instead of human-readable receipt banner",
    )
    args = parser.parse_args(argv)

    try:
        report = run_boundary_preflight(
            active=args.active,
            protected=args.protected,
            venv=args.venv,
        )
        if args.json:
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        else:
            print(report.render_banner())

        return 0 if (report.passed and report.decision_verdict == "GO") else 2
    except Exception as exc:
        print(f"[ERROR] Boundary preflight unexpected exception: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
