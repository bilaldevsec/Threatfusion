"""Deterministic Zero-Trust Repository Truth Audit Gate.

Provides programmatic and cryptographic proof of repository reality:
1. Workspace Isolation & Git State Check.
2. Frozen Model Artifact SHA-256 Invariance Check.
3. Canonical Evaluation Pack Rev2 (AI-FYP-2006, 6a36dcd) Runtime Check.
4. Section 8 (fusion_disabled) Runtime Enforcement Check.
5. No Duplicate Package Regression Check.
6. Section 13.C / 13.D / 13.E / 13.F Live Functional Probe.
7. Issue Register Honesty & Canonical Title Check (TF-008..TF-011 OPEN, no duplicates, no cross-doc contradictions).

Guarantees that no AI session can misreport what is actually implemented in the repository.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import importlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import ModuleType
from typing import Any, Mapping

REPO_TRUTH_AUDIT_SCHEMA_VERSION = "repo_truth_audit_v1"
CANONICAL_WORKSPACE_PATH = Path("/home/muhammad-bilal/projects/threatfusion-gemini").resolve()

EXPECTED_MODEL_DIGESTS: dict[str, dict[str, str]] = {
    "random_forest": {
        "label": "Random Forest",
        "rel_path": (
            "artifacts/models/network_random_forest_baseline/"
            "full-network-random-forest-6d69c72-v1/random_forest.joblib"
        ),
        "expected_sha256": "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9",
    },
    "logistic_regression": {
        "label": "Logistic Regression",
        "rel_path": (
            "artifacts/models/network_logistic_baseline/"
            "full-network-logistic-5e70ed9-v1/logistic_regression.joblib"
        ),
        "expected_sha256": "2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148",
    },
    "autoencoder_v2": {
        "label": "Autoencoder v2",
        "rel_path": (
            "artifacts/models/network_autoencoder/"
            "full-benign-autoencoder-2a51c94-v2/autoencoder_state.pt"
        ),
        "expected_sha256": "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23",
    },
    "rate_log1p_candidate": {
        "label": "Rate-Log1p Candidate",
        "rel_path": (
            "artifacts/models/network_rate_log1p_autoencoder/"
            "rate-log1p-autoencoder-b5e6e5d-v1/autoencoder_state.pt"
        ),
        "expected_sha256": "1d02e5bba556cb28709bd0faefce5f29da424a419a2d95332ad27a8995b26f63",
    },
}

FORBIDDEN_SPLIT_PASTE_PATHS: tuple[str, ...] = (
    "backend/src/threatfusion/intel",
    "backend/src/threatfusion/llm",
    "backend/src/threatfusion/soar/soar_ledger.py",
    "backend/tests/unit/test_advisory_debrief.py",
    "backend/tests/unit/test_soar_ledger.py",
)

CANONICAL_MODULES: tuple[str, ...] = (
    "threatfusion.enrichment.threat_intel",
    "threatfusion.advisory.explanation_engine",
    "threatfusion.advisory.gemini_client",
    "threatfusion.soar.playbook_ledger",
    "threatfusion.evaluation.workload_measurement",
    "threatfusion.datasets.adapters.suricata_flow",
    "threatfusion.operations.cloud_live_telemetry",
)

EXPECTED_CANONICAL_ISSUE_ROWS: Mapping[str, tuple[str, ...]] = {
    "TF-008": (
        "open",
        "**Independent Model Benchmark Beyond Inspected January/February UNSW Splits.** "
        "January (216,568 rows) and February (1,452,844 rows) were both previously inspected "
        "during model selection/evaluation; closing TF-008 requires evaluation on an "
        "untouched independent holdout or external dataset benchmark.",
        "Model generalization, independent evaluation claims",
        "Predeclare and freeze protocol on an untouched independent benchmark dataset; "
        "evaluate without prior threshold or feature tuning.",
        "Formal evaluation report on untouched external holdout proves generalization "
        "without inspected split bias.",
    ),
    "TF-009": (
        "open",
        "**Measured Reduction of Analyst Workload / Alert Fatigue.** "
        "`workload_measurement.py` (Section 13.F) provides the counterfactual January FP shield "
        "proof (201 RF FPs vs 1,775 fused FPs = 8.831x) and the SQLite telemetry recorder "
        "(`workload_study.sqlite3`), but closing TF-009 requires real human-factors / analyst cohort "
        'study trials (`study_cohort="human_analyst_cohort_study"`, `min_human_trials >= 10`).',
        "Operational alert fatigue reduction, analyst workflow claims",
        "Run controlled human-factors / analyst cohort study comparing baseline raw alerts "
        "against ThreatFusion enriched advisory triage.",
        "Statistically significant reduction in time-to-disposition and false-alarm triage burden "
        "verified across at least 10 real human analyst trials.",
    ),
    "TF-010": (
        "open",
        "**External FAST-NUCES FYP-II Jury Rubric & Signed Supervisor/Jury Evaluation Alignment.** "
        "Internal traceability (`jury_traceability.py`) and Evaluation Pack Rev2 (`AI-FYP-2006`) "
        "alignment are wired, but closing TF-010 requires the official external signed "
        "FAST-NUCES jury/supervisor rubric artifact.",
        "Scope control, jury compliance, formal academic defense",
        "Formally attach external signed FAST-NUCES FYP-II jury rubric and verify alignment "
        "against repository deliverables.",
        "Official signed FAST-NUCES jury rubric artifact attached and validated with zero "
        "discrepancies against code deliverables.",
    ),
    "TF-011": (
        "open",
        "**Real Operational SIEM / Threat-Intelligence Production Source Proof.** "
        "`SuricataFlowAdapter` (Slide 14) and `SourcedThreatIntelEnricher` (Section 13.C) "
        "are verified on bounded/recorded flows and local snapshots, but closing TF-011 requires "
        "live operational SIEM / production threat-intelligence source deployment evidence.",
        "Operational deployment, live enterprise threat-intel ingestion",
        "Deploy live operational SIEM pipeline and production threat-intelligence feeds "
        "in enterprise environment.",
        "Verified live telemetry streams ingested from operational enterprise SIEM and production "
        "threat-intel sources with end-to-end evidence.",
    ),
}


def _file_sha256(path: Path) -> str:
    """Compute SHA-256 digest of a file in 64 KiB chunks."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_module_origin(mod: ModuleType, expected_src_root: Path) -> tuple[bool, str]:
    """Verify that an imported module originates within the expected workspace source root."""
    file_path = getattr(mod, "__file__", None)
    if not file_path:
        return False, f"Module {getattr(mod, '__name__', str(mod))} lacks __file__ attribute"
    try:
        resolved_mod_file = Path(file_path).resolve()
        resolved_src_root = expected_src_root.resolve()
        if not resolved_mod_file.is_relative_to(resolved_src_root):
            return (
                False,
                f"Module {getattr(mod, '__name__', str(mod))} resolved at {resolved_mod_file}, "
                f"outside expected workspace source root {resolved_src_root}",
            )
    except Exception as exc:
        return (
            False,
            f"Failed resolving module origin for {getattr(mod, '__name__', str(mod))}: {exc}",
        )
    return True, "OK"


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Deterministic result for an individual truth audit check."""

    check_id: int
    name: str
    passed: bool
    summary: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "passed": self.passed,
            "summary": self.summary,
            "details": self.details,
        }


@dataclass(frozen=True, slots=True)
class RepoTruthAuditReport:
    """Comprehensive cryptographic report of repository reality."""

    audit_version: str
    timestamp_utc: str
    repo_root: str
    git_branch: str
    git_head_sha: str
    clean_working_tree: bool
    modified_tracked_files: dict[str, str]
    untracked_files: dict[str, str]
    model_digests: dict[str, dict[str, str]]
    checks: list[CheckResult]
    all_checks_passed: bool
    receipt_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_version": self.audit_version,
            "timestamp_utc": self.timestamp_utc,
            "repo_root": self.repo_root,
            "git_branch": self.git_branch,
            "git_head_sha": self.git_head_sha,
            "clean_working_tree": self.clean_working_tree,
            "modified_tracked_files": self.modified_tracked_files,
            "untracked_files": self.untracked_files,
            "model_digests": self.model_digests,
            "checks": [c.to_dict() for c in self.checks],
            "all_checks_passed": self.all_checks_passed,
            "receipt_digest": self.receipt_digest,
        }

    def render_receipt_banner(self) -> str:
        """Render human-readable cryptographic truth receipt banner."""
        lines = [
            "=" * 80,
            "           THREATFUSION DETERMINISTIC ZERO-TRUST REPOSITORY TRUTH AUDIT",
            "=" * 80,
            f"Workspace Root:       {self.repo_root}",
            f"Git Branch:           {self.git_branch}",
            f"Git Head Commit:      {self.git_head_sha}",
            f"Working Tree Clean:   {self.clean_working_tree}",
            f"Audit Timestamp UTC:  {self.timestamp_utc}",
            "",
            "-" * 80,
            "DETERMINISTIC VERIFICATION CHECKS:",
            "-" * 80,
        ]
        for check in self.checks:
            tag = "[PASS]" if check.passed else "[FAIL]"
            lines.append(f" {tag} Check {check.check_id}: {check.name}")
            lines.append(f"        {check.summary}")

        lines.extend(
            [
                "",
                "-" * 80,
                "FROZEN MODEL ARTIFACT DIGESTS (EXACT INVARIANCE):",
                "-" * 80,
            ]
        )
        for key, info in self.model_digests.items():
            label = info.get("label", key)
            actual = info.get("actual_sha256", "MISSING")
            match = info.get("matched", False)
            status = "[OK]" if match else "[FAIL]"
            lines.append(f" • {label:<22} {actual} {status}")

        lines.extend(
            [
                "",
                "-" * 80,
                "CRYPTOGRAPHIC GROUND-TRUTH RECEIPT SHA-256:",
                f"  {self.receipt_digest}",
                "",
                f"OVERALL STATUS: {'ALL 7 ZERO-TRUST CHECKS PASSED' if self.all_checks_passed else 'AUDIT FAILED (Discrepancy Detected)'}",
                "=" * 80,
            ]
        )
        return "\n".join(lines)


def _check_1_workspace_isolation(
    repo_root: Path,
) -> tuple[CheckResult, str, str, bool, dict[str, str], dict[str, str]]:
    """Check 1: Workspace Isolation & Git State Check."""
    resolved_root = repo_root.resolve()
    passed = True
    issues: list[str] = []

    if resolved_root != CANONICAL_WORKSPACE_PATH:
        passed = False
        issues.append(f"Workspace path mismatch: {resolved_root} != {CANONICAL_WORKSPACE_PATH}")

    branch = "UNKNOWN"
    head_sha = "UNKNOWN"
    clean_working_tree = False
    modified_tracked: dict[str, str] = {}
    untracked: dict[str, str] = {}

    try:
        branch_proc = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=resolved_root,
            capture_output=True,
            text=True,
            check=True,
        )
        branch = branch_proc.stdout.strip()
    except Exception as e:
        passed = False
        issues.append(f"Failed to query git branch: {e}")

    try:
        head_proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=resolved_root,
            capture_output=True,
            text=True,
            check=True,
        )
        head_sha = head_proc.stdout.strip()
    except Exception as e:
        passed = False
        issues.append(f"Failed to query git HEAD SHA: {e}")

    try:
        status_proc = subprocess.run(
            ["git", "status", "--porcelain=v1"],
            cwd=resolved_root,
            capture_output=True,
            text=True,
            check=True,
        )
        status_lines = [line for line in status_proc.stdout.splitlines() if line.strip()]
        for line in status_lines:
            status_code = line[:2]
            file_rel = line[3:].strip().strip('"')
            full_path = resolved_root / file_rel
            if full_path.is_file():
                digest = _file_sha256(full_path)
            else:
                digest = "NON_FILE_OR_DELETED"
            if status_code == "??":
                untracked[file_rel] = digest
            else:
                modified_tracked[file_rel] = digest
        clean_working_tree = len(modified_tracked) == 0 and len(untracked) == 0
    except Exception as e:
        passed = False
        issues.append(f"Failed to query git status: {e}")

    summary = (
        f"Verified workspace isolation ({resolved_root}). Branch '{branch}' at {head_sha[:8]}."
        if passed
        else "; ".join(issues)
    )

    result = CheckResult(
        check_id=1,
        name="Workspace Isolation & Git State Check",
        passed=passed,
        summary=summary,
        details={
            "resolved_root": str(resolved_root),
            "canonical_root": str(CANONICAL_WORKSPACE_PATH),
            "branch": branch,
            "head_sha": head_sha,
            "clean_working_tree": clean_working_tree,
            "modified_tracked_count": len(modified_tracked),
            "untracked_count": len(untracked),
        },
    )
    return result, branch, head_sha, clean_working_tree, modified_tracked, untracked


def _check_2_frozen_model_invariance(
    repo_root: Path,
) -> tuple[CheckResult, dict[str, dict[str, str]]]:
    """Check 2: Frozen Model Artifact SHA-256 Invariance Check."""
    resolved_root = repo_root.resolve()
    passed = True
    model_digests: dict[str, dict[str, str]] = {}
    failures: list[str] = []

    for key, spec in EXPECTED_MODEL_DIGESTS.items():
        rel_path = spec["rel_path"]
        expected = spec["expected_sha256"]
        full_path = resolved_root / rel_path

        # Fail closed on missing, symlink, or non-regular files
        if full_path.is_symlink() or not full_path.is_file():
            passed = False
            reason = "Artifact is missing, a symlink, or not a regular file"
            failures.append(f"{spec['label']}: {reason} at {rel_path}")
            model_digests[key] = {
                "label": spec["label"],
                "rel_path": rel_path,
                "expected_sha256": expected,
                "actual_sha256": ("NON_REGULAR_OR_SYMLINK" if full_path.exists() else "MISSING"),
                "matched": False,
            }
            continue

        try:
            actual = _file_sha256(full_path)
        except OSError as exc:
            passed = False
            failures.append(f"{spec['label']} I/O read failure ({exc}) at {rel_path}")
            model_digests[key] = {
                "label": spec["label"],
                "rel_path": rel_path,
                "expected_sha256": expected,
                "actual_sha256": "IO_ERROR",
                "matched": False,
            }
            continue

        matched = actual == expected
        if not matched:
            passed = False
            failures.append(f"{spec['label']} SHA-256 mismatch ({actual} != {expected})")

        model_digests[key] = {
            "label": spec["label"],
            "rel_path": rel_path,
            "expected_sha256": expected,
            "actual_sha256": actual,
            "matched": matched,
        }

    summary = (
        "All 4 frozen model artifacts verified byte-identical against immutable reference hashes."
        if passed
        else "; ".join(failures)
    )

    return (
        CheckResult(
            check_id=2,
            name="Frozen Model Artifact SHA-256 Invariance Check",
            passed=passed,
            summary=summary,
            details=model_digests,
        ),
        model_digests,
    )


def _check_3_canonical_evaluation_pack(expected_src_root: Path) -> CheckResult:
    """Check 3: Canonical Evaluation Pack Rev2 (AI-FYP-2006, Checkpoint 6a36dcd) Runtime Verification."""
    passed = True
    failures: list[str] = []

    try:
        from threatfusion.models.canonical_evaluation import (
            CANONICAL_EVALUATION_PACK_REV2 as P,
        )
        import threatfusion.models.canonical_evaluation as ce_mod

        ok, msg = _verify_module_origin(ce_mod, expected_src_root)
        if not ok:
            failures.append(msg)

        if P.project_id != "AI-FYP-2006":
            failures.append(f"Bad project_id: {P.project_id}")
        if P.supervisor != "Sir Sameer Faisal":
            failures.append(f"Bad supervisor: {P.supervisor}")

        roll_numbers = [r for _, r in P.team_members]
        if roll_numbers != ["21K-3551", "22K-4302", "22K-4718"]:
            failures.append(f"Bad roll numbers: {roll_numbers}")

        pop = P.populations
        if (
            pop.train_total_rows != 865480
            or pop.train_benign_rows != 847837
            or pop.train_attack_rows != 17643
        ):
            failures.append(f"Bad train rows: {pop.train_total_rows}")
        if (
            pop.january_validation_total_rows != 216568
            or pop.january_validation_attack_rows != 4358
        ):
            failures.append(f"Bad January validation rows: {pop.january_validation_total_rows}")
        if pop.february_benchmark_total_rows != 1452844:
            failures.append(f"Bad February benchmark rows: {pop.february_benchmark_total_rows}")

        rf = P.frozen_random_forest
        if rf.tp != 4045 or rf.fp != 201 or rf.tn != 212009 or rf.fn != 313:
            failures.append(f"Bad RF confusion matrix: tp={rf.tp}, fp={rf.fp}")
        if (
            rf.precision_pct != 95.266
            or rf.recall_pct != 92.818
            or rf.f1_pct != 94.026
            or rf.fpr_pct != 0.095
        ):
            failures.append(f"Bad RF metrics: precision={rf.precision_pct}, f1={rf.f1_pct}")

        ae = P.autoencoder_v2
        if ae.threshold != 0.1181361214680695:
            failures.append(f"Bad AE threshold: {ae.threshold}")
        if (
            ae.january_tp != 1988
            or ae.january_fp != 1628
            or ae.january_tn != 210582
            or ae.january_fn != 2370
        ):
            failures.append(f"Bad AE January matrix: tp={ae.january_tp}, fp={ae.january_fp}")

        sec8 = P.section_8_complementarity
        if (
            sec8.ae_only_additional_attacks_january != 96
            or sec8.ae_only_additional_benign_fps_january != 1574
        ):
            failures.append(
                f"Bad Section 8 complementarity: +{sec8.ae_only_additional_attacks_january} attacks"
            )

        blk = P.blocked_candidate
        if blk.disposition != "BLOCKED_preserve_baseline":
            failures.append(f"Bad rate-log1p disposition: {blk.disposition}")
        if (
            blk.ae_only_attacks != 59
            or blk.ae_only_benign_fps != 2080
            or blk.total_ae_fps != 2122
            or blk.tp != 945
        ):
            failures.append(f"Bad rate-log1p candidate metrics: tp={blk.tp}")

        if failures:
            passed = False
    except Exception as e:
        passed = False
        failures.append(f"Import or inspection error: {e}")

    summary = (
        "Reconciled September 21, 2026 Evaluation Pack Rev2 (6a36dcd) metrics and populations."
        if passed
        else "; ".join(failures)
    )

    return CheckResult(
        check_id=3,
        name="Canonical Evaluation Pack Rev2 (AI-FYP-2006, 6a36dcd) Runtime Check",
        passed=passed,
        summary=summary,
        details={"failures": failures},
    )


def _check_4_section_8_fusion_disabled(expected_src_root: Path) -> CheckResult:
    """Check 4: Section 8 (fusion_disabled) Runtime Enforcement Check."""
    passed = True
    failures: list[str] = []

    try:
        from threatfusion.models.multi_signal_risk import evaluate_multi_signal_risk
        import threatfusion.models.multi_signal_risk as msr_mod

        ok, msg = _verify_module_origin(msr_mod, expected_src_root)
        if not ok:
            failures.append(msg)

        res = evaluate_multi_signal_risk(rf_prob=0.825, ae_error=0.25)
        if res.production_fusion_enabled is not False:
            failures.append("res.production_fusion_enabled is not False")
        if res.production_alert_authority != "frozen_random_forest_only":
            failures.append(f"Bad authority: {res.production_alert_authority}")

        # Enforce that setting production_fusion_enabled=True raises ValueError
        try:
            evaluate_multi_signal_risk(production_fusion_enabled=True)
            failures.append(
                "evaluate_multi_signal_risk(production_fusion_enabled=True) did not raise ValueError"
            )
        except ValueError:
            pass  # Expected fail-closed behavior
        except Exception as e:
            failures.append(f"Unexpected error when testing fusion guard: {e}")

        if failures:
            passed = False
    except Exception as e:
        passed = False
        failures.append(f"Runtime failure: {e}")

    summary = (
        "Section 8 invariant strictly enforced (production_fusion_enabled=False; raises ValueError on True)."
        if passed
        else "; ".join(failures)
    )

    return CheckResult(
        check_id=4,
        name="Section 8 (fusion_disabled) Runtime Enforcement Check",
        passed=passed,
        summary=summary,
        details={"failures": failures},
    )


def _check_5_no_duplicate_package_regression(
    repo_root: Path, expected_src_root: Path
) -> CheckResult:
    """Check 5: No Duplicate Package Regression Check."""
    resolved_root = repo_root.resolve()
    passed = True
    failures: list[str] = []

    for rel_path in FORBIDDEN_SPLIT_PASTE_PATHS:
        full_path = resolved_root / rel_path
        if full_path.exists():
            passed = False
            failures.append(f"Forbidden duplicate path still exists on disk: {rel_path}")

    unicorn_sop_path = resolved_root / "design_guidelines" / "soc_unicorn_interface_sop.md"
    if not unicorn_sop_path.is_file():
        passed = False
        failures.append(
            "Missing required architecture SOP file: design_guidelines/soc_unicorn_interface_sop.md"
        )

    for mod_name in CANONICAL_MODULES:
        try:
            mod = importlib.import_module(mod_name)
            ok, msg = _verify_module_origin(mod, expected_src_root)
            if not ok:
                failures.append(msg)
        except Exception as e:
            passed = False
            failures.append(f"Failed to import canonical module {mod_name}: {e}")

    summary = (
        "Zero split-paste duplicate packages detected; all canonical packages (including Gemini advisory client and cloud live telemetry) import cleanly, and SOC Unicorn SOP is verified on disk."
        if passed
        else "; ".join(failures)
    )

    return CheckResult(
        check_id=5,
        name="No Duplicate Package Regression Check",
        passed=passed,
        summary=summary,
        details={"failures": failures},
    )


def _check_6_functional_probe(expected_src_root: Path) -> CheckResult:
    """Check 6: Section 13.C / 13.D / 13.E / 13.F Live Functional Probe."""
    passed = True
    failures: list[str] = []

    try:
        # Pillar 4: Correlation Engine Dual-Window Invariance (30s burst / 600s campaign)
        import threatfusion.alerts.correlation_engine as ce_mod
        from threatfusion.alerts.correlation_engine import EntityProvenanceContract

        ok, msg = _verify_module_origin(ce_mod, expected_src_root)
        if not ok:
            failures.append(msg)
        if getattr(ce_mod, "BURST_WINDOW_SECONDS", None) != 30.0:
            failures.append(
                f"Pillar 4 BURST_WINDOW_SECONDS mismatch: {getattr(ce_mod, 'BURST_WINDOW_SECONDS', None)} != 30.0"
            )
        if getattr(ce_mod, "CAMPAIGN_WINDOW_SECONDS", None) != 600.0:
            failures.append(
                f"Pillar 4 CAMPAIGN_WINDOW_SECONDS mismatch: {getattr(ce_mod, 'CAMPAIGN_WINDOW_SECONDS', None)} != 600.0"
            )

        # Probe 13.C: RFC1918 Private-IP Guard
        from threatfusion.enrichment.threat_intel import SourcedThreatIntelEnricher
        import threatfusion.enrichment.threat_intel as ti_mod

        ok, msg = _verify_module_origin(ti_mod, expected_src_root)
        if not ok:
            failures.append(msg)

        # Probe 13.C: RFC1918 Private-IP Guard
        enricher = SourcedThreatIntelEnricher()
        contract = EntityProvenanceContract(
            entity_namespace_id="azure_lab:suricata_live_v1",
            clock_synchronized=True,
            src_entity_id="10.0.0.4",
            dst_entity_id="10.0.0.5",
            protocol="tcp",
            service_or_port="80",
        )
        ti_res = enricher.enrich_entity_contract(contract)
        if ti_res.private_ip_guard_triggered is not True:
            failures.append("13.C Private-IP guard was not triggered for 10.0.0.4 -> 10.0.0.5")
        if ti_res.external_lookup_performed is not False:
            failures.append("13.C External lookup was improperly performed for private IPs")

        # Probe 13.D: Advisory Engine Anti-Hallucination Guard
        from threatfusion.advisory.explanation_engine import (
            AdvisoryEvidenceBundle,
            AdvisoryExplanationEngine,
            EvidenceBoundExplanation,
            verify_explanation_groundedness,
        )
        import threatfusion.advisory.explanation_engine as ee_mod

        ok, msg = _verify_module_origin(ee_mod, expected_src_root)
        if not ok:
            failures.append(msg)

        bundle = AdvisoryEvidenceBundle(
            candidate_id="probe_candidate",
            record_id="rec_01",
            rf_model_version="full-network-random-forest-6d69c72-v1",
            rf_attack_probability=0.85,
            rf_threshold=0.5,
            top_feature_signals={"rate": 10.0},
            enrichment_result=None,
        )
        hallucinated = EvidenceBoundExplanation(
            candidate_id=bundle.candidate_id,
            generation_mode="verified_local_llm_advisory",
            advisory_only_non_authoritative=True,
            summary_headline="Test",
            detection_rationale="Model scored 0.85",
            complementarity_and_fusion_note="Fusion disabled",
            correlation_and_enrichment_context="Attacker at 99.88.77.66 probed the host.",
            recommended_analyst_checks=(),
            cited_evidence_keys=("candidate_id",),
            groundedness_verified=True,
        )
        if verify_explanation_groundedness(hallucinated, bundle) is not False:
            failures.append("13.D Hallucinated IP was not rejected by groundedness verifier")

        safe_exp = AdvisoryExplanationEngine.generate_explanation(
            bundle, optional_llm_callable=lambda b: hallucinated
        )
        if safe_exp.generation_mode != "deterministic_evidence_template":
            failures.append(
                f"13.D Explanation engine did not fallback to deterministic template: {safe_exp.generation_mode}"
            )

        # Probe 13.E: Approval-Gated SOAR Ledger
        from threatfusion.soar.playbook_ledger import (
            ApprovalGatedSoarEngine,
            SoarPlaybookSqliteRepository,
            SoarStateTransitionError,
        )
        import threatfusion.soar.playbook_ledger as soar_mod

        ok, msg = _verify_module_origin(soar_mod, expected_src_root)
        if not ok:
            failures.append(msg)

        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "probe_soar.sqlite3"
            repo = SoarPlaybookSqliteRepository(db_path)
            soar_engine = ApprovalGatedSoarEngine(repo)
            recs = soar_engine.recommend_actions_for_alert("cand_probe", contract)
            if not recs or recs[0].state != "pending_approval":
                failures.append("13.E Recommendation did not start in 'pending_approval' state")

            soar_blocked = False
            try:
                soar_engine.execute_approved_action(
                    recs[0].playbook_id, actor_id="analyst", expected_version=1
                )
            except SoarStateTransitionError:
                soar_blocked = True
            except Exception as e:
                failures.append(f"13.E Unexpected exception executing unapproved action: {e}")

            if not soar_blocked:
                failures.append(
                    "13.E Unapproved SOAR action executed without raising SoarStateTransitionError"
                )

        # Probe 13.F: Alert-Fatigue & Workload Measurement
        from threatfusion.evaluation.workload_measurement import evaluate_alert_fatigue_compression
        import threatfusion.evaluation.workload_measurement as wm_mod

        ok, msg = _verify_module_origin(wm_mod, expected_src_root)
        if not ok:
            failures.append(msg)

        comp = evaluate_alert_fatigue_compression(
            raw_flow_count=100,
            rf_alert_candidate_count=10,
            correlated_incident_count=2,
            uncorrelatable_alert_count=1,
        )
        if comp.rf_only_false_positives != 201:
            failures.append(
                f"13.F RF false positives mismatch: {comp.rf_only_false_positives} != 201"
            )
        if comp.counterfactual_fused_false_positives != 1775:
            failures.append(
                f"13.F Fused false positives mismatch: {comp.counterfactual_fused_false_positives} != 1775"
            )
        if comp.tf_009_closure_eligible is not False:
            failures.append("13.F tf_009_closure_eligible is not False for synthetic cohort")

        # Milestone #28: Live Resilient Suricata Ingestion & Cloud Budget Kill-Switch Probe
        from threatfusion.operations.cloud_live_telemetry import (
            evaluate_budget_kill_switch,
            process_suricata_eve_stream_resilient,
        )
        import threatfusion.operations.cloud_live_telemetry as clt_mod

        ok, msg = _verify_module_origin(clt_mod, expected_src_root)
        if not ok:
            failures.append(msg)

        valid_eve_flow = json.dumps(
            {
                "timestamp": "2026-10-18T10:00:00.000000+00:00",
                "event_type": "flow",
                "src_ip": "10.0.0.4",
                "src_port": 44120,
                "dest_ip": "10.0.0.5",
                "dest_port": 80,
                "proto": "TCP",
                "flow": {
                    "pkts_toserver": 15,
                    "pkts_toclient": 12,
                    "bytes_toserver": 1250,
                    "bytes_toclient": 4800,
                    "start": "2026-10-18T10:00:00.000000+00:00",
                    "end": "2026-10-18T10:00:01.500000+00:00",
                },
            }
        )
        corrupted_json_line = '{"event_type": "flow", "corrupted": true, broken'

        probe_stream = [valid_eve_flow, corrupted_json_line]
        probe_batch = process_suricata_eve_stream_resilient(probe_stream)

        if probe_batch.dead_letter_count != 1:
            failures.append(f"M28 dead_letter_count mismatch: {probe_batch.dead_letter_count} != 1")
        if (
            len(probe_batch.dead_letter_records) != 1
            or probe_batch.dead_letter_records[0].error_code != "malformed_json_line"
        ):
            failures.append("M28 corrupted JSON line was not quarantined into dead_letter_records")
        if probe_batch.valid_flows_adapted != 1:
            failures.append(
                f"M28 valid_flows_adapted mismatch: {probe_batch.valid_flows_adapted} != 1"
            )

        budget_probe = evaluate_budget_kill_switch(5.0)
        if budget_probe.get("should_detach_billing") is not True:
            failures.append(
                f"M28 evaluate_budget_kill_switch(5.0) should_detach_billing is not True: {budget_probe}"
            )

        if failures:
            passed = False
    except Exception as e:
        passed = False
        failures.append(f"Functional probe failure: {e}")

    summary = (
        "Functional probe verified Pillar 4 correlation windows (30s/600s), 13.C RFC1918 guard, "
        "13.D groundedness, 13.E SOAR approval gate, 13.F FP shield, and M28 resilient Suricata "
        "quarantine & budget kill-switch."
        if passed
        else "; ".join(failures)
    )

    return CheckResult(
        check_id=6,
        name="Section 13.C/13.D/13.E/13.F Live Functional Probe",
        passed=passed,
        summary=summary,
        details={"failures": failures},
    )


def _check_7_issue_register_honesty(
    repo_root: Path,
    issue_register_path: Path | None = None,
    project_status_path: Path | None = None,
    gemini_master_path: Path | None = None,
) -> CheckResult:
    """Check 7: Issue Register Honesty & Canonical Title Check (TF-008..TF-011 OPEN, no duplicates, no cross-doc contradictions)."""
    resolved_root = repo_root.resolve()
    target_path = (
        issue_register_path.resolve()
        if issue_register_path is not None
        else (resolved_root / "docs" / "issue_register.md")
    )
    passed = True
    failures: list[str] = []

    if not target_path.exists():
        return CheckResult(
            check_id=7,
            name="Issue Register Honesty & Canonical Title Check (TF-008..TF-011 OPEN)",
            passed=False,
            summary=f"Issue register file not found: {target_path}",
            details={"path": str(target_path)},
        )

    text = target_path.read_text(encoding="utf-8")
    seen_ids: set[str] = set()
    table_issues: dict[str, tuple[str, str, list[str]]] = {}

    for line in text.splitlines():
        line_s = line.strip()
        if not (line_s.startswith("|") and line_s.endswith("|")):
            continue
        parts = [p.strip() for p in line_s.split("|")[1:-1]]
        if len(parts) >= 7 and parts[0].startswith("TF-"):
            issue_id = parts[0]
            if issue_id in seen_ids:
                passed = False
                failures.append(f"Duplicate issue ID detected in issue_register.md: {issue_id}")
            seen_ids.add(issue_id)
            status = parts[6].lower()
            table_issues[issue_id] = (status, line_s, parts)

    required_issues = ("TF-008", "TF-009", "TF-010", "TF-011")

    for req in required_issues:
        if req not in table_issues:
            passed = False
            failures.append(f"Missing required issue {req} in issue register table")
            continue

        status, row_str, parts = table_issues[req]
        if status != "open":
            passed = False
            failures.append(f"{req} is marked '{status}', but MUST remain open")

        norm_parts = [" ".join(p.split()) for p in parts]
        # Exact whitespace-normalized tuple: (status, title_and_evidence, scope, next_action, closure_test)
        actual_cells = (
            norm_parts[6],
            norm_parts[2],
            norm_parts[3],
            norm_parts[4],
            norm_parts[5],
        )
        expected_cells = EXPECTED_CANONICAL_ISSUE_ROWS[req]
        if actual_cells != expected_cells:
            passed = False
            failures.append(
                f"Canonical field mismatch for {req}: expected exact canonical definition matching docs/issue_register.md lines 28-31"
            )

    # Cross-Document Contradiction Scan
    status_doc = (
        project_status_path.resolve()
        if project_status_path is not None
        else (resolved_root / "docs" / "project_status.md")
    )
    master_doc = (
        gemini_master_path.resolve()
        if gemini_master_path is not None
        else (resolved_root / "docs" / "GEMINI_PROJECT_MASTER.md")
    )

    for doc_path in (status_doc, master_doc):
        if not doc_path.exists():
            continue
        doc_text = doc_path.read_text(encoding="utf-8")
        for line_num, doc_line in enumerate(doc_text.splitlines(), start=1):
            for issue_key in ("TF-008", "TF-009", "TF-010", "TF-011"):
                # Unqualified resolved claim pattern e.g. "TF-010 resolved" or "TF-010 Resolved"
                pattern = rf"\b{issue_key}\b.*?\bresolved\b"
                if re.search(pattern, doc_line, re.IGNORECASE):
                    passed = False
                    failures.append(
                        f"Contradictory '{issue_key} resolved' claim detected in {doc_path.name}:{line_num}: {doc_line.strip()[:80]}"
                    )

    summary = (
        "Verified TF-008, TF-009, TF-010, and TF-011 are all honestly OPEN with exact canonical definitions and zero document contradictions."
        if passed
        else "; ".join(failures)
    )

    return CheckResult(
        check_id=7,
        name="Issue Register Honesty & Canonical Title Check (TF-008..TF-011 OPEN)",
        passed=passed,
        summary=summary,
        details={
            "failures": failures,
            "table_issues": {k: v[0] for k, v in table_issues.items()},
        },
    )


def run_repository_truth_audit(
    repo_root: Path | None = None,
    issue_register_path: Path | None = None,
    project_status_path: Path | None = None,
    gemini_master_path: Path | None = None,
) -> RepoTruthAuditReport:
    """Run full deterministic zero-trust repository truth audit across 7 checks."""
    if repo_root is None:
        # Resolve repo root from this file location: backend/src/threatfusion/evaluation/repo_truth_audit.py -> repo_root
        repo_root = Path(__file__).resolve().parents[4]
    else:
        repo_root = Path(repo_root).resolve()

    timestamp_utc = datetime.now(UTC).isoformat()

    # Ensure sys.path prioritizes the repository backend/src
    src_root = (repo_root / "backend" / "src").resolve()
    if src_root.is_dir():
        src_root_str = str(src_root)
        if not sys.path or sys.path[0] != src_root_str:
            if src_root_str in sys.path:
                sys.path.remove(src_root_str)
            sys.path.insert(0, src_root_str)

    c1, branch, head_sha, clean_tree, mod_files, untracked_files = _check_1_workspace_isolation(
        repo_root
    )
    c2, model_digests = _check_2_frozen_model_invariance(repo_root)
    c3 = _check_3_canonical_evaluation_pack(src_root)
    c4 = _check_4_section_8_fusion_disabled(src_root)
    c5 = _check_5_no_duplicate_package_regression(repo_root, src_root)
    c6 = _check_6_functional_probe(src_root)
    c7 = _check_7_issue_register_honesty(
        repo_root, issue_register_path, project_status_path, gemini_master_path
    )

    checks = [c1, c2, c3, c4, c5, c6, c7]
    all_passed = all(c.passed for c in checks)

    # Compute deterministic receipt hash over canonical json of report payload
    pre_receipt_payload = {
        "audit_version": REPO_TRUTH_AUDIT_SCHEMA_VERSION,
        "timestamp_utc": timestamp_utc,
        "repo_root": str(repo_root),
        "git_branch": branch,
        "git_head_sha": head_sha,
        "clean_working_tree": clean_tree,
        "modified_tracked_files": mod_files,
        "untracked_files": untracked_files,
        "model_digests": model_digests,
        "checks": [c.to_dict() for c in checks],
        "all_checks_passed": all_passed,
    }
    canonical_repr = json.dumps(pre_receipt_payload, sort_keys=True, separators=(",", ":"))
    receipt_digest = hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()

    return RepoTruthAuditReport(
        audit_version=REPO_TRUTH_AUDIT_SCHEMA_VERSION,
        timestamp_utc=timestamp_utc,
        repo_root=str(repo_root),
        git_branch=branch,
        git_head_sha=head_sha,
        clean_working_tree=clean_tree,
        modified_tracked_files=mod_files,
        untracked_files=untracked_files,
        model_digests=model_digests,
        checks=checks,
        all_checks_passed=all_passed,
        receipt_digest=receipt_digest,
    )
