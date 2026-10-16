#!/usr/bin/env python3
"""CLI executable for Deterministic Zero-Trust Repository Truth Audit Gate.

Runs 7 deterministic, non-mocked checks against live repository and runtime objects:
1. Workspace Isolation & Git State Check.
2. Frozen Model Artifact SHA-256 Invariance Check.
3. Canonical Evaluation Pack Rev2 (AI-FYP-2006, Checkpoint 6a36dcd) Runtime Check.
4. Section 8 (fusion_disabled) Runtime Enforcement Check.
5. No Duplicate Package Regression Check.
6. Section 13.C / 13.D / 13.E / 13.F Live Functional Probe.
7. Issue Register Honesty & Canonical Title Check (TF-008..TF-011 OPEN).

Prints a cryptographic ground-truth receipt banner and exits with code 0 if and only if
all 7 checks pass.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from threatfusion.evaluation.repo_truth_audit import run_repository_truth_audit


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ThreatFusion Deterministic Zero-Trust Repository Truth Audit Gate"
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Path to repository root (defaults to auto-detected root)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON audit report instead of receipt banner",
    )
    args = parser.parse_args()

    report = run_repository_truth_audit(repo_root=args.repo_root)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(report.render_receipt_banner())

    return 0 if report.all_checks_passed else 1


if __name__ == "__main__":
    sys.exit(main())
