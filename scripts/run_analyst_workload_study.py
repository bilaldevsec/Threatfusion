#!/usr/bin/env python3
"""ThreatFusion Section 13.F Analyst Workload & Triage Study CLI Executable.

Supports:
1. Automated Smoke Mode (--mode smoke):
   Deterministic 20-trial evaluation across both conditions tagged with
   study_cohort="synthetic_smoke_verification", enforcing that tf_009_closure_eligible
   is strictly False.
2. Interactive Human Analyst Mode (--mode interactive --participant <ID>):
   Prompts human analyst through 10 cases under both conditions, recording wall-clock
   first review and disposition times under study_cohort="human_analyst_cohort_study",
   generating JSON + Markdown summary reports.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import tempfile

from threatfusion.evaluation.study_runner import (
    run_automated_smoke_study,
    run_interactive_study,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ThreatFusion Section 13.F Analyst Workload & Triage Study CLI"
    )
    parser.add_argument(
        "--mode",
        choices=["smoke", "interactive"],
        default="smoke",
        help="Execution mode: 'smoke' (automated scripted verification) or 'interactive' (human analyst trial)",
    )
    parser.add_argument(
        "--participant",
        type=str,
        default="analyst_test_01",
        help="Participant identifier or roll number (e.g. 21K-3551)",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Path to workload_study.sqlite3 database (defaults to temporary directory)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory to save JSON and Markdown reports (defaults to temporary directory)",
    )
    args = parser.parse_args()

    # Default paths in temporary directory to keep repository git status clean
    default_base = Path(tempfile.gettempdir()) / "threatfusion_workload_study"
    default_base.mkdir(parents=True, exist_ok=True)

    db_path = args.db_path if args.db_path is not None else default_base / "workload_study.sqlite3"
    output_dir = args.output_dir if args.output_dir is not None else default_base / "reports"

    try:
        if args.mode == "smoke":
            print(f"Executing automated smoke study (20 trials) -> DB: {db_path}")
            summary = run_automated_smoke_study(db_path=db_path)
            print("\nAutomated Smoke Study Results:")
            print(f"  Cohort:               {summary.study_cohort}")
            print(f"  Total Trials:         {summary.total_trials} (10 baseline, 10 ThreatFusion)")
            print(f"  Baseline Mean Time:   {summary.baseline_mean_time_to_disposition_ms:.1f} ms")
            print(
                f"  ThreatFusion Mean:    {summary.threatfusion_mean_time_to_disposition_ms:.1f} ms"
            )
            print(f"  Measured Speedup:     {summary.speedup_pct:.2f}%")
            print(f"  Baseline Accuracy:    {summary.baseline_accuracy_pct:.2f}%")
            print(f"  ThreatFusion Accuracy: {summary.threatfusion_accuracy_pct:.2f}%")
            print(f"  Accuracy Gain:        {summary.accuracy_gain_percentage_points:+.2f} pp")
            print(
                f"  TF-009 Closure:       {summary.tf_009_closure_eligible} (strictly False for synthetic cohort)"
            )
            print("\n[SUCCESS] Automated smoke verification passed.")
        else:
            summary, json_path, md_path = run_interactive_study(
                db_path=db_path,
                participant_id=args.participant,
                output_dir=output_dir,
            )
            print("Interactive study concluded successfully.")
            print(f"Report: {md_path}")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
