#!/usr/bin/env python3
"""CLI Entrypoint: Turnkey Two-Track Jury & Supervisor Demonstration Runner.

Executes Track A (Recorded UNSW-NB15 mTLS Baseline) and Track B (Slide 14 Azure VM Live Ingestion)
end-to-end, producing full_soc_demo_report.json and full_soc_demo_report.md.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import tempfile

# Ensure backend/src is on sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_SRC = REPO_ROOT / "backend" / "src"
if str(BACKEND_SRC) not in sys.path:
    sys.path.insert(0, str(BACKEND_SRC))

from threatfusion.operations.full_soc_demo import run_full_soc_demo  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ThreatFusion Turnkey Two-Track Jury & Supervisor Demonstration Runner"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(tempfile.gettempdir()) / "threatfusion_full_soc_demo",
        help="Target directory to write JSON and Markdown demonstration reports",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console progress output",
    )

    args = parser.parse_args()

    if not args.quiet:
        print("=" * 70)
        print("ThreatFusion: Turnkey Two-Track SOC Demo Runner (AI-FYP-2006)")
        print(f"Output Directory: {args.output_dir}")
        print("=" * 70)

    try:
        report = run_full_soc_demo(output_dir=args.output_dir)
        if not args.quiet:
            print("\n[SUCCESS] ThreatFusion Turnkey Two-Track Demonstration Completed.")
            print(f"Schema Version: {report['schema_version']}")
            print(f"Checkpoint Commit: {report['evaluation_checkpoint_commit']}")
            print(f"Track A Rows Evaluated: {len(report['track_a_unsw_replay']['rows_evaluated'])}")
            print(f"Track B Incident ID: {report['track_b_azure_live_spine']['incident_id']}")
            print(f"Reports Generated at: {args.output_dir.resolve()}")
            print(f" - JSON: {args.output_dir / 'full_soc_demo_report.json'}")
            print(f" - Markdown: {args.output_dir / 'full_soc_demo_report.md'}")
        return 0
    except Exception as exc:
        print(f"\n[ERROR] Demonstration runner failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
