#!/usr/bin/env python3
"""ThreatFusion Cloud Suricata EVE Live Telemetry Forwarder CLI.

Ingests Suricata eve.json telemetry streams from file or stdin with self-healing
dead-letter quarantine, adapting valid network flow records into the exact 14 features
and EntityProvenanceContract required by the frozen Random Forest inference pipeline.
Includes programmatic evaluation of the $0 cloud budget kill-switch.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.operations.cloud_live_telemetry import (  # noqa: E402
    CloudBudgetKillSwitchPolicy,
    SuricataStreamBatchReport,
    evaluate_budget_kill_switch,
    process_suricata_eve_stream_resilient,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "ThreatFusion Resilient Cloud Suricata EVE Telemetry Forwarder "
            "with Dead-Letter Quarantine & $0 Cloud Budget Kill-Switch."
        )
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=None,
        help="Path to Suricata eve.json file (default: stdin if omitted or '-').",
    )
    parser.add_argument(
        "-i",
        "--input-file",
        dest="input_file_flag",
        default=None,
        help="Explicit path to Suricata eve.json file.",
    )
    parser.add_argument(
        "--sensor-namespace",
        default="azure-suricata-edge-01",
        help="Sensor namespace identifier for EntityProvenanceContract (default: azure-suricata-edge-01).",
    )
    parser.add_argument(
        "--clock-synced",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Assert synchronized sensor clock for provenance verification (default: True).",
    )
    parser.add_argument(
        "--max-dead-letters",
        type=int,
        default=1000,
        help="Maximum number of dead-letter records to retain in memory (default: 1000).",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output report format (default: json).",
    )
    parser.add_argument(
        "--budget-check",
        nargs="?",
        const=0.0,
        type=float,
        default=None,
        metavar="GROSS_SPEND_USD",
        help="Evaluate $0 cloud budget kill-switch (optionally provide gross spend in USD, default: 0.0).",
    )
    parser.add_argument(
        "--spend-usd",
        type=float,
        default=None,
        help="Explicit gross spend in USD to evaluate against the budget kill-switch policy.",
    )
    parser.add_argument(
        "--hard-shutoff-threshold",
        type=float,
        default=5.0,
        help="Hard shutoff threshold in USD for budget kill-switch (default: 5.0).",
    )
    parser.add_argument(
        "--monthly-credit",
        type=float,
        default=10.0,
        help="Monthly cloud credit in USD (default: 10.0 for Google AI Pro credit).",
    )
    parser.add_argument(
        "--fail-on-kill-switch",
        action="store_true",
        default=False,
        help="Return exit code 2 if budget kill-switch triggers billing detachment.",
    )
    return parser


def _format_text_report(
    report: SuricataStreamBatchReport,
    sensor_namespace: str,
    budget_eval: dict[str, Any] | None = None,
) -> str:
    lines = [
        "=" * 64,
        "ThreatFusion Cloud Suricata EVE Live Telemetry Forwarder Report",
        "=" * 64,
        f"Sensor Namespace:          {sensor_namespace}",
        f"Total Lines Ingested:      {report.total_lines_read}",
        f"Valid Flows Adapted:       {report.valid_flows_adapted}",
        f"Provenance Verified Count: {report.provenance_verified_count}",
        f"Non-Flow Events Skipped:   {report.non_flow_events_skipped}",
        f"Dead-Letter Quarantined:   {report.dead_letter_count}",
        "-" * 64,
    ]

    if report.dead_letter_records:
        lines.append("Quarantined Dead-Letter Samples:")
        for r in report.dead_letter_records[:5]:
            lines.append(f"  • [Line {r.line_number}] code={r.error_code} error={r.error_detail}")
        if len(report.dead_letter_records) > 5:
            lines.append(f"  ... and {len(report.dead_letter_records) - 5} more records")
        lines.append("-" * 64)

    if budget_eval is not None:
        lines.extend(
            [
                "Cloud Budget Kill-Switch Policy Evaluation:",
                f"  Status:                  {budget_eval['status']}",
                f"  Gross Spend:             ${budget_eval['gross_spend_usd']:.2f} USD",
                f"  Monthly Credit Cap:      ${budget_eval['monthly_credit_usd']:.2f} USD",
                f"  Hard Shutoff Threshold:  ${budget_eval['hard_shutoff_threshold_usd']:.2f} USD",
                f"  Should Detach Billing:   {budget_eval['should_detach_billing']}",
                f"  Action On Threshold:     {budget_eval['action']}",
                f"  Reason:                  {budget_eval['reason']}",
                "=" * 64,
            ]
        )
    else:
        lines.append("=" * 64)

    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    # 1. Budget kill-switch evaluation if requested
    budget_eval: dict[str, Any] | None = None
    spend = args.spend_usd if args.spend_usd is not None else args.budget_check
    if spend is not None:
        policy = CloudBudgetKillSwitchPolicy(
            monthly_credit_usd=args.monthly_credit,
            hard_shutoff_threshold_usd=args.hard_shutoff_threshold,
        )
        budget_eval = evaluate_budget_kill_switch(spend, policy)

    # 2. Determine input source
    input_path = args.input_file_flag or args.input
    lines: list[str] = []

    if input_path and input_path != "-":
        target = Path(input_path)
        if not target.is_file():
            sys.stderr.write(f"Error: input file not found: {target}\n")
            return 1
        with target.open("r", encoding="utf-8") as f:
            lines = f.readlines()
    elif spend is not None and not input_path:
        # Budget check only run without input stream
        lines = []
    elif input_path == "-" or not sys.stdin.isatty():
        try:
            lines = sys.stdin.readlines()
        except OSError:
            lines = []
    else:
        # Interactive stdin or no input
        lines = []

    # 3. Process telemetry stream
    report = process_suricata_eve_stream_resilient(
        lines,
        sensor_namespace=args.sensor_namespace,
        clock_synced=args.clock_synced,
        max_dead_letters=args.max_dead_letters,
    )

    # 4. Format and emit report
    if args.format == "json":
        output_payload: dict[str, Any] = {
            "status": "success",
            "sensor_namespace": args.sensor_namespace,
            "telemetry_batch_report": report.to_dict(),
        }
        if budget_eval is not None:
            output_payload["budget_kill_switch"] = budget_eval
        print(json.dumps(output_payload, indent=2))
    else:
        text_out = _format_text_report(
            report,
            sensor_namespace=args.sensor_namespace,
            budget_eval=budget_eval,
        )
        print(text_out)

    if budget_eval and budget_eval.get("should_detach_billing") and args.fail_on_kill_switch:
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
