"""ThreatFusion Cloud Live Telemetry Forwarder and Resilience Ingestion.

Provides self-healing Suricata eve.json stream processing with dead-letter
quarantine and a fail-closed $0 cloud budget kill-switch for the Google AI Pro
/ Google Developer Program credit model.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import math
from typing import Any

from threatfusion.datasets.adapters.base import SourceRowValidationError
from threatfusion.datasets.adapters.suricata_flow import (
    SuricataFlowAdapter,
    SuricataFlowAdaptationResult,
)


@dataclass(frozen=True, slots=True)
class DeadLetterQuarantineRecord:
    """Record of a quarantined malformed or invalid Suricata telemetry line."""

    line_number: int
    error_code: str
    error_detail: str
    raw_excerpt: str
    recorded_at_utc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "line_number": self.line_number,
            "error_code": self.error_code,
            "error_detail": self.error_detail,
            "raw_excerpt": self.raw_excerpt,
            "recorded_at_utc": self.recorded_at_utc,
        }


@dataclass(frozen=True, slots=True)
class SuricataStreamBatchReport:
    """Summary of batch stream processing across valid, skipped, and quarantined events."""

    total_lines_read: int
    non_flow_events_skipped: int
    valid_flows_adapted: int
    dead_letter_count: int
    dead_letter_records: tuple[DeadLetterQuarantineRecord, ...]
    adapted_results: tuple[SuricataFlowAdaptationResult, ...]
    provenance_verified_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_lines_read": self.total_lines_read,
            "non_flow_events_skipped": self.non_flow_events_skipped,
            "valid_flows_adapted": self.valid_flows_adapted,
            "dead_letter_count": self.dead_letter_count,
            "provenance_verified_count": self.provenance_verified_count,
            "dead_letter_records": [r.to_dict() for r in self.dead_letter_records],
            "adapted_results_count": len(self.adapted_results),
        }


def process_suricata_eve_stream_resilient(
    lines: Iterable[str],
    *,
    sensor_namespace: str = "azure-suricata-edge-01",
    clock_synced: bool = True,
    max_dead_letters: int = 1000,
) -> SuricataStreamBatchReport:
    """Process a stream of Suricata eve.json lines with dead-letter resilience.

    - Blank lines are safely ignored.
    - Non-flow Suricata events (event_type != 'flow') increment non_flow_events_skipped cleanly.
    - Malformed/truncated JSON lines, missing flow fields, negative durations/counts, or
      invalid IP addresses are caught and quarantined into dead_letter_records with
      deterministic error_code values ('malformed_json_line', 'schema_validation_failed')
      without crashing or halting stream processing of subsequent valid attack flows.
    - When valid flow is adapted, increments valid_flows_adapted and provenance_verified_count
      (if provenance_contract present and verified).
    - Respects max_dead_letters cap for recorded entries while still tracking dead_letter_count.
    """
    adapter = SuricataFlowAdapter(default_sensor_namespace=sensor_namespace)

    total_lines_read = 0
    non_flow_events_skipped = 0
    valid_flows_adapted = 0
    dead_letter_count = 0
    provenance_verified_count = 0

    dead_letter_records: list[DeadLetterQuarantineRecord] = []
    adapted_results: list[SuricataFlowAdaptationResult] = []

    for line_number, raw_line in enumerate(lines, start=1):
        total_lines_read += 1
        stripped = raw_line.strip()
        if not stripped:
            continue

        # 1. Attempt JSON decoding
        try:
            record = json.loads(stripped)
        except Exception as exc:
            dead_letter_count += 1
            if len(dead_letter_records) < max_dead_letters:
                dead_letter_records.append(
                    DeadLetterQuarantineRecord(
                        line_number=line_number,
                        error_code="malformed_json_line",
                        error_detail=f"Malformed or truncated JSON: {exc}",
                        raw_excerpt=stripped[:500],
                        recorded_at_utc=datetime.now(UTC).isoformat(),
                    )
                )
            continue

        # 2. Must be a JSON dictionary
        if not isinstance(record, dict):
            dead_letter_count += 1
            if len(dead_letter_records) < max_dead_letters:
                dead_letter_records.append(
                    DeadLetterQuarantineRecord(
                        line_number=line_number,
                        error_code="schema_validation_failed",
                        error_detail=f"EVE record must be a JSON dictionary, got {type(record).__name__}",
                        raw_excerpt=stripped[:500],
                        recorded_at_utc=datetime.now(UTC).isoformat(),
                    )
                )
            continue

        # 3. Cleanly skip non-flow Suricata events (e.g. stats, dns, http, tls, alert)
        event_type = record.get("event_type")
        if isinstance(event_type, str) and event_type != "flow":
            non_flow_events_skipped += 1
            continue

        # 4. Adapt flow record into 14 features and provenance contract
        try:
            res = adapter.adapt_eve_flow_record(
                record,
                sensor_namespace=sensor_namespace,
                clock_synchronized=clock_synced,
            )
            adapted_results.append(res)
            valid_flows_adapted += 1

            contract = getattr(res, "provenance_contract", None)
            if contract is not None:
                is_v = getattr(contract, "is_verified", None)
                if callable(is_v):
                    if is_v():
                        provenance_verified_count += 1
                else:
                    provenance_verified_count += 1
        except SourceRowValidationError as exc:
            dead_letter_count += 1
            if len(dead_letter_records) < max_dead_letters:
                dead_letter_records.append(
                    DeadLetterQuarantineRecord(
                        line_number=line_number,
                        error_code="schema_validation_failed",
                        error_detail=str(exc),
                        raw_excerpt=stripped[:500],
                        recorded_at_utc=datetime.now(UTC).isoformat(),
                    )
                )
        except Exception as exc:
            dead_letter_count += 1
            if len(dead_letter_records) < max_dead_letters:
                dead_letter_records.append(
                    DeadLetterQuarantineRecord(
                        line_number=line_number,
                        error_code="schema_validation_failed",
                        error_detail=f"Adaptation failed: {exc}",
                        raw_excerpt=stripped[:500],
                        recorded_at_utc=datetime.now(UTC).isoformat(),
                    )
                )

    return SuricataStreamBatchReport(
        total_lines_read=total_lines_read,
        non_flow_events_skipped=non_flow_events_skipped,
        valid_flows_adapted=valid_flows_adapted,
        dead_letter_count=dead_letter_count,
        dead_letter_records=tuple(dead_letter_records),
        adapted_results=tuple(adapted_results),
        provenance_verified_count=provenance_verified_count,
    )


@dataclass(frozen=True, slots=True)
class CloudBudgetKillSwitchPolicy:
    """Policy definition for cloud spending cap and automated kill-switch."""

    monthly_credit_usd: float = 10.0
    hard_shutoff_threshold_usd: float = 5.0
    include_credits_in_cost: bool = False
    action_on_threshold: str = "detach_billing_account_and_stop_instances"


def evaluate_budget_kill_switch(
    gross_spend_usd: float,
    policy: CloudBudgetKillSwitchPolicy | None = None,
) -> dict[str, Any]:
    """Evaluate gross cloud spend against policy, fail-closed on malformed spend or threshold breach."""
    if policy is None:
        policy = CloudBudgetKillSwitchPolicy()

    # Fail-closed check: negative spend, NaN, Inf, or non-numeric
    if (
        not isinstance(gross_spend_usd, (int, float))
        or math.isnan(gross_spend_usd)
        or math.isinf(gross_spend_usd)
        or gross_spend_usd < 0.0
    ):
        return {
            "should_detach_billing": True,
            "kill_switch_triggered": True,
            "gross_spend_usd": (
                float(gross_spend_usd)
                if isinstance(gross_spend_usd, (int, float)) and not math.isnan(gross_spend_usd)
                else -1.0
            ),
            "hard_shutoff_threshold_usd": policy.hard_shutoff_threshold_usd,
            "monthly_credit_usd": policy.monthly_credit_usd,
            "action": policy.action_on_threshold,
            "status": "triggered_fail_closed",
            "reason": (
                f"Fail-closed: malformed or negative spend telemetry ({gross_spend_usd!r} USD). "
                f"Detaching billing account to prevent liability."
            ),
            "remaining_safe_budget_usd": 0.0,
        }

    spend = float(gross_spend_usd)
    if spend >= policy.hard_shutoff_threshold_usd:
        return {
            "should_detach_billing": True,
            "kill_switch_triggered": True,
            "gross_spend_usd": spend,
            "hard_shutoff_threshold_usd": policy.hard_shutoff_threshold_usd,
            "monthly_credit_usd": policy.monthly_credit_usd,
            "action": policy.action_on_threshold,
            "status": "triggered_threshold_exceeded",
            "reason": (
                f"Gross spend ${spend:.2f} USD reached or exceeded hard shutoff threshold "
                f"${policy.hard_shutoff_threshold_usd:.2f} USD (credit limit: ${policy.monthly_credit_usd:.2f} USD). "
                f"Detaching billing account to guarantee $0 out-of-pocket charges."
            ),
            "remaining_safe_budget_usd": 0.0,
        }

    remaining = round(policy.hard_shutoff_threshold_usd - spend, 4)
    return {
        "should_detach_billing": False,
        "kill_switch_triggered": False,
        "gross_spend_usd": spend,
        "hard_shutoff_threshold_usd": policy.hard_shutoff_threshold_usd,
        "monthly_credit_usd": policy.monthly_credit_usd,
        "action": "allow",
        "status": "normal",
        "reason": f"Gross spend ${spend:.2f} USD is within safe budget threshold ${policy.hard_shutoff_threshold_usd:.2f} USD.",
        "remaining_safe_budget_usd": remaining,
    }


__all__ = [
    "CloudBudgetKillSwitchPolicy",
    "DeadLetterQuarantineRecord",
    "SuricataStreamBatchReport",
    "evaluate_budget_kill_switch",
    "process_suricata_eve_stream_resilient",
]
