"""Unit tests for resilient Cloud Live Telemetry and $0 Budget Kill-Switch (Milestone #28)."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from threatfusion.operations.cloud_live_telemetry import (
    CloudBudgetKillSwitchPolicy,
    DeadLetterQuarantineRecord,
    SuricataStreamBatchReport,
    evaluate_budget_kill_switch,
    process_suricata_eve_stream_resilient,
)

SOURCE_ROOT = Path(__file__).resolve().parents[3] / "backend/src"
SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import run_cloud_suricata_forwarder as forwarder_cli  # noqa: E402


def _make_eve_flow_record(
    *,
    src_ip: str = "10.0.0.4",
    dest_ip: str = "10.0.0.5",
    src_port: int = 44120,
    dest_port: int = 80,
    proto: str = "TCP",
    pkts_toserver: int = 15,
    pkts_toclient: int = 12,
    bytes_toserver: int = 1250,
    bytes_toclient: int = 4800,
    start: str = "2026-10-15T12:00:00.000000+00:00",
    end: str = "2026-10-15T12:00:01.500000+00:00",
    event_type: str = "flow",
) -> dict[str, object]:
    return {
        "timestamp": start,
        "event_type": event_type,
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "app_proto": "http",
        "flow_id": 98765432101234,
        "flow": {
            "pkts_toserver": pkts_toserver,
            "pkts_toclient": pkts_toclient,
            "bytes_toserver": bytes_toserver,
            "bytes_toclient": bytes_toclient,
            "start": start,
            "end": end,
            "age": 1.5,
            "state": "closed",
            "reason": "shutdown",
            "alerted": False,
        },
    }


def test_dead_letter_quarantine_record_and_report_serialization():
    record = DeadLetterQuarantineRecord(
        line_number=42,
        error_code="schema_validation_failed",
        error_detail="Invalid destination port",
        raw_excerpt='{"dest_port": 99999}',
        recorded_at_utc="2026-10-18T10:00:00.000000+00:00",
    )
    d = record.to_dict()
    assert d["line_number"] == 42
    assert d["error_code"] == "schema_validation_failed"
    assert d["raw_excerpt"] == '{"dest_port": 99999}'

    report = SuricataStreamBatchReport(
        total_lines_read=10,
        non_flow_events_skipped=3,
        valid_flows_adapted=5,
        dead_letter_count=2,
        dead_letter_records=(record,),
        adapted_results=(),
        provenance_verified_count=5,
    )
    rd = report.to_dict()
    assert rd["total_lines_read"] == 10
    assert rd["valid_flows_adapted"] == 5
    assert rd["provenance_verified_count"] == 5
    assert rd["dead_letter_count"] == 2
    assert len(rd["dead_letter_records"]) == 1


def test_process_suricata_eve_stream_resilient_happy_and_fault_tolerant():
    valid_flow_1 = json.dumps(_make_eve_flow_record(src_port=10001))
    valid_flow_2 = json.dumps(_make_eve_flow_record(src_port=10002))

    # Various non-flow events
    stats_event = json.dumps(
        {"timestamp": "2026-10-15T12:00:00+00:00", "event_type": "stats", "stats": {}}
    )
    dns_event = json.dumps(
        {"timestamp": "2026-10-15T12:00:00+00:00", "event_type": "dns", "dns": {}}
    )
    alert_event = json.dumps(
        {"timestamp": "2026-10-15T12:00:00+00:00", "event_type": "alert", "alert": {}}
    )
    unrecognized_event = json.dumps(
        {"timestamp": "2026-10-15T12:00:00+00:00", "event_type": "smb", "smb": {}}
    )

    # Various malformed lines
    malformed_json_1 = "   {not valid json at all   "
    malformed_json_2 = '{"truncated": true, "key": '
    non_dict_json = "[1, 2, 3]"

    # Schema invalid flow events
    bad_ip = json.dumps(_make_eve_flow_record(src_ip="999.999.999.999"))
    negative_pkts = json.dumps(_make_eve_flow_record(pkts_toserver=-5))
    inverted_times = json.dumps(
        _make_eve_flow_record(
            start="2026-10-15T12:00:05.000000+00:00",
            end="2026-10-15T12:00:01.000000+00:00",
        )
    )

    stream_lines = [
        "",  # blank 1
        "   \n",  # blank 2
        valid_flow_1,  # Line 3: valid
        stats_event,  # Line 4: skip non-flow
        malformed_json_1,  # Line 5: dead letter malformed_json_line
        dns_event,  # Line 6: skip non-flow
        non_dict_json,  # Line 7: dead letter schema_validation_failed
        bad_ip,  # Line 8: dead letter schema_validation_failed
        "",  # blank 9
        alert_event,  # Line 10: skip non-flow
        negative_pkts,  # Line 11: dead letter schema_validation_failed
        unrecognized_event,  # Line 12: skip non-flow
        malformed_json_2,  # Line 13: dead letter malformed_json_line
        inverted_times,  # Line 14: dead letter schema_validation_failed
        valid_flow_2,  # Line 15: valid (stream keeps processing!)
    ]

    report = process_suricata_eve_stream_resilient(
        stream_lines,
        sensor_namespace="test-sensor-01",
        clock_synced=True,
    )

    assert report.total_lines_read == 15
    assert report.valid_flows_adapted == 2
    assert report.provenance_verified_count == 2
    assert report.non_flow_events_skipped == 4  # stats, dns, alert, smb
    assert report.dead_letter_count == 6  # 2 malformed_json + 1 non_dict + 3 schema failures
    assert len(report.dead_letter_records) == 6
    assert len(report.adapted_results) == 2

    # Check error codes
    error_codes = [r.error_code for r in report.dead_letter_records]
    assert error_codes.count("malformed_json_line") == 2
    assert error_codes.count("schema_validation_failed") == 4

    # Verify that valid flow adapted results contain 14 features and correct provenance
    res1, res2 = report.adapted_results
    assert len(res1.features_14) == 14
    assert res1.provenance_contract.entity_namespace_id == "test-sensor-01"
    assert res1.provenance_contract.is_verified() is True


def test_process_suricata_eve_stream_clock_unsynced_and_cap():
    valid_flow = json.dumps(_make_eve_flow_record())
    bad_line = "{bad"

    lines = [bad_line] * 10 + [valid_flow]

    report = process_suricata_eve_stream_resilient(
        lines,
        sensor_namespace="test-sensor-02",
        clock_synced=False,
        max_dead_letters=3,
    )

    assert report.total_lines_read == 11
    assert report.valid_flows_adapted == 1
    # Because clock_synced is False, provenance is not verified
    assert report.provenance_verified_count == 0
    # dead_letter_count tracks all 10 failures
    assert report.dead_letter_count == 10
    # But dead_letter_records capped at max_dead_letters=3
    assert len(report.dead_letter_records) == 3


def test_evaluate_budget_kill_switch_normal_spend():
    policy = CloudBudgetKillSwitchPolicy()
    res = evaluate_budget_kill_switch(3.50, policy)

    assert res["should_detach_billing"] is False
    assert res["kill_switch_triggered"] is False
    assert res["status"] == "normal"
    assert res["action"] == "allow"
    assert res["remaining_safe_budget_usd"] == 1.50
    assert res["hard_shutoff_threshold_usd"] == 5.0
    assert res["monthly_credit_usd"] == 10.0


def test_evaluate_budget_kill_switch_threshold_breach():
    policy = CloudBudgetKillSwitchPolicy()

    # Exact threshold ($5.00)
    res_exact = evaluate_budget_kill_switch(5.00, policy)
    assert res_exact["should_detach_billing"] is True
    assert res_exact["kill_switch_triggered"] is True
    assert res_exact["status"] == "triggered_threshold_exceeded"
    assert res_exact["action"] == "detach_billing_account_and_stop_instances"
    assert res_exact["remaining_safe_budget_usd"] == 0.0

    # Over threshold ($5.01)
    res_over = evaluate_budget_kill_switch(5.01, policy)
    assert res_over["should_detach_billing"] is True
    assert res_over["kill_switch_triggered"] is True
    assert res_over["status"] == "triggered_threshold_exceeded"

    # Well over ($10.00)
    res_credit = evaluate_budget_kill_switch(10.00, policy)
    assert res_credit["should_detach_billing"] is True


def test_evaluate_budget_kill_switch_fail_closed_malformed_spend():
    policy = CloudBudgetKillSwitchPolicy()

    # Negative spend
    res_neg = evaluate_budget_kill_switch(-0.01, policy)
    assert res_neg["should_detach_billing"] is True
    assert res_neg["kill_switch_triggered"] is True
    assert res_neg["status"] == "triggered_fail_closed"
    assert "negative spend" in res_neg["reason"]

    # NaN
    res_nan = evaluate_budget_kill_switch(float("nan"), policy)
    assert res_nan["should_detach_billing"] is True
    assert res_nan["status"] == "triggered_fail_closed"

    # Inf
    res_inf = evaluate_budget_kill_switch(float("inf"), policy)
    assert res_inf["should_detach_billing"] is True
    assert res_inf["status"] == "triggered_fail_closed"


def test_forwarder_cli_budget_check_json_and_text(capsys):
    # Test JSON output
    code_json = forwarder_cli.main(["--budget-check", "3.00", "--format", "json"])
    assert code_json == 0
    captured_json = capsys.readouterr().out
    data = json.loads(captured_json)
    assert data["status"] == "success"
    assert data["budget_kill_switch"]["should_detach_billing"] is False
    assert data["budget_kill_switch"]["gross_spend_usd"] == 3.0

    # Test text output
    code_text = forwarder_cli.main(["--budget-check", "5.25", "--format", "text"])
    assert code_text == 0
    captured_text = capsys.readouterr().out
    assert "ThreatFusion Cloud Suricata EVE Live Telemetry Forwarder Report" in captured_text
    assert "Should Detach Billing:   True" in captured_text
    assert "Gross Spend:             $5.25 USD" in captured_text

    # Test fail-on-kill-switch flag
    code_fail = forwarder_cli.main(["--budget-check", "6.00", "--fail-on-kill-switch"])
    assert code_fail == 2
    captured_fail = capsys.readouterr().out
    data_fail = json.loads(captured_fail)
    assert data_fail["budget_kill_switch"]["should_detach_billing"] is True


def test_forwarder_cli_file_input(tmp_path, capsys):
    test_file = tmp_path / "suricata_test.json"
    valid_record = _make_eve_flow_record(src_port=55110)
    test_file.write_text(f"{json.dumps(valid_record)}\n{{invalid_json\n", encoding="utf-8")

    code = forwarder_cli.main(
        [
            str(test_file),
            "--sensor-namespace",
            "cli-test-sensor",
            "--format",
            "json",
        ]
    )
    assert code == 0
    captured = capsys.readouterr().out
    res = json.loads(captured)
    report = res["telemetry_batch_report"]
    assert report["total_lines_read"] == 2
    assert report["valid_flows_adapted"] == 1
    assert report["dead_letter_count"] == 1
    assert len(report["dead_letter_records"]) == 1
    assert report["dead_letter_records"][0]["error_code"] == "malformed_json_line"
