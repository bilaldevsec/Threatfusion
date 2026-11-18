#!/usr/bin/env python3
"""Read-only ThreatFusion MCP server (JSON-RPC 2.0 over stdio).

Exposes queue, incident, advisory-trace, and draft-rule tools only.
Never exposes Approve, Dispatch, Isolate, or Rollback.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "backend" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from threatfusion.advisory.telemetry_shield import (  # noqa: E402
    draft_detection_rule,
    mcp_action_is_forbidden,
    mcp_readonly_tool_names,
)
from threatfusion.api.live_soc_console import (  # noqa: E402
    draft_live_hunter_rule,
    read_advisory_trace,
)
from threatfusion.api.live_soc_console import (  # noqa: E402
    _flow_rows as flow_rows,
)

SERVER_NAME = "threatfusion-readonly-mcp"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"
FORBIDDEN_TOOLS = frozenset(
    {
        "threatfusion_approve",
        "threatfusion_dispatch",
        "threatfusion_isolate",
        "threatfusion_rollback",
        "approve",
        "dispatch",
        "isolate",
        "rollback",
        "contain",
    }
)


def _live_db_path() -> Path:
    raw = os.environ.get("THREATFUSION_LIVE_DB", "").strip()
    if raw:
        return Path(raw)
    return Path("/tmp/threatfusion-range-demo/live_flows.sqlite3")


def _tool_schemas() -> list[dict[str, Any]]:
    return [
        {
            "name": "threatfusion_list_queue",
            "description": (
                "List top prioritized live incidents with Frozen RF, AE, "
                "9-Class DNN, and burst_count. Read-only."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                },
            },
        },
        {
            "name": "threatfusion_get_incident",
            "description": (
                "Return full forensic evidence and CVE/MITRE context for one flow_id. " "Read-only."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"flow_id": {"type": "integer"}},
                "required": ["flow_id"],
            },
        },
        {
            "name": "threatfusion_get_advisory_trace",
            "description": (
                "Return Gate G9 proof, decision_writes_by_advisory_components, "
                "Evidence Fence digest, and Ledger Verification status. Read-only."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"flow_id": {"type": "integer"}},
                "required": ["flow_id"],
            },
        },
        {
            "name": "threatfusion_draft_detection_rule",
            "description": (
                "Draft review-only Suricata and Sigma detection rules for a flow "
                "or natural-language query. Never deploys."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "flow_id": {"type": "integer"},
                    "query": {"type": "string"},
                    "format": {
                        "type": "string",
                        "enum": ["suricata", "sigma", "both"],
                    },
                },
            },
        },
    ]


def _list_queue(arguments: dict[str, Any]) -> dict[str, Any]:
    limit = int(arguments.get("limit") or 20)
    rows = flow_rows(_live_db_path(), limit=max(1, min(limit, 100)))
    queue = []
    for row in rows:
        queue.append(
            {
                "flow_id": row.get("flow_id"),
                "decision": row.get("decision"),
                "rf_attack_probability": row.get("rf_attack_probability"),
                "ae_loss": row.get("ae_loss"),
                "dnn_attack_probability": row.get("dnn_attack_probability"),
                "unsw_attack_category": row.get("unsw_attack_category"),
                "burst_count": int(row.get("burst_count") or 1),
                "simhash_signature": row.get("simhash_signature") or "",
                "src_entity_id": row.get("src_entity_id"),
                "dst_entity_id": row.get("dst_entity_id"),
                "case_title": row.get("case_title"),
                "production_fusion_enabled": False,
            }
        )
    return {
        "schema_version": "threatfusion_mcp_queue_v1",
        "read_only": True,
        "count": len(queue),
        "queue": queue,
    }


def _get_incident(arguments: dict[str, Any]) -> dict[str, Any]:
    flow_id = int(arguments.get("flow_id") or 0)
    rows = flow_rows(_live_db_path(), limit=1, flow_id=flow_id)
    if not rows:
        return {
            "schema_version": "threatfusion_mcp_incident_v1",
            "read_only": True,
            "reason": "flow_not_stored",
            "flow_id": flow_id,
        }
    row = rows[0]
    return {
        "schema_version": "threatfusion_mcp_incident_v1",
        "read_only": True,
        "incident": row,
        "production_fusion_enabled": False,
    }


def _get_advisory_trace(arguments: dict[str, Any]) -> dict[str, Any]:
    flow_id = int(arguments.get("flow_id") or 0)
    payload = read_advisory_trace(_live_db_path(), flow_id)
    authority = payload.get("authority") if isinstance(payload.get("authority"), dict) else {}
    return {
        "schema_version": "threatfusion_mcp_advisory_trace_v1",
        "read_only": True,
        "flow_id": flow_id,
        "gate_g9": authority.get("gate_g9"),
        "decision_writes_by_advisory_components": payload.get(
            "decision_writes_by_advisory_components", 0
        ),
        "evidence_envelope": payload.get("evidence_envelope"),
        "envelope_sha256": payload.get("envelope_sha256"),
        "ledger_verification": payload.get("ledger_verification"),
        "authority": authority,
        "production_fusion_enabled": False,
    }


def _draft_rule(arguments: dict[str, Any]) -> dict[str, Any]:
    flow_id = arguments.get("flow_id")
    number = None
    if flow_id not in (None, ""):
        try:
            number = int(flow_id)
        except (TypeError, ValueError):
            number = None
    if number is not None:
        return draft_live_hunter_rule(
            _live_db_path(),
            flow_id=number,
            query=str(arguments.get("query") or ""),
            rule_format=str(arguments.get("format") or "both"),
        )
    drafted = draft_detection_rule(
        query=str(arguments.get("query") or ""),
        flow_record=None,
        rule_format=str(arguments.get("format") or "both"),
    )
    drafted["read_only"] = True
    drafted["http_status"] = 200
    return drafted


_HANDLERS = {
    "threatfusion_list_queue": _list_queue,
    "threatfusion_get_incident": _get_incident,
    "threatfusion_get_advisory_trace": _get_advisory_trace,
    "threatfusion_draft_detection_rule": _draft_rule,
}

_RUNBOOKS: dict[str, dict[str, str]] = {
    "ioc_enrichment_runbook": {
        "description": (
            "Read-only steps to compare stored addresses and ports with the local "
            "indicator snapshot."
        ),
        "text": (
            "1. Read the stored source and destination addresses for the selected flow.\n"
            "2. Compare those addresses and ports with the local indicator snapshot.\n"
            "3. Keep private, loopback, and link-local addresses on this host.\n"
            "4. Record only indicator tags that already exist on the stored flow.\n"
            "5. Leave the frozen-forest decision unchanged."
        ),
    },
    "alert_triage_runbook": {
        "description": (
            "Read-only steps to compare a stored forest probability with the 0.5 threshold."
        ),
        "text": (
            "1. Read the live queue and the selected flow id.\n"
            "2. Compare the frozen-forest probability with the 0.5 threshold.\n"
            "3. Record the decision, the evidence state, and an analyst note that cites "
            "only stored fields.\n"
            "4. Leave the forest score and the evidence row unchanged."
        ),
    },
    "statistical_hunt_runbook": {
        "description": (
            "Read-only steps to compare a hunting hypothesis with the stored source-byte z-score."
        ),
        "text": (
            "1. Read the five hunting guides and their hypothesis H1 strings.\n"
            "2. Compare max_sbytes_zscore with the stored source-byte distribution.\n"
            "3. Draft review-only detection text for the selected guide.\n"
            "4. Do not insert a row into the live database."
        ),
    },
}


def _rpc_result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def handle_rpc(message: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC request. Notifications return None."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _rpc_error(None, -32600, "Invalid Request")
    request_id = message.get("id")
    method = str(message.get("method") or "")
    params = message.get("params") if isinstance(message.get("params"), dict) else {}
    if method == "initialize":
        return _rpc_result(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}, "prompts": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": (
                    "ThreatFusion read-only MCP. Approve/Dispatch/Isolate/Rollback "
                    "are intentionally unavailable."
                ),
            },
        )
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _rpc_result(request_id, {"tools": _tool_schemas()})
    if method == "prompts/list":
        prompts = [
            {"name": name, "description": spec["description"], "arguments": []}
            for name, spec in _RUNBOOKS.items()
        ]
        return _rpc_result(request_id, {"prompts": prompts})
    if method == "prompts/get":
        name = str(params.get("name") or "")
        spec = _RUNBOOKS.get(name)
        if spec is None:
            return _rpc_error(request_id, -32602, f"Unknown prompt: {name}")
        return _rpc_result(
            request_id,
            {
                "description": spec["description"],
                "messages": [
                    {
                        "role": "user",
                        "content": {"type": "text", "text": spec["text"]},
                    }
                ],
            },
        )
    if method == "tools/call":
        name = str(params.get("name") or "")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if name in FORBIDDEN_TOOLS or mcp_action_is_forbidden(name):
            return _rpc_error(
                request_id,
                -32001,
                "read_only_guard: Approve/Dispatch/Isolate/Rollback are forbidden",
            )
        if name not in mcp_readonly_tool_names() or name not in _HANDLERS:
            return _rpc_error(request_id, -32601, f"Unknown tool: {name}")
        try:
            payload = _HANDLERS[name](arguments)
        except Exception as exc:  # noqa: BLE001 — surface tool failures to MCP client
            return _rpc_error(request_id, -32000, f"tool_failed: {exc}")
        return _rpc_result(
            request_id,
            {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(payload, sort_keys=True, default=str),
                    }
                ],
                "structuredContent": payload,
                "isError": False,
            },
        )
    if request_id is None:
        return None
    return _rpc_error(request_id, -32601, f"Method not found: {method}")


def serve_stdio() -> int:
    """Read newline-delimited JSON-RPC from stdin and write responses to stdout."""
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(
                json.dumps(_rpc_error(None, -32700, "Parse error"), sort_keys=True) + "\n"
            )
            sys.stdout.flush()
            continue
        response = handle_rpc(message if isinstance(message, dict) else {})
        if response is None:
            continue
        sys.stdout.write(json.dumps(response, sort_keys=True, default=str) + "\n")
        sys.stdout.flush()
    return 0


def main() -> int:
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
