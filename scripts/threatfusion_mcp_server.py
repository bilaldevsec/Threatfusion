#!/usr/bin/env python3
"""Read-only ThreatFusion MCP server (JSON-RPC 2.0 over stdio).

Exposes queue, incident, advisory-trace, and draft-rule tools only.
Never exposes Approve, Dispatch, Isolate, or Rollback.
"""

from __future__ import annotations

import json
import os
import re
import sys
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "backend" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from threatfusion.advisory.telemetry_shield import (  # noqa: E402
    _strip_combining_marks,
    _strip_cf_cc,
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
_MAX_RPC_BYTES = 1_048_576
_MAX_HEADER_COUNT = 32
_MAX_HEADER_BYTES = 16_384
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


class InvalidMcpParamsError(ValueError):
    """Raised when MCP tool arguments fail strict schema validation."""


def _require_int_arg(
    arguments: Mapping[str, Any],
    key: str,
    *,
    required: bool,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int | None:
    if key not in arguments or arguments[key] is None:
        if required:
            raise InvalidMcpParamsError(f"missing_required_param:{key}")
        return None
    raw = arguments[key]
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise InvalidMcpParamsError(f"invalid_int_param:{key}")
    if minimum is not None and raw < minimum:
        raise InvalidMcpParamsError(f"param_below_minimum:{key}")
    if maximum is not None and raw > maximum:
        raise InvalidMcpParamsError(f"param_above_maximum:{key}")
    return raw


def _require_optional_str_arg(arguments: Mapping[str, Any], key: str) -> str:
    if key not in arguments or arguments[key] is None:
        return ""
    raw = arguments[key]
    if not isinstance(raw, str):
        raise InvalidMcpParamsError(f"invalid_str_param:{key}")
    return raw


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
    parsed_limit = _require_int_arg(arguments, "limit", required=False, minimum=1, maximum=100)
    limit = 20 if parsed_limit is None else parsed_limit
    rows = flow_rows(_live_db_path(), limit=limit)
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
    flow_id = _require_int_arg(arguments, "flow_id", required=True, minimum=1)
    assert flow_id is not None
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
    flow_id = _require_int_arg(arguments, "flow_id", required=True, minimum=1)
    assert flow_id is not None
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
    number = _require_int_arg(arguments, "flow_id", required=False, minimum=1)
    query = _require_optional_str_arg(arguments, "query")
    rule_format = _require_optional_str_arg(arguments, "format") or "both"
    if number is not None:
        return draft_live_hunter_rule(
            _live_db_path(),
            flow_id=number,
            query=query,
            rule_format=rule_format,
        )
    drafted = draft_detection_rule(
        query=query,
        flow_record=None,
        rule_format=rule_format,
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


_DRAFT_QUERY_MUTATION_DIRECTIVES = (
    re.compile(r"(?i)\bthreatfusion_(?:approve|dispatch|isolate|rollback|contain)\b"),
    re.compile(
        r"(?i)\b(?:action|tool|command|cmd|method|operation)\s*[:=]\s*['\"]?"
        r"(?:approve|dispatch|isolate|rollback|contain|execute|exec|block|drop|"
        r"kill|terminate|quarantine|remediate|revoke|modify|destroy|purge|"
        r"overwrite|patch|deploy|shutdown)\b"
    ),
    re.compile(r"(?i)\bdrop\s+(?:table|database|schema)\b"),
    re.compile(
        r"(?i)\b(?:please|now|run|call|invoke|trigger|perform)\s+"
        r"(?:approve|dispatch|isolate|rollback|contain|execute|block|kill|"
        r"terminate|quarantine|remediate|revoke|destroy|purge|shutdown)\b"
    ),
    re.compile(
        r"(?i)\b(?:approve|dispatch|isolate|rollback|quarantine|remediate|revoke|"
        r"destroy|purge|shutdown|kill|terminate)\s+"
        r"(?:host|vm|ip|alert|playbook|session|process|pid|endpoint|target|now|immediately)\b"
    ),
    re.compile(r"(?i)(?:^|[;\n|&`])\s*(?:sudo|bash|sh|exec|eval|iptables|nft|systemctl|rm|kill)\b"),
)


def _draft_query_contains_mutation_directive(query_text: str) -> bool:
    nfkc = unicodedata.normalize("NFKC", str(query_text or ""))
    cleaned = _strip_combining_marks(_strip_cf_cc(nfkc, preserve_line_whitespace=False))
    nfkd_cleaned = _strip_combining_marks(
        _strip_cf_cc(unicodedata.normalize("NFKD", nfkc), preserve_line_whitespace=False)
    )
    return any(
        pattern.search(candidate)
        for candidate in (cleaned, nfkd_cleaned)
        for pattern in _DRAFT_QUERY_MUTATION_DIRECTIVES
    )


def _smuggle_walk(value: Any, *, tool_name: str, field_path: str) -> bool:
    if isinstance(value, str):
        if tool_name == "threatfusion_draft_detection_rule" and field_path == "query":
            return _draft_query_contains_mutation_directive(value)
        return mcp_action_is_forbidden(value)
    if isinstance(value, dict):
        for key, item in value.items():
            key_str = str(key)
            if mcp_action_is_forbidden(key_str):
                return True
            next_path = key_str if not field_path else f"{field_path}.{key_str}"
            if _smuggle_walk(item, tool_name=tool_name, field_path=next_path):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(
            _smuggle_walk(item, tool_name=tool_name, field_path=field_path) for item in value
        )
    return False


def _arguments_smuggle_forbidden_action(value: Any, *, tool_name: str = "") -> bool:
    """True when a tool argument key or string hides Approve/Dispatch/Isolate/Rollback."""
    return _smuggle_walk(value, tool_name=tool_name, field_path="")


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
        raw_arguments = params.get("arguments")
        if (
            "arguments" in params
            and raw_arguments is not None
            and not isinstance(raw_arguments, dict)
        ):
            return _rpc_error(request_id, -32602, "Invalid params")
        arguments = raw_arguments if isinstance(raw_arguments, dict) else {}
        if (
            name in FORBIDDEN_TOOLS
            or mcp_action_is_forbidden(name)
            or _arguments_smuggle_forbidden_action(arguments, tool_name=name)
        ):
            return _rpc_error(
                request_id,
                -32001,
                "read_only_guard: Approve/Dispatch/Isolate/Rollback are forbidden",
            )
        if name not in mcp_readonly_tool_names() or name not in _HANDLERS:
            return _rpc_error(request_id, -32601, f"Unknown tool: {name}")
        try:
            payload = _HANDLERS[name](arguments)
        except InvalidMcpParamsError:
            return _rpc_error(request_id, -32602, "Invalid params")
        except Exception:  # noqa: BLE001 — sanitize internal tool failures
            return _rpc_error(request_id, -32000, "tool_failed: internal_error")
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


def _emit_rpc(response: Mapping[str, Any], *, framed: bool) -> None:
    body = json.dumps(response, sort_keys=True, default=str)
    if framed:
        body_len = len(body.encode("utf-8"))
        sys.stdout.write(f"Content-Length: {body_len}\r\n\r\n{body}")
    else:
        sys.stdout.write(body + "\n")
    sys.stdout.flush()


def _read_bounded_line(raw_in: Any) -> tuple[bytes, bool]:
    """Read one line bounded to _MAX_RPC_BYTES; return (bytes, exceeded_limit)."""
    if raw_in is not None:
        chunk = raw_in.readline(_MAX_RPC_BYTES + 1)
    else:
        text = sys.stdin.readline(_MAX_RPC_BYTES + 1)
        chunk = text.encode("utf-8") if isinstance(text, str) else b""
    if len(chunk) <= _MAX_RPC_BYTES:
        return chunk, False
    # Drain remainder of oversized line so following messages stay aligned.
    while not chunk.endswith(b"\n"):
        if raw_in is not None:
            more = raw_in.readline(65536)
        else:
            more_text = sys.stdin.readline(65536)
            more = more_text.encode("utf-8") if isinstance(more_text, str) else b""
        if not more:
            break
        chunk = more
    return b"", True


def _read_exact_payload(raw_in: Any, length: int) -> bytes | None:
    if raw_in is not None:
        chunks: list[bytes] = []
        remaining = length
        while remaining > 0:
            part = raw_in.read(remaining)
            if not part:
                return None
            chunks.append(part)
            remaining -= len(part)
        return b"".join(chunks)
    # Text-only stream fallback (e.g., io.StringIO in unit tests).
    collected = bytearray()
    while len(collected) < length:
        ch = sys.stdin.read(1)
        if not ch:
            return None
        collected.extend(ch.encode("utf-8"))
    return bytes(collected)


def _drain_payload(raw_in: Any, length: int) -> None:
    remaining = length
    while remaining > 0:
        step = min(remaining, 65536)
        if raw_in is not None:
            part = raw_in.read(step)
        else:
            part_text = sys.stdin.read(step)
            part = part_text.encode("utf-8") if part_text else b""
        if not part:
            break
        remaining -= len(part)


def serve_stdio() -> int:
    """Read newline-delimited or Content-Length JSON-RPC from stdin and write responses."""
    raw_in = getattr(sys.stdin, "buffer", None)
    while True:
        line_bytes, exceeded = _read_bounded_line(raw_in)
        if exceeded:
            _emit_rpc(
                _rpc_error(None, -32600, "Invalid Request: message exceeds max size"), framed=False
            )
            continue
        if not line_bytes:
            break
        stripped = line_bytes.strip()
        if not stripped:
            continue

        # Detect Content-Length / header-framed MCP/LSP messages.
        if not stripped.startswith((b"{", b"[")) and b":" in stripped:
            headers: list[bytes] = [stripped]
            total_header_bytes = len(line_bytes)
            header_failed = False
            while True:
                if len(headers) >= _MAX_HEADER_COUNT or total_header_bytes > _MAX_HEADER_BYTES:
                    header_failed = True
                    break
                hdr_line, hdr_exceeded = _read_bounded_line(raw_in)
                if hdr_exceeded:
                    header_failed = True
                    break
                if not hdr_line:
                    header_failed = True
                    break
                total_header_bytes += len(hdr_line)
                hdr_clean = hdr_line.strip()
                if not hdr_clean:
                    break
                headers.append(hdr_clean)
            if header_failed:
                _emit_rpc(_rpc_error(None, -32600, "Invalid Request"), framed=True)
                break
            content_length: int | None = None
            invalid_header = False
            for hdr in headers:
                if b":" not in hdr:
                    invalid_header = True
                    break
                h_name, h_val = hdr.split(b":", 1)
                if h_name.strip().lower() == b"content-length":
                    val_str = h_val.decode("ascii", errors="replace").strip()
                    if not val_str.isdigit():
                        invalid_header = True
                        break
                    content_length = int(val_str)
            if invalid_header or content_length is None or content_length < 0:
                _emit_rpc(
                    _rpc_error(None, -32600, "Invalid Request: invalid Content-Length"),
                    framed=True,
                )
                break
            if content_length > _MAX_RPC_BYTES:
                _drain_payload(raw_in, content_length)
                _emit_rpc(
                    _rpc_error(None, -32600, "Invalid Request: message exceeds max size"),
                    framed=True,
                )
                continue
            body_bytes = _read_exact_payload(raw_in, content_length)
            if body_bytes is None:
                _emit_rpc(_rpc_error(None, -32700, "Parse error"), framed=True)
                break
            try:
                message = json.loads(body_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                _emit_rpc(_rpc_error(None, -32700, "Parse error"), framed=True)
                continue
            response = handle_rpc(message if isinstance(message, dict) else {})
            if response is not None:
                _emit_rpc(response, framed=True)
            continue

        try:
            message = json.loads(stripped.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _emit_rpc(_rpc_error(None, -32700, "Parse error"), framed=False)
            continue
        response = handle_rpc(message if isinstance(message, dict) else {})
        if response is not None:
            _emit_rpc(response, framed=False)
    return 0


def main() -> int:
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
