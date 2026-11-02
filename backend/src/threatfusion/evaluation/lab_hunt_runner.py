"""Deterministic lab-only hunt pack runner.

Operates on local replay fixtures inside an in-process network block.
Filter steps are hashed with canonical JSON into a separate lab chain file.
Output rows are hypotheses. They are not alerts, scores, or SOAR actions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

LAB_HUNT_SCHEMA_VERSION = "lab_hunt_result_v1"
LAB_FIXTURE_SCHEMA_VERSION = "lab_hunt_fixture_v1"
LAB_PACK_SCHEMA_VERSION = "lab_hunt_pack_v1"
LAB_CHAIN_SCHEMA_VERSION = "lab_hunt_hash_chain_v1"
LAB_CLASSIFICATION = "LAB HYPOTHESIS — NOT AN ALERT"
LAB_CHAIN_GENESIS = "0" * 64
FORBIDDEN_PRODUCTION_DB_NAMES = frozenset(
    {"soar.sqlite3", "alerts.sqlite3", "incidents.sqlite3"}
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_RECORD_KEYS = frozenset({"record_id", "actor", "technique_id", "observed_at", "fields"})
_FIXTURE_KEYS = frozenset({"schema_version", "fixture_id", "source", "records"})
_PACK_KEYS = frozenset({"schema_version", "pack_id", "filters"})
_FILTER_KEYS = frozenset({"step_id", "field", "equals"})
_HASHED_ENTRY_KEYS = (
    "filter",
    "hypotheses_sha256",
    "prev_entry_sha256",
    "sequence_id",
    "surviving_record_ids",
)

_SANDBOX_DEPTH = 0
_ORIGINAL_CONNECT: Any = None
_ORIGINAL_CREATE_CONNECTION: Any = None


class LabHuntSchemaError(ValueError):
    """Raised when a fixture or pack fails the closed lab schema."""


class LabHuntSandboxError(RuntimeError):
    """Raised when an outbound socket is attempted or still allowed."""


def canonical_json(value: Any) -> str:
    """RFC 8785-style canonical JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _blocked_connect(self: socket.socket, _address: Any) -> None:
    raise LabHuntSandboxError("outbound socket connection refused")


def _blocked_create_connection(*_args: Any, **_kwargs: Any) -> socket.socket:
    raise LabHuntSandboxError("outbound socket connection refused")


@contextmanager
def lab_network_sandbox() -> Iterator[None]:
    """Refuse outbound socket connections until the block is released."""
    global _SANDBOX_DEPTH, _ORIGINAL_CONNECT, _ORIGINAL_CREATE_CONNECTION
    if _SANDBOX_DEPTH == 0:
        _ORIGINAL_CONNECT = socket.socket.connect
        _ORIGINAL_CREATE_CONNECTION = socket.create_connection
        socket.socket.connect = _blocked_connect  # type: ignore[method-assign]
        socket.create_connection = _blocked_create_connection
    _SANDBOX_DEPTH += 1
    try:
        yield
    finally:
        _SANDBOX_DEPTH -= 1
        if _SANDBOX_DEPTH == 0:
            socket.socket.connect = _ORIGINAL_CONNECT  # type: ignore[method-assign]
            socket.create_connection = _ORIGINAL_CREATE_CONNECTION
            _ORIGINAL_CONNECT = None
            _ORIGINAL_CREATE_CONNECTION = None


def probe_outbound_socket_blocked() -> None:
    """Abort when a connect would be allowed, or when a connect is attempted."""
    if socket.socket.connect is not _blocked_connect:
        raise LabHuntSandboxError("outbound socket connection is allowed")
    if socket.create_connection is not _blocked_create_connection:
        raise LabHuntSandboxError("outbound socket connection is allowed")
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("203.0.113.10", 443))
    except LabHuntSandboxError:
        return
    raise LabHuntSandboxError("outbound socket connection is allowed")


def _refuse_production_database(path: Path) -> None:
    if path.name in FORBIDDEN_PRODUCTION_DB_NAMES:
        raise LabHuntSandboxError(f"production_database_refused:{path.name}")
    if path.is_symlink():
        raise LabHuntSandboxError("symlink_chain_refused")


def _require_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise LabHuntSchemaError(f"invalid_{field_name}")
    return value


def _json_scalar(value: Any, field_name: str) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not value == value or value in (float("inf"), float("-inf")):
            raise LabHuntSchemaError(f"non_finite_{field_name}")
        return value
    raise LabHuntSchemaError(f"invalid_{field_name}")


def _validate_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise LabHuntSchemaError("record_must_be_object")
    if set(record) - _RECORD_KEYS:
        raise LabHuntSchemaError("record_unknown_field")
    normalized: dict[str, Any] = {
        "record_id": _require_identifier(record.get("record_id"), "record_id")
    }
    for key in ("actor", "technique_id", "observed_at"):
        if key in record:
            text = record[key]
            if not isinstance(text, str) or len(text) > 256:
                raise LabHuntSchemaError(f"invalid_{key}")
            normalized[key] = text
    if "fields" in record:
        fields = record["fields"]
        if not isinstance(fields, dict):
            raise LabHuntSchemaError("invalid_fields")
        copied: dict[str, Any] = {}
        for key, value in fields.items():
            if not isinstance(key, str) or not key or len(key) > 64:
                raise LabHuntSchemaError("invalid_field_name")
            copied[key] = _json_scalar(value, "field_value")
        normalized["fields"] = copied
    return normalized


def _validate_fixture(fixture: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(fixture, Mapping):
        raise LabHuntSchemaError("fixture_must_be_object")
    if set(fixture) != _FIXTURE_KEYS:
        raise LabHuntSchemaError("fixture_schema_mismatch")
    if fixture.get("schema_version") != LAB_FIXTURE_SCHEMA_VERSION:
        raise LabHuntSchemaError("fixture_schema_version")
    if fixture.get("source") != "local_replay":
        raise LabHuntSchemaError("local_replay_required")
    fixture_id = _require_identifier(fixture.get("fixture_id"), "fixture_id")
    records = fixture.get("records")
    if not isinstance(records, list) or not records:
        raise LabHuntSchemaError("records_required")
    normalized_records = [_validate_record(item) for item in records]
    seen: set[str] = set()
    for item in normalized_records:
        if item["record_id"] in seen:
            raise LabHuntSchemaError("duplicate_record_id")
        seen.add(item["record_id"])
    return {
        "schema_version": LAB_FIXTURE_SCHEMA_VERSION,
        "fixture_id": fixture_id,
        "source": "local_replay",
        "records": normalized_records,
    }


def _validate_pack(pack: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(pack, Mapping):
        raise LabHuntSchemaError("pack_must_be_object")
    if set(pack) != _PACK_KEYS:
        raise LabHuntSchemaError("pack_schema_mismatch")
    if pack.get("schema_version") != LAB_PACK_SCHEMA_VERSION:
        raise LabHuntSchemaError("pack_schema_version")
    pack_id = _require_identifier(pack.get("pack_id"), "pack_id")
    filters = pack.get("filters")
    if not isinstance(filters, list) or not filters:
        raise LabHuntSchemaError("filters_required")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in filters:
        if not isinstance(item, dict) or set(item) != _FILTER_KEYS:
            raise LabHuntSchemaError("filter_schema_mismatch")
        step_id = _require_identifier(item.get("step_id"), "step_id")
        if step_id in seen:
            raise LabHuntSchemaError("duplicate_step_id")
        seen.add(step_id)
        field = item.get("field")
        if not isinstance(field, str) or not field or len(field) > 64:
            raise LabHuntSchemaError("invalid_filter_field")
        normalized.append(
            {
                "step_id": step_id,
                "field": field,
                "equals": _json_scalar(item.get("equals"), "equals"),
            }
        )
    return {
        "schema_version": LAB_PACK_SCHEMA_VERSION,
        "pack_id": pack_id,
        "filters": normalized,
    }


def _field_value(record: Mapping[str, Any], field: str) -> Any:
    if field in {"record_id", "actor", "technique_id", "observed_at"}:
        return record.get(field)
    fields = record.get("fields")
    if isinstance(fields, dict) and field in fields:
        return fields[field]
    return None


def _apply_filter(records: list[dict[str, Any]], filt: Mapping[str, Any]) -> list[dict[str, Any]]:
    expected = filt["equals"]
    field = str(filt["field"])
    return [record for record in records if _field_value(record, field) == expected]


def _hypotheses(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        row = {
            "actor": record.get("actor", ""),
            "alert_created": False,
            "classification": LAB_CLASSIFICATION,
            "fields": dict(record.get("fields") or {}),
            "observed_at": record.get("observed_at", ""),
            "record_id": record["record_id"],
            "technique_id": record.get("technique_id", ""),
        }
        rows.append(row)
    return rows


def _chain_entry(
    *,
    filt: Mapping[str, Any],
    prev: str,
    sequence_id: int,
    surviving_ids: list[str],
    hypotheses_sha256: str | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "filter": {
            "equals": filt["equals"],
            "field": filt["field"],
            "step_id": filt["step_id"],
        },
        "prev_entry_sha256": prev,
        "sequence_id": sequence_id,
        "surviving_record_ids": list(surviving_ids),
    }
    if hypotheses_sha256 is not None:
        payload["hypotheses_sha256"] = hypotheses_sha256
    payload["entry_sha256"] = canonical_sha256(
        {key: payload[key] for key in _HASHED_ENTRY_KEYS if key in payload}
    )
    return payload


def _write_chain(path: Path, document: Mapping[str, Any]) -> None:
    _refuse_production_database(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise LabHuntSandboxError("symlink_chain_refused")
    payload = canonical_json(document).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def verify_lab_hash_chain(path: Path) -> bool:
    """Recompute the lab chain. Production database names never verify."""
    if path.name in FORBIDDEN_PRODUCTION_DB_NAMES or path.is_symlink() or not path.is_file():
        return False
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(document, dict):
        return False
    if document.get("schema_version") != LAB_CHAIN_SCHEMA_VERSION:
        return False
    if document.get("genesis_sha256") != LAB_CHAIN_GENESIS:
        return False
    if document.get("classification") != LAB_CLASSIFICATION:
        return False
    entries = document.get("entries")
    hypotheses = document.get("hypotheses")
    if not isinstance(entries, list) or not entries or not isinstance(hypotheses, list):
        return False
    prev = LAB_CHAIN_GENESIS
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return False
        if entry.get("prev_entry_sha256") != prev:
            return False
        if entry.get("sequence_id") != index + 1:
            return False
        expected = canonical_sha256(
            {key: entry[key] for key in _HASHED_ENTRY_KEYS if key in entry}
        )
        if entry.get("entry_sha256") != expected:
            return False
        prev = expected
    if document.get("head_sha256") != prev:
        return False
    last = entries[-1]
    if last.get("hypotheses_sha256") != canonical_sha256(hypotheses):
        return False
    for item in hypotheses:
        if not isinstance(item, dict) or item.get("classification") != LAB_CLASSIFICATION:
            return False
        if item.get("alert_created") is not False:
            return False
    return True


def run_lab_hunt_pack(
    fixture: Mapping[str, Any],
    pack: Mapping[str, Any],
    chain_path: Path,
    *,
    allow_network: bool = False,
) -> dict[str, Any]:
    """Filter a local replay fixture and append one lab hash-chain file.

    ``allow_network=True`` aborts before any filter or write. A connect attempt
    inside the sandbox aborts the same way. The chain path cannot be
    ``soar.sqlite3``, ``alerts.sqlite3``, or ``incidents.sqlite3``.
    """
    if allow_network:
        raise LabHuntSandboxError("outbound socket connection is allowed")
    validated_fixture = _validate_fixture(fixture)
    validated_pack = _validate_pack(pack)
    destination = Path(chain_path)
    _refuse_production_database(destination)
    with lab_network_sandbox():
        probe_outbound_socket_blocked()
        surviving = list(validated_fixture["records"])
        snapshots: list[tuple[dict[str, Any], list[str]]] = []
        for filt in validated_pack["filters"]:
            surviving = _apply_filter(surviving, filt)
            snapshots.append((filt, [row["record_id"] for row in surviving]))
        hypotheses = _hypotheses(surviving)
        hypotheses_sha = canonical_sha256(hypotheses)
        entries: list[dict[str, Any]] = []
        prev = LAB_CHAIN_GENESIS
        last_index = len(snapshots)
        for index, (filt, surviving_ids) in enumerate(snapshots, start=1):
            entry = _chain_entry(
                filt=filt,
                prev=prev,
                sequence_id=index,
                surviving_ids=surviving_ids,
                hypotheses_sha256=hypotheses_sha if index == last_index else None,
            )
            entries.append(entry)
            prev = str(entry["entry_sha256"])
        document = {
            "chain_path_name": destination.name,
            "classification": LAB_CLASSIFICATION,
            "entries": entries,
            "fixture_id": validated_fixture["fixture_id"],
            "genesis_sha256": LAB_CHAIN_GENESIS,
            "head_sha256": prev,
            "hypotheses": hypotheses,
            "pack_id": validated_pack["pack_id"],
            "schema_version": LAB_CHAIN_SCHEMA_VERSION,
        }
        _write_chain(destination, document)
    return {
        "schema_version": LAB_HUNT_SCHEMA_VERSION,
        "classification": LAB_CLASSIFICATION,
        "production_fusion_enabled": False,
        "alert_created": False,
        "network_blocked": True,
        "fixture_id": validated_fixture["fixture_id"],
        "pack_id": validated_pack["pack_id"],
        "chain_path": str(destination),
        "head_sha256": prev,
        "records": hypotheses,
    }
