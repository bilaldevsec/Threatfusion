"""Disk-backed, diagnostic-only preflight for a future UNSW network split."""

from __future__ import annotations

import hashlib
import ipaddress
import itertools
import json
import math
import re
import shutil
import sqlite3
import struct
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from threatfusion.datasets.adapters.base import SourceRowValidationError
from threatfusion.datasets.adapters.unsw_nb15 import adapt_unsw_row
from threatfusion.datasets.manifests import load_dataset_manifest, verify_dataset_manifest
from threatfusion.datasets.unsw_raw import UnswRawReader, read_unsw_feature_names
from threatfusion.features.network_behavior import (
    NETWORK_BEHAVIOR_V1_FEATURES,
    NETWORK_BEHAVIOR_V1_FEATURE_NAMES,
    assert_network_behavior_model_fields,
    project_network_behavior,
)
from threatfusion.schemas.dataset_manifest import DatasetFile
from threatfusion.schemas.flow import NetworkFlow
from threatfusion.utils.checksum import sha256_file

PREFLIGHT_SCHEMA_VERSION = "unsw_split_preflight_v1"
FEATURE_CONTRACT_NAME = "network_behavior_v1"
FEATURE_METADATA_FILENAME = "NUSW-NB15_features.csv"
RAW_FILENAMES: tuple[str, ...] = tuple(f"UNSW-NB15_{part}.csv" for part in range(1, 5))
DEFAULT_BATCH_SIZE = 10_000
DEFAULT_SQLITE_CACHE_MIB = 256
DEFAULT_DISK_BUDGET_BYTES = 8 * 1024**3
DEFAULT_MINIMUM_FREE_BYTES = 2 * 1024**3
SQLITE_QUERY_BATCH_SIZE = 2_048
RAW_TIMESTAMP_QUANTIZATION_SECONDS = Decimal("1")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class UnswSplitPreflightError(RuntimeError):
    """A sanitized failure that is safe to expose in a report or CLI output."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PreflightConfig:
    """Resource and scope controls for one preflight run."""

    batch_size: int = DEFAULT_BATCH_SIZE
    sqlite_cache_mib: int = DEFAULT_SQLITE_CACHE_MIB
    disk_budget_bytes: int = DEFAULT_DISK_BUDGET_BYTES
    minimum_free_bytes: int = DEFAULT_MINIMUM_FREE_BYTES
    max_rows_per_file: int | None = None

    def __post_init__(self) -> None:
        if self.batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if self.sqlite_cache_mib <= 0:
            raise ValueError("sqlite_cache_mib must be positive")
        if self.disk_budget_bytes <= 0:
            raise ValueError("disk_budget_bytes must be positive")
        if self.minimum_free_bytes < 0:
            raise ValueError("minimum_free_bytes must not be negative")
        if self.max_rows_per_file is not None and self.max_rows_per_file <= 0:
            raise ValueError("max_rows_per_file must be positive when set")


@dataclass(frozen=True, slots=True)
class RegisteredUnswInputs:
    """Verified metadata and raw inputs selected from the UNSW manifest."""

    manifest_digest: str
    manifest_version: str
    feature_metadata: DatasetFile
    raw_files: tuple[DatasetFile, ...]
    feature_names: tuple[str, ...]


@dataclass(slots=True)
class ScopeCounters:
    """Fixed-cardinality counters for one file or the overall run."""

    total: int = 0
    accepted: int = 0
    rejected: int = 0
    rejection_categories: Counter[str] = field(default_factory=Counter)
    timestamp_failures: Counter[str] = field(default_factory=Counter)
    timestamp_precision: Counter[str] = field(default_factory=Counter)
    interval_consistency: Counter[str] = field(default_factory=Counter)
    earliest_timestamp: datetime | None = None
    latest_timestamp: datetime | None = None

    def observe_timestamp(self, timestamp: datetime) -> None:
        """Expand the accepted-record UTC timestamp range."""
        self.earliest_timestamp = (
            timestamp
            if self.earliest_timestamp is None
            else min(self.earliest_timestamp, timestamp)
        )
        self.latest_timestamp = (
            timestamp if self.latest_timestamp is None else max(self.latest_timestamp, timestamp)
        )


@dataclass(slots=True)
class DuplicateSummary:
    """Aggregate counts for repeated keys without retaining the keys."""

    groups: int = 0
    rows: int = 0
    excess_rows: int = 0

    def include(self, multiplicity: int) -> None:
        """Include a repeated group of the supplied size."""
        if multiplicity > 1:
            self.groups += 1
            self.rows += multiplicity
            self.excess_rows += multiplicity - 1


@dataclass(slots=True)
class FeatureSummary(DuplicateSummary):
    """Repeated model-vector counts plus label-conflict groups."""

    conflicting_label_groups: int = 0
    conflicting_label_rows: int = 0

    def include_feature(self, multiplicity: int, label_count: int) -> None:
        """Include one feature vector and its number of distinct binary labels."""
        self.include(multiplicity)
        if label_count > 1:
            self.conflicting_label_groups += 1
            self.conflicting_label_rows += multiplicity


@dataclass(slots=True)
class IntervalComponent:
    """Constant-memory state for one connected interval component."""

    end_us: int
    size: int = 1


@dataclass(frozen=True, slots=True)
class PreflightRunResult:
    """Safe paths and summary returned after a report is atomically written."""

    completed: bool
    report_path: Path
    database_path: Path
    total: int
    accepted: int
    rejected: int


def _encode_length_prefixed(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise ValueError("fingerprint field is too large")
    return struct.pack(">I", len(value)) + value


def source_record_fingerprint(row: dict[str, Any], feature_names: Sequence[str]) -> bytes:
    """Hash the exact ordered source fields, excluding reader-injected provenance IDs."""
    digest = hashlib.sha256(b"threatfusion:unsw-source-record:v1\0")
    for name in feature_names:
        digest.update(_encode_length_prefixed(name.encode("utf-8")))
        digest.update(_encode_length_prefixed(str(row[name]).encode("utf-8")))
    return digest.digest()


def model_feature_fingerprint(flow: NetworkFlow) -> bytes:
    """Hash the exact label-free network_behavior_v1 projection and order."""
    assert_network_behavior_model_fields(NETWORK_BEHAVIOR_V1_FEATURE_NAMES)
    values = project_network_behavior(flow)
    digest = hashlib.sha256(b"threatfusion:network-behavior-v1:v1\0")
    for specification, value in zip(NETWORK_BEHAVIOR_V1_FEATURES, values, strict=True):
        digest.update(_encode_length_prefixed(specification.name.encode("utf-8")))
        if specification.dtype == "integer":
            encoded = b"i" + int(value).to_bytes(8, byteorder="big", signed=True)
        elif specification.dtype == "float":
            number = float(value)
            if not math.isfinite(number):
                raise ValueError("model feature must be finite")
            encoded = b"f" + struct.pack(">d", number)
        elif specification.dtype == "category":
            encoded = b"s" + _encode_length_prefixed(str(value).encode("utf-8"))
        else:  # pragma: no cover - protected by the versioned feature contract
            raise ValueError("unsupported feature data type")
        digest.update(encoded)
    return digest.digest()


def normalized_flow_identity_fingerprint(flow: NetworkFlow) -> bytes:
    """Hash a direction-normalized endpoint pair and protocol for internal overlap scans."""

    def endpoint(address: object, port: int) -> bytes:
        parsed = ipaddress.ip_address(str(address))
        return (
            bytes((parsed.version,))
            + _encode_length_prefixed(parsed.packed)
            + struct.pack(">H", port)
        )

    endpoints = sorted((endpoint(flow.src_ip, flow.src_port), endpoint(flow.dst_ip, flow.dst_port)))
    digest = hashlib.sha256(b"threatfusion:normalized-flow-identity:v1\0")
    digest.update(_encode_length_prefixed(endpoints[0]))
    digest.update(_encode_length_prefixed(endpoints[1]))
    digest.update(_encode_length_prefixed(flow.protocol.encode("utf-8")))
    return digest.digest()


def _strict_nonnegative_decimal(value: Any) -> Decimal:
    try:
        parsed = Decimal(str(value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("not a decimal") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("not a nonnegative finite decimal")
    return parsed


def classify_raw_interval(row: dict[str, Any]) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    """Classify raw Stime/Ltime/duration agreement without repairing source values."""
    parsed: dict[str, Decimal] = {}
    failures: list[str] = []
    precision: list[str] = []
    for field_name in ("stime", "ltime", "dur"):
        try:
            parsed[field_name] = _strict_nonnegative_decimal(row[field_name])
        except (KeyError, ValueError):
            failures.append(field_name)
            continue
        if field_name in {"stime", "ltime"}:
            suffix = (
                "integral_seconds"
                if parsed[field_name] == parsed[field_name].to_integral()
                else "fractional_seconds"
            )
            precision.append(f"{field_name}_{suffix}")

    if failures:
        return "unavailable_parse_failure", tuple(failures), tuple(precision)
    elapsed = parsed["ltime"] - parsed["stime"]
    if elapsed < 0:
        return "ltime_before_stime", (), tuple(precision)
    discrepancy = abs(elapsed - parsed["dur"])
    if discrepancy == 0:
        return "exact", (), tuple(precision)
    if discrepancy <= RAW_TIMESTAMP_QUANTIZATION_SECONDS:
        return "within_one_second_quantization", (), tuple(precision)
    return "unexplained_over_one_second", (), tuple(precision)


def _datetime_to_microseconds(value: datetime) -> int:
    delta = value.astimezone(UTC) - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def _run_size_bytes(run_directory: Path) -> int:
    return sum(path.stat().st_size for path in run_directory.iterdir() if path.is_file())


def _guard_disk_budget(run_directory: Path, config: PreflightConfig) -> None:
    if _run_size_bytes(run_directory) > config.disk_budget_bytes:
        raise UnswSplitPreflightError("working_disk_budget_exceeded")
    if shutil.disk_usage(run_directory).free < config.minimum_free_bytes:
        raise UnswSplitPreflightError("minimum_free_space_violated")


def _safe_artifact_root(project_root: Path, artifact_root: Path) -> Path:
    resolved_root = project_root.resolve()
    resolved_artifact = artifact_root.resolve()
    ignored_parent = (resolved_root / "data/interim").resolve()
    if not resolved_artifact.is_relative_to(ignored_parent):
        raise UnswSplitPreflightError("artifact_root_must_be_under_data_interim")
    return resolved_artifact


def verify_registered_unsw_inputs(project_root: Path, manifest_path: Path) -> RegisteredUnswInputs:
    manifest = load_dataset_manifest(manifest_path)
    if manifest.name != "unsw_nb15":
        raise UnswSplitPreflightError("manifest_is_not_unsw_nb15")
    verification = verify_dataset_manifest(manifest, project_root)
    if not verification.verified:
        raise UnswSplitPreflightError("manifest_verification_failed")

    raw_entries = [item for item in manifest.files if item.role == "raw"]
    entries_by_name: dict[str, DatasetFile] = {}
    for item in raw_entries:
        if item.path.name in entries_by_name:
            raise UnswSplitPreflightError("duplicate_registered_raw_basename")
        entries_by_name[item.path.name] = item
    expected_names = {FEATURE_METADATA_FILENAME, *RAW_FILENAMES}
    if set(entries_by_name) != expected_names:
        raise UnswSplitPreflightError("registered_raw_input_set_mismatch")

    feature_metadata = entries_by_name[FEATURE_METADATA_FILENAME]
    if feature_metadata.rows != 49:
        raise UnswSplitPreflightError("feature_metadata_row_count_mismatch")
    raw_files = tuple(entries_by_name[name] for name in RAW_FILENAMES)
    if any(item.rows is None for item in raw_files):
        raise UnswSplitPreflightError("registered_raw_row_count_missing")

    feature_path = (project_root / feature_metadata.path).resolve()
    feature_names = read_unsw_feature_names(feature_path)
    required = {"stime", "ltime", "dur", "srcip", "dstip", "sport", "dsport", "proto", "label"}
    if not required.issubset(feature_names):
        raise UnswSplitPreflightError("required_raw_feature_missing")
    assert_network_behavior_model_fields(NETWORK_BEHAVIOR_V1_FEATURE_NAMES)
    return RegisteredUnswInputs(
        manifest_digest=sha256_file(manifest_path),
        manifest_version=manifest.version,
        feature_metadata=feature_metadata,
        raw_files=raw_files,
        feature_names=feature_names,
    )


def _connect_database(database_path: Path, config: PreflightConfig) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path, isolation_level=None)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute(f"PRAGMA cache_size={-(config.sqlite_cache_mib * 1024)}")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript("""
        CREATE TABLE records (
            file_index INTEGER NOT NULL,
            source_fp BLOB NOT NULL,
            accepted INTEGER NOT NULL,
            feature_fp BLOB,
            tuple_fp BLOB,
            start_us INTEGER,
            end_us INTEGER,
            label INTEGER
        );
        CREATE TABLE day_counts (
            file_index INTEGER NOT NULL,
            utc_day TEXT NOT NULL,
            label TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY (file_index, utc_day, label)
        ) WITHOUT ROWID;
        """)
    return connection


def _flush_batches(
    connection: sqlite3.Connection,
    records: list[tuple[Any, ...]],
    day_counts: Counter[tuple[int, str, str]],
) -> None:
    if not records:
        return
    connection.execute("BEGIN")
    try:
        connection.executemany("INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?)", records)
        connection.executemany(
            """
            INSERT INTO day_counts (file_index, utc_day, label, count)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(file_index, utc_day, label)
            DO UPDATE SET count = count + excluded.count
            """,
            (
                (file_index, day, label, count)
                for (file_index, day, label), count in day_counts.items()
            ),
        )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    records.clear()
    day_counts.clear()


def _update_interval_diagnostics(scopes: Iterable[ScopeCounters], row: dict[str, Any]) -> None:
    category, failures, precision = classify_raw_interval(row)
    for scope in scopes:
        scope.interval_consistency[category] += 1
        scope.timestamp_precision.update(precision)
        scope.timestamp_failures.update(
            failure for failure in failures if failure in {"stime", "ltime"}
        )


def _adapt_row(row: dict[str, Any]) -> tuple[NetworkFlow | None, str | None]:
    try:
        return adapt_unsw_row(row), None
    except SourceRowValidationError:
        return None, "source_validation"
    except ValidationError:
        return None, "canonical_schema_validation"
    except (OverflowError, OSError):
        return None, "timestamp_out_of_range"


def _stream_rows_to_database(
    connection: sqlite3.Connection,
    project_root: Path,
    inputs: RegisteredUnswInputs,
    config: PreflightConfig,
    run_directory: Path,
    progress: Callable[[str, int, int, int], None] | None,
) -> tuple[ScopeCounters, list[ScopeCounters]]:
    overall = ScopeCounters()
    per_file = [ScopeCounters() for _ in inputs.raw_files]
    records: list[tuple[Any, ...]] = []
    day_counts: Counter[tuple[int, str, str]] = Counter()

    for file_index, item in enumerate(inputs.raw_files):
        file_scope = per_file[file_index]
        path = (project_root / item.path).resolve()
        rows: Iterator[dict[str, str]] = iter(
            UnswRawReader(feature_names=inputs.feature_names, raw_files=(path,))
        )
        if config.max_rows_per_file is not None:
            rows = _take(rows, config.max_rows_per_file)
        for row in rows:
            scopes = (overall, file_scope)
            for scope in scopes:
                scope.total += 1
            _update_interval_diagnostics(scopes, row)
            source_fp = source_record_fingerprint(row, inputs.feature_names)
            flow, rejection_category = _adapt_row(row)
            if flow is None:
                for scope in scopes:
                    scope.rejected += 1
                    scope.rejection_categories[rejection_category or "unknown"] += 1
                records.append((file_index, source_fp, 0, None, None, None, None, None))
            else:
                for scope in scopes:
                    scope.accepted += 1
                    scope.observe_timestamp(flow.timestamp_start)
                day = flow.timestamp_start.astimezone(UTC).date().isoformat()
                label = str(flow.label)
                day_counts[(-1, day, label)] += 1
                day_counts[(file_index, day, label)] += 1
                records.append(
                    (
                        file_index,
                        source_fp,
                        1,
                        model_feature_fingerprint(flow),
                        normalized_flow_identity_fingerprint(flow),
                        _datetime_to_microseconds(flow.timestamp_start),
                        _datetime_to_microseconds(flow.timestamp_end),
                        1 if label == "Attack" else 0,
                    )
                )
            if len(records) >= config.batch_size:
                _flush_batches(connection, records, day_counts)
                _guard_disk_budget(run_directory, config)
                if progress is not None:
                    progress(item.path.name, overall.total, overall.accepted, overall.rejected)
        _flush_batches(connection, records, day_counts)
        _guard_disk_budget(run_directory, config)
    return overall, per_file


def _take(rows: Iterator[dict[str, str]], limit: int) -> Iterator[dict[str, str]]:
    yield from itertools.islice(rows, limit)


def _create_indexes(
    connection: sqlite3.Connection, run_directory: Path, config: PreflightConfig
) -> None:
    statements = (
        "CREATE INDEX records_source_idx ON records(source_fp, file_index)",
        "CREATE INDEX records_feature_idx ON records(feature_fp, file_index, label) WHERE accepted = 1",
        "CREATE INDEX records_tuple_idx ON records(tuple_fp, start_us, end_us, file_index) WHERE accepted = 1",
    )

    def stop_if_over_budget() -> int:
        return int(_run_size_bytes(run_directory) > config.disk_budget_bytes)

    connection.set_progress_handler(stop_if_over_budget, 10_000)
    try:
        for statement in statements:
            try:
                connection.execute(statement)
            except sqlite3.OperationalError as exc:
                if _run_size_bytes(run_directory) > config.disk_budget_bytes:
                    raise UnswSplitPreflightError("working_disk_budget_exceeded") from exc
                raise
            _guard_disk_budget(run_directory, config)
    finally:
        connection.set_progress_handler(None, 0)


def _batched_rows(cursor: sqlite3.Cursor) -> Iterator[tuple[Any, ...]]:
    while batch := cursor.fetchmany(SQLITE_QUERY_BATCH_SIZE):
        yield from batch


def _duplicate_summaries(
    connection: sqlite3.Connection, file_count: int
) -> tuple[DuplicateSummary, list[DuplicateSummary]]:
    overall = DuplicateSummary()
    per_file = [DuplicateSummary() for _ in range(file_count)]
    cursor = connection.execute("""
        SELECT source_fp, file_index, COUNT(*)
        FROM records
        GROUP BY source_fp, file_index
        ORDER BY source_fp, file_index
        """)
    current: bytes | None = None
    total = 0
    for fingerprint, file_index, count in _batched_rows(cursor):
        if current is not None and fingerprint != current:
            overall.include(total)
            total = 0
        current = fingerprint
        multiplicity = int(count)
        total += multiplicity
        per_file[int(file_index)].include(multiplicity)
    if current is not None:
        overall.include(total)
    return overall, per_file


def _feature_summaries(
    connection: sqlite3.Connection, file_count: int
) -> tuple[FeatureSummary, list[FeatureSummary]]:
    overall = FeatureSummary()
    per_file = [FeatureSummary() for _ in range(file_count)]
    cursor = connection.execute("""
        SELECT feature_fp, file_index, label, COUNT(*)
        FROM records
        WHERE accepted = 1
        GROUP BY feature_fp, file_index, label
        ORDER BY feature_fp, file_index, label
        """)
    current: bytes | None = None
    total = 0
    labels: set[int] = set()
    file_totals = [0] * file_count
    file_labels: list[set[int]] = [set() for _ in range(file_count)]

    def finish() -> None:
        if current is None:
            return
        overall.include_feature(total, len(labels))
        for index in range(file_count):
            per_file[index].include_feature(file_totals[index], len(file_labels[index]))

    for fingerprint, file_index, label, count in _batched_rows(cursor):
        if current is not None and fingerprint != current:
            finish()
            total = 0
            labels.clear()
            file_totals = [0] * file_count
            file_labels = [set() for _ in range(file_count)]
        current = fingerprint
        index = int(file_index)
        multiplicity = int(count)
        total += multiplicity
        labels.add(int(label))
        file_totals[index] += multiplicity
        file_labels[index].add(int(label))
    finish()
    return overall, per_file


def _finish_component(summary: DuplicateSummary, component: IntervalComponent | None) -> None:
    if component is not None:
        summary.include(component.size)


def _include_interval(
    summary: DuplicateSummary, component: IntervalComponent | None, start_us: int, end_us: int
) -> IntervalComponent:
    if component is None:
        return IntervalComponent(end_us=end_us)
    if start_us <= component.end_us:
        component.size += 1
        component.end_us = max(component.end_us, end_us)
        return component
    _finish_component(summary, component)
    return IntervalComponent(end_us=end_us)


def _tuple_overlap_summaries(
    connection: sqlite3.Connection, file_count: int
) -> tuple[DuplicateSummary, list[DuplicateSummary]]:
    overall = DuplicateSummary()
    per_file = [DuplicateSummary() for _ in range(file_count)]
    cursor = connection.execute("""
        SELECT tuple_fp, start_us, end_us, file_index
        FROM records
        WHERE accepted = 1
        ORDER BY tuple_fp, start_us, end_us, file_index
        """)
    current: bytes | None = None
    overall_component: IntervalComponent | None = None
    file_components: list[IntervalComponent | None] = [None] * file_count
    for fingerprint, start_us, end_us, file_index in _batched_rows(cursor):
        if current is not None and fingerprint != current:
            _finish_component(overall, overall_component)
            for index in range(file_count):
                _finish_component(per_file[index], file_components[index])
            overall_component = None
            file_components = [None] * file_count
        current = fingerprint
        start = int(start_us)
        end = int(end_us)
        index = int(file_index)
        overall_component = _include_interval(overall, overall_component, start, end)
        file_components[index] = _include_interval(
            per_file[index], file_components[index], start, end
        )
    _finish_component(overall, overall_component)
    for index in range(file_count):
        _finish_component(per_file[index], file_components[index])
    return overall, per_file


def _counter_payload(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items()))


def _duplicate_payload(summary: DuplicateSummary) -> dict[str, int]:
    return {
        "group_count": summary.groups,
        "row_count": summary.rows,
        "excess_row_count": summary.excess_rows,
    }


def _feature_payload(summary: FeatureSummary) -> dict[str, int]:
    return {
        **_duplicate_payload(summary),
        "conflicting_label_group_count": summary.conflicting_label_groups,
        "conflicting_label_row_count": summary.conflicting_label_rows,
    }


def _scope_payload(
    scope: ScopeCounters,
    source_duplicates: DuplicateSummary,
    feature_vectors: FeatureSummary,
    tuple_overlaps: DuplicateSummary,
) -> dict[str, Any]:
    return {
        "total_input_rows": scope.total,
        "accepted_count": scope.accepted,
        "rejected_count": scope.rejected,
        "rejection_categories": _counter_payload(scope.rejection_categories),
        "timestamp_range": {
            "earliest": scope.earliest_timestamp.isoformat() if scope.earliest_timestamp else None,
            "latest": scope.latest_timestamp.isoformat() if scope.latest_timestamp else None,
        },
        "timestamp_failures": _counter_payload(scope.timestamp_failures),
        "timestamp_precision_counts": _counter_payload(scope.timestamp_precision),
        "interval_consistency_counts": _counter_payload(scope.interval_consistency),
        "exact_source_duplicates": _duplicate_payload(source_duplicates),
        "repeated_model_feature_vectors": _feature_payload(feature_vectors),
        "overlapping_flow_identities": _duplicate_payload(tuple_overlaps),
    }


def _write_report(
    report_path: Path,
    connection: sqlite3.Connection,
    payload: dict[str, Any],
    input_names: Sequence[str],
) -> None:
    temporary_path = report_path.with_suffix(report_path.suffix + ".tmp")
    with temporary_path.open("w", encoding="utf-8") as report_file:
        report_file.write("{\n")
        keys = sorted((*payload.keys(), "utc_day_class_counts"))
        for key_index, key in enumerate(keys):
            report_file.write(f"  {json.dumps(key)}: ")
            if key != "utc_day_class_counts":
                serialized = json.dumps(payload[key], indent=2, sort_keys=True)
                report_file.write(serialized.replace("\n", "\n  "))
            else:
                report_file.write("[\n")
                cursor = connection.execute(
                    "SELECT file_index, utc_day, label, count FROM day_counts ORDER BY file_index, utc_day, label"
                )
                first = True
                for file_index, utc_day, label, count in _batched_rows(cursor):
                    item = {
                        "count": int(count),
                        "label": str(label),
                        "scope": "overall" if int(file_index) == -1 else "file",
                        "source_file": (
                            None if int(file_index) == -1 else input_names[int(file_index)]
                        ),
                        "utc_day": str(utc_day),
                    }
                    if not first:
                        report_file.write(",\n")
                    report_file.write("    " + json.dumps(item, sort_keys=True))
                    first = False
                report_file.write("\n  ]")
            report_file.write(",\n" if key_index < len(keys) - 1 else "\n")
        report_file.write("}\n")
    temporary_path.replace(report_path)


def _write_failure_report(run_directory: Path, scope: str, code: str) -> None:
    path = run_directory / "preflight_failure.json"
    path.write_text(
        json.dumps(
            {
                "completed": False,
                "creates_assignments": False,
                "failure_code": code,
                "run_scope": scope,
                "schema_version": PREFLIGHT_SCHEMA_VERSION,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def run_unsw_split_preflight(
    project_root: Path,
    manifest_path: Path,
    artifact_root: Path,
    run_id: str,
    config: PreflightConfig = PreflightConfig(),
    progress: Callable[[str, int, int, int], None] | None = None,
) -> PreflightRunResult:
    """Verify and fully diagnose registered UNSW raw inputs without making assignments."""
    if not _RUN_ID.fullmatch(run_id):
        raise UnswSplitPreflightError("invalid_run_id")
    project_root = project_root.resolve()
    artifact_root = _safe_artifact_root(project_root, artifact_root)
    artifact_root.mkdir(parents=True, exist_ok=True)
    run_directory = artifact_root / run_id
    try:
        run_directory.mkdir()
    except FileExistsError as exc:
        raise UnswSplitPreflightError("run_directory_already_exists") from exc
    scope = "partial" if config.max_rows_per_file is not None else "full"
    database_path = run_directory / "preflight.sqlite3"
    connection: sqlite3.Connection | None = None
    try:
        available = shutil.disk_usage(run_directory).free
        if available < config.disk_budget_bytes + config.minimum_free_bytes:
            raise UnswSplitPreflightError("insufficient_free_space_for_disk_budget")
        inputs = verify_registered_unsw_inputs(project_root, manifest_path.resolve())
        connection = _connect_database(database_path, config)
        overall, per_file = _stream_rows_to_database(
            connection,
            project_root,
            inputs,
            config,
            run_directory,
            progress,
        )
        if config.max_rows_per_file is None:
            for item, counters in zip(inputs.raw_files, per_file, strict=True):
                if counters.total != item.rows:
                    raise UnswSplitPreflightError("registered_raw_row_count_mismatch")
        _create_indexes(connection, run_directory, config)
        source_overall, source_per_file = _duplicate_summaries(connection, len(per_file))
        feature_overall, feature_per_file = _feature_summaries(connection, len(per_file))
        tuple_overall, tuple_per_file = _tuple_overlap_summaries(connection, len(per_file))
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        _guard_disk_budget(run_directory, config)

        completed = config.max_rows_per_file is None
        input_names = [item.path.name for item in inputs.raw_files]
        per_file_payload = []
        for index, (item, counters) in enumerate(zip(inputs.raw_files, per_file, strict=True)):
            per_file_payload.append(
                {
                    "source_file": item.path.name,
                    "expected_rows": item.rows,
                    **_scope_payload(
                        counters,
                        source_per_file[index],
                        feature_per_file[index],
                        tuple_per_file[index],
                    ),
                }
            )
        payload: dict[str, Any] = {
            "completed": completed,
            "creates_assignments": False,
            "run_scope": scope,
            "schema_version": PREFLIGHT_SCHEMA_VERSION,
            "source_dataset": "unsw_nb15",
            "manifest": {
                "name": "unsw_nb15",
                "sha256": inputs.manifest_digest,
                "verified": True,
                "version": inputs.manifest_version,
            },
            "registered_inputs": {
                "feature_metadata": {
                    "expected_rows": inputs.feature_metadata.rows,
                    "sha256": inputs.feature_metadata.sha256,
                    "source_file": inputs.feature_metadata.path.name,
                },
                "raw_files": [
                    {
                        "expected_rows": item.rows,
                        "sha256": item.sha256,
                        "source_file": item.path.name,
                    }
                    for item in inputs.raw_files
                ],
            },
            "feature_contract": {
                "name": FEATURE_CONTRACT_NAME,
                "ordered_features": list(NETWORK_BEHAVIOR_V1_FEATURE_NAMES),
            },
            "configuration": {
                "batch_size": config.batch_size,
                "disk_budget_bytes": config.disk_budget_bytes,
                "max_rows_per_file": config.max_rows_per_file,
                "minimum_free_bytes": config.minimum_free_bytes,
                "sqlite_cache_mib": config.sqlite_cache_mib,
            },
            "checks": {
                "accounting_reconciled": overall.total == overall.accepted + overall.rejected,
                "diagnostics_succeeded": True,
                "feature_metadata_verified": True,
                "inputs_fully_exhausted": completed,
                "manifest_verified": True,
                "working_disk_budget_respected": True,
            },
            "fingerprints": {
                "model_features": (
                    "SHA-256 over named, typed, exact network_behavior_v1 values in contract order; "
                    "labels and non-contract fields excluded"
                ),
                "source_record": (
                    "SHA-256 over length-prefixed UTF-8 names and exact CSV-decoded values in "
                    "registered metadata order; injected flow_id excluded"
                ),
            },
            "interval_semantics": {
                "canonical_interval": "adapter UTC start plus duration-derived end",
                "overlap_identity": (
                    "direction-normalized (IP, port) endpoint pair plus normalized protocol"
                ),
                "overlap_rule": "same identity with closed canonical intervals that overlap or touch",
                "raw_comparison": (
                    "Ltime minus Stime compared with dur exactly and within a one-second "
                    "quantization diagnostic; values are never repaired"
                ),
                "tuple_overlap_assessed": True,
            },
            "limitations": [
                "diagnostics do not create groups, dispositions, cutoffs, or split assignments",
                "repeated feature vectors are potential leakage links, not proven source events",
                "label conflicts are reported without resolution or relabeling",
                "near duplicates and independent capture/session provenance are not assessed",
            ],
            "overall": _scope_payload(overall, source_overall, feature_overall, tuple_overall),
            "per_file": per_file_payload,
        }
        report_name = "preflight_report.json" if completed else "preflight_partial.json"
        report_path = run_directory / report_name
        _write_report(report_path, connection, payload, input_names)
        _guard_disk_budget(run_directory, config)
        return PreflightRunResult(
            completed=completed,
            report_path=report_path,
            database_path=database_path,
            total=overall.total,
            accepted=overall.accepted,
            rejected=overall.rejected,
        )
    except UnswSplitPreflightError as exc:
        (run_directory / "preflight_report.json").unlink(missing_ok=True)
        (run_directory / "preflight_partial.json").unlink(missing_ok=True)
        (run_directory / "preflight_report.json.tmp").unlink(missing_ok=True)
        (run_directory / "preflight_partial.json.tmp").unlink(missing_ok=True)
        _write_failure_report(run_directory, scope, exc.code)
        raise
    except Exception:
        (run_directory / "preflight_report.json").unlink(missing_ok=True)
        (run_directory / "preflight_partial.json").unlink(missing_ok=True)
        (run_directory / "preflight_report.json.tmp").unlink(missing_ok=True)
        (run_directory / "preflight_partial.json.tmp").unlink(missing_ok=True)
        _write_failure_report(run_directory, scope, "internal_preflight_failure")
        raise
    finally:
        if connection is not None:
            connection.close()
