"""Deterministic, disk-backed UNSW development split and assignment audit."""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import re
import shutil
import sqlite3
import struct
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threatfusion.datasets.split_policy import (
    PHASE0_SPLIT_POLICY,
    SplitAssignment,
    SplitName,
)
from threatfusion.datasets.unsw_raw import UnswRawReader
from threatfusion.datasets.unsw_split_preflight import (
    PREFLIGHT_SCHEMA_VERSION,
    RegisteredUnswInputs,
    classify_raw_interval,
    source_record_fingerprint,
    verify_registered_unsw_inputs,
)
from threatfusion.utils.checksum import sha256_file

ASSIGNMENT_SCHEMA_VERSION = "unsw_development_split_v1"
ASSIGNMENT_SEED = "threatfusion-unsw-dev-split-v1"
DEFAULT_ARTIFACT_BUDGET_BYTES = 8 * 1024**3
DEFAULT_MINIMUM_FREE_BYTES = 2 * 1024**3
DEFAULT_BATCH_SIZE = 10_000
DEFAULT_SQLITE_CACHE_MIB = 256
QUERY_BATCH_SIZE = 2_048
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def _utc_microseconds(value: datetime) -> int:
    return int(value.timestamp()) * 1_000_000 + value.microsecond


DEVELOPMENT_START_US = _utc_microseconds(datetime(2015, 1, 22, tzinfo=UTC))
DEVELOPMENT_END_US = _utc_microseconds(datetime(2015, 1, 24, tzinfo=UTC))
TEST_START_US = _utc_microseconds(datetime(2015, 2, 18, tzinfo=UTC))
TEST_END_US = _utc_microseconds(datetime(2015, 2, 19, tzinfo=UTC))

TIMING_CATEGORY_CODES: dict[str, int] = {
    "exact": 0,
    "within_one_second_quantization": 1,
    "unexplained_over_one_second": 2,
    "ltime_before_stime": 3,
    "unavailable_parse_failure": 4,
}
TIMING_CATEGORY_NAMES = {value: key for key, value in TIMING_CATEGORY_CODES.items()}

QUARANTINE_UNEXPLAINED_TIMING = 1
QUARANTINE_INVALID_TIMING = 2
QUARANTINE_DEVELOPMENT_TEST_GROUP = 4
QUARANTINE_PERIOD_INTERVAL = 8
QUARANTINE_OUTSIDE_PERIOD = 16


class UnswDevelopmentSplitError(RuntimeError):
    """A sanitized assignment failure safe for report and CLI output."""

    def __init__(self, code: str, details: dict[str, Any] | None = None) -> None:
        self.code = code
        self.details = details or {}
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class DevelopmentSplitConfig:
    """Frozen policy plus bounded-resource settings for one assignment run."""

    seed: str = ASSIGNMENT_SEED
    batch_size: int = DEFAULT_BATCH_SIZE
    sqlite_cache_mib: int = DEFAULT_SQLITE_CACHE_MIB
    artifact_budget_bytes: int = DEFAULT_ARTIFACT_BUDGET_BYTES
    minimum_free_bytes: int = DEFAULT_MINIMUM_FREE_BYTES
    max_rows_per_file: int | None = None

    def __post_init__(self) -> None:
        if self.seed != ASSIGNMENT_SEED:
            raise ValueError("the frozen assignment seed cannot be changed")
        if self.batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if self.sqlite_cache_mib <= 0:
            raise ValueError("sqlite_cache_mib must be positive")
        if self.artifact_budget_bytes <= 0:
            raise ValueError("artifact_budget_bytes must be positive")
        if self.minimum_free_bytes < 0:
            raise ValueError("minimum_free_bytes must not be negative")
        if self.max_rows_per_file is not None and self.max_rows_per_file <= 0:
            raise ValueError("max_rows_per_file must be positive when set")


@dataclass(frozen=True, slots=True)
class DevelopmentSplitResult:
    """Safe result metadata for one completed or explicitly partial run."""

    completed: bool
    report_path: Path
    assignment_path: Path
    database_path: Path
    total_rows: int


@dataclass(slots=True)
class GroupAccumulator:
    """Fixed-cardinality state retained for only the current leakage group."""

    anchor: int
    total: int = 0
    benign: int = 0
    attack: int = 0
    development_starts: int = 0
    test_starts: int = 0
    outside_starts: int = 0
    period_interval_failures: int = 0
    unexplained_timing: int = 0
    invalid_timing: int = 0

    def include(self, start_us: int, end_us: int, label: int, timing_category: int) -> None:
        """Include one accepted record without using its label for group identity or hashing."""
        self.total += 1
        if label == 0:
            self.benign += 1
        else:
            self.attack += 1
        if DEVELOPMENT_START_US <= start_us < DEVELOPMENT_END_US:
            self.development_starts += 1
            if end_us > DEVELOPMENT_END_US:
                self.period_interval_failures += 1
        elif TEST_START_US <= start_us < TEST_END_US:
            self.test_starts += 1
            if end_us > TEST_END_US:
                self.period_interval_failures += 1
        else:
            self.outside_starts += 1
        if timing_category == TIMING_CATEGORY_CODES["unexplained_over_one_second"]:
            self.unexplained_timing += 1
        elif timing_category not in {
            TIMING_CATEGORY_CODES["exact"],
            TIMING_CATEGORY_CODES["within_one_second_quantization"],
        }:
            self.invalid_timing += 1


@dataclass(slots=True)
class FeatureAudit:
    """Aggregate model-vector collision evidence after assignment."""

    repeated_groups: int = 0
    repeated_rows: int = 0
    excess_rows: int = 0
    conflicting_label_groups: int = 0
    conflicting_label_rows: int = 0
    shared_assigned_split_groups: int = 0
    pairwise_shared_groups: Counter[str] = field(default_factory=Counter)


class DiskUnionFind:
    """SQLite-backed union-find whose canonical root is the smallest record ordinal."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def find(self, record_id: int) -> int:
        """Find and iteratively compress one parent chain with constant Python memory."""
        root = record_id
        while True:
            row = self.connection.execute(
                "SELECT parent FROM groups WHERE record_id = ?", (root,)
            ).fetchone()
            if row is None:
                raise UnswDevelopmentSplitError("group_record_missing")
            parent = int(row[0])
            if parent == root:
                break
            root = parent
        current = record_id
        while current != root:
            parent = int(
                self.connection.execute(
                    "SELECT parent FROM groups WHERE record_id = ?", (current,)
                ).fetchone()[0]
            )
            self.connection.execute(
                "UPDATE groups SET parent = ? WHERE record_id = ?", (root, current)
            )
            current = parent
        return root

    def union(self, first: int, second: int) -> None:
        """Join two components without using labels or model features."""
        first_root = self.find(first)
        second_root = self.find(second)
        if first_root == second_root:
            return
        smaller, larger = sorted((first_root, second_root))
        self.connection.execute(
            "UPDATE groups SET parent = ? WHERE record_id = ?", (smaller, larger)
        )


def deterministic_group_identifier(anchor: int) -> bytes:
    """Derive a stable internal group identifier from label-free source provenance."""
    if anchor <= 0:
        raise ValueError("group anchor must be positive")
    digest = hashlib.sha256(b"threatfusion:unsw-leakage-group:v1\0")
    digest.update(anchor.to_bytes(8, byteorder="big", signed=False))
    return digest.digest()


def deterministic_development_split(group_identifier: bytes, seed: str = ASSIGNMENT_SEED) -> str:
    """Assign approximately one fifth of groups to validation with the frozen seed."""
    if seed != ASSIGNMENT_SEED:
        raise ValueError("the frozen assignment seed cannot be changed")
    seed_bytes = seed.encode("utf-8")
    digest = hashlib.sha256(b"threatfusion:unsw-dev-group-assignment:v1\0")
    digest.update(struct.pack(">I", len(seed_bytes)))
    digest.update(seed_bytes)
    digest.update(group_identifier)
    score = int.from_bytes(digest.digest()[:8], byteorder="big", signed=False)
    return "validation" if score < (2**64 // 5) else "train"


def validate_policy_assignment_batch(
    source_dataset: str, assignments: Sequence[tuple[bytes, str]]
) -> None:
    """Apply canonical source-role validation to one bounded group batch."""
    canonical = tuple(
        SplitAssignment(
            source_dataset=source_dataset,
            source_group=group_identifier.hex(),
            split=SplitName(disposition),
        )
        for group_identifier, disposition in assignments
    )
    PHASE0_SPLIT_POLICY.validate_assignments(canonical)


def _artifact_size(run_directory: Path) -> int:
    return sum(path.stat().st_size for path in run_directory.iterdir() if path.is_file())


def _guard_budget(run_directory: Path, config: DevelopmentSplitConfig) -> None:
    if _artifact_size(run_directory) > config.artifact_budget_bytes:
        raise UnswDevelopmentSplitError("artifact_budget_exceeded")
    if shutil.disk_usage(run_directory).free < config.minimum_free_bytes:
        raise UnswDevelopmentSplitError("minimum_free_space_violated")


def _safe_artifact_root(project_root: Path, artifact_root: Path) -> Path:
    resolved = artifact_root.resolve()
    if not resolved.is_relative_to((project_root / "data/interim").resolve()):
        raise UnswDevelopmentSplitError("artifact_root_must_be_under_data_interim")
    return resolved


def _load_verified_preflight_report(
    report_path: Path, inputs: RegisteredUnswInputs
) -> dict[str, Any]:
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UnswDevelopmentSplitError("preflight_report_unreadable") from exc
    required_checks = {
        "accounting_reconciled",
        "diagnostics_succeeded",
        "feature_metadata_verified",
        "inputs_fully_exhausted",
        "manifest_verified",
        "working_disk_budget_respected",
    }
    checks = report.get("checks")
    if (
        report.get("schema_version") != PREFLIGHT_SCHEMA_VERSION
        or report.get("completed") is not True
        or report.get("run_scope") != "full"
        or report.get("creates_assignments") is not False
        or not isinstance(checks, dict)
        or any(checks.get(name) is not True for name in required_checks)
        or report.get("manifest", {}).get("sha256") != inputs.manifest_digest
    ):
        raise UnswDevelopmentSplitError("preflight_evidence_not_complete_or_consistent")
    return report


def _connect_working_database(
    database_path: Path, preflight_database: Path, config: DevelopmentSplitConfig
) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path, isolation_level=None, uri=True)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute(f"PRAGMA cache_size={-(config.sqlite_cache_mib * 1024)}")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute(
        "ATTACH DATABASE ? AS preflight", (f"file:{preflight_database.resolve()}?mode=ro",)
    )
    connection.executescript("""
        CREATE TABLE timing (
            record_id INTEGER PRIMARY KEY,
            category INTEGER NOT NULL
        );
        CREATE TABLE groups (
            record_id INTEGER PRIMARY KEY,
            parent INTEGER NOT NULL
        );
        CREATE TABLE group_decisions (
            anchor INTEGER PRIMARY KEY,
            group_identifier BLOB NOT NULL UNIQUE,
            disposition TEXT NOT NULL,
            primary_reason TEXT,
            quarantine_mask INTEGER NOT NULL,
            total_count INTEGER NOT NULL,
            benign_count INTEGER NOT NULL,
            attack_count INTEGER NOT NULL
        );
        """)
    return connection


def _verify_preflight_database(connection: sqlite3.Connection, report: dict[str, Any]) -> None:
    columns = {str(row[1]) for row in connection.execute("PRAGMA preflight.table_info(records)")}
    required = {
        "file_index",
        "source_fp",
        "accepted",
        "feature_fp",
        "tuple_fp",
        "start_us",
        "end_us",
        "label",
    }
    if not required <= columns:
        raise UnswDevelopmentSplitError("preflight_database_schema_mismatch")
    total, accepted, rejected = connection.execute(
        "SELECT COUNT(*), SUM(accepted), SUM(1-accepted) FROM preflight.records"
    ).fetchone()
    overall = report.get("overall", {})
    if (
        int(total) != overall.get("total_input_rows")
        or int(accepted) != overall.get("accepted_count")
        or int(rejected) != overall.get("rejected_count")
    ):
        raise UnswDevelopmentSplitError("preflight_database_count_mismatch")


def _take(rows: Iterator[dict[str, str]], limit: int | None) -> Iterator[dict[str, str]]:
    if limit is None:
        yield from rows
        return
    for _ in range(limit):
        try:
            yield next(rows)
        except StopIteration:
            return


def _stream_timing_evidence(
    connection: sqlite3.Connection,
    project_root: Path,
    inputs: RegisteredUnswInputs,
    config: DevelopmentSplitConfig,
    run_directory: Path,
    progress: Callable[[str, int], None] | None,
) -> tuple[int, Counter[str]]:
    batch: list[tuple[int, int]] = []
    total = 0
    categories: Counter[str] = Counter()
    row_offset = 0
    for file_index, item in enumerate(inputs.raw_files):
        expected_rows = int(item.rows or 0)
        selected_rows = (
            expected_rows
            if config.max_rows_per_file is None
            else min(expected_rows, config.max_rows_per_file)
        )
        first_record_id = row_offset + 1
        last_record_id = row_offset + selected_rows
        indexed = connection.execute(
            """
            SELECT rowid, file_index, source_fp
            FROM preflight.records
            WHERE rowid BETWEEN ? AND ?
            ORDER BY rowid
            """,
            (first_record_id, last_record_id),
        )
        raw_path = (project_root / item.path).resolve()
        rows = _take(
            iter(UnswRawReader(inputs.feature_names, (raw_path,))), config.max_rows_per_file
        )
        seen = 0
        for row in rows:
            indexed_row = indexed.fetchone()
            if indexed_row is None:
                raise UnswDevelopmentSplitError("preflight_record_alignment_failed")
            record_id, indexed_file, indexed_source_fp = indexed_row
            if int(indexed_file) != file_index or source_record_fingerprint(
                row, inputs.feature_names
            ) != bytes(indexed_source_fp):
                raise UnswDevelopmentSplitError("preflight_record_alignment_failed")
            category, _, _ = classify_raw_interval(row)
            try:
                category_code = TIMING_CATEGORY_CODES[category]
            except KeyError as exc:
                raise UnswDevelopmentSplitError("unknown_timing_category") from exc
            batch.append((int(record_id), category_code))
            categories[category] += 1
            total += 1
            seen += 1
            if len(batch) >= config.batch_size:
                connection.execute("BEGIN")
                connection.executemany("INSERT INTO timing VALUES (?, ?)", batch)
                connection.execute("COMMIT")
                batch.clear()
                _guard_budget(run_directory, config)
                if progress is not None:
                    progress("timing", total)
        if indexed.fetchone() is not None or seen != selected_rows:
            raise UnswDevelopmentSplitError("preflight_record_alignment_failed")
        row_offset += expected_rows
    if batch:
        connection.execute("BEGIN")
        connection.executemany("INSERT INTO timing VALUES (?, ?)", batch)
        connection.execute("COMMIT")
    _guard_budget(run_directory, config)
    return total, categories


def _initialize_groups(
    connection: sqlite3.Connection, config: DevelopmentSplitConfig, run_directory: Path
) -> int:
    minimum, maximum, count = connection.execute(
        "SELECT MIN(record_id), MAX(record_id), COUNT(*) FROM timing"
    ).fetchone()
    if count == 0:
        return 0
    inserted = 0
    lower = int(minimum)
    maximum = int(maximum)
    while lower <= maximum:
        upper = lower + config.batch_size - 1
        connection.execute("BEGIN")
        connection.execute(
            """
            INSERT INTO groups(record_id, parent)
            SELECT r.rowid, r.rowid
            FROM preflight.records AS r
            JOIN timing AS t ON t.record_id = r.rowid
            WHERE r.accepted = 1 AND r.rowid BETWEEN ? AND ?
            """,
            (lower, upper),
        )
        inserted += int(connection.execute("SELECT changes()").fetchone()[0])
        connection.execute("COMMIT")
        lower = upper + 1
        _guard_budget(run_directory, config)
    return inserted


def _union_exact_source_duplicates(
    connection: sqlite3.Connection,
    union_find: DiskUnionFind,
    config: DevelopmentSplitConfig,
) -> int:
    cursor = connection.execute("""
        SELECT r.source_fp, r.rowid
        FROM preflight.records AS r INDEXED BY records_source_idx
        JOIN groups AS g ON g.record_id = r.rowid
        WHERE r.accepted = 1
        ORDER BY r.source_fp, r.file_index, r.rowid
        """)
    current: bytes | None = None
    first_record = 0
    edges = 0
    connection.execute("BEGIN")
    for fingerprint, record_id in _batched_rows(cursor):
        fingerprint = bytes(fingerprint)
        record_id = int(record_id)
        if current != fingerprint:
            current = fingerprint
            first_record = record_id
            continue
        union_find.union(first_record, record_id)
        edges += 1
        if edges % config.batch_size == 0:
            connection.execute("COMMIT")
            connection.execute("BEGIN")
    connection.execute("COMMIT")
    return edges


def _union_overlap_components(
    connection: sqlite3.Connection,
    union_find: DiskUnionFind,
    config: DevelopmentSplitConfig,
) -> int:
    cursor = connection.execute("""
        SELECT r.tuple_fp, r.start_us, r.end_us, r.rowid
        FROM preflight.records AS r INDEXED BY records_tuple_idx
        JOIN groups AS g ON g.record_id = r.rowid
        WHERE r.accepted = 1
        ORDER BY r.tuple_fp, r.start_us, r.end_us, r.file_index, r.rowid
        """)
    current: bytes | None = None
    component_anchor = 0
    component_end = 0
    edges = 0
    connection.execute("BEGIN")
    for fingerprint, start_us, end_us, record_id in _batched_rows(cursor):
        fingerprint = bytes(fingerprint)
        start_us = int(start_us)
        end_us = int(end_us)
        record_id = int(record_id)
        if current != fingerprint or start_us > component_end:
            current = fingerprint
            component_anchor = record_id
            component_end = end_us
            continue
        union_find.union(component_anchor, record_id)
        component_end = max(component_end, end_us)
        edges += 1
        if edges % config.batch_size == 0:
            connection.execute("COMMIT")
            connection.execute("BEGIN")
    connection.execute("COMMIT")
    return edges


def _batched_rows(cursor: sqlite3.Cursor) -> Iterator[tuple[Any, ...]]:
    while batch := cursor.fetchmany(QUERY_BATCH_SIZE):
        yield from batch


def _compress_groups(
    connection: sqlite3.Connection,
    union_find: DiskUnionFind,
    config: DevelopmentSplitConfig,
    run_directory: Path,
    progress: Callable[[str, int], None] | None,
) -> int:
    cursor = connection.execute("SELECT record_id FROM groups ORDER BY record_id")
    processed = 0
    connection.execute("BEGIN")
    for (record_id,) in _batched_rows(cursor):
        record_id = int(record_id)
        root = union_find.find(record_id)
        connection.execute("UPDATE groups SET parent = ? WHERE record_id = ?", (root, record_id))
        processed += 1
        if processed % config.batch_size == 0:
            connection.execute("COMMIT")
            _guard_budget(run_directory, config)
            if progress is not None:
                progress("compress", processed)
            connection.execute("BEGIN")
    connection.execute("COMMIT")
    connection.execute("CREATE INDEX groups_parent_idx ON groups(parent, record_id)")
    _guard_budget(run_directory, config)
    return processed


def _quarantine_mask(group: GroupAccumulator) -> int:
    mask = 0
    if group.unexplained_timing:
        mask |= QUARANTINE_UNEXPLAINED_TIMING
    if group.invalid_timing:
        mask |= QUARANTINE_INVALID_TIMING
    if group.development_starts and group.test_starts:
        mask |= QUARANTINE_DEVELOPMENT_TEST_GROUP
    if group.period_interval_failures:
        mask |= QUARANTINE_PERIOD_INTERVAL
    if group.outside_starts:
        mask |= QUARANTINE_OUTSIDE_PERIOD
    return mask


def _primary_quarantine_reason(mask: int) -> str | None:
    if mask & QUARANTINE_DEVELOPMENT_TEST_GROUP:
        return "development_test_group_overlap"
    if mask & QUARANTINE_UNEXPLAINED_TIMING:
        return "unexplained_timing_group"
    if mask & QUARANTINE_INVALID_TIMING:
        return "invalid_timing_group"
    if mask & QUARANTINE_PERIOD_INTERVAL:
        return "period_boundary_interval_group"
    if mask & QUARANTINE_OUTSIDE_PERIOD:
        return "outside_policy_period_group"
    return None


def _group_decision(
    group: GroupAccumulator, config: DevelopmentSplitConfig
) -> tuple[bytes, str, int, str | None]:
    group_identifier = deterministic_group_identifier(group.anchor)
    mask = _quarantine_mask(group)
    if mask:
        disposition = "quarantine"
    elif group.development_starts:
        disposition = deterministic_development_split(group_identifier, config.seed)
    elif group.test_starts:
        disposition = "test"
    else:
        disposition = "quarantine"
        mask |= QUARANTINE_OUTSIDE_PERIOD
    return group_identifier, disposition, mask, _primary_quarantine_reason(mask)


def _build_group_decisions(
    connection: sqlite3.Connection,
    config: DevelopmentSplitConfig,
    run_directory: Path,
) -> int:
    cursor = connection.execute("""
        SELECT g.parent, r.start_us, r.end_us, r.label, t.category
        FROM groups AS g INDEXED BY groups_parent_idx
        JOIN preflight.records AS r ON r.rowid = g.record_id
        JOIN timing AS t ON t.record_id = g.record_id
        ORDER BY g.parent, g.record_id
        """)
    current: GroupAccumulator | None = None
    decision_batch: list[tuple[Any, ...]] = []
    policy_batch: list[tuple[bytes, str]] = []
    group_count = 0

    def finish() -> None:
        nonlocal group_count
        if current is None:
            return
        identifier, disposition, mask, reason = _group_decision(current, config)
        decision_batch.append(
            (
                current.anchor,
                identifier,
                disposition,
                reason,
                mask,
                current.total,
                current.benign,
                current.attack,
            )
        )
        if disposition in {"train", "validation", "test"}:
            policy_batch.append((identifier, disposition))
        group_count += 1

    def flush() -> None:
        if not decision_batch:
            return
        validate_policy_assignment_batch("unsw_nb15", policy_batch)
        connection.execute("BEGIN")
        connection.executemany(
            "INSERT INTO group_decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?)", decision_batch
        )
        connection.execute("COMMIT")
        decision_batch.clear()
        policy_batch.clear()
        _guard_budget(run_directory, config)

    for anchor, start_us, end_us, label, timing_category in _batched_rows(cursor):
        anchor = int(anchor)
        if current is None or current.anchor != anchor:
            finish()
            if len(decision_batch) >= config.batch_size:
                flush()
            current = GroupAccumulator(anchor=anchor)
        current.include(int(start_us), int(end_us), int(label), int(timing_category))
    finish()
    flush()
    return group_count


def _split_counts(
    connection: sqlite3.Connection, rejected_count: int
) -> dict[str, dict[str, int | None]]:
    counts: dict[str, dict[str, int | None]] = {}
    for disposition, groups, total, benign, attack in connection.execute("""
        SELECT disposition, COUNT(*), SUM(total_count), SUM(benign_count), SUM(attack_count)
        FROM group_decisions
        GROUP BY disposition
        ORDER BY disposition
        """):
        counts[str(disposition)] = {
            "group_count": int(groups),
            "total_count": int(total),
            "benign_count": int(benign),
            "attack_count": int(attack),
        }
    counts["rejected"] = {
        "group_count": None,
        "total_count": rejected_count,
        "benign_count": None,
        "attack_count": None,
    }
    for disposition in ("train", "validation", "test", "quarantine"):
        counts.setdefault(
            disposition,
            {"group_count": 0, "total_count": 0, "benign_count": 0, "attack_count": 0},
        )
    return counts


def _acceptance_checks(
    connection: sqlite3.Connection,
    timing_rows: int,
    accepted_rows: int,
    split_counts: dict[str, dict[str, int | None]],
) -> dict[str, bool]:
    decided_rows = sum(
        int(split_counts[name]["total_count"] or 0)
        for name in ("train", "validation", "test", "quarantine")
    )
    grouped_rows = int(connection.execute("SELECT COUNT(*) FROM groups").fetchone()[0])
    decisionless = int(connection.execute("""
            SELECT COUNT(*)
            FROM groups AS g
            LEFT JOIN group_decisions AS d ON d.anchor = g.parent
            WHERE d.anchor IS NULL
            """).fetchone()[0])
    cross_split_groups = int(connection.execute("""
            SELECT COUNT(*)
            FROM (
                SELECT g.parent
                FROM groups AS g
                JOIN group_decisions AS d ON d.anchor = g.parent
                WHERE d.disposition IN ('train', 'validation', 'test')
                GROUP BY g.parent
                HAVING COUNT(DISTINCT d.disposition) > 1
            )
            """).fetchone()[0])
    return {
        "all_selected_rows_accounted_once": decided_rows
        + int(split_counts["rejected"]["total_count"] or 0)
        == timing_rows,
        "all_accepted_rows_grouped": grouped_rows == accepted_rows,
        "all_groups_have_one_decision": decisionless == 0,
        "enforced_group_cross_split_count_zero": cross_split_groups == 0,
        "train_has_benign_and_attack": int(split_counts["train"]["benign_count"] or 0) > 0
        and int(split_counts["train"]["attack_count"] or 0) > 0,
        "validation_has_benign_and_attack": int(split_counts["validation"]["benign_count"] or 0) > 0
        and int(split_counts["validation"]["attack_count"] or 0) > 0,
    }


def _quarantine_impacts(connection: sqlite3.Connection) -> dict[str, dict[str, int]]:
    reasons = {
        "unexplained_timing": QUARANTINE_UNEXPLAINED_TIMING,
        "invalid_timing": QUARANTINE_INVALID_TIMING,
        "development_test_group_overlap": QUARANTINE_DEVELOPMENT_TEST_GROUP,
        "period_boundary_interval": QUARANTINE_PERIOD_INTERVAL,
        "outside_policy_period": QUARANTINE_OUTSIDE_PERIOD,
    }
    impacts: dict[str, dict[str, int]] = {}
    for name, bit in reasons.items():
        groups, total, benign, attack = connection.execute(
            """
            SELECT COUNT(*), COALESCE(SUM(total_count), 0),
                   COALESCE(SUM(benign_count), 0), COALESCE(SUM(attack_count), 0)
            FROM group_decisions
            WHERE quarantine_mask & ? != 0
            """,
            (bit,),
        ).fetchone()
        impacts[name] = {
            "group_count": int(groups),
            "total_count": int(total),
            "benign_count": int(benign),
            "attack_count": int(attack),
        }
    return impacts


def _feature_audit(connection: sqlite3.Connection) -> FeatureAudit:
    cursor = connection.execute("""
        SELECT r.feature_fp, r.label, d.disposition
        FROM preflight.records AS r INDEXED BY records_feature_idx
        JOIN groups AS g ON g.record_id = r.rowid
        JOIN group_decisions AS d ON d.anchor = g.parent
        WHERE r.accepted = 1
        ORDER BY r.feature_fp, r.file_index, r.label, r.rowid
        """)
    audit = FeatureAudit()
    current: bytes | None = None
    size = 0
    labels: set[int] = set()
    dispositions: set[str] = set()

    def finish() -> None:
        if current is None:
            return
        if size > 1:
            audit.repeated_groups += 1
            audit.repeated_rows += size
            audit.excess_rows += size - 1
        if len(labels) > 1:
            audit.conflicting_label_groups += 1
            audit.conflicting_label_rows += size
        assigned = sorted(dispositions & {"train", "validation", "test"})
        if len(assigned) > 1:
            audit.shared_assigned_split_groups += 1
            for first_index, first in enumerate(assigned):
                for second in assigned[first_index + 1 :]:
                    audit.pairwise_shared_groups[f"{first}__{second}"] += 1

    for fingerprint, label, disposition in _batched_rows(cursor):
        fingerprint = bytes(fingerprint)
        if current is not None and current != fingerprint:
            finish()
            size = 0
            labels.clear()
            dispositions.clear()
        current = fingerprint
        size += 1
        labels.add(int(label))
        dispositions.add(str(disposition))
    finish()
    return audit


def _write_assignment_artifact(
    connection: sqlite3.Connection, path: Path, expected_rows: int
) -> tuple[int, str]:
    temporary = path.with_suffix(path.suffix + ".tmp")
    count = 0
    previous_record_id = 0
    with temporary.open("wb") as raw_file:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_file, mtime=0) as compressed:
            with io.TextIOWrapper(compressed, encoding="utf-8", newline="") as text_file:
                writer = csv.writer(text_file, lineterminator="\n")
                writer.writerow(("record_id", "group_id", "disposition", "reason"))
                cursor = connection.execute("""
                    SELECT t.record_id, r.accepted, d.group_identifier,
                           d.disposition, d.primary_reason
                    FROM timing AS t
                    JOIN preflight.records AS r ON r.rowid = t.record_id
                    LEFT JOIN groups AS g ON g.record_id = t.record_id
                    LEFT JOIN group_decisions AS d ON d.anchor = g.parent
                    ORDER BY t.record_id
                    """)
                for record_id, accepted, identifier, disposition, reason in _batched_rows(cursor):
                    record_id = int(record_id)
                    if record_id <= previous_record_id:
                        raise UnswDevelopmentSplitError("assignment_record_order_invalid")
                    previous_record_id = record_id
                    if int(accepted) == 1:
                        if identifier is None or disposition is None:
                            raise UnswDevelopmentSplitError("eligible_assignment_missing")
                        writer.writerow(
                            (
                                record_id,
                                bytes(identifier).hex(),
                                str(disposition),
                                "" if reason is None else str(reason),
                            )
                        )
                    else:
                        writer.writerow((record_id, "", "rejected", "source_rejected"))
                    count += 1
    if count != expected_rows:
        temporary.unlink(missing_ok=True)
        raise UnswDevelopmentSplitError("assignment_row_count_mismatch")
    temporary.replace(path)
    return count, sha256_file(path)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _failure_report(run_directory: Path, scope: str, error: UnswDevelopmentSplitError) -> None:
    payload: dict[str, Any] = {
        "completed": False,
        "creates_final_assignments": False,
        "failure_code": error.code,
        "run_scope": scope,
        "schema_version": ASSIGNMENT_SCHEMA_VERSION,
    }
    payload.update(error.details)
    _write_json(run_directory / "assignment_failure.json", payload)


def run_unsw_development_split(
    project_root: Path,
    manifest_path: Path,
    preflight_database: Path,
    preflight_report: Path,
    artifact_root: Path,
    run_id: str,
    config: DevelopmentSplitConfig = DevelopmentSplitConfig(),
    progress: Callable[[str, int], None] | None = None,
) -> DevelopmentSplitResult:
    """Create and audit the frozen grouped-development/chronological-test assignment."""
    if not _RUN_ID.fullmatch(run_id):
        raise UnswDevelopmentSplitError("invalid_run_id")
    project_root = project_root.resolve()
    artifact_root = _safe_artifact_root(project_root, artifact_root)
    artifact_root.mkdir(parents=True, exist_ok=True)
    run_directory = artifact_root / run_id
    try:
        run_directory.mkdir()
    except FileExistsError as exc:
        raise UnswDevelopmentSplitError("run_directory_already_exists") from exc
    scope = "partial" if config.max_rows_per_file is not None else "full"
    database_path = run_directory / "assignment_work.sqlite3"
    assignment_name = "assignments_partial.csv.gz" if scope == "partial" else "assignments.csv.gz"
    assignment_path = run_directory / assignment_name
    connection: sqlite3.Connection | None = None
    try:
        if shutil.disk_usage(run_directory).free < (
            config.artifact_budget_bytes + config.minimum_free_bytes
        ):
            raise UnswDevelopmentSplitError("insufficient_free_space_for_artifact_budget")
        inputs = verify_registered_unsw_inputs(project_root, manifest_path.resolve())
        preflight_payload = _load_verified_preflight_report(preflight_report.resolve(), inputs)
        connection = _connect_working_database(database_path, preflight_database.resolve(), config)
        _verify_preflight_database(connection, preflight_payload)
        timing_rows, timing_categories = _stream_timing_evidence(
            connection,
            project_root,
            inputs,
            config,
            run_directory,
            progress,
        )
        accepted_rows = _initialize_groups(connection, config, run_directory)
        rejected_rows = timing_rows - accepted_rows
        union_find = DiskUnionFind(connection)
        source_edges = _union_exact_source_duplicates(connection, union_find, config)
        overlap_edges = _union_overlap_components(connection, union_find, config)
        compressed_rows = _compress_groups(connection, union_find, config, run_directory, progress)
        if compressed_rows != accepted_rows:
            raise UnswDevelopmentSplitError("group_compression_count_mismatch")
        group_count = _build_group_decisions(connection, config, run_directory)
        split_counts = _split_counts(connection, rejected_rows)
        checks = _acceptance_checks(connection, timing_rows, accepted_rows, split_counts)
        if scope == "full" and not all(checks.values()):
            raise UnswDevelopmentSplitError(
                "assignment_acceptance_failed",
                {"acceptance_checks": checks, "split_counts": split_counts},
            )
        feature_audit = _feature_audit(connection)
        artifact_rows, artifact_sha256 = _write_assignment_artifact(
            connection, assignment_path, timing_rows
        )
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        _guard_budget(run_directory, config)
        completed = scope == "full"
        report_payload: dict[str, Any] = {
            "completed": completed,
            "creates_final_assignments": completed,
            "global_training_ready": False,
            "network_split_status": "verified" if completed else "partial",
            "run_scope": scope,
            "schema_version": ASSIGNMENT_SCHEMA_VERSION,
            "source_dataset": "unsw_nb15",
            "policy": {
                "development_start_inclusive": "2015-01-22T00:00:00+00:00",
                "development_end_exclusive": "2015-01-24T00:00:00+00:00",
                "test_start_inclusive": "2015-02-18T00:00:00+00:00",
                "test_end_exclusive": "2015-02-19T00:00:00+00:00",
                "development_assignment": (
                    "validation iff first SHA-256 score uint64 < floor(2^64/5); train otherwise"
                ),
                "group_percentage_target": {"train": 80, "validation": 20},
                "seed": config.seed,
                "validation_kind": "grouped_development_validation",
                "test_kind": "later_period_chronological_test",
                "cic_role": "external_evaluation_only",
            },
            "grouping": {
                "relationships": [
                    "exact ordered 49-field source fingerprint excluding injected flow_id",
                    "connected closed-interval overlap for direction-normalized endpoint-pair/protocol",
                ],
                "transitive": True,
                "identical_model_vectors_are_grouping_relationships": False,
                "group_identifier_uses_labels": False,
                "source_duplicate_union_edge_count": source_edges,
                "overlap_union_edge_count": overlap_edges,
                "final_group_count": group_count,
            },
            "timing_evidence": {
                "category_counts": dict(sorted(timing_categories.items())),
                "one_second_tolerance_status": "working_assumption_not_proven_precision",
                "unexplained_values_repaired": False,
            },
            "split_counts": split_counts,
            "quarantine_reason_impacts": _quarantine_impacts(connection),
            "assignment_audit": {
                **checks,
                "canonical_split_policy_validated_in_bounded_batches": True,
                "artifact_row_count": artifact_rows,
                "artifact_sha256": artifact_sha256,
                "artifact_file": assignment_path.name,
            },
            "feature_collision_diagnostics": {
                "repeated_group_count": feature_audit.repeated_groups,
                "repeated_row_count": feature_audit.repeated_rows,
                "excess_row_count": feature_audit.excess_rows,
                "conflicting_label_group_count": feature_audit.conflicting_label_groups,
                "conflicting_label_row_count": feature_audit.conflicting_label_rows,
                "shared_assigned_split_group_count": (feature_audit.shared_assigned_split_groups),
                "pairwise_shared_group_counts": dict(
                    sorted(feature_audit.pairwise_shared_groups.items())
                ),
                "automatic_exclusion_or_relabeling": False,
            },
            "provenance": {
                "manifest_sha256": inputs.manifest_digest,
                "preflight_report_sha256": sha256_file(preflight_report),
                "preflight_schema_version": PREFLIGHT_SCHEMA_VERSION,
                "registered_raw_files": [item.path.name for item in inputs.raw_files],
            },
            "resource_configuration": {
                "artifact_budget_bytes": config.artifact_budget_bytes,
                "batch_size": config.batch_size,
                "max_rows_per_file": config.max_rows_per_file,
                "minimum_free_bytes": config.minimum_free_bytes,
                "sqlite_cache_mib": config.sqlite_cache_mib,
            },
            "limitations": [
                "capture and session provenance remain unresolved",
                "near-duplicate leakage is not assessed",
                "attack-category coverage is unavailable in the preflight index",
                "network assignment verification does not make host or global training ready",
            ],
        }
        report_name = "assignment_report.json" if completed else "assignment_partial.json"
        report_path = run_directory / report_name
        _write_json(report_path, report_payload)
        _guard_budget(run_directory, config)
        return DevelopmentSplitResult(
            completed=completed,
            report_path=report_path,
            assignment_path=assignment_path,
            database_path=database_path,
            total_rows=timing_rows,
        )
    except UnswDevelopmentSplitError as exc:
        for name in (
            "assignments.csv.gz",
            "assignments.csv.gz.tmp",
            "assignments_partial.csv.gz",
            "assignments_partial.csv.gz.tmp",
            "assignment_report.json",
            "assignment_report.json.tmp",
            "assignment_partial.json",
            "assignment_partial.json.tmp",
        ):
            (run_directory / name).unlink(missing_ok=True)
        _failure_report(run_directory, scope, exc)
        raise
    except Exception:
        for name in (
            "assignments.csv.gz",
            "assignments.csv.gz.tmp",
            "assignments_partial.csv.gz",
            "assignments_partial.csv.gz.tmp",
            "assignment_report.json",
            "assignment_report.json.tmp",
            "assignment_partial.json",
            "assignment_partial.json.tmp",
        ):
            (run_directory / name).unlink(missing_ok=True)
        error = UnswDevelopmentSplitError("internal_assignment_failure")
        _failure_report(run_directory, scope, error)
        raise
    finally:
        if connection is not None:
            connection.close()
