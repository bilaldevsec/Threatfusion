import csv
import gzip
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from threatfusion.datasets.adapters.unsw_nb15 import adapt_unsw_row
from threatfusion.datasets.manifests import write_dataset_manifest
from threatfusion.datasets.unsw_development_split import (
    ASSIGNMENT_SEED,
    DevelopmentSplitConfig,
    DiskUnionFind,
    UnswDevelopmentSplitError,
    deterministic_development_split,
    deterministic_group_identifier,
    run_unsw_development_split,
    validate_policy_assignment_batch,
)
from threatfusion.datasets.unsw_split_preflight import (
    FEATURE_METADATA_FILENAME,
    RAW_FILENAMES,
    PreflightConfig,
    UnswSplitPreflightError,
    classify_raw_interval,
    model_feature_fingerprint,
    normalized_flow_identity_fingerprint,
    run_unsw_split_preflight,
    source_record_fingerprint,
)
from threatfusion.schemas.dataset_manifest import DatasetFile, DatasetManifest
from threatfusion.utils.checksum import sha256_file

FEATURE_NAMES = (
    "srcip",
    "sport",
    "dstip",
    "dsport",
    "proto",
    "state",
    "dur",
    "sbytes",
    "dbytes",
    "sttl",
    "dttl",
    "sloss",
    "dloss",
    "service",
    "sload",
    "dload",
    "spkts",
    "dpkts",
    "swin",
    "dwin",
    "stcpb",
    "dtcpb",
    "smeansz",
    "dmeansz",
    "trans_depth",
    "res_bdy_len",
    "sjit",
    "djit",
    "stime",
    "ltime",
    "sintpkt",
    "dintpkt",
    "tcprtt",
    "synack",
    "ackdat",
    "is_sm_ips_ports",
    "ct_state_ttl",
    "ct_flw_http_mthd",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_srv_src",
    "ct_srv_dst",
    "ct_dst_ltm",
    "ct_src_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "attack_cat",
    "label",
)


def _row(
    *,
    srcip: str = "192.0.2.1",
    sport: str = "1234",
    dstip: str = "198.51.100.2",
    dsport: str = "53",
    proto: str = "udp",
    state: str = "CON",
    duration: str = "2",
    stime: str = "1421927414",
    ltime: str = "1421927416",
    label: str = "0",
    attack_category: str = "",
) -> dict[str, str]:
    values = {name: "0" for name in FEATURE_NAMES}
    values.update(
        {
            "srcip": srcip,
            "sport": sport,
            "dstip": dstip,
            "dsport": dsport,
            "proto": proto,
            "state": state,
            "dur": duration,
            "sbytes": "120",
            "dbytes": "60",
            "spkts": "2",
            "dpkts": "1",
            "stime": stime,
            "ltime": ltime,
            "attack_cat": attack_category,
            "label": label,
        }
    )
    return values


def _write_csv(path: Path, rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerows(rows)


def _build_project(project_root: Path, rows_by_file: list[list[dict[str, str]]]) -> Path:
    raw_directory = project_root / "data/raw/unsw_nb15/official"
    feature_path = raw_directory / FEATURE_METADATA_FILENAME
    _write_csv(
        feature_path,
        [
            ["No.", "Name", "Type", "Description"],
            *[
                [str(index), name, "test", "fixture field"]
                for index, name in enumerate(FEATURE_NAMES, start=1)
            ],
        ],
    )
    files = [
        DatasetFile(
            path=feature_path.relative_to(project_root),
            sha256=sha256_file(feature_path),
            rows=49,
            role="raw",
        )
    ]
    for filename, rows in zip(RAW_FILENAMES, rows_by_file, strict=True):
        path = raw_directory / filename
        _write_csv(path, [[row[name] for name in FEATURE_NAMES] for row in rows])
        files.append(
            DatasetFile(
                path=path.relative_to(project_root),
                sha256=sha256_file(path),
                rows=len(rows),
                role="raw",
            )
        )
    manifest = DatasetManifest(
        name="unsw_nb15",
        version="synthetic preflight fixture",
        license_note="test fixture",
        files=files,
    )
    manifest_path = project_root / "data/manifests/unsw_nb15.yaml"
    write_dataset_manifest(manifest, manifest_path)
    return manifest_path


def _run(
    project_root: Path,
    rows_by_file: list[list[dict[str, str]]],
    *,
    batch_size: int = 2,
    max_rows_per_file: int | None = None,
) -> tuple[dict[str, Any], Path]:
    manifest = _build_project(project_root, rows_by_file)
    result = run_unsw_split_preflight(
        project_root,
        manifest,
        project_root / "data/interim/preflight",
        "test-run",
        PreflightConfig(
            batch_size=batch_size,
            sqlite_cache_mib=1,
            disk_budget_bytes=32 * 1024**2,
            minimum_free_bytes=0,
            max_rows_per_file=max_rows_per_file,
        ),
    )
    return json.loads(result.report_path.read_text(encoding="utf-8")), result.database_path


def test_fingerprints_are_deterministic_ordered_and_exclude_labels_and_ids() -> None:
    first = _row(label="0")
    second = dict(first, label="1", attack_cat="Generic")
    first["flow_id"] = "injected:1"
    second["flow_id"] = "injected:999"

    assert source_record_fingerprint(first, FEATURE_NAMES) != source_record_fingerprint(
        second, FEATURE_NAMES
    )
    assert source_record_fingerprint(first, FEATURE_NAMES) == source_record_fingerprint(
        dict(first, flow_id="another-id"), FEATURE_NAMES
    )
    first_flow = adapt_unsw_row(first)
    second_flow = adapt_unsw_row(second)
    assert model_feature_fingerprint(first_flow) == model_feature_fingerprint(second_flow)
    assert model_feature_fingerprint(first_flow) == model_feature_fingerprint(first_flow)
    changed_flow = adapt_unsw_row(dict(first, dbytes="61"))
    assert model_feature_fingerprint(first_flow) != model_feature_fingerprint(changed_flow)


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        ({"stime": "100", "ltime": "102", "dur": "2"}, "exact"),
        (
            {"stime": "100", "ltime": "102", "dur": "2.75"},
            "within_one_second_quantization",
        ),
        ({"stime": "100", "ltime": "102", "dur": "4"}, "unexplained_over_one_second"),
        ({"stime": "102", "ltime": "100", "dur": "2"}, "ltime_before_stime"),
        ({"stime": "bad", "ltime": "100", "dur": "2"}, "unavailable_parse_failure"),
    ],
)
def test_classifies_numeric_epoch_interval_boundaries(row: dict[str, str], expected: str) -> None:
    assert classify_raw_interval(row)[0] == expected


def test_distinguishes_source_duplicates_feature_collisions_and_label_conflicts(
    tmp_path: Path,
) -> None:
    source = _row()
    outside_contract_change = dict(source, state="FIN")
    conflict = dict(outside_contract_change, label="1", attack_cat="Generic")
    payload, _ = _run(
        tmp_path, [[source, dict(source), outside_contract_change, conflict], [], [], []]
    )

    overall = payload["overall"]
    assert overall["exact_source_duplicates"] == {
        "excess_row_count": 1,
        "group_count": 1,
        "row_count": 2,
    }
    assert overall["repeated_model_feature_vectors"]["group_count"] == 1
    assert overall["repeated_model_feature_vectors"]["excess_row_count"] == 3
    assert overall["repeated_model_feature_vectors"]["conflicting_label_group_count"] == 1
    assert overall["repeated_model_feature_vectors"]["conflicting_label_row_count"] == 4


def test_counts_accepted_rejected_rows_and_processes_multiple_sqlite_batches(
    tmp_path: Path,
) -> None:
    rows = [
        _row(stime=str(1421927414 + index), ltime=str(1421927416 + index)) for index in range(5)
    ]
    rows.append(_row(sport="-"))
    payload, database = _run(tmp_path, [rows, [], [], []], batch_size=2)

    assert payload["completed"] is True
    assert payload["overall"]["total_input_rows"] == 6
    assert payload["overall"]["accepted_count"] == 5
    assert payload["overall"]["rejected_count"] == 1
    assert payload["checks"]["accounting_reconciled"] is True
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM records").fetchone() == (6,)


def test_partial_run_is_clearly_incomplete(tmp_path: Path) -> None:
    payload, _ = _run(tmp_path, [[_row(), _row(state="FIN")], [], [], []], max_rows_per_file=1)

    assert payload["completed"] is False
    assert payload["run_scope"] == "partial"
    assert payload["checks"]["inputs_fully_exhausted"] is False
    assert payload["creates_assignments"] is False


def test_manifest_failure_writes_only_an_incomplete_failure_report(tmp_path: Path) -> None:
    manifest = _build_project(tmp_path, [[_row()], [], [], []])
    raw_path = tmp_path / "data/raw/unsw_nb15/official" / RAW_FILENAMES[0]
    with raw_path.open("a", encoding="utf-8") as handle:
        handle.write("corrupt\n")

    with pytest.raises(UnswSplitPreflightError, match="manifest_verification_failed"):
        run_unsw_split_preflight(
            tmp_path,
            manifest,
            tmp_path / "data/interim/preflight",
            "failed-run",
            PreflightConfig(disk_budget_bytes=32 * 1024**2, minimum_free_bytes=0),
        )

    run_directory = tmp_path / "data/interim/preflight/failed-run"
    failure = json.loads((run_directory / "preflight_failure.json").read_text(encoding="utf-8"))
    assert failure["completed"] is False
    assert not (run_directory / "preflight_report.json").exists()


def test_report_is_sanitized(tmp_path: Path) -> None:
    payload, database = _run(tmp_path, [[_row()], [], [], []])
    text = database.with_name("preflight_report.json").read_text(encoding="utf-8")

    assert "192.0.2.1" not in text
    assert "198.51.100.2" not in text
    assert str(tmp_path) not in text
    assert "injected:1" not in text
    assert payload["creates_assignments"] is False


def test_direction_normalized_touching_intervals_are_reported_as_overlap(
    tmp_path: Path,
) -> None:
    first = _row(stime="100", ltime="102", duration="2")
    reverse_touching = _row(
        srcip="198.51.100.2",
        sport="53",
        dstip="192.0.2.1",
        dsport="1234",
        stime="102",
        ltime="103",
        duration="1",
    )
    separated = _row(stime="104", ltime="105", duration="1", state="FIN")
    first_flow = adapt_unsw_row(dict(first, flow_id="fixture:1"))
    reverse_flow = adapt_unsw_row(dict(reverse_touching, flow_id="fixture:2"))
    assert normalized_flow_identity_fingerprint(first_flow) == normalized_flow_identity_fingerprint(
        reverse_flow
    )

    payload, _ = _run(tmp_path, [[first, reverse_touching, separated], [], [], []])

    assert payload["overall"]["overlapping_flow_identities"] == {
        "excess_row_count": 1,
        "group_count": 1,
        "row_count": 2,
    }


def _balanced_development_rows() -> list[dict[str, str]]:
    start = int(datetime(2015, 1, 22, 12, tzinfo=UTC).timestamp())
    return [
        _row(
            sport=str(10_000 + index),
            stime=str(start + index * 10),
            ltime=str(start + index * 10 + 1),
            duration="1",
            label=str(index % 2),
            attack_category="Generic" if index % 2 else "",
        )
        for index in range(40)
    ]


def _run_assignment_fixture(
    project_root: Path,
    rows_by_file: list[list[dict[str, str]]],
    *,
    run_id: str = "assignment-run",
    max_rows_per_file: int | None = None,
) -> tuple[dict[str, Any], Path]:
    manifest = _build_project(project_root, rows_by_file)
    preflight = run_unsw_split_preflight(
        project_root,
        manifest,
        project_root / "data/interim/preflight",
        "preflight-run",
        PreflightConfig(
            batch_size=3,
            sqlite_cache_mib=1,
            disk_budget_bytes=32 * 1024**2,
            minimum_free_bytes=0,
        ),
    )
    result = run_unsw_development_split(
        project_root=project_root,
        manifest_path=manifest,
        preflight_database=preflight.database_path,
        preflight_report=preflight.report_path,
        artifact_root=project_root / "data/interim/assignment",
        run_id=run_id,
        config=DevelopmentSplitConfig(
            batch_size=3,
            sqlite_cache_mib=1,
            artifact_budget_bytes=32 * 1024**2,
            minimum_free_bytes=0,
            max_rows_per_file=max_rows_per_file,
        ),
    )
    return json.loads(result.report_path.read_text(encoding="utf-8")), result.assignment_path


def test_development_group_assignment_is_deterministic_and_seed_is_frozen() -> None:
    identifier = deterministic_group_identifier(42)

    assert identifier == deterministic_group_identifier(42)
    assert deterministic_development_split(identifier) == deterministic_development_split(
        identifier
    )
    with pytest.raises(ValueError, match="frozen assignment seed"):
        deterministic_development_split(identifier, "retry-for-balance")
    assert ASSIGNMENT_SEED == "threatfusion-unsw-dev-split-v1"


def test_disk_union_find_combines_relationships_transitively() -> None:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.execute(
        "CREATE TABLE groups(record_id INTEGER PRIMARY KEY, parent INTEGER NOT NULL)"
    )
    connection.executemany("INSERT INTO groups VALUES (?, ?)", [(1, 1), (2, 2), (3, 3)])
    union_find = DiskUnionFind(connection)

    union_find.union(1, 2)
    union_find.union(2, 3)

    assert [union_find.find(record_id) for record_id in (1, 2, 3)] == [1, 1, 1]


def test_forbidden_source_role_is_rejected_by_canonical_assignment_policy() -> None:
    with pytest.raises(ValueError, match="does not allow split"):
        validate_policy_assignment_batch(
            "cse_cic_ids2018", [(deterministic_group_identifier(1), "train")]
        )


def test_assignment_reconciles_and_is_byte_deterministic(tmp_path: Path) -> None:
    development = _balanced_development_rows()
    test_start = int(datetime(2015, 2, 18, 6, tzinfo=UTC).timestamp())
    held_out = _row(
        sport="20000",
        stime=str(test_start),
        ltime=str(test_start + 1),
        duration="1",
        label="1",
        attack_category="Generic",
    )
    rows = [development, [], [], [held_out]]
    payload, assignment = _run_assignment_fixture(tmp_path, rows)
    second_payload, second_assignment = _run_assignment_fixture(
        tmp_path / "second", rows, run_id="second-assignment"
    )

    assert payload["completed"] is True
    assert payload["assignment_audit"]["all_selected_rows_accounted_once"] is True
    assert payload["assignment_audit"]["enforced_group_cross_split_count_zero"] is True
    assert payload["split_counts"]["train"]["benign_count"] > 0
    assert payload["split_counts"]["train"]["attack_count"] > 0
    assert payload["split_counts"]["validation"]["benign_count"] > 0
    assert payload["split_counts"]["validation"]["attack_count"] > 0
    assert payload["split_counts"]["test"]["total_count"] == 1
    assert assignment.read_bytes() == second_assignment.read_bytes()
    assert (
        payload["assignment_audit"]["artifact_sha256"]
        == second_payload["assignment_audit"]["artifact_sha256"]
    )


def test_unexplained_timing_quarantines_a_transitive_overlap_group(tmp_path: Path) -> None:
    start = int(datetime(2015, 1, 22, 13, tzinfo=UTC).timestamp())
    chained = [
        _row(stime=str(start), ltime=str(start + 5), duration="2"),
        _row(stime=str(start + 2), ltime=str(start + 4), duration="2", state="FIN"),
        _row(stime=str(start + 4), ltime=str(start + 6), duration="2", state="REQ"),
    ]
    held_out_start = int(datetime(2015, 2, 18, 6, tzinfo=UTC).timestamp())
    held_out = _row(
        sport="25000",
        stime=str(held_out_start),
        ltime=str(held_out_start + 1),
        duration="1",
    )
    payload, _ = _run_assignment_fixture(
        tmp_path, [_balanced_development_rows() + chained, [], [], [held_out]]
    )

    impact = payload["quarantine_reason_impacts"]["unexplained_timing"]
    assert impact["group_count"] == 1
    assert impact["total_count"] == 3
    assert payload["split_counts"]["quarantine"]["total_count"] == 3


def test_period_boundary_interval_quarantines_its_group(tmp_path: Path) -> None:
    boundary_start = int(datetime(2015, 1, 23, 23, 59, 59, tzinfo=UTC).timestamp())
    boundary = _row(
        sport="26000",
        stime=str(boundary_start),
        ltime=str(boundary_start + 2),
        duration="2",
    )
    held_out_start = int(datetime(2015, 2, 18, 6, tzinfo=UTC).timestamp())
    held_out = _row(
        sport="27000",
        stime=str(held_out_start),
        ltime=str(held_out_start + 1),
        duration="1",
    )
    payload, _ = _run_assignment_fixture(
        tmp_path, [_balanced_development_rows() + [boundary], [], [], [held_out]]
    )

    impact = payload["quarantine_reason_impacts"]["period_boundary_interval"]
    assert impact["group_count"] == 1
    assert impact["total_count"] == 1


def test_class_support_failure_writes_no_final_assignment(tmp_path: Path) -> None:
    rows = [
        _row(
            sport=str(30_000 + index),
            stime=str(int(datetime(2015, 1, 22, 12, tzinfo=UTC).timestamp()) + index * 10),
            ltime=str(int(datetime(2015, 1, 22, 12, tzinfo=UTC).timestamp()) + index * 10 + 1),
            duration="1",
            label="0",
        )
        for index in range(20)
    ]
    manifest = _build_project(tmp_path, [rows, [], [], []])
    preflight = run_unsw_split_preflight(
        tmp_path,
        manifest,
        tmp_path / "data/interim/preflight",
        "preflight-run",
        PreflightConfig(sqlite_cache_mib=1, disk_budget_bytes=32 * 1024**2, minimum_free_bytes=0),
    )

    with pytest.raises(UnswDevelopmentSplitError, match="assignment_acceptance_failed"):
        run_unsw_development_split(
            tmp_path,
            manifest,
            preflight.database_path,
            preflight.report_path,
            tmp_path / "data/interim/assignment",
            "failed-assignment",
            DevelopmentSplitConfig(
                sqlite_cache_mib=1,
                artifact_budget_bytes=32 * 1024**2,
                minimum_free_bytes=0,
            ),
        )

    run_directory = tmp_path / "data/interim/assignment/failed-assignment"
    failure = json.loads((run_directory / "assignment_failure.json").read_text(encoding="utf-8"))
    assert failure["completed"] is False
    assert failure["acceptance_checks"]["validation_has_benign_and_attack"] is False
    assert not (run_directory / "assignments.csv.gz").exists()


def test_assignment_report_and_public_output_are_sanitized(tmp_path: Path) -> None:
    test_start = int(datetime(2015, 2, 18, 6, tzinfo=UTC).timestamp())
    payload, assignment = _run_assignment_fixture(
        tmp_path,
        [
            _balanced_development_rows(),
            [],
            [],
            [
                _row(
                    sport="28000",
                    stime=str(test_start),
                    ltime=str(test_start + 1),
                    duration="1",
                )
            ],
        ],
    )
    report_text = assignment.with_name("assignment_report.json").read_text(encoding="utf-8")
    with gzip.open(assignment, mode="rt", encoding="utf-8") as handle:
        header = handle.readline().strip()

    assert header == "record_id,group_id,disposition,reason"
    assert "192.0.2.1" not in report_text
    assert "198.51.100.2" not in report_text
    assert str(tmp_path) not in report_text
    assert "source_fp" not in report_text
    assert "tuple_fp" not in report_text
    assert payload["global_training_ready"] is False
