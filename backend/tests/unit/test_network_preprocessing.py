import csv
import gzip
import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from threatfusion.datasets.unsw_development_split import (
    ASSIGNMENT_SCHEMA_VERSION,
    ASSIGNMENT_SEED,
)
from threatfusion.datasets.unsw_split_preflight import (
    PREFLIGHT_SCHEMA_VERSION,
    RegisteredUnswInputs,
)
from threatfusion.preprocessing import network_behavior_v1 as preprocessing
from threatfusion.preprocessing.network_behavior_v1 import (
    CATEGORY_FEATURE_NAMES,
    FIXED_PROTOCOL_CATEGORIES,
    LABEL_MAPPING,
    NUMERIC_FEATURE_NAMES,
    PREPROCESSING_SCHEMA_VERSION,
    TRANSFORMED_FEATURE_NAMES,
    AssignmentEvidence,
    NetworkBehaviorPreprocessor,
    NetworkPreprocessingError,
    encode_binary_label,
    iter_assigned_source_records,
    verify_assignment_evidence,
)
from threatfusion.schemas.dataset_manifest import DatasetFile
from threatfusion.utils.checksum import sha256_file

RAW_FEATURE_NAMES = (
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


def _record(offset: float = 0.0, protocol: str = "tcp", label: str = "Normal") -> SimpleNamespace:
    return SimpleNamespace(
        duration_ms=10.0 + offset,
        fwd_packets=2 + int(offset),
        bwd_packets=1 + int(offset),
        fwd_bytes=100 + int(offset),
        bwd_bytes=50 + int(offset),
        packets_per_second=3.0 + offset,
        bytes_per_second=150.0 + offset,
        fwd_packet_length_mean=50.0 + offset,
        bwd_packet_length_mean=50.0 + offset,
        dst_port=443 + int(offset),
        protocol=protocol,
        label=label,
    )


def test_contract_classification_order_and_label_mapping_are_stable() -> None:
    assert NUMERIC_FEATURE_NAMES == (
        "duration_ms",
        "fwd_packets",
        "bwd_packets",
        "fwd_bytes",
        "bwd_bytes",
        "packets_per_second",
        "bytes_per_second",
        "fwd_packet_length_mean",
        "bwd_packet_length_mean",
        "dst_port",
    )
    assert CATEGORY_FEATURE_NAMES == ("protocol",)
    assert TRANSFORMED_FEATURE_NAMES == (
        *(f"{name}__zscore" for name in NUMERIC_FEATURE_NAMES),
        "protocol=tcp",
        "protocol=udp",
        "protocol=icmp",
        "protocol=other",
    )
    assert LABEL_MAPPING == {"Normal": 0, "Attack": 1}
    assert encode_binary_label("Normal") == 0
    assert encode_binary_label("Attack") == 1
    with pytest.raises(NetworkPreprocessingError, match="unknown_binary_label"):
        encode_binary_label("benign-ish")


def test_validation_values_cannot_change_train_fitted_state() -> None:
    train = [_record(0), _record(1, "udp", "Attack"), _record(2)]
    first = NetworkBehaviorPreprocessor.fit(train, batch_size=1)
    before = first.to_dict()

    first.transform_batch([_record(1_000_000, "icmp", "Attack")])
    second = NetworkBehaviorPreprocessor.fit(train, batch_size=3)

    assert first.to_dict() == before
    np.testing.assert_allclose(first.numeric_means, second.numeric_means, rtol=1e-12, atol=1e-12)
    np.testing.assert_allclose(first.numeric_scales, second.numeric_scales, rtol=1e-12, atol=1e-12)


def test_unknown_categories_and_non_finite_values_fail_closed() -> None:
    fitted = NetworkBehaviorPreprocessor.fit([_record(0), _record(1)])
    with pytest.raises(NetworkPreprocessingError, match="unknown_protocol_category"):
        fitted.transform(_record(protocol="sctp"))
    invalid = _record()
    invalid.duration_ms = float("inf")
    with pytest.raises(NetworkPreprocessingError, match="non_finite_predictor"):
        fitted.transform(invalid)


def test_fitted_state_reload_preserves_transform_results_and_rejects_prohibited_fields(
    tmp_path: Path,
) -> None:
    fitted = NetworkBehaviorPreprocessor.fit([_record(0), _record(1, "other")])
    state_path = tmp_path / "state.json"
    fitted.save(state_path)
    reloaded = NetworkBehaviorPreprocessor.load(state_path)

    np.testing.assert_array_equal(
        fitted.transform(_record(2, "udp")), reloaded.transform(_record(2, "udp"))
    )

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["input_feature_names"].append("label")
    state_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(NetworkPreprocessingError, match="fitted_state_contract_mismatch"):
        NetworkBehaviorPreprocessor.load(state_path)


def test_batch_boundaries_preserve_outputs_within_declared_tolerance() -> None:
    records = [_record(float(index), FIXED_PROTOCOL_CATEGORIES[index % 4]) for index in range(20)]
    first = NetworkBehaviorPreprocessor.fit(records, batch_size=1)
    second = NetworkBehaviorPreprocessor.fit(records, batch_size=7)

    first_output = first.transform_batch(records)
    second_output = second.transform_batch(records)
    np.testing.assert_allclose(first_output, second_output, rtol=1e-12, atol=1e-12)


def _valid_report(total: int, assignment_hash: str, preflight_hash: str) -> dict[str, object]:
    zero = {"total_count": 0, "benign_count": 0, "attack_count": 0, "group_count": 0}
    return {
        "schema_version": ASSIGNMENT_SCHEMA_VERSION,
        "completed": True,
        "creates_final_assignments": True,
        "run_scope": "full",
        "network_split_status": "verified",
        "source_dataset": "unsw_nb15",
        "policy": {"seed": ASSIGNMENT_SEED},
        "split_counts": {
            "train": {**zero, "total_count": total, "benign_count": total},
            "validation": dict(zero),
            "test": dict(zero),
            "quarantine": dict(zero),
            "rejected": {
                "total_count": 0,
                "benign_count": None,
                "attack_count": None,
                "group_count": None,
            },
        },
        "assignment_audit": {
            "all_accepted_rows_grouped": True,
            "all_groups_have_one_decision": True,
            "all_selected_rows_accounted_once": True,
            "canonical_split_policy_validated_in_bounded_batches": True,
            "enforced_group_cross_split_count_zero": True,
            "train_has_benign_and_attack": True,
            "validation_has_benign_and_attack": True,
            "artifact_row_count": total,
            "artifact_file": "assignments.csv.gz",
            "artifact_sha256": assignment_hash,
        },
        "provenance": {
            "manifest_sha256": "a" * 64,
            "preflight_schema_version": PREFLIGHT_SCHEMA_VERSION,
            "preflight_report_sha256": preflight_hash,
            "registered_raw_files": ["UNSW-NB15_1.csv"],
        },
    }


def _registered_inputs(project_root: Path, rows: int) -> RegisteredUnswInputs:
    feature = DatasetFile(path=Path("data/raw/features.csv"), sha256="b" * 64, rows=49, role="raw")
    raw = DatasetFile(path=Path("data/raw/UNSW-NB15_1.csv"), sha256="c" * 64, rows=rows, role="raw")
    return RegisteredUnswInputs(
        manifest_digest="a" * 64,
        manifest_version="fixture",
        feature_metadata=feature,
        raw_files=(raw,),
        feature_names=RAW_FEATURE_NAMES,
    )


def _write_gzip_assignments(path: Path, rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, mode="wt", encoding="utf-8", newline="") as handle:
        csv.writer(handle, lineterminator="\n").writerows(
            [["record_id", "group_id", "disposition", "reason"], *rows]
        )


def test_partial_or_corrupted_assignment_evidence_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assignment_directory = tmp_path / "data/interim/unsw_development_split/fixture-assignment"
    assignment_path = assignment_directory / "assignments.csv.gz"
    _write_gzip_assignments(assignment_path, [["1", "1" * 64, "train", ""]])
    preflight_path = tmp_path / "data/interim/preflight_report.json"
    preflight_path.parent.mkdir(parents=True, exist_ok=True)
    preflight = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "completed": True,
        "run_scope": "full",
        "creates_assignments": False,
        "checks": {
            "accounting_reconciled": True,
            "diagnostics_succeeded": True,
            "feature_metadata_verified": True,
            "inputs_fully_exhausted": True,
            "manifest_verified": True,
            "working_disk_budget_respected": True,
        },
        "manifest": {"sha256": "a" * 64},
        "overall": {"total_input_rows": 1, "rejected_count": 0},
    }
    preflight_path.write_text(json.dumps(preflight), encoding="utf-8")
    report = _valid_report(1, sha256_file(assignment_path), sha256_file(preflight_path))
    report["completed"] = False
    (assignment_directory / "assignment_report.json").write_text(
        json.dumps(report), encoding="utf-8"
    )
    monkeypatch.setattr(
        preprocessing,
        "verify_registered_unsw_inputs",
        lambda project_root, manifest_path: _registered_inputs(project_root, 1),
    )

    with pytest.raises(
        NetworkPreprocessingError, match="assignment_evidence_not_complete_or_consistent"
    ):
        verify_assignment_evidence(
            tmp_path,
            tmp_path / "manifest.yaml",
            assignment_directory,
            preflight_path,
        )

    report["completed"] = True
    (assignment_directory / "assignment_report.json").write_text(
        json.dumps(report), encoding="utf-8"
    )
    assignment_path.write_bytes(assignment_path.read_bytes() + b"corrupt")
    with pytest.raises(NetworkPreprocessingError, match="assignment_archive_hash_mismatch"):
        verify_assignment_evidence(
            tmp_path,
            tmp_path / "manifest.yaml",
            assignment_directory,
            preflight_path,
        )


def _raw_row(label: str = "0") -> dict[str, str]:
    row = {name: "0" for name in RAW_FEATURE_NAMES}
    row.update(
        {
            "srcip": "192.0.2.1",
            "sport": "1234",
            "dstip": "198.51.100.2",
            "dsport": "443",
            "proto": "tcp",
            "dur": "1",
            "sbytes": "100",
            "dbytes": "50",
            "spkts": "2",
            "dpkts": "1",
            "stime": "1421928000",
            "ltime": "1421928001",
            "label": label,
        }
    )
    return row


def test_duplicate_or_unmatched_assignment_entries_fail(tmp_path: Path) -> None:
    raw_path = tmp_path / "data/raw/UNSW-NB15_1.csv"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    with raw_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        for row in (_raw_row(), _raw_row("1")):
            writer.writerow([row[name] for name in RAW_FEATURE_NAMES])
    assignment_path = tmp_path / "assignments.csv.gz"
    _write_gzip_assignments(
        assignment_path,
        [["1", "1" * 64, "train", ""], ["1", "2" * 64, "validation", ""]],
    )
    inputs = _registered_inputs(tmp_path, 2)
    evidence = AssignmentEvidence(
        inputs=inputs,
        report={},
        report_sha256="d" * 64,
        assignment_path=assignment_path,
        assignment_sha256=sha256_file(assignment_path),
        preflight_report_path=tmp_path / "preflight.json",
        preflight_report_sha256="e" * 64,
        total_rows=2,
    )

    with pytest.raises(
        NetworkPreprocessingError, match="assignment_record_order_or_coverage_invalid"
    ):
        list(iter_assigned_source_records(tmp_path, evidence))


def test_state_schema_version_is_explicit(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    NetworkBehaviorPreprocessor.fit([_record(), _record(1)]).save(state_path)
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == PREPROCESSING_SCHEMA_VERSION
