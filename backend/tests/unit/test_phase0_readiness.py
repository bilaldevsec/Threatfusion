import json
from pathlib import Path

from scripts.audit_phase0_readiness import (
    find_prohibited_predictors,
    inspect_report_payload,
    run_audit,
)

from threatfusion.datasets.manifests import write_dataset_manifest
from threatfusion.schemas.dataset_manifest import DatasetFile, DatasetManifest
from threatfusion.utils.checksum import sha256_file


def _quality_payload(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "source": "Mordor/fixture.json",
        "completed": True,
        "total_rows": 2,
        "accepted_count": 2,
        "rejected_count": 0,
        "rejection_rate": 0.0,
        "rejection_details": [],
    }
    payload.update(updates)
    return payload


def _mordor_profile_payload() -> dict[str, object]:
    return {
        "dataset": "mordor",
        "source_file": "fixture.json",
        "classification": "attack_test_only",
        "completed": True,
        "total_rows": 2,
        "accepted_count": 2,
        "rejected_count": 0,
        "rejection_rate": 0.0,
        "rejection_details": [],
        "event_id_counts": {"missing_or_invalid": 2},
        "event_id_overflow_count": 0,
        "field_presence_counts": {},
        "process_event_count": 0,
        "earliest_timestamp": None,
        "latest_timestamp": None,
    }


def _audit_fixture(
    tmp_path: Path,
    *,
    matching_checksum: bool = True,
    include_profile: bool = True,
    quality_updates: dict[str, object] | None = None,
) -> dict[str, object]:
    manifest_directory = tmp_path / "data/manifests"
    report_directory = tmp_path / "artifacts/reports"
    raw_path = tmp_path / "data/raw/mordor/fixture.json"
    raw_path.parent.mkdir(parents=True)
    raw_path.write_text("{}\n{}\n", encoding="utf-8")
    manifest = DatasetManifest(
        name="mordor",
        version="fixture",
        license_note="fixture",
        notes="Attack/test-only fixture; not benign training data.",
        files=[
            DatasetFile(
                path=Path("data/raw/mordor/fixture.json"),
                sha256=sha256_file(raw_path) if matching_checksum else "0" * 64,
                rows=2,
                role="test",
            )
        ],
    )
    write_dataset_manifest(manifest, manifest_directory / "mordor.yaml")
    quality_path = report_directory / "mordor/fixture_quality.json"
    quality_path.parent.mkdir(parents=True)
    quality_path.write_text(
        json.dumps(_quality_payload(**(quality_updates or {}))), encoding="utf-8"
    )
    if include_profile:
        (report_directory / "mordor/mordor_profile.json").write_text(
            json.dumps(_mordor_profile_payload()), encoding="utf-8"
        )

    return run_audit(
        tmp_path,
        manifest_directory,
        report_directory,
        report_directory / "phase0/phase0_readiness.json",
        predictor_contracts={"safe_fixture": ("event_type",)},
        ignore_check=lambda _path: True,
    )


def _dataset(payload: dict[str, object], name: str) -> dict[str, object]:
    datasets = payload["datasets"]
    assert isinstance(datasets, list)
    return next(item for item in datasets if isinstance(item, dict) and item["name"] == name)


def test_passing_manifest_and_report_checks(tmp_path: Path) -> None:
    payload = _audit_fixture(tmp_path)
    mordor = _dataset(payload, "mordor")

    manifest = mordor["manifest_verification"]
    reports = mordor["report_verification"]
    assert isinstance(manifest, dict) and manifest["verified"] is True
    assert isinstance(reports, list)
    assert all(report["verified"] is True for report in reports)
    assert mordor["required_report_evidence_verified"] is True


def test_missing_expected_report_fails_even_when_other_reports_exist(tmp_path: Path) -> None:
    payload = _audit_fixture(tmp_path, include_profile=False)
    mordor = _dataset(payload, "mordor")

    assert mordor["required_report_evidence_verified"] is False
    assert "required_report_missing" in payload["blockers"]
    assert "required_report_evidence_failed" in payload["blockers"]


def test_malformed_or_incomplete_required_report_fails_evidence(tmp_path: Path) -> None:
    payload = _audit_fixture(
        tmp_path,
        quality_updates={"completed": False, "accepted_count": 1, "rejected_count": 0},
    )
    mordor = _dataset(payload, "mordor")

    assert mordor["required_report_evidence_verified"] is False
    assert "report_verification_gate_failed" in payload["blockers"]


def test_wrong_quality_report_source_association_fails_evidence(tmp_path: Path) -> None:
    payload = _audit_fixture(tmp_path, quality_updates={"source": "Mordor/other.json"})
    mordor = _dataset(payload, "mordor")

    assert mordor["required_report_evidence_verified"] is False
    assert "report_verification_gate_failed" in payload["blockers"]


def test_failing_manifest_checksum_is_a_blocker(tmp_path: Path) -> None:
    payload = _audit_fixture(tmp_path, matching_checksum=False)
    mordor = _dataset(payload, "mordor")

    manifest = mordor["manifest_verification"]
    assert isinstance(manifest, dict) and manifest["verified"] is False
    assert "manifest_integrity_gate_failed" in payload["blockers"]
    assert payload["ready_for_training"] is False
    assert payload["pipeline_ready"] is False
    assert payload["training_ready"] is False


def test_failing_report_completion_and_totals_are_detected() -> None:
    payload = _quality_payload(
        completed=False,
        total_rows=3,
        accepted_count=1,
        rejected_count=0,
    )

    inspection = inspect_report_payload("fixture_quality.json", payload)

    assert inspection["completed"] is False
    assert inspection["valid"] is False
    assert "report_not_completed" in inspection["errors"]


def test_forbidden_report_keys_and_raw_markers_are_detected() -> None:
    payload = _quality_payload(
        raw_row={"command_line": "TOP-SECRET-COMMAND", "src_ip": "192.0.2.1"}
    )

    inspection = inspect_report_payload("fixture_quality.json", payload)

    assert inspection["keys_approved"] is False
    assert inspection["content_sanitized"] is False


def test_prohibited_predictor_fields_are_reported_by_contract() -> None:
    result = find_prohibited_predictors(
        {
            "unsafe": ("duration_ms", "flow_id", "src_port", "label", "ProcessGuid"),
            "safe": ("duration_ms", "dst_port", "event_count"),
        }
    )

    assert result == {
        "unsafe": ["flow_id", "label", "process_guid", "src_port"],
    }


def test_attack_only_mordor_and_missing_benign_baseline_are_explicit(
    tmp_path: Path,
) -> None:
    payload = _audit_fixture(tmp_path)
    checks = {
        item["check"]: item["status"]
        for item in payload["leakage_checks"]
        if isinstance(item, dict)
    }

    assert checks["mordor_attack_test_isolation"] == "passed"
    assert checks["benign_synthetic_lab_baseline"] == "failed"
    assert "benign_synthetic_lab_baseline_missing" in payload["blockers"]
    assert payload["ready_for_training"] is False


def test_absent_split_assignments_are_not_reported_as_verified(tmp_path: Path) -> None:
    payload = _audit_fixture(tmp_path)
    checks = {
        item["check"]: item["status"]
        for item in payload["split_policy_checks"]
        if isinstance(item, dict)
    }

    assert checks["source_aware_split"] == "configured"
    assert checks["split_assignments"] == "not_verified"
    assert "split_assignments_missing" in payload["blockers"]


def test_written_audit_is_sanitized_json(tmp_path: Path) -> None:
    payload = _audit_fixture(tmp_path)
    report_path = tmp_path / "artifacts/reports/phase0/phase0_readiness.json"
    report_text = report_path.read_text(encoding="utf-8")

    assert json.loads(report_text) == payload
    assert str(tmp_path) not in report_text
    assert "192.0.2.1" not in report_text
    assert "TOP-SECRET" not in report_text
    assert set(payload) == {
        "phase",
        "schema_version",
        "pipeline_ready",
        "training_ready",
        "ready_for_training",
        "datasets",
        "feature_contract_summaries",
        "leakage_checks",
        "split_policy_checks",
        "blockers",
        "warnings",
    }
