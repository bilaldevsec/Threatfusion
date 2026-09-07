import json
import subprocess
from pathlib import Path

from scripts.audit_phase0_readiness import (
    synthetic_baseline_is_ready,
    synthetic_pipeline_is_ready,
)
from scripts.generate_synthetic_lab_baseline import EVENT_SEQUENCE, generate_baseline
from scripts.validate_synthetic_lab import run_validation

from threatfusion.datasets.manifests import load_dataset_manifest, write_dataset_manifest
from threatfusion.datasets.synthetic_lab import SyntheticLabQualityGates
from threatfusion.schemas.dataset_manifest import DatasetFile, DatasetManifest
from threatfusion.utils.checksum import sha256_file

PROJECT_ROOT = Path(__file__).parents[3]


def _fixture_manifest(project_root: Path, paths: tuple[Path, ...]) -> Path:
    manifest = DatasetManifest(
        name="synthetic_lab",
        version="fixture",
        license_note="controlled synthetic fixture",
        files=[
            DatasetFile(
                path=path.relative_to(project_root),
                sha256=sha256_file(path),
                rows=len(EVENT_SEQUENCE),
                role="development_fixture",
            )
            for path in paths
        ],
        notes="Controlled benign fixture with independent sessions.",
    )
    manifest_path = project_root / "data/manifests/synthetic_lab.yaml"
    write_dataset_manifest(manifest, manifest_path)
    return manifest_path


def test_generator_is_byte_for_byte_deterministic(tmp_path: Path) -> None:
    first = generate_baseline(tmp_path / "first")
    second = generate_baseline(tmp_path / "second")

    assert [path.name for path in first] == [path.name for path in second]
    assert [path.read_bytes() for path in first] == [path.read_bytes() for path in second]
    assert all(sum(1 for _line in path.open(encoding="utf-8")) == 14 for path in first)


def test_tracked_manifest_registers_three_development_fixture_sessions() -> None:
    manifest = load_dataset_manifest(PROJECT_ROOT / "data/manifests/synthetic_lab.yaml")

    assert manifest.name == "synthetic_lab"
    assert manifest.version == "development-pipeline-fixture-v1"
    assert [item.rows for item in manifest.files] == [14, 14, 14]
    assert [item.role for item in manifest.files] == [
        "development_fixture",
        "development_fixture",
        "development_fixture",
    ]
    assert not any(item.role == "train" for item in manifest.files)
    assert [item.path.name for item in manifest.files] == [
        "synthetic-session-01.jsonl",
        "synthetic-session-02.jsonl",
        "synthetic-session-03.jsonl",
    ]
    assert "Labels are" in str(manifest.notes)


def test_streaming_validation_and_default_quality_gates_pass(tmp_path: Path) -> None:
    paths = generate_baseline(tmp_path / "data/raw/synthetic_lab/official")
    manifest_path = _fixture_manifest(tmp_path, paths)
    report_directory = tmp_path / "artifacts/reports/synthetic_lab"

    payload = run_validation(
        tmp_path,
        manifest_path,
        report_directory,
        SyntheticLabQualityGates(),
    )

    assert payload["completed"] is True
    assert payload["session_count"] == 3
    assert payload["total_rows"] == 42
    assert payload["accepted_count"] == 42
    assert payload["rejected_count"] == 0
    assert payload["label_counts"] == {"Normal": 42}
    assert payload["event_type_counts"] == {
        "process": 6,
        "network": 6,
        "authentication": 6,
        "file": 6,
        "registry": 6,
        "privilege": 6,
        "other": 6,
    }
    assert payload["quality_gates"]["passed"] is True
    assert payload["training_quality_gates"]["passed"] is False
    assert len(list(report_directory.glob("*_quality.json"))) == 3


def test_configurable_incomplete_gate_keeps_baseline_not_ready(tmp_path: Path) -> None:
    paths = generate_baseline(tmp_path / "data/raw/synthetic_lab/official")
    manifest_path = _fixture_manifest(tmp_path, paths)
    payload = run_validation(
        tmp_path,
        manifest_path,
        tmp_path / "artifacts/reports/synthetic_lab",
        SyntheticLabQualityGates(minimum_sessions=4),
    )

    assert payload["quality_gates"]["passed"] is False
    assert synthetic_pipeline_is_ready({"verified": True}, payload) is False
    assert synthetic_baseline_is_ready({"verified": True}, payload) is False


def test_profile_report_is_aggregate_only_and_sanitized(tmp_path: Path) -> None:
    paths = generate_baseline(tmp_path / "data/raw/synthetic_lab/official")
    manifest_path = _fixture_manifest(tmp_path, paths)
    report_directory = tmp_path / "artifacts/reports/synthetic_lab"
    run_validation(
        tmp_path,
        manifest_path,
        report_directory,
        SyntheticLabQualityGates(),
    )
    report_path = report_directory / "synthetic_lab_profile.json"
    report_text = report_path.read_text(encoding="utf-8")
    payload = json.loads(report_text)

    assert synthetic_pipeline_is_ready({"verified": True}, payload) is True
    assert synthetic_baseline_is_ready({"verified": True}, payload) is False
    for forbidden in (
        str(tmp_path),
        "synthetic-lab-host",
        "synthetic-windows-provider",
        "synthetic-benign-process",
        "command_line",
        "src_ip",
        "username",
        "secret",
    ):
        assert forbidden not in report_text


def test_synthetic_raw_and_report_paths_are_git_ignored() -> None:
    for candidate in (
        "data/raw/synthetic_lab/official/synthetic-session-01.jsonl",
        "artifacts/reports/synthetic_lab/synthetic_lab_profile.json",
    ):
        result = subprocess.run(
            ["git", "check-ignore", "--quiet", "--", candidate],
            cwd=PROJECT_ROOT,
            check=False,
        )
        assert result.returncode == 0
