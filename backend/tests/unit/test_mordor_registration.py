import hashlib
import json
import subprocess
from pathlib import Path

from scripts.validate_mordor import validate_mordor_file

from threatfusion.datasets.manifests import load_dataset_manifest, verify_dataset_manifest
from threatfusion.schemas.dataset_manifest import DatasetFile, DatasetManifest

PROJECT_ROOT = Path(__file__).parents[3]
REGISTERED_BASENAME = "cmd_sharpview_pcre_net_2020-10-2920232423.json"


def _event(index: int) -> dict[str, object]:
    return {
        "@timestamp": f"2020-10-29T20:23:{index % 60:02d}.000Z",
        "Hostname": "fixture-host",
        "EventID": 7,
    }


def _write_events(path: Path, count: int) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for index in range(count):
            handle.write(json.dumps(_event(index)) + "\n")


def test_tracked_manifest_registers_only_selected_attack_test_ndjson() -> None:
    manifest = load_dataset_manifest(PROJECT_ROOT / "data/manifests/mordor.yaml")

    assert manifest.name == "mordor"
    assert len(manifest.files) == 1
    item = manifest.files[0]
    assert item.path.name == REGISTERED_BASENAME
    assert item.rows == 267
    assert item.role == "test"
    assert item.sha256 == "b3df9616bb41ee1b464595eb0d5a5b612f475d34d78429786a6fa8ee8a16be9d"
    assert "415,506 bytes" in str(manifest.notes)
    assert "Attack/test-only" in str(manifest.notes)
    assert "psh_powershell_httplistener" not in manifest.model_dump_json()


def test_existing_verifier_accepts_matching_synthetic_checksum(tmp_path: Path) -> None:
    source_path = tmp_path / "tiny.json"
    source_path.write_text("{}\n", encoding="utf-8")
    digest = hashlib.sha256(b"{}\n").hexdigest()
    manifest = DatasetManifest(
        name="mordor",
        version="fixture",
        license_note="MIT fixture",
        files=[DatasetFile(path=Path("tiny.json"), sha256=digest, rows=1, role="test")],
    )

    result = verify_dataset_manifest(manifest, tmp_path)

    assert result.verified is True


def test_validation_streams_exactly_267_events_and_writes_completed_report(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "tiny.json"
    _write_events(source_path, 267)
    report_path = tmp_path / "new" / "reports" / "quality.json"

    result = validate_mordor_file(source_path, report_path, expected_rows=267)
    payload = json.loads(report_path.read_text(encoding="utf-8"))

    assert result.report.total_rows == 267
    assert payload["accepted_count"] == 267
    assert payload["rejected_count"] == 0
    assert payload["completed"] is True
    assert set(payload) == {
        "source",
        "completed",
        "total_rows",
        "accepted_count",
        "rejected_count",
        "rejection_rate",
        "rejection_details",
    }


def test_raw_inputs_and_generated_reports_are_git_ignored() -> None:
    candidates = (
        "data/raw/mordor/incoming/cmd_sharpview_pcre_net.zip",
        f"data/raw/mordor/incoming/{REGISTERED_BASENAME}",
        "artifacts/reports/mordor/mordor_profile.json",
    )

    for candidate in candidates:
        result = subprocess.run(
            ["git", "check-ignore", "--quiet", "--", candidate],
            cwd=PROJECT_ROOT,
            check=False,
        )
        assert result.returncode == 0
