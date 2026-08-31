from pathlib import Path

from threatfusion.datasets.manifests import (
    VerificationStatus,
    load_dataset_manifest,
    verify_dataset_manifest,
    write_dataset_manifest,
)
from threatfusion.schemas.dataset_manifest import DatasetManifest
from threatfusion.utils.checksum import sha256_file


def make_manifest(file_path: Path, sha256: str | None) -> DatasetManifest:
    return DatasetManifest.model_validate(
        {
            "name": "unsw_nb15",
            "version": "test",
            "license_note": "Test fixture only.",
            "files": [
                {
                    "path": file_path,
                    "sha256": sha256,
                    "role": "sample",
                }
            ],
        }
    )


def test_yaml_manifest_round_trip(tmp_path: Path) -> None:
    manifest = make_manifest(
        Path("data/raw/sample.csv"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    manifest_path = tmp_path / "manifests" / "sample.yaml"

    write_dataset_manifest(manifest, manifest_path)

    assert load_dataset_manifest(manifest_path) == manifest


def test_verify_matching_file(tmp_path: Path) -> None:
    relative_path = Path("data/sample.csv")
    file_path = tmp_path / relative_path
    file_path.parent.mkdir(parents=True)
    file_path.write_bytes(b"abc")
    manifest = make_manifest(relative_path, sha256_file(file_path))

    result = verify_dataset_manifest(manifest, tmp_path)

    assert result.verified
    assert result.files[0].status is VerificationStatus.VERIFIED
    assert result.files[0].actual_sha256 == manifest.files[0].sha256


def test_verify_missing_file(tmp_path: Path) -> None:
    manifest = make_manifest(
        Path("data/missing.csv"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )

    result = verify_dataset_manifest(manifest, tmp_path)

    assert not result.verified
    assert result.files[0].status is VerificationStatus.MISSING_FILE
    assert result.files[0].actual_sha256 is None


def test_verify_missing_checksum(tmp_path: Path) -> None:
    relative_path = Path("data/sample.csv")
    file_path = tmp_path / relative_path
    file_path.parent.mkdir(parents=True)
    file_path.write_bytes(b"abc")
    manifest = make_manifest(relative_path, None)

    result = verify_dataset_manifest(manifest, tmp_path)

    assert not result.verified
    assert result.files[0].status is VerificationStatus.MISSING_CHECKSUM
    assert result.files[0].expected_sha256 is None


def test_verify_checksum_mismatch(tmp_path: Path) -> None:
    relative_path = Path("data/sample.csv")
    file_path = tmp_path / relative_path
    file_path.parent.mkdir(parents=True)
    file_path.write_bytes(b"abc")
    manifest = make_manifest(relative_path, "0" * 64)

    result = verify_dataset_manifest(manifest, tmp_path)

    assert not result.verified
    assert result.files[0].status is VerificationStatus.CHECKSUM_MISMATCH
    assert result.files[0].actual_sha256 == sha256_file(file_path)


def test_verify_symlink_outside_project_root(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    outside_file = tmp_path / "outside.csv"
    outside_file.write_bytes(b"abc")
    symlink_path = project_root / "dataset.csv"
    symlink_path.symlink_to(outside_file)
    manifest = make_manifest(Path("dataset.csv"), sha256_file(outside_file))

    result = verify_dataset_manifest(manifest, project_root)

    assert not result.verified
    assert result.files[0].status is VerificationStatus.OUTSIDE_PROJECT_ROOT
    assert result.files[0].actual_sha256 is None
