from pathlib import Path

import pytest
from pydantic import ValidationError

from threatfusion.schemas.dataset_manifest import DatasetManifest


def test_dataset_manifest_schema() -> None:
    manifest = DatasetManifest.model_validate(
        {
            "name": "unsw_nb15",
            "version": "official_train_test_split",
            "source_url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "license_note": "Academic research dataset; verify redistribution limits.",
            "files": [
                {
                    "path": "data/raw/unsw/UNSW_NB15_training-set.csv",
                    "sha256": None,
                    "rows": 175341,
                    "role": "train",
                }
            ],
            "notes": "Used for single-label multiclass network attack classification.",
        }
    )

    assert manifest.name == "unsw_nb15"
    assert manifest.files[0].role == "train"


@pytest.mark.parametrize(
    "sha256",
    [
        "too-short",
        "A" * 64,
        "g" * 64,
    ],
)
def test_dataset_manifest_rejects_malformed_sha256(sha256: str) -> None:
    with pytest.raises(ValidationError):
        DatasetManifest.model_validate(
            {
                "name": "unsw_nb15",
                "version": "test",
                "license_note": "Test fixture only.",
                "files": [
                    {
                        "path": "data/raw/sample.csv",
                        "sha256": sha256,
                        "role": "sample",
                    }
                ],
            }
        )


def test_dataset_file_rejects_absolute_path(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="path must be project-relative"):
        DatasetManifest.model_validate(
            {
                "name": "unsw_nb15",
                "version": "test",
                "license_note": "Test fixture only.",
                "files": [{"path": tmp_path / "sample.csv", "role": "sample"}],
            }
        )


def test_dataset_file_rejects_traversal_path() -> None:
    with pytest.raises(ValidationError, match="path must not contain"):
        DatasetManifest.model_validate(
            {
                "name": "unsw_nb15",
                "version": "test",
                "license_note": "Test fixture only.",
                "files": [{"path": "data/../sample.csv", "role": "sample"}],
            }
        )


def test_dataset_manifest_rejects_empty_files() -> None:
    with pytest.raises(ValidationError):
        DatasetManifest.model_validate(
            {
                "name": "unsw_nb15",
                "version": "test",
                "license_note": "Test fixture only.",
                "files": [],
            }
        )
