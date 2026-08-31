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
