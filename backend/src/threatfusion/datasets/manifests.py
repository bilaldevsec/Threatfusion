"""YAML persistence and integrity verification for dataset manifests."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from threatfusion.schemas.dataset_manifest import DatasetManifest
from threatfusion.utils.checksum import sha256_file


class VerificationStatus(str, Enum):
    """Possible integrity outcomes for one dataset file."""

    VERIFIED = "verified"
    MISSING_FILE = "missing_file"
    MISSING_CHECKSUM = "missing_checksum"
    CHECKSUM_MISMATCH = "checksum_mismatch"
    OUTSIDE_PROJECT_ROOT = "outside_project_root"


@dataclass(frozen=True)
class DatasetFileVerification:
    """Integrity result for one file declared in a dataset manifest."""

    path: Path
    status: VerificationStatus
    expected_sha256: str | None
    actual_sha256: str | None = None

    @property
    def verified(self) -> bool:
        return self.status is VerificationStatus.VERIFIED


@dataclass(frozen=True)
class ManifestVerificationResult:
    """Aggregate integrity result for every file in a manifest."""

    files: tuple[DatasetFileVerification, ...]

    @property
    def verified(self) -> bool:
        return all(file.verified for file in self.files)


def load_dataset_manifest(path: Path) -> DatasetManifest:
    """Load and validate a dataset manifest from YAML."""
    with path.open(encoding="utf-8") as manifest_file:
        data: Any = yaml.safe_load(manifest_file)
    return DatasetManifest.model_validate(data)


def write_dataset_manifest(manifest: DatasetManifest, path: Path) -> None:
    """Write a validated dataset manifest as YAML."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as manifest_file:
        yaml.safe_dump(
            manifest.model_dump(mode="json"),
            manifest_file,
            sort_keys=False,
        )


def verify_dataset_manifest(
    manifest: DatasetManifest, project_root: Path
) -> ManifestVerificationResult:
    """Verify every file in a manifest relative to a project root."""
    results: list[DatasetFileVerification] = []
    resolved_project_root = project_root.resolve()

    for dataset_file in manifest.files:
        file_path = (resolved_project_root / dataset_file.path).resolve()
        if not file_path.is_relative_to(resolved_project_root):
            status = VerificationStatus.OUTSIDE_PROJECT_ROOT
            actual_sha256 = None
        elif not file_path.is_file():
            status = VerificationStatus.MISSING_FILE
            actual_sha256 = None
        elif dataset_file.sha256 is None:
            status = VerificationStatus.MISSING_CHECKSUM
            actual_sha256 = None
        else:
            actual_sha256 = sha256_file(file_path)
            status = (
                VerificationStatus.VERIFIED
                if actual_sha256 == dataset_file.sha256
                else VerificationStatus.CHECKSUM_MISMATCH
            )

        results.append(
            DatasetFileVerification(
                path=dataset_file.path,
                status=status,
                expected_sha256=dataset_file.sha256,
                actual_sha256=actual_sha256,
            )
        )

    return ManifestVerificationResult(files=tuple(results))
