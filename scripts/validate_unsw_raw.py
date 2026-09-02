"""Stream and validate the four official UNSW-NB15 raw CSV files."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.datasets.adapters.unsw_nb15 import adapt_unsw_row
from threatfusion.datasets.batch import BatchQualityReport, stream_adapt_rows, write_quality_report
from threatfusion.datasets.manifests import load_dataset_manifest, write_dataset_manifest
from threatfusion.datasets.unsw_raw import UnswRawReader, read_unsw_feature_names
from threatfusion.schemas.dataset_manifest import DatasetFile
from threatfusion.utils.checksum import sha256_file

RAW_FILENAMES: tuple[str, ...] = tuple(f"UNSW-NB15_{part}.csv" for part in range(1, 5))
FEATURE_FILENAME = "NUSW-NB15_features.csv"
REJECTION_EXAMPLE_LIMIT = 20


@dataclass(frozen=True, slots=True)
class FileValidationResult:
    """Non-row validation metadata for one raw input file."""

    path: Path
    size_bytes: int
    sha256: str
    report_path: Path
    report: BatchQualityReport


def validate_raw_file(
    raw_file: Path,
    feature_names: tuple[str, ...],
    report_path: Path,
) -> FileValidationResult:
    """Validate one raw file in a bounded-memory streaming pass."""
    report = BatchQualityReport(
        source=f"UNSW-NB15/{raw_file.name}",
        rejection_example_limit=REJECTION_EXAMPLE_LIMIT,
    )
    rows = UnswRawReader(feature_names=feature_names, raw_files=(raw_file,))

    # Exhaust the lazy adapter without collecting any accepted NetworkFlow objects.
    for _record in stream_adapt_rows(rows, adapt_unsw_row, report):
        pass

    write_quality_report(report, report_path)
    return FileValidationResult(
        path=raw_file,
        size_bytes=raw_file.stat().st_size,
        sha256=sha256_file(raw_file),
        report_path=report_path,
        report=report,
    )


def update_raw_manifest(
    manifest_path: Path,
    project_root: Path,
    feature_file: Path,
    results: Sequence[FileValidationResult],
) -> None:
    """Add or replace the exact raw inputs while retaining other manifest entries."""
    manifest = load_dataset_manifest(manifest_path)
    raw_paths = {result.path.resolve() for result in results}
    raw_paths.add(feature_file.resolve())

    retained_files = [
        item for item in manifest.files if (project_root / item.path).resolve() not in raw_paths
    ]
    retained_files.append(
        DatasetFile(
            path=feature_file.relative_to(project_root),
            sha256=sha256_file(feature_file),
            rows=len(read_unsw_feature_names(feature_file)),
            role="raw",
        )
    )
    retained_files.extend(
        DatasetFile(
            path=result.path.relative_to(project_root),
            sha256=result.sha256,
            rows=result.report.total_rows,
            role="raw",
        )
        for result in results
    )
    manifest.files = retained_files
    write_dataset_manifest(manifest, manifest_path)


def run_validation(
    project_root: Path,
    raw_directory: Path,
    report_directory: Path,
    manifest_path: Path,
) -> tuple[FileValidationResult, ...]:
    """Validate all official partitions and update their reproducibility manifest."""
    feature_file = raw_directory / FEATURE_FILENAME
    feature_names = read_unsw_feature_names(feature_file)
    results = tuple(
        validate_raw_file(
            raw_directory / filename,
            feature_names,
            report_directory / f"{Path(filename).stem}_quality.json",
        )
        for filename in RAW_FILENAMES
    )
    update_raw_manifest(manifest_path, project_root, feature_file, results)
    return results


def _parser() -> argparse.ArgumentParser:
    project_root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(
        description="Stream-validate all four official UNSW-NB15 raw CSV partitions."
    )
    parser.add_argument("--project-root", type=Path, default=project_root)
    parser.add_argument(
        "--raw-directory",
        type=Path,
        default=project_root / "data/raw/unsw_nb15/official",
    )
    parser.add_argument(
        "--report-directory",
        type=Path,
        default=project_root / "artifacts/reports/unsw_nb15",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=project_root / "data/manifests/unsw_nb15.yaml",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point."""
    args = _parser().parse_args(argv)
    results = run_validation(
        project_root=args.project_root.resolve(),
        raw_directory=args.raw_directory.resolve(),
        report_directory=args.report_directory.resolve(),
        manifest_path=args.manifest.resolve(),
    )
    for result in results:
        report = result.report
        reasons = sorted({detail.reason for detail in report.rejection_details})
        print(
            f"{result.path.name}: total={report.total_rows} accepted={report.accepted_count} "
            f"rejected={report.rejected_count} rejection_rate={report.rejection_rate:.8%} "
            f"size_bytes={result.size_bytes} sha256={result.sha256} "
            f"reasons={reasons} report={result.report_path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
