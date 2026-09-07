"""Verify and stream-validate the registered Mordor NDJSON sample."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.datasets.adapters.mordor import adapt_mordor_row  # noqa: E402
from threatfusion.datasets.batch import (  # noqa: E402
    BatchQualityReport,
    stream_adapt_rows,
    write_quality_report,
)
from threatfusion.datasets.manifests import (  # noqa: E402
    load_dataset_manifest,
    verify_dataset_manifest,
)
from threatfusion.datasets.mordor_raw import MordorNdjsonReader, MordorStructureError  # noqa: E402

REJECTION_EXAMPLE_LIMIT = 20


class MordorValidationError(RuntimeError):
    """A sanitized failure showing that the registered sample is not ready."""


@dataclass(frozen=True, slots=True)
class MordorValidationResult:
    """Aggregate-only result from one complete streaming validation."""

    source_file: str
    report_path: Path
    report: BatchQualityReport


def validate_mordor_file(
    source_path: Path, report_path: Path, *, expected_rows: int
) -> MordorValidationResult:
    """Fully consume one registered file and write only its quality aggregates."""
    report = BatchQualityReport(
        source=f"Mordor/{source_path.name}",
        rejection_example_limit=REJECTION_EXAMPLE_LIMIT,
    )
    for _event in stream_adapt_rows(MordorNdjsonReader(source_path), adapt_mordor_row, report):
        pass
    if report.total_rows != expected_rows:
        raise MordorValidationError(
            f"{source_path.name}: expected {expected_rows} rows, found {report.total_rows}"
        )
    write_quality_report(report, report_path)
    return MordorValidationResult(source_path.name, report_path, report)


def run_validation(
    project_root: Path, manifest_path: Path, report_directory: Path
) -> tuple[MordorValidationResult, ...]:
    """Verify the manifest, then validate every registered Mordor test file."""
    manifest = load_dataset_manifest(manifest_path)
    if manifest.name != "mordor":
        raise MordorValidationError("manifest is not for mordor")
    verification = verify_dataset_manifest(manifest, project_root)
    if not verification.verified:
        failures = ", ".join(
            f"{item.path.name}:{item.status.value}"
            for item in verification.files
            if not item.verified
        )
        raise MordorValidationError(f"manifest verification failed: {failures}")

    results: list[MordorValidationResult] = []
    for item in manifest.files:
        if item.role != "test" or item.rows is None:
            raise MordorValidationError(
                f"{item.path.name}: expected test role and declared row count"
            )
        source_path = project_root / item.path
        results.append(
            validate_mordor_file(
                source_path,
                report_directory / f"{source_path.stem}_quality.json",
                expected_rows=item.rows,
            )
        )
    return tuple(results)


def _parser() -> argparse.ArgumentParser:
    project_root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=project_root)
    parser.add_argument(
        "--manifest", type=Path, default=project_root / "data/manifests/mordor.yaml"
    )
    parser.add_argument(
        "--report-directory",
        type=Path,
        default=project_root / "artifacts/reports/mordor",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point."""
    args = _parser().parse_args(argv)
    try:
        results = run_validation(
            args.project_root.resolve(),
            args.manifest.resolve(),
            args.report_directory.resolve(),
        )
    except (MordorValidationError, MordorStructureError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1

    for result in results:
        report = result.report
        reasons = sorted({detail.reason for detail in report.rejection_details})
        print(
            f"{result.source_file}: total={report.total_rows} "
            f"accepted={report.accepted_count} rejected={report.rejected_count} "
            f"rejection_rate={report.rejection_rate:.8%} completed={report.completed} "
            f"reasons={reasons} report={result.report_path.name}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
