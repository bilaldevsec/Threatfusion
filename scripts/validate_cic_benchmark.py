"""Fully stream-validate the approved processed CSE-CIC-IDS2018 subset."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.datasets.adapters.cic_ids2018_benchmark import adapt_cic_benchmark_row
from threatfusion.datasets.batch import BatchQualityReport, stream_adapt_rows
from threatfusion.datasets.cic_processed import CIC_PROCESSED_COLUMN_COUNT, CicProcessedReader
from threatfusion.datasets.manifests import load_dataset_manifest, verify_dataset_manifest
from threatfusion.schemas.dataset_manifest import DatasetManifest
from threatfusion.schemas.network_benchmark import NetworkBenchmarkRecord

REJECTION_EXAMPLE_LIMIT = 20


class CicBenchmarkValidationError(RuntimeError):
    """A safe failure showing that the approved benchmark is not ready."""


@dataclass(frozen=True, slots=True)
class CicBenchmarkValidationResult:
    """Safe aggregate result for one fully consumed benchmark file."""

    report_path: Path
    payload: dict[str, Any]


def _report_payload(
    report: BatchQualityReport,
    source_file: str,
    canonical_labels: Counter[str],
    attack_categories: Counter[str],
) -> dict[str, Any]:
    payload = report.to_dict()
    payload.update(
        {
            "source_file": source_file,
            "expected_column_count": CIC_PROCESSED_COLUMN_COUNT,
            "canonical_label_counts": dict(sorted(canonical_labels.items())),
            "attack_category_counts": dict(sorted(attack_categories.items())),
        }
    )
    return payload


def _write_report(payload: dict[str, Any], report_path: Path) -> None:
    if payload.get("completed") is not True:
        raise ValueError("cannot write an incomplete CIC benchmark report")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def validate_cic_benchmark_file(
    path: Path,
    report_path: Path,
    *,
    expected_rows: int,
    adapter: Callable[[dict[str, Any]], NetworkBenchmarkRecord] = adapt_cic_benchmark_row,
) -> CicBenchmarkValidationResult:
    """Fully consume one file while retaining only bounded safe aggregates."""
    report = BatchQualityReport(
        source=f"CSE-CIC-IDS2018 benchmark/{path.name}",
        rejection_example_limit=REJECTION_EXAMPLE_LIMIT,
    )
    canonical_labels: Counter[str] = Counter()
    attack_categories: Counter[str] = Counter()

    for record in stream_adapt_rows(CicProcessedReader(path), adapter, report):
        canonical_labels[record.label] += 1
        if record.attack_name is not None:
            attack_categories[record.attack_name] += 1

    if report.total_rows != expected_rows:
        raise CicBenchmarkValidationError(
            f"{path.name}: expected {expected_rows} rows, found {report.total_rows}"
        )
    payload = _report_payload(report, path.name, canonical_labels, attack_categories)
    _write_report(payload, report_path)
    return CicBenchmarkValidationResult(report_path=report_path, payload=payload)


def _verified_manifest(project_root: Path, manifest_path: Path) -> DatasetManifest:
    manifest = load_dataset_manifest(manifest_path)
    if manifest.name != "cse_cic_ids2018":
        raise CicBenchmarkValidationError("manifest is not for cse_cic_ids2018")
    verification = verify_dataset_manifest(manifest, project_root)
    if not verification.verified:
        failures = ", ".join(
            f"{result.path.name}:{result.status.value}"
            for result in verification.files
            if not result.verified
        )
        raise CicBenchmarkValidationError(f"manifest verification failed: {failures}")
    return manifest


def run_validation(
    project_root: Path,
    manifest_path: Path,
    report_directory: Path,
) -> tuple[CicBenchmarkValidationResult, ...]:
    """Verify the manifest and fully validate every declared benchmark file."""
    manifest = _verified_manifest(project_root, manifest_path)
    results: list[CicBenchmarkValidationResult] = []
    for dataset_file in manifest.files:
        if dataset_file.role != "validation" or dataset_file.rows is None:
            raise CicBenchmarkValidationError(
                f"{dataset_file.path.name}: expected validation role and declared row count"
            )
        source_path = project_root / dataset_file.path
        report_path = report_directory / f"{source_path.stem}_quality.json"
        results.append(
            validate_cic_benchmark_file(
                source_path,
                report_path,
                expected_rows=dataset_file.rows,
            )
        )
    return tuple(results)


def _parser() -> argparse.ArgumentParser:
    project_root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=project_root)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=project_root / "data/manifests/cse_cic_ids2018.yaml",
    )
    parser.add_argument(
        "--report-directory",
        type=Path,
        default=project_root / "artifacts/reports/cse_cic_ids2018",
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
    except CicBenchmarkValidationError as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1

    for result in results:
        payload = result.payload
        print(
            f"{payload['source_file']}: total={payload['total_rows']} "
            f"accepted={payload['accepted_count']} rejected={payload['rejected_count']} "
            f"rejection_rate={payload['rejection_rate']:.8%} report={result.report_path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
