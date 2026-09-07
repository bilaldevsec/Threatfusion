"""Fit and apply the first train-only network_behavior_v1 preprocessing pipeline."""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.preprocessing.network_behavior_v1 import (  # noqa: E402
    DEFAULT_ARTIFACT_BUDGET_BYTES,
    DEFAULT_BATCH_SIZE,
    DEFAULT_MINIMUM_FREE_BYTES,
    NetworkPreprocessingError,
    PreprocessingConfig,
    run_unsw_network_preprocessing,
    smoke_check_unsw_network_preprocessing,
)


def _parser() -> argparse.ArgumentParser:
    project_root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(
        description=(
            "Verify the frozen UNSW assignment, fit preprocessing on TRAIN only, and transform "
            "TRAIN/VALIDATION only."
        )
    )
    parser.add_argument("--project-root", type=Path, default=project_root)
    parser.add_argument(
        "--manifest", type=Path, default=project_root / "data/manifests/unsw_nb15.yaml"
    )
    parser.add_argument(
        "--assignment-directory",
        type=Path,
        default=(project_root / "data/interim/unsw_development_split/full-assignment-f10992-v1"),
    )
    parser.add_argument(
        "--preflight-report",
        type=Path,
        default=(
            project_root / "data/interim/unsw_split_preflight/full-f10992-v1/preflight_report.json"
        ),
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=project_root / "data/processed/unsw_network_preprocessing",
    )
    parser.add_argument(
        "--run-id",
        default=datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
        help="Fresh output directory name; existing directories are never reused.",
    )
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--artifact-budget-bytes", type=int, default=DEFAULT_ARTIFACT_BUDGET_BYTES)
    parser.add_argument("--minimum-free-bytes", type=int, default=DEFAULT_MINIMUM_FREE_BYTES)
    parser.add_argument(
        "--smoke-records",
        type=int,
        help=(
            "Verify all input/evidence hashes and exercise only this many joined source rows; "
            "does not create fitted state or transformed artifacts."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    started = time.monotonic()
    try:
        if args.smoke_records is not None:
            counts = smoke_check_unsw_network_preprocessing(
                project_root=args.project_root.resolve(),
                manifest_path=args.manifest.resolve(),
                assignment_directory=args.assignment_directory.resolve(),
                preflight_report_path=args.preflight_report.resolve(),
                max_records=args.smoke_records,
            )
            print(
                "smoke completed=true "
                + " ".join(f"{name}={value}" for name, value in counts.items())
                + f" elapsed_seconds={time.monotonic() - started:.3f}"
            )
            return 0

        last_progress = 0

        def progress(processed: int, total: int) -> None:
            nonlocal last_progress
            if processed - last_progress >= 250_000:
                last_progress = processed
                print(f"progress processed={processed} total={total}", flush=True)

        result = run_unsw_network_preprocessing(
            project_root=args.project_root.resolve(),
            manifest_path=args.manifest.resolve(),
            assignment_directory=args.assignment_directory.resolve(),
            preflight_report_path=args.preflight_report.resolve(),
            artifact_root=args.artifact_root.resolve(),
            run_id=args.run_id,
            config=PreprocessingConfig(
                batch_size=args.batch_size,
                artifact_budget_bytes=args.artifact_budget_bytes,
                minimum_free_bytes=args.minimum_free_bytes,
            ),
            progress=progress,
        )
    except (NetworkPreprocessingError, ValueError) as exc:
        code = exc.code if isinstance(exc, NetworkPreprocessingError) else "invalid_configuration"
        print(f"preprocessing failed code={code}", file=sys.stderr)
        return 1
    print(
        f"preprocessing completed=true train={result.train_rows} "
        f"validation={result.validation_rows} output_features={result.output_features} "
        f"elapsed_seconds={result.elapsed_seconds:.3f} report={result.report_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
