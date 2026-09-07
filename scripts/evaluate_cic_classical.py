"""Evaluate saved classical network models on the two registered CIC exports."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

for variable in (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "BLIS_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
    "NUMEXPR_NUM_THREADS",
):
    os.environ[variable] = "1"

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.models.network_cic_external_evaluation import (  # noqa: E402
    NetworkBaselineError,
    run_cic_external_evaluation,
    run_cic_smoke,
)


def _parser() -> argparse.ArgumentParser:
    root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=root)
    parser.add_argument(
        "--manifest", type=Path, default=root / "data/manifests/cse_cic_ids2018.yaml"
    )
    parser.add_argument(
        "--quality-directory", type=Path, default=root / "artifacts/reports/cse_cic_ids2018"
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=root / "artifacts/reports/cse_cic_ids2018/cse_cic_ids2018_profile.json",
    )
    parser.add_argument(
        "--preprocessing-directory",
        type=Path,
        default=root / "data/processed/unsw_network_preprocessing/full-train-only-0141bde-v1",
    )
    parser.add_argument(
        "--logistic-directory",
        type=Path,
        default=root
        / "artifacts/models/network_logistic_baseline/full-network-logistic-5e70ed9-v1",
    )
    parser.add_argument(
        "--forest-directory",
        type=Path,
        default=root
        / "artifacts/models/network_random_forest_baseline/full-network-random-forest-6d69c72-v1",
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=root / "artifacts/reports/network_cic_external_evaluation",
    )
    parser.add_argument("--run-id", default=datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--batch-size", type=int, default=10_000)
    parser.add_argument("--smoke-records-per-file", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    common = {
        "project_root": args.project_root.resolve(),
        "manifest_path": args.manifest.resolve(),
        "quality_directory": args.quality_directory.resolve(),
        "profile_path": args.profile.resolve(),
        "preprocessing_directory": args.preprocessing_directory.resolve(),
        "logistic_directory": args.logistic_directory.resolve(),
        "forest_directory": args.forest_directory.resolve(),
        "artifact_root": args.artifact_root.resolve(),
        "run_id": args.run_id,
    }
    try:
        if args.smoke_records_per_file is not None:
            path = run_cic_smoke(**common, max_records_per_file=args.smoke_records_per_file)
            print(f"smoke partial=true completed=false report={path}")
            return 0

        result = run_cic_external_evaluation(
            **common,
            batch_size=args.batch_size,
            progress=lambda stage: print(f"progress stage={stage}", flush=True),
        )
    except (NetworkBaselineError, ValueError) as exc:
        print(
            f"CIC evaluation failed code={getattr(exc, 'code', 'invalid_configuration')}",
            file=sys.stderr,
        )
        return 1
    print(
        f"CIC evaluation completed=true accepted={result.accepted_rows} "
        f"rejected={result.rejected_rows} elapsed_seconds={result.elapsed_seconds:.3f} "
        f"report={result.report_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
