"""Run the authorized fixed Random Forest network baseline."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

# Random Forest owns four workers; keep nested numeric runtimes single-threaded.
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

from threatfusion.models.network_logistic_baseline import NetworkBaselineError  # noqa: E402
from threatfusion.models.network_random_forest_baseline import (  # noqa: E402
    run_network_random_forest_baseline,
)


def _parser() -> argparse.ArgumentParser:
    project_root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(
        description="Fit fixed Random Forest on full TRAIN and evaluate VALIDATION only."
    )
    parser.add_argument("--project-root", type=Path, default=project_root)
    parser.add_argument(
        "--preprocessing-run",
        type=Path,
        default=(
            project_root / "data/processed/unsw_network_preprocessing/full-train-only-0141bde-v1"
        ),
    )
    parser.add_argument(
        "--logistic-run",
        type=Path,
        default=(
            project_root
            / "artifacts/models/network_logistic_baseline/full-network-logistic-5e70ed9-v1"
        ),
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=project_root / "artifacts/models/network_random_forest_baseline",
    )
    parser.add_argument(
        "--run-id",
        default=datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
        help="Fresh ignored run-directory name; existing directories are never reused.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = run_network_random_forest_baseline(
            project_root=args.project_root.resolve(),
            preprocessing_run_directory=args.preprocessing_run.resolve(),
            logistic_run_directory=args.logistic_run.resolve(),
            artifact_root=args.artifact_root.resolve(),
            run_id=args.run_id,
        )
    except (NetworkBaselineError, ValueError) as exc:
        code = exc.code if isinstance(exc, NetworkBaselineError) else "invalid_configuration"
        print(f"random forest baseline failed code={code}", file=sys.stderr)
        return 1
    print(
        f"random forest baseline completed=true elapsed_seconds={result.elapsed_seconds:.3f} "
        f"report={result.report_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
