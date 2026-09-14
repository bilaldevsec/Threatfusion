"""Run a fresh versioned benign-only UNSW autoencoder experiment."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
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

from threatfusion.models.network_autoencoder import (  # noqa: E402
    NetworkAutoencoderError,
    run_full_autoencoder,
    run_synthetic_smoke,
)
from threatfusion.models.network_logistic_baseline import NetworkBaselineError  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(
        description="Run a fresh versioned benign-only UNSW autoencoder."
    )
    parser.add_argument("--smoke", action="store_true", help="Run bounded synthetic smoke only.")
    parser.add_argument("--run-id", help="Fresh ignored full-run directory name.")
    parser.add_argument("--project-root", type=Path, default=root)
    parser.add_argument(
        "--preprocessing-directory",
        type=Path,
        default=root / "data/processed/unsw_network_preprocessing/full-train-only-0141bde-v1",
    )
    parser.add_argument(
        "--forest-directory",
        type=Path,
        default=root
        / "artifacts/models/network_random_forest_baseline/full-network-random-forest-6d69c72-v1",
    )
    parser.add_argument(
        "--february-directory",
        type=Path,
        default=root
        / "artifacts/reports/network_classical_evaluation/full-february-classical-2528ee8-v1",
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=root / "artifacts/models/network_autoencoder",
    )
    parser.add_argument(
        "--protocol",
        type=Path,
        default=root / "docs/network_autoencoder_protocol.md",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.smoke:
            if args.run_id is not None:
                raise NetworkAutoencoderError("smoke_run_id_not_allowed")
            result = run_synthetic_smoke()
            print(
                f"autoencoder smoke completed=true epochs={result['epochs']} "
                f"samples={result['sample_count']} final_batches={result['final_epoch_batch_sizes']}"
            )
            return 0
        if args.run_id is None:
            raise NetworkAutoencoderError("run_id_required")
        result = run_full_autoencoder(
            project_root=args.project_root.resolve(),
            preprocessing_directory=args.preprocessing_directory.resolve(),
            forest_directory=args.forest_directory.resolve(),
            february_directory=args.february_directory.resolve(),
            artifact_root=args.artifact_root.resolve(),
            run_id=args.run_id,
            protocol_path=args.protocol.resolve(),
        )
    except (NetworkAutoencoderError, NetworkBaselineError, ValueError) as exc:
        print(
            f"autoencoder failed code={getattr(exc, 'code', 'invalid_configuration')}",
            file=sys.stderr,
        )
        return 1
    print(
        f"autoencoder completed=true threshold={result.threshold:.17g} "
        f"elapsed_seconds={result.elapsed_seconds:.3f} report={result.report_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
