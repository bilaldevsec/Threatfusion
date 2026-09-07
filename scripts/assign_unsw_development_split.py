"""Create and audit the frozen UNSW grouped-development assignment."""

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

from threatfusion.datasets.unsw_development_split import (  # noqa: E402
    ASSIGNMENT_SEED,
    DEFAULT_ARTIFACT_BUDGET_BYTES,
    DEFAULT_BATCH_SIZE,
    DEFAULT_MINIMUM_FREE_BYTES,
    DEFAULT_SQLITE_CACHE_MIB,
    DevelopmentSplitConfig,
    UnswDevelopmentSplitError,
    run_unsw_development_split,
)

PROGRESS_INTERVAL_ROWS = 250_000


def _parser() -> argparse.ArgumentParser:
    project_root = SOURCE_ROOT.parents[1]
    preflight_root = project_root / "data/interim/unsw_split_preflight/full-f10992-v1"
    parser = argparse.ArgumentParser(
        description="Create the frozen UNSW grouped-development and chronological-test assignment."
    )
    parser.add_argument("--project-root", type=Path, default=project_root)
    parser.add_argument(
        "--manifest", type=Path, default=project_root / "data/manifests/unsw_nb15.yaml"
    )
    parser.add_argument(
        "--preflight-database", type=Path, default=preflight_root / "preflight.sqlite3"
    )
    parser.add_argument(
        "--preflight-report", type=Path, default=preflight_root / "preflight_report.json"
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=project_root / "data/interim/unsw_development_split",
    )
    parser.add_argument(
        "--run-id",
        default=datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
        help="Fresh run-directory name; existing directories are never reused.",
    )
    parser.add_argument("--seed", default=ASSIGNMENT_SEED)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--sqlite-cache-mib", type=int, default=DEFAULT_SQLITE_CACHE_MIB)
    parser.add_argument("--artifact-budget-bytes", type=int, default=DEFAULT_ARTIFACT_BUDGET_BYTES)
    parser.add_argument("--minimum-free-bytes", type=int, default=DEFAULT_MINIMUM_FREE_BYTES)
    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        help="Bounded smoke mode; output remains partial and cannot verify the final split.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run assignment construction while printing sanitized aggregate progress only."""
    args = _parser().parse_args(argv)
    started = time.monotonic()
    last_progress: dict[str, int] = {}

    def progress(phase: str, total: int) -> None:
        previous = last_progress.get(phase, 0)
        if total - previous < PROGRESS_INTERVAL_ROWS:
            return
        last_progress[phase] = total
        print(f"progress phase={phase} rows={total}", flush=True)

    try:
        result = run_unsw_development_split(
            project_root=args.project_root.resolve(),
            manifest_path=args.manifest.resolve(),
            preflight_database=args.preflight_database.resolve(),
            preflight_report=args.preflight_report.resolve(),
            artifact_root=args.artifact_root.resolve(),
            run_id=args.run_id,
            config=DevelopmentSplitConfig(
                seed=args.seed,
                batch_size=args.batch_size,
                sqlite_cache_mib=args.sqlite_cache_mib,
                artifact_budget_bytes=args.artifact_budget_bytes,
                minimum_free_bytes=args.minimum_free_bytes,
                max_rows_per_file=args.max_rows_per_file,
            ),
            progress=progress,
        )
    except (UnswDevelopmentSplitError, ValueError) as exc:
        code = exc.code if isinstance(exc, UnswDevelopmentSplitError) else "invalid_configuration"
        print(f"assignment failed code={code}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started
    artifact_size = sum(
        path.stat().st_size for path in result.report_path.parent.iterdir() if path.is_file()
    )
    print(
        f"assignment completed={str(result.completed).lower()} total={result.total_rows} "
        f"elapsed_seconds={elapsed:.3f} artifact_size_bytes={artifact_size} "
        f"report={result.report_path.name} assignments={result.assignment_path.name}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
