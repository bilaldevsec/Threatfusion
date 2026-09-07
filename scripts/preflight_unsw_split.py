"""Run disk-backed diagnostics required before designing an UNSW split assignment."""

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

from threatfusion.datasets.unsw_split_preflight import (  # noqa: E402
    DEFAULT_BATCH_SIZE,
    DEFAULT_DISK_BUDGET_BYTES,
    DEFAULT_MINIMUM_FREE_BYTES,
    DEFAULT_SQLITE_CACHE_MIB,
    PreflightConfig,
    UnswSplitPreflightError,
    run_unsw_split_preflight,
)

PROGRESS_INTERVAL_ROWS = 250_000


def _parser() -> argparse.ArgumentParser:
    project_root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(
        description="Run diagnostic-only UNSW split preflight with bounded SQLite working state."
    )
    parser.add_argument("--project-root", type=Path, default=project_root)
    parser.add_argument(
        "--manifest", type=Path, default=project_root / "data/manifests/unsw_nb15.yaml"
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=project_root / "data/interim/unsw_split_preflight",
    )
    parser.add_argument(
        "--run-id",
        default=datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
        help="New run-directory name; an existing directory is never reused.",
    )
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--sqlite-cache-mib", type=int, default=DEFAULT_SQLITE_CACHE_MIB)
    parser.add_argument("--disk-budget-bytes", type=int, default=DEFAULT_DISK_BUDGET_BYTES)
    parser.add_argument("--minimum-free-bytes", type=int, default=DEFAULT_MINIMUM_FREE_BYTES)
    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        help="Bounded smoke mode; its report is always completed=false and run_scope=partial.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the preflight and print only sanitized aggregate status."""
    args = _parser().parse_args(argv)
    started = time.monotonic()
    last_progress_total = 0

    def progress(source_file: str, total: int, accepted: int, rejected: int) -> None:
        nonlocal last_progress_total
        if total - last_progress_total < PROGRESS_INTERVAL_ROWS:
            return
        last_progress_total = total
        print(
            f"progress source={source_file} total={total} accepted={accepted} rejected={rejected}",
            flush=True,
        )

    try:
        result = run_unsw_split_preflight(
            project_root=args.project_root.resolve(),
            manifest_path=args.manifest.resolve(),
            artifact_root=args.artifact_root.resolve(),
            run_id=args.run_id,
            config=PreflightConfig(
                batch_size=args.batch_size,
                sqlite_cache_mib=args.sqlite_cache_mib,
                disk_budget_bytes=args.disk_budget_bytes,
                minimum_free_bytes=args.minimum_free_bytes,
                max_rows_per_file=args.max_rows_per_file,
            ),
            progress=progress,
        )
    except (UnswSplitPreflightError, ValueError) as exc:
        code = exc.code if isinstance(exc, UnswSplitPreflightError) else "invalid_configuration"
        print(f"preflight failed code={code}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started
    artifact_size = sum(
        path.stat().st_size for path in result.report_path.parent.iterdir() if path.is_file()
    )
    print(
        f"preflight completed={str(result.completed).lower()} total={result.total} "
        f"accepted={result.accepted} rejected={result.rejected} "
        f"elapsed_seconds={elapsed:.3f} artifact_size_bytes={artifact_size} "
        f"report={result.report_path.name}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
