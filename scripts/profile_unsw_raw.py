"""Stream-profile the four official UNSW-NB15 raw CSV files."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.datasets.unsw_profile import profile_unsw_rows, write_unsw_profile
from threatfusion.datasets.unsw_raw import UnswRawReader

RAW_FILENAMES: tuple[str, ...] = tuple(f"UNSW-NB15_{part}.csv" for part in range(1, 5))
FEATURE_FILENAME = "NUSW-NB15_features.csv"


def run_profile(raw_directory: Path, report_path: Path) -> dict[str, object]:
    """Profile every official raw partition and write one aggregate report."""
    raw_files = tuple(raw_directory / filename for filename in RAW_FILENAMES)
    rows = UnswRawReader.from_feature_file(raw_directory / FEATURE_FILENAME, raw_files)
    profile = profile_unsw_rows(rows)
    write_unsw_profile(profile, report_path)
    return profile.to_dict()


def _parser() -> argparse.ArgumentParser:
    project_root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(
        description="Stream-profile all four official UNSW-NB15 raw CSV partitions."
    )
    parser.add_argument(
        "--raw-directory",
        type=Path,
        default=project_root / "data/raw/unsw_nb15/official",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=project_root / "artifacts/reports/unsw_nb15/unsw_nb15_profile.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point."""
    args = _parser().parse_args(argv)
    report = run_profile(args.raw_directory.resolve(), args.report.resolve())
    print(
        f"profiled total={report['total_input_rows']} accepted={report['accepted_count']} "
        f"rejected={report['rejected_count']} report={args.report.resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
