"""Stream-profile the registered CSE-CIC-IDS2018 benchmark exports."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.datasets.cic_profile import profile_cic_files, write_cic_profile
from threatfusion.datasets.manifests import load_dataset_manifest, verify_dataset_manifest


class CicProfileError(RuntimeError):
    """A safe failure showing that the registered benchmark is not profile-ready."""


def run_profile(project_root: Path, manifest_path: Path, report_path: Path) -> dict[str, Any]:
    """Verify, stream-profile, and report on all registered CIC benchmark files."""
    manifest = load_dataset_manifest(manifest_path)
    if manifest.name != "cse_cic_ids2018":
        raise CicProfileError("manifest is not for cse_cic_ids2018")

    verification = verify_dataset_manifest(manifest, project_root)
    if not verification.verified:
        failures = ", ".join(
            f"{result.path.name}:{result.status.value}"
            for result in verification.files
            if not result.verified
        )
        raise CicProfileError(f"manifest verification failed: {failures}")

    expected_rows: dict[str, int] = {}
    paths: list[Path] = []
    for dataset_file in manifest.files:
        if dataset_file.role != "validation" or dataset_file.rows is None:
            raise CicProfileError(
                f"{dataset_file.path.name}: expected validation role and declared row count"
            )
        expected_rows[dataset_file.path.name] = dataset_file.rows
        paths.append(project_root / dataset_file.path)

    profile = profile_cic_files(paths)
    for file_profile in profile.files:
        expected = expected_rows[file_profile.source_file]
        if file_profile.quality.total_rows != expected:
            raise CicProfileError(
                f"{file_profile.source_file}: expected {expected} rows, "
                f"found {file_profile.quality.total_rows}"
            )

    write_cic_profile(profile, report_path)
    return profile.to_dict()


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
        "--report",
        type=Path,
        default=(project_root / "artifacts/reports/cse_cic_ids2018/cse_cic_ids2018_profile.json"),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point."""
    args = _parser().parse_args(argv)
    try:
        payload = run_profile(
            args.project_root.resolve(), args.manifest.resolve(), args.report.resolve()
        )
    except CicProfileError as exc:
        print(f"profiling failed: {exc}", file=sys.stderr)
        return 1

    for file_profile in payload["files"]:
        print(
            f"{file_profile['source_file']}: total={file_profile['total_rows']} "
            f"accepted={file_profile['accepted_count']} "
            f"rejected={file_profile['rejected_count']} "
            f"rejection_rate={file_profile['rejection_rate']:.8%}"
        )
    combined = payload["combined"]
    print(
        f"combined: total={combined['total_rows']} accepted={combined['accepted_count']} "
        f"rejected={combined['rejected_count']} "
        f"rejection_rate={combined['rejection_rate']:.8%} report={args.report.resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
