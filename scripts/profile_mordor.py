"""Verify and stream-profile the registered Mordor NDJSON sample."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.datasets.manifests import (  # noqa: E402
    load_dataset_manifest,
    verify_dataset_manifest,
)
from threatfusion.datasets.mordor_profile import (  # noqa: E402
    profile_mordor_rows,
    write_mordor_profile,
)
from threatfusion.datasets.mordor_raw import MordorNdjsonReader, MordorStructureError  # noqa: E402


class MordorProfileError(RuntimeError):
    """A sanitized failure showing that the registered sample is not profile-ready."""


def run_profile(project_root: Path, manifest_path: Path, report_path: Path) -> dict[str, Any]:
    """Verify and fully stream-profile the single registered Mordor sample."""
    manifest = load_dataset_manifest(manifest_path)
    if manifest.name != "mordor" or len(manifest.files) != 1:
        raise MordorProfileError("manifest must contain one mordor file")
    verification = verify_dataset_manifest(manifest, project_root)
    if not verification.verified:
        failures = ", ".join(
            f"{item.path.name}:{item.status.value}"
            for item in verification.files
            if not item.verified
        )
        raise MordorProfileError(f"manifest verification failed: {failures}")

    item = manifest.files[0]
    if item.role != "test" or item.rows is None:
        raise MordorProfileError(f"{item.path.name}: expected test role and declared row count")
    source_path = project_root / item.path
    profile = profile_mordor_rows(MordorNdjsonReader(source_path), source_path.name)
    if profile.quality.total_rows != item.rows:
        raise MordorProfileError(
            f"{source_path.name}: expected {item.rows} rows, found {profile.quality.total_rows}"
        )
    write_mordor_profile(profile, report_path)
    return profile.to_dict()


def _parser() -> argparse.ArgumentParser:
    project_root = SOURCE_ROOT.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=project_root)
    parser.add_argument(
        "--manifest", type=Path, default=project_root / "data/manifests/mordor.yaml"
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=project_root / "artifacts/reports/mordor/mordor_profile.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point."""
    args = _parser().parse_args(argv)
    try:
        payload = run_profile(
            args.project_root.resolve(), args.manifest.resolve(), args.report.resolve()
        )
    except (MordorProfileError, MordorStructureError) as exc:
        print(f"profiling failed: {exc}", file=sys.stderr)
        return 1

    print(
        f"{payload['source_file']}: total={payload['total_rows']} "
        f"accepted={payload['accepted_count']} rejected={payload['rejected_count']} "
        f"rejection_rate={payload['rejection_rate']:.8%} "
        f"completed={payload['completed']} report={args.report.name}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
