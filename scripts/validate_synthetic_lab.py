"""Verify, stream-validate, and profile the benign synthetic_lab baseline."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.datasets.batch import write_quality_report  # noqa: E402
from threatfusion.datasets.manifests import (  # noqa: E402
    load_dataset_manifest,
    verify_dataset_manifest,
)
from threatfusion.datasets.synthetic_lab import (  # noqa: E402
    SyntheticLabQualityGates,
    SyntheticLabStructureError,
    SyntheticLabTrainingGates,
    build_synthetic_profile,
    profile_synthetic_session,
    write_synthetic_profile,
)


class SyntheticLabValidationError(RuntimeError):
    """A sanitized failure showing that the benign baseline is not ready."""


def run_validation(
    project_root: Path,
    manifest_path: Path,
    report_directory: Path,
    gates: SyntheticLabQualityGates,
    training_gates: SyntheticLabTrainingGates | None = None,
) -> dict[str, Any]:
    """Verify and fully stream every registered independent session once."""
    manifest = load_dataset_manifest(manifest_path)
    if manifest.name != "synthetic_lab":
        raise SyntheticLabValidationError("manifest is not for synthetic_lab")
    verification = verify_dataset_manifest(manifest, project_root)
    if not verification.verified:
        failures = ", ".join(
            f"{item.path.name}:{item.status.value}"
            for item in verification.files
            if not item.verified
        )
        raise SyntheticLabValidationError(f"manifest verification failed: {failures}")

    sessions = []
    for item in manifest.files:
        if item.role != "development_fixture" or item.rows is None:
            raise SyntheticLabValidationError(
                f"{item.path.name}: expected development_fixture role and declared row count"
            )
        source_path = project_root / item.path
        profile = profile_synthetic_session(source_path)
        if profile.quality.total_rows != item.rows:
            raise SyntheticLabValidationError(
                f"{source_path.name}: expected {item.rows} rows, "
                f"found {profile.quality.total_rows}"
            )
        write_quality_report(
            profile.quality,
            report_directory / f"{source_path.stem}_quality.json",
        )
        sessions.append(profile)

    payload = build_synthetic_profile(sessions, gates, training_gates)
    write_synthetic_profile(payload, report_directory / "synthetic_lab_profile.json")
    return payload


def _parser() -> argparse.ArgumentParser:
    project_root = SOURCE_ROOT.parents[1]
    defaults = SyntheticLabQualityGates()
    training_defaults = SyntheticLabTrainingGates()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=project_root)
    parser.add_argument(
        "--manifest", type=Path, default=project_root / "data/manifests/synthetic_lab.yaml"
    )
    parser.add_argument(
        "--report-directory",
        type=Path,
        default=project_root / "artifacts/reports/synthetic_lab",
    )
    parser.add_argument("--minimum-sessions", type=int, default=defaults.minimum_sessions)
    parser.add_argument("--minimum-event-types", type=int, default=defaults.minimum_event_types)
    parser.add_argument(
        "--minimum-events-per-session",
        type=int,
        default=defaults.minimum_events_per_session,
    )
    parser.add_argument(
        "--minimum-session-duration-seconds",
        type=float,
        default=defaults.minimum_session_duration_seconds,
    )
    parser.add_argument(
        "--training-minimum-sessions", type=int, default=training_defaults.minimum_sessions
    )
    parser.add_argument(
        "--training-minimum-total-events",
        type=int,
        default=training_defaults.minimum_total_events,
    )
    parser.add_argument(
        "--training-minimum-events-per-session",
        type=int,
        default=training_defaults.minimum_events_per_session,
    )
    parser.add_argument(
        "--training-minimum-time-span-seconds",
        type=float,
        default=training_defaults.minimum_time_span_seconds,
    )
    parser.add_argument(
        "--training-minimum-event-type-diversity",
        type=int,
        default=training_defaults.minimum_event_type_diversity,
    )
    parser.add_argument(
        "--allow-uniform-training-event-frequencies",
        action="store_true",
        help="Disable the project gate rejecting artificially uniform frequencies.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run validation and print only aggregate status and a safe report basename."""
    args = _parser().parse_args(argv)
    gates = SyntheticLabQualityGates(
        minimum_sessions=args.minimum_sessions,
        minimum_event_types=args.minimum_event_types,
        minimum_events_per_session=args.minimum_events_per_session,
        minimum_session_duration_seconds=args.minimum_session_duration_seconds,
    )
    training_gates = SyntheticLabTrainingGates(
        minimum_sessions=args.training_minimum_sessions,
        minimum_total_events=args.training_minimum_total_events,
        minimum_events_per_session=args.training_minimum_events_per_session,
        minimum_time_span_seconds=args.training_minimum_time_span_seconds,
        minimum_event_type_diversity=args.training_minimum_event_type_diversity,
        reject_artificially_uniform_event_frequencies=(
            not args.allow_uniform_training_event_frequencies
        ),
    )
    try:
        payload = run_validation(
            args.project_root.resolve(),
            args.manifest.resolve(),
            args.report_directory.resolve(),
            gates,
            training_gates,
        )
    except (SyntheticLabValidationError, SyntheticLabStructureError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1

    print(
        f"sessions={payload['session_count']} total={payload['total_rows']} "
        f"accepted={payload['accepted_count']} rejected={payload['rejected_count']} "
        f"completed={payload['completed']} quality_gates_passed="
        f"{payload['quality_gates']['passed']} training_quality_gates_passed="
        f"{payload['training_quality_gates']['passed']} report=synthetic_lab_profile.json"
    )
    return 0 if payload["quality_gates"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
