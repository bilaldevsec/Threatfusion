"""Run one metadata-free functional smoke through the UNSW inference boundary."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "backend/src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threatfusion.models.network_inference import (  # noqa: E402
    NetworkInferenceError,
    NetworkModelChoice,
    UnswNetworkInferenceBoundary,
    default_artifact_directories,
    synthetic_contract_valid_request,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Functional smoke for frozen UNSW inference; this is not accuracy evaluation."
    )
    parser.add_argument(
        "--model",
        choices=[choice.value for choice in NetworkModelChoice],
        default=NetworkModelChoice.RANDOM_FOREST.value,
        help="Explicit frozen model selection; no fallback occurs.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    project_root = SOURCE_ROOT.parents[1]
    preprocessing, logistic, forest = default_artifact_directories(project_root)
    try:
        boundary = UnswNetworkInferenceBoundary(
            preprocessing_directory=preprocessing,
            logistic_directory=logistic,
            random_forest_directory=forest,
        )
        result = boundary.infer(
            synthetic_contract_valid_request(), model=NetworkModelChoice(args.model)
        )
    except NetworkInferenceError as exc:
        print(json.dumps({"status": "failed", "reason": exc.code}, sort_keys=True))
        return 1
    print(json.dumps(result.to_dict(), sort_keys=True))
    return 0 if result.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
