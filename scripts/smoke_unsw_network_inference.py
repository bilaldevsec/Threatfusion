"""Run one synthetic raw UNSW row through the supported inference boundary."""

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
    try:
        boundary = UnswNetworkInferenceBoundary(project_root=project_root)
        # Synthetic raw_49 fixture, never accuracy or capture-membership evidence.
        row = ["0"] * 49
        for index, value in {
            0: "192.0.2.1",
            1: "1234",
            2: "198.51.100.2",
            3: "443",
            4: "tcp",
            6: "0.1",
            7: "120",
            8: "60",
            16: "2",
            17: "1",
            28: "1421928000",
            29: "1421928001",
        }.items():
            row[index] = value
        result = boundary.infer(row, model=NetworkModelChoice(args.model))
    except NetworkInferenceError as exc:
        print(json.dumps({"status": "failed", "reason": exc.code}, sort_keys=True))
        return 1
    print(json.dumps(result.to_dict(), sort_keys=True))
    return 0 if result.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
