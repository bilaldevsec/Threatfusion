#!/usr/bin/env python3
"""Save console screenshots. This script is not part of pytest.

It expects a console already listening on 127.0.0.1:8766. A missing browser
or a missing console is reported and the script exits non-zero.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "assets" / "screenshots"
BASE = "http://127.0.0.1:8766/"
DESKTOP_WINDOW_SIZE = "1440,900"
MOBILE_WINDOW_SIZE = "390,844"
SHOTS = (
    ("01-investigations-queue.png", "#investigations", DESKTOP_WINDOW_SIZE),
    ("02-investigation-detail-ml.png", "#evidence", DESKTOP_WINDOW_SIZE),
    ("03-gemini-copilot-grounded.png", "#detail", DESKTOP_WINDOW_SIZE),
    ("04-ai-action-graph-soar.png", "#graph", DESKTOP_WINDOW_SIZE),
    ("05-ai-threat-hunter-rules.png", "#hunter", DESKTOP_WINDOW_SIZE),
    ("06-mobile-console.png", "#investigations", MOBILE_WINDOW_SIZE),
)


def _browser() -> list[str] | None:
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        path = shutil.which(name)
        if path:
            return [path]
    return None


def _console_ready() -> bool:
    try:
        with urllib.request.urlopen(BASE + "healthz", timeout=5) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError):
        return False


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    if not _console_ready():
        print("console is not ready at 127.0.0.1:8766", file=sys.stderr)
        return 1
    browser = _browser()
    if browser is None:
        print("no Chrome or Chromium binary is available for screenshots", file=sys.stderr)
        return 1
    for filename, suffix, window_size in SHOTS:
        destination = OUT / filename
        command = [
            *browser,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--hide-scrollbars",
            f"--window-size={window_size}",
            f"--screenshot={destination}",
            BASE + suffix,
        ]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        if (
            completed.returncode != 0
            or not destination.is_file()
            or destination.stat().st_size < 1000
        ):
            print(completed.stderr[-500:], file=sys.stderr)
            print(f"screenshot failed: {filename}", file=sys.stderr)
            return 1
        print(f"wrote {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
