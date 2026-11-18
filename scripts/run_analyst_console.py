#!/usr/bin/env python3
"""Analyst console launcher.

HTTP routes stay in scripts/run_misp_and_callback_contract_server.py.
This file does not register a second route table.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

TARGET = Path(__file__).resolve().with_name("run_misp_and_callback_contract_server.py")


def main() -> None:
    sys.argv[0] = str(TARGET)
    runpy.run_path(str(TARGET), run_name="__main__")


if __name__ == "__main__":
    main()
