#!/usr/bin/env python3
"""Serve the loopback live analyst console.

The process binds 127.0.0.1 only. Suricata flows are stored without a model
decision. UNSW raw rows are scored only by the frozen Random Forest boundary.
"""

from __future__ import annotations

import sys

from threatfusion.api.live_analyst_console import main

if __name__ == "__main__":
    sys.exit(main())
