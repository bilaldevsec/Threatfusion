"""CLI entry for the Protocol 0 boundary preflight.

The check implementation lives in threatfusion.evaluation.boundary_preflight so the
script and the repository-truth audit cannot drift apart.
"""

from __future__ import annotations

import sys

from threatfusion.evaluation.boundary_preflight import main

if __name__ == "__main__":
    sys.exit(main())
