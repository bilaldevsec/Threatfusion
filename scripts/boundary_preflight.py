"""CLI entry for the Protocol 0 boundary preflight.

The check implementation lives in threatfusion.evaluation.boundary_preflight so the
script and the repository-truth audit cannot drift apart. When the declared gemini
checkout is absent, the default active root is the git repository that contains
this script. A missing resolved directory fails closed. The protected tree stays
unread, unlinked, and unreferenced.
"""

from __future__ import annotations

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_SRC = REPO_ROOT / "backend" / "src"
if BACKEND_SRC.is_dir() and str(BACKEND_SRC) not in sys.path:
    sys.path.insert(0, str(BACKEND_SRC))

from threatfusion.evaluation.boundary_preflight import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
