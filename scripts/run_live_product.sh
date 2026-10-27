#!/usr/bin/env bash
# Start the local SOC console and the MISP/SOAR contract endpoints.
# Both are the same process: the page and /api/v1/soar/* share one listener.
# The HMAC and MISP values below are lab defaults, not production credentials.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export THREATFUSION_SOAR_HMAC_SECRET="${THREATFUSION_SOAR_HMAC_SECRET:-lab-only-not-a-production-secret}"
export THREATFUSION_MISP_API_KEY="${THREATFUSION_MISP_API_KEY:-lab-only-misp-key-16xx}"
PORT="${PORT:-8766}"
exec env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
  "$ROOT/threatfusion-venv/bin/python" \
  "$ROOT/scripts/run_misp_and_callback_contract_server.py" \
  --host 127.0.0.1 \
  --port "$PORT"
