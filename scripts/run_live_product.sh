#!/usr/bin/env bash
# Turnkey launcher for the local SOC console and the MISP/TheHive/n8n contract server.
# Both surfaces are one process on 127.0.0.1: the page is GET /, and the contract
# routes are GET /healthz, POST /api/v1/soar/verify-state, POST /api/v1/soar/callback,
# and POST /attributes/restSearch.
# Approval, verify-state, and the HMAC callback share one ledger: THREATFUSION_SOAR_LEDGER_DB_PATH
# when set, otherwise threatfusion-live-soar.sqlite3 beside the console database.
# The HMAC and MISP values below are lab defaults, not production credentials.
# production_fusion_enabled stays false. This script does not enable fusion.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

HOST="127.0.0.1"
PORT="${PORT:-8766}"
MODE="serve"
PYTHON="${ROOT}/threatfusion-venv/bin/python"
SERVER="${ROOT}/scripts/run_misp_and_callback_contract_server.py"
CHILD_PID=""
PIDFILE=""

usage() {
  cat <<'EOF'
Usage: scripts/run_live_product.sh [--dry-run | --smoke | --seed-demo] [--port PORT]

  (default)   Start the SOC console and the contract server. Ctrl-C stops both.
  --dry-run   Check files, secrets, and the port, print the plan, and do not bind.
  --smoke     Start both surfaces, require HTTP 200 from / and /healthz, then stop.
  --seed-demo Start both surfaces, store the four labeled scenarios, and keep serving.
  --port N    Listen on 127.0.0.1:N (default 8766, or PORT).

Lab defaults: THREATFUSION_SOAR_HMAC_SECRET and THREATFUSION_MISP_API_KEY.
Set THREATFUSION_SOAR_LEDGER_DB_PATH to choose the shared approval ledger.
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      [[ "$MODE" == "serve" ]] || die "--dry-run, --smoke, and --seed-demo cannot be combined"
      MODE="dry-run"
      shift
      ;;
    --smoke)
      [[ "$MODE" == "serve" ]] || die "--dry-run, --smoke, and --seed-demo cannot be combined"
      MODE="smoke"
      shift
      ;;
    --seed-demo)
      [[ "$MODE" == "serve" ]] || die "--dry-run, --smoke, and --seed-demo cannot be combined"
      MODE="seed-demo"
      shift
      ;;
    --port)
      [[ $# -ge 2 ]] || die "--port requires a value"
      PORT="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ "$PORT" =~ ^[0-9]+$ ]] || die "PORT must be an integer, got '${PORT}'"
if (( PORT < 1 || PORT > 65535 )); then
  die "PORT ${PORT} is outside 1-65535"
fi

export THREATFUSION_SOAR_HMAC_SECRET="${THREATFUSION_SOAR_HMAC_SECRET:-lab-only-not-a-production-secret}"
export THREATFUSION_MISP_API_KEY="${THREATFUSION_MISP_API_KEY:-lab-only-misp-key-16xx}"

if (( ${#THREATFUSION_SOAR_HMAC_SECRET} < 16 )); then
  die "THREATFUSION_SOAR_HMAC_SECRET must be at least 16 characters"
fi
if (( ${#THREATFUSION_MISP_API_KEY} < 16 )); then
  die "THREATFUSION_MISP_API_KEY must be at least 16 characters"
fi

[[ -x "$PYTHON" ]] || die "Python interpreter not found or not executable: ${PYTHON}"
[[ -f "$SERVER" ]] || die "Contract server script not found: ${SERVER}"
for rel in frontend/index.html frontend/css/soc_unicorn.css frontend/js/soc_dashboard.js; do
  [[ -f "${ROOT}/${rel}" ]] || die "SOC console file missing: ${rel}"
done

LIVE_DB="${THREATFUSION_LIVE_CONSOLE_DB:-${TMPDIR:-/tmp}/threatfusion-live-console.sqlite3}"
if [[ -z "$LIVE_DB" ]]; then
  die "THREATFUSION_LIVE_CONSOLE_DB is empty"
fi
export THREATFUSION_LIVE_CONSOLE_DB="$LIVE_DB"
if [[ -z "${THREATFUSION_SOAR_LEDGER_DB_PATH+x}" ]]; then
  export THREATFUSION_SOAR_LEDGER_DB_PATH="$(dirname "$LIVE_DB")/threatfusion-live-soar.sqlite3"
elif [[ -z "${THREATFUSION_SOAR_LEDGER_DB_PATH}" ]]; then
  die "THREATFUSION_SOAR_LEDGER_DB_PATH is empty"
fi

port_in_use() {
  "$PYTHON" -c '
import socket
import sys
host = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket()
sock.settimeout(0.3)
try:
    code = sock.connect_ex((host, port))
finally:
    sock.close()
raise SystemExit(0 if code == 0 else 1)
' "$HOST" "$PORT"
}

http_ok() {
  local url="$1"
  local needle="$2"
  "$PYTHON" -c '
import sys
import urllib.error
import urllib.request
url, needle = sys.argv[1], sys.argv[2]
try:
    with urllib.request.urlopen(url, timeout=1) as response:
        body = response.read().decode("utf-8", "replace")
        if response.status != 200 or needle not in body:
            raise SystemExit(1)
except (urllib.error.URLError, TimeoutError, OSError, ValueError):
    raise SystemExit(1)
' "$url" "$needle"
}

if port_in_use; then
  die "${HOST}:${PORT} is already in use. Stop the other process or set PORT."
fi

cat <<EOF
ThreatFusion live product
  mode: ${MODE}
  bind: ${HOST}:${PORT}
  soc_console: http://${HOST}:${PORT}/
  contract_health: http://${HOST}:${PORT}/healthz
  contract_routes: POST /api/v1/soar/verify-state, POST /api/v1/soar/callback, POST /attributes/restSearch
  python: ${PYTHON}
  server: ${SERVER}
  live_db: ${THREATFUSION_LIVE_CONSOLE_DB}
  soar_ledger: ${THREATFUSION_SOAR_LEDGER_DB_PATH}
  production_fusion_enabled: false
EOF

if [[ "$MODE" == "dry-run" ]]; then
  echo "dry-run: preflight passed; no process was started."
  exit 0
fi

mkdir -p "$(dirname "$THREATFUSION_LIVE_CONSOLE_DB")" "$(dirname "$THREATFUSION_SOAR_LEDGER_DB_PATH")"

shutdown_child() {
  trap - EXIT INT TERM
  if [[ -n "${CHILD_PID}" ]] && kill -0 "$CHILD_PID" 2>/dev/null; then
    echo "Shutting down the SOC console and the contract server (pid ${CHILD_PID})." >&2
    # Background jobs ignore SIGINT. SIGTERM hits the server's shutdown handler.
    kill -TERM "$CHILD_PID" 2>/dev/null || true
    local _i
    for _i in $(seq 1 30); do
      if ! kill -0 "$CHILD_PID" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$CHILD_PID" 2>/dev/null; then
      kill -KILL "$CHILD_PID" 2>/dev/null || true
    fi
    wait "$CHILD_PID" 2>/dev/null || true
  fi
  CHILD_PID=""
  if [[ -n "$PIDFILE" && -f "$PIDFILE" ]]; then
    rm -f "$PIDFILE"
  fi
}

on_signal() {
  shutdown_child
  exit 0
}

trap on_signal INT TERM
trap shutdown_child EXIT

PIDFILE="${TMPDIR:-/tmp}/threatfusion-live-product-${PORT}.pid"
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
  "$PYTHON" "$SERVER" --host "$HOST" --port "$PORT" &
CHILD_PID=$!
echo "$CHILD_PID" > "$PIDFILE"

ready=0
for _i in $(seq 1 150); do
  if ! kill -0 "$CHILD_PID" 2>/dev/null; then
    die "the contract server exited before the SOC console and /healthz were ready"
  fi
  if http_ok "http://${HOST}:${PORT}/healthz" '"status": "ok"' \
    && http_ok "http://${HOST}:${PORT}/" "ThreatFusion SOC Console"; then
    ready=1
    break
  fi
  sleep 0.1
done

if [[ "$ready" != 1 ]]; then
  die "timed out waiting for the SOC console and contract health endpoint on ${HOST}:${PORT}"
fi

if [[ "$MODE" == "seed-demo" ]]; then
  "$PYTHON" - "$HOST" "$PORT" <<'PY'
import json
import sys
import urllib.request

host, port = sys.argv[1], sys.argv[2]
request = urllib.request.Request(
    f"http://{host}:{port}/api/v1/live/scenarios",
    data=b"{}",
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=60) as response:
    body = json.load(response)
ids = {row.get("scenario_id") for row in body.get("flows", [])}
required = {"web_exploit", "ssh_brute", "internal_recon", "benign_false_alarm"}
if response.status != 200 or body.get("member_count") != 4 or not required <= ids:
    sys.stderr.write("error: seed-demo did not store the four scenarios\n")
    sys.exit(1)
print("seed-demo: four scenarios stored")
PY
fi

if [[ "$MODE" == "smoke" ]]; then
  echo "smoke: SOC console and contract health both responded on ${HOST}:${PORT}"
  shutdown_child
  trap - EXIT INT TERM
  released=0
  for _i in $(seq 1 20); do
    if ! port_in_use; then
      released=1
      break
    fi
    sleep 0.1
  done
  if [[ "$released" != 1 ]]; then
    die "port ${PORT} was still in use after shutdown"
  fi
  echo "smoke: shutdown released ${HOST}:${PORT}"
  exit 0
fi

echo "Ready. Open http://${HOST}:${PORT}/  (Ctrl-C stops the SOC console and the contract server)."
set +e
wait "$CHILD_PID"
status=$?
set -e
CHILD_PID=""
exit "$status"
