#!/usr/bin/env bash
# Start the lab console, the private range, the eve follower, and live n8n.
# The analyst URL is http://127.0.0.1:8766. The process also listens on the
# docker bridge so n8n can call host.docker.internal:8766. This script does
# not change the host firewall and does not start Azure resources.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-8766}"
PYTHON="${ROOT}/threatfusion-venv/bin/python"
SERVER="${ROOT}/scripts/run_misp_and_callback_contract_server.py"
DEMO_DIR="${TMPDIR:-/tmp}/threatfusion-range-demo"
CONSOLE_PIDFILE="${DEMO_DIR}/console.pid"
FOLLOWER_PIDFILE="${DEMO_DIR}/follower.pid"
FOLLOWER_LOG="${DEMO_DIR}/follower.log"

export THREATFUSION_SOAR_HMAC_SECRET="${THREATFUSION_SOAR_HMAC_SECRET:-lab-only-not-a-production-secret}"
export THREATFUSION_MISP_API_KEY="${THREATFUSION_MISP_API_KEY:-lab-only-misp-key-16xx}"
export THREATFUSION_N8N_WEBHOOK_URL="${THREATFUSION_N8N_WEBHOOK_URL:-http://127.0.0.1:5678/webhook/threatfusion-live-console}"
export THREATFUSION_LIVE_CONSOLE_DB="${DEMO_DIR}/threatfusion-live-console.sqlite3"
export THREATFUSION_SOAR_LEDGER_DB_PATH="${DEMO_DIR}/threatfusion-live-soar.sqlite3"
export THREATFUSION_OPERATOR_POLICY_DIR="${DEMO_DIR}/operator-policy"

usage() {
  cat <<'EOF'
Usage: scripts/run_full_range_demo.sh --up | --scan | --down

  --up     Start the console, n8n, the private range, and the eve follower.
           Wait until Suricata logs that its engine has started.
  --scan   Run non-interactive curl and ssh from the attacker container.
  --down   Stop the follower, the console, n8n, and the range.
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

require_tools() {
  command -v docker >/dev/null 2>&1 || die "docker is required"
  [[ -x "$PYTHON" ]] || die "Python interpreter not found: ${PYTHON}"
}

stop_pidfile() {
  local pidfile="$1"
  if [[ -f "$pidfile" ]]; then
    local pid
    pid="$(cat "$pidfile")"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
}

cmd_up() {
  require_tools
  mkdir -p "$DEMO_DIR"
  mkdir -p "${ROOT}/docker/range/eve"
  if ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${PORT}$"; then
    die "port ${PORT} is already in use"
  fi
  env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
    "$PYTHON" "$SERVER" --bind 0.0.0.0 --port "$PORT" \
    >"${DEMO_DIR}/console.log" 2>&1 &
  echo $! >"$CONSOLE_PIDFILE"
  local ready=0
  for _i in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:${PORT}/healthz" 2>/dev/null | grep -q '"status": "ok"'; then
      ready=1
      break
    fi
    sleep 0.2
  done
  [[ "$ready" == 1 ]] || die "console did not become ready on 127.0.0.1:${PORT}"
  docker compose -f docker/docker-compose.n8n.yml up -d
  docker compose -f docker/docker-compose.range.yml up -d
  local deadline=$((SECONDS + 120))
  local engine=0
  while (( SECONDS < deadline )); do
    if docker logs threatfusion_range_suricata 2>&1 | grep -q "Engine started"; then
      engine=1
      break
    fi
    sleep 2
  done
  [[ "$engine" == 1 ]] || die "Suricata did not log Engine started within 120s"
  env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
    "$PYTHON" "${ROOT}/scripts/follow_suricata_eve.py" \
    >"$FOLLOWER_LOG" 2>&1 &
  echo $! >"$FOLLOWER_PIDFILE"
  curl -fsS -X POST "http://127.0.0.1:${PORT}/api/v1/live/purge-bridge-noise" \
    -H 'Content-Type: application/json' -d '{}' >/dev/null
  echo "Analyst URL: http://127.0.0.1:${PORT}/"
  echo "Suricata engine started. Follower pid $(cat "$FOLLOWER_PIDFILE")."
}

cmd_scan() {
  require_tools
  docker inspect -f '{{.State.Running}}' threatfusion_range_attacker | grep -qx true \
    || die "attacker container is not running; use --up first"
  echo "waiting for 172.29.0.10 -> 172.29.0.20 in eve.json and the live queue"
  local response
  response="$(curl -fsS -X POST "http://127.0.0.1:${PORT}/api/v1/live/range-scan" \
    -H 'Content-Type: application/json' -d '{}')" || die "range scan was not ingested"
  printf '%s\n' "$response"
  printf '%s\n' "$response" | grep -q '"ingested": true' \
    || die "range scan did not store 172.29.0.10 -> 172.29.0.20"
}

cmd_down() {
  require_tools
  stop_pidfile "$FOLLOWER_PIDFILE"
  stop_pidfile "$CONSOLE_PIDFILE"
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${PORT}/tcp" >/dev/null 2>&1 || true
  fi
  docker compose -f docker/docker-compose.n8n.yml down
  docker compose -f docker/docker-compose.range.yml down
  echo "follower, console, n8n, and range stopped"
}

[[ $# -eq 1 ]] || { usage >&2; exit 2; }
case "$1" in
  --up) cmd_up ;;
  --scan) cmd_scan ;;
  --down) cmd_down ;;
  --help|-h) usage ;;
  *) usage >&2; exit 2 ;;
esac
