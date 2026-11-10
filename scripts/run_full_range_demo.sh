#!/usr/bin/env bash
# Start the lab console, the private range, the eve follower, and live n8n.
# The analyst URL is http://127.0.0.1:8766. The process binds to the docker0
# bridge address when that interface exists, so n8n can call the host without
# listening on 0.0.0.0. Otherwise it binds 127.0.0.1. This script does not
# change the host firewall and does not start Azure resources.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Source the lab key only when this script starts the console (--up).
load_gemini_dotenv() {
  local offline="${THREATFUSION_OFFLINE_ONLY:-}"
  offline="${offline,,}"
  if [[ "${THREATFUSION_IGNORE_DOTENV:-}" == "1" || "$offline" == "1" || "$offline" == "true" ]]; then
    return 0
  fi
  local env_file="$1"
  if [[ -f "$env_file" ]]; then
    local line key value
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line#"${line%%[![:space:]]*}"}"
      [[ -z "$line" || "$line" == \#* ]] && continue
      [[ "$line" == export\ * ]] && line="${line#export }"
      [[ "$line" == *=* ]] || continue
      key="${line%%=*}"
      value="${line#*=}"
      key="${key%"${key##*[![:space:]]}"}"
      if [[ "$key" != "GEMINI_API_KEY" && "$key" != "GEMINI_MODEL" && "$key" != "GEMINI_ENABLED" ]]; then
        continue
      fi
      if [[ ${#value} -ge 2 && ( "$value" == \"*\" || "$value" == \'*\' ) ]]; then
        value="${value:1:${#value}-2}"
      fi
      printf -v "$key" '%s' "$value"
      export "$key"
    done < "$env_file"
  fi
}

if [[ "${1:-}" == "--up" ]]; then
  load_gemini_dotenv "$ROOT/.env"
fi

PORT="${PORT:-8766}"
if [[ -n "${THREATFUSION_PYTHON:-}" ]]; then
  PYTHON="${THREATFUSION_PYTHON}"
elif [[ -x "${ROOT}/threatfusion-venv/bin/python" ]]; then
  PYTHON="${ROOT}/threatfusion-venv/bin/python"
else
  PYTHON="$(command -v python3 || command -v python)"
fi
SERVER="${ROOT}/scripts/run_misp_and_callback_contract_server.py"
DEMO_DIR="${TMPDIR:-/tmp}/threatfusion-range-demo"
CONSOLE_PIDFILE="${DEMO_DIR}/console.pid"
FOLLOWER_PIDFILE="${DEMO_DIR}/follower.pid"
FOLLOWER_LOG="${DEMO_DIR}/follower.log"

if [[ "${1:-}" != "--dry-run" ]]; then
  if [[ -z "${THREATFUSION_SOAR_HMAC_SECRET:-}" ]]; then
    export THREATFUSION_SOAR_HMAC_SECRET="$("$PYTHON" -c 'import secrets; print(secrets.token_hex(32), end="")')"
  fi
  if [[ -z "${THREATFUSION_MISP_API_KEY:-}" ]]; then
    export THREATFUSION_MISP_API_KEY="$("$PYTHON" -c 'import secrets; print(secrets.token_hex(32), end="")')"
  fi
  if [[ -z "${THREATFUSION_SENSOR_INGEST_TOKEN:-}" ]]; then
    export THREATFUSION_SENSOR_INGEST_TOKEN="$("$PYTHON" -c 'import secrets; print(secrets.token_hex(32), end="")')"
  fi
fi
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
      if ps -p "$pid" -o args= 2>/dev/null | grep -Eq "threatfusion|run_misp_and_callback_contract_server"; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
      fi
    fi
    rm -f "$pidfile"
  fi
}

# human_credentials rejects a policy directory whose parent is group-writable.
# /tmp is a root-owned sticky directory and stays unchanged. The demo directory
# created by mkdir -p is mode 0775, so enrollment must tighten that parent.
prepare_operator_policy_dir() {
  local policy_dir="$1"
  local parent mode uid
  mkdir -p "$policy_dir"
  if [[ -L "$policy_dir" ]]; then
    die "refusing to chmod a symlink: ${policy_dir}"
  fi
  chmod 0700 "$policy_dir"
  parent="$(dirname "$policy_dir")"
  if [[ "$parent" == "/" || "$parent" == "." ]]; then
    return 0
  fi
  mode="$(stat -c '%a' "$parent")"
  uid="$(stat -c '%u' "$parent")"
  if [[ "$mode" == 1* && "$uid" == "0" ]]; then
    return 0
  fi
  case "$parent" in
    /tmp/*|/var/tmp/*)
      if [[ -L "$parent" ]]; then
        die "refusing to chmod a symlink: ${parent}"
      fi
      chmod 0700 "$parent"
      ;;
  esac
}

cmd_up() {
  require_tools
  mkdir -p "$DEMO_DIR"
  prepare_operator_policy_dir "$THREATFUSION_OPERATOR_POLICY_DIR"
  mkdir -p "${ROOT}/docker/range/eve"
  local BIND_HOST="127.0.0.1"
  if command -v ip >/dev/null 2>&1; then
    local bridge_ip
    bridge_ip="$(ip -4 -o addr show docker0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
    if [[ "$bridge_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      BIND_HOST="$bridge_ip"
    fi
  fi
  printf '%s\n' "$BIND_HOST" >"${DEMO_DIR}/bind-host"
  if ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${PORT}$"; then
    die "port ${PORT} is already in use"
  fi
  nohup env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
    "$PYTHON" "$SERVER" --bind "$BIND_HOST" --port "$PORT" \
    >"${DEMO_DIR}/console.log" 2>&1 &
  echo $! >"$CONSOLE_PIDFILE"
  local ready=0
  for _i in $(seq 1 50); do
    if curl -fsS "http://${BIND_HOST}:${PORT}/healthz" 2>/dev/null | grep -q '"status": "ok"'; then
      ready=1
      break
    fi
    sleep 0.2
  done
  [[ "$ready" == 1 ]] || die "console did not become ready on ${BIND_HOST}:${PORT}"
  docker compose -p threatfusion-n8n -f docker/docker-compose.n8n.yml up -d --remove-orphans
  docker compose -p threatfusion-range -f docker/docker-compose.range.yml up -d --remove-orphans
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
  nohup env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
    "$PYTHON" "${ROOT}/scripts/follow_suricata_eve.py" \
    --console-url "http://${BIND_HOST}:${PORT}/api/v1/live/sensor" \
    >"$FOLLOWER_LOG" 2>&1 &
  echo $! >"$FOLLOWER_PIDFILE"
  local csrf
  csrf="$(curl -fsS -H "Origin: http://${BIND_HOST}:${PORT}" -H "Sec-Fetch-Site: same-origin" "http://${BIND_HOST}:${PORT}/api/v1/live/health" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("csrf_token",""))')"
  curl -fsS -X POST "http://${BIND_HOST}:${PORT}/api/v1/live/purge-bridge-noise" \
    -H 'Content-Type: application/json' -H "X-ThreatFusion-CSRF: ${csrf}" -d '{}' >/dev/null
  if ! curl -fsS -X POST "http://${BIND_HOST}:${PORT}/api/v1/live/scenarios" \
    -H 'Content-Type: application/json' -H "X-ThreatFusion-CSRF: ${csrf}" -d '{}' >/dev/null; then
    echo "scenario replay did not store rows" >&2
  fi
  prepare_operator_policy_dir "$THREATFUSION_OPERATOR_POLICY_DIR"
  "$PYTHON" - "$ROOT" "$THREATFUSION_OPERATOR_POLICY_DIR" <<'PY'
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root / "backend" / "src"))
from threatfusion.api.live_soc_console import enroll_lab_operator

directory = Path(sys.argv[2]).expanduser().resolve()
directory.mkdir(mode=0o700, parents=True, exist_ok=True)
os.chmod(directory, 0o700)
parent = directory.parent
if parent != parent.parent:
    info = parent.stat()
    sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
    parent_text = str(parent)
    if info.st_mode & 0o022 and not sticky_root and (
        parent_text.startswith("/tmp/") or parent_text.startswith("/var/tmp/")
    ):
        os.chmod(parent, 0o700)
stamp = enroll_lab_operator(directory, "lab_operator")
accepted = stamp.get("evidence_state") == "verified" and stamp.get("reason") in {
    "lab_operator_enrolled",
    "already_enrolled",
}
if not accepted:
    sys.stderr.write("operator certificate enrollment did not complete\n")
    raise SystemExit(1)
PY
  echo "Analyst URL: http://${BIND_HOST}:${PORT}/"
  echo "Suricata engine started. Follower pid $(cat "$FOLLOWER_PIDFILE")."
}

cmd_scan() {
  require_tools
  local BIND_HOST="127.0.0.1"
  if [[ -f "${DEMO_DIR}/bind-host" ]]; then
    BIND_HOST="$(tr -d '[:space:]' <"${DEMO_DIR}/bind-host")"
  fi
  docker inspect -f '{{.State.Running}}' threatfusion_range_attacker | grep -qx true \
    || die "attacker container is not running; use --up first"
  echo "waiting for 172.29.0.10 -> 172.29.0.20 in eve.json and the live queue"
  local response
  local csrf
  csrf="$(curl -fsS -H "Origin: http://${BIND_HOST}:${PORT}" -H "Sec-Fetch-Site: same-origin" "http://${BIND_HOST}:${PORT}/api/v1/live/health" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("csrf_token",""))')"
  response="$(curl -fsS -X POST "http://${BIND_HOST}:${PORT}/api/v1/live/range-scan" \
    -H 'Content-Type: application/json' -H "X-ThreatFusion-CSRF: ${csrf}" -d '{}')" || die "range scan was not ingested"
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
  docker compose -p threatfusion-n8n -f docker/docker-compose.n8n.yml down --remove-orphans
  docker compose -p threatfusion-range -f docker/docker-compose.range.yml down --remove-orphans
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
