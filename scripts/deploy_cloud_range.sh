#!/usr/bin/env bash
# Provider-agnostic ThreatFusion cyber range.
#
# Reads the operator's own cloud session. Account, tenant, subscription, and
# project identifiers are never hardcoded. Runtime metadata is written to
# /tmp/threatfusion-range-demo/cloud_state.json and, for Azure, mirrored to
# azure_portal_state.json.
#
#   --provision-range     172.29.0.10 attacker + 172.29.0.20 victim, SSH/22,
#                         auto-shutdown cost guardrail, in the signed-in account
#   --deploy-full-stack   Console + ML engine + Suricata + n8n on the victim
#   --teardown            delete the recorded stack so ongoing cost is 0.00
#
# Providers: azure, aws, gcp, generic.
# Generic mode uses --victim-host and --attacker-host, or
# TF_VICTIM_PUBLIC_IP and TF_ATTACKER_PUBLIC_IP.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${THREATFUSION_CLOUD_STATE_DIR:-/tmp/threatfusion-range-demo}"
CLOUD_STATE="${STATE_DIR}/cloud_state.json"
AZURE_STATE="${STATE_DIR}/azure_portal_state.json"
RANGE_TAG="threatfusion-range"
VICTIM_PRIVATE="172.29.0.20"
ATTACKER_PRIVATE="172.29.0.10"
VPC_CIDR="172.29.0.0/16"
SUBNET_CIDR="172.29.0.0/24"
AUTO_SHUTDOWN_UTC="2100"
COST_GUARDRAIL="Auto-shutdown at 21:00 UTC. Teardown removes the recorded stack so ongoing cost is 0.00."
CLOUD_ENV_FILE="${ROOT}/.env.cloud"
STACK_SECRET_KEYS=(
  THREATFUSION_MISP_API_KEY
  THREATFUSION_SOAR_HMAC_SECRET
  THREATFUSION_SENSOR_INGEST_TOKEN
  THREATFUSION_THEHIVE_SECRET
  THREATFUSION_THEHIVE_API_KEY
  THREATFUSION_N8N_USER
  THREATFUSION_N8N_PASSWORD
)

PROVIDER=""
ACTION=""
DRY_RUN=0
AUTO_IP=0
LOW_COST_TIER=0
VICTIM_HOST="${TF_VICTIM_PUBLIC_IP:-}"
ATTACKER_HOST="${TF_ATTACKER_PUBLIC_IP:-}"

usage() {
  cat <<'EOF'
Usage: scripts/deploy_cloud_range.sh [--dry-run] [--auto-ip] [--low-cost-tier] [--provider azure|aws|gcp|generic|ssh] [--victim-host IP] [--attacker-host IP] (--provision-range|--deploy-full-stack|--simulate-attack|--teardown|--status|--deallocate|--help)

  --provider         azure, aws, gcp, generic, or ssh (alias for generic).
                     When omitted, --victim-host or TF_VICTIM_PUBLIC_IP selects
                     generic; otherwise the first logged-in CLI wins: az account
                     show, aws sts get-caller-identity, gcloud config get-value project.
  --low-cost-tier    Use lowest-cost VM sizes / budget auto-shutdown on Azure
                     (alias: --student-free-tier).
  --provision-range  Create the 2-VM range in the signed-in account, or record
                     a generic Ubuntu/Linux pair. Opens SSH port 22 from
                     CLOUD_ADMIN_SSH_CIDR, AZURE_ADMIN_SSH_CIDR, or
                     AWS_ADMIN_SSH_CIDR only. 0.0.0.0/0 is refused.
  --auto-ip          When no admin SSH prefix is set, use
                     $(curl -fsS https://api.ipify.org)/32.
  --deploy-full-stack
                     Copy the repo to the victim and start Console, ML engine,
                     Suricata, and n8n with Docker Compose over SSH. Installs
                     nmap, curl, and python3 on the attacker VM.
  --simulate-attack  Install nmap, curl, and python3 on the attacker if they
                     are missing, check the Suricata eve.json bridge returns
                     HTTP 200, and require alerts.sqlite3 stored_rows > 0.
  --teardown         Destroy the recorded resource group, stack, or instances.
  --status           Refresh cloud_state.json from the active CLI session.
  --deallocate       Stop recorded instances without deleting the network.
  --dry-run          Print the plan. Do not call cloud APIs or write state.
  --victim-host      Public address of a generic victim.
  --attacker-host    Public address of a generic attacker.

Environment: CLOUD_PROVIDER, CLOUD_ACCOUNT_ID, CLOUD_REGION,
TF_VICTIM_PUBLIC_IP, TF_ATTACKER_PUBLIC_IP, CLOUD_ADMIN_SSH_CIDR,
AZURE_ADMIN_SSH_CIDR, AWS_ADMIN_SSH_CIDR.
Account identifiers are read from the CLI session, not from the repository.
Missing THREATFUSION_* stack secrets are generated into mode-0600 .env.cloud.
EOF
}

run_cmd() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'dry-run:'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

require_ssh_cidr() {
  local cidr="${CLOUD_ADMIN_SSH_CIDR:-${AZURE_ADMIN_SSH_CIDR:-${AWS_ADMIN_SSH_CIDR:-}}}"
  if [[ -z "$cidr" && "$AUTO_IP" -eq 1 ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      cidr="auto-ip/32"
    else
      local ip
      ip="$(curl -fsS --max-time 20 https://api.ipify.org | tr -d '[:space:]')"
      if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "Could not resolve an IPv4 address from https://api.ipify.org." >&2
        exit 1
      fi
      cidr="${ip}/32"
    fi
  fi
  if [[ -n "$cidr" ]]; then
    if [[ "$cidr" == "0.0.0.0/0" || "$cidr" == "*" ]]; then
      echo "The admin SSH prefix must not be open to the internet." >&2
      exit 1
    fi
    export CLOUD_ADMIN_SSH_CIDR="${CLOUD_ADMIN_SSH_CIDR:-$cidr}"
    export AZURE_ADMIN_SSH_CIDR="${AZURE_ADMIN_SSH_CIDR:-$cidr}"
    export AWS_ADMIN_SSH_CIDR="${AWS_ADMIN_SSH_CIDR:-$cidr}"
    printf '%s\n' "$cidr"
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%s\n' "operator-prefix-required"
    return 0
  fi
  echo "Set AZURE_ADMIN_SSH_CIDR or AWS_ADMIN_SSH_CIDR. 0.0.0.0/0 is refused." >&2
  echo "Pass --auto-ip, or export the operator prefix:" >&2
  echo '  export AZURE_ADMIN_SSH_CIDR="$(curl -fsS https://api.ipify.org)/32"' >&2
  exit 1
}

cli_ok() {
  local seconds="${1:-12}"
  shift
  if [[ "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi
  if command -v timeout >/dev/null 2>&1; then
    timeout "$seconds" "$@" >/dev/null 2>&1
  else
    "$@" >/dev/null 2>&1
  fi
}

detect_provider() {
  if [[ -n "${CLOUD_PROVIDER:-}" ]]; then
    if [[ "$CLOUD_PROVIDER" == "ssh" ]]; then
      printf '%s\n' "generic"
    else
      printf '%s\n' "$CLOUD_PROVIDER"
    fi
    return 0
  fi
  if [[ -n "${VICTIM_HOST:-}" || -n "${TF_VICTIM_PUBLIC_IP:-}" ]]; then
    printf '%s\n' "generic"
    return 0
  fi
  if command -v az >/dev/null 2>&1 && cli_ok 15 az account show; then
    printf '%s\n' "azure"
    return 0
  fi
  if command -v aws >/dev/null 2>&1 && cli_ok 15 aws sts get-caller-identity; then
    printf '%s\n' "aws"
    return 0
  fi
  if command -v gcloud >/dev/null 2>&1; then
    local project
    project="$(gcloud config get-value project 2>/dev/null || true)"
    if [[ -n "$project" && "$project" != "(unset)" ]]; then
      printf '%s\n' "gcp"
      return 0
    fi
  fi
  printf '%s\n' "unbound"
}

write_state_json() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: write ${CLOUD_STATE} provider=${PROVIDER}"
    return 0
  fi
  mkdir -p "$STATE_DIR"
  PROVIDER="$PROVIDER" \
  CLOUD_STATE="$CLOUD_STATE" \
  AZURE_STATE="$AZURE_STATE" \
  ACCOUNT_ID="${ACCOUNT_ID:-}" \
  TENANT_ID="${TENANT_ID:-}" \
  PROJECT_ID="${PROJECT_ID:-}" \
  SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-}" \
  REGION_NAME="${REGION_NAME:-}" \
  RESOURCE_GROUP="${RESOURCE_GROUP:-}" \
  VICTIM_PUBLIC="${VICTIM_PUBLIC:-}" \
  ATTACKER_PUBLIC="${ATTACKER_PUBLIC:-}" \
  SSH_USER="${SSH_USER:-}" \
  VICTIM_STATE="${VICTIM_STATE:-}" \
  ATTACKER_STATE="${ATTACKER_STATE:-}" \
  COST_GUARDRAIL="$COST_GUARDRAIL" \
  AUTO_SHUTDOWN_UTC="$AUTO_SHUTDOWN_UTC" \
  VICTIM_PRIVATE="$VICTIM_PRIVATE" \
  ATTACKER_PRIVATE="$ATTACKER_PRIVATE" \
  RESOURCE_IDS="${RESOURCE_IDS:-{}}" \
  python3 - <<'PY'
import json
import os
from pathlib import Path

provider = os.environ["PROVIDER"]
state = {
    "provider": provider,
    "account_id": os.environ.get("ACCOUNT_ID", ""),
    "tenant_id": os.environ.get("TENANT_ID", ""),
    "project_id": os.environ.get("PROJECT_ID", ""),
    "subscription_id": os.environ.get("SUBSCRIPTION_ID", ""),
    "subscription_name": "",
    "region": os.environ.get("REGION_NAME", ""),
    "location": os.environ.get("REGION_NAME", ""),
    "resource_group": os.environ.get("RESOURCE_GROUP", ""),
    "victim_vm_ip": os.environ.get("VICTIM_PRIVATE", ""),
    "attacker_vm_ip": os.environ.get("ATTACKER_PRIVATE", ""),
    "victim_public_ip": os.environ.get("VICTIM_PUBLIC", ""),
    "attacker_public_ip": os.environ.get("ATTACKER_PUBLIC", ""),
    "ssh_user": os.environ.get("SSH_USER", ""),
    "admin_username": os.environ.get("SSH_USER", ""),
    "victim_state": os.environ.get("VICTIM_STATE", ""),
    "attacker_state": os.environ.get("ATTACKER_STATE", ""),
    "auto_shutdown_utc": os.environ.get("AUTO_SHUTDOWN_UTC", ""),
    "auto_shutdown_pkt": "02:00",
    "auto_shutdown_label": "Enabled (02:00 PKT / 21:00 UTC)",
    "cost_guardrail": os.environ.get("COST_GUARDRAIL", ""),
    "victim": {
        "private_ip": os.environ.get("VICTIM_PRIVATE", ""),
        "public_ip": os.environ.get("VICTIM_PUBLIC", ""),
        "state": os.environ.get("VICTIM_STATE", ""),
        "power_state": os.environ.get("VICTIM_STATE", ""),
    },
    "attacker": {
        "private_ip": os.environ.get("ATTACKER_PRIVATE", ""),
        "public_ip": os.environ.get("ATTACKER_PUBLIC", ""),
        "state": os.environ.get("ATTACKER_STATE", ""),
        "power_state": os.environ.get("ATTACKER_STATE", ""),
    },
    "vms": {
        "tf-soc-victim-vm": {
            "name": "tf-soc-victim-vm",
            "private_ip": os.environ.get("VICTIM_PRIVATE", ""),
            "public_ip": os.environ.get("VICTIM_PUBLIC", ""),
            "power_state": os.environ.get("VICTIM_STATE", ""),
        },
        "tf-attacker-redteam-vm": {
            "name": "tf-attacker-redteam-vm",
            "private_ip": os.environ.get("ATTACKER_PRIVATE", ""),
            "public_ip": os.environ.get("ATTACKER_PUBLIC", ""),
            "power_state": os.environ.get("ATTACKER_STATE", ""),
        },
    },
}
try:
    extra = json.loads(os.environ.get("RESOURCE_IDS") or "{}")
except json.JSONDecodeError:
    extra = {}
if isinstance(extra, dict):
    state["resource_ids"] = extra
cloud_path = Path(os.environ["CLOUD_STATE"])
cloud_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
if provider == "azure":
    Path(os.environ["AZURE_STATE"]).write_text(
        json.dumps(state, indent=2) + "\n", encoding="utf-8"
    )
print(cloud_path)
PY
}

mirror_azure_portal_state() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: mirror ${AZURE_STATE} to ${CLOUD_STATE}"
    return 0
  fi
  if [[ ! -f "$AZURE_STATE" ]]; then
    return 0
  fi
  AZURE_STATE="$AZURE_STATE" CLOUD_STATE="$CLOUD_STATE" COST_GUARDRAIL="$COST_GUARDRAIL" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

azure_path = Path(os.environ["AZURE_STATE"])
state = json.loads(azure_path.read_text(encoding="utf-8"))
if not isinstance(state, dict):
    raise SystemExit("azure portal state is not an object")
state["provider"] = "azure"
state.setdefault("account_id", state.get("subscription_id") or "")
state.setdefault("region", state.get("location") or "")
state.setdefault("ssh_user", state.get("admin_username") or "azureuser")
state.setdefault("cost_guardrail", os.environ.get("COST_GUARDRAIL", ""))
text = json.dumps(state, indent=2) + "\n"
Path(os.environ["CLOUD_STATE"]).write_text(text, encoding="utf-8")
azure_path.write_text(text, encoding="utf-8")
print(os.environ["CLOUD_STATE"])
PY
}

load_existing_public_ips() {
  if [[ ! -f "$CLOUD_STATE" ]]; then
    return 0
  fi
  eval "$(CLOUD_STATE="$CLOUD_STATE" CURRENT_PROVIDER="${PROVIDER:-}" python3 - <<'PY'
import json, os, shlex
from pathlib import Path
path = Path(os.environ["CLOUD_STATE"])
try:
    state = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    state = {}
if not isinstance(state, dict):
    state = {}
current_provider = os.environ.get("CURRENT_PROVIDER", "")
state_provider = str(state.get("provider") or "")
if current_provider and state_provider and state_provider != current_provider:
    state = {}
pairs = {
    "VICTIM_PUBLIC": state.get("victim_public_ip") or "",
    "ATTACKER_PUBLIC": state.get("attacker_public_ip") or "",
    "SSH_USER": state.get("ssh_user") or state.get("admin_username") or "",
    "REGION_NAME": state.get("region") or state.get("location") or "",
    "RESOURCE_GROUP": state.get("resource_group") or "",
    "ACCOUNT_ID": state.get("account_id") or state.get("subscription_id") or "",
}
for key, value in pairs.items():
    print(f"{key}={shlex.quote(str(value))}")
PY
)"
}

load_saved_state_field() {
  local expected_provider="$1"
  local field_name="$2"
  if [[ ! -f "$CLOUD_STATE" ]]; then
    return 0
  fi
  CLOUD_STATE="$CLOUD_STATE" EXPECTED_PROVIDER="$expected_provider" FIELD_NAME="$field_name" python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ["CLOUD_STATE"])
expected_provider = os.environ["EXPECTED_PROVIDER"]
field = os.environ["FIELD_NAME"]
try:
    state = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    raise SystemExit(0)
if not isinstance(state, dict):
    raise SystemExit(0)
provider = str(state.get("provider") or "")
if expected_provider and provider and provider != expected_provider:
    raise SystemExit(0)
if field == "region":
    value = state.get("region") or state.get("location") or ""
elif field == "zone":
    resource_ids = state.get("resource_ids")
    nested = resource_ids.get("zone") if isinstance(resource_ids, dict) else ""
    value = state.get("zone") or nested or ""
else:
    value = state.get(field) or ""
if value:
    print(str(value))
PY
}

azure_delegate() {
  local flag="$1"
  shift || true
  local -a extra=()
  if [[ "$DRY_RUN" -eq 1 ]]; then
    extra+=(--dry-run)
  fi
  if [[ "$LOW_COST_TIER" -eq 1 ]]; then
    extra+=(--low-cost-tier)
  fi
  TF_AZURE_RANGE_IMPL=1 bash "$ROOT/scripts/deploy_azure_cyber_range.sh" ${extra[@]+"${extra[@]}"} "$flag"
  mirror_azure_portal_state
}

read_azure_account() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    ACCOUNT_ID="${CLOUD_ACCOUNT_ID:-}"
    SUBSCRIPTION_ID="${CLOUD_ACCOUNT_ID:-}"
    TENANT_ID=""
    REGION_NAME="${CLOUD_REGION:-southeastasia}"
    return 0
  fi
  local raw
  raw="$(az account show -o json)"
  eval "$(printf '%s' "$raw" | python3 -c '
import json, shlex, sys
account = json.load(sys.stdin)
print("ACCOUNT_ID=" + shlex.quote(str(account.get("id") or "")))
print("SUBSCRIPTION_ID=" + shlex.quote(str(account.get("id") or "")))
print("TENANT_ID=" + shlex.quote(str(account.get("tenantId") or "")))
')"
  REGION_NAME="${CLOUD_REGION:-${AZURE_LOCATION:-southeastasia}}"
}

read_aws_account() {
  REGION_NAME="${CLOUD_REGION:-}"
  if [[ -z "$REGION_NAME" ]]; then
    REGION_NAME="$(aws configure get region 2>/dev/null || true)"
  fi
  REGION_NAME="${REGION_NAME:-us-east-1}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    ACCOUNT_ID="${CLOUD_ACCOUNT_ID:-}"
    return 0
  fi
  local raw
  raw="$(aws sts get-caller-identity --output json)"
  ACCOUNT_ID="$(printf '%s' "$raw" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("Account") or "")')"
  SSH_USER="${TF_SSH_USER:-ubuntu}"
}

read_gcp_account() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    PROJECT_ID="${CLOUD_ACCOUNT_ID:-}"
    ACCOUNT_ID="${CLOUD_ACCOUNT_ID:-}"
    REGION_NAME="${CLOUD_REGION:-us-central1}"
    return 0
  fi
  PROJECT_ID="$(gcloud config get-value project 2>/dev/null || true)"
  ACCOUNT_ID="$(gcloud config get-value account 2>/dev/null || true)"
  REGION_NAME="${CLOUD_REGION:-}"
  if [[ -z "$REGION_NAME" ]]; then
    REGION_NAME="$(gcloud config get-value compute/region 2>/dev/null || true)"
  fi
  if [[ -z "$REGION_NAME" || "$REGION_NAME" == "(unset)" ]]; then
    REGION_NAME="us-central1"
  fi
  SSH_USER="${TF_SSH_USER:-ubuntu}"
}

shutdown_user_data() {
  cat <<'EOF'
#!/bin/bash
printf '%s\n' '0 21 * * * root /sbin/shutdown -h now' > /etc/cron.d/threatfusion-autoshutdown
chmod 644 /etc/cron.d/threatfusion-autoshutdown
EOF
}

provision_generic() {
  if [[ -z "$VICTIM_HOST" || -z "$ATTACKER_HOST" ]]; then
    echo "Generic range needs --victim-host and --attacker-host, or TF_VICTIM_PUBLIC_IP and TF_ATTACKER_PUBLIC_IP." >&2
    exit 1
  fi
  PROVIDER="generic"
  ACCOUNT_ID="${CLOUD_ACCOUNT_ID:-generic-linux}"
  REGION_NAME="${CLOUD_REGION:-generic}"
  RESOURCE_GROUP="generic-linux-hosts"
  VICTIM_PUBLIC="$VICTIM_HOST"
  ATTACKER_PUBLIC="$ATTACKER_HOST"
  SSH_USER="${TF_SSH_USER:-ubuntu}"
  VICTIM_STATE="recorded"
  ATTACKER_STATE="recorded"
  write_state_json
}

provision_aws() {
  local cidr ami key_name vpc subnet igw route sg victim attacker
  cidr="$(require_ssh_cidr)"
  read_aws_account
  RESOURCE_GROUP="$RANGE_TAG"
  SSH_USER="${TF_SSH_USER:-ubuntu}"
  key_name="${CLOUD_SSH_KEY_NAME:-threatfusion-range}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: aws ec2 range in ${REGION_NAME} account ${ACCOUNT_ID:-from-cli} cidr ${cidr}"
    VICTIM_STATE="dry-run"
    ATTACKER_STATE="dry-run"
    write_state_json
    return 0
  fi
  if ! aws ec2 describe-key-pairs --key-names "$key_name" --region "$REGION_NAME" >/dev/null 2>&1; then
    mkdir -p "$STATE_DIR"
    aws ec2 create-key-pair --region "$REGION_NAME" --key-name "$key_name" \
      --query KeyMaterial --output text > "${STATE_DIR}/${key_name}.pem"
    chmod 600 "${STATE_DIR}/${key_name}.pem"
  fi
  vpc="$(aws ec2 describe-vpcs --region "$REGION_NAME" \
    --filters "Name=tag:Name,Values=${RANGE_TAG}" "Name=cidr,Values=${VPC_CIDR}" \
    --query 'Vpcs[0].VpcId' --output text)"
  if [[ -z "$vpc" || "$vpc" == "None" ]]; then
    vpc="$(aws ec2 create-vpc --region "$REGION_NAME" --cidr-block "$VPC_CIDR" \
      --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=${RANGE_TAG}}]" \
      --query Vpc.VpcId --output text)"
    aws ec2 modify-vpc-attribute --region "$REGION_NAME" --vpc-id "$vpc" --enable-dns-support
    aws ec2 modify-vpc-attribute --region "$REGION_NAME" --vpc-id "$vpc" --enable-dns-hostnames
  fi
  subnet="$(aws ec2 describe-subnets --region "$REGION_NAME" \
    --filters "Name=vpc-id,Values=${vpc}" "Name=cidr,Values=${SUBNET_CIDR}" \
    --query 'Subnets[0].SubnetId' --output text)"
  if [[ -z "$subnet" || "$subnet" == "None" ]]; then
    subnet="$(aws ec2 create-subnet --region "$REGION_NAME" --vpc-id "$vpc" \
      --cidr-block "$SUBNET_CIDR" \
      --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=tf-range-subnet}]" \
      --query Subnet.SubnetId --output text)"
    aws ec2 modify-subnet-attribute --region "$REGION_NAME" --subnet-id "$subnet" --map-public-ip-on-launch
  fi
  igw="$(aws ec2 describe-internet-gateways --region "$REGION_NAME" \
    --filters "Name=attachment.vpc-id,Values=${vpc}" \
    --query 'InternetGateways[0].InternetGatewayId' --output text)"
  if [[ -z "$igw" || "$igw" == "None" ]]; then
    igw="$(aws ec2 create-internet-gateway --region "$REGION_NAME" \
      --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${RANGE_TAG}}]" \
      --query InternetGateway.InternetGatewayId --output text)"
    aws ec2 attach-internet-gateway --region "$REGION_NAME" --internet-gateway-id "$igw" --vpc-id "$vpc"
  fi
  route="$(aws ec2 describe-route-tables --region "$REGION_NAME" \
    --filters "Name=vpc-id,Values=${vpc}" "Name=association.main,Values=true" \
    --query 'RouteTables[0].RouteTableId' --output text)"
  aws ec2 create-route --region "$REGION_NAME" --route-table-id "$route" \
    --destination-cidr-block "0.0.0.0/0" --gateway-id "$igw" >/dev/null 2>&1 || true
  sg="$(aws ec2 describe-security-groups --region "$REGION_NAME" \
    --filters "Name=vpc-id,Values=${vpc}" "Name=group-name,Values=${RANGE_TAG}" \
    --query 'SecurityGroups[0].GroupId' --output text)"
  if [[ -z "$sg" || "$sg" == "None" ]]; then
    sg="$(aws ec2 create-security-group --region "$REGION_NAME" --vpc-id "$vpc" \
      --group-name "$RANGE_TAG" --description "ThreatFusion range SSH" \
      --query GroupId --output text)"
  fi
  aws ec2 authorize-security-group-ingress --region "$REGION_NAME" --group-id "$sg" \
    --protocol tcp --port 22 --cidr "$cidr" >/dev/null 2>&1 || true
  aws ec2 authorize-security-group-ingress --region "$REGION_NAME" --group-id "$sg" \
    --protocol -1 --cidr "$SUBNET_CIDR" >/dev/null 2>&1 || true
  # Port 8766 stays closed to 0.0.0.0/0. Operators use an SSH local forward.
  aws ec2 revoke-security-group-ingress --region "$REGION_NAME" --group-id "$sg" \
    --protocol tcp --port 8766 --cidr "0.0.0.0/0" >/dev/null 2>&1 || true
  aws ec2 revoke-security-group-ingress --region "$REGION_NAME" --group-id "$sg" \
    --protocol tcp --port 8766 --cidr "$cidr" >/dev/null 2>&1 || true
  local instance_type="${CLOUD_INSTANCE_TYPE:-t3.small}"
  local ami_arch="amd64"
  case "$instance_type" in
    t4g.*|c6g.*|m6g.*|c7g.*|m7g.*)
      ami_arch="arm64"
      ;;
  esac
  ami="$(aws ssm get-parameter --region "$REGION_NAME" \
    --name "/aws/service/canonical/ubuntu/server/24.04/stable/current/${ami_arch}/hvm/ebs-gp3/ami-id" \
    --query Parameter.Value --output text)"
  local root_dev
  root_dev="$(aws ec2 describe-images --region "$REGION_NAME" --image-ids "$ami" \
    --query 'Images[0].RootDeviceName' --output text 2>/dev/null || true)"
  if [[ -z "$root_dev" || "$root_dev" == "None" ]]; then
    root_dev="/dev/sda1"
  fi
  local user_data
  user_data="$(mktemp)"
  shutdown_user_data > "$user_data"
  launch_one() {
    local name="$1" private_ip="$2" existing
    existing="$(aws ec2 describe-instances --region "$REGION_NAME" \
      --filters "Name=tag:Name,Values=${name}" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
      --query 'Reservations[0].Instances[0].InstanceId' --output text)"
    if [[ -n "$existing" && "$existing" != "None" ]]; then
      printf '%s\n' "$existing"
      return 0
    fi
    aws ec2 run-instances --region "$REGION_NAME" --image-id "$ami" \
      --instance-type "$instance_type" --key-name "$key_name" \
      --subnet-id "$subnet" --private-ip-address "$private_ip" \
      --security-group-ids "$sg" --user-data "file://${user_data}" \
      --block-device-mappings "[{\"DeviceName\":\"${root_dev}\",\"Ebs\":{\"VolumeSize\":24,\"VolumeType\":\"gp3\",\"DeleteOnTermination\":true}}]" \
      --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${name}},{Key=Project,Value=${RANGE_TAG}}]" "ResourceType=volume,Tags=[{Key=Name,Value=${name}},{Key=Project,Value=${RANGE_TAG}}]" \
      --query 'Instances[0].InstanceId' --output text
  }
  victim="$(launch_one tf-soc-victim-vm "$VICTIM_PRIVATE")"
  attacker="$(launch_one tf-attacker-redteam-vm "$ATTACKER_PRIVATE")"
  rm -f "$user_data"
  aws ec2 wait instance-running --region "$REGION_NAME" --instance-ids "$victim" "$attacker"
  VICTIM_PUBLIC="$(aws ec2 describe-instances --region "$REGION_NAME" --instance-ids "$victim" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
  ATTACKER_PUBLIC="$(aws ec2 describe-instances --region "$REGION_NAME" --instance-ids "$attacker" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
  VICTIM_STATE="running"
  ATTACKER_STATE="running"
  RESOURCE_IDS="$(python3 -c 'import json,sys; print(json.dumps({"vpc_id": sys.argv[1], "subnet_id": sys.argv[2], "igw_id": sys.argv[3], "sg_id": sys.argv[4], "victim_id": sys.argv[5], "attacker_id": sys.argv[6], "key_name": sys.argv[7]}))' \
    "$vpc" "$subnet" "$igw" "$sg" "$victim" "$attacker" "$key_name")"
  write_state_json
}

provision_gcp() {
  local cidr zone
  cidr="$(require_ssh_cidr)"
  read_gcp_account
  zone="${CLOUD_ZONE:-${REGION_NAME}-a}"
  RESOURCE_GROUP="$RANGE_TAG"
  SSH_USER="${TF_SSH_USER:-ubuntu}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: gcloud range project ${PROJECT_ID:-from-cli} region ${REGION_NAME} cidr ${cidr}"
    VICTIM_STATE="dry-run"
    ATTACKER_STATE="dry-run"
    write_state_json
    return 0
  fi
  if ! gcloud compute networks describe "$RANGE_TAG" >/dev/null 2>&1; then
    gcloud compute networks create "$RANGE_TAG" --subnet-mode custom
  fi
  if ! gcloud compute networks subnets describe tf-range-subnet --region "$REGION_NAME" >/dev/null 2>&1; then
    gcloud compute networks subnets create tf-range-subnet \
      --network "$RANGE_TAG" --range "$SUBNET_CIDR" --region "$REGION_NAME"
  fi
  if gcloud compute firewall-rules describe threatfusion-range-ssh >/dev/null 2>&1; then
    gcloud compute firewall-rules update threatfusion-range-ssh \
      --allow tcp:22 --source-ranges "$cidr"
  else
    gcloud compute firewall-rules create threatfusion-range-ssh \
      --network "$RANGE_TAG" --allow tcp:22 \
      --source-ranges "$cidr" --target-tags "$RANGE_TAG"
  fi
  if gcloud compute firewall-rules describe threatfusion-range-internal >/dev/null 2>&1; then
    gcloud compute firewall-rules update threatfusion-range-internal \
      --allow tcp,udp,icmp --source-ranges "$SUBNET_CIDR" --target-tags "$RANGE_TAG"
  else
    gcloud compute firewall-rules create threatfusion-range-internal \
      --network "$RANGE_TAG" --allow tcp,udp,icmp \
      --source-ranges "$SUBNET_CIDR" --target-tags "$RANGE_TAG"
  fi
  ensure_admin_ssh_key
  local pub_key=""
  if [[ -f "${SSH_IDENTITY}.pub" ]]; then
    pub_key="$(tr -d '\r\n' < "${SSH_IDENTITY}.pub")"
  else
    pub_key="$(ssh-keygen -y -f "${SSH_IDENTITY}" 2>/dev/null | tr -d '\r\n' || true)"
  fi
  local gcp_machine_type="${CLOUD_INSTANCE_TYPE:-e2-micro}"
  local gcp_image_family="ubuntu-2404-lts-amd64"
  case "$gcp_machine_type" in
    t2a-*|c4a-*|n4a-*|*-arm64*)
      gcp_image_family="ubuntu-2404-lts-arm64"
      ;;
  esac
  local startup
  startup="$(mktemp)"
  shutdown_user_data > "$startup"
  launch_gcp() {
    local name="$1" private_ip="$2"
    if gcloud compute instances describe "$name" --zone "$zone" >/dev/null 2>&1; then
      return 0
    fi
    local -a metadata_args=()
    if [[ -n "$pub_key" ]]; then
      metadata_args+=(--metadata "ssh-keys=${SSH_USER}:${pub_key}")
    fi
    gcloud compute instances create "$name" \
      --zone "$zone" --machine-type "$gcp_machine_type" \
      --image-family "$gcp_image_family" --image-project ubuntu-os-cloud \
      --boot-disk-size 24GB \
      --subnet tf-range-subnet --private-network-ip "$private_ip" \
      --tags "$RANGE_TAG" ${metadata_args[@]+"${metadata_args[@]}"} \
      --metadata-from-file startup-script="$startup"
  }
  launch_gcp tf-soc-victim-vm "$VICTIM_PRIVATE"
  launch_gcp tf-attacker-redteam-vm "$ATTACKER_PRIVATE"
  rm -f "$startup"
  VICTIM_PUBLIC="$(gcloud compute instances describe tf-soc-victim-vm --zone "$zone" \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)')"
  ATTACKER_PUBLIC="$(gcloud compute instances describe tf-attacker-redteam-vm --zone "$zone" \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)')"
  VICTIM_STATE="running"
  ATTACKER_STATE="running"
  ACCOUNT_ID="${PROJECT_ID}"
  RESOURCE_IDS="$(python3 -c 'import json,sys; print(json.dumps({"network": sys.argv[1], "subnet": sys.argv[2], "zone": sys.argv[3]}))' \
    "$RANGE_TAG" "tf-range-subnet" "$zone")"
  write_state_json
}

victim_ssh_target() {
  load_existing_public_ips
  if [[ -n "$VICTIM_HOST" ]]; then
    VICTIM_PUBLIC="$VICTIM_HOST"
  fi
  SSH_USER="${TF_SSH_USER:-${SSH_USER:-ubuntu}}"
  if [[ -z "${VICTIM_PUBLIC:-}" || "${VICTIM_PUBLIC}" == "None" ]]; then
    echo "No victim public address is recorded. Provision the range or pass --victim-host." >&2
    exit 1
  fi
  printf '%s@%s\n' "$SSH_USER" "$VICTIM_PUBLIC"
}

ensure_admin_ssh_key() {
  if [[ -n "${TF_SSH_IDENTITY:-}" && -f "${TF_SSH_IDENTITY}" ]]; then
    SSH_IDENTITY="$TF_SSH_IDENTITY"
    return 0
  fi
  if [[ "${PROVIDER:-}" == "aws" ]]; then
    local aws_key_name="${CLOUD_SSH_KEY_NAME:-${RANGE_TAG}}"
    local aws_cand
    for aws_cand in "${STATE_DIR}/${aws_key_name}.pem" "${STATE_DIR}/${RANGE_TAG}.pem"; do
      if [[ -f "$aws_cand" ]]; then
        SSH_IDENTITY="$aws_cand"
        return 0
      fi
    done
  fi
  local range_key="${STATE_DIR}/threatfusion-range-ed25519"
  if [[ -f "$range_key" ]]; then
    SSH_IDENTITY="$range_key"
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    SSH_IDENTITY="$range_key"
    echo "dry-run: ssh-keygen -t ed25519 -f ${SSH_IDENTITY}"
    return 0
  fi
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  ssh-keygen -t ed25519 -N "" -f "$range_key" -C "threatfusion-range"
  chmod 600 "$range_key"
  if [[ -f "${range_key}.pub" ]]; then
    chmod 644 "${range_key}.pub"
  fi
  SSH_IDENTITY="$range_key"
}

ssh_base() {
  ensure_admin_ssh_key
  printf '%s\n' "-i" "$SSH_IDENTITY" \
    "-o" "StrictHostKeyChecking=accept-new" \
    "-o" "BatchMode=yes" \
    "-o" "ServerAliveInterval=30" \
    "-o" "ServerAliveCountMax=6" \
    "-o" "ConnectTimeout=15"
}

load_cloud_env_file() {
  local env_file="$1" line key value
  [[ -f "$env_file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    case "$line" in
      ''|\#*) continue ;;
    esac
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      THREATFUSION_MISP_API_KEY|THREATFUSION_SOAR_HMAC_SECRET|THREATFUSION_SENSOR_INGEST_TOKEN|THREATFUSION_THEHIVE_SECRET|THREATFUSION_THEHIVE_API_KEY|THREATFUSION_N8N_USER|THREATFUSION_N8N_PASSWORD)
        if [[ -z "${!key:-}" ]]; then
          export "${key}=${value}"
        fi
        ;;
    esac
  done < "$env_file"
}

load_local_gemini_env() {
  local env_file="$1" line key value
  [[ -f "$env_file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"
    case "$key" in
      GEMINI_API_KEY|GEMINI_MODEL|GEMINI_ENABLED)
        if [[ ${#value} -ge 2 && ( "$value" == \"*\" || "$value" == \'*\' ) ]]; then
          value="${value:1:${#value}-2}"
        fi
        if [[ -z "${!key:-}" && -n "$value" ]]; then
          printf -v "$key" '%s' "$value"
          export "${key?}"
        fi
        ;;
    esac
  done < "$env_file"
}

write_cloud_env_file() {
  local env_file="$1" tmp key
  umask 077
  tmp="$(mktemp "${env_file}.XXXXXX")"
  chmod 600 "$tmp"
  {
    echo "# Local cloud secrets generated by scripts/deploy_cloud_range.sh. Do not commit."
    for key in "${STACK_SECRET_KEYS[@]}"; do
      printf '%s=%s\n' "$key" "${!key}"
    done
  } > "$tmp"
  mv "$tmp" "$env_file"
  chmod 600 "$env_file"
}

require_stack_env() {
  local key missing=0
  load_cloud_env_file "$CLOUD_ENV_FILE"
  for key in "${STACK_SECRET_KEYS[@]}"; do
    if [[ -z "${!key:-}" ]]; then
      missing=1
      if [[ "$DRY_RUN" -eq 0 ]]; then
        if ! command -v openssl >/dev/null 2>&1; then
          echo "openssl is required to generate stack secrets." >&2
          exit 1
        fi
        export "${key}=$(openssl rand -hex 32)"
      fi
    fi
  done
  if [[ "$DRY_RUN" -eq 1 ]]; then
    if [[ "$missing" -eq 1 ]]; then
      echo "dry-run: generate missing THREATFUSION_* secrets into ${CLOUD_ENV_FILE} mode 0600"
    fi
    return 0
  fi
  write_cloud_env_file "$CLOUD_ENV_FILE"
}

install_attacker_tooling() {
  # nmap, curl, and python3 belong on the attacker VM. Missing tools are installed
  # before a live probe. Dry-run only prints the plan.
  local mode="${1:-optional}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: attacker apt-get install -y nmap curl python3"
    echo "dry-run: fail-fast if nmap, curl, or python3 is still missing"
    return 0
  fi
  load_existing_public_ips
  SSH_USER="${TF_SSH_USER:-${SSH_USER:-ubuntu}}"
  local target="${ATTACKER_HOST:-${ATTACKER_PUBLIC:-}}"
  if [[ -z "$target" ]]; then
    if [[ "$mode" == "required" ]]; then
      echo "Attacker host is not recorded. Set --attacker-host or TF_ATTACKER_PUBLIC_IP." >&2
      exit 1
    fi
    echo "Attacker host is not recorded. nmap install runs with --simulate-attack."
    return 0
  fi
  local -a ssh_args=()
  local _a
  while IFS= read -r _a; do
    ssh_args+=("$_a")
  done < <(ssh_base)
  ssh ${ssh_args[@]+"${ssh_args[@]}"} "${SSH_USER}@${target}" "bash -s" <<'REMOTE'
set -euo pipefail
missing=()
for tool in nmap curl python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done
if [[ ${#missing[@]} -gt 0 ]]; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "attacker is missing: ${missing[*]} and apt-get is unavailable" >&2
    exit 1
  fi
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" nmap curl python3
fi
for tool in nmap curl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "attacker tool still missing: $tool" >&2; exit 1; }
done
REMOTE
}

verify_live_flow_bridge() {
  # Victim Suricata eve.json must be followed into ThreatFusion and answer HTTP 200.
  # A live probe is confirmed only when alerts.sqlite3 reports stored_rows > 0.
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: start threatfusion-eve-follower on victim eve.json"
    echo "dry-run: curl -fsS http://127.0.0.1:8766/readyz expects HTTP 200"
    echo "dry-run: python3 checks threatfusion-live-console.sqlite3 / alerts.sqlite3 stored_rows > 0"
    return 0
  fi
  load_existing_public_ips
  SSH_USER="${TF_SSH_USER:-${SSH_USER:-ubuntu}}"
  local target="${VICTIM_HOST:-${VICTIM_PUBLIC:-}}"
  if [[ -z "$target" ]]; then
    echo "Victim host is not recorded. Set --victim-host or TF_VICTIM_PUBLIC_IP." >&2
    exit 1
  fi
  local -a ssh_args=()
  local _a
  while IFS= read -r _a; do
    ssh_args+=("$_a")
  done < <(ssh_base)
  ssh ${ssh_args[@]+"${ssh_args[@]}"} "${SSH_USER}@${target}" "bash -s" <<'REMOTE'
set -euo pipefail
if command -v systemctl >/dev/null 2>&1; then
  sudo systemctl enable --now suricata || true
  if [[ -f /etc/systemd/system/threatfusion-eve-follower.service ]]; then
    sudo systemctl enable --now threatfusion-eve-follower.service
  fi
fi
if [[ ! -f /var/log/suricata/eve.json ]]; then
  echo "victim Suricata eve.json is missing" >&2
  exit 1
fi
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8766/readyz || true)"
if [[ "$code" != "200" ]]; then
  echo "live flow bridge health check returned HTTP ${code:-000}, expected 200" >&2
  exit 1
fi
python3 - <<'PY'
import sqlite3
import sys
import time
from pathlib import Path

candidates = (
    Path("/var/lib/threatfusion/threatfusion-live-console.sqlite3"),
    Path("/tmp/threatfusion-range-demo/threatfusion-live-console.sqlite3"),
    Path("/var/lib/threatfusion/alerts.sqlite3"),
    Path("/opt/threatfusion/alerts.sqlite3"),
    Path("/var/lib/threatfusion/live_console.sqlite3"),
)
deadline = time.monotonic() + 90.0
count = 0
while True:
    max_count = 0
    for path in candidates:
        if not path.is_file():
            continue
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2.0)
        except sqlite3.Error:
            continue
        try:
            tables = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if "live_flows" in tables:
                max_count = max(
                    max_count,
                    int(conn.execute("SELECT COUNT(*) FROM live_flows").fetchone()[0]),
                )
            if "alerts" in tables:
                max_count = max(
                    max_count,
                    int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]),
                )
        except sqlite3.Error:
            pass
        finally:
            conn.close()
    count = max_count
    if count > 0 or time.monotonic() >= deadline:
        break
    time.sleep(2.0)
print(f"stored_rows={int(count)}")
if int(count) <= 0:
    sys.exit(1)
PY
REMOTE
}

simulate_range_attack() {
  install_attacker_tooling required
  load_existing_public_ips
  SSH_USER="${TF_SSH_USER:-${SSH_USER:-ubuntu}}"
  local attacker="${ATTACKER_HOST:-${ATTACKER_PUBLIC:-}}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: nmap -Pn -p 22,80,445 172.29.0.20 from the attacker VM"
    verify_live_flow_bridge
    return 0
  fi
  local -a ssh_args=()
  local _a
  while IFS= read -r _a; do
    ssh_args+=("$_a")
  done < <(ssh_base)
  ssh ${ssh_args[@]+"${ssh_args[@]}"} "${SSH_USER}@${attacker}" "command -v nmap >/dev/null && command -v curl >/dev/null && command -v python3 >/dev/null && nmap -Pn -p 22,80,445 172.29.0.20"
  verify_live_flow_bridge
}

deploy_full_stack() {
  local target env_file
  local -a ssh_args=()
  ensure_admin_ssh_key
  require_stack_env
  install_attacker_tooling
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: deploy_full_stack preflight passed."
    echo "dry-run: rsync repo to victim:/opt/threatfusion excluding .git data/raw data/interim *.npy venv __pycache__ .env"
    echo "dry-run: THREATFUSION_ENV=production docker compose restart: unless-stopped"
    echo "dry-run: install and enable threatfusion-eve-follower.service with /opt/threatfusion-venv/bin/python"
    echo "dry-run: poll /readyz then ssh -N -L 8766:127.0.0.1:8766"
    verify_live_flow_bridge
    return 0
  fi
  load_local_gemini_env "${ROOT}/.env"
  target="$(victim_ssh_target)"
  env_file="$(mktemp)"
  chmod 600 "$env_file"
  umask 077
  cat > "$env_file" <<EOF
THREATFUSION_ENV=production
THREATFUSION_DATA_DIR=/var/lib/threatfusion
THREATFUSION_LIVE_CONSOLE_DB=/var/lib/threatfusion/threatfusion-live-console.sqlite3
THREATFUSION_MISP_API_KEY=${THREATFUSION_MISP_API_KEY:-}
THREATFUSION_SOAR_HMAC_SECRET=${THREATFUSION_SOAR_HMAC_SECRET:-}
THREATFUSION_SENSOR_INGEST_TOKEN=${THREATFUSION_SENSOR_INGEST_TOKEN:-}
THREATFUSION_THEHIVE_SECRET=${THREATFUSION_THEHIVE_SECRET:-}
THREATFUSION_THEHIVE_API_KEY=${THREATFUSION_THEHIVE_API_KEY:-}
THREATFUSION_N8N_USER=${THREATFUSION_N8N_USER:-}
THREATFUSION_N8N_PASSWORD=${THREATFUSION_N8N_PASSWORD:-}
TF_ADMIN_EMAIL=${TF_ADMIN_EMAIL:-admin@threatfusion.local}
TF_ADMIN_SECRET=${TF_ADMIN_SECRET:-}
GEMINI_ENABLED=${GEMINI_ENABLED:-false}
EOF
  if [[ -n "${GEMINI_API_KEY:-}" ]]; then
    printf 'GEMINI_API_KEY=%s\n' "${GEMINI_API_KEY}" >> "$env_file"
  fi
  if [[ -n "${GEMINI_MODEL:-}" ]]; then
    printf 'GEMINI_MODEL=%s\n' "${GEMINI_MODEL}" >> "$env_file"
  fi
  local -a ssh_args=()
  local _a
  while IFS= read -r _a; do
    ssh_args+=("$_a")
  done < <(ssh_base)
  ssh ${ssh_args[@]+"${ssh_args[@]}"} "$target" "sudo mkdir -p /opt/threatfusion /opt/threatfusion-venv /var/lib/threatfusion && sudo chown -R \$(id -u):\$(id -g) /opt/threatfusion /opt/threatfusion-venv /var/lib/threatfusion && chmod 700 /var/lib/threatfusion"
  COPYFILE_DISABLE=1 tar -C "$ROOT" \
    --exclude .git \
    --exclude='data/raw' \
    --exclude='data/interim' \
    --exclude='*.npy' \
    --exclude='artifacts/reports/network_cic_external_evaluation' \
    --exclude='artifacts/reports/network_classical_evaluation' \
    --exclude threatfusion-venv \
    --exclude .venv \
    --exclude venv \
    --exclude __pycache__ \
    --exclude .env \
    --exclude '.env.*' \
    --exclude .cursor \
    -czf - . | ssh ${ssh_args[@]+"${ssh_args[@]}"} "$target" "tar -C /opt/threatfusion -xzf -"
  scp ${ssh_args[@]+"${ssh_args[@]}"} "$env_file" "${target}:/opt/threatfusion/.env"
  rm -f "$env_file"
  ssh ${ssh_args[@]+"${ssh_args[@]}"} "$target" "bash -s" <<'REMOTE'
set -euo pipefail
cd /opt/threatfusion
chmod 600 .env
sudo mkdir -p /var/lib/threatfusion
sudo chown "$(id -u):$(id -g)" /var/lib/threatfusion
chmod 700 /var/lib/threatfusion
echo "[1/6] Allocating 4GB swapfile"
if ! swapon --show | grep -q '/swapfile'; then
  if [[ ! -f /swapfile ]]; then
    sudo fallocate -l 4G /swapfile 2>/dev/null || sudo dd if=/dev/zero of=/swapfile bs=1M count=4096
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
  fi
  sudo swapon /swapfile || true
  if ! grep -q '/swapfile' /etc/fstab; then
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
  fi
fi
echo "[2/6] Installing packages non-interactively"
if command -v apt-get >/dev/null 2>&1; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
    docker.io docker-compose-v2 suricata ethtool python3 python3-venv python3-pip nmap curl
  sudo systemctl enable --now docker
fi
PRIMARY_NIC="$(ip -o -4 route show to default | awk '{print $5; exit}')"
PRIMARY_NIC="${PRIMARY_NIC:-eth0}"
ETHTOOL_BIN=""
for _cand in /sbin/ethtool /usr/sbin/ethtool; do
  if [[ -x "$_cand" ]]; then
    ETHTOOL_BIN="$_cand"
    break
  fi
done
if [[ -z "$ETHTOOL_BIN" ]]; then
  ETHTOOL_BIN="$(command -v ethtool || true)"
fi
ETHTOOL_BIN="${ETHTOOL_BIN:-/sbin/ethtool}"
sudo "$ETHTOOL_BIN" -K "$PRIMARY_NIC" gro off lro off tso off gso off 2>/dev/null || true
if [[ -f /etc/suricata/suricata.yaml ]]; then
  sudo python3 - "$PRIMARY_NIC" <<'SURICATA_PY'
import re
import sys
from pathlib import Path

nic = sys.argv[1]
cfg_path = Path("/etc/suricata/suricata.yaml")
text = cfg_path.read_text(encoding="utf-8")
text = re.sub(
    r"(?ms)(^af-packet:\s*\n(?:[ \t]*#[^\n]*\n|[ \t]+[^\n]*\n)*?[ \t]*-\s*interface:\s*)([^\s#\n]+)",
    rf"\g<1>{nic}",
    text,
    count=1,
)
if re.search(r"(?m)^[ \t]*checksum-validation:\s*", text):
    text = re.sub(
        r"(?m)^([ \t]*checksum-validation:\s*)[^\s#\n]+",
        r"\g<1>no",
        text,
    )
else:
    text = re.sub(
        r"(?m)^(stream:\s*\n)",
        r"\1  checksum-validation: no\n",
        text,
        count=1,
    )
cfg_path.write_text(text, encoding="utf-8")
SURICATA_PY
fi
sudo mkdir -p /etc/systemd/system/suricata.service.d
sudo tee /etc/systemd/system/suricata.service.d/threatfusion-offload.conf >/dev/null <<EOF
[Service]
ExecStartPre=-${ETHTOOL_BIN} -K ${PRIMARY_NIC} gro off lro off tso off gso off
EOF
sudo install -d -m 0755 /var/log/suricata
if [[ ! -f /var/log/suricata/eve.json ]]; then
  sudo touch /var/log/suricata/eve.json
fi
if id -u suricata >/dev/null 2>&1; then
  sudo chown -R suricata:suricata /var/log/suricata
fi
if command -v systemctl >/dev/null 2>&1; then
  sudo systemctl daemon-reload
  sudo systemctl enable --now suricata || true
  sudo systemctl restart suricata || true
fi
echo "[3/6] Starting SOC stack without a second publisher on port 5678"
sudo docker compose --env-file .env -f docker/docker-compose.soc-stack.yml up -d
if [[ -f docker/docker-compose.n8n.yml ]] && ! grep -q '5678:5678' docker/docker-compose.soc-stack.yml; then
  sudo docker compose --env-file .env -f docker/docker-compose.n8n.yml up -d
fi
echo "[4/6] Preparing locked Python 3.11 virtualenv via uv"
export PATH="${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"
fi
if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required to provision /opt/threatfusion-venv with locked Python 3.11 dependencies." >&2
  exit 1
fi
if ! uv python find 3.11 >/dev/null 2>&1; then
  uv python install 3.11
fi
if [[ -x /opt/threatfusion-venv/bin/python ]] && ! /opt/threatfusion-venv/bin/python -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)" >/dev/null 2>&1; then
  rm -rf /opt/threatfusion-venv
fi
UV_PROJECT_ENVIRONMENT=/opt/threatfusion-venv uv sync --locked --python 3.11 --no-dev
if ! /opt/threatfusion-venv/bin/python -c "import sys, sklearn, threadpoolctl, torch; assert sys.version_info[:2] == (3, 11) and sklearn.__version__ == '1.9.0' and threadpoolctl.__version__ == '3.6.0' and torch.__version__.startswith('2.10.0')" >/dev/null 2>&1; then
  echo "Locked Python 3.11 runtime verification failed (expected torch==2.10.0+cpu, scikit-learn==1.9.0, threadpoolctl==3.6.0)." >&2
  exit 1
fi
cat > /opt/threatfusion/run-console-watchdog.sh <<'WATCH'
#!/bin/bash
set -euo pipefail
if [[ -f /opt/threatfusion/.env ]]; then
  while IFS='=' read -r k v || [[ -n "${k:-}${v:-}" ]]; do
    k="${k%$'\r'}"
    v="${v%$'\r'}"
    k="${k#"${k%%[![:space:]]*}"}"
    k="${k%"${k##*[![:space:]]}"}"
    [[ -z "$k" || "$k" == \#* ]] && continue
    if [[ "$k" == export\ * ]]; then
      k="${k#export }"
      k="${k#"${k%%[![:space:]]*}"}"
    fi
    case "$k" in
      THREATFUSION_*|TF_*|GEMINI_*)
        if [[ ! "$k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
          continue
        fi
        if [[ ${#v} -ge 2 && ( ( "$v" == \"*\" ) || ( "$v" == \'*\' ) ) ]]; then
          v="${v:1:${#v}-2}"
        fi
        printf -v "$k" '%s' "$v"
        export "${k?}"
        ;;
    esac
  done < /opt/threatfusion/.env
fi
export THREATFUSION_ENV=production
export THREATFUSION_DATA_DIR="${THREATFUSION_DATA_DIR:-/var/lib/threatfusion}"
export THREATFUSION_LIVE_CONSOLE_DB="${THREATFUSION_LIVE_CONSOLE_DB:-/var/lib/threatfusion/threatfusion-live-console.sqlite3}"
mkdir -p "$THREATFUSION_DATA_DIR"
chmod 700 "$THREATFUSION_DATA_DIR"
export PYTHONPATH=/opt/threatfusion/backend/src
while true; do
  /opt/threatfusion-venv/bin/python /opt/threatfusion/scripts/run_misp_and_callback_contract_server.py \
    --bind 127.0.0.1 --port 8766 >>/var/lib/threatfusion/console.log 2>&1 || true
  sleep 2
done
WATCH
chmod 700 /opt/threatfusion/run-console-watchdog.sh
if [[ -f /var/lib/threatfusion/console-watchdog.pid ]]; then
  old="$(cat /var/lib/threatfusion/console-watchdog.pid || true)"
  if [[ -n "${old}" ]] && kill -0 "$old" 2>/dev/null; then
    echo "console watchdog already running (${old})"
  else
    nohup /opt/threatfusion/run-console-watchdog.sh >/var/lib/threatfusion/watchdog.log 2>&1 &
    echo $! > /var/lib/threatfusion/console-watchdog.pid
  fi
else
  nohup /opt/threatfusion/run-console-watchdog.sh >/var/lib/threatfusion/watchdog.log 2>&1 &
  echo $! > /var/lib/threatfusion/console-watchdog.pid
fi
echo "[5/6] Polling /readyz for up to 180s"
python3 - <<'PY'
import time, urllib.request
deadline = time.time() + 180
started = time.time()
last = ""
print("[5/6] polling /readyz (deadline 180s)", flush=True)
while time.time() < deadline:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8766/readyz", timeout=3) as response:
            body = response.read().decode("utf-8")
            if response.status == 200 and '"ready"' in body:
                print(body)
                raise SystemExit(0)
            last = body
    except Exception as exc:
        last = str(exc)
    elapsed = int(time.time() - started)
    print(f"[5/6] /readyz waiting {elapsed}s", flush=True)
    time.sleep(2)
print(last)
raise SystemExit(1)
PY
echo "[6/6] Installing and enabling threatfusion-eve-follower.service"
sudo install -d -m 0755 /var/log/suricata
if [[ ! -f /var/log/suricata/eve.json ]]; then
  sudo touch /var/log/suricata/eve.json
fi
if id -u suricata >/dev/null 2>&1; then
  sudo chown -R suricata:suricata /var/log/suricata
fi
sudo tee /etc/systemd/system/threatfusion-eve-follower.service >/dev/null <<'UNIT'
[Unit]
Description=ThreatFusion Suricata EVE follower
After=network-online.target suricata.service

[Service]
WorkingDirectory=/opt/threatfusion
EnvironmentFile=/opt/threatfusion/.env
Environment=PYTHONPATH=/opt/threatfusion/backend/src
ExecStart=/opt/threatfusion-venv/bin/python /opt/threatfusion/scripts/follow_suricata_eve.py --eve /var/log/suricata/eve.json --console-url http://127.0.0.1:8766/api/v1/live/sensor
Restart=on-failure
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now suricata || true
sudo systemctl enable --now threatfusion-eve-follower.service
REMOTE
  ssh -N -L 8766:127.0.0.1:8766 -o ExitOnForwardFailure=yes ${ssh_args[@]+"${ssh_args[@]}"} -f "$target"
  echo "Operator console: http://127.0.0.1:8766/"
  echo "Port 8766 stays closed to 0.0.0.0/0. Access is the SSH local forward."
}

verify_teardown_zero_burn() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: verify zero orphaned disks or public IPs remain (idle burn 0.00)"
    return 0
  fi
  case "$PROVIDER" in
    aws)
      REGION_NAME="${REGION_NAME:-${CLOUD_REGION:-}}"
      if [[ -z "$REGION_NAME" ]]; then
        REGION_NAME="$(load_saved_state_field "aws" "region")"
      fi
      REGION_NAME="${REGION_NAME:-us-east-1}"
      local instances volume_rows volumes address_rows addresses
      instances="$(aws ec2 describe-instances --region "$REGION_NAME" \
        --filters "Name=tag:Project,Values=${RANGE_TAG}" "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down" \
        --query 'Reservations[].Instances[].InstanceId' --output text)"
      if [[ -n "$instances" && "$instances" != "None" ]]; then
        echo "Orphaned EC2 instances remain after teardown: ${instances}" >&2
        exit 1
      fi
      volume_rows="$(aws ec2 describe-volumes --region "$REGION_NAME" \
        --filters "Name=tag:Project,Values=${RANGE_TAG}" \
        --query 'Volumes[].[VolumeId,State]' --output text)"
      if [[ -n "$volume_rows" && "$volume_rows" != "None" ]]; then
        local volume_id volume_state
        while read -r volume_id volume_state; do
          [[ -z "$volume_id" || "$volume_id" == "None" ]] && continue
          if [[ "$volume_state" == "available" ]]; then
            aws ec2 delete-volume --region "$REGION_NAME" --volume-id "$volume_id" || true
          fi
        done <<< "$volume_rows"
      fi
      volumes="$(aws ec2 describe-volumes --region "$REGION_NAME" \
        --filters "Name=tag:Project,Values=${RANGE_TAG}" \
        --query 'Volumes[].VolumeId' --output text)"
      if [[ -n "$volumes" && "$volumes" != "None" ]]; then
        echo "Orphaned disks remain after teardown: ${volumes}" >&2
        exit 1
      fi
      address_rows="$(aws ec2 describe-addresses --region "$REGION_NAME" \
        --filters "Name=tag:Project,Values=${RANGE_TAG}" \
        --query 'Addresses[].[AllocationId,AssociationId]' --output text)"
      if [[ -n "$address_rows" && "$address_rows" != "None" ]]; then
        local allocation assoc_id
        while read -r allocation assoc_id; do
          [[ -z "$allocation" || "$allocation" == "None" ]] && continue
          if [[ -z "$assoc_id" || "$assoc_id" == "None" ]]; then
            aws ec2 release-address --region "$REGION_NAME" --allocation-id "$allocation" || true
          fi
        done <<< "$address_rows"
      fi
      addresses="$(aws ec2 describe-addresses --region "$REGION_NAME" \
        --filters "Name=tag:Project,Values=${RANGE_TAG}" \
        --query 'Addresses[].AllocationId' --output text)"
      if [[ -n "$addresses" && "$addresses" != "None" ]]; then
        echo "Orphaned public IPs remain after teardown: ${addresses}" >&2
        exit 1
      fi
      ;;
    gcp)
      local instances disks addresses
      instances="$(gcloud compute instances list --filter="name~'^tf-'" --format='value(name)')"
      if [[ -n "$instances" ]]; then
        echo "Orphaned instances remain after teardown: ${instances}" >&2
        exit 1
      fi
      disks="$(gcloud compute disks list --filter="name~'^tf-'" --format='value(name)')"
      if [[ -n "$disks" ]]; then
        echo "Orphaned disks remain after teardown: ${disks}" >&2
        exit 1
      fi
      addresses="$(gcloud compute addresses list --filter="name~'^tf-'" --format='value(name)')"
      if [[ -n "$addresses" ]]; then
        echo "Orphaned public IPs remain after teardown: ${addresses}" >&2
        exit 1
      fi
      ;;
    azure)
      if ! command -v az >/dev/null 2>&1; then
        echo "az CLI is required to verify Azure teardown." >&2
        exit 1
      fi
      az group wait --name ThreatFusion-RG --deleted >/dev/null 2>&1 || true
      local rg_exists
      rg_exists="$(az group exists --name ThreatFusion-RG --output tsv 2>/dev/null || echo true)"
      if [[ "$rg_exists" != "false" ]]; then
        local rg_state
        rg_state="$(az group show --name ThreatFusion-RG --query properties.provisioningState -o tsv 2>/dev/null || true)"
        if [[ "$rg_state" == "Deleting" ]]; then
          echo "Azure resource group ThreatFusion-RG is still in state \"Deleting\" after teardown wait." >&2
        else
          echo "Azure resource group ThreatFusion-RG still exists after teardown (exists=${rg_exists:-unknown}, state=${rg_state:-unknown})." >&2
        fi
        exit 1
      fi
      ;;
    generic)
      ;;
  esac
  echo "Teardown verified: zero orphaned disks or public IPs. Idle burn 0.00."
}

teardown_aws() {
  local forced_region="${CLOUD_REGION:-${REGION_NAME:-}}"
  read_aws_account
  if [[ -n "$forced_region" ]]; then
    REGION_NAME="$forced_region"
  else
    local saved_region
    saved_region="$(load_saved_state_field "aws" "region")"
    if [[ -n "$saved_region" ]]; then
      REGION_NAME="$saved_region"
    fi
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: delete tagged ${RANGE_TAG} instances, security group, subnet, gateway, and vpc in ${REGION_NAME}"
    return 0
  fi
  local ids vpc subnet igw sg
  ids="$(aws ec2 describe-instances --region "$REGION_NAME" \
    --filters "Name=tag:Project,Values=${RANGE_TAG}" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' --output text || true)"
  if [[ -n "$ids" && "$ids" != "None" ]]; then
    # shellcheck disable=SC2086
    aws ec2 terminate-instances --region "$REGION_NAME" --instance-ids $ids >/dev/null
    # shellcheck disable=SC2086
    aws ec2 wait instance-terminated --region "$REGION_NAME" --instance-ids $ids || true
  fi
  vpc="$(aws ec2 describe-vpcs --region "$REGION_NAME" \
    --filters "Name=tag:Name,Values=${RANGE_TAG}" --query 'Vpcs[0].VpcId' --output text || true)"
  if [[ -n "$vpc" && "$vpc" != "None" ]]; then
    sg="$(aws ec2 describe-security-groups --region "$REGION_NAME" \
      --filters "Name=vpc-id,Values=${vpc}" "Name=group-name,Values=${RANGE_TAG}" \
      --query 'SecurityGroups[0].GroupId' --output text || true)"
  else
    sg="$(aws ec2 describe-security-groups --region "$REGION_NAME" \
      --filters "Name=group-name,Values=${RANGE_TAG}" --query 'SecurityGroups[0].GroupId' --output text || true)"
  fi
  if [[ -n "$sg" && "$sg" != "None" ]]; then
    aws ec2 delete-security-group --region "$REGION_NAME" --group-id "$sg" || true
  fi
  if [[ -n "$vpc" && "$vpc" != "None" ]]; then
    subnet="$(aws ec2 describe-subnets --region "$REGION_NAME" --filters "Name=vpc-id,Values=${vpc}" \
      --query 'Subnets[0].SubnetId' --output text || true)"
    igw="$(aws ec2 describe-internet-gateways --region "$REGION_NAME" \
      --filters "Name=attachment.vpc-id,Values=${vpc}" \
      --query 'InternetGateways[0].InternetGatewayId' --output text || true)"
    if [[ -n "$subnet" && "$subnet" != "None" ]]; then
      aws ec2 delete-subnet --region "$REGION_NAME" --subnet-id "$subnet" || true
    fi
    if [[ -n "$igw" && "$igw" == "None" ]]; then
      :
    elif [[ -n "$igw" ]]; then
      aws ec2 detach-internet-gateway --region "$REGION_NAME" --internet-gateway-id "$igw" --vpc-id "$vpc" || true
      aws ec2 delete-internet-gateway --region "$REGION_NAME" --internet-gateway-id "$igw" || true
    fi
    aws ec2 delete-vpc --region "$REGION_NAME" --vpc-id "$vpc" || true
  fi
}

teardown_gcp() {
  local forced_region="${CLOUD_REGION:-${REGION_NAME:-}}"
  local forced_zone="${CLOUD_ZONE:-}"
  read_gcp_account
  if [[ -n "$forced_region" ]]; then
    REGION_NAME="$forced_region"
  else
    local saved_region
    saved_region="$(load_saved_state_field "gcp" "region")"
    if [[ -n "$saved_region" ]]; then
      REGION_NAME="$saved_region"
    fi
  fi
  local zone="$forced_zone"
  if [[ -z "$zone" && -z "$forced_region" ]]; then
    zone="$(load_saved_state_field "gcp" "zone")"
  fi
  zone="${zone:-${REGION_NAME}-a}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: gcloud compute instances delete tf-soc-victim-vm tf-attacker-redteam-vm --zone ${zone}"
    return 0
  fi
  gcloud compute instances delete tf-soc-victim-vm tf-attacker-redteam-vm --zone "$zone" --quiet || true
  gcloud compute firewall-rules delete threatfusion-range-ssh --quiet || true
  gcloud compute firewall-rules delete threatfusion-range-internal --quiet || true
  gcloud compute networks subnets delete tf-range-subnet --region "$REGION_NAME" --quiet || true
  gcloud compute networks delete "$RANGE_TAG" --quiet || true
}

teardown_generic() {
  local target="${VICTIM_HOST:-}"
  load_existing_public_ips
  if [[ -z "$target" ]]; then
    target="${VICTIM_PUBLIC:-}"
  fi
  SSH_USER="${TF_SSH_USER:-${SSH_USER:-ubuntu}}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: docker compose down on ${SSH_USER}@${target} and remove local cloud state"
    return 0
  fi
  if [[ -n "$target" ]]; then
    local -a ssh_args=()
    local _a
    while IFS= read -r _a; do
      ssh_args+=("$_a")
    done < <(ssh_base)
    ssh ${ssh_args[@]+"${ssh_args[@]}"} \
      "${SSH_USER}@${target}" \
      "cd /opt/threatfusion && sudo docker compose -f docker/docker-compose.soc-stack.yml down && sudo docker compose -f docker/docker-compose.n8n.yml down" \
      || true
  fi
}

clear_state_files() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: rm -f ${CLOUD_STATE} ${AZURE_STATE}"
    return 0
  fi
  rm -f "$CLOUD_STATE" "$AZURE_STATE"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider)
      PROVIDER="${2:-}"
      shift 2
      ;;
    --provider=*)
      PROVIDER="${1#*=}"
      shift
      ;;
    --victim-host)
      VICTIM_HOST="${2:-}"
      shift 2
      ;;
    --attacker-host)
      ATTACKER_HOST="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --auto-ip)
      AUTO_IP=1
      shift
      ;;
    --low-cost-tier|--student-free-tier)
      LOW_COST_TIER=1
      shift
      ;;
    --help|-h)
      ACTION="help"
      shift
      ;;
    --provision-range|--deploy-full-stack|--simulate-attack|--teardown|--status|--deallocate|--pair-forwarder|--setup-entra-app)
      ACTION="${1#--}"
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$ACTION" || "$ACTION" == "help" ]]; then
  usage
  if [[ "$ACTION" == "help" ]]; then
    exit 0
  fi
  exit 2
fi

if [[ -z "$PROVIDER" ]]; then
  PROVIDER="$(detect_provider)"
fi
if [[ "$PROVIDER" == "ssh" ]]; then
  PROVIDER="generic"
fi
case "$PROVIDER" in
  azure|aws|gcp|generic) ;;
  *)
    echo "No cloud CLI session is logged in. Run 'az login' / 'aws configure' / 'gcloud auth login' + ./scripts/deploy_cloud_range.sh --provision-range" >&2
    exit 1
    ;;
esac

victim_public_recorded() {
  if [[ -n "${VICTIM_HOST:-}" ]]; then
    return 0
  fi
  load_existing_public_ips
  if [[ -n "${VICTIM_PUBLIC:-}" && "${VICTIM_PUBLIC}" != "None" ]]; then
    return 0
  fi
  return 1
}

provision_selected_range() {
  case "$PROVIDER" in
    azure)
      require_ssh_cidr >/dev/null
      azure_delegate --provision-live-azure
      ;;
    aws) provision_aws ;;
    gcp) provision_gcp ;;
    generic) provision_generic ;;
  esac
}

case "$ACTION" in
  provision-range)
    provision_selected_range
    ;;
  simulate-attack)
    simulate_range_attack
    ;;
  deploy-full-stack)
    if ! victim_public_recorded; then
      if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "dry-run: no victim public address in cloud_state.json; provision-range is not called"
      else
        echo "No victim public address is recorded. Provisioning the range before deploy-full-stack."
        provision_selected_range
        load_existing_public_ips
      fi
    fi
    deploy_full_stack
    ;;
  teardown)
    case "$PROVIDER" in
      azure) azure_delegate --teardown-rg ;;
      aws) teardown_aws ;;
      gcp) teardown_gcp ;;
      generic) teardown_generic ;;
    esac
    verify_teardown_zero_burn
    clear_state_files
    ;;
  status)
    case "$PROVIDER" in
      azure)
        azure_delegate --status || true
        if [[ ! -f "$AZURE_STATE" ]]; then
          read_azure_account
          RESOURCE_GROUP="ThreatFusion-RG"
          SSH_USER="${TF_SSH_USER:-azureuser}"
          VICTIM_STATE="not-recorded"
          ATTACKER_STATE="not-recorded"
          write_state_json
        fi
        ;;
      aws)
        read_aws_account
        RESOURCE_GROUP="$RANGE_TAG"
        SSH_USER="${TF_SSH_USER:-ubuntu}"
        load_existing_public_ips
        VICTIM_STATE="${VICTIM_STATE:-recorded}"
        ATTACKER_STATE="${ATTACKER_STATE:-recorded}"
        write_state_json
        ;;
      gcp)
        read_gcp_account
        ACCOUNT_ID="${PROJECT_ID:-}"
        RESOURCE_GROUP="$RANGE_TAG"
        load_existing_public_ips
        VICTIM_STATE="${VICTIM_STATE:-recorded}"
        ATTACKER_STATE="${ATTACKER_STATE:-recorded}"
        write_state_json
        ;;
      generic)
        if [[ -n "$VICTIM_HOST" && -n "$ATTACKER_HOST" ]]; then
          provision_generic
        else
          load_existing_public_ips
          if [[ -n "$VICTIM_HOST" ]]; then
            VICTIM_PUBLIC="$VICTIM_HOST"
          fi
          if [[ -n "$ATTACKER_HOST" ]]; then
            ATTACKER_PUBLIC="$ATTACKER_HOST"
          fi
          ACCOUNT_ID="${ACCOUNT_ID:-${CLOUD_ACCOUNT_ID:-}}"
          REGION_NAME="${REGION_NAME:-${CLOUD_REGION:-generic}}"
          RESOURCE_GROUP="${RESOURCE_GROUP:-generic-linux-hosts}"
          SSH_USER="${TF_SSH_USER:-${SSH_USER:-ubuntu}}"
          VICTIM_STATE="${VICTIM_STATE:-recorded}"
          ATTACKER_STATE="${ATTACKER_STATE:-recorded}"
          write_state_json
        fi
        ;;
    esac
    ;;
  deallocate)
    case "$PROVIDER" in
      azure) azure_delegate --deallocate-vms ;;
      aws)
        read_aws_account
        if [[ "$DRY_RUN" -eq 1 ]]; then
          echo "dry-run: aws ec2 stop-instances for tag ${RANGE_TAG}"
        else
          ids="$(aws ec2 describe-instances --region "$REGION_NAME" \
            --filters "Name=tag:Project,Values=${RANGE_TAG}" "Name=instance-state-name,Values=running" \
            --query 'Reservations[].Instances[].InstanceId' --output text || true)"
          if [[ -n "$ids" && "$ids" != "None" ]]; then
            # shellcheck disable=SC2086
            aws ec2 stop-instances --region "$REGION_NAME" --instance-ids $ids >/dev/null
          fi
        fi
        ;;
      gcp)
        read_gcp_account
        zone="${CLOUD_ZONE:-${REGION_NAME}-a}"
        run_cmd gcloud compute instances stop tf-soc-victim-vm tf-attacker-redteam-vm --zone "$zone"
        ;;
      generic)
        echo "Generic hosts are not stopped automatically. Use --teardown to stop the ThreatFusion stack."
        ;;
    esac
    ;;
  pair-forwarder)
    if [[ "$PROVIDER" != "azure" ]]; then
      echo "Use --deploy-full-stack to install Suricata on ${PROVIDER}." >&2
      exit 2
    fi
    azure_delegate --pair-forwarder
    ;;
  setup-entra-app)
    if [[ "$PROVIDER" != "azure" ]]; then
      echo "Entra app registration is an Azure action." >&2
      exit 2
    fi
    azure_delegate --setup-entra-app
    ;;
esac
