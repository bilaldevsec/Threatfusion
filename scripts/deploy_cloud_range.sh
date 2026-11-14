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
STATE_DIR="/tmp/threatfusion-range-demo"
CLOUD_STATE="${STATE_DIR}/cloud_state.json"
AZURE_STATE="${STATE_DIR}/azure_portal_state.json"
RANGE_TAG="threatfusion-range"
VICTIM_PRIVATE="172.29.0.20"
ATTACKER_PRIVATE="172.29.0.10"
VPC_CIDR="172.29.0.0/16"
SUBNET_CIDR="172.29.0.0/24"
AUTO_SHUTDOWN_UTC="2100"
COST_GUARDRAIL="Auto-shutdown at 21:00 UTC. Teardown removes the recorded stack so ongoing cost is 0.00."

PROVIDER=""
ACTION=""
DRY_RUN=0
STUDENT=0
VICTIM_HOST="${TF_VICTIM_PUBLIC_IP:-}"
ATTACKER_HOST="${TF_ATTACKER_PUBLIC_IP:-}"

usage() {
  cat <<'EOF'
Usage: scripts/deploy_cloud_range.sh [--dry-run] [--provider azure|aws|gcp|generic] [--victim-host IP] [--attacker-host IP] (--provision-range|--deploy-full-stack|--teardown|--status|--deallocate|--help)

  --provider         azure, aws, gcp, or generic. When omitted, the first
                     logged-in CLI wins: az account show, aws sts
                     get-caller-identity, gcloud config get-value project.
                     Host flags or TF_VICTIM_PUBLIC_IP and
                     TF_ATTACKER_PUBLIC_IP select generic.
  --provision-range  Create the 2-VM range in the signed-in account, or record
                     a generic Ubuntu/Linux pair. Opens SSH port 22 from
                     CLOUD_ADMIN_SSH_CIDR or AZURE_ADMIN_SSH_CIDR only.
  --deploy-full-stack
                     Copy the repo to the victim and start Console, ML engine,
                     Suricata, and n8n with Docker Compose over SSH.
  --teardown         Destroy the recorded resource group, stack, or instances.
  --status           Refresh cloud_state.json from the active CLI session.
  --deallocate       Stop recorded instances without deleting the network.
  --dry-run          Print the plan. Do not call cloud APIs or write state.
  --victim-host      Public address of a generic victim.
  --attacker-host    Public address of a generic attacker.

Environment: CLOUD_PROVIDER, CLOUD_ACCOUNT_ID, CLOUD_REGION,
TF_VICTIM_PUBLIC_IP, TF_ATTACKER_PUBLIC_IP, CLOUD_ADMIN_SSH_CIDR.
Account identifiers are read from the CLI session, not from the repository.
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
  local cidr="${CLOUD_ADMIN_SSH_CIDR:-${AZURE_ADMIN_SSH_CIDR:-}}"
  if [[ -z "$cidr" && "$DRY_RUN" -eq 1 ]]; then
    printf '%s\n' "operator-prefix-required"
    return 0
  fi
  if [[ -z "$cidr" ]]; then
    echo "Set CLOUD_ADMIN_SSH_CIDR or AZURE_ADMIN_SSH_CIDR. 0.0.0.0/0 is refused." >&2
    exit 1
  fi
  if [[ "$cidr" == "0.0.0.0/0" || "$cidr" == "*" ]]; then
    echo "The admin SSH prefix must not be open to the internet." >&2
    exit 1
  fi
  printf '%s\n' "$cidr"
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
    printf '%s\n' "$CLOUD_PROVIDER"
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
  if [[ -n "$VICTIM_HOST" && -n "$ATTACKER_HOST" ]]; then
    printf '%s\n' "generic"
    return 0
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
  eval "$(CLOUD_STATE="$CLOUD_STATE" python3 - <<'PY'
import json, os, shlex
from pathlib import Path
path = Path(os.environ["CLOUD_STATE"])
try:
    state = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    state = {}
if not isinstance(state, dict):
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

azure_delegate() {
  local flag="$1"
  shift || true
  local -a extra=()
  if [[ "$DRY_RUN" -eq 1 ]]; then
    extra+=(--dry-run)
  fi
  if [[ "$STUDENT" -eq 1 ]]; then
    extra+=(--student-free-tier)
  fi
  TF_AZURE_RANGE_IMPL=1 bash "$ROOT/scripts/deploy_azure_cyber_range.sh" "${extra[@]}" "$flag"
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
import json, sys
account = json.load(sys.stdin)
print("ACCOUNT_ID=" + json.dumps(account.get("id") or ""))
print("SUBSCRIPTION_ID=" + json.dumps(account.get("id") or ""))
print("TENANT_ID=" + json.dumps(account.get("tenantId") or ""))
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
    --protocol tcp --port 8766 --cidr "$cidr" >/dev/null 2>&1 || true
  ami="$(aws ssm get-parameter --region "$REGION_NAME" \
    --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
    --query Parameter.Value --output text)"
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
      --instance-type "${CLOUD_INSTANCE_TYPE:-t3.micro}" --key-name "$key_name" \
      --subnet-id "$subnet" --private-ip-address "$private_ip" \
      --security-group-ids "$sg" --user-data "file://${user_data}" \
      --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${name}},{Key=Project,Value=${RANGE_TAG}}]" \
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
  if ! gcloud compute firewall-rules describe threatfusion-range-ssh >/dev/null 2>&1; then
    gcloud compute firewall-rules create threatfusion-range-ssh \
      --network "$RANGE_TAG" --allow tcp:22,tcp:8766 \
      --source-ranges "$cidr" --target-tags "$RANGE_TAG"
  fi
  local startup
  startup="$(mktemp)"
  shutdown_user_data > "$startup"
  launch_gcp() {
    local name="$1" private_ip="$2"
    if gcloud compute instances describe "$name" --zone "$zone" >/dev/null 2>&1; then
      return 0
    fi
    gcloud compute instances create "$name" \
      --zone "$zone" --machine-type "${CLOUD_INSTANCE_TYPE:-e2-micro}" \
      --image-family ubuntu-2404-lts --image-project ubuntu-os-cloud \
      --subnet tf-range-subnet --private-network-ip "$private_ip" \
      --tags "$RANGE_TAG" --metadata-from-file startup-script="$startup"
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

require_stack_env() {
  local missing=() key
  for key in THREATFUSION_MISP_API_KEY THREATFUSION_SOAR_HMAC_SECRET THREATFUSION_THEHIVE_SECRET THREATFUSION_THEHIVE_API_KEY THREATFUSION_N8N_USER THREATFUSION_N8N_PASSWORD; do
    if [[ -z "${!key:-}" ]]; then
      missing+=("$key")
    fi
  done
  if ((${#missing[@]})) && [[ "$DRY_RUN" -eq 0 ]]; then
    echo "Missing stack environment: ${missing[*]}" >&2
    exit 1
  fi
}

deploy_full_stack() {
  local target env_file
  target="$(victim_ssh_target)"
  require_stack_env
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: rsync ${ROOT} to ${target}:/opt/threatfusion"
    echo "dry-run: docker compose soc stack, n8n, suricata, and the console on ${target}"
    return 0
  fi
  env_file="$(mktemp)"
  chmod 600 "$env_file"
  umask 077
  cat > "$env_file" <<EOF
THREATFUSION_MISP_API_KEY=${THREATFUSION_MISP_API_KEY:-}
THREATFUSION_SOAR_HMAC_SECRET=${THREATFUSION_SOAR_HMAC_SECRET:-}
THREATFUSION_THEHIVE_SECRET=${THREATFUSION_THEHIVE_SECRET:-}
THREATFUSION_THEHIVE_API_KEY=${THREATFUSION_THEHIVE_API_KEY:-}
THREATFUSION_N8N_USER=${THREATFUSION_N8N_USER:-}
THREATFUSION_N8N_PASSWORD=${THREATFUSION_N8N_PASSWORD:-}
EOF
  ssh -o StrictHostKeyChecking=no -o BatchMode=yes "$target" "sudo mkdir -p /opt/threatfusion && sudo chown \$(id -u):\$(id -g) /opt/threatfusion"
  tar -C "$ROOT" \
    --exclude threatfusion-venv \
    --exclude .git \
    --exclude .cursor \
    --exclude __pycache__ \
    -czf - . | ssh -o StrictHostKeyChecking=no -o BatchMode=yes "$target" "tar -C /opt/threatfusion -xzf -"
  scp -o StrictHostKeyChecking=no -o BatchMode=yes "$env_file" "${target}:/opt/threatfusion/.env"
  rm -f "$env_file"
  ssh -o StrictHostKeyChecking=no -o BatchMode=yes "$target" "bash -s" <<'REMOTE'
set -euo pipefail
cd /opt/threatfusion
chmod 600 .env
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y docker.io docker-compose-v2 suricata python3 python3-venv python3-pip
  sudo systemctl enable --now docker
  sudo systemctl enable --now suricata || true
fi
sudo docker compose --env-file .env -f docker/docker-compose.soc-stack.yml up -d
if [[ -f docker/docker-compose.n8n.yml ]]; then
  sudo docker compose --env-file .env -f docker/docker-compose.n8n.yml up -d
fi
if [[ ! -x /opt/threatfusion-venv/bin/python ]]; then
  python3 -m venv /opt/threatfusion-venv
  /opt/threatfusion-venv/bin/pip install --upgrade pip
  /opt/threatfusion-venv/bin/pip install --index-url https://download.pytorch.org/whl/cpu 'torch==2.10.0+cpu'
  /opt/threatfusion-venv/bin/pip install 'pandas>=2,<3' 'pydantic>=2,<3' 'pydantic-settings>=2,<3' 'PyYAML>=6,<7' 'scikit-learn>=1.5'
fi
set -a
# shellcheck disable=SC1091
. /opt/threatfusion/.env
set +a
export PYTHONPATH=/opt/threatfusion/backend/src
nohup /opt/threatfusion-venv/bin/python /opt/threatfusion/scripts/run_misp_and_callback_contract_server.py \
  --bind 0.0.0.0 --port 8766 >/var/log/threatfusion-console.log 2>&1 &
REMOTE
  echo "Full stack started on ${target} port 8766. Restrict that port to the admin prefix."
}

teardown_aws() {
  read_aws_account
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
  sg="$(aws ec2 describe-security-groups --region "$REGION_NAME" \
    --filters "Name=group-name,Values=${RANGE_TAG}" --query 'SecurityGroups[0].GroupId' --output text || true)"
  vpc="$(aws ec2 describe-vpcs --region "$REGION_NAME" \
    --filters "Name=tag:Name,Values=${RANGE_TAG}" --query 'Vpcs[0].VpcId' --output text || true)"
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
    if [[ -n "$igw" && "$igw" != "None" ]]; then
      aws ec2 detach-internet-gateway --region "$REGION_NAME" --internet-gateway-id "$igw" --vpc-id "$vpc" || true
      aws ec2 delete-internet-gateway --region "$REGION_NAME" --internet-gateway-id "$igw" || true
    fi
    aws ec2 delete-vpc --region "$REGION_NAME" --vpc-id "$vpc" || true
  fi
}

teardown_gcp() {
  read_gcp_account
  local zone="${CLOUD_ZONE:-${REGION_NAME}-a}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: gcloud compute instances delete tf-soc-victim-vm tf-attacker-redteam-vm --zone ${zone}"
    return 0
  fi
  gcloud compute instances delete tf-soc-victim-vm tf-attacker-redteam-vm --zone "$zone" --quiet || true
  gcloud compute firewall-rules delete threatfusion-range-ssh --quiet || true
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
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=8 \
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
    --student-free-tier)
      STUDENT=1
      shift
      ;;
    --help|-h)
      ACTION="help"
      shift
      ;;
    --provision-range|--deploy-full-stack|--teardown|--status|--deallocate|--pair-forwarder|--setup-entra-app)
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
case "$PROVIDER" in
  azure|aws|gcp|generic) ;;
  *)
    echo "No cloud CLI session is logged in. Run 'az login' / 'aws configure' / 'gcloud auth login' + ./scripts/deploy_cloud_range.sh --provision-range" >&2
    exit 1
    ;;
esac

case "$ACTION" in
  provision-range)
    case "$PROVIDER" in
      azure) azure_delegate --provision-live-azure ;;
      aws) provision_aws ;;
      gcp) provision_gcp ;;
      generic) provision_generic ;;
    esac
    ;;
  deploy-full-stack)
    deploy_full_stack
    ;;
  teardown)
    case "$PROVIDER" in
      azure) azure_delegate --teardown-rg ;;
      aws) teardown_aws ;;
      gcp) teardown_gcp ;;
      generic) teardown_generic ;;
    esac
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
