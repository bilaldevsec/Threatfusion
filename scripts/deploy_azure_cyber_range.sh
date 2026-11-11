#!/usr/bin/env bash
# ThreatFusion Azure 2-VM cyber range.
#
# Builds ThreatFusion-RG, VNet tf-cyber-range-vnet (172.29.0.0/16),
# victim VM tf-soc-victim-vm at 172.29.0.20, and attacker VM
# tf-attacker-redteam-vm at 172.29.0.10. The victim installs Suricata and
# the repository forwarder as /opt/threatfusion/suricata_eve_follower.py,
# then pairs that forwarder with the ThreatFusion console.
#
# Required for a live provision (not for --dry-run or --help):
#   az CLI logged in
#   AZURE_ADMIN_SSH_CIDR   source prefix allowed to SSH, never 0.0.0.0/0
#   THREATFUSION_CONSOLE_URL
#   THREATFUSION_SENSOR_TOKEN
#   THREATFUSION_SOAR_HMAC_SECRET   at least 16 characters
# Optional mTLS material, copied only when both files exist:
#   THREATFUSION_CLIENT_CERT
#   THREATFUSION_CLIENT_KEY

set -euo pipefail

RG="ThreatFusion-RG"
VNET="tf-cyber-range-vnet"
VNET_PREFIX="172.29.0.0/16"
SUBNET="tf-range-subnet"
SUBNET_PREFIX="172.29.0.0/24"
NSG="tf-range-nsg"
LOCATION="${AZURE_LOCATION:-southeastasia}"
VICTIM_NAME="tf-soc-victim-vm"
VICTIM_IP="172.29.0.20"
ATTACKER_NAME="tf-attacker-redteam-vm"
ATTACKER_IP="172.29.0.10"
VM_SIZE="${AZURE_VM_SIZE:-Standard_B2s}"
VICTIM_SIZE="$VM_SIZE"
ATTACKER_SIZE="$VM_SIZE"
IMAGE="${AZURE_VM_IMAGE:-Ubuntu2404}"
OS_DISK_GB=""
STORAGE_SKU=""
STUDENT_FREE_TIER=0
ADMIN_USER="${AZURE_ADMIN_USER:-threatfusion}"
FORWARDER_SRC="scripts/follow_suricata_eve.py"
FORWARDER_DST="/opt/threatfusion/suricata_eve_follower.py"
EVE_LOG="/var/log/suricata/eve.json"

DRY_RUN=0
ACTION=""

usage() {
  cat <<'EOF'
Usage: scripts/deploy_azure_cyber_range.sh [--dry-run] [--student-free-tier] (--help|--provision|--provision-live-azure|--pair-forwarder|--status|--deallocate|--deallocate-vms|--setup-entra-app)

  --help             Show this text and exit 0.
  --dry-run          Print the az and remote steps without calling them.
  --student-free-tier
                     Azure for Students budget mode. Uses free-tier eligible
                     Standard_B1s and Standard_B2pts_v2, Ubuntu 22.04, a 64 GB
                     Standard SSD, and an auto-shutdown at 23:59 Pakistan time
                     so the $60 credit is not left running overnight.
  --provision        Create the resource group, VNet, NSG, and both VMs.
  --provision-live-azure
                     Sign in with az when needed, register the ThreatFusion-SOC-Platform
                     Entra app roles, and create ThreatFusion-RG, ThreatFusion-VNet
                     172.29.0.0/16, subnet 172.29.0.0/24, ThreatFusion-NSG, and two
                     Ubuntu 22.04 Standard_B1s VMs. Auto-shutdown is 02:00 Pakistan
                     time (UTC+5). Writes /tmp/threatfusion-range-demo/azure_portal_state.json.
  --pair-forwarder   Install Suricata and suricata_eve_follower.py on the victim
                     and pair it with the ThreatFusion console over the sensor
                     route. HMAC and optional mTLS material stay in a root-only
                     env file on that VM.
  --status           Run: az vm list -g ThreatFusion-RG -d -o table
  --deallocate       Stop both VMs and release compute so billing stops after a demo.
  --deallocate-vms   Same as --deallocate.
  --setup-entra-app  Register the ThreatFusion Microsoft Entra ID app roles.

The address plan is fixed: tf-soc-victim-vm 172.29.0.20 and
tf-attacker-redteam-vm 172.29.0.10 inside tf-cyber-range-vnet 172.29.0.0/16.
EOF
}

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'dry-run:'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

require_az() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi
  if ! command -v az >/dev/null 2>&1; then
    echo "az CLI is not on PATH. Re-run with --dry-run to print the plan." >&2
    exit 1
  fi
}

require_ssh_cidr() {
  local cidr="${AZURE_ADMIN_SSH_CIDR:-}"
  if [[ -z "$cidr" && "$DRY_RUN" -eq 1 ]]; then
    AZURE_ADMIN_SSH_CIDR="operator-prefix-required"
    return 0
  fi
  if [[ -z "$cidr" ]]; then
    echo "Set AZURE_ADMIN_SSH_CIDR to the operator prefix. 0.0.0.0/0 is refused." >&2
    exit 1
  fi
  if [[ "$cidr" == "0.0.0.0/0" || "$cidr" == "*" ]]; then
    echo "AZURE_ADMIN_SSH_CIDR must not be open to the internet." >&2
    exit 1
  fi
}

provision_range() {
  require_az
  require_ssh_cidr
  run az group create --name "$RG" --location "$LOCATION"
  run az network nsg create --resource-group "$RG" --name "$NSG"
  run az network nsg rule create \
    --resource-group "$RG" \
    --nsg-name "$NSG" \
    --name allow-range-internal \
    --priority 100 \
    --access Allow \
    --direction Inbound \
    --protocol '*' \
    --source-address-prefixes "$SUBNET_PREFIX" \
    --destination-address-prefixes "$SUBNET_PREFIX" \
    --destination-port-ranges '*'
  run az network nsg rule create \
    --resource-group "$RG" \
    --nsg-name "$NSG" \
    --name allow-admin-ssh \
    --priority 110 \
    --access Allow \
    --direction Inbound \
    --protocol Tcp \
    --source-address-prefixes "$AZURE_ADMIN_SSH_CIDR" \
    --destination-port-ranges 22
  run az network vnet create \
    --resource-group "$RG" \
    --name "$VNET" \
    --address-prefix "$VNET_PREFIX" \
    --subnet-name "$SUBNET" \
    --subnet-prefix "$SUBNET_PREFIX"
  run az network vnet subnet update \
    --resource-group "$RG" \
    --vnet-name "$VNET" \
    --name "$SUBNET" \
    --network-security-group "$NSG"
  local -a disk_args=()
  if [[ -n "$OS_DISK_GB" ]]; then
    disk_args+=(--os-disk-size-gb "$OS_DISK_GB" --storage-sku "$STORAGE_SKU")
  fi
  run az vm create \
    --resource-group "$RG" \
    --name "$VICTIM_NAME" \
    --image "$IMAGE" \
    --size "$VICTIM_SIZE" \
    --admin-username "$ADMIN_USER" \
    --generate-ssh-keys \
    --vnet-name "$VNET" \
    --subnet "$SUBNET" \
    --nsg "$NSG" \
    --private-ip-address "$VICTIM_IP" \
    --public-ip-address "" \
    "${disk_args[@]}"
  run az vm create \
    --resource-group "$RG" \
    --name "$ATTACKER_NAME" \
    --image "$IMAGE" \
    --size "$ATTACKER_SIZE" \
    --admin-username "$ADMIN_USER" \
    --generate-ssh-keys \
    --vnet-name "$VNET" \
    --subnet "$SUBNET" \
    --nsg "$NSG" \
    --private-ip-address "$ATTACKER_IP" \
    --public-ip-address "" \
    "${disk_args[@]}"
  if [[ "$STUDENT_FREE_TIER" -eq 1 ]]; then
    schedule_student_shutdown "$VICTIM_NAME"
    schedule_student_shutdown "$ATTACKER_NAME"
  fi
}

schedule_student_shutdown() {
  local name="$1"
  run az vm auto-shutdown \
    --resource-group "$RG" \
    --name "$name" \
    --time 2359 \
    --timezone "Pakistan Standard Time"
}

deallocate_range() {
  require_az
  run az vm deallocate --resource-group "$RG" --name "$VICTIM_NAME"
  run az vm deallocate --resource-group "$RG" --name "$ATTACKER_NAME"
}

setup_entra_app() {
  require_az
  local roles
  roles='[{"allowedMemberTypes":["User"],"description":"Tier-3 SOC approver who may sign SOAR playbooks","displayName":"SOC Commander Approver","id":"c1a0b001-1111-4111-8111-000000000001","isEnabled":true,"value":"SOC.Commander.Approver"},{"allowedMemberTypes":["User"],"description":"Tier-1 analyst limited to triage","displayName":"SOC Analyst Tier 1","id":"c1a0b002-2222-4222-8222-000000000002","isEnabled":true,"value":"SOC.Analyst.Tier1"},{"allowedMemberTypes":["User"],"description":"Read-only compliance auditor","displayName":"SOC Compliance Auditor","id":"c1a0b003-3333-4333-8333-000000000003","isEnabled":true,"value":"SOC.Compliance.Auditor"}]'
  run az ad app create \
    --display-name "ThreatFusion SOC Console" \
    --sign-in-audience AzureADMyOrg \
    --app-roles "$roles"
}

pair_forwarder() {
  require_az
  local console_url="${THREATFUSION_CONSOLE_URL:-}"
  local sensor_token="${THREATFUSION_SENSOR_TOKEN:-}"
  local hmac_secret="${THREATFUSION_SOAR_HMAC_SECRET:-}"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    if [[ -z "$console_url" || -z "$sensor_token" || ${#hmac_secret} -lt 16 ]]; then
      echo "Set THREATFUSION_CONSOLE_URL, THREATFUSION_SENSOR_TOKEN, and a 16+ character THREATFUSION_SOAR_HMAC_SECRET." >&2
      exit 1
    fi
    if [[ ! -f "$FORWARDER_SRC" ]]; then
      echo "Missing forwarder source: $FORWARDER_SRC" >&2
      exit 1
    fi
  fi
  local remote
  remote=$(cat <<EOF
set -euo pipefail
sudo apt-get update
sudo apt-get install -y suricata python3
sudo install -d -m 0750 /opt/threatfusion /etc/threatfusion
sudo install -d -m 0755 /var/log/suricata
if [[ ! -f ${EVE_LOG} ]]; then
  sudo touch ${EVE_LOG}
fi
sudo tee /etc/threatfusion/range.env >/dev/null <<'ENV'
THREATFUSION_CONSOLE_URL=${console_url}
THREATFUSION_SENSOR_TOKEN=${sensor_token}
THREATFUSION_SOAR_HMAC_SECRET=${hmac_secret}
THREATFUSION_CLIENT_CERT=/etc/threatfusion/client.crt
THREATFUSION_CLIENT_KEY=/etc/threatfusion/client.key
ENV
sudo chmod 0600 /etc/threatfusion/range.env
sudo tee /etc/systemd/system/threatfusion-eve-follower.service >/dev/null <<'UNIT'
[Unit]
Description=ThreatFusion Suricata EVE follower
After=network-online.target suricata.service

[Service]
EnvironmentFile=/etc/threatfusion/range.env
ExecStart=/usr/bin/python3 /opt/threatfusion/suricata_eve_follower.py --eve ${EVE_LOG} --console-url ${console_url}
Restart=on-failure
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now suricata
sudo systemctl enable --now threatfusion-eve-follower.service
EOF
)
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'dry-run: copy %s to %s:%s\n' "$FORWARDER_SRC" "$VICTIM_NAME" "$FORWARDER_DST"
    printf 'dry-run: az vm run-command invoke --resource-group %s --name %s --command-id RunShellScript\n' "$RG" "$VICTIM_NAME"
    printf 'dry-run remote script follows\n%s\n' "$remote"
    if [[ -n "${THREATFUSION_CLIENT_CERT:-}" && -n "${THREATFUSION_CLIENT_KEY:-}" ]]; then
      echo "dry-run: copy optional mTLS client certificate and key to /etc/threatfusion/"
    fi
    return 0
  fi
  local encoded
  encoded="$(base64 -w 0 "$FORWARDER_SRC" 2>/dev/null || base64 "$FORWARDER_SRC" | tr -d '\n')"
  run az vm run-command invoke \
    --resource-group "$RG" \
    --name "$VICTIM_NAME" \
    --command-id RunShellScript \
    --scripts "echo ${encoded} | base64 -d | sudo tee ${FORWARDER_DST} >/dev/null && sudo chmod 0755 ${FORWARDER_DST}"
  if [[ -n "${THREATFUSION_CLIENT_CERT:-}" && -n "${THREATFUSION_CLIENT_KEY:-}" && -f "$THREATFUSION_CLIENT_CERT" && -f "$THREATFUSION_CLIENT_KEY" ]]; then
    local cert_b64 key_b64
    cert_b64="$(base64 -w 0 "$THREATFUSION_CLIENT_CERT" 2>/dev/null || base64 "$THREATFUSION_CLIENT_CERT" | tr -d '\n')"
    key_b64="$(base64 -w 0 "$THREATFUSION_CLIENT_KEY" 2>/dev/null || base64 "$THREATFUSION_CLIENT_KEY" | tr -d '\n')"
    run az vm run-command invoke \
      --resource-group "$RG" \
      --name "$VICTIM_NAME" \
      --command-id RunShellScript \
      --scripts "echo ${cert_b64} | base64 -d | sudo tee /etc/threatfusion/client.crt >/dev/null; echo ${key_b64} | base64 -d | sudo tee /etc/threatfusion/client.key >/dev/null; sudo chmod 0600 /etc/threatfusion/client.key"
  fi
  run az vm run-command invoke \
    --resource-group "$RG" \
    --name "$VICTIM_NAME" \
    --command-id RunShellScript \
    --scripts "$remote"
}

show_status() {
  require_az
  run az vm list -g "$RG" -d -o table
}

pick_southeastasia_vm_size() {
  local preferred size available
  preferred=(
    Standard_D2s_v3
    Standard_D2as_v5
    Standard_D2s_v5
    Standard_D2s_v4
    Standard_D2as_v4
    Standard_D2_v2
    Standard_DS1_v2
    Standard_B2s
    Standard_B2ats_v2
  )
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%s\n' "Standard_D2s_v3"
    return 0
  fi
  available="$(az vm list-skus --location southeastasia --resource-type virtualMachines --query "[?restrictions==\`[]\`].name" -o tsv)"
  for size in "${preferred[@]}"; do
    if printf '%s\n' "$available" | grep -qx "$size"; then
      printf '%s\n' "$size"
      return 0
    fi
  done
  size="$(printf '%s\n' "$available" | grep -E '^Standard_D[^[:space:]]*s' | head -n 1 || true)"
  if [[ -z "$size" ]]; then
    size="$(printf '%s\n' "$available" | grep -E '^Standard_B' | head -n 1 || true)"
  fi
  if [[ -z "$size" ]]; then
    echo "No unrestricted D-series or B-series VM SKU is available in southeastasia." >&2
    return 1
  fi
  printf '%s\n' "$size"
}

create_vm_with_zone_retry() {
  if run az vm create "$@"; then
    return 0
  fi
  local zone
  for zone in 1 2 3; do
    if run az vm create "$@" --zone "$zone"; then
      return 0
    fi
  done
  return 1
}

ensure_southeastasia_group() {
  local existing vm_count
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: az group show --name $RG"
    run az group create --name "$RG" --location southeastasia
    return 0
  fi
  existing="$(az group show --name "$RG" --query location -o tsv 2>/dev/null || true)"
  if [[ -n "$existing" && "$existing" != "southeastasia" ]]; then
    vm_count="$(az vm list --resource-group "$RG" --query "length(@)" -o tsv 2>/dev/null || echo 0)"
    if [[ "$vm_count" != "0" ]]; then
      echo "ThreatFusion-RG exists in ${existing} and still has VMs. Refusing to recreate it." >&2
      return 1
    fi
    az group delete --name "$RG" --yes --no-wait
    az group wait --name "$RG" --deleted || true
  fi
  run az group create --name "$RG" --location southeastasia
}

provision_live_azure() {
  require_az
  local live_location="southeastasia"
  local vm_size
  vm_size="$(pick_southeastasia_vm_size)"
  local roles
  roles='[{"allowedMemberTypes":["User"],"description":"Tier-3 SOC approver who may sign SOAR playbooks","displayName":"SOC Approver","id":"c1a0b011-1111-4111-8111-000000000011","isEnabled":true,"value":"soc_approver"},{"allowedMemberTypes":["User"],"description":"Tier-1 analyst limited to triage","displayName":"Tier-1 Triage","id":"c1a0b012-2222-4222-8222-000000000012","isEnabled":true,"value":"tier1_triage"},{"allowedMemberTypes":["User"],"description":"Read-only compliance auditor","displayName":"Compliance Auditor","id":"c1a0b013-3333-4333-8333-000000000013","isEnabled":true,"value":"compliance_auditor"}]'
  local live_vnet="ThreatFusion-VNet"
  local live_subnet="ThreatFusion-Subnet"
  local live_nsg="ThreatFusion-NSG"
  local app_id="dry-run-app-id"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: az account show"
    echo "dry-run: az login   # only when az account show fails"
    echo "dry-run: az ad app list --display-name ThreatFusion-SOC-Platform"
    run az ad app create \
      --display-name "ThreatFusion-SOC-Platform" \
      --sign-in-audience AzureADMyOrg \
      --app-roles "$roles"
  else
    if ! az account show >/dev/null 2>&1; then
      az login
    fi
    app_id="$(az ad app list --display-name ThreatFusion-SOC-Platform --query '[0].appId' -o tsv || true)"
    if [[ -z "$app_id" ]]; then
      app_id="$(az ad app create \
        --display-name "ThreatFusion-SOC-Platform" \
        --sign-in-audience AzureADMyOrg \
        --app-roles "$roles" \
        --query appId \
        -o tsv)"
    fi
  fi
  ensure_southeastasia_group
  run az network nsg create --resource-group "$RG" --name "$live_nsg"
  run az network nsg rule create \
    --resource-group "$RG" \
    --nsg-name "$live_nsg" \
    --name allow-range-internal \
    --priority 100 \
    --access Allow \
    --direction Inbound \
    --protocol '*' \
    --source-address-prefixes "$SUBNET_PREFIX" \
    --destination-address-prefixes "$SUBNET_PREFIX" \
    --destination-port-ranges '*'
  if [[ -n "${AZURE_ADMIN_SSH_CIDR:-}" && "${AZURE_ADMIN_SSH_CIDR}" != "0.0.0.0/0" && "${AZURE_ADMIN_SSH_CIDR}" != "*" ]]; then
    run az network nsg rule create \
      --resource-group "$RG" \
      --nsg-name "$live_nsg" \
      --name allow-admin-ssh \
      --priority 110 \
      --access Allow \
      --direction Inbound \
      --protocol Tcp \
      --source-address-prefixes "$AZURE_ADMIN_SSH_CIDR" \
      --destination-port-ranges 22
  fi
  run az network vnet create \
    --resource-group "$RG" \
    --name "$live_vnet" \
    --address-prefix "$VNET_PREFIX" \
    --subnet-name "$live_subnet" \
    --subnet-prefix "$SUBNET_PREFIX"
  run az network vnet subnet update \
    --resource-group "$RG" \
    --vnet-name "$live_vnet" \
    --name "$live_subnet" \
    --network-security-group "$live_nsg"
  create_vm_with_zone_retry \
    --resource-group "$RG" \
    --name "$VICTIM_NAME" \
    --image Ubuntu2204 \
    --size "$vm_size" \
    --admin-username "$ADMIN_USER" \
    --generate-ssh-keys \
    --vnet-name "$live_vnet" \
    --subnet "$live_subnet" \
    --nsg "$live_nsg" \
    --private-ip-address "$VICTIM_IP" \
    --public-ip-address ""
  create_vm_with_zone_retry \
    --resource-group "$RG" \
    --name "$ATTACKER_NAME" \
    --image Ubuntu2204 \
    --size "$vm_size" \
    --admin-username "$ADMIN_USER" \
    --generate-ssh-keys \
    --vnet-name "$live_vnet" \
    --subnet "$live_subnet" \
    --nsg "$live_nsg" \
    --private-ip-address "$ATTACKER_IP" \
    --public-ip-address ""
  # 02:00 PKT is 21:00 UTC.
  run az vm auto-shutdown \
    --resource-group "$RG" \
    --name "$VICTIM_NAME" \
    --time 0200 \
    --timezone "Pakistan Standard Time"
  run az vm auto-shutdown \
    --resource-group "$RG" \
    --name "$ATTACKER_NAME" \
    --time 0200 \
    --timezone "Pakistan Standard Time"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would write /tmp/threatfusion-range-demo/azure_portal_state.json"
    return 0
  fi
  mkdir -p /tmp/threatfusion-range-demo
  AZURE_APP_ID="$app_id" az account show -o json | python3 -c '
import json, os, sys
account = json.load(sys.stdin)
state = {
    "tenant_id": account.get("tenantId") or "",
    "subscription_id": account.get("id") or "",
    "app_id": os.environ.get("AZURE_APP_ID", ""),
    "resource_group": "ThreatFusion-RG",
    "victim_vm_ip": "172.29.0.20",
    "attacker_vm_ip": "172.29.0.10",
}
path = "/tmp/threatfusion-range-demo/azure_portal_state.json"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(state, handle, indent=2)
    handle.write("\n")
print(path)
'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --provision)
      ACTION="provision"
      shift
      ;;
    --provision-live-azure)
      ACTION="provision-live"
      shift
      ;;
    --student-free-tier)
      STUDENT_FREE_TIER=1
      VICTIM_SIZE="Standard_B1s"
      ATTACKER_SIZE="Standard_B2pts_v2"
      IMAGE="Ubuntu2204"
      OS_DISK_GB="64"
      STORAGE_SKU="StandardSSD_LRS"
      shift
      ;;
    --deallocate|--deallocate-vms)
      ACTION="deallocate"
      shift
      ;;
    --setup-entra-app)
      ACTION="entra"
      shift
      ;;
    --pair-forwarder)
      ACTION="pair"
      shift
      ;;
    --status)
      ACTION="status"
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$ACTION" ]]; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    ACTION="provision"
  else
    usage >&2
    exit 2
  fi
fi

case "$ACTION" in
  provision) provision_range ;;
  provision-live) provision_live_azure ;;
  pair) pair_forwarder ;;
  status) show_status ;;
  deallocate) deallocate_range ;;
  entra) setup_entra_app ;;
  *)
    usage >&2
    exit 2
    ;;
esac
