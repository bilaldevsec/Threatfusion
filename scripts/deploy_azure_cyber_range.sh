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
LOCATION="${AZURE_LOCATION:-eastus}"
VICTIM_NAME="tf-soc-victim-vm"
VICTIM_IP="172.29.0.20"
ATTACKER_NAME="tf-attacker-redteam-vm"
ATTACKER_IP="172.29.0.10"
VM_SIZE="${AZURE_VM_SIZE:-Standard_B2s}"
IMAGE="${AZURE_VM_IMAGE:-Ubuntu2404}"
ADMIN_USER="${AZURE_ADMIN_USER:-threatfusion}"
FORWARDER_SRC="scripts/follow_suricata_eve.py"
FORWARDER_DST="/opt/threatfusion/suricata_eve_follower.py"
EVE_LOG="/var/log/suricata/eve.json"

DRY_RUN=0
ACTION=""

usage() {
  cat <<'EOF'
Usage: scripts/deploy_azure_cyber_range.sh [--dry-run] (--help|--provision|--pair-forwarder|--status)

  --help             Show this text and exit 0.
  --dry-run          Print the az and remote steps without calling them.
  --provision        Create the resource group, VNet, NSG, and both VMs.
  --pair-forwarder   Install Suricata and suricata_eve_follower.py on the victim
                     and pair it with the ThreatFusion console over the sensor
                     route. HMAC and optional mTLS material stay in a root-only
                     env file on that VM.
  --status           Show the two VM power states and private addresses.

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
  run az vm create \
    --resource-group "$RG" \
    --name "$VICTIM_NAME" \
    --image "$IMAGE" \
    --size "$VM_SIZE" \
    --admin-username "$ADMIN_USER" \
    --generate-ssh-keys \
    --vnet-name "$VNET" \
    --subnet "$SUBNET" \
    --nsg "$NSG" \
    --private-ip-address "$VICTIM_IP" \
    --public-ip-address ""
  run az vm create \
    --resource-group "$RG" \
    --name "$ATTACKER_NAME" \
    --image "$IMAGE" \
    --size "$VM_SIZE" \
    --admin-username "$ADMIN_USER" \
    --generate-ssh-keys \
    --vnet-name "$VNET" \
    --subnet "$SUBNET" \
    --nsg "$NSG" \
    --private-ip-address "$ATTACKER_IP" \
    --public-ip-address ""
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
  run az vm list \
    --resource-group "$RG" \
    --show-details \
    --query "[].{name:name, power:powerState, privateIp:privateIps}" \
    --output table
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
  pair) pair_forwarder ;;
  status) show_status ;;
  *)
    usage >&2
    exit 2
    ;;
esac
