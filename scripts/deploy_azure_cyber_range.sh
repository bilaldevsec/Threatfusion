#!/usr/bin/env bash
# ThreatFusion Azure 2-VM cyber range.
#
# Builds or reuses ThreatFusion-RG, ThreatFusion-VNet (172.29.0.0/16),
# ThreatFusion-Subnet (172.29.0.0/24), victim VM tf-soc-victim-vm at
# 172.29.0.20, and attacker VM tf-attacker-redteam-vm at 172.29.0.10.
# Live provision pins verified 2-vCPU SKUs that fit the Azure for Students
# 6 Regional Core cap in southeastasia. The victim installs Suricata and
# the repository forwarder as /opt/threatfusion/suricata_eve_follower.py.
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
                     Entra app roles, reuse ThreatFusion-RG / ThreatFusion-VNet /
                     ThreatFusion-Subnet / ThreatFusion-NSG in southeastasia, and create
                     two Ubuntu 22.04 VMs on verified 2-vCPU SKUs (6-core student quota).
                     Victim 172.29.0.20, attacker 172.29.0.10, admin azureuser.
                     Auto-shutdown is 21:00 UTC (02:00 PKT). Writes
                     /tmp/threatfusion-range-demo/azure_portal_state.json from az vm list.
  --pair-forwarder   Install Suricata and suricata_eve_follower.py on the victim
                     and pair it with the ThreatFusion console over the sensor
                     route. HMAC and optional mTLS material stay in a root-only
                     env file on that VM.
  --status           Show live VMs, public/private IPs, and auto-shutdown policy.
  --deallocate       Stop both VMs and release compute so billing stops after a demo.
  --deallocate-vms   Same as --deallocate.
  --setup-entra-app  Register the ThreatFusion Microsoft Entra ID app roles.

The address plan is fixed: tf-soc-victim-vm 172.29.0.20 and
tf-attacker-redteam-vm 172.29.0.10 inside ThreatFusion-VNet 172.29.0.0/16.
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

# Verified unrestricted 2-vCPU SKUs in southeastasia for the Azure for Students
# 6 Regional Core quota. Never fall back to unrestricted larger D-series sizes.
STUDENT_QUOTA_SKUS=(
  "Standard_D2as_v7"
  "Standard_D2ads_v7"
  "Standard_D2als_v7"
  "Standard_D2alds_v7"
  "Standard_D2pds_v5"
  "Standard_B2pts_v2"
  "Standard_B2ps_v2"
  "Standard_B2pls_v2"
)

X86_UBUNTU_IMAGE="Canonical:0001-com-ubuntu-server-jammy:22_04-lts:latest"
ARM_UBUNTU_IMAGE="Canonical:0001-com-ubuntu-server-jammy:22_04-lts-arm64:latest"
STATE_PATH="/tmp/threatfusion-range-demo/azure_portal_state.json"
LIVE_VNET="ThreatFusion-VNet"
LIVE_SUBNET="ThreatFusion-Subnet"
LIVE_NSG="ThreatFusion-NSG"
LIVE_ADMIN_USER="azureuser"
AUTO_SHUTDOWN_UTC="2100"

is_arm_sku() {
  case "$1" in
    Standard_B2pts_v2|Standard_B2ps_v2|Standard_B2pls_v2|Standard_D2pds_v5)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

ubuntu_image_for_sku() {
  if is_arm_sku "$1"; then
    printf '%s\n' "$ARM_UBUNTU_IMAGE"
  else
    printf '%s\n' "$X86_UBUNTU_IMAGE"
  fi
}

show_status() {
  require_az
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: az vm list -g $RG -d -o table"
    echo "dry-run: would print public/private IPs and auto-shutdown policy"
    return 0
  fi
  echo "=== ThreatFusion Azure range VMs ($RG / $LOCATION) ==="
  az vm list -g "$RG" -d -o table
  echo
  echo "=== Address plan ==="
  printf '%-28s %-16s %-16s\n' "VM" "Private IP" "Public IP"
  local name private public
  for name in "$VICTIM_NAME" "$ATTACKER_NAME"; do
    private="$(az vm list-ip-addresses -g "$RG" -n "$name" --query "[0].virtualMachine.network.privateIpAddresses[0]" -o tsv 2>/dev/null || true)"
    public="$(az vm list-ip-addresses -g "$RG" -n "$name" --query "[0].virtualMachine.network.publicIpAddresses[0].ipAddress" -o tsv 2>/dev/null || true)"
    printf '%-28s %-16s %-16s\n' "$name" "${private:-n/a}" "${public:-n/a}"
  done
  echo
  echo "=== Auto-shutdown (21:00 UTC / 02:00 PKT) ==="
  for name in "$VICTIM_NAME" "$ATTACKER_NAME"; do
    local sched_name="shutdown-computevm-${name}"
    local sched enabled time_val tz
    sched="$(az resource show -g "$RG" -n "$sched_name" --resource-type Microsoft.DevTestLab/schedules -o json 2>/dev/null || true)"
    if [[ -z "$sched" || "$sched" == "null" ]]; then
      printf '%s: not configured\n' "$name"
      continue
    fi
    enabled="$(printf '%s' "$sched" | python3 -c 'import json,sys; d=json.load(sys.stdin); p=d.get("properties") or d; print(p.get("status") or d.get("status") or "")' 2>/dev/null || true)"
    time_val="$(printf '%s' "$sched" | python3 -c 'import json,sys; d=json.load(sys.stdin); p=d.get("properties") or d; print((p.get("dailyRecurrence") or {}).get("time") or "")' 2>/dev/null || true)"
    tz="$(printf '%s' "$sched" | python3 -c 'import json,sys; d=json.load(sys.stdin); p=d.get("properties") or d; print(p.get("timeZoneId") or p.get("timeZone") or "UTC")' 2>/dev/null || true)"
    printf '%s: status=%s time=%s tz=%s\n' "$name" "${enabled:-unknown}" "${time_val:-unknown}" "${tz:-UTC}"
  done
  if [[ -f "$STATE_PATH" ]]; then
    echo
    echo "=== Portal state file ==="
    echo "$STATE_PATH"
  fi
}

sku_family_tokens() {
  # Map a verified 2-vCPU SKU onto az vm list-usage family name fragments.
  case "$1" in
    Standard_D2as_v7) printf '%s\n' "dasv7" ;;
    Standard_D2ads_v7) printf '%s\n' "dadsv7" ;;
    Standard_D2als_v7) printf '%s\n' "dalsv7" ;;
    Standard_D2alds_v7) printf '%s\n' "daldsv7" ;;
    Standard_D2pds_v5) printf '%s\n' "dpdsv5" ;;
    Standard_B2pts_v2) printf '%s\n' "bptsv2" "bpsv2" ;;
    Standard_B2ps_v2) printf '%s\n' "bpsv2" ;;
    Standard_B2pls_v2) printf '%s\n' "bplsv2" "pbs" ;;
    *) return 1 ;;
  esac
}

family_quota_remaining() {
  local size="$1"
  local usage_json="$2"
  local token limit current remaining
  while IFS= read -r token; do
    [[ -z "$token" ]] && continue
    limit="$(
      USAGE_JSON="$usage_json" TOKEN="$token" python3 - <<'PY'
import json, os
token = os.environ["TOKEN"].lower()
rows = json.loads(os.environ["USAGE_JSON"])
for row in rows:
    name = row.get("name") or {}
    label = str(name.get("localizedValue") or name.get("value") or "").lower()
    if "family" not in label:
        continue
    if token in label.replace(" ", "").replace("-", ""):
        print(int(row.get("limit") or 0))
        break
else:
    print(0)
PY
    )"
    current="$(
      USAGE_JSON="$usage_json" TOKEN="$token" python3 - <<'PY'
import json, os
token = os.environ["TOKEN"].lower()
rows = json.loads(os.environ["USAGE_JSON"])
for row in rows:
    name = row.get("name") or {}
    label = str(name.get("localizedValue") or name.get("value") or "").lower()
    if "family" not in label:
        continue
    if token in label.replace(" ", "").replace("-", ""):
        print(int(row.get("currentValue") or 0))
        break
else:
    print(0)
PY
    )"
    remaining=$((limit - current))
    if [[ "$remaining" -ge 2 ]]; then
      printf '%s\n' "$remaining"
      return 0
    fi
  done < <(sku_family_tokens "$size")
  printf '%s\n' "0"
  return 1
}

pick_southeastasia_vm_size() {
  local preferred size available forced usage_json regional_remaining family_remaining
  preferred=("${STUDENT_QUOTA_SKUS[@]}")
  forced="${AZURE_VM_SIZE:-}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    if [[ -n "$forced" ]]; then
      printf '%s\n' "$forced"
    else
      # Prefer the first x86 candidate in dry-run; live mode still filters by family quota.
      printf '%s\n' "${preferred[0]}"
    fi
    return 0
  fi
  available="$(az vm list-skus --location southeastasia --resource-type virtualMachines --query "[?restrictions==\`[]\`].name" -o tsv)"
  usage_json="$(az vm list-usage --location southeastasia -o json)"
  regional_remaining="$(
    USAGE_JSON="$usage_json" python3 - <<'PY'
import json, os
rows = json.loads(os.environ["USAGE_JSON"])
for row in rows:
    name = row.get("name") or {}
    label = str(name.get("localizedValue") or name.get("value") or "").lower()
    if label == "total regional vcpus":
        print(int(row.get("limit") or 0) - int(row.get("currentValue") or 0))
        break
else:
    print(0)
PY
  )"
  if [[ "$regional_remaining" -lt 4 ]]; then
    echo "southeastasia Total Regional vCPUs remaining=${regional_remaining}; need 4 for two 2-vCPU VMs." >&2
    return 1
  fi
  if [[ -n "$forced" ]]; then
    local allowed=0
    for size in "${preferred[@]}"; do
      if [[ "$forced" == "$size" ]]; then
        allowed=1
        break
      fi
    done
    if [[ "$allowed" -ne 1 ]]; then
      echo "AZURE_VM_SIZE=$forced is outside the verified 2-vCPU student quota SKU list." >&2
      return 1
    fi
    if ! printf '%s\n' "$available" | grep -qx "$forced"; then
      echo "AZURE_VM_SIZE=$forced is restricted or unavailable in southeastasia." >&2
      return 1
    fi
    family_remaining="$(family_quota_remaining "$forced" "$usage_json" || true)"
    if [[ "${family_remaining:-0}" -lt 2 ]]; then
      echo "AZURE_VM_SIZE=$forced family quota remaining=${family_remaining:-0}; need at least 2." >&2
      return 1
    fi
    printf '%s\n' "$forced"
    return 0
  fi
  for size in "${preferred[@]}"; do
    if ! printf '%s\n' "$available" | grep -qx "$size"; then
      continue
    fi
    family_remaining="$(family_quota_remaining "$size" "$usage_json" || true)"
    if [[ "${family_remaining:-0}" -lt 2 ]]; then
      echo "Skipping $size (family quota remaining=${family_remaining:-0})" >&2
      continue
    fi
    printf '%s\n' "$size"
    return 0
  done
  echo "None of the verified 2-vCPU student-quota SKUs have both unrestricted SKU availability and family quota in southeastasia." >&2
  echo "Tried: ${preferred[*]}" >&2
  return 1
}

create_vm_with_zone_retry() {
  local output status
  if [[ "$DRY_RUN" -eq 1 ]]; then
    run az vm create "$@"
    return 0
  fi
  set +e
  output="$(az vm create "$@" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output"
  if [[ "$status" -eq 0 ]]; then
    return 0
  fi
  if printf '%s' "$output" | grep -Eqi 'QuotaExceeded|exceeding approved .*Cores quota'; then
    echo "Quota exceeded for this SKU; not retrying availability zones." >&2
    return 2
  fi
  local zone
  for zone in 1 2 3; do
    set +e
    output="$(az vm create "$@" --zone "$zone" 2>&1)"
    status=$?
    set -e
    printf '%s\n' "$output"
    if [[ "$status" -eq 0 ]]; then
      return 0
    fi
    if printf '%s' "$output" | grep -Eqi 'QuotaExceeded|exceeding approved .*Cores quota'; then
      echo "Quota exceeded for this SKU in zone $zone; stopping zone retries." >&2
      return 2
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

ensure_live_nsg() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    run az network nsg create --resource-group "$RG" --name "$LIVE_NSG"
  elif ! az network nsg show --resource-group "$RG" --name "$LIVE_NSG" >/dev/null 2>&1; then
    run az network nsg create --resource-group "$RG" --name "$LIVE_NSG"
  fi
  if [[ "$DRY_RUN" -eq 1 ]] || ! az network nsg rule show --resource-group "$RG" --nsg-name "$LIVE_NSG" --name allow-range-internal >/dev/null 2>&1; then
    run az network nsg rule create \
      --resource-group "$RG" \
      --nsg-name "$LIVE_NSG" \
      --name allow-range-internal \
      --priority 100 \
      --access Allow \
      --direction Inbound \
      --protocol '*' \
      --source-address-prefixes "$SUBNET_PREFIX" \
      --destination-address-prefixes "$SUBNET_PREFIX" \
      --destination-port-ranges '*'
  fi
  if [[ -n "${AZURE_ADMIN_SSH_CIDR:-}" && "${AZURE_ADMIN_SSH_CIDR}" != "0.0.0.0/0" && "${AZURE_ADMIN_SSH_CIDR}" != "*" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]] || ! az network nsg rule show --resource-group "$RG" --nsg-name "$LIVE_NSG" --name allow-admin-ssh >/dev/null 2>&1; then
      run az network nsg rule create \
        --resource-group "$RG" \
        --nsg-name "$LIVE_NSG" \
        --name allow-admin-ssh \
        --priority 110 \
        --access Allow \
        --direction Inbound \
        --protocol Tcp \
        --source-address-prefixes "$AZURE_ADMIN_SSH_CIDR" \
        --destination-port-ranges 22
    fi
  fi
}

ensure_live_vnet() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: reuse or create $LIVE_VNET / $LIVE_SUBNET in $RG"
    run az network vnet create \
      --resource-group "$RG" \
      --name "$LIVE_VNET" \
      --address-prefix "$VNET_PREFIX" \
      --subnet-name "$LIVE_SUBNET" \
      --subnet-prefix "$SUBNET_PREFIX"
  elif ! az network vnet show --resource-group "$RG" --name "$LIVE_VNET" >/dev/null 2>&1; then
    run az network vnet create \
      --resource-group "$RG" \
      --name "$LIVE_VNET" \
      --address-prefix "$VNET_PREFIX" \
      --subnet-name "$LIVE_SUBNET" \
      --subnet-prefix "$SUBNET_PREFIX"
  elif ! az network vnet subnet show --resource-group "$RG" --vnet-name "$LIVE_VNET" --name "$LIVE_SUBNET" >/dev/null 2>&1; then
    run az network vnet subnet create \
      --resource-group "$RG" \
      --vnet-name "$LIVE_VNET" \
      --name "$LIVE_SUBNET" \
      --address-prefixes "$SUBNET_PREFIX"
  fi
  run az network vnet subnet update \
    --resource-group "$RG" \
    --vnet-name "$LIVE_VNET" \
    --name "$LIVE_SUBNET" \
    --network-security-group "$LIVE_NSG"
}

create_live_vm_if_missing() {
  local name="$1"
  local private_ip="$2"
  local vm_size="$3"
  local image="$4"
  local status
  if [[ "$DRY_RUN" -eq 0 ]] && az vm show --resource-group "$RG" --name "$name" >/dev/null 2>&1; then
    echo "VM $name already exists in $RG; leaving it in place."
    return 0
  fi
  set +e
  create_vm_with_zone_retry \
    --resource-group "$RG" \
    --name "$name" \
    --image "$image" \
    --size "$vm_size" \
    --admin-username "$LIVE_ADMIN_USER" \
    --generate-ssh-keys \
    --vnet-name "$LIVE_VNET" \
    --subnet "$LIVE_SUBNET" \
    --nsg "$LIVE_NSG" \
    --private-ip-address "$private_ip"
  status=$?
  set -e
  return "$status"
}

create_both_live_vms() {
  # Try verified SKUs from the quota-selected size onward. Prefer x86 when family
  # quota exists; fall through to ARM B2p* with the ARM64 Ubuntu image otherwise.
  local preferred size image status start="${1:-}" seen_start=0
  preferred=("${STUDENT_QUOTA_SKUS[@]}")
  if [[ -n "${AZURE_VM_SIZE:-}" ]]; then
    preferred=("${AZURE_VM_SIZE}")
    start="${AZURE_VM_SIZE}"
  fi
  for size in "${preferred[@]}"; do
    if [[ -n "$start" && "$seen_start" -eq 0 && "$size" != "$start" ]]; then
      continue
    fi
    seen_start=1
    image="$(ubuntu_image_for_sku "$size")"
    echo "Attempting VM create with size=$size image=$image"
    set +e
    create_live_vm_if_missing "$VICTIM_NAME" "$VICTIM_IP" "$size" "$image"
    status=$?
    set -e
    if [[ "$status" -eq 2 ]]; then
      echo "Victim create hit family quota on $size; trying next verified SKU." >&2
      continue
    fi
    if [[ "$status" -ne 0 ]]; then
      echo "Victim create failed on $size (status=$status); trying next verified SKU." >&2
      continue
    fi
    set +e
    create_live_vm_if_missing "$ATTACKER_NAME" "$ATTACKER_IP" "$size" "$image"
    status=$?
    set -e
    if [[ "$status" -eq 0 ]]; then
      SELECTED_VM_SIZE="$size"
      SELECTED_VM_IMAGE="$image"
      echo "Provisioned both VMs with $size"
      return 0
    fi
    echo "Attacker create failed on $size after victim succeeded (status=$status)." >&2
    return "$status"
  done
  echo "Unable to provision both VMs with any verified 2-vCPU student-quota SKU." >&2
  return 1
}

schedule_utc_shutdown() {
  local name="$1"
  # 21:00 UTC == 02:00 PKT.
  run az vm auto-shutdown \
    --resource-group "$RG" \
    --name "$name" \
    --time "$AUTO_SHUTDOWN_UTC"
}

write_azure_portal_state() {
  local app_id="$1"
  mkdir -p /tmp/threatfusion-range-demo
  AZURE_APP_ID="$app_id" \
  VICTIM_NAME="$VICTIM_NAME" \
  ATTACKER_NAME="$ATTACKER_NAME" \
  VICTIM_IP="$VICTIM_IP" \
  ATTACKER_IP="$ATTACKER_IP" \
  STATE_PATH="$STATE_PATH" \
  RG="$RG" \
  LOCATION="$LOCATION" \
  LIVE_VNET="$LIVE_VNET" \
  LIVE_SUBNET="$LIVE_SUBNET" \
  LIVE_NSG="$LIVE_NSG" \
  LIVE_ADMIN_USER="$LIVE_ADMIN_USER" \
  AUTO_SHUTDOWN_UTC="$AUTO_SHUTDOWN_UTC" \
  SELECTED_VM_SIZE="${SELECTED_VM_SIZE:-}" \
  SELECTED_VM_IMAGE="${SELECTED_VM_IMAGE:-}" \
  python3 - <<'PY'
import json
import os
import subprocess
from pathlib import Path

rg = os.environ["RG"]
victim_name = os.environ["VICTIM_NAME"]
attacker_name = os.environ["ATTACKER_NAME"]
state_path = Path(os.environ["STATE_PATH"])

account = json.loads(
    subprocess.check_output(["az", "account", "show", "-o", "json"], text=True)
)
vms = json.loads(
    subprocess.check_output(
        ["az", "vm", "list", "-g", rg, "-d", "-o", "json"], text=True
    )
)
by_name = {str(item.get("name") or ""): item for item in vms if isinstance(item, dict)}


def ip_bundle(name: str, fallback_private: str) -> dict:
    item = by_name.get(name) or {}
    private = str(item.get("privateIps") or fallback_private or "")
    public = str(item.get("publicIps") or "")
    return {
        "name": name,
        "power_state": str(item.get("powerState") or ""),
        "size": str(item.get("hardwareProfile", {}).get("vmSize") or item.get("vmSize") or ""),
        "private_ip": private.split(",")[0].strip() if private else fallback_private,
        "public_ip": public.split(",")[0].strip() if public else "",
        "location": str(item.get("location") or os.environ.get("LOCATION") or ""),
    }


victim = ip_bundle(victim_name, os.environ["VICTIM_IP"])
attacker = ip_bundle(attacker_name, os.environ["ATTACKER_IP"])
state = {
    "tenant_id": account.get("tenantId") or "",
    "subscription_id": account.get("id") or "",
    "subscription_name": account.get("name") or "",
    "app_id": os.environ.get("AZURE_APP_ID", ""),
    "resource_group": rg,
    "location": os.environ.get("LOCATION") or "southeastasia",
    "vnet": os.environ["LIVE_VNET"],
    "subnet": os.environ["LIVE_SUBNET"],
    "nsg": os.environ["LIVE_NSG"],
    "admin_username": os.environ["LIVE_ADMIN_USER"],
    "auto_shutdown_utc": os.environ["AUTO_SHUTDOWN_UTC"],
    "auto_shutdown_pkt": "02:00",
    "vm_size": os.environ.get("SELECTED_VM_SIZE") or victim.get("size") or "",
    "vm_image": os.environ.get("SELECTED_VM_IMAGE") or "",
    "victim_vm_ip": victim["private_ip"],
    "attacker_vm_ip": attacker["private_ip"],
    "victim_public_ip": victim["public_ip"],
    "attacker_public_ip": attacker["public_ip"],
    "vms": {
        victim_name: victim,
        attacker_name: attacker,
    },
}
state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
print(state_path)
PY
}

provision_live_azure() {
  require_az
  local vm_size image
  SELECTED_VM_SIZE=""
  SELECTED_VM_IMAGE=""
  vm_size="$(pick_southeastasia_vm_size)"
  image="$(ubuntu_image_for_sku "$vm_size")"
  echo "Preferred southeastasia SKU: $vm_size"
  echo "Preferred Ubuntu image: $image"
  local roles
  roles='[{"allowedMemberTypes":["User"],"description":"Tier-3 SOC approver who may sign SOAR playbooks","displayName":"SOC Approver","id":"c1a0b011-1111-4111-8111-000000000011","isEnabled":true,"value":"soc_approver"},{"allowedMemberTypes":["User"],"description":"Tier-1 analyst limited to triage","displayName":"Tier-1 Triage","id":"c1a0b012-2222-4222-8222-000000000012","isEnabled":true,"value":"tier1_triage"},{"allowedMemberTypes":["User"],"description":"Read-only compliance auditor","displayName":"Compliance Auditor","id":"c1a0b013-3333-4333-8333-000000000013","isEnabled":true,"value":"compliance_auditor"}]'
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
  ensure_live_nsg
  ensure_live_vnet
  if [[ "$DRY_RUN" -eq 1 ]]; then
    create_live_vm_if_missing "$VICTIM_NAME" "$VICTIM_IP" "$vm_size" "$image"
    create_live_vm_if_missing "$ATTACKER_NAME" "$ATTACKER_IP" "$vm_size" "$image"
    SELECTED_VM_SIZE="$vm_size"
    SELECTED_VM_IMAGE="$image"
  else
    create_both_live_vms "$vm_size"
  fi
  schedule_utc_shutdown "$VICTIM_NAME"
  schedule_utc_shutdown "$ATTACKER_NAME"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would write $STATE_PATH from az vm list -g $RG -d"
    return 0
  fi
  write_azure_portal_state "$app_id"
  show_status
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
