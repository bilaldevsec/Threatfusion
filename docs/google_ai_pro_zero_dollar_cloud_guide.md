# Google AI Pro $0-Guaranteed Cloud Architecture & Programmatic Kill-Switch Guide

## 1. Executive Summary & Zero-Dollar Financial Safety Invariant

ThreatFusion's cloud deployment architecture (Slide 14: Azure/GCP victim VM with Suricata EVE edge forwarder) provides end-to-end telemetry ingestion for live attack detection. Because ThreatFusion is an academic Final Year Project (FYP-II), it operates under a strict, non-negotiable financial constraint:

> **Core Invariant**: Absolute $0.00 out-of-pocket liability. The project must run entirely within the $10.00/month Google AI Pro / Google Developer Program recurring cloud credit, with mathematical guarantees preventing any charges from spilling onto the developer's personal credit card.

To enforce this invariant, ThreatFusion implements a **dual-layer self-healing and financial shutoff architecture**:
1. **Telemetry Ingestion Layer (`threatfusion.operations.cloud_live_telemetry`)**: A self-healing Suricata EVE JSON forwarder that catches malformed packets, truncated records, and schema errors into an isolated dead-letter quarantine, preventing infinite retry loops or runaway log generation.
2. **Financial Kill-Switch Layer (`CloudBudgetKillSwitchPolicy`)**: An automated, fail-closed spending monitor that detaches the Cloud Billing Account when gross project spend reaches **$5.00 USD** (50% of the $10.00 monthly credit).

```
                      +----------------------------------------+
                      |  Google AI Pro Monthly Credit: $10.00   |
                      +----------------------------------------+
                                          |
    Gross Spend: $0.00 to $4.99           |           Gross Spend: >= $5.00
  [NORMAL OPERATION REGION]               |        [KILL-SWITCH DETACHMENT REGION]
  • Suricata edge forwarding active       |        • Billing account detached
  • RF 14-feature adaptation running      |        • Compute Engine VMs stopped
  • Provenance contracts bound            |        • Network egress stopped
  • Dead letters safely quarantined       |        • Out-of-pocket charges = $0.00
                                          |
                      +----------------------------------------+
                      |   Hard Shutoff Threshold: $5.00 USD    |
                      |   Safety Margin Buffer:   $5.00 USD    |
                      +----------------------------------------+
```

---

## 2. Why a $5.00 Hard Shutoff Threshold?

Cloud provider billing metrics (including GCP Cloud Billing export and Azure Cost Management) exhibit **reporting latency between 1 to 4 hours**. If a kill-switch triggered only at 100% ($10.00), a sudden burst of network egress or runaway compute could accumulate an additional $1.00–$2.00 in charges before the billing export message arrived, resulting in out-of-pocket overdraft.

By setting `hard_shutoff_threshold_usd = 5.0`:
- **50% Safety Margin**: Exactly $5.00 of the credit remains untouched as an absorption buffer for billing propagation delays.
- **Fail-Closed Assurance**: Even in the worst-case propagation delay, total charges remain comfortably beneath the $10.00 credit ceiling.
- **Out-of-Pocket Guarantee**: The developer never incurs a single cent ($0.00) in personal charges.

---

## 3. Architecture Component Walkthrough

### 3.1. Resilient Stream Processor with Dead-Letter Quarantine

Located in `backend/src/threatfusion/operations/cloud_live_telemetry.py`:
- **`process_suricata_eve_stream_resilient`**:
  - Safely ignores blank lines and whitespace.
  - Automatically skips non-flow Suricata records (`event_type` in `{"stats", "dns", "http", "tls", "alert"}`) without raising errors.
  - Catches malformed JSON lines (`"malformed_json_line"`) and invalid schemas (`"schema_validation_failed"`: negative packet counters, invalid IP addresses, end timestamps preceding start timestamps) and stores them in `DeadLetterQuarantineRecord`.
  - Never halts or crashes the processing of subsequent valid attack flows.
  - Accurately binds and verifies `EntityProvenanceContract` for legitimate attack flows.

### 3.2. Programmatic Budget Kill-Switch Policy

- **`CloudBudgetKillSwitchPolicy`**:
  - `monthly_credit_usd: float = 10.0`
  - `hard_shutoff_threshold_usd: float = 5.0`
  - `include_credits_in_cost: bool = False`
  - `action_on_threshold: str = "detach_billing_account_and_stop_instances"`

- **`evaluate_budget_kill_switch`**:
  - Evaluates current gross spend against the policy.
  - **Fail-Closed Invariant**: If `gross_spend_usd < 0` or is non-finite (`NaN`, `Inf`), it immediately triggers `should_detach_billing = True` with status `triggered_fail_closed`.
  - When `gross_spend_usd >= 5.0`, triggers `should_detach_billing = True` with status `triggered_threshold_exceeded`.
  - When `0.0 <= gross_spend_usd < 5.0`, returns `should_detach_billing = False` with status `normal`.

---

## 4. Step-by-Step GCP Cloud Billing Kill-Switch Deployment

To deploy this automated kill-switch in a Google Cloud Platform project:

### Step 1: Create Cloud Pub/Sub Topic for Billing Alerts

```bash
gcloud pubsub topics create billing-kill-switch-topic
```

### Step 2: Configure Cloud Billing Budget with Pub/Sub Push

1. Open the [Google Cloud Console Billing Budgets & Alerts](https://console.cloud.google.com/billing/budgets).
2. Create a new budget named `ThreatFusion-Zero-Dollar-Cap`.
3. Set **Budget type** to `Specified amount` = **$10.00**.
4. Set **Actions / Trigger thresholds**:
   - `50%` of budget ($5.00 actual)
   - `100%` of budget ($10.00 actual)
5. Under **Manage notifications**, check **Connect a Pub/Sub topic to this budget** and select `billing-kill-switch-topic`.

### Step 3: Deploy Automated Detachment Cloud Function

Deploy a lightweight Python Cloud Function that subscribes to `billing-kill-switch-topic`:

```python
# main.py in Cloud Function
import base64
import json
import logging
from googleapiclient import discovery

def stop_billing(event, context):
    pubsub_data = base64.b64decode(event['data']).decode('utf-8')
    data = json.loads(pubsub_data)
    cost = data.get('costAmount', 0.0)
    project_id = data.get('budgetDisplayName', 'threatfusion-edge')
    
    logging.info(f"Received billing telemetry: cost={cost} USD")
    
    # Fail-closed check: >= $5.00 threshold or malformed negative cost
    if cost >= 5.00 or cost < 0:
        logging.critical(f"KILL-SWITCH TRIGGERED: spend={cost} USD exceeds $5.00 threshold. Detaching billing!")
        billing = discovery.build('cloudbilling', 'v1', cache_discovery=False)
        project_name = f'projects/{project_id}'
        
        # Disassociate billing account - immediately terminates all billable services & VMs
        billing.projects().updateBillingInfo(
            name=project_name,
            body={"billingAccountName": ""}
        ).execute()
        logging.info(f"Billing account successfully detached from {project_id}.")
```

Deploy the Cloud Function:
```bash
gcloud functions deploy billing-kill-switch \
    --runtime python311 \
    --trigger-topic billing-kill-switch-topic \
    --entry-point stop_billing \
    --region us-central1
```

---

## 5. Local Telemetry Forwarder CLI Usage

The forwarder script `scripts/run_cloud_suricata_forwarder.py` provides local testing and real-time streaming integration:

### 5.1. Streaming Suricata EVE Records from File or Pipe

```bash
# Ingest live or recorded Suricata eve.json stream
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/python scripts/run_cloud_suricata_forwarder.py \
    --input-file /var/log/suricata/eve.json \
    --sensor-namespace azure-suricata-edge-01 \
    --format text
```

### 5.2. Evaluating Budget Kill-Switch Policy

```bash
# Test safe spend below threshold ($3.50 USD)
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/python scripts/run_cloud_suricata_forwarder.py \
    --budget-check 3.50 \
    --format text
```
**Output:**
```
================================================================
ThreatFusion Cloud Suricata EVE Live Telemetry Forwarder Report
================================================================
Sensor Namespace:          azure-suricata-edge-01
Total Lines Ingested:      0
Valid Flows Adapted:       0
Provenance Verified Count: 0
Non-Flow Events Skipped:   0
Dead-Letter Quarantined:   0
----------------------------------------------------------------
Cloud Budget Kill-Switch Policy Evaluation:
  Status:                  normal
  Gross Spend:             $3.50 USD
  Monthly Credit Cap:      $10.00 USD
  Hard Shutoff Threshold:  $5.00 USD
  Should Detach Billing:   False
  Action On Threshold:     allow
  Reason:                  Gross spend $3.50 USD is within safe budget threshold $5.00 USD.
================================================================
```

```bash
# Test threshold breach ($5.50 USD) with fail-on-kill-switch enforcement
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/python scripts/run_cloud_suricata_forwarder.py \
    --budget-check 5.50 \
    --fail-on-kill-switch \
    --format json
```
**Output:**
```json
{
  "status": "success",
  "sensor_namespace": "azure-suricata-edge-01",
  "telemetry_batch_report": {
    "total_lines_read": 0,
    "non_flow_events_skipped": 0,
    "valid_flows_adapted": 0,
    "dead_letter_count": 0,
    "provenance_verified_count": 0,
    "dead_letter_records": [],
    "adapted_results_count": 0
  },
  "budget_kill_switch": {
    "should_detach_billing": true,
    "kill_switch_triggered": true,
    "gross_spend_usd": 5.5,
    "hard_shutoff_threshold_usd": 5.0,
    "monthly_credit_usd": 10.0,
    "action": "detach_billing_account_and_stop_instances",
    "status": "triggered_threshold_exceeded",
    "reason": "Gross spend $5.50 USD reached or exceeded hard shutoff threshold $5.00 USD (credit limit: $10.00 USD). Detaching billing account to guarantee $0 out-of-pocket charges.",
    "remaining_safe_budget_usd": 0.0
  }
}
```
*(Exit code: `2` indicating automated shutoff condition).*

---

## 6. Reversibility & Auditability

1. **Reversibility**: Detaching a billing account does not delete persistent disks or repository code. Once the monthly billing cycle resets and fresh credits are granted, the billing account can be re-linked with a single command:
   ```bash
   gcloud billing projects link PROJECT_ID --billing-account=BILLING_ACCOUNT_ID
   ```
2. **Audit Logging**: Every dead-letter event and budget check evaluates deterministically without network side effects, writing ISO 8601 UTC timestamps into structured telemetry reports for verifiable evidence defense.
