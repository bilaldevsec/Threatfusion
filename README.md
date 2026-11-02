<div align="center">

# 🛡️ ThreatFusion (AI-FYP-2006)

**Deterministic-First AI Security Operations Center (SOC) — Mitigating Alert Fatigue in Security Operations through a Unified Threat Intelligence and Analytics Interface**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Ubuntu 24.04 LTS](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![Frozen Random Forest](https://img.shields.io/badge/Frozen%20Random%20Forest-bd2853a6-238636)](#section-8-benchmark)
[![n8n Hash-Chained SOAR](https://img.shields.io/badge/n8n-Hash--Chained%20SOAR-EA4B71?logo=n8n&logoColor=white)](#analyst-workflow)
[![FAST-NUCES CS492 FYP-II](https://img.shields.io/badge/FAST--NUCES-CS492%20FYP--II-0A2540)](#project)
[![Repository Integrity Gate](https://img.shields.io/badge/Repository%20Integrity%20Gate-GO-1f6feb)](#governance)

[Product tour](#product-tour) · [Architecture](#architecture) · [Quickstart](#quickstart) · [Analyst workflow](#analyst-workflow) · [Section 8 benchmark](#section-8-benchmark) · [Governance](#governance) · [Project](#project)

</div>

ThreatFusion is a local security operations console. A frozen Random Forest is the only alert authority. Analysts record a separate verdict, assign a case, and approve a response. The autoencoder does not change the alert decision. Host containment stays unauthorized.

## Executive summary

- **Sole alert authority.** The frozen Random Forest scores each 14-feature flow. `production_fusion_enabled = False`.
- **Secondary v2 autoencoder ranker.** The autoencoder can order a queue. It does not change the forest decision.
- **Institutional context memory.** A grounded analyst verdict remembers an entity rule beside the score. The forest probability stays as stored.
- **Cryptographic SOAR ledger.** Approval is a SHA-256 hash chain. Dispatch records an HMAC callback. Containment of `172.29.0.10` runs only inside the lab victim after that chain and callback.

## Product tour

The console is four full-screen views. Simulation controls stay in the lab drawer.

### Active Investigations Queue

Stored rows, source filters, and the frozen-forest decision.

![Active Investigations Queue](docs/screenshots/01_master_detail_dashboard.png)

### Investigation Detail and Evidence Locker

Sensor line, forest score, and the three stored SQL queries.

![Investigation Detail and Evidence Locker](docs/screenshots/02_gemini_threat_copilot.png)

### AI Action Graph and 5-column DAG

Alert, understand, collect, analyze, and respond.

![AI Action Graph and 5-column DAG](docs/screenshots/03_glassbox_evidence_checklist.png)

### AI Threat Hunter and asset telemetry

Queue mix and the digital asset inventory.

![AI Threat Hunter and asset telemetry](docs/screenshots/04_n8n_soar_callback.png)

### SOAR containment and reversible firewall drop

Lab drop of `172.29.0.10` inside the victim namespace, then rollback.

![SOAR containment and reversible firewall drop](docs/screenshots/05_victim_firewall_containment.png)

### Adversarial red-team audit

Five refusal probes against an isolated temporary database.

![Adversarial red-team audit](docs/screenshots/06_agy_adversarial_audit.png)

## Architecture

One process on `127.0.0.1` serves the console and the contract routes. `scripts/run_live_product.sh` starts that process, waits for `GET /` and `GET /healthz`, and stops it on Ctrl-C or `SIGTERM`.

```mermaid
flowchart LR
  subgraph stage12 [Stage 1 and 2 Telemetry]
    sensor[Suricata or recorded 14-feature flow]
    mtls[Admission and source identity]
  end
  subgraph stage3 [Stage 3 Scoring]
    forest[Frozen Random Forest]
    gate[Gate G9]
    ae[v2 autoencoder ranker]
  end
  subgraph stage45 [Stage 4 and 5 Correlation and RAG]
    stitch["30.0s burst and 600.0s campaign"]
    rag[Local MITRE and CVE retrieval]
    memory[Context memory]
  end
  subgraph stage6 [Stage 6 SOAR and Containment]
    chain[SHA-256 approval chain]
    callback[HMAC callback]
    lab[Lab victim drop and rollback]
  end
  sensor --> mtls --> forest
  gate --- forest
  forest --> ae
  forest --> stitch --> rag --> memory
  memory --> chain --> callback --> lab
```

`production_fusion_enabled = False`. The autoencoder does not decide the alert. Host containment stays unauthorized until an analyst approves a hash-chained playbook and a callback is recorded. The lab drop still does not mark `containment_executed` on the approval route.

```text
Recorded 14-feature flow
  -> frozen Random Forest decision
  -> SQLite queue with live counts
  -> analyst verdict, rationale, assignee, and review status
  -> glass-box checklist from stored fields
  -> correlation of Attack rows that share a verified entity key
  -> grounded shift handoff
  -> hash-chained approval, verify-state, and HMAC callback
```

Approval, verify-state, and the callback share one ledger file. A missing ledger fails closed.

## Quickstart

From the repository root, with `threatfusion-venv` installed:

```bash
uv python install 3.11 && uv venv threatfusion-venv --python 3.11 && UV_PROJECT_ENVIRONMENT=threatfusion-venv uv sync --locked --dev
```

```bash
./scripts/run_live_product.sh --seed-demo
```

Open `http://127.0.0.1:8766/`. `--seed-demo` stores four labeled scenarios and keeps serving. `--dry-run` checks the interpreter, the console files, the lab secret lengths, and a free port without binding. `--smoke` requires HTTP 200 from the page and from `/healthz`, then stops and checks that the port is free.

The lab HMAC and MISP values are not production credentials. Replace them before any shared deployment.

### Cyber range

```bash
./scripts/run_full_range_demo.sh --up
./scripts/run_full_range_demo.sh --scan
./scripts/run_full_range_demo.sh --down
```

`--up` starts the console, `docker/docker-compose.n8n.yml`, the private `172.29.0.0/24` range, and the eve follower. It waits until Suricata logs `Engine started`. The process listens beyond loopback so the n8n container can call `http://host.docker.internal:8766`. `--scan` runs non-interactive `curl` and `ssh -o BatchMode=yes` from `172.29.0.10` and waits until a new `172.29.0.10 -> 172.29.0.20` row is stored. Multicast, link-local, broadcast, and port 5353 are not ingested. `--down` stops the follower, the console, n8n, and the range. The host firewall is not changed. No Azure resources are created.

## Analyst workflow

| Action | Route | What is stored |
|---|---|---|
| Ingest or replay | `POST /api/v1/live/ingest`, `POST /api/v1/live/replay`, `POST /api/v1/live/scenarios` | 14-feature flow scored by the frozen Random Forest |
| Live sensor | `POST /api/v1/live/sensor` | One Suricata bridge flow. Optional `sensor_node` defaults to `suricata_bridge` and may be `aws_cloud_sensor`. A configured `THREATFUSION_SENSOR_INGEST_TOKEN` requires a matching bearer token. The observation line and the forest score stay separate |
| Context memory | `POST /api/v1/live/context-memory`, `GET /api/v1/live/context-memory` | Institutional rule for a stored flow entity. A verified verdict writes one too. The frozen forest score stays unchanged |
| Assets | `GET /api/v1/live/assets` | Observed source and destination entities, RFC1918 classification, and memory counts |
| Verdict | `POST /api/v1/live/verdict` | `true_positive`, `false_positive`, or `inconclusive`, with a grounded rationale, beside the forest decision |
| Assignment | `POST /api/v1/live/assignment` | Local assignee and `unassigned`, `in_review`, or `reviewed` |
| Triage | `POST /api/v1/live/triage` | Acknowledge, escalate, or dismiss |
| Handoff | `POST /api/v1/live/handoff` | Four blocks plus the verdict, assignee, and review status, only when the note stays inside stored evidence |
| Approve | `POST /api/v1/live/soar/approve` | Hash-chained approval. `containment_executed` stays false |
| Dispatch | `POST /api/v1/live/soar/dispatch` | Signed callback. Uses live n8n when `THREATFUSION_N8N_WEBHOOK_URL` is set, otherwise `local_contract_fallback`. `containment_executed` stays false |
| Contain | `POST /api/v1/live/soar/contain` | Drops `172.29.0.10` inside the victim container after an approved hash chain and a verified callback |
| Rollback | `POST /api/v1/live/soar/rollback` | Removes that victim-namespace drop and requires the attacker path to succeed |
| Stitch | `POST /api/v1/live/correlate` | Attack rows inside the 30.0 second burst window or the 600.0 second campaign window |

The queue searches, filters, and sorts stored rows by source, forest decision, triage state, analyst verdict, and forest probability. Live sensor rows, the recorded UNSW study, and the labeled scenario replay do not share a campaign id. The hero cards show the live SQLite flow, campaign, and incident counts, plus how many stored rows came from the live bridge. The January 216,568-flow figures stay in the Frozen Benchmark Evaluation Baseline.

## Section 8 benchmark

January validation has 216,568 rows. The frozen Random Forest counts are TP 4,045, FP 201, TN 212,009, FN 313. FPR is 0.095% (201 / 212,210 benign).

| Measure | Frozen Random Forest | Fusion candidate |
|---|---|---|
| Rows | 216,568 | same population |
| Recall | 92.818% (4,045 / 4,358) | 95.021% |
| Precision | 95.266% | 69.997% |
| False positives | 201 | 1,775 |
| False positive rate | 0.095% (201 / 212,210) | — |
| Extra attacks | — | 96 |
| Extra false alarms | — | 1,574 |

That is a +2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045). `production_fusion_enabled = False` because those 96 extra attacks cost 1,574 extra false alarms.

| Model | Role | SHA-256 |
|---|---|---|
| Random Forest | sole alert authority | `bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9` |
| Logistic regression | linear baseline | `2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148` |
| Autoencoder v2 | unfused ranker | `c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23` |
| Rate-log1p candidate | blocked baseline | `1d02e5bba556cb28709bd0faefce5f29da424a419a2d95332ad27a8995b26f63` |

## Governance

- The frozen Random Forest scores a flow only when the artifact digest matches and the input width is 14.
- The analyst verdict, rationale, assignee, and review status are stored separately from that decision.
- A rationale that names an address the flow does not store is refused.
- RFC1918, loopback, link-local, and IPv6 unique-local addresses are refused before any indicator lookup.
- The SOAR ledger is a SHA-256 hash chain. A failed timing write does not report the callback as recorded.
- Host containment stays unauthorized.
- TF-008, TF-009, TF-010, and TF-011 remain open. Scores on unseen traffic, a human cohort of at least 10, a signed jury form, and a live feed are not done.

## Project

Muhammad Bilal (21K-3551), Muhammad Suhaib Shaikh (22K-4302), Muhammad Hasnain (22K-4718), Supervisor Sir Sameer Faisal — FAST-NUCES Karachi CS492 AI-FYP-2006. Documented evaluation checkpoint: 21 September 2026.
