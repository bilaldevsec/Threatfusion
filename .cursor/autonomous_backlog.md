# ThreatFusion Autonomous Engineering Backlog (Updated Post-cfe3430)

## Autonomous Execution Rules
1. NEVER stop after finishing a task. Immediately proceed to the next unchecked `[ ]` task.
2. NEVER ask the user for confirmation or input.
3. Before every commit:
   - `git diff --check`
   - `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/python scripts/boundary_preflight.py --venv threatfusion-venv --json` (B0-B6 GO)
   - `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/python scripts/audit_repo_truth.py` (7/7 GO)
4. Mark completed tasks `[x]`, commit to `gemini/product-20260924`, and immediately start the next `[ ]` task until all tasks are `[x]` or weekly quota reaches 95%.

## Completed Foundation Slices
- [x] TASK-1 (Commit 8d9d3cb): Live 14-feature flow ingestion panel, Frozen RF scoring (`production_fusion_enabled = False`), local MITRE copilot (`T1059`), 6-node n8n workbench inspection, analyst notes, and non-mutating PSI drift check.
- [x] TASK-2 (Commit cfe3430): Dynamic SQLite-backed Campaign Queue replacing sample walkthrough, 5-vector UNSW-NB15 replay (`4 Benign`, `1 Attack at 54.3%`), and real SHA-256 hash-chained SOAR approval (`soar:dcb1e6213c6b`, receipt `be30bcf02a8cf50e`).

## Remaining Autonomous Product Queue (Execute Non-Stop in Order)
- [x] TASK-3: End-to-End SOAR Containment & Signed Callback Loop: Wire approved SOAR playbooks (`approved` state in `soar.sqlite3`) to dispatch to the local contract server (`run_misp_and_callback_contract_server.py`), verify Node 2 (`/api/v1/soar/verify-state`), create the 4-Block TheHive case, and record the signed 64-hex HMAC callback receipt (`POST /api/v1/soar/callback`) with real MTTR calculation in the UI. The earlier checkmark overstated the default launcher: approval wrote `threatfusion-live-soar.sqlite3`, while verify-state and callback required an explicit `soar_db_path` and returned HTTP 403. Those endpoints now use that same ledger. `test_http_dispatch_records_four_block_case_hmac_and_ledger_mttr` posts to the live dispatch route with the ledger unset. Host containment stays unauthorized.
- [x] TASK-4: Live Dual-Window Correlation & Attack Timeline Drawer: When multiple attack flows are ingested or replayed within the `30.0s` burst / `600.0s` campaign windows, stitch them automatically via `IncidentCorrelationEngine`, display the correlated flow count and unified timeline in the browser, and enforce the `HTTP 422` RFC1918 private-IP guard on MISP lookups. The earlier checkmark was not HTTP-proven. Ingest and replay now call the engine; a gap of `30.0s` stays in the burst and `30.001s` falls through to the campaign; a gap of `600.0s` stays in the campaign and `600.001s` does not stitch. The browser drawer reads `correlated_flow_count` and timeline events from that response. `POST /attributes/restSearch` returns HTTP 422 for RFC1918, IPv6 ULA, loopback, and link-local addresses before the local indicator table. Documentation ranges `198.51.100.0/24` and `203.0.113.0/24` are not RFC1918 and still match the local canonical indicators.
- [x] TASK-5: Interactive Analyst Triage, Shift Handoff & Grounded Brief Export: Wire `Acknowledge`, `Escalate`, `Dismiss`, and `Export Shift Handoff / 4-Block Incident Report` in the UI to SQLite and `verify_explanation_groundedness()`.
- [x] TASK-6: Turnkey 1-Command Product Launcher & Root README: Create `scripts/run_live_product.sh` (starts both the SOC console and MISP/TheHive/n8n contract server cleanly) and write an executive root `README.md` with architecture diagrams, Section 8 math proof, and quickstart commands.
- [x] TASK-7: Full Test Suite Audit & Board of Directors Final Report: The full pytest suite passed 1,527 tests after a damaged alert database was classified as `database_corrupt`. `docs/BOARD_OF_DIRECTORS_FINAL_REPORT.md` records the completed console, the verification output, and the live demo walkthrough.
