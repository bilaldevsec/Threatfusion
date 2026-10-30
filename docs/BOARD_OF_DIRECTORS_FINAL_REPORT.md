# ThreatFusion board report

**Date:** 2026-10-27  
**Branch:** `gemini/product-20260924`  
**Status:** bounded lab product with a live local console. Not a deployed enterprise SOC.

## What an analyst can do today

On `http://127.0.0.1:8766` the top funnel, the pipeline ribbon, the queue, and the five-tab inspector read one live SQLite database through `GET /api/v1/live/surfaces`. There is no separate sample queue.

- Ingest sends 14 canonical features to `POST /api/v1/live/ingest`.
- The frozen Random Forest scores that vector only when its file verifies and its input width is 14. A browser check on 2026-10-27 returned `Benign (frozen_random_forest_scored)` for a toy all-ones vector, with fusion disabled.
- Analyst notes are stored in a local WAL SQLite file.
- The MITRE question box queries the local corpus. A browser check returned `T1059 Command and Scripting Interpreter`. A containment question is refused.
- Drift reads stored rows and does not change model weights.
- The workbench lists the 6 n8n nodes and does not dispatch a playbook.

The campaign queue reads stored flows from that same database. Replay scores the five recorded UNSW-NB15 study vectors with the frozen Random Forest and does not copy the printed study probability. Approve writes a hash-chained local approval and returns the 64-hex receipt. It does not execute containment, and it does not invent a TheHive case or an n8n signature. A missing or empty database shows zero funnel counts and an empty queue. It does not substitute the January benchmark population or a hardcoded incident.

Dispatch sends an approved playbook to `POST /api/v1/soar/verify-state`, writes a 4-block TheHive case (queued offline when TheHive is down), then records the HMAC-SHA256 callback from `POST /api/v1/soar/callback`. The drawer shows that callback's case id, HMAC prefix, and MTTR from the ledger timestamps (`t_callback_verified - t_approval_queued`). A second dispatch returns the same 64-hex signature. Host containment stays unauthorized.

The default launcher does not set a separate ledger path. Approval, verify-state, and the callback share `threatfusion-live-soar.sqlite3` beside the console database. Before this correction, verify-state ignored that file and returned HTTP 403, so the UI could not show a real callback MTTR. A missing ledger still fails closed. A timing write that fails does not report the callback as recorded.

Ingest and replay call `IncidentCorrelationEngine` on stored Attack rows. The burst window is 30.0 seconds and the campaign window is 600.0 seconds. A gap equal to either boundary stays inside that window. Two rows that share a verified 5-tuple at exactly 30.0 seconds become one burst. The same pair at 30.001 seconds is not a burst; it is still inside the campaign window, so it becomes one campaign. Two different ports on the same host pair at exactly 600.0 seconds become one campaign. At 600.001 seconds they stay singletons. The drawer shows `correlated_flow_count` and one timeline line per flow, using that flow's observed time. Rows without a verified entity key stay singletons. The recorded UNSW study replay has no entity key, so those five rows do not stitch. Benign rows are not members.

`POST /attributes/restSearch` returns HTTP 422 for RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), IPv6 ULA (`fc00::/7`), loopback (`127.0.0.0/8` and `::1`), and link-local (`169.254.0.0/16` and `fe80::/10`) before the local indicator table is read. An IPv4-mapped address is judged as its embedded IPv4 address. No outbound MISP socket is opened on that route. Documentation ranges `198.51.100.0/24` and `203.0.113.0/24` are not RFC1918. The previous `ipaddress.is_private` check refused them, so the route's own indicators `198.51.100.27` and `203.0.113.195` never matched. Those two addresses now return the local canonical attribute. `POST /api/v1/live/misp-guard` uses the same address rule and does not perform a lookup.

Acknowledge, Escalate, and Dismiss each append a triage row and store the latest state on that flow. The campaign card and the drawer show the stored state after the queue reloads. Export Shift Handoff builds the four blocks from the stored row, includes those triage events in the shift-handoff timeline, and calls `verify_explanation_groundedness()`. Block 3 stays `unavailable` because no technique is stored on the flow. A shift note that names an address outside the stored entity ids is refused and is not copied into the report. The page shows and downloads the markdown only after that check passes. Containment stays unauthorized.

`scripts/run_live_product.sh` starts the page and the contract endpoints as one process on `127.0.0.1:8766`. Before it binds, it checks that the port is free, the virtualenv interpreter exists, the console files exist, and the lab HMAC and MISP values are at least 16 characters. A failed check prints `error:` and leaves no listener. After the process is up, the launcher waits for HTTP 200 from `GET /` and from `GET /healthz`. Ctrl-C and `SIGTERM` stop that process and release the port. `--dry-run` prints the plan without binding. `--smoke` checks both responses and the release. The launcher sets `THREATFUSION_SOAR_LEDGER_DB_PATH` to the live SOAR file beside the console database so approval, verify-state, and the callback share one ledger when the variable was unset. The root README states the architecture, the Section 8 comparison (`+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)`; those 96 true positives cost 1,574 extra false positives, 16.3958 false alarms per extra attack, fused precision 69.997%), and the same quickstart. The lab HMAC and MISP defaults are not production credentials.

Open pull requests #2, #3, and #4 are not in this branch. Dispatch on this branch uses the ledger path the launcher now sets. Stitch still runs when the analyst calls `POST /api/v1/live/correlate`; ingest and replay do not stitch by themselves. Acknowledge, Escalate, and Dismiss store a triage row, and the handoff stays grounded with block 3 `unavailable` when no technique was retrieved. The unmerged requests add the server fallback for an unset ledger, automatic stitch, the member timeline tab, and triage history inside the handoff packet.

A browser check on 2026-10-27 replayed those five vectors. The frozen Random Forest scored four Benign and one Attack (54.3%). Approve then showed `SOAR Chain: VERIFIED (SHA-256 Linked)` for playbook `soar:dcb1e6213c6b`, with receipt prefix `be30bcf02a8cf50e` and ledger state `approved`. The other four rows stayed pending.

## What is not claimed

- TF-008, TF-009, TF-010, and TF-011 remain open.
- There is no live enterprise SIEM feed, no 10-person analyst study, and no signed jury rubric.
- The autoencoder does not decide alerts.
- The four frozen model digests are unchanged.
- Private addresses are not sent to a public reputation service by this panel.

## Live demo walkthrough

1. Run `scripts/run_live_product.sh --dry-run`, then `scripts/run_live_product.sh`.
2. Open `http://127.0.0.1:8766`. Confirm `/healthz` returns `{"status": "ok"}`.
3. Choose Replay Benchmark Attack Burst. The frozen Random Forest scores the five recorded vectors. The 2026-10-27 browser check scored four Benign and one Attack at 54.3%.
4. Approve the Attack row. The drawer shows `SOAR Chain: VERIFIED (SHA-256 Linked)` and the 64-hex receipt.
5. Choose Dispatch signed callback on an approved row. The drawer shows the HMAC prefix, the stored case id, and the callback MTTR. Host containment is not executed. Approval and the callback share one ledger even when the environment path is unset; the launcher also exports that shared path.
6. Ingest or replay two Attack rows that share a verified entity key. A 30.0-second gap on the same 5-tuple shows correlated flow count 2 and a burst timeline. A 600.0-second gap on different ports shows one campaign. Choose Stitch verified windows to read the same stored result again.
7. Choose Check private IP guard. The status line reports HTTP 422 for `10.0.0.4`. Loopback and link-local addresses are refused by the same MISP lookup route before any indicator lookup.
8. Choose Acknowledge, Escalate, or Dismiss on a stored flow. The card keeps the stored triage state after the queue reloads.
9. Optionally type a shift note, then choose Export Shift Handoff / 4-Block Incident Report. The four-block markdown is shown and downloaded only when the note stays inside the stored evidence. A note that names an address that is not stored is refused.

Stop the process with Ctrl-C when the walkthrough is finished. The launcher binds only to `127.0.0.1` and shuts the child down on `SIGTERM` as well.

## Gates for this slice

On 2026-10-30 the checkout was the bind mount `/home/muhammad-bilal/projects/threatfusion-gemini`. `libnss3-tools` provided `certutil`. No UNSW data was downloaded.

`git diff --check` passed.

`scripts/boundary_preflight.py --venv threatfusion-venv --json` was GO for B0–B6.

`scripts/audit_repo_truth.py` was 7/7 GO. Check 2 matched these digests:

- Random Forest `bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9`
- Logistic Regression `2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148`
- Autoencoder v2 `c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23`
- Rate-log1p candidate `1d02e5bba556cb28709bd0faefce5f29da424a419a2d95332ad27a8995b26f63`

Section 8 stayed `production_fusion_enabled=False`. Gate G9 passed. TF-008, TF-009, TF-010, and TF-011 stayed open.

`env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/pytest -q --tb=line backend/tests` collected 1,544 tests: 1,530 passed, 7 failed, 7 skipped, exit code 1. The 7 failures are the known missing-UNSW registration set. Six raise `unsw_registration_invalid` because `NUSW-NB15_features.csv` and the processed UNSW tree are gitignored and were not downloaded:

- `test_full_soc_demo_runner_end_to_end`
- `test_milestone23_complete_product_spine`
- `test_slide14_end_to_end_spine_suricata_to_quiescent_snapshot`
- `test_slide14_full_post_ingestion_soc_workflow`
- `test_full_soc_demo_incorporates_chromadb_misp_thehive_n8n`
- `test_run_full_soc_demo_incorporates_soar_chain_queue_ranker_and_drift`

`test_one_registered_attack_reaches_authenticated_browser_and_degrades_cleanly` exits `registered_browser_path_failed` for that same missing registration. The earlier product checkpoint's 1,527-pass count was measured before these deltas and before this checkout's missing UNSW files.

## Deltas taken from open PRs 2–5

- PR #2 (`cursor/task-3-soar-callback-8fab`, `9665090`): approval, verify-state, and the HMAC callback share one SQLite ledger even when `THREATFUSION_SOAR_LEDGER_DB_PATH` is unset. A failed timing write does not report the callback as recorded. The drawer shows the stored case id, HMAC prefix, and ledger MTTR.
- PR #3 (`cursor/task-4-correlation-timeline-a054`, `458ccba`): ingest and replay call `IncidentCorrelationEngine` with the inclusive 30-second burst and 600-second campaign windows. The drawer shows `correlated_flow_count` and each flow's observed time. MISP lookup returns HTTP 422 for RFC1918, ULA, loopback, and link-local addresses before any indicator lookup.
- PR #4 (`cursor/task-5-triage-handoff-c007`, `ee15e91` and `22ab96c`): Acknowledge, Escalate, and Dismiss append `triage_events` and keep the latest state on the flow across reload. The grounded handoff includes that history. A note that names an address outside the stored flow is refused by `verify_explanation_groundedness()`.
- PR #5 (`cursor/task-6-product-launcher-bd6b`, `7093708`): `scripts/run_live_product.sh` preflights the port, secrets, and console files, waits until `/` and `/healthz` answer, points verify-state at the same ledger, and stops that process on SIGTERM. `--dry-run` and `--smoke` are part of that launcher.

These four pull requests can be closed as superseded by this branch. The measured gates for the integrated checkout are in the section above. This branch also adds `GET /api/v1/live/surfaces`, so the top funnel, pipeline ribbon, queue, and five-tab inspector read that one SQLite file. TF-008, TF-009, TF-010, and TF-011 stay open. The four frozen digests are unchanged. `production_fusion_enabled` stays false.
