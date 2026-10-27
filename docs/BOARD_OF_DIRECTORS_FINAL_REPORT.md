# ThreatFusion board report

**Date:** 2026-10-27  
**Branch:** `gemini/product-20260924`  
**Status:** bounded lab product with a live local console. Not a deployed enterprise SOC.

## What an analyst can do today

On `http://127.0.0.1` the SOC page now has a live panel next to the sample walkthrough.

- Ingest sends 14 canonical features to `POST /api/v1/live/ingest`.
- The frozen Random Forest scores that vector only when its file verifies and its input width is 14. A browser check on 2026-10-27 returned `Benign (frozen_random_forest_scored)` for a toy all-ones vector, with fusion disabled.
- Analyst notes are stored in a local WAL SQLite file.
- The MITRE question box queries the local corpus. A browser check returned `T1059 Command and Scripting Interpreter`. A containment question is refused.
- Drift reads stored rows and does not change model weights.
- The workbench lists the 6 n8n nodes and does not dispatch a playbook.

The campaign queue reads stored flows. Replay scores the five recorded UNSW-NB15 study vectors with the frozen Random Forest and does not copy the printed study probability. Approve writes a hash-chained local approval and returns the 64-hex receipt. It does not execute containment, and it does not invent a TheHive case or an n8n signature. Sample incidents remain only when the campaign request cannot be reached.

Dispatch sends an approved playbook to `POST /api/v1/soar/verify-state`, writes a 4-block TheHive case (queued offline when TheHive is down), then records the HMAC-SHA256 callback from `POST /api/v1/soar/callback`. The drawer shows that callback's case id, HMAC prefix, and MTTR from the ledger timestamps (`t_callback_verified - t_approval_queued`). A second dispatch returns the same 64-hex signature. Host containment stays unauthorized.

The default launcher does not set a separate ledger path. Approval, verify-state, and the callback share `threatfusion-live-soar.sqlite3` beside the console database. Before this correction, verify-state ignored that file and returned HTTP 403, so the UI could not show a real callback MTTR. A missing ledger still fails closed. A timing write that fails does not report the callback as recorded.

Ingest and replay call `IncidentCorrelationEngine` on stored Attack rows. The burst window is 30.0 seconds and the campaign window is 600.0 seconds. A gap equal to either boundary stays inside that window. Two rows that share a verified 5-tuple at exactly 30.0 seconds become one burst. The same pair at 30.001 seconds is not a burst; it is still inside the campaign window, so it becomes one campaign. Two different ports on the same host pair at exactly 600.0 seconds become one campaign. At 600.001 seconds they stay singletons. The drawer shows `correlated_flow_count` and one timeline line per flow, using that flow's observed time. Rows without a verified entity key stay singletons. The recorded UNSW study replay has no entity key, so those five rows do not stitch. Benign rows are not members.

`POST /attributes/restSearch` returns HTTP 422 for RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), IPv6 ULA (`fc00::/7`), loopback (`127.0.0.0/8` and `::1`), and link-local (`169.254.0.0/16` and `fe80::/10`) before the local indicator table is read. An IPv4-mapped address is judged as its embedded IPv4 address. No outbound MISP socket is opened on that route. Documentation ranges `198.51.100.0/24` and `203.0.113.0/24` are not RFC1918. The previous `ipaddress.is_private` check refused them, so the route's own indicators `198.51.100.27` and `203.0.113.195` never matched. Those two addresses now return the local canonical attribute. `POST /api/v1/live/misp-guard` uses the same address rule and does not perform a lookup.

Acknowledge, Escalate, and Dismiss persist a triage row. Export Shift Handoff calls `verify_explanation_groundedness()` and keeps block 3 `unavailable` when no technique was retrieved. A brief that names an address outside the evidence bundle is not verified.

`scripts/run_live_product.sh` starts the page and the contract endpoints as one process on `127.0.0.1:8766`. The root README states the architecture, the Section 8 comparison (`+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)`; fusion stays off because those 96 true positives cost 1,574 extra false positives), and the same quickstart. The lab HMAC and MISP defaults are not production credentials.

A browser check on 2026-10-27 replayed those five vectors. The frozen Random Forest scored four Benign and one Attack (54.3%). Approve then showed `SOAR Chain: VERIFIED (SHA-256 Linked)` for playbook `soar:dcb1e6213c6b`, with receipt prefix `be30bcf02a8cf50e` and ledger state `approved`. The other four rows stayed pending.

## What is not claimed

- TF-008, TF-009, TF-010, and TF-011 remain open.
- There is no live enterprise SIEM feed, no 10-person analyst study, and no signed jury rubric.
- The autoencoder does not decide alerts.
- The four frozen model digests are unchanged.
- Private addresses are not sent to a public reputation service by this panel.

## Live demo walkthrough

1. Run `scripts/run_live_product.sh`.
2. Open `http://127.0.0.1:8766`.
3. Choose Replay Benchmark Attack Burst. The frozen Random Forest scores the five recorded vectors. The 2026-10-27 browser check scored four Benign and one Attack at 54.3%.
4. Approve the Attack row. The drawer shows `SOAR Chain: VERIFIED (SHA-256 Linked)` and the 64-hex receipt.
5. Choose Dispatch signed callback. The drawer shows the HMAC prefix, the case id, and the callback MTTR.
6. Ingest or replay two Attack rows that share a verified entity key. A 30.0-second gap on the same 5-tuple shows correlated flow count 2 and a burst timeline. A 600.0-second gap on different ports shows one campaign. Choose Stitch verified windows to read the same stored result again.
7. Choose Check private IP guard. The status line reports HTTP 422 for `10.0.0.4`. Loopback and link-local addresses are refused by the same MISP lookup route before any indicator lookup.
8. Choose Acknowledge, Escalate, or Dismiss. The triage state is stored on that flow.
9. Choose Export Shift Handoff / 4-Block Incident Report. The packet is returned only when the brief is grounded.

Stop the process when the walkthrough is finished. The launcher binds only to `127.0.0.1`.

## Gates for this slice

On 2026-10-27 the full pytest suite was run from this repository with `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/pytest -q --tb=line`. The first run finished in about 314 seconds and failed one test: `backend/tests/unit/test_alert_persistence.py::test_corruption_is_not_replaced_and_errors_are_sanitized`. Opening a non-SQLite file ran `PRAGMA journal_mode=WAL` before the integrity check, and SQLite's `file is not a database` was labeled `database_unavailable`. The alert repository now labels that message `database_corrupt` and still leaves the damaged bytes in place. The persistence file then passed 19 tests. The full suite was run again and passed 1,527 tests in about 312 seconds, with exit code 0.

`git diff --check`, boundary preflight B0–B6, and the repository-truth audit (7/7) are the commit gates for this report. TF-008, TF-009, TF-010, and TF-011 stay open. The four frozen digests are unchanged. `production_fusion_enabled` stays false.

## TASK-3 verification, 2026-10-27

The signed callback path, the 4-block case writer, the HMAC check, and the MTTR formula were already in the tree. The default launcher did not complete that loop. This change binds verify-state and the callback to the approval ledger and adds `test_http_dispatch_records_four_block_case_hmac_and_ledger_mttr`.

## TASK-4 verification on 2026-10-27

Ingest and replay call `IncidentCorrelationEngine`. A gap of 30.0 seconds stays in the burst window and 30.001 seconds falls through to the campaign window. A gap of 600.0 seconds stays in the campaign window and 600.001 seconds does not stitch. `POST /attributes/restSearch` returns HTTP 422 for RFC1918, IPv6 ULA, loopback, and link-local addresses before the local indicator table.

The integrated checkout gates are recorded in the section below after this branch is measured. TF-008, TF-009, TF-010, and TF-011 stay open. The four frozen digests are unchanged. `production_fusion_enabled` stays false.
