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

Dispatch sends an approved playbook to `POST /api/v1/soar/verify-state`, writes a 4-block TheHive case (queued offline when TheHive is down), then records the HMAC-SHA256 callback from `POST /api/v1/soar/callback`. The UI shows that callback's MTTR. A second dispatch returns the same 64-hex signature. Host containment stays unauthorized.

Stitch runs `IncidentCorrelationEngine` on stored Attack rows. Two rows that share a verified entity key inside the 30-second burst window become one incident, and the drawer shows the unified timeline. Rows without that key stay singletons. Benign rows are not members. The private-IP check returns HTTP 422 for `10.0.0.4` and does not send that address anywhere.

Acknowledge, Escalate, and Dismiss persist a triage row. Export Shift Handoff calls `verify_explanation_groundedness()` and keeps block 3 `unavailable` when no technique was retrieved. A brief that names an address outside the evidence bundle is not verified.

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
5. Choose Dispatch signed callback on an approved row. The status line shows the HMAC prefix, the callback MTTR, and that host containment was not executed. That call reaches verify-state only because the launcher set the shared ledger path.
6. Choose Stitch verified windows after two Attack rows share a verified entity key inside 30 seconds. The status line reports the incident count, the largest stitch, and the timeline event count. Ingest and replay do not stitch on their own on this branch.
7. Choose Check private IP guard. The client reports that `10.0.0.4` was refused before any external lookup when the response is HTTP 422.
8. Choose Acknowledge, Escalate, or Dismiss. The triage state is stored on that flow.
9. Choose Export Shift Handoff / 4-Block Incident Report. The packet is returned only when the brief is grounded.

Stop the process with Ctrl-C when the walkthrough is finished. The launcher binds only to `127.0.0.1` and shuts the child down on `SIGTERM` as well.

## Gates for this slice

On 2026-10-27 the full pytest suite was run from this repository with `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/pytest -q --tb=line`. The first run finished in about 314 seconds and failed one test: `backend/tests/unit/test_alert_persistence.py::test_corruption_is_not_replaced_and_errors_are_sanitized`. Opening a non-SQLite file ran `PRAGMA journal_mode=WAL` before the integrity check, and SQLite's `file is not a database` was labeled `database_unavailable`. The alert repository now labels that message `database_corrupt` and still leaves the damaged bytes in place. The persistence file then passed 19 tests. The full suite was run again and passed 1,527 tests in about 312 seconds, with exit code 0.

`git diff --check`, boundary preflight B0–B6, and the repository-truth audit (7/7) are the commit gates for this report. TF-008, TF-009, TF-010, and TF-011 stay open. The four frozen digests are unchanged. `production_fusion_enabled` stays false.
