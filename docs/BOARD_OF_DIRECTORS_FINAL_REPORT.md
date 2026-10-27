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

Acknowledge, Escalate, and Dismiss each append a triage row and store the latest state on that flow. The campaign card and the drawer show the stored state after the queue reloads. Export Shift Handoff builds the four blocks from the stored row, includes those triage events in the shift-handoff timeline, and calls `verify_explanation_groundedness()`. Block 3 stays `unavailable` because no technique is stored on the flow. A shift note that names an address outside the stored entity ids is refused and is not copied into the report. The page shows and downloads the markdown only after that check passes. Containment stays unauthorized.

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
6. Choose Stitch verified windows after two Attack rows share a verified entity key inside 30 seconds. The timeline lists both members.
7. Choose Check private IP guard. The status line reports HTTP 422 for `10.0.0.4`.
8. Choose Acknowledge, Escalate, or Dismiss on a stored flow. The card keeps the stored triage state after the queue reloads.
9. Optionally type a shift note, then choose Export Shift Handoff / 4-Block Incident Report. The four-block markdown is shown and downloaded only when the note stays inside the stored evidence. A note that names an address that is not stored is refused.

Stop the process when the walkthrough is finished. The launcher binds only to `127.0.0.1`.

## Gates for this slice

On 2026-10-27 the full pytest suite was run from this repository with `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/pytest -q --tb=line`. The first run finished in about 314 seconds and failed one test: `backend/tests/unit/test_alert_persistence.py::test_corruption_is_not_replaced_and_errors_are_sanitized`. Opening a non-SQLite file ran `PRAGMA journal_mode=WAL` before the integrity check, and SQLite's `file is not a database` was labeled `database_unavailable`. The alert repository now labels that message `database_corrupt` and still leaves the damaged bytes in place. The persistence file then passed 19 tests. The full suite was run again and passed 1,527 tests in about 312 seconds, with exit code 0.

`git diff --check`, boundary preflight B0–B6, and the repository-truth audit (7/7) are the commit gates for this report. TF-008, TF-009, TF-010, and TF-011 stay open. The four frozen digests are unchanged. `production_fusion_enabled` stays false.

## TASK-5 evidence

On 2026-10-27 this checkout recorded the triage and handoff slice above.

- `backend/tests/unit/test_live_soc_console.py` passed 12 tests. Acknowledge, escalate, and dismiss each write a `triage_events` row. The handoff timeline includes those rows. `POST /api/v1/live/triage` and `POST /api/v1/live/handoff` do the same through the contract server. A note naming `203.0.113.99` is refused with `explanation_not_grounded` and is not copied into the markdown. Block 3 stays `unavailable`.
- A local contract server on `127.0.0.1` served the page with the four controls and the shift-note box. Ingest of a 14-feature vector stayed `production_fusion_enabled` false. Acknowledge stored `acknowledged`. The same foreign address was refused on the handoff route. The buttons were not clicked in a graphical browser.
- `git diff --check` was clean.
- `scripts/boundary_preflight.py --venv threatfusion-venv` is NO-GO only on B1 and B6, because the process cwd is `/workspace` and the package file is `/workspace/backend/src/threatfusion/__init__.py`, while the default active root is `/home/muhammad-bilal/projects/threatfusion-gemini`. The same command with `--active /workspace` is GO for B0–B6.
- `scripts/audit_repo_truth.py` is 6/7. Check 1 fails only on that checkout path. Checks 2–7 pass, including the four frozen digests, Section 8 (`production_fusion_enabled` false), Gate G9, and TF-008 through TF-011 still open.
- The full pytest run collected 1,529 tests: 1,502 passed, 20 failed, 7 skipped. The 20 failures are missing UNSW registration (`unsw_registration_invalid`), missing `certutil` (`nss_tool_failed` and the registered browser path), and the same checkout-path checks. No other failure appeared.
