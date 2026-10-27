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

Stitch runs `IncidentCorrelationEngine` on stored Attack rows. Two rows that share a verified entity key inside the 30-second burst window become one incident, and the drawer shows the unified timeline. Rows without that key stay singletons. Benign rows are not members. The private-IP check returns HTTP 422 for `10.0.0.4` and does not send that address anywhere.

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
6. Choose Stitch verified windows after two Attack rows share a verified entity key inside 30 seconds. The timeline lists both members.
7. Choose Check private IP guard. The status line reports HTTP 422 for `10.0.0.4`.
8. Choose Acknowledge, Escalate, or Dismiss. The triage state is stored on that flow.
9. Choose Export Shift Handoff / 4-Block Incident Report. The packet is returned only when the brief is grounded.

Stop the process when the walkthrough is finished. The launcher binds only to `127.0.0.1`.

## Gates for this slice

On 2026-10-27 the full pytest suite was run from this repository with `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/pytest -q --tb=line`. The first run finished in about 314 seconds and failed one test: `backend/tests/unit/test_alert_persistence.py::test_corruption_is_not_replaced_and_errors_are_sanitized`. Opening a non-SQLite file ran `PRAGMA journal_mode=WAL` before the integrity check, and SQLite's `file is not a database` was labeled `database_unavailable`. The alert repository now labels that message `database_corrupt` and still leaves the damaged bytes in place. The persistence file then passed 19 tests. The full suite was run again and passed 1,527 tests in about 312 seconds, with exit code 0.

`git diff --check`, boundary preflight B0–B6, and the repository-truth audit (7/7) are the commit gates for this report. TF-008, TF-009, TF-010, and TF-011 stay open. The four frozen digests are unchanged. `production_fusion_enabled` stays false.

## TASK-3 verification, 2026-10-27

The signed callback path, the 4-block case writer, the HMAC check, and the MTTR formula were already in the tree. The default launcher did not complete that loop. This change binds verify-state and the callback to the approval ledger and adds `test_http_dispatch_records_four_block_case_hmac_and_ledger_mttr`.

On this checkout the four frozen digests still match:

- Random Forest `bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9`
- Logistic Regression `2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148`
- Autoencoder v2 `c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23`
- Rate-log1p candidate `1d02e5bba556cb28709bd0faefce5f29da424a419a2d95332ad27a8995b26f63`

`git diff --check` passed. The backlog command `scripts/boundary_preflight.py --venv threatfusion-venv --json` was NO-GO: B1 and B6 fail because the current directory and `threatfusion.__file__` are under `/workspace`, while the default active root is `/home/muhammad-bilal/projects/threatfusion-gemini`. The same B0–B6 checks with `--active /workspace` were GO. `scripts/audit_repo_truth.py` was NO-GO, 6 of 7 checks passed. Check 1 failed only on `Workspace path mismatch: /workspace != /home/muhammad-bilal/projects/threatfusion-gemini`. Checks 2–7 passed, including the four digests above, Section 8 (`production_fusion_enabled` stays false and `True` raises `ValueError`), Gate G9, and TF-008 through TF-011 still open.

`env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/pytest -q --tb=line backend/tests` collected 1,528 tests: 1,501 passed, 20 failed, 7 skipped, exit code 1. The new dispatch test passed. The 20 failures are environment gaps on this checkout, not a change to the frozen models:

- `test_live_repository_truth_audit_passes`, `test_cli_runner_script_execution`, and `test_repo_truth_audit_controlled_valid_fixture_and_scientific_disclosures` fail because check 1 requires the canonical workspace path. The live audit test also asserts `git_branch == gemini/product-20260924`, which this review branch is not.
- `test_live_boundary_preflight_passes` and `test_b6_passes_when_pythonpath_is_unset` fail with the same B1/B6 path findings.
- `test_full_soc_demo_runner_end_to_end`, `test_full_soc_demo_incorporates_chromadb_misp_thehive_n8n`, `test_run_full_soc_demo_incorporates_soar_chain_queue_ranker_and_drift`, `test_milestone23_complete_product_spine`, both Slide 14 spine tests, and `test_one_registered_attack_reaches_authenticated_browser_and_degrades_cleanly` raise `unsw_registration_invalid`. `NUSW-NB15_features.csv` and `data/processed/unsw_network_preprocessing/full-train-only-0141bde-v1` are not in this checkout. Registration fails before inference.
- Eight Firefox provisioning tests raise `nss_tool_failed`. `certutil` is not installed here.

A headless Chrome check on `http://127.0.0.1:8766` replayed the five recorded vectors. The frozen Random Forest scored the selected row Attack at 54.33% with digest `bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9`. Dispatch then showed case `case_live_flow_3_d1123e`, HMAC prefix `6b3b206692109890`, and MTTR `0.132s`. The status line said host containment was not executed. Block 3 stayed `unavailable` because no technique was retrieved. This is one local browser check, not a user study, and it does not close TF-008, TF-009, TF-010, or TF-011.
