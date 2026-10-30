# ThreatFusion board report

**Date:** 2026-10-30
**Branch:** `gemini/product-20260924`
**Status:** bounded lab product with one live local console. Not a deployed enterprise SOC.

## What the console does

`scripts/run_live_product.sh` starts the page and the contract routes as one process on `127.0.0.1:8766`. `--dry-run` prints the plan and does not bind. `--smoke` requires HTTP 200 from `GET /` and `GET /healthz`, then stops and checks that the port is free. `--seed-demo` stores the four labeled scenarios and keeps serving. Ctrl-C and `SIGTERM` stop the child. The lab HMAC and MISP values are not production credentials.

The inspector follows the stored flow. The sample topology and the 5-minute walkthrough stay in the page and are hidden once the campaign store loads. They return only when that request fails.

On 2026-10-30 a browser session at `http://127.0.0.1:8766` did the following:

- Replay of the five recorded UNSW-NB15 study vectors scored four Benign and one Attack at 54.3%. Approve wrote playbook `soar:a11fab108999`. Dispatch recorded HMAC prefix `7f6698f18c054126`, case `case_live_flow_3_a46929`, and MTTR `8.875s`. Host containment was not executed.
- Acknowledge stored triage state `acknowledged` for flow 3. The handoff was grounded and listed that event. Block 3 stayed `unavailable`.
- Check private IP guard reported that `10.0.0.4` was refused before any external lookup.
- Replay four scenarios reported `web_exploit T1190: Attack 54.3%`, `ssh_brute T1110: Attack 54.3%`, `internal_recon T1046: Attack 54.3%, private IP refused HTTP 422`, and `benign_false_alarm: Benign 29.1%`. The technique id is a scenario label. The frozen Random Forest supplied the decision.
- Run constitutional health reported checks 1–7 PASS, boundary GO, truth GO, and the four digest prefixes `bd2853a6f9d7f650`, `2cf4de6686d937c4`, `c8675d13869308ba`, and `1d02e5bba556cb28`.

The earlier 2026-10-27 browser check of the five-vector replay showed playbook `soar:dcb1e6213c6b` and receipt prefix `be30bcf02a8cf50e`. That was a different stored row.

## Product path

- Ingest and replay score the canonical 14 features with the frozen Random Forest only when the artifact verifies and its input width is 14. `production_fusion_enabled` stays false. The autoencoder does not decide.
- Approval, verify-state, and the HMAC callback share one ledger. A failed timing write returns HTTP 403 `callback_timing_not_recorded`. A second dispatch returns the same receipt.
- Ingest and replay call `IncidentCorrelationEngine`. The burst window is 30.0 seconds and the campaign window is 600.0 seconds, boundaries included. Rows without a verified entity key stay singletons. Benign rows are not members.
- The MISP route returns HTTP 422 for RFC1918, IPv6 ULA, loopback, and link-local addresses before any indicator match. Documentation ranges `198.51.100.0/24` and `203.0.113.0/24` are not treated as RFC1918.
- Acknowledge, escalate, and dismiss append `triage_events`. The handoff calls `verify_explanation_groundedness()`. A note that names an address outside the stored flow is refused.
- The console states that UNSW-NB15 and CIC byte layers are not interchangeable and that CIC is not a validated compatible external test.

Section 8 stays: `+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)`. Fusion stays off because those 96 true positives cost 1,574 extra false positives.

## What is not claimed

- TF-008, TF-009, TF-010, and TF-011 remain open.
- TF-012 and TF-002 remain open. The live sentence does not prove five-field byte equivalence, and it does not cover every historical export.
- There is no live enterprise SIEM feed, no 10-person analyst study, and no signed jury rubric.
- The four frozen model digests are unchanged.
- The host firewall is not changed. A drop of `172.29.0.10` runs only inside the victim container, and only after an approved hash chain and a verified callback. Approve and dispatch still report `containment_executed: false`.

## Measured lab path, 2026-10-30

- An approved dispatch through the running n8n container returned `execution_path=n8n_live_container`, a 64-character HMAC, `mttr_seconds=0.052761`, `private_ip_guard_triggered=true` for `172.29.0.10`, and `containment_executed=false`. An unapproved dispatch returned `playbook_not_approved` and recorded no callback.
- `analyst_a` stays `unverified_local_label`. `operator_id`, `cert_sha256_prefix`, and `identity_verified: true` are stored only for an enrolled, enabled, unrevoked certificate such as `lab_operator`.
- Inside the victim namespace, `curl` from `172.29.0.10` to `172.29.0.20` returned `range-victim` before the drop, timed out with curl exit 28 after the drop, and returned `range-victim` after rollback. With the range stopped, the same request returned `range_not_running` and `containment_executed: false`.

## Five-minute jury sequence

1. Run `scripts/run_full_range_demo.sh --up` and open `http://127.0.0.1:8766/`.
2. Run `--scan`. Read the Suricata line and the frozen forest score as two separate facts.
3. Enroll `lab_operator`. Leave a typed `analyst_a` label unverified.
4. Approve one bridge row and dispatch it. The path label is `n8n_live_container`. The private address `172.29.0.10` is refused with HTTP 422 and the signed callback is still recorded.
5. Drop `172.29.0.10` in the victim container, show curl failing, roll the rule back, and show curl succeeding. Then run `--down`.

## Azure checklist, not started

This work spent $0 and created no Azure resources. A later rehearsal, if the board asks for one, is one small Linux VM, deallocated after that rehearsal, and started again only on defense day. Keep the VM off between those two windows so the spend stays inside a $60 cap. Do not leave it running.

## Walkthrough

1. Run `scripts/run_live_product.sh --seed-demo`.
2. Open `http://127.0.0.1:8766`.
3. Read the four scenario rows and the source-qualification sentence.
4. Approve an Attack row, then Dispatch signed callback.
5. Choose Stitch verified windows and Check private IP guard.
6. Acknowledge the row and export the shift handoff.
7. Choose Run constitutional health and read the seven checks and the digest prefixes.
8. Stop the process with Ctrl-C.

## Gates

On 2026-10-27 the full pytest suite passed 1,527 tests after a damaged alert database was classified as `database_corrupt`. On 2026-10-30 each slice in this report passed `git diff --check`, boundary preflight B0–B6, and the repository-truth audit 7/7 before it was pushed. The focused live-console, scenario, health, qualification, and seed-demo tests passed. The full suite was not run again on 2026-10-30.

The four digests checked by the live drawer and by audit check 2 are unchanged: Random Forest `bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9`, Logistic Regression `2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148`, Autoencoder v2 `c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23`, Rate-log1p candidate `1d02e5bba556cb28709bd0faefce5f29da424a419a2d95332ad27a8995b26f63`.
