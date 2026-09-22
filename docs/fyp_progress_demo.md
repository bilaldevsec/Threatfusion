# FYP-II progress-evaluation demonstration

## Purpose and claim boundary

This is a repeatable 5–7 minute demonstration of the implemented ThreatFusion registered-offline
producer path. It replays two deliberately selected records from the registered UNSW-NB15 snapshot
through a real IPv4 loopback TLS 1.3 mutual-TLS connection, the existing admission/rate/concurrency
gates, replay journal, security audit, terminating spawned-worker Random Forest inference boundary, and
parent-owned Attack-only alert repository.

It is **recorded UNSW replay**, not live traffic, an accuracy test, production serving, or proof of
operational usefulness. Rows 1 and 21 of registered member
`7d851bbeabd27894ce39c8e78835c73341fc946652fb7743b9eff193b55eb511` are frozen demonstration
examples because the real Random Forest produces one Normal and one Attack outcome. Their known dataset
labels are shown separately and would be preserved if a later model result disagreed.

The final section independently verifies and scores the same two compatible records with the saved v2
autoencoder. That result is experimental research evidence only. The v2 identity is not added to the
product-approved registry, is not part of the producer workflow, and is not fused with the Random
Forest result.

## Prerequisites

- Linux with IPv4 loopback binding permitted and no external/public listener requirement.
- Repository checkout with the project Python 3.11 `.venv` already synchronized from the lock file.
- `openssl` available on `PATH`; it issues one-use credentials inside a mode-`0700` temporary directory.
- Registered UNSW manifest, feature metadata, and `UNSW-NB15_1.csv` at their configured ignored paths.
- The unchanged frozen preprocessing, logistic-regression, Random Forest, historical autoencoder, and
  corrected v2 autoencoder artifacts at their documented ignored paths.
- Run from the repository root. No internet access, package download, training, calibration, or
  persistent service is needed.

## Single launch command

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/run_fyp_progress_demo.py
```

The runner exits zero only after all demonstration assertions and cleanup checks pass. It replaces the
last successful sanitized evidence file at
`artifacts/reports/fyp_progress_demo/latest/evidence.json`. That directory is ignored. It never writes
credentials, private keys, raw records, endpoints, or runtime databases into the evidence report.

## What the evaluator sees

1. A PASS heading, the exact Git revision, and confirmation of real loopback TLS 1.3 with mutual TLS.
2. Two selected registered records with the known label beside the actual frozen Random Forest class,
   attack probability, and alert disposition. The current frozen results are:
   - row 1: known Normal, predicted Normal, probability `0.000012665262`, not actionable;
   - row 21: known Attack, predicted Attack, probability `0.824988317192`, one AlertCandidate created.
3. An identical retry with byte-identical wire and cached response bytes. Inference calls remain `2 ->
   2`, alert insertion calls remain `1 -> 1`, and the alert count remains `1 -> 1`.
4. A separate authenticated invalid application request with a producer-ID mismatch receiving HTTP 400
   `request_rejected`. Inference calls, insertion calls, and alert count remain unchanged.
5. A separate experimental v2 autoencoder section showing identity
   `bdb7fc33d5b092566995018b5f83aa66bdb8ce95841d6b8b9021111c9a392a9a`, calibrated threshold
   `0.1181361214680695`, each reconstruction score, the strict `score > threshold` result, and known
   label. The current scores are `0.000353499239` (row 1, not anomalous) and `0.546426254102` (row 21,
   anomalous).
6. Confirmation that inference workers and request threads joined, the listener closed, leases were
   released, SQLite sidecars were absent, and the temporary credential/database directory was removed.

## Suggested 5–7 minute speaking sequence

1. **0:00–0:45 — Scope.** State that this is registered recorded UNSW replay, not live capture or an
   accuracy evaluation. Point out the intentionally illustrative two-row selection.
2. **0:45–1:30 — Integrity and transport.** Launch the single command. Explain that the runner verifies
   frozen model/preprocessor/manifest identities and uses one-use mTLS credentials on `127.0.0.1` only.
3. **1:30–3:00 — Random Forest path.** Read the two known labels and actual predictions. Show that only
   the Attack prediction creates one durable AlertCandidate.
4. **3:00–4:00 — Replay and rejection.** Show byte-identical cached replay and unchanged call/count
   values, then the authenticated invalid request rejected with no downstream effect. Mention that the
   unchanged frozen burst-two rate rule legitimately covers the initial request and its retry; malformed
   admission is rejected before rate charging.
5. **4:00–5:15 — Experimental autoencoder.** Show scores, threshold, and strict decisions. Explicitly
   say it is verified experimental evidence, outside the product registry, separate from alerts, and not
   fused.
6. **5:15–6:00 — Cleanup and limitations.** Point to the cleanup line and ignored evidence report. State
   the remaining worker/service, dashboard, live-source, correlation, and operational-evidence gaps.

## Recovery if live loopback execution fails

1. Do not call the failed attempt successful and do not replace it with a live-traffic claim. Read the
   sanitized one-line failure reason.
2. Confirm no runner remains and no unexpected listener is active, then verify that local policy permits
   an ephemeral bind to IPv4 `127.0.0.1`. Do not use a wildcard, external address, proxy, or weakened TLS.
3. Confirm `.venv`, `openssl`, registered UNSW files, and ignored frozen artifacts are available, then
   rerun the same command once. Do not reset gates, edit evidence, or bypass validation.
4. If the rerun cannot be completed, present the saved ignored evidence only as prior rehearsal evidence,
   including its revision and `status`. Explicitly state that it is a fallback transcript and not a live
   successful run.

## Limitations

The synchronous one-request orchestrator now uses one terminating worker per newly claimed request, but
still has no serving loop or long-running service/resource evidence. This demo does not add dashboard,
correlation, explanation, analyst workflow, backup/recovery, audit export/rotation, live-source identity,
Azure, cross-source compatibility, LLM, SOAR, or containment. Its chosen records cannot measure
accuracy, false-positive rate, throughput, user value, generalization, or readiness. February/CIC
outcomes remain development-known, TF-006/TF-007 remain scientific limitations, and TF-008/TF-009
remain open for their broader product and reliability acceptance requirements.
