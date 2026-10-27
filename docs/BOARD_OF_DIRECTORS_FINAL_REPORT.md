# ThreatFusion board report

**Date:** 2026-10-27
**Branch:** `cursor/live-analyst-console-211f`, rebased onto `gemini/product-20260924` at `fb58caf`
**Status:** bounded lab product with a live local console. Not a deployed enterprise SOC.

## What an analyst can do today

On `http://127.0.0.1` the SOC page has a live panel next to the sample walkthrough.

- Ingest sends 14 canonical features to `POST /api/v1/live/ingest`.
- The frozen Random Forest scores that vector only when its file verifies and its input width is 14.
- Analyst notes are stored in a local WAL SQLite file.
- The MITRE question box queries the local corpus. A containment question is refused.
- Drift reads stored rows and does not change model weights.
- The workbench lists the 6 n8n nodes and does not dispatch a playbook.

The campaign queue reads stored flows. Replay scores the five recorded UNSW-NB15 study vectors with the frozen Random Forest and does not copy the printed study probability. Approve writes a hash-chained local approval and returns the 64-hex receipt. It does not execute containment, and it does not invent a TheHive case or an n8n signature. Sample incidents remain only when the campaign request cannot be reached.

A separate loopback ledger, `POST /api/v1/ingest/unsw-raw`, scores a 49-column string row only through `UnswNetworkInferenceBoundary`. `POST /api/v1/ingest/suricata-eve` stores adapted features and leaves `rf_decision` null. The v2 autoencoder reconstruction error stays withheld. A body that sets `production_fusion_enabled` true is rejected before a write. The listener accepts `127.0.0.1` or `::1` only.

## Frozen model digests in this checkout

SHA-256 of the four tracked artifacts, computed on 2026-10-27:

| Artifact | Digest |
|---|---|
| `random_forest.joblib` | `bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9` |
| `logistic_regression.joblib` | `2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148` |
| v2 `autoencoder_state.pt` | `c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23` |
| rate-log1p `autoencoder_state.pt` | `1d02e5bba556cb28709bd0faefce5f29da424a419a2d95332ad27a8995b26f63` |

These match the frozen reference digests. The files were not rewritten.

The registered 49-column path also needs `data/raw/unsw_nb15/official/NUSW-NB15_features.csv` and `data/processed/unsw_network_preprocessing/full-train-only-0141bde-v1`. Those files are not in this checkout. Until they are present, `POST /api/v1/ingest/unsw-raw` stores no probability and no Attack/Normal decision.

## What is not claimed

- TF-008, TF-009, TF-010, and TF-011 remain open.
- There is no live enterprise SIEM feed, no 10-person analyst study, and no signed jury rubric.
- The autoencoder does not decide alerts.
- The four frozen model digests are unchanged.
- Private addresses are not sent to a public reputation service by this panel.

## Gates for this slice

Whitespace, unit tests, boundary preflight, and the repository-truth audit are recorded after the rebase in the verification note below. The full 1,500-test suite was not run for the owner console commits. This rebase does not weaken those gates.

## Verification note

Gate counts for this rebased checkout are written in the follow-up revision after `pytest backend/tests/unit`, `scripts/boundary_preflight.py`, `scripts/audit_repo_truth.py`, and `git diff --check` finish. This section does not invent a GO verdict.
