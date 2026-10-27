# ThreatFusion

ThreatFusion is a local analyst console for recorded network flows. A frozen Random Forest decides whether a flow is an attack. A person approves any response. The autoencoder does not change that decision.

This repository is a bounded lab prototype. It is not a deployed enterprise SOC, and it does not claim a live SIEM, a finished human study, or a signed jury rubric.

## Architecture

```text
Recorded flow or Suricata record
  -> strict feature check
  -> frozen Random Forest (sole alert authority)
  -> SQLite campaign queue
  -> dual-window grouping only with a verified entity key
  -> local MITRE answer and private-IP refusal
  -> analyst triage and grounded brief
  -> hash-chained approval
  -> signed verify-state and callback
```

The browser page and the MISP / SOAR contract endpoints are one process, started by `scripts/run_live_product.sh`.

## Section 8

Adding the v2 autoencoder to the Random Forest finds 96 more attacks on the inspected January split. That is a +2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045). Those 96 attacks add 1,574 false alarms, about 16.4 false alarms per extra attack. `production_fusion_enabled` stays false. The four frozen model digests stay unchanged.

## Quickstart

```bash
scripts/run_live_product.sh
```

The listener binds to `127.0.0.1` on port `8766` unless `PORT` is set. Open the page from that listener. Replay scores the recorded study vectors. Approve writes the hash chain. Dispatch sends verify-state and the HMAC callback. A private address such as `10.0.0.4` is refused before any external lookup.

The script's HMAC and MISP values are lab defaults. Replace them before any shared deployment. Host containment stays unauthorized.

## Still open

TF-008, TF-009, TF-010, and TF-011 remain open. Scores on unseen traffic, a human cohort of at least 10, a signed jury form, and a live feed are not done.
