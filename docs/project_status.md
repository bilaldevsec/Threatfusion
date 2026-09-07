# ThreatFusion current project status

## Snapshot

Status date: 2026-09-08. Branch: `main`. Latest commit:
`f49e7de5b64f274bc080d6fb9e93e43bc8689790` (`Add frozen CIC external evaluation and audit
findings`). At the start of this requirements milestone the index was empty and the working tree was
dirty only because [`network_feature_comparability_audit.md`](network_feature_comparability_audit.md)
was untracked. This milestone adds `AGENTS.md`, this file, [`product_charter.md`](product_charter.md),
and [`issue_register.md`](issue_register.md) as documentation-only untracked files. Nothing is staged.

Repository evidence takes precedence over older phase summaries. In particular, the aggregate Phase 0
readiness report still says split assignments are missing, but the later completed full assignment and
preprocessing artifacts supersede that one blocker. The report itself remains historical and must not be
rewritten. Global training/product readiness still does not pass because host training evidence and
integrated product acceptance are absent.

## Implemented and verified

- Manifest-backed readers, strict adapters, bounded validation/profiling, sanitized reports, checksum
  verification, and ignore rules exist for the registered UNSW, CIC, Mordor, and `synthetic_lab` roles.
- A completed full UNSW assignment covers every registered row once. It produced 865,480 TRAIN,
  216,568 VALIDATION, and 1,452,844 February TEST records, plus 5,145 quarantine and 10 rejected
  records. Group/split verification completed; capture provenance and near duplicates remain limitations.
- TRAIN-only preprocessing produced the frozen 14-column output (ten numeric z-scores plus four fixed
  protocol indicators), with 865,480 TRAIN and 216,568 VALIDATION rows. Integrity, finite values,
  assignment reconciliation, TRAIN-only fitting, and state reload were verified.
- Frozen logistic-regression and Random Forest baselines were trained on the full TRAIN matrix and
  evaluated on the same VALIDATION matrix. Their saved artifacts, model/preprocessor binding, metric
  definitions, resource controls, and reload behavior are documented and tested.
- Both saved models were evaluated without refitting on February UNSW and the two registered CIC
  exports. The targeted CIC audit verified the inspected prediction path, hashes, feature order,
  probability mapping, single scaling, rejection alignment, bounded replay, and confusion arithmetic.

## Implemented with limitations

- `network_behavior_v1` is valid as the frozen input order for the historical UNSW models, but its
  cross-source byte mapping is not a validated common measurement contract. Five byte-dependent CIC
  predictors have incompatible documented semantics; direction/flow policy remains uncertain. See
  [`network_feature_comparability_audit.md`](network_feature_comparability_audit.md) and TF-001.
- CIC metrics are preserved historical research evidence, not proof of compatible external transfer or
  operational usefulness. February and CIC outcomes are known and must be disclosed in future work.
- Host-event schemas, Mordor ingestion/validation, `host_behavior_v1`, and the synthetic fixture exercise
  pipeline behavior only. Mordor is attack/test-only; `synthetic_lab` is not representative training data.
- Feature collisions/conflicting labels are documented. Near-duplicate leakage, capture/session
  provenance, possible CIC row caps, CIC timezone, and historical extractor configuration remain open.

## Blocked

- Host-model training and host scientific claims are blocked by missing representative benign-host data.
- Global training readiness remains false even though the authorized network baselines completed.
- Deep-learning work remains paused pending a feature-comparability remediation decision.
- New claims of independent February/CIC evaluation are blocked because those outcomes are known.
- Cross-source compatibility approval is blocked by TF-001 and TF-003.

## Not yet implemented

- A supported end-to-end product path connecting ingestion, validation, inference, alert persistence,
  deduplication/correlation, explanation, and dashboard display.
- Product API/view-model contracts, dashboard behavior, persistence/restart recovery, optional-service
  degradation, and integrated resource/latency evidence.
- Approval-gated allowlisted containment with audit and rollback. No automatic containment is supported.
- A verified jury requirements reference, confirmed target-user/environment decision, operational
  acceptance targets, manual-workflow baseline, or representative-user usefulness study.

## One next implementation task

Implement a **cross-source compatibility gate** that prevents unverified compatibility from being
represented as approved in the affected contract/evaluation path. Likely scope is a small
machine-readable disposition beside `network_behavior_v1`, CIC evaluation verification/report fields,
focused unit tests, and updates to the feature/evaluation documentation. Preserve UNSW-NB15, both saved
model families, historical artifacts, scores, and hashes; do not retrain or reinterpret old metrics.

Acceptance tests must prove that:

1. the five known byte-dependent UNSW/CIC mappings cannot be marked equivalent;
2. conditional direction/duration mappings remain explicitly unresolved;
3. a new CIC result cannot claim approved compatible external evaluation or silently pass the gate;
4. the same-source UNSW inference path and exact feature/model order remain unchanged;
5. historical reports remain readable and retain their original provenance and exposure notices; and
6. malformed/missing compatibility evidence fails closed with sanitized errors.

This task should precede an integrated vertical slice. It does not authorize or automatically launch a
same-PCAP extraction study, model training, or another benchmark evaluation.
