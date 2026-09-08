# ThreatFusion current project status

## Snapshot

Status date: 2026-09-08. Branch: `main`. Latest commit:
`4bd0e5fbf729c7a1e35c30f127b84651ca8d2d5e` (`Record product reliability requirements and
compatibility issues`). The baseline was clean. The working tree now contains only the scoped
compatibility-gate source, test, documentation, and narrow CLI lint changes; nothing is staged.

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
- A typed compatibility decision now keys the actual input/fitted-source representations, contract
  version, and model/preprocessing requirements. Same-source verified UNSW use is supported; the
  registered CIC representation is rejected before transformation/inference or run artifact creation.
  Unknown and incomplete evidence fails closed. Historical completion remains separately readable.
- Repository-wide Ruff passes. Four direct-execution CLIs retain their intentional `backend/src`
  bootstrap with import-level `E402` suppressions matching the established script convention; their
  `--help` paths exit without starting data work or creating artifacts.

## Implemented with limitations

- `network_behavior_v1` is valid as the frozen input order for the historical UNSW models, but its
  cross-source byte mapping is not a validated common measurement contract. Five byte-dependent CIC
  predictors have incompatible documented semantics; direction/flow policy remains uncertain. See
  [`network_feature_comparability_audit.md`](network_feature_comparability_audit.md) and TF-012. The
  gate prevents unapproved use; it does not improve accuracy or establish compatible measurements.
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
- Cross-source compatibility approval is blocked by TF-012 and TF-003.

## Not yet implemented

- A supported end-to-end product path connecting ingestion, validation, inference, alert persistence,
  deduplication/correlation, explanation, and dashboard display.
- Product API/view-model contracts, dashboard behavior, persistence/restart recovery, optional-service
  degradation, and integrated resource/latency evidence.
- Approval-gated allowlisted containment with audit and rollback. No automatic containment is supported.
- A verified jury requirements reference, confirmed target-user/environment decision, operational
  acceptance targets, manual-workflow baseline, or representative-user usefulness study.

## One next implementation task

Implement an explicitly **UNSW-source-specific inference boundary** as the first integrated vertical
slice. It should accept only the verified UNSW Argus raw representation and existing frozen
preprocessor/model bundles, emit a versioned alert candidate with model/source provenance, and reject
CIC or unknown representations through the compatibility gate. Reuse current readers, validation,
projection, preprocessing, and model verification; do not retrain.

Acceptance tests should prove supported UNSW input reaches a bounded inference/alert interface with
stable identity and exact feature order; malformed input, duplicate ingestion, artifact mismatch, and
unsupported representation fail visibly and idempotently; no external service is required; and no
result claims production readiness or independent evaluation. This is source-specific operation, not
a substitute for resolving TF-012, and it does not authorize containment or deployment.
