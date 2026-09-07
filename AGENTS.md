# ThreatFusion repository instructions

These instructions apply to the entire repository. More specific instructions may add constraints but
must not weaken this file, the product charter, an explicit user instruction, or a safety requirement.

## Start and evidence discipline

- Before relevant product, data, model, integration, evaluation, or release work, read
  `docs/product_charter.md`, `docs/project_status.md`, and `docs/issue_register.md`.
- Treat current repository code, tracked documentation, verified manifests, and completed artifact
  evidence as authoritative over stale chat summaries. Reconcile contradictions explicitly.
- Identify every open known issue affected by the proposed work before extending a component.
- Resolve correctness, integrity, security, and demo-blocking defects before relying on the affected
  component. Do not build claims or integrations on a failed or unverified boundary.
- Keep uncertainty visible. Never turn a failed, missing, partial, stale, or inapplicable gate into a
  pass merely to advance a phase.

## Product and scientific constraints

- Preserve UNSW-NB15 and every documented jury-approved base-model family. Do not silently remove,
  replace, or substitute them.
- The repository currently lacks an authoritative document containing the exact complete
  jury-approved model list. Never invent that list. Preserve existing model families and require the
  supporting jury document before claiming completeness or approval.
- Reuse existing schemas, readers, validators, preprocessing, metrics, provenance checks, and runners.
  Prefer small shared helpers over disconnected runners or duplicated logic.
- Preserve historical experiments and immutable provenance. Disclose when validation, February UNSW,
  CIC, or any other test outcomes are already known and therefore development-informing.
- Do not claim cross-source compatibility, readiness, usefulness, user validation, or operational
  performance without the evidence required by `docs/product_charter.md`.
- Maintain `docs/project_status.md` and issue dispositions in `docs/issue_register.md` at each completed
  milestone. Never mark a limitation accepted without an explicit recorded decision.

## Data, artifacts, authorization, and safety

- Keep raw data, generated/interim/processed data, reports, matrices, predictions, and model artifacts
  ignored and unstaged. Commit only intentionally reviewable source, tests, configuration, and docs.
- Require explicit user authorization for dataset or package downloads, any fitting/training/refitting,
  commits, pushes, external deployment, external messages, or destructive operations.
- Preserve unrelated work and historical artifacts. Fail closed on integrity, provenance, contract,
  feature-order, model/preprocessor, or assignment mismatches.
- Keep containment approval-gated, allowlisted, audited, and reversible with a documented rollback.
  LLM output is advisory only and must never directly execute shell commands, API actions, or
  containment operations.
- When work stops, leave a concise resume handoff containing outcome, evidence, changed files, checks,
  blockers, and exactly one recommended next action.
