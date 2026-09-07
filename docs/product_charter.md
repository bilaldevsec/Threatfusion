# ThreatFusion product charter

## Authority and purpose

This charter defines persistent product acceptance requirements. Repository-wide working rules are in
[`AGENTS.md`](../AGENTS.md), current evidence is in [`project_status.md`](project_status.md), and
prioritized gaps are in [`issue_register.md`](issue_register.md). Phase and experiment documents remain
the detailed evidence records; this charter does not overwrite their provenance or results.

ThreatFusion is intended to become a reliable, integrated, demo-ready SOC triage prototype with
evidence that it helps its intended users. It is not currently production-ready, and neither market fit
nor user value has been established.

## A. Scope

The product scope is a reproducible, single-node SOC triage prototype. Its provisional target operator
is a Tier-1 SOC analyst, or a technical reviewer acting in that role, who receives security telemetry,
reviews prioritized alerts and supporting evidence, decides whether to close or escalate, and may
request a separately approved containment action. This target-user choice requires confirmation with
the project owner and representative users or reviewers.

The provisional demonstration environment is one Linux workstation or laptop using the repository's
locked Python 3.11 environment, bounded memory/disk, local persistence, and a local dashboard. The core
workflow must remain demonstrable when optional network services, hosted LLMs, and other external
services are unavailable. Exact supported hardware, browser, retention, throughput, and deployment
requirements remain to be measured and frozen; a successful research runner is not a product demo.

## B. Jury constraints

| Constraint | Repository evidence and disposition |
|---|---|
| UNSW-NB15 must remain | This is an explicit product requirement. Its registered reader, split, preprocessing, and evaluations are documented in [`network_training_split_design.md`](network_training_split_design.md), [`network_preprocessing.md`](network_preprocessing.md), and the baseline documents. It must not be silently replaced or removed. |
| Jury-approved datasets | No authoritative jury requirements file was found in the repository as of 2026-09-08. UNSW-NB15 is the only dataset explicitly confirmed by the current product instruction. CIC-IDS2018 is a registered external benchmark, Mordor is attack/test-only, and `synthetic_lab` is a fixture; those repository roles do not prove jury approval. The exact jury dataset list requires documentary verification. |
| Jury-approved model families | No repository document enumerates the exact approved list. Existing logistic-regression and Random Forest baselines are documented in [`network_logistic_baseline.md`](network_logistic_baseline.md) and [`network_random_forest_baseline.md`](network_random_forest_baseline.md) and must be preserved. They must not be asserted to be the complete jury list or silently substituted for an unverified family. |

A dated jury brief, rubric, signed requirement, or equivalent authoritative project record must be added
or referenced before the dataset/model list is called complete. New evidence may clarify the list but
must not rewrite historical experiments.

## C. End-to-end acceptance

The documented supported input must complete every stage below in one integrated workflow. These are
acceptance interfaces; a schema marked “to define” is not implemented merely because this table names
it.

| Stage | Required interface | Required failure behavior |
|---|---|---|
| Extraction/adaptation | A documented source reader yields validated canonical records with source/version provenance. The first supported demo source must be named explicitly. | Unsupported schema, malformed structure, or source-integrity failure is rejected with sanitized evidence; no invented fields. |
| Validation | A bounded stream produces reconciled accepted/rejected counts and a completion/integrity disposition. | Partial, corrupt, mismatched, or unexplained counts fail closed and cannot feed inference. |
| Versioned features | A canonical record plus contract version produces an exact ordered predictor vector and separately retained label/provenance. | Unknown or incompatible mappings, prohibited fields, non-finite values, feature-order changes, or state mismatches block the affected path. |
| Inference | A verified model/preprocessor bundle plus an ordered batch produces model identity, score, decision rule, and sanitized record provenance. | Missing/corrupt/mismatched artifacts or unsupported source compatibility produce an explicit unavailable/blocked result, never a guessed score. |
| Alert handling and correlation | A versioned `AlertCandidate` interface (to define) carries stable ingestion identity, source, model decision, evidence references, status, and deduplication key into a bounded correlation interface. | Duplicate ingestion is idempotent; conflicting identity, persistence failure, or correlation failure is visible and cannot silently lose or multiply alerts. |
| Explanation | A versioned explanation result (to define) binds claims to the alert, model, features, and evidence and distinguishes unavailable evidence from benign evidence. | Explanation failure does not alter the model decision. Unverified claims are omitted or marked uncertain. LLM output cannot execute actions. |
| Dashboard | A versioned API/view model (to define) displays queue state, severity/score context, evidence, explanation status, provenance, and analyst disposition. | Backend/optional-service failure is shown as a degraded or unavailable state with retry/recovery behavior; stale data is identified. |

Passing end-to-end acceptance requires a reproducible invocation and a test/demonstration showing that
one supported input reaches dashboard display with reconciled identity and status across all stages.
Individual CLIs, models, reports, or UI mockups do not establish integration.

Containment is outside the automatic core path. If added, it must use an explicit analyst approval,
action/target allowlists, authorization checks, immutable audit evidence, bounded execution, post-action
verification, and a tested rollback. An LLM may explain or propose an action but may never invoke it.

## D. Reliability evidence

Before calling the prototype demo-ready, automated tests and one bounded end-to-end demonstration must
cover:

- malformed, truncated, duplicated, and out-of-order input;
- model/preprocessor/source-contract and feature-order mismatches;
- unavailable optional services, including LLM and external network services;
- process restart, persistence recovery, interrupted batches, and replay;
- duplicate ingestion and idempotent alert/correlation handling;
- bounded RAM, disk, batch size, queue growth, timeouts, and sanitized error retention;
- safe degradation of explanation/dashboard features without changing detection evidence.

The documented core workflow must complete locally with external services unavailable. Report measured
latency, throughput, peak memory, disk use, rejection/error rate, and recovery results separately from
unverified goals. Operational false-positive, detection, latency, and capacity targets are product
decisions still to be made; do not invent them or convert benchmark metrics into operational targets.

## E. Scientific evidence

- Report source-specific development, later-period, and external results separately. Cross-source
  claims require verified measurement semantics and collection comparability.
- Never present an incompatible or unresolved feature mapping as a validated common contract. The
  current byte-semantics finding is detailed in
  [`network_feature_comparability_audit.md`](network_feature_comparability_audit.md).
- A benchmark whose labels or outcomes influenced feature, model, preprocessing, or threshold choices
  is development-informed, not independent evaluation. Preserve an uninspected source for subsequent
  independent evidence.
- Synthetic fixtures establish deterministic pipeline behavior only. They cannot establish real benign
  host suitability, operational usefulness, or real-world accuracy.
- Ordinary labeled attack benchmarks do not demonstrate zero-day detection. Do not make that claim
  without a predeclared zero-day definition and appropriate held-out evidence.
- Weak transfer does not prove domain shift or overfitting, and passing implementation checks does not
  prove source semantics are equivalent.

## F. User-value evidence

The intended provisional analyst workflow is: receive a prioritized queue item, inspect the model and
source evidence, review correlation and explanation, decide close/escalate, record rationale, and—only
when authorized—request containment. The comparison baseline must be the same analyst tasks using the
current manual tools/runbook without ThreatFusion; that baseline workflow has not yet been documented
with representative users.

Evaluation tasks should measure whether users can identify the alert needing attention, find supporting
evidence, explain the prioritization, make and revise a disposition, recognize unavailable/uncertain
evidence, and recover from a degraded service. Evidence still needed includes representative-user or
reviewer recruitment criteria, a consent-safe protocol, realistic non-sensitive cases, task completion
and error rates, elapsed time, decision consistency, and qualitative trust/usability feedback. No user
contact or validation is authorized by this charter, and none has occurred merely because these
requirements are documented.
