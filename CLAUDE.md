# ThreatFusion — AI Engineering Handoff and Continuity Contract

**Handoff date:** 2026-09-28  
**Project:** ThreatFusion — AI-driven SOC alert-triage / analyst-support platform  
**Primary local workspace known to the previous assistant:** `~/projects/threatfusion-gemini`  
**Last known working branch:** `gemini/product-20260924`  
**Owner:** Muhammad Bilal  
**Target:** A defensible, production-quality FYP prototype for a simulated/lab SOC environment. Engineering quality should be enterprise-grade, but never claim production deployment, production readiness, autonomous containment, zero-day detection, or scientific conclusions that have not been demonstrated.

---

## 0. READ THIS FIRST — THIS FILE IS A HANDOFF, NOT THE SOURCE OF TRUTH

This document transfers the project context from prior ChatGPT/Codex work to a new coding agent.

The repository may have changed **after this file was generated**, especially because Gemini/Antigravity may continue working on it before you are used. Therefore:

1. **Never reset the repository to a commit mentioned in this file.**
2. **Never assume the “last known commit” below is still HEAD.**
3. First inspect the live repository, current branch, worktree, recent commits, local instructions, project-status docs, and open issues.
4. The **live repository plus its current tracked documentation outrank this handoff**.
5. Preserve any valid work added after 2026-09-28. Reconcile it; do not erase it.
6. Do not speculate about code you have not opened.
7. Planned architecture is not the same thing as implemented architecture.
8. A passing test is evidence only for what that test actually proves.

### Authority order

When sources disagree, use this order:

1. Current code, tests, artifacts, and live `git` state.
2. Repository instructions such as `AGENTS.md` and any nested agent instruction files.
3. Current `docs/project_status.md`, `docs/issue_register.md`, contracts, and evidence documents.
4. Current experiment manifests, model metadata, dataset manifests, generated evidence, and test outputs.
5. This handoff file.
6. Old chats, old plans, proposal language, or aspirational architecture.

Do not silently “resolve” contradictions. Identify them and choose the interpretation backed by the strongest current evidence.

---

# 1. REQUIRED STARTUP BOOTSTRAP — DO THIS BEFORE EDITING

Start in the project repository and discover the truth.

```bash
cd "$HOME/projects/threatfusion-gemini"

pwd
git status --short --branch --untracked-files=all
git branch --show-current
git rev-parse HEAD
git log --oneline --decorate -20
git diff --stat
git diff --check
git diff --cached --stat
git remote -v

find .. -name AGENTS.md -o -name CLAUDE.md -o -name GEMINI.md 2>/dev/null
```

Then read, **if present**, in approximately this order:

```text
AGENTS.md
docs/product_charter.md
docs/project_status.md
docs/issue_register.md
docs/alert_correlation_analyst_state.md
docs/analyst_authentication_transport.md
docs/registered_browser_path.md
docs/fyp_progress_demo.md
docs/producer_admission_transport_policy.md
docs/network_classical_evaluation_protocol.md
docs/fyp_evidence_viewer.md
docs/ai_handoff_2026-09-24.md
GEMINI.md
MIGRATE_TO_ANTIGRAVITY.md
README.md
pyproject.toml
```

Also inspect relevant tests before modifying a subsystem. Use code search rather than guessing filenames.

Before the first edit, produce a concise internal/current-session state model containing:

- current branch and HEAD;
- whether the worktree is clean;
- untracked/staged/unstaged files;
- most recent coherent milestone;
- current open issue(s) being worked;
- what is verified implemented;
- what is only planned;
- what is experimentally demonstrated but not product-integrated;
- failing or skipped tests, if any;
- the next smallest defensible milestone.

If the repository state differs from this handoff, **the repository wins**.

---

# 2. PROJECT PURPOSE

ThreatFusion is intended to mitigate SOC alert fatigue by moving from raw security/network telemetry toward **traceable, prioritized, analyst-reviewable security evidence**.

The broad intended path is:

```text
Supported input / recorded telemetry
        ↓
Strict validation + source identity/provenance
        ↓
Bounded preprocessing / feature preparation
        ↓
Classical ML inference
        ↓
Optional anomaly / DL research signals
        ↓
Persisted alert candidates
        ↓
Evidence-backed correlation (only when relationship keys are defensible)
        ↓
Threat-intelligence enrichment (optional / provenance-aware)
        ↓
Explanation / triage narrative
        ↓
Analyst queue + detail + state workflow
        ↓
Optional case management / SOAR with human approval
        ↓
Evaluation: correctness, reliability, usability, and alert-fatigue impact
```

The implementation must remain **evidence-first**. Do not build impressive-looking layers on top of scientifically invalid assumptions.

---

# 3. IMPORTANT DISTINCTION: VERIFIED PRODUCT PATH VS FUTURE ARCHITECTURE

## 3.1 Verified/current product direction

The strongest verified product path from prior work is centered on:

- registered/known recorded UNSW-NB15 input;
- strict producer admission and identity binding;
- authenticated local TLS/mTLS transport;
- terminating/bounded inference worker behavior;
- a **frozen Random Forest** as the product inference path;
- attack-only alert persistence for the bounded demo path;
- replay/idempotency protections;
- analyst state and history persistence;
- human analyst authentication;
- read-only analyst queue/detail presentation;
- local browser-facing HTTPS/mTLS boundary;
- explicit error/degraded behavior;
- security-audit evidence;
- evidence and project-status documentation.

Treat this as the core to preserve unless the live repo shows a newer approved design.

## 3.2 Research / experimental work

The corrected v2 autoencoder is research evidence / a DL baseline. It is **not automatically a fused production signal**.

Any CNN/BiLSTM or other sequence model is conditional on defensible temporal/entity sequencing. Do **not** manufacture sequences from shuffled UNSW rows.

Other planned models/signals from earlier architecture documents may include Isolation Forest, UEBA, DNS/C2 features, DBSCAN/JA3-style experiments, Gradient Boosting, or other detectors. Their presence in plans does not prove implementation or product integration.

## 3.3 Intended later product capabilities

The wider product vision includes:

- bounded alert correlation;
- risk/prioritization;
- threat-intelligence enrichment;
- evidence-backed explanations;
- analyst case workflow;
- dashboard/API evolution;
- optional MISP;
- optional TheHive;
- optional n8n;
- optional Pi-hole containment in a safe lab;
- optional vector/RAG components such as ChromaDB;
- LLM-assisted root-cause/triage narrative;
- candidate response playbooks / Sigma content with validation and human review.

**Do not mark any of these complete merely because they appeared in a proposal or master plan.**

---

# 4. DATASET AND SCIENTIFIC-INTEGRITY RULES

These rules are critical.

## 4.1 Intended dataset roles

The project has discussed:

- **UNSW-NB15** — primary network-flow training/development source and current verified registered recorded-data path.
- **CSE-CIC-IDS2018 subset** — intended later-period / cross-source evaluation or complementary evidence, subject to semantic compatibility and provenance.
- **Mordor logs** — intended host/log-level complementary evidence, not automatically interchangeable with flow telemetry.
- Synthetic UEBA data may be used only as clearly labeled synthetic fallback/research evidence when real suitable user-behavior data is unavailable.

## 4.2 Never pretend heterogeneous datasets are interchangeable

CIC, UNSW, and Mordor differ in schemas, capture environments, semantics, labels, entities, and provenance. A model trained on one cannot simply be “tested” on another unless preprocessing, feature semantics, label mapping, source integrity, and non-overlap are defensibly established.

Do not claim:

- “CIC is just the test set for UNSW”;
- “Mordor is another network-flow dataset”;
- “cross-dataset generalization” without a frozen, compatible protocol;
- “independent evaluation” when outcomes were already inspected during development.

## 4.3 Outcome exposure

Prior work explicitly tracked evaluation-exposure risk. February/CIC outcomes have been known during development in at least some prior experiments. Preserve that limitation.

A future independent evaluation source/protocol must be frozen before inspection if the project wants a defensible independent-evaluation claim.

## 4.4 Entity / provenance discipline

Before correlation or sequence modeling, prove what constitutes the same entity/event/capture.

Do not infer a stable host or relationship key merely because columns look similar.

If capture provenance cannot prove that two alerts relate to the same underlying entity/session/incident, do not group them into an “incident” and do not use them to claim alert reduction.

## 4.5 Claims discipline

Always separate:

- ground-truth dataset label;
- model prediction;
- model score/confidence;
- anomaly score;
- policy risk score;
- analyst state;
- explanation;
- external threat-intel evidence.

Never merge these into one “truth” field.

---

# 5. LAST KNOWN PROJECT STATE — HISTORICAL ORIENTATION ONLY

**Do not reset to these commits. Inspect live Git first.**

Known historical checkpoints from the previous work include:

- `main` baseline referenced by project docs:  
  `8aa26ba250e4a63f95d90960ec87e224325b6d2f`
- A later Gemini branch contained a read-only browser boundary milestone around commit prefix `a3a0b53`.
- A later explanation milestone was referenced around commit `6b3f2c1`.
- Another clean checkpoint was referenced around `6d44a42`.
- The last terminal excerpt visible to ChatGPT before this handoff showed a local commit whose prefix began `a615...` with message:
  `docs: record UNSW entity provenance limits`
  touching:
  - `docs/alert_correlation_analyst_state.md`
  - `docs/issue_register.md`
  - `docs/project_status.md`

There may be commits after these. Use `git log`.

A push guard was previously present:

```text
no-push://requires-explicit-review
```

Preserve the no-push posture unless the user explicitly authorizes a push.

---

# 6. VERIFIED MILESTONES FROM PRIOR SESSIONS

The following were demonstrated in prior captured evidence. Re-verify against the live repo before relying on them.

## 6.1 Producer / admission path

Prior work established a bounded producer path with strict validation before inference/persistence, source-event identity binding, replay behavior, and TLS transport.

Expected safety property:

```text
invalid / unauthorized / mismatched request
        ↓
rejected before predictor and repository side effects
```

Do not weaken this ordering.

## 6.2 Random Forest inference

The Random Forest is the principal product inference path from the verified work.

Model identity and preprocessing should be pinned/frozen by artifacts and tests. Never silently retrain or substitute a model in a demo path.

## 6.3 Worker isolation / time limits

Prior project work introduced spawned worker-process isolation for preparation/prediction, with parent-enforced limits and cleanup evidence.

Do not regress to an uninterruptible synchronous predictor simply because it is easier.

## 6.4 Alert persistence

The bounded path persisted Attack alerts and preserved replay/idempotency semantics. Repository reopening was used in tests/evidence.

Do not change persistence semantics without reviewing replay, duplicate, restart, and state-history tests.

## 6.5 Analyst state

An analyst-state contract and persistence layer were built for alert state/history. Concurrency/version behavior, idempotent transition IDs, rollback/reopen behavior, and explicit state semantics have been important.

Read the current contract before touching this layer.

## 6.6 Analyst human authentication / TLS boundary

Prior work used human mTLS identity rather than trusting arbitrary HTTP headers.

Actor identity was intended to derive from the verified certificate SAN plus the internal credential registry.

Do not replace this with a spoofable `X-User` style header.

## 6.7 Read-only analyst dashboard/browser slice

A read-only analyst view was built for queue/detail behavior.

A distinct local browser-facing HTTPS/TLS listener (`AnalystBrowserTlsListener` in prior state) exposed queue/detail HTML while retaining the human-identity boundary.

Prior safety properties included:

- read-only behavior;
- invalid path → 404;
- auth/revocation failure → 401 without secret leakage;
- `Cache-Control: no-store`;
- restrictive CSP;
- bounded HTML response size;
- sanitized 503 on backend/internal view failures;
- security-audit evidence.

Do not assume write transitions are browser-safe unless current code proves a session/origin/CSRF design.

## 6.8 Registered one-input browser path

Prior captured evidence showed a registered UNSW member flowing through:

```text
registered UNSW input
→ producer TLS/orchestrator
→ frozen RF worker
→ persisted Attack alert
→ reopened repository
→ analyst view
→ authenticated browser TLS queue/detail
```

The evidence reconciled the same alert candidate identity, decision `Attack`, and analyst state `new` across layers.

A deliberately injected view failure returned a sanitized HTTP 503 and audit evidence without mutating alert state.

A focused adjacent suite in one captured run passed **198 tests**.

This was an automated real-TLS client path, not automatically a human-browser acceptance test.

## 6.9 Manual browser qualification

At one point the manual Firefox path was still not fully qualified. A later session encountered a Firefox/profile CA trust problem after a timeout/relaunch.

Therefore, **do not claim manual browser acceptance unless the live repo/current evidence explicitly proves it was completed after that point.**

## 6.10 Explanation milestone

A later milestone reportedly added explanation work. Inspect the live code/docs/tests to determine exactly what was implemented and what evidence binds the explanation to model/alert evidence.

Do not assume “LLM explanation” merely from the word explanation. Determine whether it is deterministic, templated, model-generated, fallback behavior, or something else.

---

# 7. OPEN RISK / ISSUE THEMES THAT MUST REMAIN VISIBLE

The exact issue numbers/statuses must come from the current `docs/issue_register.md`, but historically important open themes include:

- **TF-008:** demo/product acceptance gap.
- **TF-009:** reliability / operational evidence gap.
- scientific evaluation exposure and independent-evaluation limitations;
- source/capture/entity provenance;
- cross-source compatibility;
- defensible relationship key before alert correlation;
- operational human credential provisioning/revocation;
- browser write authentication / session / CSRF safety;
- explanation evidence and unavailable/degraded behavior;
- endurance/resource evidence;
- service lifecycle and signal/service-manager behavior;
- backup/recovery and cross-database consistency;
- audit export/retention/rotation;
- optional-service outage behavior;
- live-source identity;
- user-value / analyst-effect evaluation;
- final recovery rehearsal and reproducible handover.

Never close an issue because code “looks complete.” Close only when its acceptance evidence is satisfied and documented.

---

# 8. CURRENT MACHINE / DEVELOPMENT CONSTRAINTS

Previously known environment:

```text
OS: Ubuntu 24.04.4 LTS
CPU: Intel i5-13420H
RAM: ~16 GB
GPU: NVIDIA RTX 4050 6 GB
Python: 3.11.16
uv: available
CUDA/GPU: available, but product path must not require GPU unless explicitly designed
Repository: ~/projects/threatfusion-gemini
```

The project has an existing environment referred to as `threatfusion-venv`.

**Do not create or switch to a random copied `.venv` just because one is convenient.**
Discover and use the environment that the current repo/instructions expect.

Useful checks:

```bash
cd "$HOME/projects/threatfusion-gemini"
ls -ld threatfusion-venv "$HOME/projects/threatfusion-venv" 2>/dev/null || true
realpath threatfusion-venv 2>/dev/null || true
which python || true
python --version || true
```

Past commands often used forms like:

```bash
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=backend/src:. \
threatfusion-venv/bin/pytest -o addopts= -q --tb=short <focused-tests>
```

Do not blindly copy this if the live environment path changed. Resolve it first.

---

# 9. QUALITY GATES

Use focused verification while iterating, then adjacent/system verification before declaring a milestone.

At minimum, adapt the repo’s current equivalents of:

```bash
# focused tests first
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/src:. \
  threatfusion-venv/bin/pytest -o addopts= -q --tb=short <relevant tests>

# static/lint
threatfusion-venv/bin/ruff check <affected paths>

# formatting
threatfusion-venv/bin/black --check <affected paths>

# whitespace / patch integrity
git diff HEAD --check
```

When appropriate, run the full or broader adjacent suite defined by the repo.

Rules:

- Do not report “tests pass” without giving the scope/count.
- Distinguish focused tests from full suite.
- Do not hide skipped/xfailed tests if they matter to the claim.
- Do not “fix” tests by weakening assertions that encode security/correctness contracts.
- Prefer regression tests that fail before the fix and pass after.
- For security boundaries, test rejection ordering and side-effect absence.
- For persistence, test restart/reopen behavior.
- For bounded services, test cleanup/timeout/interruption.
- For browser/UI paths, test explicit empty/error/degraded states, not just happy path.

---

# 10. GIT SAFETY

Treat Git history as project evidence.

### Never do without explicit user authorization

- `git push`
- force push
- destructive reset of user work
- deleting branches containing user work
- rewriting `main`
- discarding uncommitted changes
- replacing a newer implementation with an older handoff version
- mass deletion because a file “looks obsolete”

### Before editing

```bash
git status --short --branch --untracked-files=all
git diff
git diff --cached
```

### Before a local commit

Verify:

```bash
git diff --check
git diff --cached --check
git status --short --branch --untracked-files=all
```

Use coherent milestone commits. Do not mix unrelated cleanup with a functional/security milestone.

If the worktree is already dirty, determine whether changes belong to the user/another agent before modifying them.

---

# 11. SECURITY ENGINEERING PRINCIPLES

ThreatFusion is a cybersecurity project. Security shortcuts are not acceptable just because the environment is local.

Preserve:

- authentication before sensitive operations;
- explicit authorization;
- least privilege;
- input/schema validation;
- idempotency;
- bounded request/body/queue/resource behavior;
- timeout/termination guarantees;
- safe cleanup;
- sanitized external errors plus internal audit evidence;
- no credential/secrets logging;
- secure local TLS/mTLS behavior where required;
- explicit degraded states;
- traceability from evidence → alert → explanation → analyst action;
- human approval before disruptive containment.

Do not turn a simulated/lab project into an unsafe autonomous response engine.

---

# 12. LLM / EXPLANATION / SOAR RULES

LLM output is not evidence.

If/when an LLM layer is used:

1. Bind its prompt/input to explicit persisted evidence references.
2. Require structured output with schema validation.
3. Do not let it invent IOCs, ATT&CK IDs, CVEs, identities, incidents, or model scores.
4. Expose missing evidence.
5. Provide deterministic fallback/unavailable behavior.
6. Store provenance/model/version where appropriate.
7. Treat generated Sigma/playbook content as a candidate requiring validation.
8. Do not execute disruptive actions directly from free-form model text.
9. Human approval is required before containment/response actions unless a separately approved safe lab rule explicitly proves otherwise.
10. “Zero-day” must not be claimed from generic anomaly detection.

---

# 13. OPTIONAL SERVICES ARE OPTIONAL

MISP, TheHive, n8n, Pi-hole, ChromaDB, external threat-intel APIs, and similar services must not become hard dependencies of the core demo unless the charter/current architecture explicitly changes.

Core behavior should degrade visibly and safely when optional services are off.

For external APIs:

- no hidden paid dependency;
- rate limits/budget must be explicit;
- caching/provenance must be stored;
- private/reserved addresses must not be sent to public reputation APIs;
- offline fallback should be defined where required.

---

# 14. TARGET DEVELOPMENT ORDER

Use the current issue register to choose the exact next task. If it does not contradict newer repo state, the preferred engineering order is:

```text
1. Preserve and verify current registered-input → alert → analyst-view path
2. Finish the highest-priority open acceptance gap
3. Make browser/analyst workflow operationally safe
4. Complete explanation evidence + failure behavior
5. Complete credential provisioning/revocation and service lifecycle evidence
6. Reliability: endurance, backup/recovery, audit lifecycle, optional-service degradation
7. Only then add defensible correlation/risk logic
8. Then enrichment / case workflow / optional integrations
9. Then independent evaluation + analyst/user assessment
10. Final reproducibility, recovery rehearsal, report/demo handover
```

Do not jump to flashy integrations while a P0 acceptance/security gap remains.

---

# 15. IMPLEMENTATION METHOD FOR EVERY TASK

For each meaningful task:

## Phase A — Investigate

- read repo instructions;
- read current status and issue entry;
- open relevant implementation;
- open relevant tests;
- identify the exact contract being changed;
- inspect git history if design intent is unclear.

## Phase B — Define a bounded milestone

Write a one-paragraph implementation intent:

```text
Current gap → exact behavior to add/fix → evidence required → explicit non-goals.
```

Keep the scope narrow enough to validate.

## Phase C — Add/adjust tests

Prefer a regression test demonstrating the current failure or missing contract.

## Phase D — Implement

Reuse current architecture. Do not create parallel frameworks/services unless there is a demonstrated need.

## Phase E — Verify

Run:

- focused tests;
- adjacent tests;
- lint/format;
- `git diff --check`;
- any contract-specific evidence command.

## Phase F — Audit the result

Ask:

- Did the change create a bypass?
- Did it weaken identity/provenance?
- Did it make a planned component look “implemented” in docs?
- Did it introduce an unverifiable claim?
- Did it create an unbounded resource path?
- Did it silently change data semantics?
- Is failure visible and safe?

## Phase G — Update existing documentation

Update the minimum correct existing status/issue/contract docs. Do not create duplicate status files for every task.

Documentation must say both:

- what is now proven;
- what remains unproven.

## Phase H — Checkpoint

If a local commit is appropriate and allowed, make one coherent commit. Never push without explicit user authorization.

---

# 16. TOKEN / TIME EFFICIENCY RULES

The owner wants high productivity and limited paid-AI usage.

Therefore:

- Investigate once, then act.
- Use `rg`, targeted reads, and test selection rather than dumping the whole repository.
- Read large docs only in relevant sections unless a full read is needed for a design decision.
- Avoid repeatedly re-explaining unchanged context.
- Prefer one coherent end-to-end milestone over many tiny cosmetic edits.
- Do not spend tokens rewriting already-good documentation.
- Do not create speculative abstractions “for future use.”
- Reuse existing fixtures/helpers/contracts.
- When a task is large, split by **verifiable milestones**, not arbitrary file counts.
- Maintain enough state in repository docs/Git so a new AI session can resume without replaying the full chat history.

Efficiency never overrides correctness, security, or scientific integrity.

---

# 17. USER COMMUNICATION STYLE

The owner expects direct technical reasoning.

When reporting progress:

- state what you verified;
- state what changed;
- state the tests/evidence;
- state what remains;
- state the next best action.

Do not use vague claims such as:

- “production-ready”;
- “enterprise-grade complete”;
- “AI SOC is finished”;
- “zero-day capable”;
- “fully autonomous”;
- “real-time” unless there is an actual serving/live source path proving it;
- “correlated incident” unless the relationship key is defensible.

Challenge assumptions that conflict with evidence.

---

# 18. CONTINUITY ACROSS GEMINI / ANTIGRAVITY / CLAUDE / CURSOR

This repository may be touched by multiple AI coding agents.

Assume **another agent may have made valid progress after this handoff**.

At the beginning of every new session:

```bash
git status --short --branch --untracked-files=all
git log --oneline --decorate -15
git diff --stat
git diff --cached --stat
```

Then read the latest relevant status/issue entries.

At the end of a substantial milestone:

- leave the worktree understandable;
- update the existing status/issue/contract docs;
- run verification;
- record evidence honestly;
- make a coherent local commit only when appropriate;
- never push without explicit authorization.

A future agent should be able to answer “where were we?” from Git + repo docs without needing the previous chat.

---

# 19. WHAT “DONE” MEANS

A feature is not done because code exists.

It is done for its bounded milestone only when:

```text
behavior exists
+ security/correctness contract is preserved
+ negative/failure paths exist
+ tests demonstrate the contract
+ quality gates pass
+ docs accurately reflect the evidence
+ remaining limitations remain visible
```

For a project issue to be closed, meet the issue’s explicit acceptance criteria, not a weaker substitute.

---

# 20. FIRST RESPONSE AFTER LOADING THIS HANDOFF

Do not immediately start rewriting code.

First tell the owner, concisely:

```text
1. Current branch + HEAD
2. Worktree state
3. Latest verified milestone
4. Highest-priority open gap
5. What you will tackle next
6. Exact tests/evidence you will use
```

Then proceed with the task unless the owner explicitly asks for planning only.

---

# 21. FINAL NON-NEGOTIABLES

- Live repo truth beats this file.
- Read before editing.
- Do not erase newer work.
- Do not push without permission.
- Do not weaken tests to get green.
- Do not fabricate scientific validity.
- Do not conflate planned architecture with implementation.
- Random Forest is the verified product inference path unless current evidence shows an approved change.
- Autoencoder/DL research is not automatically fused into the product.
- Do not correlate without a defensible relationship/entity key.
- Do not claim independent evaluation after outcome exposure.
- Do not trust browser/user identity from spoofable headers.
- Do not make optional integrations hard dependencies without an explicit design decision.
- Keep disruptive SOAR human-approved.
- Keep all evidence and limitations auditable.

---

# CLAUDE-SPECIFIC OPERATING INSTRUCTIONS

This version is intended primarily for **Claude Code**. If using only the Claude web app, upload this file together with the current repository/archive or the specific files needed for the task; the web app cannot inspect a local repository it has not been given.

## Recommended installation/use

Place this file at the project root as:

```text
CLAUDE.md
```

Do **not** overwrite a newer `CLAUDE.md` blindly. If one already exists, compare and merge the durable instructions.

Claude Code automatically loads project `CLAUDE.md` instructions. Start from the repo:

```bash
cd "$HOME/projects/threatfusion-gemini"
claude
```

Initial instruction:

```text
Read CLAUDE.md and the repository's AGENTS.md/status/issue documents.
Run the bootstrap audit before making changes.
Treat the live repository as authoritative over historical handoff details.
Then continue the highest-priority currently open ThreatFusion milestone.
```

## Claude behavior for this project

- Default to implementation when the user asks to build/fix/complete something.
- For a request that is explicitly “review”, “audit”, or “plan only”, do not edit until that requested review is delivered.
- Use tools to inspect files instead of guessing.
- Work persistently through a coherent milestone.
- Do not prematurely stop because context is getting long; leave durable state in Git/repository docs before context compaction.
- Avoid spawning many speculative subagents for small tasks.
- If subagents are useful, give them narrow read/review tasks and reconcile their output yourself.
- Avoid duplicated implementations created by independent subagents.
- Preserve existing style, contracts, and test patterns.
- Before a risky/destructive action, ask.
- Local, reversible edits and test runs are normal.
- Never use `--dangerously-skip-permissions` as a default project setup.
- Never change the push guard or push just to “save progress.”

## Claude context discipline

When the context becomes large:

1. Keep current task scope fixed.
2. Record concrete progress in the existing project-status/issue docs when it is real.
3. Use Git checkpoints for tested coherent milestones where appropriate.
4. Continue from repository truth after compaction.
5. Do not replace concrete evidence with a prose summary if the code/tests can be inspected.

## Claude review pass before claiming completion

Before reporting a milestone complete, independently inspect:

```text
security boundary
failure behavior
scientific/data semantics
idempotency/replay
resource bounds
persistence/restart behavior
documentation claims
git diff
test scope
```

Then report the exact test count/scope and any remaining issue acceptance criteria.

## Claude web-app fallback

If Claude Code is not being used and only Claude Pro web is available, the minimum useful upload set is:

```text
this handoff
AGENTS.md
docs/product_charter.md
docs/project_status.md
docs/issue_register.md
relevant contract docs
relevant source files
relevant tests
```

For substantial coding, provide a current repo archive rather than relying on copied snippets. Claude must not claim it modified or tested a local repo when it only saw uploaded text.

---

# CLAUDE START COMMAND

After this file has been placed as `CLAUDE.md`, begin with:

```text
Bootstrap ThreatFusion from the live repository now. Do not make edits until you have read AGENTS.md, the current project status, issue register, and the relevant tests. Tell me the current HEAD/worktree state, the exact latest verified milestone, the highest-priority open acceptance gap, and the bounded task you will execute. Then implement it, test it, update the existing evidence/status docs honestly, and leave a clean understandable checkpoint. Do not push.
```


---

## 19. RECONCILIATION AND GEMINI BRANCH SYNCHRONIZATION (2026-10-16)

This file was installed from `~/Downloads/THREATFUSION_CLAUDE_HANDOFF.md` into `~/projects/threatfusion-gemini/CLAUDE.md` on 2026-10-16 to maintain permanent multi-agent governance continuity across Claude, Gemini, Antigravity, and Copilot.

### Verified Milestones Completed on `gemini/product-20260924`:
1. **Milestones #18–#20 (Phase P3 & P4):** Completed entity provenance contract, dual-window (30s burst / 10m campaign) incident correlation engine, Mordor scenario and authorized lab sensor adapters (`provenance_sources.py`), Section 8 edge-case gates (NAT/address reuse, entity validity intervals, clock skew <= 5.0s, candidate deduplication, member justifications), and audited manual grouping corrections (`incidents.sqlite3`).
2. **Milestone #21 (Phase P5):** Implemented missing-data aware multi-signal risk evaluator (`multi_signal_risk.py`, schema `dynamic_risk_assessment_v1`), detector ablation evaluator (`detector_ablation_report_v1`), jury requirements traceability registry (`jury_traceability.py`, schema `jury_traceability_matrix_v1`), and offline retraining feedback ledger (`retraining_feedback_ledger.py`, schema `offline_retraining_feedback_sqlite_v1`, mode 0600 SQLite with pre/post zero online weight drift verification).
3. **Governance Discipline Applied:** In accordance with Section 7 of this document ("Never close an issue because code 'looks complete.' Close only when its acceptance evidence is satisfied"), `TF-010` is maintained as **`open`** in `docs/issue_register.md`. While the code-side disposition registry and checksum verification are fully implemented, closure of `TF-010` formally requires external attachment of the dated, signed FYP-1 jury brief/rubric.
4. **Milestone #22 (Phase F):** Deep presentation audit (`docs/fyp2_final_presentation_and_azure_live_path_audit.md`), Slide 14 Box 03 Suricata 14-Feature Flow Adapter (`SuricataFlowAdapter`), `incident_repository` integration into `HumanListenerLifecycle`, and quiescent 4-DB atomic snapshot verification across `alerts`, `states`, `audit`, and `incidents`.
5. **Milestone #23 (Phase P6 & Evaluation Pack Rev2):**
   - **Canonical FYP-II Evaluation Pack Rev2 (`AI-FYP-2006`):** Authoritative CS492 baseline (FAST-NUCES Karachi, Muhammad Bilal 21K-3551, Muhammad Suhaib Shaikh 22K-4302, Muhammad Hasnain 22K-4718, Supervisor: Sir Sameer Faisal, evaluation checkpoint `6a36dcd`). Distinguishes `ThreatFusion_Evaluation_Pack_Rev2.zip` (authoritative Sept 21 numbers) from earlier draft deck `Final Presentation (1).pptx` (legacy split metrics + Slide 14 Azure path).
   - **Section 8 `fusion_disabled` Invariant:** Enforced across `canonical_evaluation.py` and `multi_signal_risk.py`. Production alert authority rests solely on the frozen Random Forest (`random_forest.joblib`). Automatic RF+AE fusion is strictly disabled due to the 16.4:1 benign-FP penalty (1,574 additional FPs for 96 attacks).
   - **Section 13.C Threat Intelligence Enrichment:** `ThreatIntelEnrichmentService` / `SourcedThreatIntelEnricher` with strict RFC 1918 / loopback / link-local private IP guard (Slide 14 internal IPs 10.0.0.4 and 10.0.0.5 never queried externally), TTL caching, and degraded outage isolation.
   - **Section 13.D Evidence-Bound Advisory Debrief:** `AdvisoryDebriefEngine` / `AdvisoryExplanationEngine` with anti-hallucination citation validation, mandatory advisory disclaimer, versioned MITRE ATT&CK mapping, and deterministic template fallback.
   - **Section 13.E Approval-Gated Reversible SOAR Ledger:** Mode-0600 SQLite store enforcing 5-step lifecycle (`pending_approval` -> `approved` -> `executed_simulated` -> `rolled_back`), protected target allowlist, and audit logging.
6. **Milestone #24 (Section 13.F Workload Measurement & Two-Track Demo Runner):**
   - Implemented `workload_measurement.py` for queue compression and January counterfactual false-positive shield (8.831x FP reduction).
   - Enforced TF-009 discipline: `tf_009_closure_eligible = False` for all non-human or under-sized cohorts.
   - Built turnkey two-track SOC demo runner (`full_soc_demo.py`, `run_full_soc_demo.py`) executing Track A (UNSW replay) and Track B (Slide 14 Suricata SOC spine).
7. **Milestone #25 (Deterministic Zero-Trust Repository Truth Audit Gate):**
   - Implemented `repo_truth_audit.py` and `scripts/audit_repo_truth.py` with 7 cryptographic ground-truth checks, verifying frozen model SHA-256 hashes, exact normalized cell equality for TF-008..TF-011, and module `__file__` origin.
8. **Milestone #26 (Presentation Deck & Academic Defense Harmonization):**
   - Harmonized 15-slide defense presentation (`generate_harmonized_defense_deck.py`) with Evaluation Pack Rev2 (`AI-FYP-2006`).
   - Retracted legacy split inversion numbers (89.77% RF, 94.95% fusion) from active slides.
   - Qualified Slide 14 badge ("BOUNDED RECORDED/LOCAL INTEGRATION PATH VERIFIED (16/16 TEST GATES); LIVE AZURE/SIEM DEPLOYMENT OPEN (TF-011)") and software-spine footer, eliminating all unqualified claims.
   - Added `test_defense_deck_harmonization.py` and committed under `9806774`.
9. **Milestone #27 (Interactive Workload Study CLI Runner & Harmonized Defense Docs):**
   - Implemented interactive & scriptable analyst workload study runner (`study_runner.py`, `run_analyst_workload_study.py`) with 10 provenance-grounded scenarios across baseline and ThreatFusion conditions.
   - Built harmonized defense documentation generator (`generate_harmonized_defense_docs.py`) generating `docs/presenter_guide_15_slides_rev2.md`, `ThreatFusion_FYP2_Presenter_Guide_Harmonized.docx`, and `ThreatFusion_FYP2_Final_Report_Harmonized.docx` with zero external dependencies.
   - Added unit test suite `test_defense_docs_and_study_runner.py` verifying all 18 milestone test suites pass cleanly.
   - Maintained `TF-008`, `TF-009`, `TF-010`, and `TF-011` strictly **open**.
10. **Milestone #28 (3-Layer Architecture SOPs, Unicorn Progressive-Disclosure SOC Interface, Resilient Suricata Ingestion, $0 Cloud Budget Kill-Switch, and Outage-Isolated Gemini Advisory Client):**
    - **Architecture & Design Guidelines:** Created Layer-1 constitutional architecture SOPs (`docs/blast_3layer_architecture_sop.md`, `design_guidelines/soc_unicorn_interface_sop.md`) formalizing the separation of Layer 1 (SOPs/declarations), Layer 2 (deterministic contracts/pipelines), and Layer 3 (atomic tools banning LLMs from the primary detection loop).
    - **Unicorn Progressive-Disclosure Interface:** Enhanced `backend/src/threatfusion/api/analyst_dashboard.py` with `data-blast-ui-tier="unicorn-progressive-disclosure-v1"` and distinct secondary anomaly badge (`.badge-secondary-anomaly`) enforcing Section 8 non-fused context.
    - **Resilient Suricata Stream Telemetry:** Implemented `backend/src/threatfusion/operations/cloud_live_telemetry.py` with `process_suricata_eve_stream_resilient`, dead-letter quarantine for corrupted JSON lines and schema-invalid flows, and CLI script `scripts/run_cloud_suricata_forwarder.py`.
    - **Programmatic $0 Cloud Budget Kill-Switch:** Built `CloudBudgetKillSwitchPolicy` and `evaluate_budget_kill_switch` guaranteeing $0 out-of-pocket charges on Google AI Pro credits by triggering `should_detach_billing=True` at $5.00 gross spend and failing closed on negative spend. Documented in `docs/google_ai_pro_zero_dollar_cloud_guide.md`.
    - **Outage-Isolated Grounded Gemini Advisory:** Created `backend/src/threatfusion/advisory/gemini_client.py` (`GeminiAdvisoryCallable`, `GeminiAdvisoryConfig`, `build_grounded_gemini_prompt`), running strictly outside detection loop with pure stdlib, failing closed to deterministic templates upon missing API keys, timeouts, or hallucinated IPs (e.g. `203.0.113.99`).
    - **Zero-Trust Audit Gate & Unit Suite:** Updated `repo_truth_audit.py` Check 5 and Check 6 live probes; created `test_blast_resilience_and_gemini_advisory.py`.
    - **Governance Discipline Maintained:** `TF-008`, `TF-009`, `TF-010`, and `TF-011` remain strictly **open**.
11. **Milestone #29 (9.5/10 B.L.A.S.T. Governance Upgrade: Whole-Tree Symlink Rejection, Programmatic GO/NO-GO Decision Report, Unresolved Risk Ledger, and Test Suite Consolidation):**
    - **Whole-Tree Symlink Rejection:** Check 1 in `repo_truth_audit.py` scans `backend`, `scripts`, `docs`, and `design_guidelines` recursively, failing closed with "Unexpected symlink detected in workspace tree: <path>" on any symlink.
    - **Programmatic GO/NO-GO Decision Report & Risk Ledger:** `RepoTruthAuditReport` computes `decision_verdict` ("GO" iff all checks pass and `failed_check_ids == ()`, else "NO-GO"), `failed_check_ids`, and the 4 canonical `unresolved_risks` disclosures. Updated `scripts/audit_repo_truth.py` to print the explicit scientific risk disclosures and final decision verdict banner.
    - **Unit Test Consolidation:** Consolidated redundant split test files (`test_advisory_explanation.py`, `test_blast_and_unicorn_sops.py`, `test_cloud_live_telemetry.py`) into authoritative `test_blast_resilience_and_gemini_advisory.py` (19 passing unit tests). Added unit tests in `test_repo_truth_audit.py` for symlink rejection and GO verdict emission.
    - **Governance Discipline Maintained:** `TF-008`, `TF-009`, `TF-010`, and `TF-011` remain strictly **open**.
12. **Milestone #30 (Unified Master Engineering Skill v3.0, Boundary Preflight B0-B5, Recall Labeling Harmonization, Gate G9 AST Check, Tamper-Evident SOAR Hash Chain, and Non-Fused AE Queue Ranker):**
    - **Unified Master Engineering Skill & Boundary Preflight:** Created `SKILL.md`, `.agents/skills/threatfusion-master-engineering/SKILL.md`, and `.agents/ownership.json`. Implemented `boundary_preflight.py` (`scripts/boundary_preflight.py` and `backend/src/threatfusion/evaluation/boundary_preflight.py`) enforcing Protocol 0 deterministic boundary checks B0 through B5 with component-wise realpath containment and negative lookahead `(?![\w\-])` to avoid false triggers on `-gemini`. Integrated Gate G0 preflight into `repo_truth_audit.py` Check 1.
    - **Recall Labeling Harmonization:** Reconciled mathematical labeling across code and defense documentation: accurately distinguished between `+2.203 pp` absolute recall gain (92.818% -> 95.021%) and `+2.373%` relative true positive increase (4,045 -> 4,141 TP, +96 attacks). Updated `workload_measurement.py`, `canonical_evaluation.py`, defense presentation scripts, presenter guide, and harmonized slide deck docs.
    - **Tamper-Evident Hash-Chained SOAR Audit Trail:** Enhanced `backend/src/threatfusion/soar/playbook_ledger.py` with cryptographic SHA-256 hash chaining (`prev_entry_sha256` and `entry_sha256`), genesis block hashing, and `verify_audit_chain_integrity()` method that detects direct SQLite database tampering, unauthorized updates, and row deletions.
    - **Non-Fused AE Queue Priority Ranker:** Implemented `rank_rf_alerts_for_triage_queue` in `backend/src/threatfusion/models/multi_signal_risk.py`, strictly enforcing `production_fusion_enabled=False`, filtering sub-threshold flows (<0.5 RF probability), and ordering analyst triage queues by incident burst size, secondary unfused AE reconstruction error ratio (`ae_error / ae_threshold`), and RF attack probability.
    - **Gate G9 AST Detection Pipeline Import-Graph Check:** Added `verify_gate_g9_ast_import_graph` in `repo_truth_audit.py` to statically verify via AST parsing that fast-path Stage 1 to 4 detection modules (`suricata_flow.py`, `provenance_sources.py`, `producer_inference_worker.py`, `network_inference.py`, `correlation_engine.py`) contain zero imports of Stage 5 advisory components (`threatfusion.advisory`, `gemini_client`, `explanation_engine`). Integrated into Check 5 and Check 6 live probes.
    - **Unit Test Suite:** Created `backend/tests/unit/test_boundary_and_high_leverage_features.py` (17 passing unit tests) covering boundary preflight B0-B5, recall labeling, SOAR audit hash chain tamper detection, AE queue priority ranker, and Gate G9 AST detection isolation.
    - **Governance Discipline Maintained:** `TF-008`, `TF-009`, `TF-010`, and `TF-011` remain strictly **open**.
13. **Milestone #31 (14-Feature PSI Drift & Model Supply-Chain Monitor, Pre-Registered TF-008 Independent Holdout Evaluator with Bootstrap CIs, and Full SOC Demo / Dashboard Integration of AE Queue Ranker & SOAR Hash Chain):**
    - **Model Supply-Chain Manifest Verifier:** Implemented `verify_frozen_model_supply_chain` in `drift_and_supply_chain.py` verifying all 4 frozen model artifacts on disk against immutable reference digests (`Random Forest` `bd2853a6...` as `primary_production_authority`, `Logistic Regression` `2cf4de66...` as `linear_baseline`, `Autoencoder v2` `c8675d13...` as `secondary_non_blocking_ranker`, `Rate-Log1p` `1d02e5bb...` as `blocked_candidate`), failing closed on missing, symlinked, or tampered artifacts.
    - **Read-Only 14-Feature PSI Drift Monitor:** Implemented `evaluate_14_feature_telemetry_drift` in `drift_and_supply_chain.py` using pure Python stdlib (`math`, `statistics`), verifying presence and finite types of all 14 canonical features without mutating inputs or model weights. Computes per-feature mean shift Z-scores and decile Population Stability Index (PSI) approximations, classifying drift into `stable_in_distribution` (<0.10), `moderate_feature_drift_monitor` (0.10..0.25), and `severe_out_of_distribution_drift_retraining_review_required` (>=0.25).
    - **Pre-Registered TF-008 Independent Holdout Evaluator:** Implemented `independent_holdout_protocol.py` and `docs/tf008_preregistered_evaluation_protocol.md`, blacklisting development-informing splits (`INSPECTED_DEVELOPMENT_DATASET_IDS = ("unsw_nb15_train_865480", "unsw_nb15_january_216568", "unsw_nb15_february_1452844")`). Any evaluation targeting inspected splits immediately triggers `protocol_violation_inspected_split=True` and `tf_008_closure_eligible=False`. Computes exact confusion counts at 0.5 threshold, precision, recall, F1, FPR, accuracy, and deterministic 95% bootstrap confidence intervals ($B \ge 200$, seeded PRNG). Enforces `tf_008_closure_eligible=False` on synthetic smoke fixtures and sample sizes <1000.
    - **Full SOC Demo & Analyst Dashboard Integration:** Wired `rank_rf_alerts_for_triage_queue`, `verify_audit_chain_integrity`, and `evaluate_14_feature_telemetry_drift` into Track B of turnkey demonstration runner `run_full_soc_demo()`, producing verified reports (`full_soc_demo_report.json` and `full_soc_demo_report.md`). Enhanced `analyst_dashboard.py` alert detail HTML view with `"SOAR Cryptographic Audit Chain: VERIFIED (SHA-256 Hash-Linked)"` badge and `"Non-Fused Queue Priority Rank"` indicator with dedicated dark-theme styling.
    - **Repo Truth Audit Upgrade & Unit Suite:** Added modules to Check 5 `CANONICAL_MODULES` with origin verification; upgraded Check 6 functional probe in `repo_truth_audit.py` (all 7 zero-trust checks pass with `POST-EXECUTION DECISION VERDICT: GO`). Created `backend/tests/unit/test_drift_supply_chain_and_tf008_protocol.py` (15 passing unit tests).
    - **Governance Discipline Maintained:** `TF-008`, `TF-009`, `TF-010`, and `TF-011` remain strictly **open**.
14. **Milestone #32 (Full Master-Plan SOC Stack Integration — ChromaDB Semantic Vector RAG, Deterministic n8n Playbook Webhook Engine, TheHive Case Management, MISP Private-IP Guarded IOC Client, Docker Compose SOC Stack, and Turnkey SOC Pipeline Integration):**
    - **ChromaDB Semantic Vector RAG (`chromadb_mitre_rag.py`):** Implemented `MitrePlaybookRagDocument`, `ChromaRagQueryResult`, and authoritative `CANONICAL_MITRE_AND_PLAYBOOK_CORPUS` (10 enterprise techniques: T1046, T1190, T1498, T1071.001, T1595, T1110, T1041, T1021, T1059, T1133). Built `DeterministicMitreEmbeddingFunction` generating 64-dimensional L2-normalized dense float vector embeddings from domain tokens and trigrams deterministically without external models or network calls. Built `ChromaDbMitrePlaybookRag` operating a persistent SQLite dense vector store (`chromadb_vectors.sqlite3`) with mode 0600 file security, cosine similarity ranking, and `query_semantic_rag_for_bundle`. Maintained strict assistant-only isolation with zero imports from Stage 1-4 detection modules (Gate G9 AST verified).
    - **Deterministic n8n, TheHive, and MISP SOC Stack Clients (`n8n_thehive_misp_stack.py`):**
      - `MispDeterministicClient`: Queries MISP indicator endpoints with strict RFC1918 Private-IP Guard (suppressing 10.0.0.4/10.0.0.5 from external egress) and verified local snapshot fallback matching known malware indicators (EICAR, Mirai) deterministically.
      - `TheHiveDeterministicClient`: Creates TheHive v4/v5 case records containing correlated incident_id, primary RF confidence score (%), non-fused AE queue rank, MISP IOC tags, and ChromaDB MITRE tags, strictly enforcing human approval gate and cryptographic hash chain integrity (failing closed on unapproved or tampered records).
      - `N8nDeterministicPlaybookClient`: Dispatches HMAC-SHA256 signed webhook triggers with idempotency keys (`idem_<playbook_id>_<version>`) enforcing mandatory human approval and hash chain verification.
      - Mode-0600 Durable SQLite Outbox (`n8n_thehive_misp_outbox.sqlite3`) ensuring auditable persistence and reliable offline queueing.
    - **Docker Compose SOC Stack & n8n Workflow JSON (`docker/docker-compose.soc-stack.yml`, `docker/n8n/workflows/threatfusion_soar_playbook.json`):** Created containerized stack configuration binding `n8n` (5678), `thehive` (9000), `chromadb` (8000), and `misp-connector` strictly to `127.0.0.1`. Authored 5-node deterministic n8n workflow JSON: (1) Webhook Trigger, (2) Verify Approval & SHA-256 Audit Chain Gate, (3) Query MISP Threat Intelligence, (4) Auto-Create Case in TheHive, (5) Security Operations Callback.
    - **Turnkey SOC Demo & Analyst Dashboard Integration:** Wired ChromaDB RAG, MISP, TheHive, and n8n clients into Track B of `run_full_soc_demo()`, producing verified reports (`full_soc_demo_report.json` and `full_soc_demo_report.md`). Added dedicated UI badges to `analyst_dashboard.py`: `"ChromaDB Semantic RAG: MITRE ATT&CK & Playbook Assistant"`, `"n8n Deterministic Playbook & TheHive Case Status"`, and `"Prioritized Alert Confidence Score (Frozen RF Primary + Secondary v2 AE)"` with CSS styling `.badge-confidence`, `.badge-chroma-rag`, and `.badge-n8n-hive`.
    - **Repo Truth Audit Upgrade & Unit Suite:** Added modules to Check 5 `CANONICAL_MODULES` with origin verification; verified `docker/n8n/workflows/threatfusion_soar_playbook.json` on disk; upgraded Check 6 functional probe in `repo_truth_audit.py` (all 7 zero-trust checks pass with `POST-EXECUTION DECISION VERDICT: GO`). Created `backend/tests/unit/test_chromadb_rag_n8n_thehive_misp.py` (19 passing unit tests).
    - **Governance Discipline Maintained:** `TF-008`, `TF-009`, `TF-010`, and `TF-011` remain strictly **open**.
15. **Milestone #33–#34 (Master-Plan SOC Stack Hardening, Ledger-Backed Contract Verification, Strict Dashboard Evidence Validation, STRIDE Threat Model, and Defense Deliverable Harmonization — 2026-10-19):**
    - **Copilot Findings #1 & #2 Remediated:** Implemented HMAC-SHA256, Idempotency, and Ledger State Verification Code Node in `threatfusion_soar_playbook.json`, with container service DNS hostnames (`http://misp-connector:8080/attributes/restSearch`, `http://thehive:9000/api/v1/case`, `http://threatfusion-callback:8443/api/v1/soar/callback`, `http://threatfusion-callback:8443/api/v1/soar/verify-state`).
    - **Copilot Finding #3 Remediated:** Built `scripts/run_misp_and_callback_contract_server.py` with server-side `SoarPlaybookSqliteRepository` state and hash-chain verification (HTTP 403 on unapproved/mismatching playbooks), anti-replay on idempotency keys (HTTP 409), strict MISP API key auth (HTTP 401), RFC1918 guard (HTTP 422), and healthz endpoint. Updated `docker-compose.soc-stack.yml` with pinned tags, zero `******` placeholders, and fail-closed environment variables (`${THREATFUSION_THEHIVE_API_KEY:?required}`, etc.). Removed hardcoded fallback secret in `n8n_thehive_misp_stack.py`.
    - **Copilot Finding #4 Remediated:** Replaced generic exception handlers with specific transport exceptions (`URLError`, `TimeoutError`, etc.) in `n8n_thehive_misp_stack.py`, and prohibited catching and discarding SQLite persistence errors.
    - **Copilot Finding #5 Remediated:** Implemented strict schema and digest validation on dashboard evidence badges in `analyst_dashboard.py`, failing closed to `data-evidence-state="unavailable"` when unverified.
    - **STRIDE Threat Model & Defense Harmonization:** Authored `docs/stride_threat_model_and_production_readiness.md` across 8 pipeline stages; regenerated `ThreatFusion_FYP2_Final_Defense_Harmonized.pptx`, `ThreatFusion_FYP2_Presenter_Guide_Harmonized.docx`, `ThreatFusion_FYP2_Final_Report_Harmonized.docx`, and updated `docs/presenter_guide_15_slides_rev2.md`.
    - **Verification & Zero-Trust Truth Audit:** Check 6 updated in `repo_truth_audit.py`; `test_chromadb_rag_n8n_thehive_misp.py` expanded with comprehensive negative probes (22 passing unit tests). All 7 truth checks pass with `POST-EXECUTION DECISION VERDICT: GO`.
    - **Governance Discipline Maintained:** `TF-008`, `TF-009`, `TF-010`, and `TF-011` remain strictly **open**.
