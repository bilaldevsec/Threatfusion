# ThreatFusion: evidence-grounded cross-agent handoff

Prepared 2026-09-24 and updated 2026-09-25 from the GitHub repository at commit
`d3f485aa3933fda996b8784ffe11dc54d43bbb8e` and the recorded user/Codex
milestone summaries. **A status document is not a substitute for local tests or
artifact inspection.** The final human-mTLS commit was visible on GitHub; the
exact-SHA CI conclusion and ignored file contents were not independently
verified from this environment. The laptop and USB checks below, along with the
`gh run list` output showing Backend quality run 36008647379 succeeded for baseline
commit d3f485aa3933fda996b8784ffe11dc54d43bbb8e, are owner-supplied command output,
not independent access to that machine or GitHub.

## Ownership and working arrangement — revised 2026-09-25

- The owner now requests a **separate full working copy**, superseding the
  earlier one-checkout decision. Original: `~/projects/threatfusion`.
  Gemini working copy: `~/projects/threatfusion-gemini`. Both are on the same
  SSD; the original is a convenient preserved reference, not protection against
  SSD failure. The separate USB provides that additional recovery location.
- Before this revision, the owner verified the clean local
  `gemini/product-20260924` branch at the baseline in the original directory,
  with local `main` and `origin/main` at the same SHA and a local push URL guard.
  The full copy script preserves that branch and independent `.git` metadata.
  The owner reported successful full-copy verification.
- Owner-reported USB evidence: the full project archive and the 98 MB uv Python
  3.11.16 supplement passed source comparison and SHA-256 checks, and both
  checksum checks passed again. Their filenames are
  `ThreatFusion-baseline-d3f485aa3933fda996b8784ffe11dc54d43bbb8e.tar` and
  `ThreatFusion-python-3.11.16-d3f485aa.tar`. Each has a `.sha256` companion.
  Both are unencrypted by the owner's explicit direction. Disconnect and
  physically protect the drive during development; preserve these snapshots.
- The Python supplement covers the three external `.venv/bin/python*` links
  found during the project scan. No further external symlinks were found
  inside that interpreter directory. These checks do not certify absence of
  other external dependencies referenced through configuration or system libraries.
- The copied `.venv` is retained for the snapshot but must not be activated
  or used; the independently built `threatfusion-venv` is the working environment.
  Its offline build, path checks, and three focused passing tests are reported
  setup evidence, not full product validation.
- The source copy stays untouched. GitHub remains `bilaldevsec/Threatfusion`.
  Use only `gemini/product-20260924` in the new directory and preserve the push
  guard. Future Git publication requires review and authorization. Record new
  recovery checkpoints as work progresses; an old snapshot cannot contain
  changes made afterward. No partition resize is required for this migration.
- Main goal: a defensible single-node FYP SOC triage prototype. The owner's
  eventual plan includes a controlled attacker/victim VM demonstration; this
  migration task does not authorize Azure deployment, live sensor integration,
  model retraining or a revised scientific evaluation. Bounded product
  implementation in the Gemini copy is authorized by the owner's ongoing
  request. Do not infer approval for model training, Azure deployment,
  destructive changes, or Git publication. Preserve the frozen RF product
  path, experimental unfused v2 AE, and blocked rate-log1p candidate. Exact
  jury-required model/dataset list remains unverified (TF-010).

## Product architecture, as implemented

1. Registered offline UNSW reader validates member identity, row order,
   assignments and canonical source values. Frozen 14-column preprocessing
   (10 numeric z-scores plus four protocol indicators) is bound to the
   existing trained model artifacts; source/feature compatibility fails closed.
2. A registered producer sends a bounded request over real IPv4 loopback
   TLS 1.3 mutual TLS. Producer admission checks its distinct credential,
   envelope, source identity, deadlines, gate, audit and durable replay claim.
3. A fresh spawn worker per newly claimed request performs registered
   preprocessing and frozen Random Forest inference. Parent validates the
   complete, ordered batch, kills/joins failed workers, and inserts Attack-only
   immutable AlertCandidate records only after valid completion. The RF rule
   is P(Attack) >= 0.5. Exact completed replay returns identical cached bytes
   and creates no new inference/alert effect.
4. A bounded producer service has startup/readiness, two fixed handlers and no
   application queue; one request executes at a time, overlap can get
   `server_busy`, and shutdown is bounded. A short harness measurement is not
   operational capacity/endurance evidence.
5. Immutable alerts are separate from analyst annotation state in SQLite.
   No two different alerts are correlated into an incident: the alert schema
   lacks a defensible shared host/entity/relationship key. The per-alert state
   is `new -> in_review -> closed | escalated`; the last two states are terminal.
   Registry-bound viewer capabilities read, analyst capabilities may transition.
   UUIDv4 transition IDs and optimistic versions make exact retries idempotent
   and conflicting/stale changes fail closed.
6. An internal view model formats bounded list, detail and transition results
   with detection evidence distinct from analyst rationale and history.
7. At the handoff commit, a **separate human mTLS listener** binds only
   `127.0.0.1`. It uses a dedicated human CA, checks the actual client cert
   DER fingerprint and exact URI SAN against an allowlist, then maps the
   server-owned actor ID to viewer/analyst authorization. Its bounded
   HTTP/1.1 routes are `GET /v1/analyst/alerts`, `GET
   /v1/analyst/alerts/<candidate_id>` and `POST
   /v1/analyst/alerts/<candidate_id>/transitions`. Viewer writes, producer
   credentials, forged role headers/IDs, stale transitions and malformed
   requests are rejected. A review fixed dispatch-after-close and fragmented
   trailing-body bugs. It is a one-request local demonstration listener,
   not a browser session, daemon, security-audited deployment or dashboard.

Read the exact contracts: `docs/producer_admission_transport_policy.md`,
`docs/alert_correlation_analyst_state.md`,
`docs/analyst_authentication_transport.md`,
`docs/network_preprocessing.md`, and `docs/product_charter.md`.

## Model science and demonstration: what is and is not claimed

- The LR and RF baseline training/evaluation and frozen artifacts predate this
  handoff. The product producer path (product inference path) uses the RF; a demonstration loads saved
  weights for **inference**, without training. On January VALIDATION the RF
  report lists TP=4,045, FP=201, TN=212,009, FN=313 (precision 95.266%,
  recall 92.818%, F1 94.026%). Validation is development-informed evidence.
- Corrected v2 AE (`bdb7fc33d5b092566995018b5f83aa66bdb8ce95841d6b8b9021111c9a392a9a`)
  is a **separate experimental** (experimental/unfused path) benign-only weight-training result. Its
  preprocessor stats were fitted on all TRAIN (865,480 rows), optimizer saw
  847,837 benign TRAIN rows, architecture 14-8-3-8-14, and January threshold
  0.1181361214680695 uses strict score > threshold. January TP=1,988,
  FP=1,628, TN=210,582, FN=2,370; it adds 96 AE-only attacks but 1,574
  AE-only benign false positives versus RF. February was already inspected
  and cannot be called a fresh independent test. Reconstruction error is not
  attack probability. No AE fusion or product registry integration is approved.
- One log1p-on-two-rates candidate was prepared with a protocol violation:
  its preprocessing traversed 1,452,844 February TEST rows before discarding
  output. Numerical January gates also all failed: AE-only attacks 59<96;
  AE-only benign FP 2,080>1,574; 40*59<3*2,080; total AE FP 2,122>1,628.
  Candidate TP/FP/TN/FN=945/2,122/210,088/3,413. Disposition is
  `BLOCKED_preserve_baseline`. Do not rerun the frozen one-attempt experiment,
  change thresholds or use this candidate in the product/demo.
- Teammate's separate Colab DNN/CNN/BiLSTM/Transformer/fusion screenshots are
  **unverified external work** with unknown splits, provenance, feature
  semantics, artifacts and comparability. Do not compare their reported
  accuracy to this RF/AE or insert them into the product without a separately
  reviewed protocol. An eventual DNN is a proposal, not an implemented model.
- Historical demo command: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python
  scripts/run_fyp_progress_demo.py`. It sent deliberately selected registered
  UNSW row 1 (Normal) and row 21 (Attack), illustrated mTLS, RF inference,
  Attack-only alert, byte-identical replay, denied invalid request, cleanup,
  and separately demonstrated experimental v2 AE scores. It is neither
  unbiased accuracy evidence nor live traffic. Future runs must use `threatfusion-venv/bin/python`.
- Historical viewer generator: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python
  scripts/generate_fyp_evidence_viewer.py`; ignored offline HTML is at
  `artifacts/reports/fyp_evidence_viewer/threatfusion_fyp_evidence.html`.
  This is a read-only evidence presentation, not a product dashboard.

## Honest roadmap and issue boundaries

Read `docs/issue_register.md` for current closure gates; the summary below
must not independently change their status.

| Issue | Current bound / why still open |
| --- | --- |
| TF-008 | Authenticated producer/analyst boundaries exist; there is no browser-safe analyst dashboard or one authenticated input flowing into a complete live display/explanation. No distinct-alert correlation key. Azure live source disabled. |
| TF-009 | Need operational credential provisioning, signal/daemon/service-manager behavior, long-running limits, measured frozen-RF resources, optional-service degradation, cross-database backup/recovery and audit export. |
| TF-003 / TF-012 | Cross-source byte semantics/extractor comparability unresolved; cannot assert CIC/UNSW equivalence. |
| TF-006 / TF-007 | Capture provenance and near duplicates unresolved; February/CIC outcomes already known. Future independent evaluation needs a genuinely uninspected and reviewed source. |
| TF-010 / TF-011 | Missing authoritative jury model/dataset list and representative-user usefulness evidence. |

Future candidate stages, **not yet integrated**: a browser-safe local analyst
UI over the reviewed human identity boundary; versioned explanation/evidence
display with optional LLM advisory text; separately justified MITRE ATT&CK
mapping from verified evidence; backup/recovery and measured resource behavior;
controlled live collection from an isolated attacker/victim lab with reviewed
14-feature extractor equivalence and stable producer identity; audited,
approval-gated reversible containment only if authorized. Do not treat a
proposed feature or slide as a delivered capability. A network attack has no
"14 attack types" requirement: 14 denotes feature positions, not attack
classes. A victim sensor/live adapter is still absent, so do not wire an Azure
VM directly into the registered-offline UNSW model.

## Immediate handoff gate and next implementation decision

1. The owner reported successful full-copy creation and checksum-comparison against the original.
2. The owner supplied `gh run list` output showing Backend quality run 36008647379
   succeeded for the baseline commit (owner-supplied command output).
3. The copied `.venv` is retained for the snapshot but must not be used. The
   independently built `threatfusion-venv` is the working environment. Its
   offline build, path checks, and three focused passing tests are reported
   setup evidence, not full product validation.
4. Design a bounded browser-safe
   analyst UI contract against the existing human mTLS listener. Keep actor/role
   ownership on the server. Specify sessions, origins/CSRF, failure behavior and
   tests before implementation. Respect the existing Host/header restrictions.
   Confirm the chosen demo workflow with the owner and work in small milestones.

## Minimum validation/reporting discipline

- For changed Python, focused tests, repository Ruff, per-file Black and
  `git diff --check`; run the full backend suite when shared production
  behavior changes. Loopback tests may need local bind permission; preserve
  an exact second result if the sandbox denies the first bind.
- Verify frozen artifact hashes/contract binding if a changed path touches
  model or preprocessing; do not train, rescore or silently refit to fix tests.
- Preserve ignored evidence and the verified USB snapshot; perform explicit ignored/untracked Git check
  before staging; never commit models/datasets/keys/reports. CI must be tied
  to the exact pushed commit SHA, not assumed from a passing previous run.
- Return the exact changed files, evidence, issues left open, limitations,
  commit/push status, and one next task in plain language for the owner.

## Source references

This note was reconciled with repository `AGENTS.md`, `docs/product_charter.md`,
`docs/project_status.md`, `docs/issue_register.md`,
`docs/analyst_authentication_transport.md` and
`docs/alert_correlation_analyst_state.md` at the stated SHA. Google account
entitlements, model list and CLI settings must be verified in the installed
Google Antigravity account instead of inferred from this note.
