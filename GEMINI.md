# ThreatFusion agent entry point (Gemini / Antigravity)

## Current workspace decision — revised 2026-09-25

The owner changed the migration plan: work in a separate full copy at
`~/projects/threatfusion-gemini`. The original `~/projects/threatfusion` is a
preserved reference. Do not edit, activate its environment, test from, fetch
into, switch branches in, or write generated files under that original tree.
The owner authorizes setup of the separate copy and Google tooling, and
bounded product implementation within the Gemini copy is authorized by the
owner's ongoing request. Do not infer approval for model training, Azure
deployment, destructive changes, or Git publication. Preserve the frozen RF product path, experimental unfused v2 AE, and blocked rate-log1p candidate.

Use only the `gemini/product-20260924` branch in the Gemini copy. Both copies
may initially display the same branch name because their `.git` directories
were copied independently. They have separate local branch pointers. Both
refer to GitHub repository `bilaldevsec/Threatfusion`; keep `main` at the
baseline and preserve `remote.origin.pushurl=no-push://requires-explicit-review`.
The guard reduces accidental pushes; it is not GitHub branch protection.
Do not create more worktrees, change partitions, or widen the workspace.

Read root AGENTS.md, docs/product_charter.md, docs/project_status.md,
docs/issue_register.md and docs/ai_handoff_2026-09-24.md, then the affected
source, contracts and tests. User instructions take precedence over historical
handoff choices. The repository and evidence remain the source of truth.

Baseline: `d3f485aa3933fda996b8784ffe11dc54d43bbb8e`.
The owner reported successful tar source comparison and SHA-256 verification
of the project backup and external uv Python supplement on the SANDISK USB.
The USB archives remain dated recovery snapshots; they do not automatically
include later work. Do not access or change them. The owner supplied `gh run list`
output showing Backend quality run 36008647379 succeeded for baseline commit
d3f485aa3933fda996b8784ffe11dc54d43bbb8e (owner-supplied command output).

## Environment rules

The copied `.venv` is retained for the snapshot but must not be activated or used.
The independently built `threatfusion-venv` is the working environment. Its
offline build, path checks, and three focused passing tests are reported setup
evidence, not full product validation.

Sharing the existing base uv interpreter read-only is allowed; modifying the
original environment is not.

## Product boundaries

The frozen registered UNSW Random Forest (product inference path) drives product inference and alerts.
Corrected v2 AE scoring (experimental/unfused path) is experimental, separate and unfused. The two-rate
log1p experiment is BLOCKED_preserve_baseline: preparation accessed February and
all numerical gates failed. No retraining, rescoring, revived candidate,
threshold adjustment or invented accuracy claims. Do not treat the registered
replay demonstration as live Azure telemetry. Correlation requires a defensible
retained relationship key; a browser-safe dashboard is still pending. LLM and
MITRE annotations are proposed stages and do not authorize containment actions.
Keep open issues open until their documented acceptance gates are met.

Preserve ignored datasets, matrices, weights and reports. Never stage, print,
upload or paste private keys, credentials or raw data. Use one active writer.

### Repeatable working procedure
1. Inspect current instructions, source, and Git state.
2. Choose one bounded outcome.
3. Trace command inputs, output paths, and exit codes.
4. Implement the change.
5. Run meaningful tests and inspect the diff.
6. Report verified facts, limitations, and the next action. Do not pin future HEAD to the baseline after new branch commits.

At every handoff, report exact HEAD and branch, changed files, tests actually
run, failures and limits, Git state, outstanding work and the next concrete task.
Distinguish owner-reported checks from your own. Existing session authorization
persists; consult AGENTS.md and ask only for actions needing new authorization.
