---
name: threatfusion-master-engineering
version: 3.0.0
description: Unified Master Engineering Skill v3.0 for ThreatFusion: B.L.A.S.T. Architecture, Boundary Preflight B0-B5, Gate G9 AST Import-Graph Check, Tamper-Evident SOAR Hash Chain, and Non-Fused AE Queue Priority Ranker.
---

# ThreatFusion Master Engineering Skill v3.0

## 1. Constitutional Workspace Isolation (Protocol 0)
- **Active Working Workspace:** `/home/muhammad-bilal/projects/threatfusion-gemini` (branch `gemini/product-20260924`).
- **Protected Reference Workspace:** `/home/muhammad-bilal/projects/threatfusion` (strict read/write/symlink/import isolation).
- **Environment:** Run all Python and pytest commands through:
  `env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 threatfusion-venv/bin/...`
- **Frozen Models:** Under no circumstances retrain, refit, or tamper with the 4 frozen model artifacts:
  - Random Forest: `bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9`
  - Logistic Regression: `2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148`
  - Autoencoder v2: `c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23`
  - Rate-Log1p Candidate: `1d02e5bba556cb28709bd0faefce5f29da424a419a2d95332ad27a8995b26f63`
- **Issue Register Invariance:** `TF-008`, `TF-009`, `TF-010`, and `TF-011` must remain strictly **OPEN** in `docs/issue_register.md`.

## 2. Deterministic Boundary Preflight Guard (B0 through B5)
`scripts/boundary_preflight.py` and `threatfusion.evaluation.boundary_preflight`:
- **B0:** Active and protected realpaths do not overlap (`Path(os.path.realpath(p)).is_relative_to(...)`).
- **B1:** `cwd` resolves inside active workspace and outside protected workspace.
- **B2:** Active workspace contains zero symlinks resolving into protected workspace or escaping active root.
- **B3:** Virtualenv (`threatfusion-venv`) contains no `.pth`, `direct_url.json`, `.egg-link`, or symlinks to protected workspace.
- **B4:** Git metadata (`.git/objects/info/alternates`, `worktrees`, `config`) contains no reference matching `prot_re`.
- **B5:** Runtime code and config files contain no literal references to protected workspace (with regex lookahead `(?![\w\-])` preventing false positive matches on `threatfusion-gemini`).

## 3. Ground-Truth Scientific Claim Formulation
- **Recall Gain Metric:** When reporting the addition of +96 True Positives identified by the unfused v2 Autoencoder over the Random Forest baseline in January UNSW:
  - **Mathematically Exact Formulation:** `+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)`.
  - **Counterfactual Protection Shield:** Section 8 strictly disables candidate fusion because capturing those 96 extra attacks introduces **1,574 false alarms** (an 8.831x increase, 201 -> 1,775 FPs), imposing a marginal penalty of **16.396 false alarms per extra detected attack**.

## 4. Gate G9 AST Detection Import-Graph Check
- Probabilistic LLM components (`threatfusion.advisory`, `gemini_client`, `explanation_engine`) are strictly isolated from the primary detection loop.
- Automated AST inspection verifies that Stage 1-4 pipeline modules (`suricata_flow.py`, `provenance_sources.py`, `producer_inference_worker.py`, `network_inference.py`, `correlation_engine.py`) contain zero imports of advisory or LLM modules.

## 5. High-Leverage Enterprise Capabilities
- **Tamper-Evident SOAR Audit Ledger:** `SoarPlaybookSqliteRepository` maintains an immutable cryptographic SHA-256 chain (`prev_entry_sha256` + canonical entry fields -> `entry_sha256`, genesis `0` * 64) with `verify_audit_chain_integrity()` to detect any row tampering or deletion.
- **Non-Fused AE Queue Priority Ranker:** `rank_rf_alerts_for_triage_queue` orders verified Random Forest alerts (`P(Attack) >= 0.5`) by burst size, secondary v2 AE reconstruction error ratio, and RF probability, optimizing analyst triage without promoting negative flows or increasing alert volume.
