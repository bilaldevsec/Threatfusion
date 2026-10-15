# ThreatFusion Jury Requirements Traceability Registry (`TF-010`)

**Schema Identity:** `jury_traceability_matrix_v1`  
**Status:** Canonical & Audited  
**Resolution Issue:** `TF-010` (Requirements Traceability Gap)  
**Governance Authority:** Academic Jury Defense Rubric & Product Charter

---

## 1. Executive Summary & Resolution of `TF-010`

`TF-010` identified a critical academic defense gap: the lack of an immutable, authoritative repository matrix explicitly enumerating all jury-approved dataset sources, model families, and their formal dispositions. Without this matrix, silent substitutions or unverified dataset combination risks could undermine evaluation integrity.

This document, backed programmatically by `backend/src/threatfusion/models/jury_traceability.py`, establishes the formal traceability contract. Every dataset source and model family is bound to an immutable role, artifact path, contract schema, temporal/leakage boundary, and disposition status.

---

## 2. Jury Dataset Dispositions (`JURY_DATASET_DISPOSITIONS`)

| Dataset Identifier | Role | Disposition Status | Temporal Split Isolation | Artifact Reference | Contract Reference | Leakage / Evaluation Boundary |
|---|---|---|---|---|---|---|
| **`UNSW-NB15`** | Registered baseline network dataset | `APPROVED_BASELINE` | **Enforced** (Jan 2015 train/val vs Feb 2015 test) | `artifacts/data/unsw-nb15/` | `network_behavior_v1` | Strict temporal split isolation; cross-split capture/session duplicate risk documented under `TF-006`; February outcome development-informing under `TF-007`. 42 Argus features. |
| **`CIC-IDS2017`** | Cross-source evaluation candidate | `BLOCKED_SEMANTIC_MISMATCH` | N/A (Blocked) | `docs/network_feature_comparability_audit.md` | `network_behavior_v1` | Blocked for direct 42-feature cross-evaluation due to 5-byte-layer semantic mismatch and extractor divergence (Argus vs CICFlowMeter) per `TF-001`, `TF-006`, `TF-012`. |
| **`CSE-CIC-IDS2018_subset`** | Secondary network telemetry source | `REQUIRES_ISOLATED_ADAPTER` | **Enforced** | `docs/GEMINI_PROJECT_MASTER.md#section-9` | `cse_cic_ids2018_adapter_contract_v1` | Requires isolated schema adapter; cannot consume UNSW weights without explicit common byte-layer mapping and holdout protocol. |
| **`Mordor_scenarios`** | Host/security event correlation replay | `APPROVED_REPLAY_ADAPTER` | N/A (Scenario replay) | `backend/src/threatfusion/datasets/adapters/provenance_sources.py` | `mordor_scenario_event_v1` | Attack/test-only host telemetry. Cannot train anomaly/UEBA models due to zero benign baseline (`TF-004`). Dedicated `MordorScenarioAdapter` enforces replay contract. |
| **`Synthetic_UEBA`** | Controlled behavioral fallback | `LABELED_SYNTHETIC_FALLBACK` | **Enforced** | `docs/phase_0p_synthetic_training_readiness.md` | `synthetic_ueba_event_v1` | Must remain strictly labeled synthetic; cannot establish real-world host detection performance (`TF-004`). Fixture & pipeline verification only. |
| **`Authorized_Lab_Sensor`** | Operational live/lab source path | `APPROVED_SENSOR_ADAPTER` | **Enforced** (Live sensor clocks) | `backend/src/threatfusion/datasets/adapters/provenance_sources.py` | `authorized_lab_sensor_event_v1` | Requires explicit sensor registration, cryptographic mTLS identity, schema compatibility check, and clock-skew bounds (`AuthorizedLabSensorAdapter`). |

---

## 3. Jury Model Family Dispositions (`JURY_MODEL_FAMILY_DISPOSITIONS`)

| Model Family Identifier | Disposition Status | Model Artifact Path | Verified SHA-256 Digest | Contract Reference | Evaluation & Safety Boundary |
|---|---|---|---|---|---|
| **`Logistic_Regression`** | `PRESERVED_LINEAR_BASELINE` | `artifacts/models/network_logistic_baseline/full-network-logistic-5e70ed9-v1/logistic_regression.joblib` | `2cf4de6686d937c485d4dbcbfa21d3e90f65bbb922087c8b31be4b012d7fb148` | `network_logistic_baseline_v1` | Preserved linear baseline for ablation comparison. Cannot be silently removed or substituted. |
| **`Random_Forest`** | `FROZEN_PRODUCTION_BASELINE` | `artifacts/models/network_random_forest_baseline/full-network-random-forest-6d69c72-v1/random_forest.joblib` | `bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9` | `network_random_forest_baseline_v1` | Primary production inference detector. Drives alerts and correlation. Weights are frozen; zero online parameter drift permitted. |
| **`Autoencoder_v2`** | `EXPERIMENTAL_UNFUSED_ADVISORY` | `artifacts/models/network_autoencoder/full-benign-autoencoder-2a51c94-v2/autoencoder_state.pt` | `c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23` | `network_autoencoder_v2` | PyTorch reconstruction anomaly model trained on benign January UNSW rows. Calibrated threshold. Retained as unfused advisory signal; not approved for automatic containment. |
| **`Rate_Log1p_Candidate`** | `BLOCKED_PRESERVE_BASELINE` | `artifacts/models/network_rate_log1p_autoencoder/rate-log1p-autoencoder-b5e6e5d-v1/autoencoder_state.pt` | `1d02e5bba556cb28709bd0faefce5f29da424a419a2d95332ad27a8995b26f63` | `network_rate_log1p_autoencoder_v1` | Blocked candidate: preparation accessed February 2015 split rows, all four numerical gates failed (ratio 0.028). Retained as negative evidence only. |
| **`Heuristic_Statistical_Signals`** | `ENRICHMENT_SIGNALS` | N/A (Algorithmic / Rule-based) | N/A | `heuristic_signals_v1` | Payload entropy, periodic beaconing, and threat intel IOC enrichments. Auxiliary signals in dynamic risk scoring. |

---

## 4. Academic Defense & Viva Invariants

1. **Non-Substitution Invariant:** No jury-approved dataset or baseline family may be omitted, replaced, or renamed without updating this registry and providing an auditable justification.
2. **Missing-Data Invariant:** In the 7-signal dynamic risk engine (`dynamic_risk_assessment_v1`), missing evidence is never treated as benign evidence. Absent signals do not dilute an attack score toward 0.0.
3. **Zero Online Weight Drift Invariant:** The offline retraining feedback ledger (`OfflineRetrainingFeedbackRepository`, mode 0600 SQLite) records analyst triage labels (`confirmed_threat` vs `false_positive`) for future batch retraining while verifying that frozen production model hashes (`random_forest.joblib` and `autoencoder_state.pt`) remain 100% byte-identical before and after feedback admission.
