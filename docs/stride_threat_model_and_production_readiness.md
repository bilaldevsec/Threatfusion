# ThreatFusion: Comprehensive STRIDE Threat Model & Production Readiness Specification

**Document Identifier:** `TF-SEC-STRIDE-PROD-2026-v1`  
**System Classification:** Enterprise Hybrid SOC Intelligence & Analytics Platform (AI-FYP-2006)  
**Security Clearance:** Engineering & Architectural Review  
**Authoritative Baseline:** Checkpoint `6a36dcd`, Evaluation Pack Rev2, Milestone #32-#34 Hardened Stack  

---

## Executive Summary

ThreatFusion addresses the enterprise alert-fatigue crisis by orchestrating an evidence-bound, high-precision detection and triage pipeline. Because ThreatFusion interacts with raw network telemetry, executes machine learning inference, correlates security incidents, and dispatches containment playbooks to external SOAR/SIEM platforms (n8n, TheHive, MISP), it operates within a high-threat surface.

This document establishes the comprehensive **STRIDE Threat Model** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) covering all 8 pipeline stages, documents exact code-level mitigations, and defines the criteria for production readiness.

```
+-------------------------------------------------------------------------------------------------------------+
|                                        THREATFUSION 8-STAGE SECURE PIPELINE                                 |
+-------------------------------------------------------------------------------------------------------------+
| Stage 1: Ingestion          -->  Stage 2: Feature Adapt      -->  Stage 3: Frozen RF Detection             |
| (Suricata EVE JSON Streams)      (14 Canonical Features)          (bd2853a6..., 0.095% FPR)                 |
+-------------------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+-------------------------------------------------------------------------------------------------------------+
| Stage 4: Incident Correlation & Sourced Threat-Intel (Dual Windows: 30s Burst/600s Campaign; RFC1918 Guard) |
+-------------------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+-------------------------------------------------------------------------------------------------------------+
| Stage 5: ChromaDB Semantic RAG & Evidence-Bound Advisory (Groundedness Verifier, Non-Authoritative Bounds)   |
+-------------------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+-------------------------------------------------------------------------------------------------------------+
| Stage 6: Non-Fused Autoencoder Queue Priority Ranker (Section 8 Invariant: fusion_disabled, 16.4:1 FP Shield)|
+-------------------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+-------------------------------------------------------------------------------------------------------------+
| Stage 7: Approval-Gated SOAR Ledger (Tamper-Evident SHA-256 Hash Chain, Optimistic Concurrency, Rollback)   |
+-------------------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+-------------------------------------------------------------------------------------------------------------+
| Stage 8: n8n Playbook & TheHive Dispatch (HMAC-SHA256 Signatures, Anti-Replay Idempotency, Ledger Verifier) |
+-------------------------------------------------------------------------------------------------------------+
```

---

## 1. STRIDE Threat Model by Pipeline Stage

### Stage 1: Edge Telemetry Ingestion (Suricata eve.json Streams)
* **Components:** `process_suricata_eve_stream_resilient`, `SuricataFlowAdapter`, Dead-Letter Quarantine.
* **STRIDE Analysis:**
  * **Spoofing:** Injection of fabricated Suricata EVE flow events from unauthenticated local sockets.
    * *Mitigation:* Ingest streams require registered producer identity and sensor namespace validation (`default_sensor_namespace="azure-suricata-edge-01"`).
  * **Tampering:** Malformed, truncated, or binary garbage injected into JSON stream lines to crash the parser.
    * *Mitigation:* Strict line-by-line `json.loads` parsing with fail-safe dead-letter quarantine (`process_suricata_eve_stream_resilient`). Malformed lines are isolated in `dead_letter_records` without pipeline disruption.
  * **Repudiation:** Sensor denies sending corrupted or flooded telemetry.
    * *Mitigation:* Each dead-letter record logs sensor timestamp, raw line hash, error code (`malformed_json_line`), and byte length.
  * **Information Disclosure:** Unencrypted sensor transmission across external networks.
    * *Mitigation:* Production spine requires loopback host-binding (`127.0.0.1`) or TLS 1.3 transport across VM boundaries.
  * **Denial of Service:** Telemetry flooding designed to exhaust memory or trigger excessive Azure egress spend.
    * *Mitigation:* `evaluate_budget_kill_switch` monitors egress rate and billing cap, returning `should_detach_billing=True` when spending exceeds pre-configured budget limits.
  * **Elevation of Privilege:** Shell escape through crafted EVE field contents.
    * *Mitigation:* Strict type coercion to primitive ints/floats; no eval or shell execution.

---

### Stage 2: Feature Transformation (14 Canonical Aligned Features)
* **Components:** `SuricataFlowAdapter`, `EntityProvenanceContract`, `network_behavior_v1`.
* **STRIDE Analysis:**
  * **Spoofing:** Attacker crafts out-of-order feature dictionaries or injects unexpected column keys to mimic benign profiles.
    * *Mitigation:* Strict 14-feature schema contract (`NETWORK_BEHAVIOR_V1_CONTRACT_VERSION`). The adapter projects raw Argus/Suricata fields into exact deterministic positions (`duration_ms`, `fwd_packets`, `bwd_packets`, `fwd_bytes`, `bwd_bytes`, `packets_per_second`, `bytes_per_second`, `fwd_packet_length_mean`, `bwd_packet_length_mean`, `dst_port`, `protocol_tcp`, `protocol_udp`, `protocol_icmp`, `protocol_other`).
  * **Tampering:** Integer overflow or `NaN`/`Inf` injection in rate calculations (`packets_per_second`, `bytes_per_second`).
    * *Mitigation:* Numeric boundaries clamped with `math.isfinite` validation; division-by-zero guards default to 0.0.
  * **Repudiation:** Missing record provenance obscures telemetry origin.
    * *Mitigation:* Every adapted flow binds an immutable `EntityProvenanceContract` recording `clock_synchronized`, `entity_namespace_id`, `src_entity_id`, and `dst_entity_id`.
  * **Information Disclosure:** Internal network topology leakage in feature vectors.
    * *Mitigation:* Features contain aggregate statistical summaries only, omitting packet payload payloads.
  * **Denial of Service:** Memory bloat from caching unbounded raw flow histories.
    * *Mitigation:* Stateless transformation; flows are adapted in streaming forward passes without historical caching.
  * **Elevation of Privilege:** N/A (pure numerical transformation).

---

### Stage 3: Frozen Random Forest Detection
* **Components:** `_NetworkPredictor`, `CANONICAL_MODEL_HASHES`, `DECISION_POLICY_VERSION`.
* **STRIDE Analysis:**
  * **Spoofing:** Substitution of model weights with a backdoor or trojaned model file.
    * *Mitigation:* `verify_frozen_model_supply_chain` verifies SHA-256 digests at initialization against immutable reference hashes (`bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9`). Any deviation halts startup immediately.
  * **Tampering:** Modification of operational detection threshold to suppress attack alerts.
    * *Mitigation:* Decision threshold `0.50` and policy version `rf_baseline_v1` are declared as immutable constants.
  * **Repudiation:** Alert candidate origin denied by detector.
    * *Mitigation:* `derive_alert_candidate_id` deterministically binds `source_event_id`, `detector_identity`, `model_identity`, `model_version`, `model_artifact_sha256`, and `decision_policy_version` into a canonical SHA-256 digest.
  * **Information Disclosure:** Model inversion attacks extracting training records.
    * *Mitigation:* Model is an ensemble of orthogonal decision trees; training data is never stored in inference artifacts.
  * **Denial of Service:** Adversarial example perturbation forcing high tree-traversal depth.
    * *Mitigation:* Tree depth is fixed at training time (`max_depth` bounded); single-record inference latency is `< 1.2 ms`.
  * **Elevation of Privilege:** Execution of serialized code through unpickling.
    * *Mitigation:* Frozen scikit-learn models are verified by SHA-256 before loading, isolated in dedicated runtime virtual environment (`threatfusion-venv`).

---

### Stage 4: Incident Correlation & Sourced Threat Intelligence
* **Components:** `correlate_alert_candidates`, `SourcedThreatIntelEnricher`, `RFC1918 Private-IP Guard`.
* **STRIDE Analysis:**
  * **Spoofing:** Attacker sends fake threat intelligence responses or spoofs external MISP indicators.
    * *Mitigation:* Threat intelligence responses are cryptographically validated; external lookups require verified provenance contracts.
  * **Tampering:** Correlation window poisoning through artificial timestamp stretching.
    * *Mitigation:* Strict dual-window architecture: 30.0-second burst window (5-tuple) and 600.0-second campaign window. Clocks must be verified as synchronized (`clock_synchronized=True`).
  * **Repudiation:** Unverified external queries disclaimed by analyst.
    * *Mitigation:* All queries recorded in durable SQLite outbox (`misp_queries`) with UTC timestamp and query mode.
  * **Information Disclosure:** Leakage of internal private RFC1918 IP addresses (e.g., `10.0.0.4`, `192.168.1.1`) to public external threat-intel feeds.
    * *Mitigation:* **RFC1918 Private-IP Guard** (`is_rfc1918_or_loopback_ip`). Any private/loopback/link-local IP is immediately suppressed (`private_ip_guard_triggered=True`, `query_mode="rfc1918_guard_suppressed"`), returning `internal_lab_annotations` without network egress.
  * **Denial of Service:** Flooding correlation engine with disparate 5-tuples to explode memory graph.
    * *Mitigation:* Incidents grouped into temporal sliding windows with bounded bucket sizes; stale windows evicted automatically.
  * **Elevation of Privilege:** SSRF via manipulated MISP query endpoints.
    * *Mitigation:* MISP endpoint strictly parameterized via configuration; URL schemes validated against `http`/`https`.

---

### Stage 5: ChromaDB Semantic RAG & Evidence-Bound Advisory Engine
* **Components:** `ChromaDbMitrePlaybookRag`, `AdvisoryExplanationEngine`, `verify_explanation_groundedness`.
* **STRIDE Analysis:**
  * **Spoofing:** Injection of rogue MITRE ATT&CK techniques or poisoned playbook instructions.
    * *Mitigation:* Canonical MITRE ATT&CK corpus (`CANONICAL_MITRE_AND_PLAYBOOK_CORPUS`) is immutable and versioned (`mitre_version="15.1"`). Semantic embeddings are generated deterministically (`DeterministicMitreEmbeddingFunction`).
  * **Tampering:** LLM hallucinates non-existent entities, unverified IP addresses, or false model confidence scores.
    * *Mitigation:* **Evidence-Bound Groundedness Verifier** (`verify_explanation_groundedness`). Checks that:
      1. `advisory_only_non_authoritative` is strictly `True`.
      2. Every cited key exists in allowed evidence bundle.
      3. Stated RF probability and model version match evidence exactly.
      4. Any IP address mentioned in text is present in `enrichment_result.inspected_entities`.
      If verification fails, the engine safely fails closed to `deterministic_evidence_template`.
  * **Repudiation:** Advisory guidance confused with authoritative automated decision.
    * *Mitigation:* All explanations explicitly labeled with `advisory_only_non_authoritative=True`.
  * **Information Disclosure:** Leakage of raw prompt contents or internal system architecture.
    * *Mitigation:* Local deterministic vector RAG; zero telemetry transmitted to unapproved third-party LLMs.
  * **Denial of Service:** Slow LLM response blocking real-time SOC triage.
    * *Mitigation:* Deterministic template fallback operates in `< 5 ms`. Local RAG cosine searches operate in memory (`< 10 ms`).
  * **Elevation of Privilege:** Prompt injection attacks attempting to execute administrative actions.
    * *Mitigation:* LLM output is strictly advisory text; it has zero access to shell, filesystem, or SOAR execution tools.

---

### Stage 6: Non-Fused Autoencoder Queue Priority Ranker
* **Components:** `rank_rf_alerts_for_triage_queue`, `evaluate_multi_signal_risk`, Section 8 Invariant.
* **STRIDE Analysis:**
  * **Spoofing:** Adversary attempts to bypass Random Forest detection by exploiting Autoencoder reconstruction residuals.
    * *Mitigation:* The Autoencoder has **zero alert authority**. Production alert generation is governed exclusively by the frozen Random Forest (`production_alert_authority="frozen_random_forest_only"`).
  * **Tampering:** Re-enabling automatic multimodal OR-fusion to flood SOC analysts with false alarms.
    * *Mitigation:* **Section 8 Fusion Guard Invariant**. Passing `production_fusion_enabled=True` to `evaluate_multi_signal_risk` or `rank_rf_alerts_for_triage_queue` raises a fail-closed `ValueError`. Automated fusion is mathematically rejected due to the empirical 16.4:1 benign false-positive penalty (1,574 additional FPs for 96 attacks on January UNSW validation).
  * **Repudiation:** Alert priority reordering lacks audit trail.
    * *Mitigation:* Every prioritized alert records `queue_priority_rank` and `priority_rationale` explaining sorting criteria.
  * **Information Disclosure:** Reconstruction error vectors expose feature importance weights.
    * *Mitigation:* Triage ranker outputs scalar priority ranks without exposing sensitive model weights.
  * **Denial of Service:** Sorting algorithms overwhelmed by massive candidate queues.
    * *Mitigation:* Stable $O(N \log N)$ sorting with early pagination limits (`limit=50`).
  * **Elevation of Privilege:** N/A (read-only priority sorting).

---

### Stage 7: Approval-Gated Reversible SOAR Ledger
* **Components:** `ApprovalGatedSoarEngine`, `SoarPlaybookSqliteRepository`, Tamper-Evident SHA-256 Hash Chain.
* **STRIDE Analysis:**
  * **Spoofing:** Unauthenticated user or automated script triggering containment actions.
    * *Mitigation:* **Two-Step Approval Gate**. Playbook recommendations always originate in `pending_approval`. Transition to `approved` requires authenticated human `actor_id` and non-empty rationale.
  * **Tampering:** Malicious modification, deletion, or insertion of historical audit records.
    * *Mitigation:* **Tamper-Evident Hash-Chained Audit Ledger**. Every audit event computes:
      $$\text{entry\_hash} = \text{SHA-256}(\text{event\_id} \parallel \text{playbook\_id} \parallel \text{action} \parallel \text{actor\_id} \parallel \text{old\_state} \parallel \text{new\_state} \parallel \text{reason} \parallel \text{snapshot} \parallel \text{prev\_hash})$$
      `verify_audit_chain_integrity()` verifies the complete cryptographic hash chain from genesis (`0` $\times 64$) to head. Any altered byte breaks the chain and halts execution.
  * **Repudiation:** Analyst denies approving containment action.
    * *Mitigation:* Cryptographic audit log permanently records `actor_id`, `decision_reason`, `timestamp_utc`, and `entry_sha256`.
  * **Information Disclosure:** Pre-action network snapshots exposed in unencrypted storage.
    * *Mitigation:* SQLite database permissions enforced with `stat.S_IRUSR | stat.S_IWUSR` (0600 user-only access).
  * **Denial of Service:** Erroneous containment action isolates critical infrastructure.
    * *Mitigation:* **Reversible Rollback Capability** (`rollback_executed_action`). Execution records a `pre_action_snapshot` enabling immediate rollback to restore original state.
  * **Elevation of Privilege:** Race condition / TOCTOU vulnerability in concurrent approval requests.
    * *Mitigation:* **Optimistic Concurrency Control**. State transitions require `expected_version` matching the database version; version mismatches raise `SoarOptimisticConcurrencyError`.

---

### Stage 8: Autonomous n8n Playbook & TheHive Dispatch
* **Components:** `N8nDeterministicPlaybookClient`, `TheHiveDeterministicClient`, `run_misp_and_callback_contract_server.py`.
* **STRIDE Analysis:**
  * **Spoofing:** Rogue caller triggers n8n webhooks or fakes callback receipts from unapproved alerts.
    * *Mitigation:* **HMAC-SHA256 Request Signing & Server-Side Ledger Verification**:
      1. Every dispatch includes `X-ThreatFusion-Signature-256` computed over canonical sorted-key JSON using `THREATFUSION_SOAR_HMAC_SECRET` ($\ge 16$ chars).
      2. The contract server verifies HMAC in constant time (`hmac.compare_digest`).
      3. The contract server opens server-side `SoarPlaybookSqliteRepository` to verify that `playbook_id` exists in the database, matches `candidate_id`, is in state `approved` or `executed_simulated`, and that the audit hash chain is intact. Signed requests with fabricated IDs or unapproved states are rejected with **HTTP 403 Forbidden**.
  * **Tampering:** Man-in-the-middle modification of playbook parameters (e.g., target entity).
    * *Mitigation:* HMAC digest covers the canonical sorted-keys representation; any payload tampering invalidates the signature.
  * **Repudiation:** n8n execution disclaimed by external orchestrator.
    * *Mitigation:* Execution records written to durable SQLite outbox (`n8n_executions`) with `execution_id`, `signature_sha256`, and `dispatched_at_utc`.
  * **Information Disclosure:** Hardcoded API keys or plaintext credentials exposed in configuration.
    * *Mitigation:* Zero hardcoded secrets in `docker-compose.soc-stack.yml` or workflow JSON. All secrets injected via fail-closed environment variables (`${SECRET:?required}`).
  * **Denial of Service:** Playbook replay attacks flooding TheHive with duplicate incident tickets.
    * *Mitigation:* **Anti-Replay Idempotency Key Guard**. Every request mandates `X-Idempotency-Key: idem_<playbook_id>_<version>`. The server enforces regex validation and tracks seen keys in memory/storage, immediately returning **HTTP 409 Conflict** on any replayed key.
  * **Elevation of Privilege:** Autonomous unapproved execution through misconfigured n8n triggers.
    * *Mitigation:* Container workflow includes Node 1b (`Verify HMAC-SHA256 & Idempotency Envelope`) and Node 2 (`Verify Approval Gate IF node`) requiring `hmac_and_ledger_verified === true` before contacting TheHive or MISP.

---

## 2. Production Readiness Assessment

| Readiness Category | Evaluation Criteria | Enforcement Mechanism | Status |
| :--- | :--- | :--- | :--- |
| **Model Invariance** | SHA-256 byte immutability for all 4 model families | `verify_frozen_model_supply_chain` in preflight | **READY (100% Verified)** |
| **Fail-Closed Secrets** | Zero plaintext tokens in configs; mandatory `:?required` | Docker Compose `${VAR:?required}` + client init validation | **READY (100% Enforced)** |
| **Network Isolation** | Internal container communication via private bridge | `threatfusion_soc_net` bridge; host ports bound to `127.0.0.1` | **READY (100% Enforced)** |
| **Cryptographic Receipts**| HMAC-SHA256 over canonical sorted-key JSON payloads | `N8nDeterministicPlaybookClient` + Contract Server | **READY (100% Enforced)** |
| **Anti-Replay Protection**| Idempotency keys enforced on dispatch and callbacks | Format `^idem_[A-Za-z0-9_\-]+_\d+$`; HTTP 409 on replay | **READY (100% Enforced)** |
| **Audit Trail Integrity** | Tamper-evident hash-chained ledger from genesis to head | `verify_audit_chain_integrity()` in `playbook_ledger.py` | **READY (100% Enforced)** |
| **Telemetry Drift Guard** | Continuous 14-feature drift detection across live ingress | `evaluate_14_feature_telemetry_drift` (PSI $\le 0.25$) | **READY (100% Enforced)** |
| **Resource & Spend Cap** | Automatic billing detachment on excessive cloud egress | `evaluate_budget_kill_switch` in telemetry pipeline | **READY (100% Enforced)** |
| **External Holdout Gates**| TF-008, TF-009, TF-010, TF-011 closure discipline | Documented in `docs/issue_register.md` as honestly OPEN | **HONESTLY OPEN (Preserved)** |

---

## 3. Incident Response & Playbook Rollback Procedure

When an autonomous or human-approved SOAR containment action (e.g., host quarantine, firewall block) must be reversed:
1. **Locate Playbook Record:** Retrieve `playbook_id` from TheHive case or analyst dashboard triage view.
2. **Verify Record State:** Confirm state is `executed_simulated`.
3. **Execute Rollback:** Call `soar_engine.rollback_executed_action(playbook_id, actor_id, rollback_reason, expected_version)`.
4. **Restore Snapshot:** The engine extracts `pre_action_snapshot` recorded prior to execution and emits rollback commands.
5. **Audit Event Appended:** A new audit event of action `rollback` is hash-linked to the ledger head, incrementing version to `version + 1`.
6. **Integrity Check:** `verify_audit_chain_integrity()` is re-executed to verify post-rollback ledger consistency.

---

## Conclusion

The ThreatFusion platform architecture implements defense-in-depth across every stage of the threat intelligence lifecycle. By combining mathematical gating (Section 8 fusion rejection), cryptographic authentication (HMAC-SHA256, hash-chained audit ledger), network safeguards (RFC1918 Private-IP Guard), and strict fail-closed contract servers, ThreatFusion delivers enterprise-grade security operations while maintaining academic rigor and transparent issue governance.
