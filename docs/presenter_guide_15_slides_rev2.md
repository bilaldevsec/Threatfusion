# ThreatFusion (AI-FYP-2006) — 3-Speaker Final Defense Presenter Guide (15 Slides, Rev2)

**Course Code:** FAST-NUCES Karachi (CS492 Final Year Project - FYP-II)  
**Project ID:** `AI-FYP-2006`  
**Project Title:** AI-FYP-2006: ThreatFusion -- Mitigating Alert Fatigue in Security Operations through a Unified Threat Intelligence and Analytics Interface  
**Supervisor:** Sir Sameer Faisal  

---

## Speaker Roles & Allocation Summary

| Speaker | Name | Roll Number | Slide Range | Primary Defense Domain |
|:---:|:---|:---:|:---:|:---|
| **Speaker 1** | **Muhammad Bilal** | `21K-3551` | **Slides 1–5** (0:00–7:00) | Project Framing, UNSW Population Reconciliation, 14-Feature Contract, Frozen RF Baseline + Two-Track Live Demo Execution (`scripts/run_full_soc_demo.py`) |
| **Speaker 2** | **Muhammad Suhaib Shaikh** | `22K-4302` | **Slides 6–10** (7:00–14:00) | Core Research Objective, System Component Matrix, Inverted Split Disclosure (Retraction of 89.77%/94.95%), Autoencoder v2 Residual Audit |
| **Speaker 3** | **Muhammad Hasnain** | `22K-4718` | **Slides 11–15** (14:00–20:00) | Section 8 Alert Fatigue Invariant, FYP-I vs FYP-II Architectural Evolution, Scientific Findings, Qualified Slide 14 Pipeline, and Honest Open-Issue Defense |

---

## Slide-by-Slide Choreography & Speaking Scripts

### PART 1: SPEAKER 1 — MUHAMMAD BILAL (`21K-3551`) [Slides 1–5 + Demo]

#### Slide 1: Project Overview & Academic Metadata
- **Slide Title:** `PROJECT OVERVIEW` | `AI-FYP-2006: ThreatFusion`
- **Subtitle:** *Mitigating Alert Fatigue in Security Operations through a Unified Threat Intelligence and Analytics Interface*
- **Script (Muhammad Bilal):**
  > "Respected jury members, evaluation panel, and supervisor Sir Sameer Faisal: Welcome to our final year project defense for AI-FYP-2006, ThreatFusion.
  >
  > I am Muhammad Bilal (21K-3551), and presenting with me today are my colleagues Muhammad Suhaib Shaikh (22K-4302) and Muhammad Hasnain (22K-4718).
  >
  > In modern Security Operations Centers, analysts are overwhelmed by thousands of daily alerts, over 90% of which are false alarms. ThreatFusion is designed to solve this crisis not by piling on unverified deep learning models, but by combining a high-precision machine learning backbone, rigorous alert-fatigue defense guards, evidence-bound explanation, and approval-gated automated containment."

#### Slide 2: Population & Split Reconciliation
- **Slide Title:** `POPULATION & SPLIT RECONCILIATION`
- **Subtitle:** *Elimination of historical split inversions grounded on Evaluation Pack Rev2 (6a36dcd)*
- **Script (Muhammad Bilal):**
  > "Before presenting our results, we establish the authoritative foundation of our dataset splits under Evaluation Pack Rev2 (checkpoint 6a36dcd).
  >
  > In preliminary FYP-I work, dataset splits were inadvertently inverted. In FYP-II, we performed a complete zero-trust reconciliation against the ground-truth UNSW-NB15 records:
  > • The TRAIN population consists of 865,480 total rows (847,837 benign and 17,643 attacks). All preprocessing statistics are derived strictly from TRAIN.
  > • The January UNSW Validation set consists of 216,568 rows (4,358 attacks and 212,210 benign flows).
  > • The February development benchmark contains 1,452,844 rows.
  >
  > On January validation, our Frozen Random Forest achieves TP = 4,045, FP = 201, TN = 212,009, and FN = 313. This gives an exact Precision of 95.266%, Recall of 92.818%, F1 of 94.026%, and a False Positive Rate of only 0.095%."

#### Slide 3: 14-Feature Aligned Network Representation
- **Slide Title:** `FEATURE ARCHITECTURE`
- **Subtitle:** *Canonical 14-Feature Aligned Network Representation (network_behavior_v1)*
- **Script (Muhammad Bilal):**
  > "To ensure seamless parity between offline model training and real-time network flow processing, we engineered the canonical network_behavior_v1 feature contract.
  >
  > The schema comprises 14 transformed features: 10 numeric metrics capturing flow duration, forward and backward packet counts, bytes, transmission rates, mean packet lengths, and destination port, complemented by 4 one-hot protocol indicators for TCP, UDP, ICMP, and Other.
  >
  > Crucially, every detector executes on a strict single-record (1, 14) forward pass contract. This guarantees that live flows adapted from Suricata IDS exhibit byte-for-byte feature parity with our offline training records."

#### Slide 4: ThreatFusion Model Families & Production Boundaries
- **Slide Title:** `MODEL FAMILY ROLES`
- **Subtitle:** *ThreatFusion Model Families & Production Boundaries*
- **Script (Muhammad Bilal):**
  > "ThreatFusion strictly bounds the operational role of each model family:
  > 1. Random Forest Baseline (SHA-256 digest bd2853a6...): 100 decision trees, trained on all-TRAIN features, operating as our sole authorized production alert generator with 95.266% precision and 0.095% FPR.
  > 2. Autoencoder v2 (digest c8675d13...): A 14->8->3->8->14 deep reconstruction bottleneck with calibrated threshold 0.1181361214680695. It operates strictly as an unfused advisory signal.
  > 3. Logistic Regression (digest 2cf4de66...): Our linear reference benchmark.
  > 4. Rate-Log1p Candidate (digest 1d02e5bb...): Evaluated and formally blocked under BLOCKED_preserve_baseline after failing all 4 numerical gates."

#### Slide 5: Canonical Evaluation Pack Rev2 Benchmark Results
- **Slide Title:** `BENCHMARK METRICS`
- **Subtitle:** *Exact verified metrics on January Validation (216,568 rows, 4,358 attack / 212,210 benign)*
- **Script (Muhammad Bilal):**
  > "Slide 5 presents the canonical benchmark table across all models evaluated on January validation:
  > • Frozen Random Forest achieves 99.76% overall accuracy, 95.266% precision, and 94.026% F1, with only 201 false alarms in 212,210 benign flows.
  > • Autoencoder v2 alone achieves 54.978% precision and 49.862% F1, generating 1,628 false positives.
  > • If one naively fuses Autoencoder with Random Forest, precision collapses to 69.997% and false alarms surge to 1,775.
  > • Logistic Regression achieves 62.10% precision and 69.32% F1.
  >
  > This proves conclusively that Random Forest is the superior production alert authority."
- **Live Demo Transition:**
  > "At this point, I will trigger our turnkey two-track demonstration runner via scripts/run_full_soc_demo.py, verifying Track A (UNSW-NB15 replay proof) and Track B (Slide 14 Suricata live SOC spine). Now I hand over to Muhammad Suhaib Shaikh for the core research objectives and anomaly audit."

---

### PART 2: SPEAKER 2 — MUHAMMAD SUHAIB SHAIKH (`22K-4302`) [Slides 6–10]

#### Slide 6: The Core Research Objective: Mitigating SOC Alert Fatigue
- **Slide Title:** `CORE RESEARCH GOAL`
- **Subtitle:** *The Core Research Objective: Mitigating SOC Alert Fatigue*
- **Script (Muhammad Suhaib Shaikh):**
  > "Thank you, Bilal. Respected jury, our research objective is defined by operational reality:
  >
  > In an enterprise SOC, an alert fatigue threshold of even 1% false positive rate translates to over 2,000 false alarms every day for a modest 200,000-flow network.
  >
  > Our central research question asks: Can modern machine learning, threat intelligence, and evidence-bound explanation measurably reduce alert fatigue without allowing real attacks to slip through? We answer this through high precision (0.095% FPR), the Section 8 fusion guard, and our Section 13.F workload reduction shield."

#### Slide 7: ThreatFusion Architecture & Component Matrix
- **Slide Title:** `SYSTEM COMPONENTS`
- **Subtitle:** *ThreatFusion Architecture & Component Matrix*
- **Script (Muhammad Suhaib Shaikh):**
  > "Rather than relying on black-box sequence models, ThreatFusion is engineered as a coordinated 5-component SOC defense spine:
  > 1. Primary Alert Authority: Frozen Random Forest generating calibrated alerts.
  > 2. Unfused Anomaly Signal: Autoencoder v2 providing reconstruction residual context.
  > 3. Sourced Threat Intel: Section 13.C with private-IP RFC1918 guard.
  > 4. Grounded Advisory: Section 13.D LLM debrief with deterministic fallback.
  > 5. Reversible SOAR Ledger: Section 13.E approval-gated containment engine."

#### Slide 8: Scientific Disclosure: Resolving the Legacy Inverted Split
- **Slide Title:** `INVERTED SPLIT DISCLOSURE`
- **Subtitle:** *Scientific Disclosure: Resolving the Legacy Inverted Split*
- **Script (Muhammad Suhaib Shaikh):**
  > "We believe true academic rigor demands complete transparency. In earlier FYP-I draft slides, training and test partitions were swapped—82,332 records were used for training and 175,341 for testing. That flawed split yielded artificial numbers: 89.77% RF accuracy and a speculative 94.95% multimodal fusion claim.
  >
  > In Evaluation Pack Rev2, we formally retracted those figures. Under the reconciled ground-truth (865,480 training and 216,568 January validation), Random Forest actually achieves 94.026% F1 and 99.76% accuracy, while speculative automatic fusion fails the false-positive threshold."

#### Slide 9: Canonical Binary Detection Evaluation on January UNSW Validation
- **Slide Title:** `BENCHMARK EVALUATION`
- **Subtitle:** *Canonical Binary Detection Evaluation on January UNSW Validation*
- **Script (Muhammad Suhaib Shaikh):**
  > "Slide 9 examines the false positive dynamics in detail. Across 212,210 benign January flows, Random Forest produces only 201 false alarms (0.095% FPR).
  >
  > In contrast, Autoencoder v2 produces 1,628 false positives (0.767% FPR). Fusing the two produces 1,775 false positives—an 8.8308x inflation.
  >
  > In real SOC operations, an 8.83x increase in false alarms paralyzes the tier-1 analyst team."

#### Slide 10: Autoencoder Reconstruction Error & Rate-Feature Skew
- **Slide Title:** `ABERRATION ANALYSIS`
- **Subtitle:** *Autoencoder Reconstruction Error & Rate-Feature Skew*
- **Script (Muhammad Suhaib Shaikh):**
  > "Why does the Autoencoder produce so many false alarms? We performed an empirical residual analysis (january-v2-record-concentration-b5e6e5d).
  >
  > The data reveals that Rate Features (packets_per_second and bytes_per_second) drive 93.784% of reconstruction error in gained attacks and 38.748% in benign false positives. High-throughput benign file transfers trigger huge reconstruction errors because rate distributions have massive variance.
  >
  > When we tested a log1p-transformation (rate-log1p candidate), the model collapsed: attack recall plunged from 92.818% down to 21.684% (only 945 attacks detected). The candidate was formally blocked.
  >
  > I now hand over to Muhammad Hasnain to present our Section 8 defense invariant, Slide 14 live architecture, and open issues."

---

### PART 3: SPEAKER 3 — MUHAMMAD HASNAIN (`22K-4718`) [Slides 11–15]

#### Slide 11: The Core Defense Pillar: Why Automatic Fusion Is Disabled
- **Slide Title:** `CORE DEFENSE PILLAR`
- **Subtitle:** *The Core Defense Pillar: Why Automatic Fusion Is Disabled*
- **Script (Muhammad Hasnain):**
  > "Thank you, Suhaib. Slide 11 is the mathematical cornerstone of our defense.
  >
  > If we enable automatic OR-fusion between Random Forest and Autoencoder:
  > • We gain +96 extra attacks: +2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045).
  > • But we inflict +1,574 additional false alarms—an 8.8308x false-positive inflation.
  > • The marginal penalty is 16.3958 benign false alarms for every single additional attack caught.
  > • Precision collapses by 25.269 percentage points from 95.266% down to 69.997%.
  >
  > Section 8 of our product charter establishes this immutable law: production_fusion_enabled is strictly False. Disabling fusion is not a limitation—it is a deliberate, mathematically proven shield against alert fatigue."

#### Slide 12: Comprehensive Progress: FYP-I vs ThreatFusion FYP-II Architectural Evolution
- **Slide Title:** `COMPREHENSIVE PROGRESS`
- **Subtitle:** *FYP-I vs ThreatFusion FYP-II: Architectural Evolution*
- **Script (Muhammad Hasnain):**
  > "Slide 12 contrasts preliminary FYP-I exploratory work against our production-grade FYP-II architecture:
  > • Split Integrity: Inverted 82k/175k split retracted -> Reconciled Rev2 (865k Train, 216k Jan, 1.45M Feb).
  > • Alert Authority: Uncalibrated RF (89.77%) -> Frozen RF (94.026% F1, 95.266% precision, 0.095% FPR).
  > • Anomaly & Fusion: Unverified 94.95% claim retracted -> Unfused AE v2 (threshold 0.1181361214680695); Section 8 fusion disabled.
  > • Fatigue Mitigation: None -> Section 13.F Workload Shield (8.8308x false alarm reduction).
  > • Ingestion: Static CSVs -> Slide 14 Suricata Flow Adapter (14 canonical features) + loopback mTLS.
  > • Modern SOC Operations: None -> Section 13.C RFC1918 Intel Guard + 13.E Reversible SOAR Ledger."

#### Slide 13: Key Scientific Findings & Defense Takeaways
- **Slide Title:** `KEY SCIENTIFIC FINDINGS`
- **Subtitle:** *Core Scientific Findings & Defense Takeaways*
- **Script (Muhammad Hasnain):**
  > "Our research yields four definitive scientific conclusions:
  > 1. High Precision Beats Complex Fusion: A precision-tuned Random Forest (0.095% FPR) vastly outperforms deep multimodal ensembles in false-alarm suppression.
  > 2. The Fusion Fatigue Penalty: Multimodal anomaly fusion imposes a 16.3958:1 false alarm penalty.
  > 3. Defense in Depth: Evidence-bound explanation and approval-gated SOAR convert raw alerts into actionable intelligence.
  > 4. Zero-Trust Verification: Our deterministic truth audit gate (scripts/audit_repo_truth.py) guarantees 100% cryptographic reproducibility."

#### Slide 14: Verified Azure VM Live-Ingestion & Modern SOC Pipeline
- **Slide Title:** `LIVE SYSTEM ARCHITECTURE`
- **Subtitle:** *Verified Azure VM Live-Ingestion & Modern SOC Pipeline*
- **Badge:** BOUNDED RECORDED/LOCAL INTEGRATION PATH VERIFIED (16/16 TEST GATES); LIVE AZURE/SIEM DEPLOYMENT OPEN (TF-011)
- **Footer:** Repository software spine (Suricata eve.json -> 14 features -> loopback mTLS 1.3 -> Frozen RF -> Correlation -> RFC1918 Threat-Intel -> Advisory -> Reversible SOAR) is verified by automated integration tests (test_slide14_suricata_live_ingestion_path.py); live Azure VM / production SIEM field deployment remains unverified and open under TF-011.
- **Script (Muhammad Hasnain):**
  > "Slide 14 documents our live system architecture. The 5-stage software spine is fully implemented and passes all 16 automated integration test gates (test_slide14_suricata_live_ingestion_path.py):
  > 1. Attacker VM (10.0.0.4) executing controlled Nmap and HTTP probes.
  > 2. Victim VM (10.0.0.5) passively capturing flows via Suricata to eve.json.
  > 3. SuricataFlowAdapter transforming JSON events into canonical 14 features with verified EntityProvenanceContract.
  > 4. Mutual TLS 1.3 listener admitting flows with anti-replay journal deduplication.
  > 5. ThreatFusion Backend executing frozen RF inference, dual-window incident correlation (30-second burst window [30s] / 10-minute campaign window [600s]), advisory debrief, and reversible SOAR.
  >
  > Expanded modern SOC integration incorporates ChromaDB Semantic RAG over 10 canonical MITRE ATT&CK techniques, MISP threat intelligence with RFC1918 suppression, TheHive v4/v5 case management, and deterministic n8n webhook playbook execution with cryptographic HMAC-SHA256 signatures, server-side ledger state verification, and anti-replay protection.
  >
  > In accordance with our zero-trust charter, we explicitly distinguish between this verified local/recorded software spine and live cloud field telemetry: live Azure VM / production enterprise SIEM deployment remains an honest, tracked limitation under TF-011."

#### Slide 15: Conclusion, Defense Summary & Open Issue Honesty
- **Slide Title:** `DEFENSE SUMMARY`
- **Subtitle:** *Questions & Academic Defense*
- **Script (Muhammad Hasnain):**
  > "In conclusion, ThreatFusion proves that machine learning can solve SOC alert fatigue when bounded by scientific discipline.
  >
  > Our architecture is comprehensively hardened with ChromaDB Semantic Vector RAG over MITRE ATT&CK, ledger-backed n8n/TheHive/MISP stack integration, continuous 14-feature PSI telemetry drift monitoring, frozen model supply-chain verification, and a comprehensive STRIDE threat model across all 8 pipeline stages.
  >
  > In strict accordance with our repository truth audit gate, four issues remain honestly OPEN:
  > • TF-008 (open): Independent holdout benchmark beyond inspected Jan/Feb splits (e.g. CIC-IDS2017).
  > • TF-009 (open): Measured analyst workload reduction in controlled human trials (requiring >= 10 human subjects).
  > • TF-010 (open): External signed FAST-NUCES evaluation rubric.
  > • TF-011 (open): Real operational SIEM enterprise production source proof.
  >
  > We thank our supervisor Sir Sameer Faisal and the evaluation panel, and we welcome your questions."

---

## 4. Key Defense Q&A Talking Points

### Q1: Why did you disable automatic multimodal fusion?
- **Answer (Muhammad Hasnain):** "Automatic fusion gains only 96 additional attacks on January validation, but unleashes 1,574 new false alarms (an 8.8308x inflation). That means analysts must investigate 16.3958 false alarms for every single extra attack caught. Under Section 8 of our product charter, production_fusion_enabled is permanently False."

### Q2: Why were earlier project numbers (89.77% RF, 94.95% Fusion) retracted?
- **Answer (Muhammad Suhaib Shaikh):** "Those preliminary figures were produced by an inverted split (82k train / 175k test). In Evaluation Pack Rev2, we reconciled against the authoritative ground truth (865,480 Train, 216,568 Jan Validation). Under the true split, Random Forest actually achieves 94.026% F1 and 95.266% precision. We retracted the flawed figures rather than defending an erroneous split."

### Q3: Is Slide 14 verified on a live cloud environment or on local/recorded telemetry?
- **Answer (Muhammad Bilal):** "The complete 5-stage software spine is fully implemented and verified across 16 integration tests using real recorded Suricata flows and loopback mTLS 1.3. However, live Azure VM cloud telemetry remains open under TF-011 because enterprise deployment was outside the bounded prototype scope."
