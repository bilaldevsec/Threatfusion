# ThreatFusion (AI-FYP-2006) — Complete Technical History, Evolution & Architecture Bible

**Project Title:** Mitigating Alert Fatigue in Security Operations through a Unified Threat Intelligence and Analytics Interface (`AI-FYP-2006`)
**Institution:** FAST-NUCES Karachi Campus (CS492 Final Year Project — FYP-II)
**Team:** Muhammad Bilal (`21K-3551`), Muhammad Suhaib Shaikh (`22K-4302`), Muhammad Hasnain (`22K-4718`)
**Supervisor:** Sir Sameer Faisal
**Active Repo:** `/home/muhammad-bilal/projects/threatfusion-gemini` (Branch: `gemini/product-20260924`)
**Protected Reference Repo (NEVER TOUCH):** `/home/muhammad-bilal/projects/threatfusion`

## 1. Chronological Evolution (Era 1 to Era 5)
1. Era 1 — Classical ML Baseline: 14 canonical network flow features (`dur`, `spkts`, `dpkts`, `sbytes`, `dbytes`, `rate`, `sload`, `dload`, `smean`, `dmean`, `sloss`, `dloss`, `service`, `state`). Frozen Random Forest (`bd2853a6...`) achieved TP=4,045, FP=201, TN=212,009, FN=313 (95.266% Precision, 92.818% Recall, 94.026% F1, 0.095% FPR).
2. Era 2 — Deep Learning Autoencoder & Section 8 Complementarity: Corrected v2 Benign Autoencoder (`c8675d13...`) trained on 847,837 benign TRAIN rows with threshold 0.1181361214680695. Proved OR-fusion inflates FPs by 8.831x (201 -> 1,775), dropping precision to 70.00%. Locked `production_fusion_enabled = False`. Frozen RF is sole alert authority; v2 AE is strictly a secondary triage queue ranker (+2.203 pp recall gain).
3. Era 3 — FYP-II Progress Pack: Loopback mTLS 1.3 `ProducerTlsListener`, attack-only SQLite alert persistence, SHA-256 wire-identical replay protection.
4. Era 4 — Hardened Analyst Boundary: `analyst_tls_service.py`, `analyst_browser_tls_service.py`, `analyst_security_audit.py` (fail-closed HTTP 503 on audit write failure), `human_credentials.py` (mode 0700, DER SHA-256 matching).
5. Era 5 — Full-Stack SOC Appliance: Live Suricata 14-feature extraction (`suricata_flow.py`), 30s/600s campaign correlation, `MispDeterministicClient` (with RFC1918 private-IP leak guard returning HTTP 422), `ChromaDbMitrePlaybookRag`, `GeminiAdvisoryCallable` ($5.00 budget cap) + `verify_explanation_groundedness()`, `soar.sqlite3` hash chain, n8n 6-node workflow, TheHive 5 cases, and the 3-Layer SecOps UI (#090D16 obsidian, #111827 slate glass, 5-Tab Inspector).

## 2. Honest Open External Gates (Keep Strictly open)
- TF-008: Untouched chronological holdout.
- TF-009: Independent benchmark beyond UNSW-NB15.
- TF-010: Live multi-host enterprise capture.
- TF-011: Prospective human SOC analyst study.
