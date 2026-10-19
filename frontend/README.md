# ThreatFusion SOC Unicorn Web Console & Interactive Walkthrough Bundle

**Document Identifier:** `README-FRONTEND-UNICORN-001`  
**Revision:** 1.0.0  
**Project:** ThreatFusion (`AI-FYP-2006`)  
**Standard:** `design_guidelines/soc_unicorn_interface_sop.md` (`SOP-UX-SOC-001`)  
**Architecture:** Zero-CDN, 100% Offline Air-Gapped Glassmorphic Dark Console  

---

## 1. Overview & Architecture

The **ThreatFusion SOC Unicorn Web Console** provides the production-grade, human-in-the-loop analyst presentation layer for the ThreatFusion intrusion detection and autonomous response pipeline. 

Designed specifically for air-gapped academic defense laboratories and high-security enterprise environments:
- **Zero External Dependencies:** Contains 0 external CDN links, web fonts, or remote JavaScript libraries. Works 100% offline from the local filesystem or air-gapped container networks.
- **Progressive Disclosure Visual Hierarchy (`SOP-UX-SOC-001`):** Resolves operational alert fatigue by dividing telemetry into 3 distinct cognitive tiers:
  1. **Tier 1 (Instant Glance / < 3s):** Authoritative Frozen Random Forest verdict (`P(Attack) >= 0.50`, 95.266% precision, 0.095% FPR).
  2. **Tier 2 (Investigative Dive / < 30s):** Dual-window incident correlation (30s burst / 600s campaign), verified sensor provenance, RFC1918 Private-IP Guard, and secondary non-fused Autoencoder reconstruction error.
  3. **Tier 3 (Synthesis & Action / < 60s):** Grounded advisory debrief, ChromaDB 64-dim L2-normalized MITRE ATT&CK RAG recommendations, and approval-gated reversible SOAR controls.

---

## 2. File Manifest

| File Path | Description | Zero-CDN Status |
|:---|:---|:---:|
| [`frontend/index.html`](index.html) | Complete SOC Unicorn Web Console & 5-Minute Walkthrough UI | 100% Local |
| [`frontend/css/soc_unicorn.css`](css/soc_unicorn.css) | Dark-mode glassmorphic styling, emerald RF and amber AE badges | 100% Local |
| [`frontend/js/soc_dashboard.js`](js/soc_dashboard.js) | Deterministic receipt verifiers, queue filtering, and walkthrough engine | 100% Local |
| [`frontend/README.md`](README.md) | Operational execution instructions and architecture documentation | N/A |

---

## 3. How to Launch & Inspect

### Method A: Direct Browser Launch (Air-Gapped / File URI)
Because the asset bundle has zero external dependencies, you can open `index.html` directly in any modern browser:

```bash
# Linux (Ubuntu / Pop!_OS / Debian)
xdg-open frontend/index.html

# Or open explicitly in Firefox / Chrome
firefox frontend/index.html
google-chrome frontend/index.html
```

### Method B: Python Standard-Library HTTP Server
To serve the static bundle locally without installing external Node.js or web server packages:

```bash
# Serve frontend/ on port 8000 via python3 stdlib
python3 -m http.server 8000 --directory frontend

# Navigate to http://localhost:8000 in your browser
```

### Method C: Programmatic Python Bundle Verification
To verify and load the bundle via Python in automated tests or backend services:

```python
from pathlib import Path
from threatfusion.api.analyst_dashboard import load_frontend_unicorn_bundle

repo_root = Path.cwd()
bundle = load_frontend_unicorn_bundle(repo_root)

print(f"Loaded index.html: {len(bundle['index_html'])} bytes")
print(f"Loaded soc_unicorn.css: {len(bundle['css'])} bytes")
print(f"Loaded soc_dashboard.js: {len(bundle['js'])} bytes")
```

---

## 4. Key Scientific Invariants & Visual Badges

### 4.1 Strict Authority Separation (RF vs Autoencoder)
- **Primary Decision Authority (`.badge-rf-confidence`):** Rendered in **Emerald** (`#238636` / `#10b981`). Backed by the frozen Random Forest (`full-network-random-forest-6d69c72-v1`, SHA-256 `bd2853a6...`). On the 216,568 January benchmark: Precision = **95.266%**, Recall = **92.818%**, F1 = **94.026%**, False Positive Rate = **0.095%** (only 201 false alarms across 212,210 benign flows).
- **Secondary Anomaly Indicator (`.badge-secondary-anomaly`):** Rendered in **Amber** (`#9e6a03` / `#f59e0b`). Backed by the v2 benign autoencoder (`c8675d13...`, bottleneck $14 \to 8 \to 3 \to 8 \to 14$, calibrated threshold `0.1181361214680695`).
- **Section 8 Lock:** Multimodal OR-fusion is strictly disabled (`production_fusion_enabled = False`). The canonical recall gain `+2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045)` is rejected because it inflates false positives by 8.8308x (+1,574 extra benign FPs; marginal penalty of 16.3958 false alarms per extra attack detected).

### 4.2 Fail-Closed Evidence Validation
Client-side JavaScript strictly validates evidence receipts:
- If SHA-256 audit chain digest is missing or does not match `^[0-9a-fA-F]{64}$`, the badge falls back to `data-evidence-state="unavailable"`.
- If ChromaDB RAG hits are empty or lack valid technique IDs (`^T\d{4}(\.\d{3})?$`), the RAG badge falls back to `data-evidence-state="unavailable"`.

---

## 5. 5-Minute Guided Real-World Scenario Walkthrough

The bottom panel provides an interactive step-by-step playback of the entire 6-stage ThreatFusion incident lifecycle:
1. **Stage 1 (00:00 - 00:45):** Suricata Flow Telemetry & 14-Feature Ingestion (Azure VM 10.0.0.5, port 80).
2. **Stage 2 (00:45 - 01:30):** Frozen Random Forest Fast-Path Inference (95.266% Precision, 0.095% FPR).
3. **Stage 3 (01:30 - 02:15):** Dual-Window Graph Incident Correlation (30.0s Burst / 600.0s Campaign).
4. **Stage 4 (02:15 - 03:00):** ChromaDB 64-Dim MITRE Vector RAG & MISP RFC1918 Private IP Guard.
5. **Stage 5 (03:00 - 03:45):** Evidence-Bound Grounded Advisory Debrief & Anti-Hallucination Guard.
6. **Stage 6 (03:45 - 05:00):** Approval-Gated Reversible SOAR Ledger Execution & TheHive / n8n Dispatch.

Click **"Play 5-Min Walkthrough"** to auto-advance through the stages every 5 seconds, or use **"Next Stage"** / **"Previous Stage"** for manual step-by-step inspection.
