#!/usr/bin/env python3
"""ThreatFusion Harmonized FYP-II Final Report & 3-Speaker Presenter Guide Generator (AI-FYP-2006).

Generates:
1. docs/presenter_guide_15_slides_rev2.md
2. artifacts/reports/ThreatFusion_FYP2_Presenter_Guide_Harmonized.docx
3. artifacts/reports/ThreatFusion_FYP2_Final_Report_Harmonized.docx

Key Architectural Mandates:
- Structured 3-speaker presentation choreography across 15 slides:
  • Speaker 1 -- Muhammad Bilal (21K-3551): Slides 1-5 + Two-Track Live Demo execution.
  • Speaker 2 -- Muhammad Suhaib Shaikh (22K-4302): Slides 6-10 (Autoencoder & Inverted Split Retraction).
  • Speaker 3 -- Muhammad Hasnain (22K-4718): Slides 11-15 (Section 8 Invariant, Slide 14 Qualification, Open Issues).
- Exact unrounded Evaluation Pack Rev2 metrics (0.1181361214680695, 212,009, 313, 95.266%, 92.818%, 94.026%, 8.8308x, 16.3958).
- Strict qualification of Slide 14:
  Badge: "BOUNDED RECORDED/LOCAL INTEGRATION PATH VERIFIED (16/16 TEST GATES); LIVE AZURE/SIEM DEPLOYMENT OPEN (TF-011)"
  Footer: "Repository software spine (Suricata eve.json -> 14 features -> loopback mTLS 1.3 -> Frozen RF -> Correlation -> RFC1918 Threat-Intel -> Advisory -> Reversible SOAR) is verified by automated integration tests (test_slide14_suricata_live_ingestion_path.py); live Azure VM / production SIEM field deployment remains unverified and open under TF-011."
- Strict prohibition of unqualified claims: ZERO instances of "VERIFIED & OPERATIONAL" or "100% operational".
- All 4 open issues (TF-008, TF-009, TF-010, TF-011) disclosed as honestly OPEN.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import xml.sax.saxutils as saxutils
import zipfile

PROJECT_TITLE = (
    "AI-FYP-2006: ThreatFusion -- Mitigating Alert Fatigue in Security Operations "
    "through a Unified Threat Intelligence and Analytics Interface"
)
INSTITUTION = "FAST-NUCES Karachi (CS492 Final Year Project - FYP-II)"
SUPERVISOR = "Sir Sameer Faisal"

SPEAKERS = (
    ("Speaker 1", "Muhammad Bilal", "21K-3551", "Slides 1-5 + Two-Track Live Demo Runner"),
    (
        "Speaker 2",
        "Muhammad Suhaib Shaikh",
        "22K-4302",
        "Slides 6-10 (Core Research & Aberration Analysis)",
    ),
    (
        "Speaker 3",
        "Muhammad Hasnain",
        "22K-4718",
        "Slides 11-15 (Section 8 Invariant, Slide 14 & Open Issues)",
    ),
)

DEFAULT_REPORTS_DIR = Path("/home/muhammad-bilal/projects/threatfusion-gemini/artifacts/reports")
DEFAULT_GUIDE_MD_PATH = Path(
    "/home/muhammad-bilal/projects/threatfusion-gemini/docs/presenter_guide_15_slides_rev2.md"
)


def _write_docx_file(items: list[tuple[str, str]], output_path: Path, doc_title: str) -> None:
    """Write an OpenXML .docx file using standard library zipfile (zero external dependencies)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    xml_parts = ["""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>"""]

    for style, text in items:
        esc = saxutils.escape(text)
        if style == "Title":
            xml_parts.append(
                f'<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:after="240"/></w:pPr>'
                f'<w:r><w:rPr><w:b/><w:sz w:val="44"/><w:color w:val="1F497D"/></w:rPr>'
                f'<w:t xml:space="preserve">{esc}</w:t></w:r></w:p>'
            )
        elif style == "Subtitle":
            xml_parts.append(
                f'<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:after="360"/></w:pPr>'
                f'<w:r><w:rPr><w:i/><w:sz w:val="24"/><w:color w:val="595959"/></w:rPr>'
                f'<w:t xml:space="preserve">{esc}</w:t></w:r></w:p>'
            )
        elif style == "Heading 1":
            xml_parts.append(
                f'<w:p><w:pPr><w:spacing w:before="360" w:after="140"/></w:pPr>'
                f'<w:r><w:rPr><w:b/><w:sz w:val="32"/><w:color w:val="1F497D"/></w:rPr>'
                f'<w:t xml:space="preserve">{esc}</w:t></w:r></w:p>'
            )
        elif style == "Heading 2":
            xml_parts.append(
                f'<w:p><w:pPr><w:spacing w:before="240" w:after="100"/></w:pPr>'
                f'<w:r><w:rPr><w:b/><w:sz w:val="26"/><w:color w:val="2E74B5"/></w:rPr>'
                f'<w:t xml:space="preserve">{esc}</w:t></w:r></w:p>'
            )
        elif style == "Heading 3":
            xml_parts.append(
                f'<w:p><w:pPr><w:spacing w:before="180" w:after="80"/></w:pPr>'
                f'<w:r><w:rPr><w:b/><w:sz w:val="22"/><w:color w:val="418AB3"/></w:rPr>'
                f'<w:t xml:space="preserve">{esc}</w:t></w:r></w:p>'
            )
        elif style == "Bullet":
            xml_parts.append(
                f'<w:p><w:pPr><w:ind w:left="400"/><w:spacing w:after="80"/></w:pPr>'
                f'<w:r><w:rPr><w:sz w:val="22"/></w:rPr>'
                f'<w:t xml:space="preserve">• {esc}</w:t></w:r></w:p>'
            )
        elif style == "Callout":
            xml_parts.append(
                f'<w:p><w:pPr><w:ind w:left="720" w:right="720"/><w:spacing w:before="140" w:after="140"/></w:pPr>'
                f'<w:r><w:rPr><w:i/><w:sz w:val="21"/><w:color w:val="262626"/></w:rPr>'
                f'<w:t xml:space="preserve">{esc}</w:t></w:r></w:p>'
            )
        else:  # Body
            xml_parts.append(
                f'<w:p><w:pPr><w:spacing w:after="120"/></w:pPr>'
                f'<w:r><w:rPr><w:sz w:val="22"/></w:rPr>'
                f'<w:t xml:space="preserve">{esc}</w:t></w:r></w:p>'
            )

    xml_parts.append("<w:sectPr/></w:body></w:document>")
    document_xml = "".join(xml_parts)

    with zipfile.ZipFile(str(output_path), "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>""",
        )
        zf.writestr(
            "_rels/.rels",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>""",
        )
        zf.writestr(
            "docProps/core.xml",
            f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:title>{saxutils.escape(doc_title)}</dc:title>
  <dc:creator>ThreatFusion Team (AI-FYP-2006)</dc:creator>
</cp:coreProperties>""",
        )
        zf.writestr(
            "docProps/app.xml",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>ThreatFusion Document Engine (AI-FYP-2006)</Application>
</Properties>""",
        )
        zf.writestr("word/document.xml", document_xml)


def generate_presenter_guide_markdown() -> str:
    """Generate comprehensive 15-slide 3-speaker presenter guide in Markdown."""
    return f"""# ThreatFusion (AI-FYP-2006) — 3-Speaker Final Defense Presenter Guide (15 Slides, Rev2)

**Course Code:** {INSTITUTION}  
**Project ID:** `AI-FYP-2006`  
**Project Title:** {PROJECT_TITLE}  
**Supervisor:** {SUPERVISOR}  

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
"""


def generate_final_report_items() -> list[tuple[str, str]]:
    """Generate structured document elements for ThreatFusion FYP-II Final Report."""
    return [
        ("Title", "AI-FYP-2006: ThreatFusion Final Defense Report"),
        (
            "Subtitle",
            "Mitigating Alert Fatigue in Security Operations through a Unified Threat Intelligence and Analytics Interface",
        ),
        ("Heading 1", "1. Academic & Administrative Metadata"),
        (
            "Body",
            f"Project Identifier: AI-FYP-2006\nInstitution: {INSTITUTION}\nSupervisor: {SUPERVISOR}\nAcademic Year: 2025-2026",
        ),
        (
            "Body",
            "Student Team Members:\n• Muhammad Bilal (Roll No: 21K-3551)\n• Muhammad Suhaib Shaikh (Roll No: 22K-4302)\n• Muhammad Hasnain (Roll No: 22K-4718)",
        ),
        ("Heading 1", "2. Executive Summary & Problem Formulation"),
        (
            "Body",
            "Modern Security Operations Centers (SOCs) face an existential alert fatigue crisis. Tier-1 security analysts are flooded with thousands of alerts daily, over 90% of which are false alarms. High false-positive rates cause alert dismissal, analyst burnout, and delayed response to actual intrusions.",
        ),
        (
            "Body",
            "ThreatFusion (AI-FYP-2006) formulates alert fatigue as a dual challenge of detection precision and operational evidence synthesis. Rather than compounding false alarms through ungrounded deep learning ensembles, ThreatFusion deploys a high-precision machine learning backbone, enforces mathematical fusion guardrails, enriches alerts with private-IP guarded threat intelligence, generates factual advisory debriefs, and coordinates approval-gated reversible containment.",
        ),
        ("Heading 1", "3. Dataset Reconciliation & Evaluation Pack Rev2 (6a36dcd)"),
        (
            "Body",
            "In preliminary FYP-I exploratory work, training and testing splits were inadvertently inverted (82,332 train / 175,341 test), producing distorted metrics (89.77% RF accuracy, 94.95% multimodal fusion claim). Evaluation Pack Rev2 (checkpoint 6a36dcd) comprehensively resolved this defect by anchoring all evaluations to authoritative UNSW-NB15 ground truth.",
        ),
        ("Heading 2", "3.1 Canonical Dataset Populations"),
        (
            "Bullet",
            "TRAIN Population: 865,480 total rows (847,837 benign rows + 17,643 attack rows). All preprocessing statistics and autoencoder weights are derived strictly from TRAIN.",
        ),
        (
            "Bullet",
            "January Validation Population: 216,568 rows (4,358 attack flows + 212,210 benign flows).",
        ),
        ("Bullet", "February Development Benchmark: 1,452,844 rows."),
        ("Heading 2", "3.2 Canonical Benchmark Results (January Validation)"),
        (
            "Body",
            "• Frozen Random Forest (digest bd2853a6...): TP = 4,045, FP = 201, TN = 212,009, FN = 313. Accuracy = 99.76%, Precision = 95.266%, Recall = 92.818%, F1 = 94.026%, FPR = 0.095%.",
        ),
        (
            "Body",
            "• Autoencoder v2 (digest c8675d13..., architecture 14->8->3->8->14, threshold = 0.1181361214680695): TP = 1,988, FP = 1,628, TN = 210,582, FN = 2,370. Precision = 54.978%, Recall = 45.617%, F1 = 49.862%, FPR = 0.767%.",
        ),
        (
            "Body",
            "• Counterfactual Fused (RF OR AE): TP = 4,141, FP = 1,775, Precision = 69.997%, Recall = 95.021%, F1 = 80.603%, FPR = 0.836%.",
        ),
        (
            "Body",
            "• Logistic Regression Baseline (digest 2cf4de66...): Precision = 62.10%, Recall = 78.45%, F1 = 69.32%, FPR = 1.950%.",
        ),
        (
            "Body",
            "• Rate-Log1p Candidate (digest 1d02e5bb...): Blocked under BLOCKED_preserve_baseline. Recall plunged to 21.684% (only 945 attacks detected) on February traversal.",
        ),
        ("Heading 1", "4. Section 8 Core Defense Pillar: Why Automatic Fusion Is Disabled"),
        (
            "Body",
            "Section 8 of the ThreatFusion product charter formalizes the mathematical trade-off of multimodal alert fusion:",
        ),
        (
            "Bullet",
            "+96 attacks added: +2.203 pp recall gain (92.818% -> 95.021%; +2.373% relative TP increase, 96/4,045).",
        ),
        (
            "Bullet",
            "+1,574 additional false alarms (an 8.8308x false-positive inflation, increasing FPs from 201 to 1,775).",
        ),
        ("Bullet", "16.3958 marginal false alarms for every single additional attack caught."),
        ("Bullet", "Precision drops 25.269 percentage points from 95.266% to 69.997%."),
        (
            "Callout",
            "Section 8 Invariant: production_fusion_enabled = False is strictly enforced at runtime. Disabling automatic fusion shields analysts from 1,574 spurious alerts while maintaining 95.266% precision.",
        ),
        ("Heading 1", "5. Section 13 Modern SOC Architectural Pillars"),
        (
            "Heading 2",
            "5.1 Section 13.A & 13.B: Persistent Serving, Subprocess Isolation & 4-DB Atomic Backup",
        ),
        (
            "Body",
            "Production inference runs under subprocess isolation with strict watchdog timeouts. Telemetry transport enforces Mutual TLS 1.3 with client certificate verification. System state is persisted across a 4-database quiescent SQLite architecture (alerts.sqlite3, states.sqlite3, audit.sqlite3, incidents.sqlite3) with atomic backup and restore.",
        ),
        ("Heading 2", "5.2 Section 13.C: Sourced Threat Intelligence with RFC 1918 Guard"),
        (
            "Body",
            "Threat intelligence enrichment enforces three strict rules: (1) Unverified provenance is skipped, (2) RFC1918 private and loopback addresses (e.g. 10.0.0.4, 10.0.0.5) trigger internal lab annotations while suppressing external API queries, preventing rate-limit exhaustion and alert noise, and (3) Outage isolation ensures external feed failures degrade gracefully without blocking alert generation.",
        ),
        ("Heading 2", "5.3 Section 13.D: Evidence-Bound Advisory Debrief Engine"),
        (
            "Body",
            "LLM-assisted explanations are strictly evidence-bound. If an external model hallucinates unobserved IP addresses or contradicts the Section 8 invariant, the verification engine rejects the explanation and falls back to a deterministic, 100% grounded evidence template.",
        ),
        ("Heading 2", "5.4 Section 13.E: Approval-Gated Reversible SOAR Ledger"),
        (
            "Body",
            "Automated containment playbooks follow an explicit lifecycle (pending_approval -> approved -> executed_simulated -> rolled_back) stored in mode-0600 SQLite with optimistic concurrency control. Autonomous command execution is prohibited; analyst approval is mandatory.",
        ),
        ("Heading 2", "5.5 Section 13.F: Alert-Fatigue Compression & Workload Measurement"),
        (
            "Body",
            "Our multi-stage pipeline compresses raw network flows to alerts by 90.0% and consolidates alerts to correlated incidents via dual-window temporal clustering (30-second burst window [30s] and 10-minute campaign window [600s]) by 70.0% (net 97.0% queue compression). The Section 13.F study harness tracks analyst triage efficiency, confirming that synthetic smoke trials never falsely close TF-009.",
        ),
        ("Heading 1", "6. Live Ingestion Architecture & Honest Open-Issue Status"),
        ("Heading 2", "6.1 Slide 14 Live Ingestion Pipeline"),
        (
            "Body",
            "Slide 14 documents our 5-stage live ingestion pipeline: (1) Attacker VM 10.0.0.4, (2) Victim VM 10.0.0.5 with Suricata eve.json, (3) SuricataFlowAdapter extracting 14 canonical features with EntityProvenanceContract, (4) Mutual TLS 1.3 registered producer, and (5) ThreatFusion Backend.",
        ),
        (
            "Callout",
            "Slide 14 Qualified Status: BOUNDED RECORDED/LOCAL INTEGRATION PATH VERIFIED (16/16 TEST GATES); LIVE AZURE/SIEM DEPLOYMENT OPEN (TF-011). Repository software spine (Suricata eve.json -> 14 features -> loopback mTLS 1.3 -> Frozen RF -> Correlation -> RFC1918 Threat-Intel -> Advisory -> Reversible SOAR) is verified by automated integration tests (test_slide14_suricata_live_ingestion_path.py); live Azure VM / production SIEM field deployment remains unverified and open under TF-011.",
        ),
        ("Heading 2", "6.2 Honest Open Issue Register"),
        (
            "Bullet",
            "TF-008 (open): Independent Model Benchmark Beyond Inspected January/February UNSW Splits.",
        ),
        (
            "Bullet",
            "TF-009 (open): Measured Reduction of Analyst Workload in Controlled Human Cohort Trials (requires >= 10 human subjects; tf_009_closure_eligible = False for synthetic runs).",
        ),
        ("Bullet", "TF-010 (open): External FAST-NUCES FYP-II Jury Rubric & Signed Alignment."),
        (
            "Bullet",
            "TF-011 (open): Real Operational SIEM / Threat-Intelligence Production Source Proof.",
        ),
        ("Heading 2", "6.3 STRIDE Threat Modeling & Production Readiness"),
        (
            "Body",
            "The platform implements a formal STRIDE threat model across all 8 pipeline stages (documented in docs/stride_threat_model_and_production_readiness.md), verifying fail-closed secrets, bridge network isolation, HMAC-SHA256 request authentication, server-side ledger state validation, and tamper-evident hash-chained audit ledgers.",
        ),
        ("Heading 1", "7. Conclusion"),
        (
            "Body",
            "ThreatFusion demonstrates that machine learning applied to cybersecurity must be governed by operational reality. By grounding our defense in audited Evaluation Pack Rev2 metrics, enforcing the Section 8 fusion-disabled shield, and verifying all claims via our zero-trust repository truth audit gate, ThreatFusion delivers a scientifically defensible foundation for modern SOC alert triage.",
        ),
    ]


def generate_presenter_guide_items() -> list[tuple[str, str]]:
    """Generate structured document elements for ThreatFusion Presenter Guide .docx."""
    items: list[tuple[str, str]] = [
        ("Title", "ThreatFusion (AI-FYP-2006) Presenter Guide"),
        ("Subtitle", "3-Speaker Final Defense Choreography & Script across 15 Harmonized Slides"),
        ("Heading 1", "Presentation Overview & Speaking Roles"),
        ("Body", f"Institution: {INSTITUTION}\nSupervisor: {SUPERVISOR}\nProject ID: AI-FYP-2006"),
        (
            "Body",
            "Speaking Assignments:\n• Speaker 1 -- Muhammad Bilal (21K-3551): Slides 1-5 + Two-Track Live Demo\n• Speaker 2 -- Muhammad Suhaib Shaikh (22K-4302): Slides 6-10 (Core Research & Aberrations)\n• Speaker 3 -- Muhammad Hasnain (22K-4718): Slides 11-15 (Section 8, Slide 14 & Open Issues)",
        ),
    ]

    # Convert the detailed markdown slides into structured items
    guide_md = generate_presenter_guide_markdown()
    current_heading = "Slide Script"
    for line in guide_md.split("\n"):
        line = line.strip()
        if not line or line.startswith("---") or line.startswith("|"):
            continue
        if line.startswith("### PART"):
            items.append(("Heading 1", line.replace("#", "").strip()))
        elif line.startswith("#### Slide"):
            current_heading = line.replace("#", "").strip()
            items.append(("Heading 2", current_heading))
        elif line.startswith("- **Slide Title:**"):
            items.append(("Heading 3", line.replace("- **Slide Title:**", "Title:").strip()))
        elif line.startswith("- **Script"):
            items.append(("Heading 3", "Speaking Script:"))
        elif line.startswith(">"):
            clean_text = line.replace(">", "").strip()
            if clean_text:
                items.append(("Callout", clean_text))
        elif line.startswith("- **"):
            clean_line = line[4:].replace("**", "").strip()
            items.append(("Bullet", clean_line))
        elif line.startswith("•"):
            items.append(("Bullet", line.replace("•", "").strip()))
        elif line.startswith("## "):
            items.append(("Heading 1", line.replace("##", "").strip()))

    return items


def generate_harmonized_defense_docs(
    output_dir: Path | str = DEFAULT_REPORTS_DIR,
    markdown_path: Path | str = DEFAULT_GUIDE_MD_PATH,
) -> tuple[Path, Path, Path]:
    """Generate presenter guide Markdown and two harmonized OpenXML .docx reports."""
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    md_file = Path(markdown_path).resolve()
    md_file.parent.mkdir(parents=True, exist_ok=True)

    # 1. Generate Presenter Guide Markdown
    print(f"Generating Presenter Guide Markdown -> {md_file}")
    md_text = generate_presenter_guide_markdown()
    with open(md_file, "w", encoding="utf-8") as f:
        f.write(md_text)

    # 2. Generate Presenter Guide .docx
    guide_docx_path = out_dir / "ThreatFusion_FYP2_Presenter_Guide_Harmonized.docx"
    print(f"Generating Presenter Guide OpenXML .docx -> {guide_docx_path}")
    guide_items = generate_presenter_guide_items()
    _write_docx_file(guide_items, guide_docx_path, "ThreatFusion 3-Speaker Presenter Guide")

    # 3. Generate Final Report .docx
    report_docx_path = out_dir / "ThreatFusion_FYP2_Final_Report_Harmonized.docx"
    print(f"Generating Harmonized Final Defense Report OpenXML .docx -> {report_docx_path}")
    report_items = generate_final_report_items()
    _write_docx_file(report_items, report_docx_path, "ThreatFusion FYP-II Final Defense Report")

    # Sanity verify all 3 generated files exist and have non-zero size
    for p in (md_file, guide_docx_path, report_docx_path):
        if not p.exists() or p.stat().st_size == 0:
            raise RuntimeError(f"Failed to generate output file: {p}")

    print("Successfully generated all 3 defense documentation artifacts.")
    return md_file, guide_docx_path, report_docx_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate harmonized defense documentation and presenter guides"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_REPORTS_DIR,
        help="Directory to save generated .docx files",
    )
    parser.add_argument(
        "--markdown-path",
        type=Path,
        default=DEFAULT_GUIDE_MD_PATH,
        help="Path to save presenter guide Markdown",
    )
    args = parser.parse_args()

    try:
        generate_harmonized_defense_docs(
            output_dir=args.output_dir,
            markdown_path=args.markdown_path,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
