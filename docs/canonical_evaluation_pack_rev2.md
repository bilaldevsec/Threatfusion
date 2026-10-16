# ThreatFusion Canonical Evaluation Pack Rev2 (`AI-FYP-2006`)

**Schema Identity:** `canonical_evaluation_pack_v2`  
**Academic Identifier:** `AI-FYP-2006`  
**Course & Project:** CS492 Final Year Project (FYP-II) — ThreatFusion: Mitigating Alert Fatigue in Security Operations through a Unified Threat Intelligence and Analytics Interface  
**Institution:** FAST-NUCES Karachi (CS492 Final Year Project - FYP-II)  
**Supervisor:** Sir Sameer Faisal  
**Team Members:**  
- Muhammad Bilal (21K-3551)  
- Muhammad Suhaib Shaikh (22K-4302)  
- Muhammad Hasnain (22K-4718)  
**Evaluation Checkpoint Commit:** `6a36dcd9af17bf509977bcf966f2ace72644d5b2` (September 21, 2026 Evaluation Pack Rev2)  
**Document Status:** Authoritative & Reconciled (October 2026)

---

## 1. Executive Summary & Scientific Baseline

The **ThreatFusion Canonical Evaluation Pack Rev2** unifies the authoritative scientific evaluation records from `ThreatFusion_Evaluation_Pack_Rev2.zip` (`6a36dcd9af17bf509977bcf966f2ace72644d5b2`):
1. **Dataset Populations**:
   - **Train**: 865,480 total rows (847,837 benign, 17,643 attack) — *benign-only weight training with all-TRAIN preprocessing statistics*.
   - **January Validation**: 216,568 total rows (4,358 attack, 212,210 benign).
   - **February Benchmark**: 1,452,844 total rows (*previously inspected; disclosed as non-untouched benchmark*).
2. **Frozen Random Forest Reference (`full-network-random-forest-6d69c72-v1`)**:
   - January (216,568 rows): TP = 4,045, FP = 201, TN = 212,009, FN = 313.
   - Precision = **95.266%**, Recall = **92.818%**, F1 = **94.026%**, FPR = **0.095%**.
   - Demo Row 1 Attack Probability = `0.00001` (~0.001%, Normal $\rightarrow$ no alert).
   - Demo Row 21 Attack Probability = `0.8249883171915375` (~82.499% $\ge$ 0.5, Attack $\rightarrow$ 1 `AlertCandidate`).
3. **Corrected v2 Single-Record Autoencoder (`full-benign-autoencoder-2a51c94-v2`)**:
   - Architecture: `14->8->3->8->14`, Threshold: `0.1181361214680695`.
   - January (216,568 rows): TP = 1,988, FP = 1,628, TN = 210,582, FN = 2,370; Precision = 54.978%, Recall = 45.617%, F1 = 49.862%, FPR = 0.767%.
   - February (1,452,844 rows): TP = 248,531, FP = 25,934, TN = 1,127,842, FN = 50,537; Precision = 90.551%, Recall = 83.102%, F1 = 86.667%, FPR = 2.248%.
4. **Section 8 Complementarity & Why Fusion Is Strictly Disabled**:
   - `ae_only_additional_attacks_january = 96`.
   - `ae_only_additional_benign_fps_january = 1574`.
   - `benign_fps_per_additional_attack = 16.395833333333332` ($\approx 16.4$).
   - `production_fusion_enabled = False`.
   - Enabling OR-fusion with the Autoencoder captures 96 extra attacks at the expense of 1,574 additional false alarms (an 8.83x inflation in false positives, dropping precision from 95.266% down to 69.997%).
5. **January Residual Audit (`january-v2-record-concentration-b5e6e5d`)**:
   - Rates-group pooled error % for AE-only attacks: **93.784%**.
   - Rates-group pooled error % for AE-only benign FPs: **38.748%**.
   - Top 158 benign FP whole record error %: **69.938%**.
   - Top 158 benign FP rate group error %: **95.676%**.
6. **Blocked `rate-log1p` Candidate (`rate-log1p-autoencoder-b5e6e5d-v1`)**:
   - Disposition: `BLOCKED_preserve_baseline`.
   - AE-only attacks = 59, AE-only benign FPs = 2,080, Total AE FPs = 2,122, TP = 945, Recall = 21.684%, FPR = 1.000%.
7. **Legacy FYP-I Figures (Superseded)**:
   - Historical preliminary deck numbers (89.77% RF, 94.95% DL fusion from `Final Presentation (1).pptx`) are preserved exclusively within `LegacyFyp1SupersededSummary` with `superseded_by_fyp2_eval_pack_rev2 = True`.

---

## 2. Quantitative Performance Matrix (January 2026 Validation — 216,568 Rows)

| Model / Architecture | Checkpoint ID | Role / Status | TP | FP | TN | FN | Precision | Recall | F1 Score | FPR |
|---|---|---|---|---|---|---|---|---|---|---|
| **Frozen Random Forest** | `full-network-random-forest-6d69c72-v1` | `FROZEN_PRODUCTION_BASELINE` | **4,045** | **201** | **212,009** | **313** | **95.266%** | **92.818%** | **94.026%** | **0.095%** |
| **Corrected v2 Autoencoder** | `full-benign-autoencoder-2a51c94-v2` | `EXPERIMENTAL_UNFUSED_BASELINE` | 1,988 | 1,628 | 210,582 | 2,370 | 54.978% | 45.617% | 49.862% | 0.767% |
| *Counterfactual OR-Fusion (Disabled)* | *RF + AE v2* | *BLOCKED_Section_8* | *4,141* | *1,775* | *210,435* | *217* | *69.997%* | *95.021%* | *80.596%* | *0.836%* |

---

## 3. Section 8 Fusion Disablement & Alert Fatigue Rationale

In accordance with Section 8 of the ThreatFusion charter:
- **Alert Fatigue Prevention**: The core thesis objective is mitigating analyst alert fatigue. Moving from RF-only to RF+AE OR-fusion introduces **16.4 false positives for every 1 extra attack caught** on January validation data.
- **Production Guard**: Candidate fusion is strictly blocked at the API and pipeline levels (`execute_production_inference_guard()`).

---

## 4. Programmatic Verification

```python
from threatfusion.models.canonical_evaluation import (
    CANONICAL_EVALUATION_PACK_REV2,
    assert_fusion_disabled_invariant,
    execute_production_inference_guard,
    get_canonical_evaluation_pack_rev2,
    is_fusion_enabled,
)

pack = get_canonical_evaluation_pack_rev2()
assert pack.project_id == "AI-FYP-2006"
assert pack.frozen_random_forest.precision_pct == 95.266
assert pack.section_8_complementarity.benign_fps_per_additional_attack == 16.395833333333332
assert pack.fusion_disabled is True
assert is_fusion_enabled() is False
assert_fusion_disabled_invariant()  # Passes cleanly
```
