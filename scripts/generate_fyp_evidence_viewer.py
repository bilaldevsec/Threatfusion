"""Generate a self-contained, read-only FYP evidence presentation.

This intentionally reads aggregate, sanitized evidence only.  It neither imports
model code nor opens datasets, matrices, model binaries, or credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import sys
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts/reports/fyp_evidence_viewer/threatfusion_fyp_evidence.html"
EVIDENCE = {
    "demo": ROOT / "artifacts/reports/fyp_progress_demo/latest/evidence.json",
    "rf": ROOT
    / "artifacts/models/network_random_forest_baseline/full-network-random-forest-6d69c72-v1/evaluation_report.json",
    "ae": ROOT
    / "artifacts/models/network_autoencoder/full-benign-autoencoder-2a51c94-v2/evaluation_report.json",
    "audit": ROOT
    / "artifacts/reports/network_autoencoder_residual_audit/january-v2-record-concentration-b5e6e5d/aggregate.json",
    "audit_recovery": ROOT
    / "artifacts/reports/network_autoencoder_residual_audit/.january-v2-record-concentration-b5e6e5d.recovery.json",
    "blocked": ROOT
    / "artifacts/models/network_rate_log1p_autoencoder/rate-log1p-autoencoder-b5e6e5d-v1/evaluation_report.json",
}

# This is a code-owned binding from the existing demonstration runner, rather
# than a claim made by the report it verifies.
TRUSTED_AE_REPORT_SHA256 = "0ec77eda4a58e40e1b75087bbc5131f39cad54d553771e174ea303bc506c3bef"
V2_IDENTITY = "bdb7fc33d5b092566995018b5f83aa66bdb8ce95841d6b8b9021111c9a392a9a"


class EvidenceError(RuntimeError):
    """A sanitized evidence-publication error."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read(path: Path, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(code) from exc
    if not isinstance(value, dict):
        raise EvidenceError(code)
    return value


def _need(value: Any, code: str) -> Any:
    if value is None:
        raise EvidenceError(code)
    return value


def _canonical_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_evidence(paths: Mapping[str, Path] = EVIDENCE) -> dict[str, Any]:
    """Load required evidence and fail closed before an output can be written."""
    required = ("demo", "rf", "ae", "audit", "audit_recovery", "blocked")
    if any(key not in paths for key in required):
        raise EvidenceError("required_evidence_path_missing")
    data = {key: _read(paths[key], f"{key}_evidence_unavailable") for key in required}
    demo, rf, ae, audit, recovery, blocked = (data[key] for key in required)
    if (
        demo.get("status") != "completed"
        or demo.get("schema_version") != "threatfusion_fyp_progress_demo_v1"
    ):
        raise EvidenceError("demo_evidence_malformed")
    if (
        rf.get("completed") is not True
        or ae.get("completed") is not True
        or audit.get("completed") is not True
    ):
        raise EvidenceError("required_evidence_incomplete")
    if blocked.get("completed") is not True:
        raise EvidenceError("blocked_candidate_evidence_incomplete")
    if (
        _sha256(paths["ae"]) != TRUSTED_AE_REPORT_SHA256
        or ae.get("model", {}).get("artifact_identity") != V2_IDENTITY
    ):
        raise EvidenceError("trusted_autoencoder_binding_mismatch")
    report = recovery.get("aggregate_report")
    # Publication appends its final output-byte count after the recovery copy is
    # cryptographically bound.  That is the documented, non-scientific delta.
    published_core = json.loads(json.dumps(audit))
    recovered_core = json.loads(json.dumps(report)) if isinstance(report, dict) else None
    if (
        not isinstance(published_core.get("resources"), dict)
        or not isinstance(recovered_core, dict)
        or not isinstance(recovered_core.get("resources"), dict)
    ):
        raise EvidenceError("residual_audit_recovery_mismatch")
    published_core["resources"].pop("output_bytes", None)
    recovered_core["resources"].pop("output_bytes", None)
    if (
        not isinstance(report, dict)
        or recovery.get("aggregate_report_sha256") != _canonical_digest(report)
        or recovered_core != published_core
        or recovery.get("artifact_identity") != V2_IDENTITY
    ):
        raise EvidenceError("residual_audit_recovery_mismatch")
    records = demo.get("random_forest_producer_demo", {}).get("records")
    if not isinstance(records, list) or len(records) != 2:
        raise EvidenceError("demo_records_malformed")
    if any(
        row.get("known_label") not in {"Normal", "Attack"}
        for row in records
        if isinstance(row, dict)
    ):
        raise EvidenceError("demo_records_malformed")
    validation = ae.get("validation", {})
    for node in (
        rf.get("validation", {}).get("random_forest"),
        validation.get("autoencoder"),
        validation.get("random_forest"),
        ae.get("february_test", {}).get("autoencoder"),
    ):
        if not isinstance(node, dict) or any(
            node.get(key) is None
            for key in (
                "true_positive",
                "false_positive",
                "true_negative",
                "false_negative",
                "attack_precision",
                "attack_recall",
                "attack_f1",
                "false_positive_rate",
            )
        ):
            raise EvidenceError("metrics_evidence_malformed")
    overlap = audit.get("overlap", {})
    if (
        overlap.get("attack", {}).get("autoencoder_only_rf_missed") != 96
        or overlap.get("normal", {}).get("autoencoder_only_added_false_positive") != 1574
    ):
        raise EvidenceError("residual_values_mismatch")
    return data


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _pct(value: float) -> str:
    return f"{float(value) * 100:.3f}%"


def _metric_card(title: str, values: Mapping[str, Any], color: str) -> str:
    labels = [
        ("TP", "true_positive"),
        ("FP", "false_positive"),
        ("TN", "true_negative"),
        ("FN", "false_negative"),
    ]
    counts = "".join(
        f"<span><b>{name}</b> {_e(f'{int(values[key]):,}')}</span>" for name, key in labels
    )
    return f"""<article class="metric" style="--accent:{color}"><h3>{_e(title)}</h3>
    <div class="counts">{counts}</div><dl><dt>Precision</dt><dd>{_pct(values['attack_precision'])}</dd>
    <dt>Recall</dt><dd>{_pct(values['attack_recall'])}</dd><dt>F1</dt><dd>{_pct(values['attack_f1'])}</dd>
    <dt>False-positive rate</dt><dd>{_pct(values['false_positive_rate'])}</dd></dl></article>"""


def _details(title: str, content: str) -> str:
    return (
        f"<details><summary>{_e(title)}</summary><div class=details-body>{content}</div></details>"
    )


def render(data: Mapping[str, Any]) -> str:
    demo, rf, ae, audit, blocked = (data[key] for key in ("demo", "rf", "ae", "audit", "blocked"))
    producer = demo["random_forest_producer_demo"]
    retry, rejected = producer["replay"], producer["authenticated_invalid_request"]
    demo_rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{_e(_pct(row[key]) if key == 'attack_probability' else row.get(key, 'unavailable'))}</td>"
            for key in (
                "row_number",
                "known_label",
                "predicted_class",
                "attack_probability",
                "disposition",
            )
        )
        + "</tr>"
        for row in producer["records"]
    )
    probability_detail_rows = "".join(
        f"<tr><td>{_e(row['row_number'])}</td><td><code>{_e(repr(row['attack_probability']))}</code></td></tr>"
        for row in producer["records"]
    )
    rf_jan, ae_jan, ae_feb = (
        rf["validation"]["random_forest"],
        ae["validation"]["autoencoder"],
        ae["february_test"]["autoencoder"],
    )
    blocked_ae = blocked["candidate"]["autoencoder"]
    audit_benign = audit["cohorts"]["ae_only_benign_false_positive"]
    audit_attack = audit["cohorts"]["ae_only_attack"]
    pooled_attack_rates = next(
        group for group in audit_attack["groups"] if group["name"] == "rates"
    )
    pooled_benign_rates = next(
        group for group in audit_benign["groups"] if group["name"] == "rates"
    )
    whole_score_top10 = audit_benign["record_score_concentration"]["top_10_percent"]
    rate_error_top10 = pooled_benign_rates["record_error_concentration"]["top_10_percent"]
    source_rows = "".join(
        f"<tr><td>{_e(name)}</td><td><code>{_e(_sha256(EVIDENCE[key]))}</code></td><td>{_e(label)}</td></tr>"
        for key, name, label in (
            (
                "demo",
                "Sanitized saved demo evidence",
                "saved recorded UNSW replay; fingerprint only",
            ),
            (
                "rf",
                "RF evaluation report: full-network-random-forest-6d69c72-v1",
                "January development validation; fingerprint only",
            ),
            (
                "ae",
                "Corrected v2 AE: bdb7fc33d5b092…a392a9a",
                "verified code-owned binding; January/previously inspected February",
            ),
            (
                "audit",
                "January v2 record-concentration aggregate",
                "recovery-bound, development-informed; fingerprint",
            ),
            (
                "blocked",
                "Rate-log1p candidate: 910d2977c932…5fb36f4",
                "BLOCKED_preserve_baseline; protocol-invalid fingerprint",
            ),
        )
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ThreatFusion — FYP evidence viewer</title>
<style>
:root{{--ink:#10233f;--paper:#f7f9fc;--card:#fff;--muted:#526479;--line:#ced8e5;--rf:#146c94;--ae:#8b3d8c;--warn:#9b401c;--ok:#176b45}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:18px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}header{{background:#10233f;color:white;padding:2.6rem max(4vw,1rem)}}header h1{{margin:0;font-size:clamp(2rem,5vw,3.5rem)}}header p{{max-width:72rem;font-size:1.2rem}}nav{{position:sticky;top:0;background:#fff;border-bottom:1px solid var(--line);padding:.65rem 4vw;z-index:2}}nav a{{color:#123e6b;font-weight:700;margin-right:1.1rem;text-decoration:none}}main{{max-width:1280px;margin:auto;padding:1rem 4vw 4rem}}section{{padding:2rem 0;border-bottom:2px solid var(--line)}}h2{{font-size:clamp(1.65rem,3vw,2.35rem);margin:0 0 .5rem}}h3{{margin:.2rem 0 .6rem}}.notice{{border-left:7px solid var(--warn);background:#fff2e9;padding:1rem 1.2rem;font-weight:650}}.ok{{border-color:var(--ok);background:#eaf8ef}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}}.card,.metric{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1.2rem}}.metric{{border-top:8px solid var(--accent)}}.counts{{display:flex;flex-wrap:wrap;gap:.55rem}}.counts span{{background:#edf2f7;padding:.18rem .42rem;border-radius:4px}}dl{{display:grid;grid-template-columns:1fr auto;margin:1rem 0 0;gap:.2rem .6rem}}dt{{color:var(--muted)}}dd{{font-weight:800;margin:0}}table{{width:100%;border-collapse:collapse;background:white;margin:1rem 0}}th,td{{padding:.65rem;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}th{{background:#eaf0f7}}code{{font-size:.75em;overflow-wrap:anywhere}}details{{background:#fff;border:1px solid var(--line);border-radius:8px;padding:.7rem 1rem;margin:1rem 0}}summary{{cursor:pointer;font-weight:750}}.details-body{{padding-top:.8rem}}.chart{{display:grid;gap:.5rem}}.bar{{display:grid;grid-template-columns:13rem 1fr 5rem;gap:.5rem;align-items:center}}.track{{height:1.25rem;background:#e7edf4;border-radius:3px;overflow:hidden}}.fill{{height:100%;background:var(--ae)}}.small{{color:var(--muted);font-size:.92rem}}@media print{{nav{{display:none}}body{{font-size:12pt;background:white}}section{{break-inside:avoid}}details{{display:block}}details>summary{{list-style:none}}details>summary::-webkit-details-marker{{display:none}}}}@media(max-width:650px){{.bar{{grid-template-columns:9rem 1fr 4rem}}}}
</style></head><body><header><h1>ThreatFusion FYP evidence viewer</h1><p>Read-only offline presentation of retained, sanitized evidence. This is not a live SOC dashboard, live processing, or an operational-readiness claim.</p><p><b>Saved run status:</b> completed · revision {_e(demo.get('revision','unavailable'))} · no model is executed by this page.</p></header>
<nav><a href="#modules">Modules</a><a href="#demo">Saved demonstration</a><a href="#results">Results</a><a href="#residual">Residuals</a><a href="#blocked">Blocked candidate</a><a href="#roadmap">Limits</a></nav><main>
<section id="modules"><h2>1. Completed modules</h2><div class="grid"><article class="card"><h3>Implemented and demonstrated</h3><ul><li>Registered recorded-data input</li><li>Mutual TLS transport</li><li>Frozen Random Forest inference</li><li>Attack-only alert persistence</li><li>Exact replay: no duplicate inference or alerts</li><li>Invalid-request rejection before inference/persistence</li><li>Experimental corrected v2 autoencoder scoring demonstration — separately demonstrated only; not product-integrated and not fused</li></ul></article><article class="card"><h3>Planned / not implemented here</h3><ul><li>Dashboard API/view model and analyst workflow</li><li>Serving loop and terminating worker isolation</li><li>Correlation, explanation, backup/recovery evidence</li><li>Live-source identity and operational measurement</li></ul></article></div></section>
<section id="demo"><h2>2. Recorded demonstration evidence</h2><div class="notice ok">SAVED RUN — two deliberately selected records, not an unbiased sample. Known dataset labels are distinct from model predictions. The viewer does not simulate processing.</div><p>Presenter command (run separately; it is not invoked here): <code>PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/run_fyp_progress_demo.py</code></p><table><thead><tr><th>Registered row</th><th>Known label</th><th>RF prediction</th><th>RF attack-probability estimate</th><th>Alert disposition</th></tr></thead><tbody>{demo_rows}</tbody></table><p class="small">RF probability is a model estimate, not guaranteed confidence.</p>{_details('Exact RF probability source values', '<table><thead><tr><th>Registered row</th><th>Source float value</th></tr></thead><tbody>'+probability_detail_rows+'</tbody></table><p>Displayed percentages are source value × 100; no rounding is used for any model decision.</p>')}<div class="grid"><article class="card"><h3>After first processing</h3><p>Inference calls: <b>{producer['inference_calls_after_first']}</b> · alert insert calls: <b>{producer['alert_insert_calls_after_first']}</b> · durable alerts: <b>{producer['alerts_after_first']}</b></p></article><article class="card"><h3>Exact replay</h3><p>Wire bytes identical: <b>{_e(retry['wire_bytes_identical'])}</b>; cached response identical: <b>{_e(retry['cached_response_bytes_identical'])}</b>.</p><p>Inference <b>{producer['inference_calls_after_first']} → {retry['inference_calls_after_retry']}</b>; inserts <b>{producer['alert_insert_calls_after_first']} → {retry['alert_insert_calls_after_retry']}</b>; alerts <b>{producer['alerts_after_first']} → {retry['alerts_after_retry']}</b>.</p></article><article class="card"><h3>Invalid request</h3><p>Authenticated request rejected: HTTP {_e(rejected['http_status'])}, <code>{_e(rejected['reason'])}</code>.</p><p>Inference remains <b>{rejected['inference_calls_after_rejection']}</b>; alerts remain <b>{rejected['alerts_after_rejection']}</b>.</p></article></div></section>
<section id="results"><h2>3. ML and experimental DL results</h2><p><b>Metric guide:</b> TP/TN are correct attack/benign decisions; FP is benign incorrectly flagged; FN is attack missed. Precision is the share of flags that are attacks; recall is the share of attacks flagged; F1 balances precision and recall; false-positive rate is the share of benign records flagged.</p><h3>January VALIDATION — development-informed evidence</h3><div class="grid">{_metric_card('Random Forest', rf_jan, '#146c94')}{_metric_card('Experimental v2 autoencoder', ae_jan, '#8b3d8c')}</div><h3>Previously inspected February benchmark — later-period, development-informed</h3><div class="grid">{_metric_card('Experimental v2 autoencoder', ae_feb, '#8b3d8c')}</div><div class="notice">The autoencoder remains experimental; fusion is disabled. Reconstruction error is not attack probability. February outcomes were previously inspected and are not independent evaluation.</div></section>
<section id="residual"><h2>4. Complementarity and residual findings</h2><div class="notice">January overlap: AE-only detections add <b>96 attacks</b> and <b>1,574 benign false positives</b> relative to RF. This is descriptive development evidence; it does not establish operational benefit or a causal explanation.</div><div class="card"><h3>Pooled feature-contribution chart</h3><p><b>Quantity:</b> combined <code>rates</code>-group squared reconstruction error. <b>Denominator:</b> all 14-feature squared reconstruction error pooled across each entire cohort. <b>Selection rule:</b> every record in the named January AE-only cohort.</p><div class="chart"><div class="bar"><b>AE-only attacks (n=96)</b><div class="track"><div class="fill" style="width:{pooled_attack_rates['fraction_of_total_reconstruction_error']*100:.3f}%"></div></div><span>{_pct(pooled_attack_rates['fraction_of_total_reconstruction_error'])}</span></div><div class="bar"><b>AE-only benign FP (n=1,574)</b><div class="track"><div class="fill" style="width:{pooled_benign_rates['fraction_of_total_reconstruction_error']*100:.3f}%"></div></div><span>{_pct(pooled_benign_rates['fraction_of_total_reconstruction_error'])}</span></div></div></div><div class="card"><h3>Per-record outlier-concentration chart — AE-only benign false positives (n=1,574)</h3><p><b>Selection rule:</b> largest <b>{whole_score_top10['record_count']}</b> records, ceiling(10% × 1,574), ordered separately for each quantity.</p><div class="chart"><div class="bar"><b>Whole-record error: {whole_score_top10['record_count']} records</b><div class="track"><div class="fill" style="width:{whole_score_top10['fraction_of_total_error']*100:.3f}%"></div></div><span>{_pct(whole_score_top10['fraction_of_total_error'])}</span></div><div class="bar"><b>Rate-group error: {rate_error_top10['record_count']} records</b><div class="track"><div class="fill" style="width:{rate_error_top10['fraction_of_total_error']*100:.3f}%"></div></div><span>{_pct(rate_error_top10['fraction_of_total_error'])}</span></div></div><p><b>69.938%</b> is the whole-record result: <code>cohorts.ae_only_benign_false_positive.record_score_concentration.top_10_percent.fraction_of_total_error</code>; denominator: total whole-record reconstruction error across this cohort. <b>95.676%</b> is distinct: <code>cohorts.ae_only_benign_false_positive.groups[name=rates].record_error_concentration.top_10_percent.fraction_of_total_error</code>; denominator: pooled rate-group error across this cohort.</p></div>{_details('Technical residual detail', '<p>Audit reconciles frozen January AE and RF confusion/overlap counts. It describes which transformed inputs contribute to reconstruction error, not why an event is malicious.</p>')}</section>
<section id="blocked"><h2>5. Rejected experiment</h2><details><summary><b>BLOCKED_preserve_baseline</b> — expand protocol-invalid candidate evidence</summary><div class="details-body"><div class="notice">BLOCKED — preserve baseline. The candidate is neither approved nor improved.</div><p>Preparation accessed February (1,452,844 TEST rows seen), violating the frozen January-only protocol. Training-child isolation did not repair that preparation access. This alone does not prove February rows entered optimizer batches: retained accounting reports only 847,837 benign TRAIN rows per epoch.</p>{_metric_card('Protocol-invalid rate-log1p candidate', blocked_ae, '#9b401c')}<p><b>Numerical failures, separate from protocol invalidity:</b> TP/FP/TN/FN were 945/2,122/210,088/3,413; all four retention gates failed; AE-only attack/benign-FP counts were 59/2,080 and ratio 0.0283654. These numbers remain readable but do not rescue the invalid protocol.</p></div></details></section>
<section id="roadmap"><h2>6. Remaining roadmap and evidence details</h2><div class="grid"><article class="card"><h3>Open limitations</h3><ul><li>No dashboard or end-to-end dashboard acceptance</li><li>No worker termination, correlation, explanation, or analyst workflow</li><li>February/CIC outcomes are development-known; cross-source compatibility remains unresolved</li><li>Near-duplicate/capture provenance and host-training evidence remain unresolved</li><li>No authoritative complete jury model/dataset list or user-value validation</li></ul></article><article class="card"><h3>Evidence labels</h3><p>January: development-informed post-calibration.</p><p>February: later-period, previously inspected, development-informed benchmark.</p><p>Demo: saved recorded UNSW replay, not live traffic or accuracy testing.</p></article></div>{_details('Source identities, integrity labels, and fingerprints', '<table><thead><tr><th>Source report identity</th><th>SHA-256</th><th>Binding / evidence label</th></tr></thead><tbody>'+source_rows+'</tbody></table><p>Fingerprints identify the local bytes read; without a pre-existing external/trusted binding they are not proof of authenticity. No optional evidence section was substituted or fabricated.</p>')}</section>
</main><script>/* Offline navigation only; no network requests or live counters. */document.querySelectorAll('nav a').forEach(a=>a.addEventListener('click',e=>{{e.preventDefault();document.querySelector(a.getAttribute('href')).scrollIntoView({{behavior:'smooth'}})}}));</script></body></html>"""


def generate(output: Path = DEFAULT_OUTPUT, paths: Mapping[str, Path] = EVIDENCE) -> Path:
    page = render(load_evidence(paths))
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(page, encoding="utf-8")
    temporary.replace(output)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the offline ThreatFusion FYP evidence viewer."
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        print(generate(args.output))
    except EvidenceError as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}), file=sys.stderr)
        return 1
    except (IndexError, KeyError, TypeError, ValueError):
        print(json.dumps({"status": "failed", "reason": "evidence_malformed"}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
