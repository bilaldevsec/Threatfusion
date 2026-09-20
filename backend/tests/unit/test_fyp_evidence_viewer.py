"""Focused tests for the offline FYP evidence viewer."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from scripts import generate_fyp_evidence_viewer as viewer


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _metrics(*, tp: int, fp: int, tn: int, fn: int) -> dict[str, object]:
    return {
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "attack_precision": tp / (tp + fp),
        "attack_recall": tp / (tp + fn),
        "attack_f1": 2 * tp / (2 * tp + fp + fn),
        "false_positive_rate": fp / (fp + tn),
    }


def _fixture_paths(tmp_path: Path, monkeypatch) -> dict[str, Path]:
    paths = {key: tmp_path / f"{key}.json" for key in viewer.EVIDENCE}
    demo = {
        "status": "completed",
        "schema_version": "threatfusion_fyp_progress_demo_v1",
        "revision": "a" * 40,
        "random_forest_producer_demo": {
            "records": [
                {
                    "row_number": 1,
                    "known_label": "Normal",
                    "predicted_class": "Normal",
                    "attack_probability": 1.266526156187045e-05,
                    "disposition": "not_actionable",
                },
                {
                    "row_number": 21,
                    "known_label": "Attack",
                    "predicted_class": "Attack",
                    "attack_probability": 0.8249883171915375,
                    "disposition": "created",
                },
            ],
            "inference_calls_after_first": 2,
            "alert_insert_calls_after_first": 1,
            "alerts_after_first": 1,
            "replay": {
                "wire_bytes_identical": True,
                "cached_response_bytes_identical": True,
                "inference_calls_after_retry": 2,
                "alert_insert_calls_after_retry": 1,
                "alerts_after_retry": 1,
            },
            "authenticated_invalid_request": {
                "http_status": 400,
                "reason": "request_rejected",
                "inference_calls_after_rejection": 2,
                "alerts_after_rejection": 1,
            },
        },
    }
    rf = {
        "completed": True,
        "validation": {"random_forest": _metrics(tp=4045, fp=201, tn=212009, fn=313)},
    }
    ae = {
        "completed": True,
        "model": {"artifact_identity": viewer.V2_IDENTITY},
        "validation": {
            "autoencoder": _metrics(tp=1988, fp=1628, tn=210582, fn=2370),
            "random_forest": _metrics(tp=4045, fp=201, tn=212009, fn=313),
        },
        "february_test": {"autoencoder": _metrics(tp=248531, fp=25934, tn=1127842, fn=50537)},
    }
    audit = {
        "completed": True,
        "resources": {"output_bytes": 100},
        "overlap": {
            "attack": {"autoencoder_only_rf_missed": 96},
            "normal": {"autoencoder_only_added_false_positive": 1574},
        },
        "cohorts": {
            "ae_only_attack": {
                "groups": [
                    {"name": "rates", "fraction_of_total_reconstruction_error": 0.9378424602739482}
                ]
            },
            "ae_only_benign_false_positive": {
                "groups": [
                    {
                        "name": "rates",
                        "fraction_of_total_reconstruction_error": 0.38748093631109315,
                        "record_error_concentration": {
                            "top_10_percent": {
                                "fraction_of_total_error": 0.9567616881486117,
                                "record_count": 158,
                            }
                        },
                    }
                ],
                "record_score_concentration": {
                    "top_10_percent": {
                        "fraction_of_total_error": 0.6993771852147558,
                        "record_count": 158,
                    }
                },
            },
        },
    }
    recovered_audit = json.loads(json.dumps(audit))
    recovered_audit["resources"].pop("output_bytes")
    recovery = {
        "artifact_identity": viewer.V2_IDENTITY,
        "aggregate_report": recovered_audit,
        "aggregate_report_sha256": viewer._canonical_digest(recovered_audit),
    }
    blocked = {
        "completed": True,
        "candidate": {"autoencoder": _metrics(tp=945, fp=2122, tn=210088, fn=3413)},
    }
    for key, value in (
        ("demo", demo),
        ("rf", rf),
        ("ae", ae),
        ("audit", audit),
        ("audit_recovery", recovery),
        ("blocked", blocked),
    ):
        _write_json(paths[key], value)
    monkeypatch.setattr(
        viewer,
        "TRUSTED_AE_REPORT_SHA256",
        hashlib.sha256(paths["ae"].read_bytes()).hexdigest(),
    )
    return paths


def test_publication_embeds_no_external_asset_and_maps_verified_metrics(
    tmp_path: Path, monkeypatch
) -> None:
    paths = _fixture_paths(tmp_path, monkeypatch)
    output = tmp_path / "viewer.html"
    viewer.generate(output, paths)
    page = output.read_text(encoding="utf-8")
    assert "ThreatFusion FYP evidence viewer" in page
    assert "4,045" in page  # January RF true positives from retained report.
    assert "1,574 benign false positives" in page
    assert "BLOCKED_preserve_baseline" in page
    assert "0.001%" in page and "82.499%" in page
    assert "1.266526156187045e-05" in page
    assert "93.784%" in page and "38.748%" in page
    assert "69.938%" in page and "95.676%" in page
    assert "record_score_concentration.top_10_percent.fraction_of_total_error" in page
    assert "record_error_concentration.top_10_percent.fraction_of_total_error" in page
    assert "not product-integrated and not fused" in page
    assert "https://" not in page and "http://" not in page
    assert "<script src=" not in page and "cdn" not in page.lower()


def test_navigation_expandable_sections_and_all_displayed_metric_values(
    tmp_path: Path, monkeypatch
) -> None:
    data = viewer.load_evidence(_fixture_paths(tmp_path, monkeypatch))
    page = viewer.render(data)
    for anchor in ("modules", "demo", "results", "residual", "blocked", "roadmap"):
        assert f'href="#{anchor}"' in page
        assert page.count(f'id="{anchor}"') == 1
    summaries = (
        "Exact RF probability source values",
        "Technical residual detail",
        "BLOCKED_preserve_baseline",
        "Source identities, integrity labels, and fingerprints",
    )
    assert page.count("<details>") == len(summaries)
    for summary in summaries:
        assert f"<summary>{summary}" in page or f"<summary><b>{summary}</b>" in page

    reports = (
        data["rf"]["validation"]["random_forest"],
        data["ae"]["validation"]["autoencoder"],
        data["ae"]["february_test"]["autoencoder"],
        data["blocked"]["candidate"]["autoencoder"],
    )
    for report in reports:
        for key in ("true_positive", "false_positive", "true_negative", "false_negative"):
            assert f"{int(report[key]):,}" in page
        for key in ("attack_precision", "attack_recall", "attack_f1", "false_positive_rate"):
            assert viewer._pct(report[key]) in page
    assert "The candidate is neither approved nor improved" in page
    assert "do not rescue the invalid protocol" in page


def test_missing_required_evidence_fails_closed_without_publication(
    tmp_path: Path, monkeypatch
) -> None:
    paths = _fixture_paths(tmp_path, monkeypatch)
    paths["demo"].unlink()
    output = tmp_path / "viewer.html"
    with pytest.raises(viewer.EvidenceError, match="demo_evidence_unavailable"):
        viewer.generate(output, paths)
    assert not output.exists()


def test_trusted_autoencoder_digest_mismatch_fails_closed(tmp_path: Path, monkeypatch) -> None:
    paths = _fixture_paths(tmp_path, monkeypatch)
    report = json.loads(paths["ae"].read_text(encoding="utf-8"))
    report["model"]["artifact_identity"] = "x" * 64
    _write_json(paths["ae"], report)
    with pytest.raises(viewer.EvidenceError, match="trusted_autoencoder_binding_mismatch"):
        viewer.load_evidence(paths)


def test_unsafe_report_string_is_escaped_in_output(tmp_path: Path, monkeypatch) -> None:
    paths = _fixture_paths(tmp_path, monkeypatch)
    report = json.loads(paths["demo"].read_text(encoding="utf-8"))
    report["random_forest_producer_demo"]["records"][0]["predicted_class"] = "<img src=x>"
    _write_json(paths["demo"], report)
    output = tmp_path / "viewer.html"
    viewer.generate(output, paths)
    page = output.read_text(encoding="utf-8")
    assert "&lt;img src=x&gt;" in page
    assert "<img src=x>" not in page


def test_tampered_recovery_binding_fails_closed(tmp_path: Path, monkeypatch) -> None:
    paths = _fixture_paths(tmp_path, monkeypatch)
    recovery = json.loads(paths["audit_recovery"].read_text(encoding="utf-8"))
    recovery["aggregate_report_sha256"] = "0" * 64
    _write_json(paths["audit_recovery"], recovery)
    with pytest.raises(viewer.EvidenceError, match="residual_audit_recovery_mismatch"):
        viewer.load_evidence(paths)


def test_cli_returns_sanitized_nonzero_for_malformed_evidence(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        viewer, "generate", lambda output: (_ for _ in ()).throw(KeyError("raw detail"))
    )
    assert viewer.main([]) == 1
    assert json.loads(capsys.readouterr().err) == {
        "status": "failed",
        "reason": "evidence_malformed",
    }
