"""Focused tests for the offline FYP evidence viewer."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from scripts import generate_fyp_evidence_viewer as viewer


def _copied_paths(tmp_path: Path) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for key, source in viewer.EVIDENCE.items():
        target = tmp_path / f"{key}.json"
        shutil.copyfile(source, target)
        paths[key] = target
    return paths


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_publication_embeds_no_external_asset_and_maps_verified_metrics(tmp_path: Path) -> None:
    output = tmp_path / "viewer.html"
    viewer.generate(output)
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


def test_navigation_expandable_sections_and_all_displayed_metric_values() -> None:
    data = viewer.load_evidence()
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


def test_missing_required_evidence_fails_closed_without_publication(tmp_path: Path) -> None:
    paths = _copied_paths(tmp_path)
    paths["demo"].unlink()
    output = tmp_path / "viewer.html"
    with pytest.raises(viewer.EvidenceError, match="demo_evidence_unavailable"):
        viewer.generate(output, paths)
    assert not output.exists()


def test_trusted_autoencoder_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    paths = _copied_paths(tmp_path)
    report = json.loads(paths["ae"].read_text(encoding="utf-8"))
    report["model"]["artifact_identity"] = "x" * 64
    _write_json(paths["ae"], report)
    with pytest.raises(viewer.EvidenceError, match="trusted_autoencoder_binding_mismatch"):
        viewer.load_evidence(paths)


def test_unsafe_report_string_is_escaped_in_output(tmp_path: Path) -> None:
    paths = _copied_paths(tmp_path)
    report = json.loads(paths["demo"].read_text(encoding="utf-8"))
    report["random_forest_producer_demo"]["records"][0]["predicted_class"] = "<img src=x>"
    _write_json(paths["demo"], report)
    output = tmp_path / "viewer.html"
    viewer.generate(output, paths)
    page = output.read_text(encoding="utf-8")
    assert "&lt;img src=x&gt;" in page
    assert "<img src=x>" not in page


def test_tampered_recovery_binding_fails_closed(tmp_path: Path) -> None:
    paths = _copied_paths(tmp_path)
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
