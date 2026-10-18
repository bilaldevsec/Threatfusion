"""Unit tests for Milestone #28: BLAST 3-Layer Architecture SOP & Unicorn SOC Interface SOP."""

from __future__ import annotations

from pathlib import Path

from threatfusion.api.analyst_dashboard import (
    DashboardAlertDetail,
    DashboardAlertQueue,
    DashboardAlertSummary,
    DashboardSnapshot,
    render_dashboard_html,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_soc_unicorn_interface_sop_exists_and_covers_all_tiers():
    """Verify design_guidelines/soc_unicorn_interface_sop.md exists and specifies the 3-Tier standard."""
    sop_file = REPO_ROOT / "design_guidelines" / "soc_unicorn_interface_sop.md"
    assert sop_file.exists(), "design_guidelines/soc_unicorn_interface_sop.md must exist"

    content = sop_file.read_text(encoding="utf-8")
    assert "SOP-UX-SOC-001" in content
    assert 'data-blast-ui-tier="unicorn-progressive-disclosure-v1"' in content
    assert "95.266%" in content
    assert "0.095%" in content
    assert "16.3958" in content or "16.4:1" in content
    assert "full-network-random-forest-6d69c72-v1" in content
    assert "full-benign-autoencoder-2a51c94-v2" in content
    assert "badge-secondary-anomaly" in content
    assert "cited_evidence_keys" in content
    assert "pending_approval" in content
    assert "executed_simulated" in content
    assert "rolled_back" in content
    assert (
        "TF-008" in content and "TF-009" in content and "TF-010" in content and "TF-011" in content
    )


def test_blast_3layer_architecture_sop_exists_and_documents_all_layers():
    """Verify docs/blast_3layer_architecture_sop.md exists and documents the 3 deterministic layers."""
    sop_file = REPO_ROOT / "docs" / "blast_3layer_architecture_sop.md"
    assert sop_file.exists(), "docs/blast_3layer_architecture_sop.md must exist"

    content = sop_file.read_text(encoding="utf-8")
    assert "SOP-ARCH-BLAST-001" in content
    assert "Layer 1: Architecture SOPs & Constitutional Policies" in content
    assert "Layer 2: Deterministic Pipeline Navigation" in content
    assert "Layer 3: Atomic Deterministic Tools" in content
    assert "production_fusion_enabled = False" in content
    assert "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9" in content
    assert "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23" in content
    assert "cited_evidence_keys" in content
    assert "Deterministic Template Fallback" in content
    assert "SuricataFlowAdapter" in content


def test_render_dashboard_html_contains_unicorn_tier_attribute_and_secondary_badge():
    """Verify render_dashboard_html injects the unicorn progressive disclosure attribute and badge."""
    summary = DashboardAlertSummary(
        alert_candidate_id="alert_candidate_v1:" + "a" * 64,
        source_event_id="evt-1",
        observed_at="2026-10-18T12:00:00Z",
        model_identity="full-network-random-forest-6d69c72-v1",
        model_version="v1",
        uncalibrated_model_score=0.85,
        decision_threshold=0.50,
        decision="Attack",
        state="new",
        version=0,
    )
    detail = DashboardAlertDetail(
        alert_candidate_id="alert_candidate_v1:" + "a" * 64,
        source_event_id="evt-1",
        observed_at="2026-10-18T12:00:00Z",
        created_at="2026-10-18T12:00:01Z",
        source_representation_identity="network_behavior_v1",
        feature_contract_identity="network_behavior_v1",
        model_identity="full-network-random-forest-6d69c72-v1",
        model_version="v1",
        model_artifact_sha256="bd2853a6" * 8,
        uncalibrated_model_score=0.85,
        decision_threshold=0.50,
        decision_policy_version="v1",
        decision="Attack",
        state="new",
        version=0,
        updated_at=None,
        updated_by=None,
        last_transition_id=None,
        history=(),
    )
    queue = DashboardAlertQueue(items=(summary,), total_loaded=1, limit=50, offset=0)
    snapshot = DashboardSnapshot(queue=queue, selected=detail, status="active")

    html_out = render_dashboard_html(snapshot)

    assert (
        '<section class="card detail-card" data-blast-ui-tier="unicorn-progressive-disclosure-v1">'
        in html_out
    )
    assert (
        '<span class="badge badge-secondary-anomaly">Secondary Anomaly Indicator (Unfused v2 Autoencoder — Section 8 Fusion Disabled)</span>'
        in html_out
    )
    assert ".badge-secondary-anomaly { background: #8957e5; color: #fff; }" in html_out
