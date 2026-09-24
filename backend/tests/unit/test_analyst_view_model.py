"""The future analyst presentation contract remains internal until identity is bound."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import json
from uuid import uuid4

import pytest

from threatfusion.api.analyst_view_model import (
    VIEW_SCHEMA_VERSION,
    AnalystAlertViewModel,
    AnalystViewError,
)
from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.analyst_state_repository import AnalystStateRepository
from threatfusion.schemas.alert_candidate import (
    ALERT_CANDIDATE_SCHEMA_VERSION,
    DECISION_POLICY_VERSION,
    DETECTOR_IDENTITY,
    DETECTOR_VERSION,
    AlertCandidate,
    derive_alert_candidate_id,
    derive_source_event_id,
)
from threatfusion.schemas.analyst_state import (
    AnalystAuthorizationRegistry,
    AnalystCapability,
    AnalystRegistryEntry,
    AnalystStateError,
)


def _candidate(index: int) -> AlertCandidate:
    source_id = derive_source_event_id(
        source_representation="unsw_nb15.argus.raw_49.transaction_bytes.v1",
        manifest_sha256="b" * 64,
        source_member_sha256=f"{index:064x}",
        row_number=index,
    )
    return AlertCandidate(
        schema_version=ALERT_CANDIDATE_SCHEMA_VERSION,
        alert_candidate_id=derive_alert_candidate_id(
            source_event_id=source_id,
            detector_identity=DETECTOR_IDENTITY,
            detector_version=DETECTOR_VERSION,
            model_identity="random_forest",
            model_version="network_random_forest_baseline_v1",
            model_artifact_sha256="a" * 64,
            decision_policy_version=DECISION_POLICY_VERSION,
        ),
        source_event_id=source_id,
        correlation_id=str(uuid4()),
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256="a" * 64,
        feature_contract_identity="network_behavior_v1",
        source_representation_identity="unsw_nb15.argus.raw_49.transaction_bytes.v1",
        observed_at=datetime(2015, 1, 22, 0, index, tzinfo=UTC),
        created_at=datetime(2026, 9, 23, 0, index, tzinfo=UTC),
        uncalibrated_model_score=0.75,
        decision_threshold=0.5,
        decision_policy_version=DECISION_POLICY_VERSION,
        decision="Attack",
        inference_status="completed",
        reason="inference_succeeded",
    )


def _setup(tmp_path):
    alert_path = tmp_path / "alerts.sqlite3"
    state_path = tmp_path / "analyst.sqlite3"
    alerts = AlertCandidateRepository(alert_path)
    candidates = (_candidate(2), _candidate(1))
    for candidate in candidates:
        alerts.insert(candidate)
    registry = AnalystAuthorizationRegistry(
        (
            AnalystRegistryEntry("queue.viewer", "viewer"),
            AnalystRegistryEntry("tier1.analyst", "analyst"),
            AnalystRegistryEntry("disabled.analyst", "analyst", enabled=False),
        )
    )
    repository = AnalystStateRepository(
        state_path, alerts, registry, clock=lambda: datetime(2026, 9, 24, tzinfo=UTC)
    )
    return candidates, alert_path, state_path, alerts, registry, AnalystAlertViewModel(repository)


def _transition(view, capability, candidate, version, target, transition_id, rationale="Reviewed"):
    return view.transition(
        capability,
        alert_candidate_id=candidate.alert_candidate_id,
        expected_version=version,
        to_state=target,
        transition_id=transition_id,
        rationale=rationale,
    )


def test_viewer_page_detail_bounds_and_explicit_evidence_fields(tmp_path):
    candidates, _, _, _, registry, view = _setup(tmp_path)
    viewer = registry.issue_for_trusted_actor("queue.viewer")
    first = candidates[1]
    page = view.list_alerts(viewer, limit=1)
    json.dumps(page)
    assert page["schema_version"] == VIEW_SCHEMA_VERSION
    assert page["items"][0]["detection_evidence"]["alert_candidate_id"] == first.alert_candidate_id
    assert page["items"][0]["analyst_state"]["state"] == "new"
    assert (
        view.list_alerts(viewer, limit=1, offset=1)["items"][0]["detection_evidence"][
            "alert_candidate_id"
        ]
        == candidates[0].alert_candidate_id
    )
    detail = view.get_alert(viewer, first.alert_candidate_id)
    json.dumps(detail)
    assert detail["analyst_history"] == []
    assert set(detail["detection_evidence"]) == {
        "alert_candidate_id",
        "source_event_id",
        "observed_at",
        "created_at",
        "source_representation_identity",
        "feature_contract_identity",
        "model_identity",
        "model_version",
        "model_artifact_sha256",
        "uncalibrated_model_score",
        "decision_threshold",
        "decision_policy_version",
        "decision",
    }
    assert "rationale" not in detail["detection_evidence"]
    assert "correlation_id" not in detail["detection_evidence"]
    assert view.get_alert(viewer, "alert_candidate_v1:" + "0" * 64) is None
    for invalid in (0, 101, True, "1"):
        with pytest.raises(AnalystViewError, match="^list_limit_invalid$"):
            view.list_alerts(viewer, limit=invalid)
    with pytest.raises(AnalystViewError, match="^list_offset_invalid$"):
        view.list_alerts(viewer, offset=1_000_001)


def test_no_untrusted_identity_or_wrong_capability_can_read_or_transition(tmp_path):
    candidates, _, _, _, registry, view = _setup(tmp_path)
    candidate = candidates[0]
    viewer = registry.issue_for_trusted_actor("queue.viewer")
    analyst = registry.issue_for_trusted_actor("tier1.analyst")
    forged = AnalystCapability(analyst.actor_id, analyst.role, analyst._registry_id, b"forged")
    other_registry = AnalystAuthorizationRegistry(
        (AnalystRegistryEntry("tier1.analyst", "analyst"),)
    )
    foreign = other_registry.issue_for_trusted_actor("tier1.analyst")
    for untrusted in (None, "tier1.analyst", {"role": "analyst"}, forged, foreign):
        with pytest.raises(AnalystViewError, match="^analyst_not_authorized$"):
            view.list_alerts(untrusted)
        with pytest.raises(AnalystViewError, match="^analyst_not_authorized$"):
            view.get_alert(untrusted, candidate.alert_candidate_id)
        with pytest.raises(AnalystViewError, match="^analyst_not_authorized$"):
            _transition(view, untrusted, candidate, 0, "in_review", str(uuid4()))
    with pytest.raises(AnalystViewError, match="^analyst_not_authorized$"):
        _transition(view, viewer, candidate, 0, "in_review", str(uuid4()))
    with pytest.raises(AnalystStateError, match="^analyst_not_authorized$"):
        registry.issue_for_trusted_actor("disabled.analyst")
    assert view.get_alert(viewer, candidate.alert_candidate_id)["analyst_history"] == []


def test_transition_replay_conflict_history_and_restart(tmp_path):
    candidates, alert_path, state_path, alerts, registry, view = _setup(tmp_path)
    candidate = candidates[0]
    analyst = registry.issue_for_trusted_actor("tier1.analyst")
    viewer = registry.issue_for_trusted_actor("queue.viewer")
    before = alerts.get(candidate.alert_candidate_id)
    command_id = str(uuid4())
    first = _transition(view, analyst, candidate, 0, "in_review", command_id)
    assert first["disposition"] == "created"
    assert (
        _transition(view, analyst, candidate, 0, "in_review", command_id)["disposition"]
        == "existing"
    )
    with pytest.raises(AnalystViewError, match="^analyst_transition_identity_conflict$"):
        _transition(view, analyst, candidate, 0, "in_review", command_id, "Changed")
    with pytest.raises(AnalystViewError, match="^analyst_state_version_conflict$"):
        _transition(view, analyst, candidate, 0, "closed", str(uuid4()))
    second = _transition(view, analyst, candidate, 1, "closed", str(uuid4()))
    assert second["analyst_state"]["version"] == 2
    assert (
        _transition(view, analyst, candidate, 0, "in_review", command_id)["analyst_state"]["state"]
        == "closed"
    )
    reopened = AnalystAlertViewModel(
        AnalystStateRepository(state_path, AlertCandidateRepository(alert_path), registry)
    )
    detail = reopened.get_alert(viewer, candidate.alert_candidate_id)
    assert [event["sequence"] for event in detail["analyst_history"]] == [1, 2]
    assert detail["analyst_history"][0]["rationale"] == "Reviewed"
    assert detail["detection_evidence"]["alert_candidate_id"] == before.alert_candidate_id
    assert alerts.get(candidate.alert_candidate_id) == before


def test_competing_commands_and_sanitized_errors(tmp_path, monkeypatch):
    candidates, _, _, _, registry, view = _setup(tmp_path)
    candidate = candidates[0]
    analyst = registry.issue_for_trusted_actor("tier1.analyst")

    def submit(note):
        try:
            return _transition(view, analyst, candidate, 0, "in_review", str(uuid4()), note)[
                "disposition"
            ]
        except AnalystViewError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(submit, ("First", "Second"))) == [
            "analyst_state_version_conflict",
            "created",
        ]

    def broken(*args, **kwargs):
        raise RuntimeError("secret /tmp/database.sqlite3 password=example")

    monkeypatch.setattr(view._repository, "get_alert", broken)
    with pytest.raises(AnalystViewError, match="^analyst_view_unavailable$") as exc:
        view.get_alert(analyst, candidate.alert_candidate_id)
    assert exc.value.__cause__ is None
    assert "secret" not in repr(exc.value)

    def unknown_repository_code(*args, **kwargs):
        raise AnalystStateError("password=/tmp/database.sqlite3")

    monkeypatch.setattr(view._repository, "get_alert", unknown_repository_code)
    with pytest.raises(AnalystViewError, match="^analyst_view_unavailable$"):
        view.get_alert(analyst, candidate.alert_candidate_id)
