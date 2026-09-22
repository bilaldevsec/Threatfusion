"""Bounded analyst workflow, authorization, replay, and restart tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import sqlite3
from uuid import uuid4

import pytest

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
    MAX_ANALYST_RATIONALE_BYTES,
    AnalystAuthorizationRegistry,
    AnalystCapability,
    AnalystRegistryEntry,
    AnalystStateError,
)

NOW = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)


def _candidate(index: int = 1, *, created_at: datetime | None = None) -> AlertCandidate:
    source_event_id = derive_source_event_id(
        source_representation="unsw_nb15.argus.raw_49.transaction_bytes.v1",
        manifest_sha256="b" * 64,
        source_member_sha256=f"{index:064x}",
        row_number=index,
    )
    candidate_id = derive_alert_candidate_id(
        source_event_id=source_event_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256="a" * 64,
        decision_policy_version=DECISION_POLICY_VERSION,
    )
    return AlertCandidate(
        schema_version=ALERT_CANDIDATE_SCHEMA_VERSION,
        alert_candidate_id=candidate_id,
        source_event_id=source_event_id,
        correlation_id=str(uuid4()),
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256="a" * 64,
        feature_contract_identity="network_behavior_v1",
        source_representation_identity="unsw_nb15.argus.raw_49.transaction_bytes.v1",
        observed_at=datetime(2015, 1, 22, 0, index, tzinfo=UTC),
        created_at=created_at or datetime(2026, 9, 23, 0, index, tzinfo=UTC),
        uncalibrated_model_score=0.75,
        decision_threshold=0.5,
        decision_policy_version=DECISION_POLICY_VERSION,
        decision="Attack",
        inference_status="completed",
        reason="inference_succeeded",
    )


def _registry() -> AnalystAuthorizationRegistry:
    return AnalystAuthorizationRegistry(
        (
            AnalystRegistryEntry("tier1.analyst", "analyst"),
            AnalystRegistryEntry("queue.viewer", "viewer"),
            AnalystRegistryEntry("disabled.analyst", "analyst", enabled=False),
        )
    )


def _repositories(tmp_path, *, candidates=(_candidate(),)):
    alerts_path = tmp_path / "alerts.sqlite3"
    analyst_path = tmp_path / "analyst.sqlite3"
    alerts = AlertCandidateRepository(alerts_path)
    for candidate in candidates:
        alerts.insert(candidate)
    registry = _registry()
    states = AnalystStateRepository(analyst_path, alerts, registry, clock=lambda: NOW)
    return alerts_path, analyst_path, alerts, states, registry


def _transition(states, analyst, candidate, version, target, rationale, transition_id=None):
    return states.transition(
        analyst,
        alert_candidate_id=candidate.alert_candidate_id,
        expected_version=version,
        to_state=target,
        transition_id=transition_id or str(uuid4()),
        rationale=rationale,
    )


def test_bounded_list_and_detail_show_implicit_new_in_candidate_order(tmp_path):
    later = _candidate(2, created_at=datetime(2026, 9, 23, 2, tzinfo=UTC))
    earlier = _candidate(1, created_at=datetime(2026, 9, 23, 1, tzinfo=UTC))
    _, _, _, states, registry = _repositories(tmp_path, candidates=(later, earlier))
    viewer = registry.issue_for_trusted_actor("queue.viewer")

    page = states.list_alerts(viewer, limit=1)
    detail = states.get_alert(viewer, earlier.alert_candidate_id)

    assert [item.candidate for item in page] == [earlier]
    assert page[0].analyst_state.state == "new"
    assert page[0].analyst_state.version == 0
    assert detail is not None
    assert detail.candidate == earlier
    assert detail.analyst_state == page[0].analyst_state
    assert detail.transitions == ()
    assert states.list_alerts(viewer, limit=1, offset=1)[0].candidate == later
    assert states.get_alert(viewer, "alert_candidate_v1:" + "0" * 64) is None
    for invalid in (0, 101, True, "1"):
        with pytest.raises(AnalystStateError, match="^list_limit_invalid$"):
            states.list_alerts(viewer, limit=invalid)


@pytest.mark.parametrize("terminal", ["closed", "escalated"])
def test_allowed_transitions_preserve_evidence_and_order_history(tmp_path, terminal):
    candidate = _candidate()
    _, _, alerts, states, registry = _repositories(tmp_path, candidates=(candidate,))
    analyst = registry.issue_for_trusted_actor("tier1.analyst")
    before = alerts.get(candidate.alert_candidate_id)

    first = _transition(states, analyst, candidate, 0, "in_review", "Triage started")
    second = _transition(states, analyst, candidate, 1, terminal, "Reviewed evidence")
    detail = states.get_alert(analyst, candidate.alert_candidate_id)

    assert (first.disposition, first.analyst_state.state) == ("created", "in_review")
    assert (second.disposition, second.analyst_state.state) == ("created", terminal)
    assert detail is not None
    assert [event.sequence for event in detail.transitions] == [1, 2]
    assert [event.from_state for event in detail.transitions] == ["new", "in_review"]
    assert [event.to_state for event in detail.transitions] == ["in_review", terminal]
    assert alerts.get(candidate.alert_candidate_id) == before == candidate


def test_exact_transition_replay_is_idempotent_and_conflict_fails(tmp_path):
    candidate = _candidate()
    _, _, _, states, registry = _repositories(tmp_path, candidates=(candidate,))
    analyst = registry.issue_for_trusted_actor("tier1.analyst")
    transition_id = str(uuid4())
    first = _transition(states, analyst, candidate, 0, "in_review", "Triage started", transition_id)
    replay = _transition(
        states, analyst, candidate, 0, "in_review", "Triage started", transition_id
    )

    assert first.disposition == "created"
    assert replay.disposition == "existing"
    assert replay.transition == first.transition
    second = _transition(states, analyst, candidate, 1, "closed", "Review completed")
    late_replay = _transition(
        states, analyst, candidate, 0, "in_review", "Triage started", transition_id
    )
    assert late_replay.disposition == "existing"
    assert late_replay.transition == first.transition
    assert late_replay.analyst_state.state == "closed"
    assert states.get_alert(analyst, candidate.alert_candidate_id).transitions == (
        first.transition,
        second.transition,
    )
    with pytest.raises(AnalystStateError, match="^analyst_transition_identity_conflict$"):
        _transition(states, analyst, candidate, 0, "in_review", "Changed note", transition_id)


def test_reordered_invalid_and_terminal_transitions_create_no_partial_event(tmp_path):
    candidate = _candidate()
    _, _, _, states, registry = _repositories(tmp_path, candidates=(candidate,))
    analyst = registry.issue_for_trusted_actor("tier1.analyst")

    with pytest.raises(AnalystStateError, match="^analyst_state_version_conflict$"):
        _transition(states, analyst, candidate, 1, "closed", "Arrived before review")
    with pytest.raises(AnalystStateError, match="^analyst_transition_invalid$"):
        _transition(states, analyst, candidate, 0, "closed", "Skipped review")
    assert states.get_alert(analyst, candidate.alert_candidate_id).transitions == ()

    _transition(states, analyst, candidate, 0, "in_review", "Triage started")
    _transition(states, analyst, candidate, 1, "closed", "False positive")
    with pytest.raises(AnalystStateError, match="^analyst_transition_invalid$"):
        _transition(states, analyst, candidate, 2, "in_review", "Attempted reopen")
    assert len(states.get_alert(analyst, candidate.alert_candidate_id).transitions) == 2


def test_concurrent_commands_for_one_version_commit_exactly_one(tmp_path):
    candidate = _candidate()
    _, _, _, states, registry = _repositories(tmp_path, candidates=(candidate,))
    analyst = registry.issue_for_trusted_actor("tier1.analyst")

    def submit(note):
        try:
            return _transition(states, analyst, candidate, 0, "in_review", note).disposition
        except AnalystStateError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(submit, ("First contender", "Second contender")))

    assert sorted(outcomes) == ["analyst_state_version_conflict", "created"]
    detail = states.get_alert(analyst, candidate.alert_candidate_id)
    assert detail is not None and len(detail.transitions) == 1


def test_concurrent_exact_replay_creates_one_event(tmp_path):
    candidate = _candidate()
    _, _, _, states, registry = _repositories(tmp_path, candidates=(candidate,))
    analyst = registry.issue_for_trusted_actor("tier1.analyst")
    transition_id = str(uuid4())

    def submit(_):
        return _transition(
            states,
            analyst,
            candidate,
            0,
            "in_review",
            "Same command",
            transition_id,
        ).disposition

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(submit, range(2)))

    assert sorted(outcomes) == ["created", "existing"]
    assert len(states.get_alert(analyst, candidate.alert_candidate_id).transitions) == 1


def test_authorization_rejects_unknown_disabled_viewer_forged_and_cross_registry(tmp_path):
    candidate = _candidate()
    _, _, _, states, registry = _repositories(tmp_path, candidates=(candidate,))
    viewer = registry.issue_for_trusted_actor("queue.viewer")
    with pytest.raises(AnalystStateError, match="^analyst_not_authorized$"):
        registry.issue_for_trusted_actor("unknown.analyst")
    with pytest.raises(AnalystStateError, match="^analyst_not_authorized$"):
        registry.issue_for_trusted_actor("disabled.analyst")
    with pytest.raises(AnalystStateError, match="^analyst_not_authorized$"):
        _transition(states, viewer, candidate, 0, "in_review", "Viewer attempted write")

    forged = AnalystCapability("tier1.analyst", "analyst", "forged", b"forged")
    with pytest.raises(AnalystStateError, match="^analyst_not_authorized$"):
        states.list_alerts(forged)
    other = _registry().issue_for_trusted_actor("tier1.analyst")
    with pytest.raises(AnalystStateError, match="^analyst_not_authorized$"):
        states.get_alert(other, candidate.alert_candidate_id)


def test_missing_candidate_and_invalid_annotation_create_nothing(tmp_path):
    candidate = _candidate()
    _, analyst_path, _, states, registry = _repositories(tmp_path, candidates=(candidate,))
    analyst = registry.issue_for_trusted_actor("tier1.analyst")
    missing = _candidate(2)

    with pytest.raises(AnalystStateError, match="^alert_candidate_not_found$"):
        _transition(states, analyst, missing, 0, "in_review", "No candidate")
    for rationale in ("", " leading", "line\nbreak", "x" * (MAX_ANALYST_RATIONALE_BYTES + 1)):
        with pytest.raises(AnalystStateError, match="^analyst_rationale_invalid$"):
            _transition(states, analyst, candidate, 0, "in_review", rationale)
    with sqlite3.connect(analyst_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM analyst_states").fetchone()[0] == 0
        assert (
            connection.execute("SELECT COUNT(*) FROM analyst_transition_events").fetchone()[0] == 0
        )


def test_state_and_history_survive_restart_with_new_process_registry(tmp_path):
    candidate = _candidate()
    alerts_path, analyst_path, _, states, registry = _repositories(
        tmp_path, candidates=(candidate,)
    )
    analyst = registry.issue_for_trusted_actor("tier1.analyst")
    first = _transition(states, analyst, candidate, 0, "in_review", "Triage started")

    reopened_alerts = AlertCandidateRepository(alerts_path)
    reopened_registry = _registry()
    reopened = AnalystStateRepository(analyst_path, reopened_alerts, reopened_registry)
    reopened_viewer = reopened_registry.issue_for_trusted_actor("queue.viewer")
    detail = reopened.get_alert(reopened_viewer, candidate.alert_candidate_id)

    assert detail is not None
    assert detail.candidate == candidate
    assert detail.analyst_state.state == "in_review"
    assert detail.transitions == (first.transition,)
    with pytest.raises(AnalystStateError, match="^analyst_not_authorized$"):
        reopened.get_alert(analyst, candidate.alert_candidate_id)


def test_write_failure_rolls_back_state_and_history(tmp_path):
    candidate = _candidate()
    _, analyst_path, _, states, registry = _repositories(tmp_path, candidates=(candidate,))
    analyst = registry.issue_for_trusted_actor("tier1.analyst")
    with sqlite3.connect(analyst_path) as connection:
        connection.execute(
            "CREATE TRIGGER reject_event BEFORE INSERT ON analyst_transition_events "
            "BEGIN SELECT RAISE(ABORT, 'private detail'); END"
        )

    with pytest.raises(AnalystStateError, match="^database_write_failed$") as error:
        _transition(states, analyst, candidate, 0, "in_review", "Will roll back")
    assert "private" not in str(error.value)
    detail = states.get_alert(analyst, candidate.alert_candidate_id)
    assert detail is not None
    assert detail.analyst_state.state == "new"
    assert detail.transitions == ()


def test_schema_mismatch_and_bad_clock_fail_closed(tmp_path):
    candidate = _candidate()
    _, analyst_path, alerts, states, registry = _repositories(tmp_path, candidates=(candidate,))
    analyst = registry.issue_for_trusted_actor("tier1.analyst")
    with sqlite3.connect(analyst_path) as connection:
        connection.execute("PRAGMA user_version = 2")
    with pytest.raises(AnalystStateError, match="^database_schema_mismatch$"):
        AnalystStateRepository(analyst_path, alerts, registry)

    second_path = tmp_path / "bad-clock.sqlite3"
    bad_clock = AnalystStateRepository(
        second_path,
        alerts,
        registry,
        clock=lambda: datetime(2026, 9, 23),
    )
    with pytest.raises(AnalystStateError, match="^analyst_clock_invalid$"):
        _transition(bad_clock, analyst, candidate, 0, "in_review", "Invalid clock")
