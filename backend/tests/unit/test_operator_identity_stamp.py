"""Operator stamps follow an enrolled lab certificate. analyst_a stays a local label."""

from __future__ import annotations

from pathlib import Path

from threatfusion.api.live_soc_console import (
    approve_live_soar,
    enroll_lab_operator,
    persist_scored_flow,
    record_analyst_verdict,
    record_case_assignment,
    record_triage_action,
    score_canonical_flow,
)
from threatfusion.models.drift_and_supply_chain import CANONICAL_14_FEATURES
from threatfusion.operations.human_credentials import active_fingerprint, restrict

REPO_ROOT = Path(__file__).resolve().parents[3]


def _features() -> dict[str, float]:
    return {name: 1.0 for name in CANONICAL_14_FEATURES}


class _Width14Model:
    n_features_in_ = 14

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        return [[0.2, 0.81]]


def _flow(tmp_path: Path) -> tuple[Path, int]:
    db_path = tmp_path / "live.sqlite3"
    stored = persist_scored_flow(
        db_path,
        _features(),
        score_canonical_flow(
            _features(), repo_root=REPO_ROOT, model=_Width14Model(), supply_verified=True
        ),
    )
    return db_path, int(stored["flow_id"])


def test_analyst_a_stays_unverified_until_a_different_actor_is_enrolled(tmp_path: Path) -> None:
    directory = tmp_path / "policy"
    refused = enroll_lab_operator(directory, "analyst_a")
    assert refused["identity_verified"] is False
    assert refused["identity_label"] == "unverified_local_label"
    assert refused["operator_id"] == ""

    db_path, flow_id = _flow(tmp_path)
    local = record_analyst_verdict(
        db_path,
        flow_id=flow_id,
        verdict="false_positive",
        rationale="The stored score stands. No new address is named.",
        actor_id="analyst_a",
        policy_dir=directory,
    )
    assert local["identity_verified"] is False
    assert local["identity_label"] == "unverified_local_label"
    assert local["cert_sha256_prefix"] == ""

    enrolled = enroll_lab_operator(directory, "lab_operator")
    assert enrolled["evidence_state"] == "verified"
    assert enrolled["identity_verified"] is True
    assert enrolled["operator_id"] == "lab_operator"
    assert len(enrolled["cert_sha256_prefix"]) == 16
    fingerprint = active_fingerprint(directory, "lab_operator")
    assert fingerprint is not None
    assert enrolled["cert_sha256_prefix"] == fingerprint[:16]

    saved = record_analyst_verdict(
        db_path,
        flow_id=flow_id,
        verdict="true_positive",
        rationale="The stored score stands. No new address is named.",
        actor_id="lab_operator",
        policy_dir=directory,
    )
    assert saved["identity_verified"] is True
    assert saved["operator_id"] == "lab_operator"
    assert saved["cert_sha256_prefix"] == fingerprint[:16]

    assigned = record_case_assignment(
        db_path,
        flow_id=flow_id,
        assignee_id="lab_operator",
        review_status="in_review",
        policy_dir=directory,
    )
    assert assigned["identity_verified"] is True
    triaged = record_triage_action(
        db_path,
        flow_id=flow_id,
        action="acknowledge",
        actor_id="lab_operator",
        policy_dir=directory,
    )
    assert triaged["identity_verified"] is True
    approved = approve_live_soar(
        db_path,
        tmp_path / "soar.sqlite3",
        flow_id=flow_id,
        actor_id="lab_operator",
        reason="Analyst recorded local approval. Containment is not executed.",
        policy_dir=directory,
    )
    assert approved["identity_verified"] is True
    assert approved["containment_executed"] is False
    assert approved["cert_sha256_prefix"] == fingerprint[:16]

    restrict(directory, fingerprint, revoke=True)
    revoked = record_triage_action(
        db_path,
        flow_id=flow_id,
        action="escalate",
        actor_id="lab_operator",
        policy_dir=directory,
    )
    assert revoked["identity_verified"] is False
    assert revoked["identity_label"] == "unverified_local_label"
    assert active_fingerprint(directory, "lab_operator") is None
