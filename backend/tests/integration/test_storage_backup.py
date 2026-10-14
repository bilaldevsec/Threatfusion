"""Integration tests for coordinated multi-database online backup and atomic restore."""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from threatfusion.db.alert_repository import AlertCandidateRepository
from threatfusion.db.analyst_security_audit import (
    AnalystSecurityAuditRepository,
    create_analyst_security_audit_event,
)
from threatfusion.db.analyst_state_repository import AnalystStateRepository
from threatfusion.operations.storage_backup import (
    ALERTS_DB_FILENAME,
    AUDIT_DB_FILENAME,
    MANIFEST_FILENAME,
    SNAPSHOT_MANIFEST_SCHEMA,
    STATES_DB_FILENAME,
    StorageBackupError,
    create_storage_snapshot,
    main,
    restore_storage_snapshot,
    verify_storage_snapshot,
)
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
)


def _authorization() -> AnalystAuthorizationRegistry:
    return AnalystAuthorizationRegistry(
        (
            AnalystRegistryEntry("queue.viewer", "viewer"),
            AnalystRegistryEntry("analyst_a", "analyst"),
        )
    )


def _candidate(index: int = 1) -> AlertCandidate:
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
        created_at=datetime(2026, 9, 23, 0, index, tzinfo=UTC),
        uncalibrated_model_score=0.75,
        decision_threshold=0.5,
        decision_policy_version=DECISION_POLICY_VERSION,
        decision="Attack",
        inference_status="completed",
        reason="inference_succeeded",
    )


@pytest.fixture
def source_storage(tmp_path: Path):
    """Set up populated alerts, analyst states, and security audit databases in mode 0700 dir."""
    directory = tmp_path / "storage"
    directory.mkdir(mode=0o700)

    alerts_repo = AlertCandidateRepository(directory / ALERTS_DB_FILENAME)
    c1 = _candidate(1)
    c2 = _candidate(2)
    c3 = _candidate(3)
    alerts_repo.insert(c1)
    alerts_repo.insert(c2)
    alerts_repo.insert(c3)

    auth = _authorization()
    states_repo = AnalystStateRepository(directory / STATES_DB_FILENAME, alerts_repo, auth)
    analyst_cap = auth.issue_for_trusted_actor("analyst_a")
    assert isinstance(analyst_cap, AnalystCapability)

    t1_id = str(uuid4())
    res1 = states_repo.transition(
        analyst_cap,
        alert_candidate_id=c1.alert_candidate_id,
        expected_version=0,
        to_state="in_review",
        transition_id=t1_id,
        rationale="Initial triage review started.",
    )
    assert res1.disposition == "created"

    t2_id = str(uuid4())
    res2 = states_repo.transition(
        analyst_cap,
        alert_candidate_id=c1.alert_candidate_id,
        expected_version=1,
        to_state="closed",
        transition_id=t2_id,
        rationale="Confirmed benign activity during review.",
    )
    assert res2.disposition == "created"

    t3_id = str(uuid4())
    res3 = states_repo.transition(
        analyst_cap,
        alert_candidate_id=c2.alert_candidate_id,
        expected_version=0,
        to_state="in_review",
        transition_id=t3_id,
        rationale="Investigating possible scanning behavior.",
    )
    assert res3.disposition == "created"

    audit_repo = AnalystSecurityAuditRepository(directory / AUDIT_DB_FILENAME)
    e1 = create_analyst_security_audit_event(
        event_type="request_admitted",
        processing_stage="admission",
        outcome="admitted",
        reason_code="request_admitted",
        actor_id="analyst_a",
        request_route="/v1/analyst/alerts",
    )
    e2 = create_analyst_security_audit_event(
        event_type="request_completed",
        processing_stage="completion",
        outcome="completed",
        reason_code="request_completed",
        actor_id="analyst_a",
        request_route="/v1/analyst/alerts",
    )
    e3 = create_analyst_security_audit_event(
        event_type="authorization_rejected",
        processing_stage="authorization",
        outcome="rejected",
        reason_code="forbidden",
        actor_id="queue.viewer",
        request_route="/v1/analyst/alerts/transitions",
    )
    audit_repo.append(e1)
    audit_repo.append(e2)
    audit_repo.append(e3)

    return {
        "directory": directory,
        "alerts_repo": alerts_repo,
        "states_repo": states_repo,
        "audit_repo": audit_repo,
        "candidates": (c1, c2, c3),
        "transition_ids": (t1_id, t2_id, t3_id),
        "audit_event_ids": (e1.audit_event_id, e2.audit_event_id, e3.audit_event_id),
    }


def test_end_to_end_snapshot_verification_and_restore(tmp_path: Path, source_storage):
    """Snapshot, verify, and restore across alerts, states, and audit preserving all invariants."""
    source_dir = source_storage["directory"]
    snapshot_dir = tmp_path / "snapshot"

    manifest = create_storage_snapshot(source_dir, snapshot_dir)
    assert manifest["schema"] == SNAPSHOT_MANIFEST_SCHEMA
    assert "created_at_utc" in manifest
    assert set(manifest["databases"].keys()) == {"alerts", "states", "audit"}
    assert manifest["databases"]["alerts"]["row_counts"]["alert_candidates"] == 3
    assert manifest["databases"]["states"]["row_counts"]["analyst_states"] == 2
    assert manifest["databases"]["states"]["row_counts"]["analyst_transition_events"] == 3
    assert manifest["databases"]["audit"]["row_counts"]["audit_events"] == 3
    assert manifest["cross_database_consistency"]["orphan_states_count"] == 0

    verified_manifest = verify_storage_snapshot(snapshot_dir)
    assert verified_manifest == manifest

    target_dir = tmp_path / "restored_storage"
    target_dir.mkdir(mode=0o700)

    restored_manifest = restore_storage_snapshot(snapshot_dir, target_dir)
    assert restored_manifest == manifest

    auth = _authorization()
    restored_alerts = AlertCandidateRepository(target_dir / ALERTS_DB_FILENAME)
    restored_states = AnalystStateRepository(target_dir / STATES_DB_FILENAME, restored_alerts, auth)
    restored_audit = AnalystSecurityAuditRepository(target_dir / AUDIT_DB_FILENAME)

    viewer_cap = auth.issue_for_trusted_actor("queue.viewer")
    assert isinstance(viewer_cap, AnalystCapability)
    analyst_cap = auth.issue_for_trusted_actor("analyst_a")
    assert isinstance(analyst_cap, AnalystCapability)

    alerts_list = restored_states.list_alerts(viewer_cap, limit=50, offset=0)
    assert len(alerts_list) == 3

    c1 = source_storage["candidates"][0]
    detail1 = restored_states.get_alert(viewer_cap, c1.alert_candidate_id)
    assert detail1.analyst_state.state == "closed"
    assert detail1.analyst_state.version == 2
    assert len(detail1.transitions) == 2
    assert detail1.analyst_state.last_transition_id == source_storage["transition_ids"][1]

    replay_res = restored_states.transition(
        analyst_cap,
        alert_candidate_id=c1.alert_candidate_id,
        expected_version=1,
        to_state="closed",
        transition_id=source_storage["transition_ids"][1],
        rationale="Confirmed benign activity during review.",
    )
    assert replay_res.disposition == "existing"

    audit_events = restored_audit.list(limit=50)
    assert len(audit_events) == 3
    retrieved_ids = {e.audit_event_id for e in audit_events}
    assert retrieved_ids == set(source_storage["audit_event_ids"])


def test_digest_tampering_rejected(tmp_path: Path, source_storage):
    """Tampering with a single byte in a snapshot database fails verification and restore."""
    source_dir = source_storage["directory"]
    snapshot_dir = tmp_path / "snapshot"
    create_storage_snapshot(source_dir, snapshot_dir)

    alerts_db = snapshot_dir / ALERTS_DB_FILENAME
    content = bytearray(alerts_db.read_bytes())
    content[100] = (content[100] + 1) % 256
    alerts_db.write_bytes(content)

    with pytest.raises(StorageBackupError) as exc_info:
        verify_storage_snapshot(snapshot_dir)
    assert exc_info.value.code == "digest_mismatch"

    target_dir = tmp_path / "target"
    target_dir.mkdir(mode=0o700)
    with pytest.raises(StorageBackupError) as exc_info:
        restore_storage_snapshot(snapshot_dir, target_dir)
    assert exc_info.value.code == "digest_mismatch"
    assert not (target_dir / ALERTS_DB_FILENAME).exists()


def test_sqlite_truncation_rejected(tmp_path: Path, source_storage):
    """A truncated SQLite file fails snapshot verification."""
    source_dir = source_storage["directory"]
    snapshot_dir = tmp_path / "snapshot"
    create_storage_snapshot(source_dir, snapshot_dir)

    states_db = snapshot_dir / STATES_DB_FILENAME
    states_db.write_bytes(b"short truncate")

    with pytest.raises(StorageBackupError):
        verify_storage_snapshot(snapshot_dir)


def test_cross_database_orphan_state_rejected_at_backup(tmp_path: Path, source_storage):
    """An alert_candidate_id in states absent from alerts fails backup referential check."""
    source_dir = source_storage["directory"]

    conn = sqlite3.connect(str(source_dir / STATES_DB_FILENAME))
    conn.execute(
        "INSERT INTO analyst_states(alert_candidate_id, state, version, updated_at, updated_by, last_transition_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            "orphan_alert_id_9999",
            "in_review",
            1,
            datetime.now(UTC).isoformat(),
            "analyst_a",
            str(uuid4()),
        ),
    )
    conn.commit()
    conn.close()

    snapshot_dir = tmp_path / "snapshot_orphan"
    with pytest.raises(StorageBackupError) as exc_info:
        create_storage_snapshot(source_dir, snapshot_dir)
    assert exc_info.value.code == "referential_integrity_failed"


def test_cross_database_orphan_state_rejected_at_verify(tmp_path: Path, source_storage):
    """An orphan alert_candidate_id injected into snapshot fails verify_storage_snapshot."""
    source_dir = source_storage["directory"]
    snapshot_dir = tmp_path / "snapshot"
    create_storage_snapshot(source_dir, snapshot_dir)

    conn = sqlite3.connect(str(snapshot_dir / STATES_DB_FILENAME))
    conn.execute(
        "INSERT INTO analyst_states(alert_candidate_id, state, version, updated_at, updated_by, last_transition_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            "orphan_alert_id_8888",
            "in_review",
            1,
            datetime.now(UTC).isoformat(),
            "analyst_a",
            str(uuid4()),
        ),
    )
    conn.commit()
    conn.close()

    import hashlib

    hasher = hashlib.sha256()
    hasher.update((snapshot_dir / STATES_DB_FILENAME).read_bytes())
    new_sha256 = hasher.hexdigest()
    new_size = (snapshot_dir / STATES_DB_FILENAME).stat().st_size

    manifest_path = snapshot_dir / MANIFEST_FILENAME
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    manifest["databases"]["states"]["sha256"] = new_sha256
    manifest["databases"]["states"]["size_bytes"] = new_size
    manifest["databases"]["states"]["row_counts"]["analyst_states"] += 1
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    with pytest.raises(StorageBackupError) as exc_info:
        verify_storage_snapshot(snapshot_dir)
    assert exc_info.value.code == "referential_integrity_failed"


def test_symlink_rejection_in_snapshot_and_target(tmp_path: Path, source_storage):
    """Symlinks in snapshot directory, database files, or target directory are rejected."""
    source_dir = source_storage["directory"]
    real_snapshot = tmp_path / "real_snapshot"
    create_storage_snapshot(source_dir, real_snapshot)

    symlink_snapshot = tmp_path / "symlink_snapshot"
    os.symlink(real_snapshot, symlink_snapshot)

    with pytest.raises(StorageBackupError) as exc_info:
        verify_storage_snapshot(symlink_snapshot)
    assert exc_info.value.code == "symlink_rejected"

    snapshot_with_file_symlink = tmp_path / "file_symlink_snapshot"
    create_storage_snapshot(source_dir, snapshot_with_file_symlink)
    alerts_file = snapshot_with_file_symlink / ALERTS_DB_FILENAME
    alerts_file.unlink()
    os.symlink(source_dir / ALERTS_DB_FILENAME, alerts_file)

    with pytest.raises(StorageBackupError) as exc_info:
        verify_storage_snapshot(snapshot_with_file_symlink)
    assert exc_info.value.code == "symlink_rejected"

    real_target = tmp_path / "real_target"
    real_target.mkdir(mode=0o700)
    symlink_target = tmp_path / "symlink_target"
    os.symlink(real_target, symlink_target)

    with pytest.raises(StorageBackupError) as exc_info:
        restore_storage_snapshot(real_snapshot, symlink_target)
    assert exc_info.value.code == "symlink_rejected"


def test_unsafe_directory_permissions_rejected(tmp_path: Path, source_storage):
    """Directories with mode other than 0700 are rejected."""
    source_dir = source_storage["directory"]
    snapshot_dir = tmp_path / "snapshot"
    create_storage_snapshot(source_dir, snapshot_dir)

    os.chmod(snapshot_dir, 0o755)
    with pytest.raises(StorageBackupError) as exc_info:
        verify_storage_snapshot(snapshot_dir)
    assert exc_info.value.code == "permission_invalid"

    os.chmod(snapshot_dir, 0o700)

    target_dir = tmp_path / "target"
    target_dir.mkdir(mode=0o755)
    with pytest.raises(StorageBackupError) as exc_info:
        restore_storage_snapshot(snapshot_dir, target_dir)
    assert exc_info.value.code == "permission_invalid"


def test_unexpected_extra_files_rejected(tmp_path: Path, source_storage):
    """Extraneous files in snapshot directory fail verification."""
    source_dir = source_storage["directory"]
    snapshot_dir = tmp_path / "snapshot"
    create_storage_snapshot(source_dir, snapshot_dir)

    extra_file = snapshot_dir / "unrelated_payload.sql"
    extra_file.write_text("SELECT 1;")
    os.chmod(extra_file, 0o600)

    with pytest.raises(StorageBackupError) as exc_info:
        verify_storage_snapshot(snapshot_dir)
    assert exc_info.value.code == "unexpected_file"


def test_non_empty_snapshot_directory_rejected(tmp_path: Path, source_storage):
    """Creating a snapshot in an already-populated directory fails."""
    source_dir = source_storage["directory"]
    snapshot_dir = tmp_path / "prepopulated_snapshot"
    snapshot_dir.mkdir(mode=0o700)
    (snapshot_dir / "existing.txt").write_text("old")

    with pytest.raises(StorageBackupError) as exc_info:
        create_storage_snapshot(source_dir, snapshot_dir)
    assert exc_info.value.code == "snapshot_directory_not_empty"


def test_lock_contention_rejected(tmp_path: Path, source_storage):
    """Flock contention on snapshot directory raises StorageBackupError."""
    source_dir = source_storage["directory"]
    snapshot_dir = tmp_path / "snapshot"
    snapshot_dir.mkdir(mode=0o700)

    fd = os.open(snapshot_dir, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(StorageBackupError) as exc_info:
            create_storage_snapshot(source_dir, snapshot_dir)
        assert exc_info.value.code == "lock_failed"
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def test_cli_commands(tmp_path: Path, source_storage, capsys):
    """CLI subcommands create, verify, and restore exit 0 with JSON output."""
    source_dir = source_storage["directory"]
    snapshot_dir = tmp_path / "cli_snapshot"
    target_dir = tmp_path / "cli_target"
    target_dir.mkdir(mode=0o700)

    rc_create = main(
        ["create", "--source-dir", str(source_dir), "--snapshot-dir", str(snapshot_dir)]
    )
    assert rc_create == 0
    out_create, _ = capsys.readouterr()
    create_manifest = json.loads(out_create)
    assert create_manifest["schema"] == SNAPSHOT_MANIFEST_SCHEMA

    rc_verify = main(["verify", "--snapshot-dir", str(snapshot_dir)])
    assert rc_verify == 0
    out_verify, _ = capsys.readouterr()
    verify_manifest = json.loads(out_verify)
    assert verify_manifest == create_manifest

    rc_restore = main(
        ["restore", "--snapshot-dir", str(snapshot_dir), "--target-dir", str(target_dir)]
    )
    assert rc_restore == 0
    out_restore, _ = capsys.readouterr()
    restore_manifest = json.loads(out_restore)
    assert restore_manifest == create_manifest
    assert (target_dir / ALERTS_DB_FILENAME).exists()
    assert (target_dir / STATES_DB_FILENAME).exists()
    assert (target_dir / AUDIT_DB_FILENAME).exists()
