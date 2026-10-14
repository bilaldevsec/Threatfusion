"""Integration tests for tamper-evident security audit export, verification, and retention pruning."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from backend.tests.integration import test_analyst_tls_service as api
from backend.tests.integration import test_operator_human_credentials as operator
from threatfusion.db.analyst_security_audit import (
    AUDIT_EVENT_SCHEMA_VERSION,
    AnalystSecurityAuditEvent,
    AnalystSecurityAuditRepository,
)
from threatfusion.operations.audit_retention import (
    AuditRetentionError,
    export_security_audit_archive,
    prune_archived_security_audit,
    verify_security_audit_archive,
)
from threatfusion.operations.human_listener_lifecycle import HumanListenerLifecycle

certificates = api.certificates
directory = operator.directory


def _event(offset_seconds: int, event_type: str = "request_admitted") -> AnalystSecurityAuditEvent:
    t = datetime.now(UTC) + timedelta(seconds=offset_seconds)
    stage = "admission" if event_type in ("request_admitted", "request_rejected") else "completion"
    outcome = "admitted" if event_type == "request_admitted" else "completed"
    code = "request_admitted" if event_type == "request_admitted" else "request_completed"
    return AnalystSecurityAuditEvent(
        schema_version=AUDIT_EVENT_SCHEMA_VERSION,
        audit_event_id=str(uuid.uuid4()),
        event_time=t,
        correlation_id=str(uuid.uuid4()),
        event_type=event_type,
        processing_stage=stage,
        outcome=outcome,
        reason_code=code,
        actor_id="analyst_a",
        request_route="/v1/analyst/alerts",
    )


@pytest.fixture
def audit_db_setup(tmp_path):
    storage_dir = tmp_path / "audit_storage"
    storage_dir.mkdir(mode=0o700)
    audit_path = storage_dir / "audit.sqlite3"
    repo = AnalystSecurityAuditRepository(audit_path)
    return repo, audit_path, storage_dir


def test_export_verify_and_prune_prefix(audit_db_setup, tmp_path):
    """Export prefix rows to archive, verify integrity, and prune prefix leaving newer rows."""
    repo, audit_path, _ = audit_db_setup

    events = [_event(i) for i in range(5)]
    for ev in events:
        repo.append(ev)

    assert len(repo.list(limit=50)) == 5

    archive_dir = tmp_path / "archive_1"
    archive_dir.mkdir(mode=0o700)

    # Export up to 3rd event
    up_to_id = events[2].audit_event_id
    manifest = export_security_audit_archive(audit_path, archive_dir, up_to_audit_id=up_to_id)

    assert manifest["schema"] == "security_audit_archive_v1"
    assert manifest["row_count"] == 3
    assert manifest["first_audit_id"] == events[0].audit_event_id
    assert manifest["last_audit_id"] == events[2].audit_event_id

    # Verify archive
    verified = verify_security_audit_archive(archive_dir)
    assert verified == manifest

    # Prune verified prefix
    result = prune_archived_security_audit(audit_path, archive_dir)
    assert result["status"] == "pruned"
    assert result["pruned_rows_count"] == 3
    assert result["first_pruned_audit_id"] == events[0].audit_event_id
    assert result["last_pruned_audit_id"] == events[2].audit_event_id

    # Remaining in DB: exactly 2 events (events[3] and events[4])
    remaining = repo.list(limit=50)
    assert len(remaining) == 2
    assert remaining[0].audit_event_id == events[3].audit_event_id
    assert remaining[1].audit_event_id == events[4].audit_event_id


def test_export_all_and_prune_all(audit_db_setup, tmp_path):
    """Export all events when up_to_audit_id is None and prune completely."""
    repo, audit_path, _ = audit_db_setup

    events = [_event(i) for i in range(3)]
    for ev in events:
        repo.append(ev)

    archive_dir = tmp_path / "archive_all"
    archive_dir.mkdir(mode=0o700)

    manifest = export_security_audit_archive(audit_path, archive_dir)
    assert manifest["row_count"] == 3

    result = prune_archived_security_audit(audit_path, archive_dir)
    assert result["pruned_rows_count"] == 3
    assert len(repo.list(limit=50)) == 0


def test_verify_detects_digest_mismatch_and_tampering(audit_db_setup, tmp_path):
    """Tampering with archive jsonl or manifest fails closed."""
    repo, audit_path, _ = audit_db_setup
    repo.append(_event(0))

    archive_dir = tmp_path / "archive_tamper"
    archive_dir.mkdir(mode=0o700)
    _ = export_security_audit_archive(audit_path, archive_dir)

    # 1. Modify events file
    events_file = archive_dir / "audit_events.jsonl"
    events_file.write_bytes(events_file.read_bytes() + b"extra\n")

    with pytest.raises(AuditRetentionError) as exc_info:
        verify_security_audit_archive(archive_dir)
    assert exc_info.value.code in ("digest_mismatch", "archive_tampered")

    # 2. Re-export clean archive
    clean_archive = tmp_path / "archive_clean"
    clean_archive.mkdir(mode=0o700)
    manifest_clean = export_security_audit_archive(audit_path, clean_archive)

    # Tamper with manifest digest
    m_file = clean_archive / "manifest.json"
    manifest_clean["sha256_digest"] = "0" * 64
    m_file.write_text(json.dumps(manifest_clean))

    with pytest.raises(AuditRetentionError) as exc_info:
        verify_security_audit_archive(clean_archive)
    assert exc_info.value.code == "digest_mismatch"


def test_prune_fails_closed_on_prefix_mismatch(audit_db_setup, tmp_path):
    """prune_archived_security_audit refuses to delete if database rows were mutated."""
    repo, audit_path, _ = audit_db_setup

    events = [_event(i) for i in range(3)]
    for ev in events:
        repo.append(ev)

    archive_dir = tmp_path / "archive_mismatch"
    archive_dir.mkdir(mode=0o700)
    export_security_audit_archive(audit_path, archive_dir)

    # Mutate row 0 in SQLite
    with sqlite3.connect(audit_path) as conn:
        conn.execute(
            "UPDATE audit_events SET request_route = '/v1/tampered' " "WHERE audit_event_id = ?",
            (events[0].audit_event_id,),
        )
        conn.commit()

    with pytest.raises(AuditRetentionError) as exc_info:
        prune_archived_security_audit(audit_path, archive_dir)
    assert exc_info.value.code == "prefix_mismatch"

    # Verify zero rows deleted
    assert len(repo.list(limit=50)) == 3


def test_export_rejects_empty_db_or_nonexistent_event(audit_db_setup, tmp_path):
    """Exporting 0 events or invalid up_to_audit_id fails closed."""
    repo, audit_path, _ = audit_db_setup

    archive_dir = tmp_path / "empty_archive"
    archive_dir.mkdir(mode=0o700)

    # Empty DB
    with pytest.raises(AuditRetentionError) as exc_info:
        export_security_audit_archive(audit_path, archive_dir)
    assert exc_info.value.code == "no_events_to_archive"

    # Add 1 event, but pass unknown up_to_audit_id
    repo.append(_event(0))
    with pytest.raises(AuditRetentionError) as exc_info:
        export_security_audit_archive(audit_path, archive_dir, up_to_audit_id=str(uuid.uuid4()))
    assert exc_info.value.code == "event_not_found"


def test_symlink_and_unsafe_permissions_rejected(audit_db_setup, tmp_path):
    """Symlinks and unsafe permissions on audit db or archive dir are rejected."""
    repo, audit_path, _ = audit_db_setup
    repo.append(_event(0))

    # Symlinked archive dir
    target = tmp_path / "real_archive"
    target.mkdir(mode=0o700)
    symlink_archive = tmp_path / "symlink_archive"
    symlink_archive.symlink_to(target)

    with pytest.raises(AuditRetentionError) as exc_info:
        export_security_audit_archive(audit_path, symlink_archive)
    assert exc_info.value.code in ("symlink_rejected", "directory_invalid")


def test_quiescent_audit_prune_on_lifecycle(tmp_path, certificates, directory):
    """HumanListenerLifecycle.prune_security_audit_quiescent drains, prunes, and resumes."""
    operator.enroll(directory, certificates)
    operator.enroll(directory, certificates, "analyst_a", "analyst_a", create=False)
    template, candidate, alerts, states, audit = api._listener(tmp_path, certificates)
    service = HumanListenerLifecycle(
        directory,
        template._configuration,
        template._configuration,
        template._authorization,
        template._view,
        audit,
        storage_directory=tmp_path / "storage",
    )
    try:
        service.replace()
        gen_before = service.snapshot()["generation"]

        # Append audit events
        events = [_event(i) for i in range(3)]
        for ev in events:
            audit.append(ev)

        archive_dir = tmp_path / "quiescent_archive"
        archive_dir.mkdir(mode=0o700)

        export_security_audit_archive(audit._database_path, archive_dir)

        # Quiescent prune
        result = service.prune_security_audit_quiescent(archive_dir)
        assert result["status"] == "pruned"
        assert result["pruned_rows_count"] == 3

        # Service resumed
        snap_after = service.snapshot()
        assert snap_after["accepting"] is True
        assert snap_after["generation"] == gen_before + 1
        assert len(audit.list(limit=50)) == 0
    finally:
        service.shutdown()
