"""Unit tests for Jury Requirements Traceability Registry and Offline Retraining Feedback Ledger."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from threatfusion.db.retraining_feedback_ledger import (
    OfflineRetrainingFeedbackRepository,
    RetrainingFeedbackError,
    verify_frozen_models_unmodified,
)
from threatfusion.models.jury_traceability import (
    DATASET_UNSW_NB15,
    FAMILY_AUTOENCODER_V2,
    FAMILY_RANDOM_FOREST,
    JURY_DATASET_DISPOSITIONS,
    JURY_MODEL_FAMILY_DISPOSITIONS,
    JURY_TRACEABILITY_SCHEMA_VERSION,
    JuryTraceabilityError,
    REQUIRED_JURY_DATASETS,
    REQUIRED_JURY_MODEL_FAMILIES,
    verify_jury_traceability_completeness,
)


class TestJuryRequirementsTraceability:
    """Test TF-010 jury requirements traceability matrix."""

    def test_jury_traceability_completeness_and_checksums(self) -> None:
        """Verify that all required datasets and model families are present and checksums match."""
        result = verify_jury_traceability_completeness(verify_checksums=True)

        assert result.schema_version == JURY_TRACEABILITY_SCHEMA_VERSION
        assert result.is_complete is True
        assert result.artifact_checksums_verified is True
        assert len(result.verified_datasets) == len(REQUIRED_JURY_DATASETS)
        assert len(result.verified_model_families) == len(REQUIRED_JURY_MODEL_FAMILIES)

        # Check UNSW-NB15 baseline dataset
        unsw = JURY_DATASET_DISPOSITIONS[DATASET_UNSW_NB15]
        assert unsw.disposition_status == "APPROVED_BASELINE"
        assert unsw.temporal_split_isolation is True
        assert "TF-006" in unsw.leakage_boundary
        assert "TF-007" in unsw.leakage_boundary

        # Check Random Forest baseline family
        rf = JURY_MODEL_FAMILY_DISPOSITIONS[FAMILY_RANDOM_FOREST]
        assert rf.disposition_status == "FROZEN_PRODUCTION_BASELINE"
        assert (
            rf.expected_sha256 == "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"
        )

        # Check Autoencoder v2 family
        ae = JURY_MODEL_FAMILY_DISPOSITIONS[FAMILY_AUTOENCODER_V2]
        assert ae.disposition_status == "EXPERIMENTAL_UNFUSED_ADVISORY"
        assert (
            ae.expected_sha256 == "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23"
        )

    def test_checksum_mismatch_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tampered model file fails closed with checksum mismatch."""
        fake_root = tmp_path / "threatfusion-fake"
        fake_root.mkdir()
        for f_id, fam in JURY_MODEL_FAMILY_DISPOSITIONS.items():
            if fam.model_artifact_path:
                p = fake_root / fam.model_artifact_path
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"tampered content")

        with pytest.raises(JuryTraceabilityError) as exc_info:
            verify_jury_traceability_completeness(repo_root=fake_root, verify_checksums=True)
        assert "model_artifact_sha256_mismatch" in exc_info.value.code


class TestOfflineRetrainingFeedbackLedger:
    """Test OfflineRetrainingFeedbackRepository and zero online weight drift verification."""

    def test_feedback_lifecycle_and_zero_drift(self, tmp_path: Path) -> None:
        """Test recording feedback into mode-0600 SQLite with zero online drift."""
        db_path = tmp_path / "feedback" / "retraining_feedback.sqlite3"
        repo = OfflineRetrainingFeedbackRepository(db_path)

        # Verify file exists and has mode 0600 permissions
        st = db_path.stat()
        file_mode = stat.S_IMODE(st.st_mode)
        assert file_mode == 0o600

        # Record confirmed threat feedback
        res1 = repo.record_feedback(
            transition_request_id="trans-001",
            alert_candidate_id="cand-001",
            stored_detector_decision="attack",
            stored_score=0.95,
            analyst_verified_outcome="confirmed_threat",
            actor_id="analyst-alice",
            recorded_at_utc="2026-10-16T00:00:00Z",
        )
        assert res1["status"] == "created"
        assert res1["transition_request_id"] == "trans-001"
        assert res1["analyst_verified_outcome"] == "confirmed_threat"
        assert (
            res1["rf_model_sha256"]
            == "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"
        )

        # Record false positive feedback
        res2 = repo.record_feedback(
            transition_request_id="trans-002",
            alert_candidate_id="cand-002",
            stored_detector_decision="attack",
            stored_score=0.62,
            analyst_verified_outcome="false_positive",
            actor_id="analyst-bob",
            recorded_at_utc="2026-10-16T00:05:00Z",
        )
        assert res2["status"] == "created"
        assert res2["analyst_verified_outcome"] == "false_positive"

        # Verify count and fetching
        assert repo.count_feedback() == 2
        rec1 = repo.get_feedback("trans-001")
        assert rec1 is not None
        assert rec1.alert_candidate_id == "cand-001"
        assert rec1.analyst_verified_outcome == "confirmed_threat"

        rec_list = repo.list_feedback()
        assert len(rec_list) == 2
        assert rec_list[0].transition_request_id == "trans-001"
        assert rec_list[1].transition_request_id == "trans-002"

        # Assert frozen model hashes remain 100% untouched
        rf_sha, ae_sha = verify_frozen_models_unmodified()
        assert rf_sha == "bd2853a6f9d7f65038cc8bd2da282a2221cb73bda1f1e4c1c714098e8bfcffa9"
        assert ae_sha == "c8675d13869308babf41f269f9437d083daf827781293357e1749d4df0af4b23"

    def test_idempotent_replay_and_conflict(self, tmp_path: Path) -> None:
        """Idempotent retry returns 'existing'; conflicting retry raises error."""
        db_path = tmp_path / "feedback_idemp.sqlite3"
        repo = OfflineRetrainingFeedbackRepository(db_path)

        # Initial insert
        res1 = repo.record_feedback(
            transition_request_id="trans-idemp",
            alert_candidate_id="cand-idemp",
            stored_detector_decision="attack",
            stored_score=0.88,
            analyst_verified_outcome="confirmed_threat",
            actor_id="analyst-charlie",
            recorded_at_utc="2026-10-16T00:00:00Z",
        )
        assert res1["status"] == "created"

        # Exact identical retry returns 'existing'
        res2 = repo.record_feedback(
            transition_request_id="trans-idemp",
            alert_candidate_id="cand-idemp",
            stored_detector_decision="attack",
            stored_score=0.88,
            analyst_verified_outcome="confirmed_threat",
            actor_id="analyst-charlie",
            recorded_at_utc="2026-10-16T00:00:00Z",
        )
        assert res2["status"] == "existing"
        assert repo.count_feedback() == 1

        # Conflicting retry with different outcome raises error
        with pytest.raises(RetrainingFeedbackError) as exc_info:
            repo.record_feedback(
                transition_request_id="trans-idemp",
                alert_candidate_id="cand-idemp",
                stored_detector_decision="attack",
                stored_score=0.88,
                analyst_verified_outcome="false_positive",  # CONFLICT!
                actor_id="analyst-charlie",
            )
        assert exc_info.value.code == "conflicting_feedback_retry"

    def test_fail_closed_validation(self, tmp_path: Path) -> None:
        """Invalid inputs fail closed."""
        db_path = tmp_path / "feedback_val.sqlite3"
        repo = OfflineRetrainingFeedbackRepository(db_path)

        # Invalid outcome
        with pytest.raises(RetrainingFeedbackError) as exc_info:
            repo.record_feedback(
                transition_request_id="trans-err",
                alert_candidate_id="cand-err",
                stored_detector_decision="attack",
                stored_score=0.88,
                analyst_verified_outcome="unsupported_outcome",
                actor_id="analyst-alice",
            )
        assert exc_info.value.code == "invalid_analyst_verified_outcome"

        # Invalid actor ID
        with pytest.raises(RetrainingFeedbackError) as exc_info:
            repo.record_feedback(
                transition_request_id="trans-err",
                alert_candidate_id="cand-err",
                stored_detector_decision="attack",
                stored_score=0.88,
                analyst_verified_outcome="confirmed_threat",
                actor_id="bad actor id!",
            )
        assert exc_info.value.code == "invalid_actor_id"

        # Invalid score
        with pytest.raises(RetrainingFeedbackError) as exc_info:
            repo.record_feedback(
                transition_request_id="trans-err",
                alert_candidate_id="cand-err",
                stored_detector_decision="attack",
                stored_score=1.5,
                analyst_verified_outcome="confirmed_threat",
                actor_id="analyst-alice",
            )
        assert exc_info.value.code == "invalid_stored_score"
