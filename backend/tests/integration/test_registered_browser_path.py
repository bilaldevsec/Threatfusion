"""One registered RF producer input reaches the persisted read-only browser view."""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path

import scripts.run_fyp_progress_demo as replay_demo
import scripts.run_registered_browser_path as browser_path
from threatfusion.models.network_inference import (
    APPROVED_MODEL_HASHES,
    APPROVED_UNSW_MANIFEST_HASH,
)
from threatfusion.schemas.alert_candidate import (
    DECISION_POLICY_VERSION,
    DETECTOR_IDENTITY,
    DETECTOR_VERSION,
    derive_alert_candidate_id,
    derive_source_event_id,
)
from threatfusion.features.network_behavior import UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1


def test_one_registered_attack_reaches_authenticated_browser_and_degrades_cleanly(
    monkeypatch, capsys
) -> None:
    runtimes: list[Path] = []
    original_runtime = replay_demo._temporary_runtime

    @contextmanager
    def capture_runtime():
        with original_runtime() as runtime:
            runtimes.append(runtime)
            yield runtime

    monkeypatch.setattr(replay_demo, "_temporary_runtime", capture_runtime)

    original_run = browser_path.run_registered_browser_path
    inspections = []

    def inspect(root, browser, credentials, detail):
        assert root.exists()
        assert browser.address[0] == "127.0.0.1"
        assert detail["explanation"]["status"] == "available"
        assert detail["explanation"]["schema_version"] == "alert_explanation_v1"
        inspections.append(detail["explanation"]["summary"])

    monkeypatch.setattr(browser_path, "run_registered_browser_path", lambda: original_run(inspect))
    assert browser_path.main([]) == 0
    assert len(inspections) == 1
    evidence = json.loads(capsys.readouterr().out)
    expected_source_id = derive_source_event_id(
        source_representation=UNSW_NB15_ARGUS_RAW_REPRESENTATION_V1,
        manifest_sha256=APPROVED_UNSW_MANIFEST_HASH,
        source_member_sha256=replay_demo.MEMBER_SHA256,
        row_number=browser_path.REGISTERED_ROW_NUMBER,
    )
    expected_candidate_id = derive_alert_candidate_id(
        source_event_id=expected_source_id,
        detector_identity=DETECTOR_IDENTITY,
        detector_version=DETECTOR_VERSION,
        model_identity="random_forest",
        model_version="network_random_forest_baseline_v1",
        model_artifact_sha256=APPROVED_MODEL_HASHES["random_forest"]["model"],
        decision_policy_version=DECISION_POLICY_VERSION,
    )

    assert evidence == {
        "status": "completed",
        "scope": "one_registered_unsw_replay_automated_tls_not_manual_browser",
        "source_member_sha256": replay_demo.MEMBER_SHA256,
        "row_number": 21,
        "producer_tls": "TLSv1.3",
        "producer_http_status": 200,
        "alert_candidate_id": expected_candidate_id,
        "source_event_id": expected_source_id,
        "model_identity": "random_forest",
        "model_artifact_sha256": APPROVED_MODEL_HASHES["random_forest"]["model"],
        "model_decision": "Attack",
        "analyst_state": "new",
        "analyst_state_version": 0,
        "browser_queue_http_status": 200,
        "browser_detail_http_status": 200,
        "injected_view_failure_http_status": 503,
        "persisted_alert_count": 1,
    }
    assert len(runtimes) == 1 and not runtimes[0].exists()
