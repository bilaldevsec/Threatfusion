"""Parent-side atomicity and recovery tests around the inference worker."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from backend.tests.unit.test_producer_inference_worker import MANIFEST
from backend.tests.unit.test_producer_orchestrator import (
    body_for,
    decoded,
    make_orchestrator,
    process,
)
from threatfusion.api.producer_admission import REGISTERED_UNSW_PRODUCER_ID
from threatfusion.api.producer_inference_worker import (
    ProducerInferenceWorkerLimits,
    TerminatingProducerInferenceWorker,
)


def _worker(tmp_path: Path, mode: str) -> TerminatingProducerInferenceWorker:
    return TerminatingProducerInferenceWorker(
        project_root=tmp_path.resolve(),
        manifest_sha256=MANIFEST,
        limits=ProducerInferenceWorkerLimits(
            record_seconds=1.0,
            request_seconds=15.0,
            cleanup_seconds=1.0,
        ),
        _test_mode=mode,
    )


def _assert_gone(executor: TerminatingProducerInferenceWorker) -> None:
    worker_pid = executor.last_worker_pid
    assert worker_pid is not None
    with pytest.raises(ProcessLookupError):
        os.kill(worker_pid, 0)
    process_group_id = executor.last_worker_process_group_id
    if process_group_id is not None:
        with pytest.raises(ProcessLookupError):
            os.killpg(process_group_id, 0)


def test_malformed_second_result_has_no_partial_alert_and_later_request_succeeds(
    tmp_path,
):
    orchestrator, _, audit, alerts, gates, _, _ = make_orchestrator(tmp_path)
    failed_worker = _worker(tmp_path, "malformed_after_attack")
    orchestrator._worker = failed_worker
    orchestrator._inline_inference_for_tests = False

    failed, failed_connection = process(orchestrator, body_for(rows=(1, 2)))
    response = decoded(failed_connection)
    assert failed.reason == response.reason == "internal_error"
    assert response.records == ()
    assert alerts.list() == ()
    assert not orchestrator.fatal
    assert "/private" not in repr(failed.response_bytes) and "credential" not in repr(
        failed.response_bytes
    )
    _assert_gone(failed_worker)

    valid_worker = _worker(tmp_path, "success_normal")
    orchestrator._worker = valid_worker
    valid, valid_connection = process(
        orchestrator,
        body_for(
            nonce="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        ),
    )
    assert valid.reason == decoded(valid_connection).reason == "request_completed"
    assert alerts.list() == ()
    assert gates.snapshot().released_count == 2
    assert [event.event_type for event in audit.list()].count("internal_failure") == 1
    _assert_gone(valid_worker)


def test_invalid_authenticated_request_never_starts_worker_or_persistence(tmp_path):
    orchestrator, _, _, alerts, _, _, _ = make_orchestrator(tmp_path)
    executor = _worker(tmp_path, "success_normal")
    orchestrator._worker = executor
    orchestrator._inline_inference_for_tests = False

    result, connection = process(
        orchestrator,
        body_for(producer_id=f"{REGISTERED_UNSW_PRODUCER_ID}-mismatch"),
    )
    assert result.reason == decoded(connection).reason == "request_rejected"
    assert executor.last_worker_pid is None
    assert alerts.list() == ()


def test_record_timeout_returns_sanitized_processing_timeout_without_alert(tmp_path):
    orchestrator, _, _, alerts, _, _, _ = make_orchestrator(tmp_path)
    executor = TerminatingProducerInferenceWorker(
        project_root=tmp_path.resolve(),
        manifest_sha256=MANIFEST,
        limits=ProducerInferenceWorkerLimits(
            record_seconds=0.2,
            request_seconds=15.0,
            cleanup_seconds=1.0,
        ),
        _test_mode="record_hang",
    )
    orchestrator._worker = executor
    orchestrator._inline_inference_for_tests = False

    result, connection = process(orchestrator, body_for())
    response = decoded(connection)
    assert result.reason == response.reason == "processing_timeout"
    assert response.records == ()
    assert alerts.list() == ()
    assert not orchestrator.fatal
    assert b"worker" not in result.response_bytes
    _assert_gone(executor)


def test_completed_replay_keeps_exact_bytes_without_starting_another_worker(tmp_path):
    body = body_for()
    orchestrator, _, _, alerts, _, _, _ = make_orchestrator(tmp_path)
    executor = _worker(tmp_path, "success_normal")
    orchestrator._worker = executor
    orchestrator._inline_inference_for_tests = False

    first, _ = process(orchestrator, body)
    first_pid = executor.last_worker_pid
    retry, _ = process(orchestrator, body)
    assert retry.response_bytes == first.response_bytes
    assert executor.last_worker_pid == first_pid
    assert executor.completed_record_count == 1
    assert alerts.list() == ()
    _assert_gone(executor)
