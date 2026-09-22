"""Deterministic process-isolation tests for registered producer inference."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from threatfusion.api.producer_inference_worker import (
    PROCESSING_RECORD_SECONDS,
    PROCESSING_REQUEST_SECONDS,
    ProducerInferenceWorkerError,
    ProducerInferenceWorkerLimits,
    TerminatingProducerInferenceWorker,
)

REFERENCE = (("b" * 64, 1),)
MANIFEST = "c" * 64


def _executor(
    tmp_path: Path,
    mode: str,
    *,
    record_seconds: float = 1.0,
    request_seconds: float = 15.0,
) -> TerminatingProducerInferenceWorker:
    return TerminatingProducerInferenceWorker(
        project_root=tmp_path.resolve(),
        manifest_sha256=MANIFEST,
        limits=ProducerInferenceWorkerLimits(
            record_seconds=record_seconds,
            request_seconds=request_seconds,
            cleanup_seconds=1.0,
        ),
        _test_mode=mode,
    )


def _assert_exact_worker_gone(executor: TerminatingProducerInferenceWorker) -> None:
    pid = executor.last_worker_pid
    assert type(pid) is int and pid > 1
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    process_group_id = executor.last_worker_process_group_id
    if process_group_id is not None:
        with pytest.raises(ProcessLookupError):
            os.killpg(process_group_id, 0)


def test_production_deadline_defaults_are_exact_and_shorter_limits_only():
    limits = ProducerInferenceWorkerLimits()
    assert limits.record_seconds == PROCESSING_RECORD_SECONDS == 30.0
    assert limits.request_seconds == PROCESSING_REQUEST_SECONDS == 300.0
    with pytest.raises(ProducerInferenceWorkerError, match="^worker_start_failed$"):
        ProducerInferenceWorkerLimits(record_seconds=30.01)
    with pytest.raises(ProducerInferenceWorkerError, match="^worker_start_failed$"):
        ProducerInferenceWorkerLimits(request_seconds=300.01)


def test_spawn_configuration_rejects_arbitrary_callable_and_nonprimitive_reference(tmp_path):
    with pytest.raises(ProducerInferenceWorkerError, match="^worker_start_failed$"):
        TerminatingProducerInferenceWorker(
            project_root=tmp_path.resolve(),
            manifest_sha256=MANIFEST,
            _test_mode=lambda: None,  # type: ignore[arg-type]
        )
    executor = _executor(tmp_path, "success_normal")
    with pytest.raises(ProducerInferenceWorkerError, match="^worker_start_failed$"):
        executor.execute(((object(), 1),))  # type: ignore[arg-type]
    assert executor.last_worker_pid is None


def test_successful_worker_result_is_validated_and_worker_is_joined(tmp_path):
    executor = _executor(tmp_path, "success_normal")
    results = executor.execute(REFERENCE)
    assert len(results) == 1
    assert results[0].inference.predicted_class == "Normal"
    assert executor.completed_record_count == 1
    _assert_exact_worker_gone(executor)


@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("crash", "worker_crashed"),
        ("silent_exit", "worker_response_missing"),
        ("malformed_wire", "worker_response_invalid"),
        ("malformed_result", "worker_response_invalid"),
        ("child_failure", "worker_failed"),
    ],
)
def test_worker_failure_is_sanitized_and_exact_child_is_reaped(tmp_path, mode, code):
    executor = _executor(tmp_path, mode)
    with pytest.raises(ProducerInferenceWorkerError, match=f"^{code}$") as caught:
        executor.execute(REFERENCE)
    rendered = f"{caught.value!r} {caught.value}"
    assert "/private" not in rendered and "secret" not in rendered
    assert executor.completed_record_count == 0
    _assert_exact_worker_gone(executor)


def test_whole_request_deadline_terminates_and_joins_exact_worker(tmp_path):
    executor = _executor(tmp_path, "request_hang", request_seconds=0.5)
    with pytest.raises(ProducerInferenceWorkerError, match="^worker_request_timeout$"):
        executor.execute(REFERENCE)
    _assert_exact_worker_gone(executor)


def test_per_record_deadline_terminates_and_joins_exact_worker(tmp_path):
    executor = _executor(
        tmp_path,
        "record_hang",
        record_seconds=0.2,
        request_seconds=15.0,
    )
    with pytest.raises(ProducerInferenceWorkerError, match="^worker_record_timeout$"):
        executor.execute(REFERENCE)
    _assert_exact_worker_gone(executor)


def test_worker_that_fails_to_exit_after_complete_is_forcibly_killed(tmp_path):
    executor = _executor(tmp_path, "cleanup_hang", request_seconds=15.0)
    with pytest.raises(ProducerInferenceWorkerError, match="^worker_cleanup_failed$"):
        executor.execute(REFERENCE)
    assert executor.completed_record_count == 0
    _assert_exact_worker_gone(executor)


def test_later_valid_execution_succeeds_after_prior_worker_failure(tmp_path):
    failed = _executor(tmp_path, "crash")
    with pytest.raises(ProducerInferenceWorkerError):
        failed.execute(REFERENCE)
    _assert_exact_worker_gone(failed)

    valid = _executor(tmp_path, "success_normal")
    assert valid.execute(REFERENCE)[0].inference.reason == "inference_succeeded"
    _assert_exact_worker_gone(valid)
