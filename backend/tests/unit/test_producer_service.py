"""Deterministic lifecycle tests around the one-request orchestrator."""

from __future__ import annotations

import time
from queue import Empty, Queue
from threading import Event, Thread
from types import MethodType

import pytest

from backend.tests.unit.test_producer_orchestrator import make_orchestrator
from threatfusion.api.producer_orchestrator import (
    ProducerOrchestratorError,
    ProducerOrchestratorResult,
)
from threatfusion.api.producer_service import (
    PRODUCER_SERVICE_HANDLER_COUNT,
    STATE_FAILED,
    STATE_READY,
    STATE_STOPPED,
    ProducerServiceError,
    ProducerServingLifecycle,
)


def _wait_for(predicate, seconds: float = 2.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError("condition_not_reached")


def _controlled_service(tmp_path, monkeypatch):
    orchestrator, *_ = make_orchestrator(tmp_path)
    attempts: Queue[object] = Queue()

    def process_one(self):
        try:
            selected = attempts.get(timeout=0.02)
        except Empty:
            raise ProducerOrchestratorError("accept_timeout") from None
        if isinstance(selected, BaseException):
            raise selected
        if callable(selected):
            return selected()
        return selected

    monkeypatch.setattr(orchestrator, "process_one", MethodType(process_one, orchestrator))
    return orchestrator, attempts, ProducerServingLifecycle(orchestrator, _shutdown_seconds=1.0)


def test_start_readiness_shutdown_and_clean_restart(tmp_path, monkeypatch):
    _, _, service = _controlled_service(tmp_path, monkeypatch)
    service.start()
    ready = service.snapshot()
    assert ready.state == STATE_READY and ready.ready
    assert ready.handler_limit == ready.live_handler_count == PRODUCER_SERVICE_HANDLER_COUNT == 2

    service.shutdown()
    stopped = service.snapshot()
    assert stopped.state == STATE_STOPPED and not stopped.ready
    assert stopped.live_handler_count == 0

    service.start()
    assert service.snapshot().start_count == 2
    service.shutdown()
    assert service.snapshot().live_handler_count == 0


def test_successive_attempts_use_fixed_handlers_without_idle_failures(tmp_path, monkeypatch):
    _, attempts, service = _controlled_service(tmp_path, monkeypatch)
    service.start()
    attempts.put(ProducerOrchestratorResult("request_completed", b"one", False))
    attempts.put(ProducerOrchestratorResult("request_completed", b"two", False))
    _wait_for(lambda: service.snapshot().completed_attempt_count == 2)
    snapshot = service.snapshot()
    assert snapshot.ready and snapshot.failed_attempt_count == 0
    service.shutdown()


def test_fatal_generation_stops_admission_and_cannot_restart(tmp_path, monkeypatch):
    orchestrator, attempts, service = _controlled_service(tmp_path, monkeypatch)
    service.start()
    orchestrator._fatal = True
    attempts.put(ProducerOrchestratorError("service_fatal"))
    _wait_for(lambda: service.snapshot().state == STATE_FAILED)
    service.shutdown()
    assert service.snapshot().live_handler_count == 0
    with pytest.raises(ProducerServiceError, match="^service_state_invalid$"):
        service.start()


def test_graceful_shutdown_stops_admission_and_drains_inflight_attempt(tmp_path, monkeypatch):
    _, attempts, service = _controlled_service(tmp_path, monkeypatch)
    entered = Event()
    release = Event()

    def inflight():
        entered.set()
        assert release.wait(1)
        return ProducerOrchestratorResult("request_completed", b"done", False)

    service.start()
    attempts.put(inflight)
    assert entered.wait(1)
    stopping = Thread(target=service.shutdown)
    stopping.start()
    time.sleep(0.02)
    assert stopping.is_alive()
    release.set()
    stopping.join(1)
    assert not stopping.is_alive()
    snapshot = service.snapshot()
    assert snapshot.state == STATE_STOPPED
    assert snapshot.completed_attempt_count == 1 and snapshot.live_handler_count == 0
