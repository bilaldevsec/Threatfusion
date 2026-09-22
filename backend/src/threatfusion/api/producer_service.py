"""Terminating serving lifecycle for the synchronous producer orchestrator."""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass

from threatfusion.api.producer_orchestrator import (
    ProducerOrchestrator,
    ProducerOrchestratorError,
)

PRODUCER_SERVICE_HANDLER_COUNT = 2
PRODUCER_SERVICE_SHUTDOWN_SECONDS = 310.0

STATE_CREATED = "created"
STATE_STARTING = "starting"
STATE_READY = "ready"
STATE_STOPPING = "stopping"
STATE_STOPPED = "stopped"
STATE_FAILED = "failed"


class ProducerServiceError(RuntimeError):
    """Allowlisted lifecycle failure without request or dependency details."""

    _CODES = frozenset(
        {
            "service_configuration_invalid",
            "service_state_invalid",
            "service_start_failed",
            "service_shutdown_timeout",
            "service_failed",
        }
    )

    def __init__(self, code: str) -> None:
        self.code = code if code in self._CODES else "service_failed"
        super().__init__(self.code)

    def __repr__(self) -> str:
        return "<ProducerServiceError>"


@dataclass(frozen=True, slots=True, repr=False)
class ProducerServiceSnapshot:
    """Bounded count-only lifecycle state."""

    state: str
    ready: bool
    start_count: int
    handler_limit: int
    live_handler_count: int
    completed_attempt_count: int
    failed_attempt_count: int

    def __repr__(self) -> str:
        return "<ProducerServiceSnapshot>"


class ProducerServingLifecycle:
    """Own one listener and two fixed no-queue request-handler threads.

    The orchestrator's existing process-local gate remains the sole execution admission
    authority and permits one active request. The second handler exists only so an
    authenticated overlap can reach that gate and receive its immediate busy response.
    """

    def __init__(
        self,
        orchestrator: ProducerOrchestrator,
        *,
        _shutdown_seconds: float = PRODUCER_SERVICE_SHUTDOWN_SECONDS,
    ) -> None:
        if (
            type(orchestrator) is not ProducerOrchestrator
            or type(_shutdown_seconds) not in {int, float}
            or not math.isfinite(_shutdown_seconds)
            or not 0 < _shutdown_seconds <= PRODUCER_SERVICE_SHUTDOWN_SECONDS
        ):
            raise ProducerServiceError("service_configuration_invalid")
        self._orchestrator = orchestrator
        self._shutdown_seconds = float(_shutdown_seconds)
        self._lock = threading.Lock()
        self._stop_requested = threading.Event()
        self._state = STATE_CREATED
        self._threads: tuple[threading.Thread, ...] = ()
        self._start_count = 0
        self._completed_attempt_count = 0
        self._failed_attempt_count = 0

    def __repr__(self) -> str:
        return "<ProducerServingLifecycle>"

    def _mark_failed(self) -> None:
        with self._lock:
            self._state = STATE_FAILED
            self._stop_requested.set()
        self._orchestrator.close()

    def _serve(self) -> None:
        while not self._stop_requested.is_set():
            try:
                result = self._orchestrator.process_one()
            except ProducerOrchestratorError as error:
                if self._stop_requested.is_set():
                    break
                if error.code == "accept_timeout":
                    continue
                with self._lock:
                    self._failed_attempt_count += 1
                if self._orchestrator.fatal or error.code in {
                    "listener_unavailable",
                    "service_fatal",
                }:
                    self._mark_failed()
                    break
                continue
            except BaseException:
                with self._lock:
                    self._failed_attempt_count += 1
                self._mark_failed()
                break
            with self._lock:
                self._completed_attempt_count += 1
            if result.fatal or self._orchestrator.fatal:
                self._mark_failed()
                break

    def start(self) -> None:
        """Atomically open admission and start the fixed handler set."""
        with self._lock:
            if self._state not in {STATE_CREATED, STATE_STOPPED} or self._orchestrator.fatal:
                raise ProducerServiceError("service_state_invalid")
            self._state = STATE_STARTING
            self._stop_requested.clear()
        started: list[threading.Thread] = []
        try:
            self._orchestrator.open()
            generation = self._start_count + 1
            threads = tuple(
                threading.Thread(
                    target=self._serve,
                    name=f"threatfusion-producer-service-{generation}-{index}",
                )
                for index in range(1, PRODUCER_SERVICE_HANDLER_COUNT + 1)
            )
            with self._lock:
                self._threads = threads
            for thread in threads:
                thread.start()
                started.append(thread)
        except BaseException:
            self._stop_requested.set()
            self._orchestrator.close()
            for thread in started:
                thread.join(self._shutdown_seconds)
            with self._lock:
                self._threads = ()
                self._state = STATE_FAILED
            raise ProducerServiceError("service_start_failed") from None
        with self._lock:
            if self._state == STATE_FAILED:
                startup_failed = True
            else:
                self._start_count = generation
                self._state = STATE_READY
                startup_failed = False
        if startup_failed:
            self._stop_requested.set()
            self._orchestrator.close()
            for thread in started:
                thread.join(self._shutdown_seconds)
            with self._lock:
                self._threads = ()
            raise ProducerServiceError("service_start_failed")

    def shutdown(self) -> None:
        """Stop admission, drain bounded in-flight work, and join every handler."""
        with self._lock:
            if self._state == STATE_CREATED:
                self._state = STATE_STOPPED
                return
            if self._state not in {STATE_READY, STATE_FAILED}:
                raise ProducerServiceError("service_state_invalid")
            preserve_failed = self._state == STATE_FAILED
            if not preserve_failed:
                self._state = STATE_STOPPING
            self._stop_requested.set()
            threads = self._threads
        self._orchestrator.close()
        deadline = time.monotonic() + self._shutdown_seconds
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            with self._lock:
                self._state = STATE_FAILED
            raise ProducerServiceError("service_shutdown_timeout")
        with self._lock:
            self._threads = ()
            self._state = STATE_FAILED if preserve_failed else STATE_STOPPED

    def snapshot(self) -> ProducerServiceSnapshot:
        with self._lock:
            live = sum(thread.is_alive() for thread in self._threads)
            ready = (
                self._state == STATE_READY
                and live == PRODUCER_SERVICE_HANDLER_COUNT
                and not self._orchestrator.fatal
            )
            return ProducerServiceSnapshot(
                state=self._state,
                ready=ready,
                start_count=self._start_count,
                handler_limit=PRODUCER_SERVICE_HANDLER_COUNT,
                live_handler_count=live,
                completed_attempt_count=self._completed_attempt_count,
                failed_attempt_count=self._failed_attempt_count,
            )

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.shutdown()
