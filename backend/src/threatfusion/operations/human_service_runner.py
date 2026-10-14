"""Signal-safe supervisor runner for HumanListenerLifecycle."""

from __future__ import annotations

import signal
import threading
from threading import Event
from typing import Callable

from threatfusion.operations.human_listener_lifecycle import (
    HumanLifecycleError,
    HumanListenerLifecycle,
)


class HumanServiceRunner:
    """Supervised single-process controller for HumanListenerLifecycle.

    Coordinates deterministic signal handling (SIGTERM, SIGINT, SIGHUP),
    bounded polling loops, policy reloads, and clean shutdown drains.
    """

    def __init__(
        self,
        lifecycle: HumanListenerLifecycle,
        *,
        register_signals: bool = True,
        on_generation_change: Callable[[int], None] | None = None,
    ) -> None:
        self._lifecycle = lifecycle
        self._register_signals_flag = register_signals
        self._on_generation_change = on_generation_change

        self._stop_event = Event()
        self._reload_event = Event()

        self._state = "initialized"
        self._signals_registered = False
        self._prev_sigterm = None
        self._prev_sigint = None
        self._prev_sighup = None

    @property
    def lifecycle(self) -> HumanListenerLifecycle:
        return self._lifecycle

    @property
    def is_ready(self) -> bool:
        snap = self._lifecycle.snapshot()
        return bool(snap["accepting"]) and not self._stop_event.is_set()

    @property
    def generation(self) -> int:
        return int(self._lifecycle.snapshot()["generation"])

    @property
    def state(self) -> str:
        return self._state

    def trigger_shutdown(self) -> None:
        """Programmatic trigger equivalent to SIGTERM / SIGINT."""
        self._stop_event.set()

    def trigger_reload(self) -> None:
        """Programmatic trigger equivalent to SIGHUP."""
        self._reload_event.set()

    def _on_signal_stop(self, signum: int, frame: object) -> None:
        self.trigger_shutdown()

    def _on_signal_reload(self, signum: int, frame: object) -> None:
        self.trigger_reload()

    def _register_signals(self) -> None:
        if not self._register_signals_flag:
            return
        if threading.current_thread() is not threading.main_thread():
            return
        try:
            self._prev_sigterm = signal.signal(signal.SIGTERM, self._on_signal_stop)
            self._prev_sigint = signal.signal(signal.SIGINT, self._on_signal_stop)
            self._prev_sighup = signal.signal(signal.SIGHUP, self._on_signal_reload)
            self._signals_registered = True
        except (ValueError, AttributeError):
            self._signals_registered = False

    def _restore_signals(self) -> None:
        if not self._signals_registered:
            return
        try:
            if self._prev_sigterm is not None:
                signal.signal(signal.SIGTERM, self._prev_sigterm)
            if self._prev_sigint is not None:
                signal.signal(signal.SIGINT, self._prev_sigint)
            if self._prev_sighup is not None:
                signal.signal(signal.SIGHUP, self._prev_sighup)
        except (ValueError, AttributeError):
            pass
        finally:
            self._signals_registered = False

    def run_until_stopped(self, poll_interval_seconds: float = 0.05) -> int:
        """Run supervisor loop until stopped or fatal failure.

        Returns:
            0 on clean stop (SIGTERM / SIGINT / trigger_shutdown)
            1 on initial startup failure or unhandled lifecycle crash
            2 on policy reload failure (fail-closed SIGHUP)
        """
        self._register_signals()
        try:
            try:
                self._lifecycle.replace()
                self._state = "running"
                if self._on_generation_change:
                    self._on_generation_change(self.generation)
            except (HumanLifecycleError, Exception):
                self._state = "failed"
                self._lifecycle.shutdown()
                return 1

            while not self._stop_event.is_set():
                if self._stop_event.wait(timeout=poll_interval_seconds):
                    break

                if self._reload_event.is_set():
                    self._reload_event.clear()
                    self._state = "reloading"
                    try:
                        self._lifecycle.replace()
                        self._state = "running"
                        if self._on_generation_change:
                            self._on_generation_change(self.generation)
                    except HumanLifecycleError:
                        self._state = "failed"
                        self._lifecycle.shutdown()
                        return 2
                    except KeyboardInterrupt:
                        self._state = "stopped"
                        self._lifecycle.shutdown()
                        return 0

                snap = self._lifecycle.snapshot()
                if snap["state"] == "failed" or (
                    snap["live_workers"] == 0 and not self._stop_event.is_set()
                ):
                    self._state = "failed"
                    self._lifecycle.shutdown()
                    return 1

            self._state = "stopping"
            self._lifecycle.shutdown()
            self._state = "stopped"
            return 0
        finally:
            self._restore_signals()

    def __enter__(self) -> HumanServiceRunner:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.trigger_shutdown()
        self._lifecycle.shutdown()
