"""Integration tests for HumanServiceRunner supervisor."""

from __future__ import annotations

import signal
import time
from threading import Thread

import pytest

from backend.tests.integration import test_analyst_tls_service as api
from backend.tests.integration import test_operator_human_credentials as operator
from threatfusion.operations import human_credentials as policy
from threatfusion.operations.human_listener_lifecycle import HumanListenerLifecycle
from threatfusion.operations.human_service_runner import HumanServiceRunner

certificates = api.certificates
directory = operator.directory


@pytest.fixture
def service_setup(tmp_path, certificates, directory):
    fingerprint_1 = operator.enroll(directory, certificates)
    fingerprint_2 = operator.enroll(directory, certificates, "analyst_a", "analyst_a", create=False)
    template, _, _, _, audit = api._listener(tmp_path, certificates)
    lifecycle = HumanListenerLifecycle(
        directory,
        template._configuration,
        template._configuration,
        template._authorization,
        template._view,
        audit,
        storage_directory=tmp_path / "storage",
    )
    try:
        yield lifecycle, directory, (fingerprint_1, fingerprint_2)
    finally:
        lifecycle.shutdown()


def test_runner_starts_becomes_ready_and_clean_shutdown(service_setup):
    """Runner starts lifecycle, becomes ready, and exits 0 on trigger_shutdown."""
    lifecycle, _, _ = service_setup
    runner = HumanServiceRunner(lifecycle, register_signals=False)

    exit_holder = []

    def _target():
        exit_holder.append(runner.run_until_stopped(poll_interval_seconds=0.01))

    worker = Thread(target=_target, daemon=True)
    worker.start()

    deadline = time.monotonic() + 5.0
    while not runner.is_ready and time.monotonic() < deadline:
        time.sleep(0.01)

    assert runner.is_ready is True
    assert runner.generation == 1
    assert runner.state == "running"

    runner.trigger_shutdown()
    worker.join(timeout=5.0)
    assert not worker.is_alive()
    assert exit_holder == [0]
    assert runner.state == "stopped"
    assert runner.is_ready is False


def test_runner_reload_advances_generation(service_setup):
    """Runner SIGHUP/trigger_reload advances generation and notifies callback."""
    lifecycle, _, _ = service_setup
    generations = []
    runner = HumanServiceRunner(
        lifecycle,
        register_signals=False,
        on_generation_change=lambda gen: generations.append(gen),
    )

    exit_holder = []

    def _target():
        exit_holder.append(runner.run_until_stopped(poll_interval_seconds=0.01))

    worker = Thread(target=_target, daemon=True)
    worker.start()

    deadline = time.monotonic() + 5.0
    while not runner.is_ready and time.monotonic() < deadline:
        time.sleep(0.01)

    assert runner.is_ready is True
    assert runner.generation == 1

    runner.trigger_reload()

    deadline = time.monotonic() + 5.0
    while runner.generation < 2 and time.monotonic() < deadline:
        time.sleep(0.01)

    assert runner.generation == 2
    assert runner.state == "running"

    runner.trigger_shutdown()
    worker.join(timeout=5.0)
    assert not worker.is_alive()
    assert exit_holder == [0]
    assert generations == [1, 2]


def test_runner_reload_failure_fails_closed(service_setup):
    """When policy reload encounters HumanLifecycleError, runner exits code 2."""
    lifecycle, policy_dir, (fp1, fp2) = service_setup
    runner = HumanServiceRunner(lifecycle, register_signals=False)

    exit_holder = []

    def _target():
        exit_holder.append(runner.run_until_stopped(poll_interval_seconds=0.01))

    worker = Thread(target=_target, daemon=True)
    worker.start()

    deadline = time.monotonic() + 5.0
    while not runner.is_ready and time.monotonic() < deadline:
        time.sleep(0.01)

    assert runner.is_ready is True

    # Revoke both credentials so active count drops to 0, which raises HumanLifecycleError on replace
    policy.restrict(policy_dir, fp1, revoke=True)
    policy.restrict(policy_dir, fp2, revoke=True)

    runner.trigger_reload()
    worker.join(timeout=5.0)
    assert not worker.is_alive()

    assert exit_holder == [2]
    assert runner.state == "failed"
    assert runner.is_ready is False
    assert lifecycle.snapshot()["accepting"] is False


def test_runner_initial_startup_failure_returns_one(tmp_path, certificates):
    """Startup failure (e.g., missing policy file) returns exit code 1."""
    empty_policy_dir = tmp_path / "empty_policy"
    empty_policy_dir.mkdir(mode=0o700)

    template, _, _, _, audit = api._listener(tmp_path, certificates)
    broken_lifecycle = HumanListenerLifecycle(
        empty_policy_dir,
        template._configuration,
        template._configuration,
        template._authorization,
        template._view,
        audit,
    )
    runner = HumanServiceRunner(broken_lifecycle, register_signals=False)

    exit_code = runner.run_until_stopped(poll_interval_seconds=0.01)
    assert exit_code == 1
    assert runner.state == "failed"


def test_runner_signal_handlers_and_context_manager(service_setup):
    """Test programmatic signal triggers, registration, and context manager."""
    lifecycle, _, _ = service_setup
    with HumanServiceRunner(lifecycle, register_signals=True) as runner:
        assert runner.lifecycle is lifecycle
        # Signal handler methods
        assert not runner._stop_event.is_set()
        assert not runner._reload_event.is_set()

        runner._on_signal_reload(signal.SIGHUP, None)
        assert runner._reload_event.is_set()

        runner._on_signal_stop(signal.SIGTERM, None)
        assert runner._stop_event.is_set()

    assert runner._stop_event.is_set()
    assert lifecycle.snapshot()["accepting"] is False


def test_runner_detects_dead_workers_as_failure(service_setup):
    """When listeners die unexpectedly, runner fails closed with exit code 1."""
    lifecycle, _, _ = service_setup
    runner = HumanServiceRunner(lifecycle, register_signals=False)

    exit_holder = []

    def _target():
        exit_holder.append(runner.run_until_stopped(poll_interval_seconds=0.01))

    worker = Thread(target=_target, daemon=True)
    worker.start()

    deadline = time.monotonic() + 5.0
    while not runner.is_ready and time.monotonic() < deadline:
        time.sleep(0.01)

    assert runner.is_ready is True

    # Close sockets and stop admission without notifying runner's stop_event
    lifecycle._shutdown()

    worker.join(timeout=5.0)
    assert not worker.is_alive()
    assert exit_holder == [1]
    assert runner.state == "failed"
