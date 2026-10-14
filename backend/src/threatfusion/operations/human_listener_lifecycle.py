"""Explicitly injected local human listeners; no demo, producer or deployment setup."""

from __future__ import annotations

import stat
from contextlib import closing
from threading import Event, RLock, Thread

from threatfusion.operations import human_credentials as policy


class HumanLifecycleError(RuntimeError):
    def __init__(self):
        super().__init__("human_lifecycle_failed")


class HumanListenerLifecycle:
    """Own both listeners and their sole process_one workers.

    Control methods belong to one operator thread and serialize against each other.
    Never hand the listeners to other workers. Shutdown drains trusted repository
    operations without claiming a deadline; it never reports stopped before join.
    """

    def __init__(
        self, directory, api_configuration, browser_configuration, authorization, view, audit
    ):
        self._arguments = (
            directory,
            api_configuration,
            browser_configuration,
            authorization,
            view,
            audit,
        )
        self._control = RLock()
        self._stop = Event()
        self._ready = Event()
        self._listeners = []
        self._workers = []
        self._generation = 0
        self._state = "stopped"

    def snapshot(self):
        """Only operational state/counts; a generation is not a claim about disk."""
        return {
            "state": self._state,
            "generation": self._generation,
            "accepting": self._state == "accepting" and not self._stop.is_set(),
            "live_workers": sum(w.is_alive() for w, _, _ in self._workers),
        }

    @property
    def addresses(self):
        with self._control:
            if not self.snapshot()["accepting"]:
                raise HumanLifecycleError()
            return tuple(listener.address for listener in self._listeners)

    def _stop_admission(self):
        self._stop.set()
        for listener in self._listeners:
            listener.stop_admission()

    def _serve(self, listener, finished):
        self._ready.wait()
        try:
            while not self._stop.is_set():
                listener.process_one()
        except BaseException:
            self._state = "failed"
            self._stop_admission()
            # The operator still owns joining these workers.
            for item in self._listeners:
                item.close()
        finally:
            finished.set()

    def _shutdown(self):
        self._state = "stopping"
        self._stop_admission()
        self._ready.set()  # release workers if their start was interrupted
        interrupted = False
        for listener in self._listeners:
            while True:
                try:
                    listener.close()
                    break
                except KeyboardInterrupt:
                    interrupted = True
        for worker, finished, failed_to_start in self._workers:
            if failed_to_start:
                continue
            while True:
                try:
                    finished.wait()
                    if worker.ident is not None:
                        worker.join()
                    break
                except KeyboardInterrupt:
                    interrupted = True
        self._listeners = []
        self._workers = []
        self._state = "stopped"
        return interrupted

    def shutdown(self):
        with self._control:
            interrupted = self._shutdown()
        if interrupted:
            raise KeyboardInterrupt
        return self.snapshot()

    def replace(self):
        """Stop/join first, then validate disk policy and open a fresh generation."""
        with self._control:
            if self._shutdown():
                raise KeyboardInterrupt
            self._stop.clear()
            self._ready.clear()
            directory, api_config, browser_config, authorization, view, audit = self._arguments
            try:
                # Keep cooperating policy writers out through both loads and startup.
                # The policy directory must remain in place, as in the operator contract.
                with policy._boundary(), policy._directory(directory):
                    for configuration, browser in ((api_config, False), (browser_config, True)):
                        self._listeners.append(
                            policy.construct_listener(
                                directory,
                                configuration,
                                authorization,
                                view,
                                audit,
                                browser=browser,
                            )
                        )
                    registry = self._listeners[0]._credentials
                    active = [r for r in registry._records if r.enabled and not r.revoked]
                    if not active:
                        raise HumanLifecycleError()
                    # Reuse repository schema gates, including an empty state database.
                    for repository in (view._repository._alerts, view._repository, audit):
                        if not stat.S_ISREG(repository._database_path.lstat().st_mode):
                            raise HumanLifecycleError()
                        with closing(repository._connect()) as connection:
                            repository._verify_schema(connection)
                    # Bounded read-only dependency probes; never print retained content.
                    audit.list(limit=1)
                    view.list_alerts(
                        authorization.issue_for_trusted_actor(active[0].actor_id), limit=1
                    )
                    self._state = "policy_loaded"
                    for listener in self._listeners:
                        listener.open()
                    for listener in self._listeners:
                        finished = Event()
                        worker = Thread(
                            target=self._serve, args=(listener, finished), name="tf-human-listener"
                        )
                        record = [worker, finished, False]
                        self._workers.append(record)
                        try:
                            worker.start()
                        except Exception:
                            record[2] = True
                            raise
                    self._generation += 1
                    self._state = "accepting"
                    self._ready.set()
            except BaseException as error:
                interrupted = self._shutdown()
                self._state = "failed"
                if isinstance(error, KeyboardInterrupt) or interrupted:
                    raise KeyboardInterrupt from None
                raise HumanLifecycleError() from None
        return self.snapshot()

    def __enter__(self):
        self.replace()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.shutdown()
