"""Explicitly injected local human listeners; no demo, producer or deployment setup."""

from __future__ import annotations

import stat
from contextlib import closing
from pathlib import Path
from threading import Event, RLock, Thread

from threatfusion.operations import human_credentials as policy
from threatfusion.operations.storage_backup import (
    create_storage_snapshot,
    restore_storage_snapshot,
    verify_storage_snapshot,
)


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
        self,
        directory,
        api_configuration,
        browser_configuration,
        authorization,
        view,
        audit,
        storage_directory=None,
        incident_repository=None,
        *,
        threat_intel_enricher=None,
        advisory_engine=None,
        soar_repository=None,
    ):
        self._arguments = (
            directory,
            api_configuration,
            browser_configuration,
            authorization,
            view,
            audit,
        )
        self._storage_directory = Path(storage_directory) if storage_directory is not None else None
        self._incident_repository = incident_repository
        self._threat_intel_enricher = threat_intel_enricher
        self._advisory_engine = advisory_engine
        self._soar_repository = soar_repository
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
            # If native thread creation never occurred, never block indefinitely
            if worker.ident is None and not worker.is_alive():
                if hasattr(worker, "_started") and not worker._started.is_set():
                    continue
            while True:
                try:
                    finished.wait()
                    if worker.ident is not None or worker.is_alive():
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
                                threat_intel_enricher=self._threat_intel_enricher,
                                advisory_engine=self._advisory_engine,
                                soar_repository=self._soar_repository,
                            )
                        )
                    registry = self._listeners[0]._credentials
                    active = [r for r in registry._records if r.enabled and not r.revoked]
                    if not active:
                        raise HumanLifecycleError()
                    # Reuse repository schema gates, including an empty state database.
                    repos = [view._repository._alerts, view._repository, audit]
                    if self._incident_repository is not None:
                        repos.append(self._incident_repository)
                    for repository in repos:
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
                        except BaseException:
                            # Interruption or failure occurred during start().
                            # Distinguish whether native OS thread creation actually occurred:
                            started = False
                            if worker.ident is not None or worker.is_alive():
                                started = True
                            elif hasattr(worker, "_started") and worker._started.wait(timeout=0.05):
                                started = True

                            if not started:
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

    def snapshot_quiescent(
        self, snapshot_dir: Path | str, storage_dir: Path | str | None = None
    ) -> dict[str, object]:
        """Stop admission/join workers, take cross-DB snapshot, resume fresh generation."""
        with self._control:
            if self._shutdown():
                raise KeyboardInterrupt
            directory, api_config, browser_config, authorization, view, audit = self._arguments
            src_dir = (
                Path(storage_dir)
                if storage_dir is not None
                else (self._storage_directory or view._repository._alerts._database_path.parent)
            )
            alerts_path = view._repository._alerts._database_path
            states_path = view._repository._database_path
            audit_path = audit._database_path
            incidents_path = (
                self._incident_repository._database_path
                if self._incident_repository is not None
                else None
            )

            manifest = create_storage_snapshot(
                snapshot_dir=snapshot_dir,
                source_dir=src_dir,
                alerts_path=alerts_path,
                states_path=states_path,
                audit_path=audit_path,
                incidents_path=incidents_path,
            )

            try:
                self.replace()
            except BaseException:
                self._shutdown()
                raise

            return manifest

    def restore_quiescent(
        self, snapshot_dir: Path | str, storage_dir: Path | str | None = None
    ) -> dict[str, object]:
        """Verify candidate snapshot, stop/join workers, restore databases, resume generation."""
        with self._control:
            manifest = verify_storage_snapshot(snapshot_dir)

            if self._shutdown():
                raise KeyboardInterrupt

            directory, api_config, browser_config, authorization, view, audit = self._arguments
            dest_dir = (
                Path(storage_dir)
                if storage_dir is not None
                else (self._storage_directory or view._repository._alerts._database_path.parent)
            )

            restore_storage_snapshot(snapshot_dir=snapshot_dir, target_dir=dest_dir)

            try:
                self.replace()
            except BaseException:
                self._shutdown()
                raise

            return manifest

    def prune_security_audit_quiescent(
        self, archive_dir: Path | str, audit_db_path: Path | str | None = None
    ) -> dict[str, object]:
        """Stop/join workers, prune verified archived audit rows, resume listener generation."""
        from threatfusion.operations.audit_retention import prune_archived_security_audit

        with self._control:
            if self._shutdown():
                raise KeyboardInterrupt

            directory, api_config, browser_config, authorization, view, audit = self._arguments
            db_path = Path(audit_db_path) if audit_db_path is not None else audit._database_path

            result = prune_archived_security_audit(audit_db_path=db_path, archive_dir=archive_dir)

            try:
                self.replace()
            except BaseException:
                self._shutdown()
                raise

            return result

    def __enter__(self):
        self.replace()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.shutdown()
