"""Launcher lifetime/cleanup with real TLS and an inert browser-process substitute."""

import http.client
import json
import os
from pathlib import Path
import signal
import subprocess
from threading import Thread
import time

import pytest

from scripts import launch_browser_demo as launcher
from scripts import run_registered_browser_path as demo
from backend.tests.unit.test_alert_explanation import approved_candidate
from threatfusion.db.alert_repository import AlertCandidateRepository


@pytest.mark.parametrize("mode", ["deadline", "interrupt", "launch_failure"])
def test_inspection_tls_lifetime_and_cleanup(tmp_path, monkeypatch, capsys, mode):
    runtime_paths = []
    processes = []
    results = []
    workers = []
    original_popen = subprocess.Popen
    sleeper = tmp_path / "inert-browser"
    sleeper.write_text("#!/bin/sh\nexec sleep 60\n")
    sleeper.chmod(0o700)
    with demo.replay_demo._temporary_runtime() as root:
        runtime_paths.append(root)
        alerts = AlertCandidateRepository(root / "alerts.sqlite3")
        candidate = approved_candidate()
        alerts.insert(candidate)
        browser, view, auth, credentials, _ = demo._create_browser(root, alerts)
        capability = auth.issue_for_trusted_actor(demo.VIEWER_ACTOR_ID)
        detail = view.get_alert(capability, candidate.alert_candidate_id)
        browser.open()
        address = browser.address

        def client():
            connection = http.client.HTTPSConnection(
                "localhost",
                address[1],
                timeout=3,
                context=demo.replay_demo._client_context(credentials),
            )
            try:
                connection.request("GET", "/v1/analyst/alerts/" + candidate.alert_candidate_id)
                response = connection.getresponse()
                results.append((response.status, response.read()))
            finally:
                connection.close()

        def popen(*args, **kwargs):
            if mode == "launch_failure":
                raise OSError("private-launch-details")
            process = original_popen(*args, **kwargs)
            processes.append(process)
            worker = Thread(target=client)
            workers.append(worker)
            worker.start()
            return process

        monkeypatch.setattr(launcher.subprocess, "Popen", popen)
        # OpenSSL uses subprocess too: export first via the original Popen.
        original_openssl = demo.replay_demo._run_openssl

        def openssl(arguments):
            monkeypatch.setattr(launcher.subprocess, "Popen", original_popen)
            try:
                original_openssl(arguments)
            finally:
                monkeypatch.setattr(launcher.subprocess, "Popen", popen)

        monkeypatch.setattr(demo.replay_demo, "_run_openssl", openssl)
        original_process_one = browser.process_one

        def interrupted():
            original_process_one()
            raise KeyboardInterrupt

        if mode == "interrupt":
            monkeypatch.setattr(browser, "process_one", interrupted)
        started = time.monotonic()
        try:
            if mode == "deadline":
                launcher.inspect_browser(
                    root, browser, credentials, detail, seconds=1, firefox=str(sleeper)
                )
            else:
                with pytest.raises(KeyboardInterrupt if mode == "interrupt" else OSError):
                    launcher.inspect_browser(
                        root, browser, credentials, detail, seconds=3, firefox=str(sleeper)
                    )
        finally:
            browser.close()
            for worker in workers:
                worker.join(timeout=5)
                assert not worker.is_alive()
        assert time.monotonic() - started < 8
        assert all(process.poll() is not None for process in processes)
        assert view.get_alert(capability, candidate.alert_candidate_id) == detail
        assert (root / "human/viewer.p12").stat().st_mode & 0o777 == 0o600
        if mode != "launch_failure":
            assert results[0][0] == 200
            assert b"Status: available" in results[0][1]
            announcement = json.loads(capsys.readouterr().out)
            assert announcement["status"] == "awaiting_human_observations"
            assert Path(announcement["profile"]).parent == root
    assert all(not path.exists() for path in runtime_paths)


def test_sigterm_restores_handlers_and_unwinds_runtime(monkeypatch, capsys):
    runtimes = []
    prior = signal.getsignal(signal.SIGTERM)

    def runner(callback, **kwargs):
        with demo.replay_demo._temporary_runtime() as root:
            runtimes.append(root)
            os.kill(os.getpid(), signal.SIGTERM)

    monkeypatch.setattr(launcher.shutil, "which", lambda _: "/usr/bin/firefox")
    monkeypatch.setattr(demo, "run_registered_browser_path", runner)
    assert launcher.main(["--seconds", "30"]) == 0
    assert signal.getsignal(signal.SIGTERM) == prior
    assert not runtimes[0].exists()
    assert json.loads(capsys.readouterr().out)["manual_result"] == "pending_user_observations"


@pytest.mark.parametrize("seconds", ["0", "1801"])
def test_invalid_lifetime_rejected(seconds):
    with pytest.raises(SystemExit):
        launcher.main(["--seconds", seconds])
