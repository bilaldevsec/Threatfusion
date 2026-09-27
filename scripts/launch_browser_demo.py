"""Bounded human inspection of the existing registered-input browser demonstration."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
from threading import Event, Timer

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import run_registered_browser_path as path_demo  # noqa: E402


def _stop_browser(process: subprocess.Popen) -> None:
    """Terminate only the separately launched demo process group, then reap it."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # Children may still exist even after the Firefox parent has exited.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def inspect_browser(root, browser, credentials, detail, *, seconds, firefox):
    profile = root / "firefox-profile"
    profile.mkdir(mode=0o700)
    (profile / "user.js").write_text(
        'user_pref("security.enterprise_roots.enabled", false);\n'
        'user_pref("security.default_personal_cert", "Ask Every Time");\n'
        'user_pref("network.proxy.type", 0);\n',
        encoding="ascii",
    )
    bundle = root / "human" / "viewer.p12"
    # No password: disposable key material stays inside a private temporary directory.
    bundle.touch(mode=0o600)
    certificate, key = credentials["client"]
    path_demo.replay_demo._run_openssl(
        [
            "pkcs12",
            "-export",
            "-out",
            str(bundle),
            "-inkey",
            str(key),
            "-in",
            str(certificate),
            "-certfile",
            str(credentials["ca"]),
            "-name",
            "ThreatFusion temporary queue.viewer",
            "-passout",
            "pass:",
        ]
    )
    stopped = Event()

    def stop():
        stopped.set()
        browser.close()

    timer = Timer(seconds, stop)
    process = None
    try:
        timer.start()
        process = subprocess.Popen(
            [firefox, "--no-remote", "--profile", str(profile), "about:preferences#privacy"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        print(
            json.dumps(
                {
                    "status": "awaiting_human_observations",
                    "queue_url": f"https://localhost:{browser.address[1]}/",
                    "detail_url": f"https://localhost:{browser.address[1]}/v1/analyst/alerts/"
                    + detail["detection_evidence"]["alert_candidate_id"],
                    "profile": str(profile),
                    "import_authority": str(credentials["ca"]),
                    "import_personal_certificate": str(bundle),
                    "lifetime_seconds": seconds,
                    "expected_explanation": detail["explanation"],
                }
            ),
            flush=True,
        )
        while not stopped.is_set() and process.poll() is None:
            browser.process_one()
        if not stopped.is_set() and process.returncode != 0:
            raise path_demo.replay_demo.DemoError("demo_browser_exited_unsuccessfully")
    finally:
        stop()
        timer.cancel()
        timer.join(timeout=5)
        if process is not None:
            _stop_browser(process)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--seconds", type=int, default=900, help="inspection lifetime, 30–1800 seconds"
    )
    args = parser.parse_args(argv)
    if not 30 <= args.seconds <= 1800:
        parser.error("--seconds must be between 30 and 1800")
    firefox = (
        "/snap/bin/firefox" if os.access("/snap/bin/firefox", os.X_OK) else shutil.which("firefox")
    )
    if firefox is None:
        print('{"status":"failed","reason":"firefox_unavailable"}')
        return 1

    def interrupt(signum, frame):
        raise KeyboardInterrupt

    previous = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        runtime_parent = PROJECT_ROOT / "artifacts/reports/browser-manual-demo"
        runtime_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path_demo.run_registered_browser_path(
            lambda *args_: inspect_browser(*args_, seconds=args.seconds, firefox=firefox),
            runtime_parent=runtime_parent,
        )
    except KeyboardInterrupt:
        pass
    except Exception:
        print('{"status":"failed","reason":"browser_demo_failed"}', flush=True)
        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print('{"status":"stopped","manual_result":"pending_user_observations"}', flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
