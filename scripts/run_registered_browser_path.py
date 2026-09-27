"""One registered UNSW alert through the existing producer and read-only browser paths."""

from __future__ import annotations

import argparse
import html
import json
import math
import socket
import ssl
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Empty, Queue
from threading import Thread
from typing import Callable, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import run_fyp_progress_demo as replay_demo  # noqa: E402
from threatfusion.api.analyst_browser_tls_service import (  # noqa: E402
    MAX_BROWSER_RESPONSE_BYTES,
    AnalystBrowserTlsListener,
)
from threatfusion.api.analyst_tls_service import (  # noqa: E402
    AnalystTlsConfiguration,
    HumanCredential,
    HumanCredentialRegistry,
)
from threatfusion.api.analyst_view_model import (  # noqa: E402
    AnalystAlertViewModel,
    AnalystViewError,
)
from threatfusion.db.analyst_security_audit import AnalystSecurityAuditRepository  # noqa: E402
from threatfusion.db.analyst_state_repository import AnalystStateRepository  # noqa: E402
from threatfusion.db.alert_repository import AlertCandidateRepository  # noqa: E402
from threatfusion.models.network_inference import (  # noqa: E402
    APPROVED_MODEL_HASHES,
    UnswNetworkInferenceBoundary,
)
from threatfusion.schemas.analyst_state import (  # noqa: E402
    AnalystAuthorizationRegistry,
    AnalystRegistryEntry,
)

REGISTERED_ROW_NUMBER = 21
VIEWER_ACTOR_ID = "queue.viewer"


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise replay_demo.DemoError(reason)


def _browser_exchange(
    listener: AnalystBrowserTlsListener, credentials: dict[str, object], target: str
) -> tuple[int, str]:
    """Send one bounded HTTPS GET using the temporary human certificate."""
    outcome: Queue[BaseException | None] = Queue(maxsize=1)

    def serve() -> None:
        try:
            listener.process_one()
            outcome.put(None)
        except BaseException as error:
            outcome.put(error)

    worker = Thread(target=serve, name="threatfusion-browser-path-request")
    worker.start()
    chunks: list[bytes] = []
    size = 0
    failed = False
    try:
        with socket.create_connection(listener.address, timeout=3) as raw:
            with replay_demo._client_context(credentials).wrap_socket(
                raw, server_hostname="localhost"
            ) as client:
                _require(client.version() == "TLSv1.3", "browser_tls_version_invalid")
                client.settimeout(5)
                request = (
                    f"GET {target} HTTP/1.1\r\n"
                    f"Host: localhost:{listener.address[1]}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                client.sendall(request)
                try:
                    while chunk := client.recv(4096):
                        size += len(chunk)
                        _require(
                            size <= MAX_BROWSER_RESPONSE_BYTES + 8192,
                            "browser_response_invalid",
                        )
                        chunks.append(chunk)
                except ssl.SSLEOFError:
                    pass
    except (OSError, ssl.SSLError, replay_demo.DemoError):
        failed = True
    finally:
        if failed:
            listener.close()
        worker.join(timeout=8)
    _require(not worker.is_alive(), "browser_worker_cleanup_failed")
    try:
        server_error = outcome.get_nowait()
    except Empty:
        raise replay_demo.DemoError("browser_worker_result_missing") from None
    _require(server_error is None and not failed, "browser_exchange_failed")

    try:
        head, body = b"".join(chunks).split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        code = int(lines[0].split(b" ")[1])
        _require(
            f"Content-Length: {len(body)}".encode("ascii") in lines
            and b"Content-Type: text/html; charset=utf-8" in lines
            and any(line.startswith(b"Cache-Control: no-store") for line in lines),
            "browser_response_invalid",
        )
        return code, body.decode("utf-8")
    except (IndexError, UnicodeError, ValueError):
        raise replay_demo.DemoError("browser_response_invalid") from None


def _create_browser(root: Path, alerts: AlertCandidateRepository) -> tuple[
    AnalystBrowserTlsListener,
    AnalystAlertViewModel,
    AnalystAuthorizationRegistry,
    dict[str, object],
    AnalystSecurityAuditRepository,
]:
    human_root = root / "human"
    human_root.mkdir(mode=0o700)
    ca, ca_key = replay_demo._issue_ca(human_root)
    server = replay_demo._issue_certificate(
        human_root, "browser-server", ca, ca_key, purpose="serverAuth", san="DNS:localhost"
    )
    viewer = replay_demo._issue_certificate(
        human_root,
        "viewer",
        ca,
        ca_key,
        purpose="clientAuth",
        san=f"URI:urn:threatfusion:human:{VIEWER_ACTOR_ID}",
    )
    now = datetime.now(UTC)
    credentials = HumanCredentialRegistry(
        (
            HumanCredential(
                VIEWER_ACTOR_ID,
                replay_demo._fingerprint(viewer[0]),
                True,
                False,
                now - timedelta(hours=1),
                now + timedelta(hours=1),
            ),
        )
    )
    authorization = AnalystAuthorizationRegistry((AnalystRegistryEntry(VIEWER_ACTOR_ID, "viewer"),))
    states = AnalystStateRepository(root / "states.sqlite3", alerts, authorization)
    view = AnalystAlertViewModel(states)
    audit = AnalystSecurityAuditRepository(root / "browser-audit.sqlite3")
    browser = AnalystBrowserTlsListener(
        AnalystTlsConfiguration(server[0], server[1], ca),
        credentials,
        authorization,
        view,
        audit,
    )
    return browser, view, authorization, {"ca": ca, "client": viewer}, audit


def run_registered_browser_path(
    inspect: (
        Callable[[Path, AnalystBrowserTlsListener, dict[str, object], dict[str, object]], None]
        | None
    ) = None,
    *,
    runtime_parent: Path | None = None,
) -> dict[str, object]:
    """Run one registered RF inference and reconcile its authenticated browser display."""
    boundary = UnswNetworkInferenceBoundary(project_root=PROJECT_ROOT)
    runtime = (
        replay_demo._temporary_runtime()
        if runtime_parent is None
        else replay_demo._temporary_runtime(directory=runtime_parent)
    )
    with runtime as root:
        producer_root = root / "producer"
        producer_root.mkdir(mode=0o700)
        producer_credentials = replay_demo._create_credentials(producer_root)
        service = replay_demo._create_service(root, producer_credentials, boundary)
        browser: AnalystBrowserTlsListener | None = None
        try:
            request = replay_demo._request_body(
                ((replay_demo.MEMBER_SHA256, REGISTERED_ROW_NUMBER),)
            )
            wire, result, producer_tls = replay_demo._exchange(
                service, producer_credentials, request
            )
            status, body, response = replay_demo._decode_wire(wire)
            _require(
                status == 200 and result.response_bytes == body and len(response.records) == 1,
                "producer_result_invalid",
            )
            record = response.records[0]
            candidate_id = record.alert_candidate_id
            _require(
                record.record_index == 1
                and record.disposition == "created"
                and record.predicted_class == "Attack"
                and type(candidate_id) is str
                and type(record.attack_probability) is float,
                "producer_result_invalid",
            )
            reopened_alerts = AlertCandidateRepository(root / "alerts.sqlite3")
            candidate = reopened_alerts.get(candidate_id)
            _require(
                candidate is not None
                and len(reopened_alerts.list()) == 1
                and candidate.alert_candidate_id == candidate_id
                and candidate.decision == record.predicted_class
                and candidate.model_identity == "random_forest"
                and candidate.model_artifact_sha256
                == APPROVED_MODEL_HASHES["random_forest"]["model"]
                and math.isclose(
                    candidate.uncalibrated_model_score,
                    record.attack_probability,
                    rel_tol=0.0,
                    abs_tol=1e-15,
                ),
                "persisted_alert_mismatch",
            )

            browser, view, authorization, human_credentials, browser_audit = _create_browser(
                root, reopened_alerts
            )
            capability = authorization.issue_for_trusted_actor(VIEWER_ACTOR_ID)
            queue = view.list_alerts(capability)
            detail = view.get_alert(capability, candidate_id)
            _require(
                len(queue["items"]) == 1
                and detail is not None
                and queue["items"][0]["detection_evidence"]["alert_candidate_id"]
                == detail["detection_evidence"]["alert_candidate_id"]
                == candidate_id
                and queue["items"][0]["detection_evidence"]["decision"]
                == detail["detection_evidence"]["decision"]
                == candidate.decision
                and detail["detection_evidence"]["uncalibrated_model_score"]
                == candidate.uncalibrated_model_score
                and queue["items"][0]["analyst_state"] == detail["analyst_state"]
                and detail["analyst_state"]["state"] == "new"
                and detail["analyst_state"]["version"] == 0
                and detail["analyst_history"] == [],
                "analyst_view_mismatch",
            )

            browser.open()
            queue_code, queue_html = _browser_exchange(browser, human_credentials, "/")
            detail_code, detail_html = _browser_exchange(
                browser, human_credentials, f"/v1/analyst/alerts/{candidate_id}"
            )
            _require(queue_code == detail_code == 200, "browser_status_mismatch")
            _require("Status: <b>active</b>" in queue_html, "browser_queue_status_mismatch")
            _require(
                f'href="/v1/analyst/alerts/{candidate_id}"' in queue_html,
                "browser_queue_link_mismatch",
            )
            _require(
                f"<span class='badge badge-decision'>{html.escape(candidate.decision)}</span>"
                in queue_html
                and "<span class='badge badge-state'>new</span>" in queue_html,
                "browser_queue_evidence_mismatch",
            )
            _require(
                f"Candidate ID:</b> <code>{html.escape(candidate_id)}</code>" in detail_html,
                "browser_candidate_id_mismatch",
            )
            _require(
                (
                    'Decision:</b> <span class="badge badge-decision">'
                    f"{html.escape(candidate.decision)}</span>"
                )
                in detail_html,
                "browser_decision_mismatch",
            )
            _require(
                'Triage State:</b> <span class="badge badge-state">new</span> (v0)' in detail_html,
                "browser_state_mismatch",
            )

            # A controlled view failure proves that the same authenticated endpoint
            # shows a sanitized unavailable page; it does not simulate a database outage.
            original_list = view.list_alerts

            def unavailable(*args: object, **kwargs: object) -> dict[str, object]:
                raise AnalystViewError("analyst_view_unavailable")

            try:
                view.list_alerts = unavailable
                failure_code, failure_html = _browser_exchange(browser, human_credentials, "/")
            finally:
                view.list_alerts = original_list
            _require(
                failure_code == 503
                and "Unavailable" in failure_html
                and candidate_id not in failure_html
                and [event.event_type for event in browser_audit.list()]
                == [
                    "request_admitted",
                    "request_completed",
                    "request_admitted",
                    "request_completed",
                    "request_admitted",
                    "internal_failure",
                ]
                and view.get_alert(capability, candidate_id) == detail,
                "browser_failure_state_invalid",
            )
            _require(
                [event.event_type for event in service.audit.list()]
                == ["request_admitted", "request_completed"],
                "producer_audit_invalid",
            )
            if inspect is not None:
                _require(
                    detail["explanation"]["status"] == "available"
                    and "alert_explanation_v1" in detail_html
                    and "Status: available" in detail_html,
                    "browser_explanation_mismatch",
                )
                inspect(root, browser, human_credentials, detail)
            return {
                "status": "completed",
                "scope": "one_registered_unsw_replay_automated_tls_not_manual_browser",
                "source_member_sha256": replay_demo.MEMBER_SHA256,
                "row_number": REGISTERED_ROW_NUMBER,
                "producer_tls": producer_tls,
                "producer_http_status": status,
                "alert_candidate_id": candidate_id,
                "source_event_id": candidate.source_event_id,
                "model_identity": candidate.model_identity,
                "model_artifact_sha256": candidate.model_artifact_sha256,
                "model_decision": candidate.decision,
                "analyst_state": detail["analyst_state"]["state"],
                "analyst_state_version": detail["analyst_state"]["version"],
                "browser_queue_http_status": queue_code,
                "browser_detail_http_status": detail_code,
                "injected_view_failure_http_status": failure_code,
                "persisted_alert_count": len(reopened_alerts.list()),
            }
        finally:
            if browser is not None:
                browser.close()
            service.close()


def main(argv: Sequence[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    try:
        evidence = run_registered_browser_path()
    except replay_demo.DemoError as error:
        print(json.dumps({"status": "failed", "reason": error.code}, sort_keys=True))
        return 1
    except Exception:
        print(json.dumps({"status": "failed", "reason": "registered_browser_path_failed"}))
        return 1
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
