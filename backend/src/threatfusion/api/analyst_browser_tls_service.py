"""Browser-facing analyst boundary with CSRF defense and audited alert transitions."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import socket
import ssl
import threading
import time
import urllib.parse
import uuid
from datetime import UTC, datetime

from threatfusion.api.analyst_tls_service import (
    AnalystTlsConfiguration,
    AnalystTlsError,
    HumanCredentialRegistry,
    REQUEST_SECONDS,
)
from threatfusion.api.analyst_view_model import AnalystAlertViewModel, AnalystViewError
from threatfusion.db.analyst_security_audit import (
    AnalystSecurityAuditRepository,
    AnalystSecurityAuditError,
    create_analyst_security_audit_event,
)
from threatfusion.schemas.analyst_state import (
    ANALYST_STATES,
    AnalystAuthorizationRegistry,
    AnalystStateError,
    canonical_uuid4,
)

from threatfusion.api.analyst_dashboard import (
    DashboardAlertQueue,
    DashboardSnapshot,
    render_dashboard_html,
    _parse_summary,
    _parse_detail,
)

# Human client-certificate selection occurs within the TLS handshake.
# This fixed total timeout bounds even unauthenticated connections.
BROWSER_HANDSHAKE_SECONDS = 60.0
MAX_BROWSER_HEAD_BYTES = 8192
MAX_BROWSER_BODY_BYTES = 2048
MAX_BROWSER_RESPONSE_BYTES = 131072
_ALERT_PATH = re.compile(r"^/v1/analyst/alerts/(alert_candidate_v1:[0-9a-f]{64})(?:\?.*)?$")
_TRANSITION_PATH = re.compile(
    r"^/v1/analyst/alerts/(alert_candidate_v1:[0-9a-f]{64})/transitions\Z"
)


def _html_response(code: int, html_body: str) -> bytes:
    body = html_body.encode("utf-8")
    if len(body) > MAX_BROWSER_RESPONSE_BYTES:
        raise AnalystTlsError("response_too_large")
    head = (
        f"HTTP/1.1 {code} {'OK' if code == 200 else 'Error'}\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate\r\n"
        f"Pragma: no-cache\r\n"
        f"Expires: 0\r\n"
        f"Surrogate-Control: no-store\r\n"
        f"Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'\r\n"
        f"X-Frame-Options: DENY\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")
    return head + body


def _error_page(code: int, message: str) -> bytes:
    html = (
        f"<!DOCTYPE html><html><head><title>{code} Error</title></head>"
        f"<body><h1>{code} Error</h1><p>{message}</p></body></html>"
    )
    return _html_response(code, html)


class AnalystBrowserTlsListener:
    """Browser-facing loopback listener; one request per connection, HTML responses."""

    def __init__(
        self,
        configuration: AnalystTlsConfiguration,
        credentials: HumanCredentialRegistry,
        authorization: AnalystAuthorizationRegistry,
        view: AnalystAlertViewModel,
        audit: AnalystSecurityAuditRepository,
    ) -> None:
        if (
            type(configuration) is not AnalystTlsConfiguration
            or type(credentials) is not HumanCredentialRegistry
            or type(authorization) is not AnalystAuthorizationRegistry
            or type(view) is not AnalystAlertViewModel
            or view._repository._authorization is not authorization
            or type(audit) is not AnalystSecurityAuditRepository
        ):
            raise AnalystTlsError("configuration_invalid")
        self._audit = audit
        self._configuration = configuration
        self._credentials = credentials
        self._authorization = authorization
        self._view = view
        self._listener: socket.socket | None = None
        self._active: socket.socket | None = None
        self._state_lock = threading.Lock()
        self._process_lock = threading.Lock()
        self._admission_stopped = threading.Event()
        self._csrf_secret = os.urandom(32)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_cert_chain(
                configuration.server_certificate_path, configuration.server_private_key_path
            )
            context.load_verify_locations(cafile=configuration.human_ca_path)
            self._context = context
        except (OSError, ssl.SSLError, ValueError):
            raise AnalystTlsError("configuration_invalid") from None

    @property
    def address(self) -> tuple[str, int]:
        with self._state_lock:
            if self._listener is None:
                raise AnalystTlsError("listener_unavailable")
            return self._listener.getsockname()

    def generate_csrf_token(
        self,
        actor_id: str,
        alert_candidate_id: str,
        expected_version: int,
        transition_request_id: str,
    ) -> str:
        message = (
            f"{actor_id}:{alert_candidate_id}:{expected_version}:{transition_request_id}".encode(
                "utf-8"
            )
        )
        return hmac.new(self._csrf_secret, message, digestmod=hashlib.sha256).hexdigest()

    def verify_csrf_token(
        self,
        token: str,
        actor_id: str,
        alert_candidate_id: str,
        expected_version: int,
        transition_request_id: str,
    ) -> bool:
        if not isinstance(token, str) or len(token) != 64:
            return False
        expected = self.generate_csrf_token(
            actor_id, alert_candidate_id, expected_version, transition_request_id
        )
        return hmac.compare_digest(token, expected)

    def open(self) -> None:
        with self._state_lock:
            if self._listener is not None:
                raise AnalystTlsError("listener_unavailable")
            try:
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", self._configuration.bind_port))
                listener.listen(1)
                listener.settimeout(3.0)
                self._listener = listener
                self._admission_stopped.clear()
            except OSError:
                if "listener" in locals():
                    listener.close()
                raise AnalystTlsError("listener_unavailable") from None

    def stop_admission(self) -> None:
        """Prevent new dispatch before waiting for an already dispatched operation."""
        self._admission_stopped.set()

    def close(self) -> None:
        self.stop_admission()
        with self._state_lock:
            listener, self._listener = self._listener, None
            active = self._active
        for connection in (listener, active):
            if connection is not None:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()

    def _read_browser_request(
        self, connection: ssl.SSLSocket
    ) -> tuple[str, str, dict[str, str], bytes]:
        deadline = time.monotonic() + REQUEST_SECONDS
        buffer = bytearray()
        while b"\r\n\r\n" not in buffer:
            if len(buffer) > MAX_BROWSER_HEAD_BYTES:
                raise AnalystTlsError("request_invalid")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if not buffer:
                    raise AnalystTlsError("connection_idle")
                raise AnalystTlsError("request_invalid")
            connection.settimeout(remaining)
            try:
                chunk = connection.recv(min(4096, MAX_BROWSER_HEAD_BYTES + 4 - len(buffer)))
            except (TimeoutError, ssl.SSLError, OSError):
                if not buffer:
                    raise AnalystTlsError("connection_idle") from None
                raise AnalystTlsError("request_invalid") from None
            if not chunk:
                if not buffer:
                    raise AnalystTlsError("connection_idle")
                raise AnalystTlsError("request_invalid")
            buffer.extend(chunk)

        head_bytes, initial_body = buffer.split(b"\r\n\r\n", 1)
        try:
            head = head_bytes.decode("ascii")
        except UnicodeDecodeError:
            raise AnalystTlsError("request_invalid")
        lines = head.split("\r\n")
        if not lines:
            raise AnalystTlsError("request_invalid")
        request_line = lines[0].split(" ")
        if len(request_line) != 3:
            raise AnalystTlsError("request_invalid")
        method, target, version = request_line
        if method not in ("GET", "POST"):
            raise AnalystTlsError("request_invalid")
        if version not in ("HTTP/1.1", "HTTP/1.0"):
            raise AnalystTlsError("request_invalid")

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                raise AnalystTlsError("request_invalid")
            key, val = line.split(":", 1)
            key = key.lower().strip()
            val = val.strip()
            if key in headers:
                raise AnalystTlsError("request_invalid")
            headers[key] = val

        if "transfer-encoding" in headers:
            raise AnalystTlsError("request_invalid")

        try:
            actual_port = self.address[1]
        except AnalystTlsError:
            actual_port = self._configuration.bind_port

        expected_hosts = (
            "localhost",
            "127.0.0.1",
            f"localhost:{actual_port}",
            f"127.0.0.1:{actual_port}",
        )
        req_host = headers.get("host")
        if req_host not in expected_hosts:
            raise AnalystTlsError("request_invalid")

        if method == "GET":
            if headers.get("content-length", "0") != "0":
                raise AnalystTlsError("request_invalid")
            if initial_body:
                raise AnalystTlsError("request_invalid")

            expected_origins = (
                f"https://localhost:{actual_port}",
                f"https://127.0.0.1:{actual_port}",
            )
            req_origin = headers.get("origin")
            if req_origin and req_origin not in expected_origins:
                raise AnalystTlsError("request_invalid")

            sec_fetch_site = headers.get("sec-fetch-site")
            if sec_fetch_site and sec_fetch_site not in ("none", "same-origin"):
                raise AnalystTlsError("request_invalid")

            return method, target, headers, b""

        # method == "POST"
        content_type = headers.get("content-type", "")
        if content_type.split(";")[0].strip() != "application/x-www-form-urlencoded":
            raise AnalystTlsError("request_invalid")

        content_length_str = headers.get("content-length")
        if not content_length_str or not content_length_str.isdigit():
            raise AnalystTlsError("request_invalid")

        content_length = int(content_length_str)
        if content_length <= 0 or content_length > MAX_BROWSER_BODY_BYTES:
            raise AnalystTlsError("request_invalid")

        body = bytearray(initial_body)
        while len(body) < content_length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AnalystTlsError("request_invalid")
            connection.settimeout(remaining)
            try:
                chunk = connection.recv(min(4096, content_length - len(body)))
            except (TimeoutError, ssl.SSLError, OSError):
                raise AnalystTlsError("request_invalid") from None
            if not chunk:
                raise AnalystTlsError("request_invalid")
            body.extend(chunk)

        if len(body) != content_length:
            raise AnalystTlsError("request_invalid")

        return method, target, headers, bytes(body)

    def _dispatch(self, capability, target: str) -> tuple[int, bytes]:
        path_only = target.split("?", 1)[0]
        if path_only in ("/", "/analyst/alerts", "/v1/analyst/alerts"):
            try:
                result = self._view.list_alerts(capability, limit=50, offset=0)
            except AnalystViewError:
                return 503, _error_page(503, "Unavailable")

            items = [_parse_summary(item) for item in result.get("items", [])]
            queue = DashboardAlertQueue(
                items=tuple(items), total_loaded=len(items), limit=50, offset=0
            )

            selected = None
            csrf_token = None
            transition_request_id = None
            if not queue.is_empty:
                try:
                    detail_res = self._view.get_alert(capability, queue.items[0].alert_candidate_id)
                    if detail_res is not None:
                        selected = _parse_detail(detail_res)
                        if capability.role == "analyst":
                            transition_request_id = str(uuid.uuid4())
                            csrf_token = self.generate_csrf_token(
                                capability.actor_id,
                                selected.alert_candidate_id,
                                selected.version,
                                transition_request_id,
                            )
                    status = "active"
                except AnalystViewError:
                    status = "unavailable"
            else:
                status = "empty"

            snapshot = DashboardSnapshot(queue=queue, selected=selected, status=status)
            return 200, _html_response(
                200,
                render_dashboard_html(
                    snapshot,
                    browser_links=True,
                    actor_role=capability.role,
                    csrf_token=csrf_token,
                    transition_request_id=transition_request_id,
                ),
            )

        match = _ALERT_PATH.fullmatch(target)
        if match:
            candidate_id = match.group(1)
            try:
                result = self._view.list_alerts(capability, limit=50, offset=0)
                detail_res = self._view.get_alert(capability, candidate_id)
            except AnalystViewError:
                return 503, _error_page(503, "Unavailable")

            items = [_parse_summary(item) for item in result.get("items", [])]
            queue = DashboardAlertQueue(
                items=tuple(items), total_loaded=len(items), limit=50, offset=0
            )

            selected = None
            if detail_res is not None:
                selected = _parse_detail(detail_res)
            else:
                return 404, _error_page(404, "Not Found")

            csrf_token = None
            transition_request_id = None
            if capability.role == "analyst":
                transition_request_id = str(uuid.uuid4())
                csrf_token = self.generate_csrf_token(
                    capability.actor_id,
                    selected.alert_candidate_id,
                    selected.version,
                    transition_request_id,
                )

            status = "active"
            snapshot = DashboardSnapshot(queue=queue, selected=selected, status=status)
            return 200, _html_response(
                200,
                render_dashboard_html(
                    snapshot,
                    browser_links=True,
                    actor_role=capability.role,
                    csrf_token=csrf_token,
                    transition_request_id=transition_request_id,
                ),
            )

        return 404, _error_page(404, "Not Found")

    def process_one(self) -> None:
        if not self._process_lock.acquire(blocking=False):
            raise AnalystTlsError("listener_busy")
        accepted: socket.socket | None = None
        try:
            with self._state_lock:
                listener = self._listener
            if listener is None:
                raise AnalystTlsError("listener_unavailable")
            accepted, address = listener.accept()
            if address[0] != "127.0.0.1":
                return
            with self._state_lock:
                if self._listener is not listener or self._admission_stopped.is_set():
                    return
                self._active = accepted
            accepted.settimeout(BROWSER_HANDSHAKE_SECONDS)
            accepted = self._context.wrap_socket(
                accepted, server_side=True, do_handshake_on_connect=False
            )
            with accepted as connection:
                accepted = None
                with self._state_lock:
                    self._active = connection
                    if self._listener is not listener or self._admission_stopped.is_set():
                        return
                connection.do_handshake()
                if connection.version() != "TLSv1.3":
                    return
                der = connection.getpeercert(binary_form=True)
                decoded = connection.getpeercert()

                correlation_id = str(uuid.uuid4())
                credential_sha256 = hashlib.sha256(der).hexdigest()
                actor_id = None

                def audit_log(
                    event_type,
                    processing_stage,
                    outcome,
                    reason_code,
                    request_route=None,
                    body_sha256=None,
                ):
                    try:
                        self._audit.append(
                            create_analyst_security_audit_event(
                                event_type=event_type,
                                processing_stage=processing_stage,
                                outcome=outcome,
                                reason_code=reason_code,
                                correlation_id=correlation_id,
                                actor_id=actor_id,
                                credential_sha256=credential_sha256,
                                request_route=request_route,
                                body_sha256=body_sha256,
                            )
                        )
                    except AnalystSecurityAuditError:
                        raise AnalystTlsError("audit_unavailable")

                try:
                    actor_id = self._credentials._actor_for_verified_peer(
                        der, decoded, datetime.now(UTC)
                    )
                except AnalystTlsError:
                    try:
                        audit_log(
                            "authentication_rejected",
                            "authentication",
                            "rejected",
                            "authentication_failed",
                        )
                    except AnalystTlsError:
                        pass
                    connection.sendall(_error_page(401, "Authentication failed"))
                    return

                try:
                    capability = self._authorization.issue_for_trusted_actor(actor_id)
                except AnalystStateError:
                    try:
                        audit_log(
                            "authorization_rejected", "authorization", "rejected", "forbidden"
                        )
                    except AnalystTlsError:
                        pass
                    connection.sendall(_error_page(401, "Authentication failed"))
                    return

                try:
                    method, target, headers, body = self._read_browser_request(connection)
                except AnalystTlsError as error:
                    if error.code == "connection_idle":
                        return
                    try:
                        audit_log("request_rejected", "admission", "rejected", "request_invalid")
                    except AnalystTlsError:
                        pass
                    connection.sendall(_error_page(400, "Bad Request"))
                    return

                # Normalization for audit log
                path_only = target.split("?", 1)[0]
                if path_only == "/":
                    route = "/"
                elif path_only in ("/analyst/alerts", "/v1/analyst/alerts"):
                    route = path_only
                elif _ALERT_PATH.fullmatch(target):
                    route = "/v1/analyst/alerts/<alert_candidate_id>"
                elif _TRANSITION_PATH.fullmatch(path_only):
                    route = "/v1/analyst/alerts/<alert_candidate_id>/transitions"
                else:
                    route = None

                body_sha256 = hashlib.sha256(body).hexdigest() if body else None

                # Same-origin enforcement for POST
                if method == "POST":
                    if not _TRANSITION_PATH.fullmatch(path_only):
                        try:
                            audit_log(
                                "request_rejected",
                                "admission",
                                "rejected",
                                "request_invalid",
                                request_route=route,
                                body_sha256=body_sha256,
                            )
                        except AnalystTlsError:
                            pass
                        connection.sendall(_error_page(404, "Not Found"))
                        return

                    try:
                        actual_port = self.address[1]
                    except AnalystTlsError:
                        actual_port = self._configuration.bind_port

                    allowed_origins = {
                        f"https://127.0.0.1:{actual_port}",
                        f"https://localhost:{actual_port}",
                    }
                    sec_fetch_site = headers.get("sec-fetch-site")
                    origin = headers.get("origin")

                    has_valid_fetch_site = sec_fetch_site == "same-origin"
                    has_valid_origin = origin in allowed_origins

                    same_origin_valid = (
                        (has_valid_fetch_site or has_valid_origin)
                        and (sec_fetch_site is None or sec_fetch_site == "same-origin")
                        and (origin is None or origin in allowed_origins)
                    )

                    if not same_origin_valid:
                        try:
                            audit_log(
                                "authorization_rejected",
                                "authorization",
                                "rejected",
                                "forbidden",
                                request_route=route,
                                body_sha256=body_sha256,
                            )
                        except AnalystTlsError:
                            pass
                        connection.sendall(_error_page(403, "Forbidden"))
                        return

                try:
                    audit_log(
                        "request_admitted",
                        "admission",
                        "admitted",
                        "request_admitted",
                        request_route=route,
                        body_sha256=body_sha256,
                    )
                except AnalystTlsError:
                    connection.sendall(_error_page(503, "Unavailable"))
                    return

                with self._state_lock:
                    if self._listener is not listener or self._admission_stopped.is_set():
                        return

                    try:
                        actor_id = self._credentials._actor_for_verified_peer(
                            der, decoded, datetime.now(UTC)
                        )
                    except AnalystTlsError:
                        try:
                            audit_log(
                                "authentication_rejected",
                                "authentication",
                                "rejected",
                                "authentication_failed",
                                request_route=route,
                                body_sha256=body_sha256,
                            )
                        except AnalystTlsError:
                            pass
                        connection.sendall(_error_page(401, "Authentication failed"))
                        return
                    try:
                        capability = self._authorization.issue_for_trusted_actor(actor_id)
                    except AnalystStateError:
                        try:
                            audit_log(
                                "authorization_rejected",
                                "authorization",
                                "rejected",
                                "forbidden",
                                request_route=route,
                                body_sha256=body_sha256,
                            )
                        except AnalystTlsError:
                            pass
                        connection.sendall(_error_page(401, "Authentication failed"))
                        return

                    if method == "POST":
                        # Role verification: viewer attempting POST
                        if capability.role != "analyst":
                            try:
                                audit_log(
                                    "authorization_rejected",
                                    "authorization",
                                    "rejected",
                                    "forbidden",
                                    request_route=route,
                                    body_sha256=body_sha256,
                                )
                            except AnalystTlsError:
                                pass
                            connection.sendall(_error_page(403, "Forbidden"))
                            return

                        # Parse urlencoded form
                        try:
                            form_text = body.decode("utf-8")
                            parsed_form = urllib.parse.parse_qs(
                                form_text, keep_blank_values=True, strict_parsing=True
                            )
                        except Exception:
                            try:
                                audit_log(
                                    "request_rejected",
                                    "admission",
                                    "rejected",
                                    "request_invalid",
                                    request_route=route,
                                    body_sha256=body_sha256,
                                )
                            except AnalystTlsError:
                                pass
                            connection.sendall(_error_page(400, "Bad Request"))
                            return

                        form = {k: v[0] for k, v in parsed_form.items() if len(v) == 1}
                        expected_version_str = form.get("expected_version")
                        transition_request_id = form.get("transition_request_id")
                        csrf_token = form.get("csrf_token")
                        target_state = form.get("target_state") or form.get("to_state")
                        rationale = form.get("reason") or form.get("rationale") or ""

                        match = _TRANSITION_PATH.fullmatch(path_only)
                        if not match:
                            connection.sendall(_error_page(404, "Not Found"))
                            return
                        candidate_id = match.group(1)

                        if (
                            not expected_version_str
                            or not re.fullmatch(r"(?:0|[1-9][0-9]*)", expected_version_str)
                            or not transition_request_id
                            or not canonical_uuid4(transition_request_id)
                            or not csrf_token
                            or not target_state
                            or target_state not in ANALYST_STATES
                            or len(rationale.encode("utf-8")) > 512
                        ):
                            try:
                                audit_log(
                                    "request_rejected",
                                    "admission",
                                    "rejected",
                                    "request_invalid",
                                    request_route=route,
                                    body_sha256=body_sha256,
                                )
                            except AnalystTlsError:
                                pass
                            connection.sendall(_error_page(400, "Bad Request"))
                            return

                        expected_version = int(expected_version_str)

                        # CSRF Token Verification
                        if not self.verify_csrf_token(
                            csrf_token,
                            actor_id=actor_id,
                            alert_candidate_id=candidate_id,
                            expected_version=expected_version,
                            transition_request_id=transition_request_id,
                        ):
                            try:
                                audit_log(
                                    "authorization_rejected",
                                    "authorization",
                                    "rejected",
                                    "forbidden",
                                    request_route=route,
                                    body_sha256=body_sha256,
                                )
                            except AnalystTlsError:
                                pass
                            connection.sendall(_error_page(403, "Forbidden"))
                            return

                        # Dispatch state transition
                        try:
                            self._view.transition(
                                capability,
                                alert_candidate_id=candidate_id,
                                expected_version=expected_version,
                                to_state=target_state,
                                transition_id=transition_request_id,
                                rationale=rationale,
                            )
                        except AnalystViewError as error:
                            if error.code == "analyst_not_authorized":
                                try:
                                    audit_log(
                                        "authorization_rejected",
                                        "authorization",
                                        "rejected",
                                        "forbidden",
                                        request_route=route,
                                        body_sha256=body_sha256,
                                    )
                                except AnalystTlsError:
                                    pass
                                connection.sendall(_error_page(403, "Forbidden"))
                                return
                            elif error.code in (
                                "analyst_state_version_conflict",
                                "analyst_transition_identity_conflict",
                            ):
                                try:
                                    audit_log(
                                        "request_completed",
                                        "completion",
                                        "completed",
                                        "request_completed",
                                        request_route=route,
                                        body_sha256=body_sha256,
                                    )
                                except AnalystTlsError:
                                    pass
                                connection.sendall(_error_page(409, "Version Conflict"))
                                return
                            elif error.code == "alert_candidate_not_found":
                                connection.sendall(_error_page(404, "Not Found"))
                                return
                            elif error.code == "analyst_view_unavailable":
                                try:
                                    audit_log(
                                        "internal_failure",
                                        "internal",
                                        "failed",
                                        "internal_error",
                                        request_route=route,
                                        body_sha256=body_sha256,
                                    )
                                except AnalystTlsError:
                                    pass
                                connection.sendall(_error_page(503, "Unavailable"))
                                return
                            else:
                                try:
                                    audit_log(
                                        "request_rejected",
                                        "admission",
                                        "rejected",
                                        "request_invalid",
                                        request_route=route,
                                        body_sha256=body_sha256,
                                    )
                                except AnalystTlsError:
                                    pass
                                connection.sendall(_error_page(400, "Bad Request"))
                                return

                        # Render updated HTML detail
                        try:
                            result = self._view.list_alerts(capability, limit=50, offset=0)
                            detail_res = self._view.get_alert(capability, candidate_id)
                        except AnalystViewError:
                            try:
                                audit_log(
                                    "internal_failure",
                                    "internal",
                                    "failed",
                                    "internal_error",
                                    request_route=route,
                                    body_sha256=body_sha256,
                                )
                            except AnalystTlsError:
                                pass
                            connection.sendall(_error_page(503, "Unavailable"))
                            return

                        items = [_parse_summary(item) for item in result.get("items", [])]
                        queue = DashboardAlertQueue(
                            items=tuple(items), total_loaded=len(items), limit=50, offset=0
                        )
                        selected = _parse_detail(detail_res) if detail_res is not None else None

                        new_transition_id = str(uuid.uuid4())
                        new_csrf_token = (
                            self.generate_csrf_token(
                                actor_id,
                                selected.alert_candidate_id,
                                selected.version,
                                new_transition_id,
                            )
                            if selected is not None
                            else None
                        )

                        snapshot = DashboardSnapshot(
                            queue=queue, selected=selected, status="active"
                        )
                        html = render_dashboard_html(
                            snapshot,
                            browser_links=True,
                            actor_role=capability.role,
                            csrf_token=new_csrf_token,
                            transition_request_id=new_transition_id,
                        )

                        try:
                            audit_log(
                                "request_completed",
                                "completion",
                                "completed",
                                "request_completed",
                                request_route=route,
                                body_sha256=body_sha256,
                            )
                        except AnalystTlsError:
                            connection.sendall(_error_page(503, "Unavailable"))
                            return

                        connection.sendall(_html_response(200, html))
                        return

                    # GET request handling
                    try:
                        response_code, response_bytes = self._dispatch(capability, target)
                        if response_code == 503:
                            audit_log(
                                "internal_failure",
                                "internal",
                                "failed",
                                "internal_error",
                                request_route=route,
                            )
                            connection.sendall(response_bytes)
                            return
                        try:
                            audit_log(
                                "request_completed",
                                "completion",
                                "completed",
                                "request_completed",
                                request_route=route,
                            )
                        except AnalystTlsError:
                            connection.sendall(_error_page(503, "Unavailable"))
                            return
                        connection.sendall(response_bytes)
                    except Exception:
                        try:
                            audit_log(
                                "internal_failure",
                                "internal",
                                "failed",
                                "internal_error",
                                request_route=route,
                            )
                        except AnalystTlsError:
                            pass
                        connection.sendall(_error_page(503, "Unavailable"))
        except (OSError, socket.timeout, AnalystTlsError):
            pass
        finally:
            if accepted is not None:
                accepted.close()
            with self._state_lock:
                self._active = None
            self._process_lock.release()
