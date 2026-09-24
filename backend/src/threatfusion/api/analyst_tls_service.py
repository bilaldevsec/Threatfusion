"""One-request loopback mTLS boundary for human alert review."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from threatfusion.api.analyst_view_model import AnalystAlertViewModel, AnalystViewError
from threatfusion.schemas.analyst_state import (
    AnalystAuthorizationRegistry,
    AnalystStateError,
    is_utc,
    valid_actor_id,
)

ANALYST_HOST = "threatfusion-analyst-loopback"
ANALYST_URI_PREFIX = "urn:threatfusion:human:"
MAX_HEAD_BYTES = 4096
MAX_BODY_BYTES = 2048
MAX_RESPONSE_BYTES = 131072
MAX_HUMAN_CREDENTIALS = 64
REQUEST_SECONDS = 5.0
HANDSHAKE_SECONDS = 3.0
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ALERT_PATH = re.compile(r"/v1/analyst/alerts/(alert_candidate_v1:[0-9a-f]{64})\Z")
_TRANSITION_PATH = re.compile(r"/v1/analyst/alerts/(alert_candidate_v1:[0-9a-f]{64})/transitions\Z")
_HEADERS_GET = frozenset({"host", "connection"})
_HEADERS_POST = frozenset({"host", "connection", "content-type", "content-length"})
_COMMAND_FIELDS = frozenset({"expected_version", "to_state", "transition_id", "rationale"})


class AnalystTlsError(RuntimeError):
    """Fixed sanitized boundary failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return "<AnalystTlsError>"


@dataclass(frozen=True, slots=True, repr=False)
class HumanCredential:
    """Deployment-owned mapping; role comes from AnalystAuthorizationRegistry."""

    actor_id: str
    certificate_sha256: str
    enabled: bool
    revoked: bool
    not_before: datetime
    not_after: datetime

    def __post_init__(self) -> None:
        if (
            not valid_actor_id(self.actor_id)
            or type(self.certificate_sha256) is not str
            or _HEX_SHA256.fullmatch(self.certificate_sha256) is None
            or type(self.enabled) is not bool
            or type(self.revoked) is not bool
            or type(self.not_before) is not datetime
            or type(self.not_after) is not datetime
            or self.not_before.tzinfo is None
            or self.not_after.tzinfo is None
            or self.not_before.utcoffset() is None
            or self.not_after.utcoffset() is None
            or self.not_before.utcoffset().total_seconds() != 0
            or self.not_after.utcoffset().total_seconds() != 0
            or self.not_before >= self.not_after
        ):
            raise AnalystTlsError("configuration_invalid")

    def __repr__(self) -> str:
        return "<HumanCredential>"


class HumanCredentialRegistry:
    """Immutable exact certificate allowlist; recreate on rotation/revocation."""

    def __init__(self, records: tuple[HumanCredential, ...]) -> None:
        if (
            type(records) is not tuple
            or not records
            or len(records) > MAX_HUMAN_CREDENTIALS
            or any(type(record) is not HumanCredential for record in records)
            or len({record.certificate_sha256 for record in records}) != len(records)
        ):
            raise AnalystTlsError("configuration_invalid")
        self._records = records

    def _actor_for_verified_peer(
        self, der: bytes, decoded: dict[str, object], now: datetime
    ) -> str:
        if type(der) is not bytes or not der or type(decoded) is not dict or not is_utc(now):
            raise AnalystTlsError("authentication_failed")
        fingerprint = hashlib.sha256(der).hexdigest()
        matched = None
        for record in self._records:
            if hmac.compare_digest(record.certificate_sha256, fingerprint):
                matched = record
        if matched is None:
            raise AnalystTlsError("authentication_failed")
        if (
            not matched.enabled
            or matched.revoked
            or now < matched.not_before
            or now >= matched.not_after
            or decoded.get("subjectAltName") != (("URI", ANALYST_URI_PREFIX + matched.actor_id),)
        ):
            raise AnalystTlsError("authentication_failed")
        return matched.actor_id


@dataclass(frozen=True, slots=True, repr=False)
class AnalystTlsConfiguration:
    server_certificate_path: Path
    server_private_key_path: Path
    human_ca_path: Path
    bind_port: int = 0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.server_certificate_path, Path)
            or not isinstance(self.server_private_key_path, Path)
            or not isinstance(self.human_ca_path, Path)
            or type(self.bind_port) is not int
            or not 0 <= self.bind_port <= 65535
        ):
            raise AnalystTlsError("configuration_invalid")

    def __repr__(self) -> str:
        return "<AnalystTlsConfiguration>"


def _read_request(connection: ssl.SSLSocket) -> tuple[str, str, bytes]:
    deadline = time.monotonic() + REQUEST_SECONDS
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        if len(buffer) > MAX_HEAD_BYTES:
            raise AnalystTlsError("request_invalid")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AnalystTlsError("request_invalid")
        connection.settimeout(remaining)
        chunk = connection.recv(min(4096, MAX_HEAD_BYTES + 4 - len(buffer)))
        if not chunk:
            raise AnalystTlsError("request_invalid")
        buffer.extend(chunk)
    raw_head, body = bytes(buffer).split(b"\r\n\r\n", 1)
    if len(raw_head) + 4 > MAX_HEAD_BYTES or b"\n" in raw_head.replace(b"\r\n", b""):
        raise AnalystTlsError("request_invalid")
    lines = raw_head.split(b"\r\n")
    if not 2 <= len(lines) <= 8:
        raise AnalystTlsError("request_invalid")
    try:
        request_line = lines[0].decode("ascii")
        method, target, version = request_line.split(" ")
        if (
            version != "HTTP/1.1"
            or method not in {"GET", "POST"}
            or not target.startswith("/")
            or len(target) > 256
            or any(ord(character) < 33 or ord(character) > 126 for character in target)
        ):
            raise ValueError
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, value = line.split(b": ", 1)
            if re.fullmatch(rb"[A-Za-z][A-Za-z-]*", name) is None or any(
                character < 32 or character > 126 for character in value
            ):
                raise ValueError
            key = name.decode("ascii").lower()
            if key in headers:
                raise ValueError
            headers[key] = value.decode("ascii")
        if headers.get("host") != ANALYST_HOST or headers.get("connection") != "close":
            raise ValueError
        if set(headers) != (_HEADERS_GET if method == "GET" else _HEADERS_POST):
            raise ValueError
        if method == "POST":
            if headers.get("content-type") != "application/json":
                raise ValueError
            size_text = headers["content-length"]
            if not re.fullmatch(r"[1-9][0-9]*", size_text):
                raise ValueError
            size = int(size_text)
            if size > MAX_BODY_BYTES:
                raise ValueError
        else:
            size = 0
    except (ValueError, UnicodeError, IndexError):
        raise AnalystTlsError("request_invalid") from None
    if len(body) > size:
        raise AnalystTlsError("request_invalid")
    while len(body) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AnalystTlsError("request_invalid")
        connection.settimeout(remaining)
        chunk = connection.recv(min(4096, size - len(body) + 1))
        if not chunk:
            raise AnalystTlsError("request_invalid")
        body += chunk
        if len(body) > size:
            raise AnalystTlsError("request_invalid")
    if connection.pending():
        raise AnalystTlsError("request_invalid")
    return method, target, body


def _list_parameters(target: str) -> tuple[int, int]:
    parsed = urlsplit(target)
    if parsed.path != "/v1/analyst/alerts" or parsed.fragment:
        raise AnalystTlsError("request_invalid")
    try:
        query = parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True)
        if set(query) - {"limit", "offset"} or any(len(values) != 1 for values in query.values()):
            raise ValueError
        limit_text = query.get("limit", ["50"])[0]
        offset_text = query.get("offset", ["0"])[0]
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)", limit_text) or not re.fullmatch(
            r"(?:0|[1-9][0-9]*)", offset_text
        ):
            raise ValueError
        return int(limit_text), int(offset_text)
    except ValueError:
        raise AnalystTlsError("request_invalid") from None


def _command(body: bytes) -> dict[str, object]:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError

    try:
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
        if type(value) is not dict or set(value) != _COMMAND_FIELDS:
            raise ValueError
        return value
    except (UnicodeError, ValueError, TypeError):
        raise AnalystTlsError("request_invalid") from None


def _response(status: int, payload: dict[str, object]) -> bytes:
    body = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")
    if len(body) > MAX_RESPONSE_BYTES:
        status, body = 503, b'{"error":"unavailable"}\n'
    reason = {
        200: "OK",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        409: "Conflict",
        503: "Service Unavailable",
    }[status]
    head = (
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    return head + body


class AnalystTlsListener:
    """Separate, directly terminated loopback listener; one request per connection."""

    def __init__(
        self,
        configuration: AnalystTlsConfiguration,
        credentials: HumanCredentialRegistry,
        authorization: AnalystAuthorizationRegistry,
        view: AnalystAlertViewModel,
    ) -> None:
        if (
            type(configuration) is not AnalystTlsConfiguration
            or type(credentials) is not HumanCredentialRegistry
            or type(authorization) is not AnalystAuthorizationRegistry
            or type(view) is not AnalystAlertViewModel
            or view._repository._authorization is not authorization
        ):
            raise AnalystTlsError("configuration_invalid")
        self._configuration = configuration
        self._credentials = credentials
        self._authorization = authorization
        self._view = view
        self._listener: socket.socket | None = None
        self._active: socket.socket | None = None
        self._state_lock = threading.Lock()
        self._process_lock = threading.Lock()
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

    def open(self) -> None:
        with self._state_lock:
            self._open()

    def _open(self) -> None:
        if self._listener is not None:
            raise AnalystTlsError("listener_unavailable")
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", self._configuration.bind_port))
            listener.listen(1)
            listener.settimeout(3.0)
            self._listener = listener
        except OSError:
            if "listener" in locals():
                listener.close()
            raise AnalystTlsError("listener_unavailable") from None

    def _dispatch(self, capability, method: str, target: str, body: bytes):
        if method == "GET" and (
            target == "/v1/analyst/alerts" or target.startswith("/v1/analyst/alerts?")
        ):
            limit, offset = _list_parameters(target)
            return 200, self._view.list_alerts(capability, limit=limit, offset=offset)
        if method == "GET" and (match := _ALERT_PATH.fullmatch(target)):
            result = self._view.get_alert(capability, match.group(1))
            return (404, {"error": "not_found"}) if result is None else (200, result)
        if method == "POST" and (match := _TRANSITION_PATH.fullmatch(target)):
            command = _command(body)
            return 200, self._view.transition(
                capability, alert_candidate_id=match.group(1), **command
            )
        raise AnalystTlsError("request_invalid")

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
                if self._listener is not listener:
                    return
                self._active = accepted
            accepted.settimeout(HANDSHAKE_SECONDS)
            accepted = self._context.wrap_socket(
                accepted, server_side=True, do_handshake_on_connect=False
            )
            with accepted as connection:
                accepted = None
                with self._state_lock:
                    if self._listener is not listener:
                        return
                    self._active = connection
                connection.do_handshake()
                if connection.version() != "TLSv1.3":
                    return
                der = connection.getpeercert(binary_form=True)
                decoded = connection.getpeercert()
                try:
                    actor_id = self._credentials._actor_for_verified_peer(
                        der, decoded, datetime.now(UTC)
                    )
                    capability = self._authorization.issue_for_trusted_actor(actor_id)
                except (AnalystTlsError, AnalystStateError):
                    connection.sendall(_response(401, {"error": "authentication_failed"}))
                    return
                try:
                    method, target, body = _read_request(connection)
                    with self._state_lock:
                        if self._listener is not listener:
                            return
                        # Close waits for an already-dispatched repository operation. No
                        # accepted peer can start another operation after close returns.
                        actor_id = self._credentials._actor_for_verified_peer(
                            der, decoded, datetime.now(UTC)
                        )
                        capability = self._authorization.issue_for_trusted_actor(actor_id)
                        status, result = self._dispatch(capability, method, target, body)
                    connection.sendall(_response(status, result))
                except (AnalystTlsError, AnalystViewError) as error:
                    if isinstance(error, AnalystViewError):
                        if error.code == "analyst_not_authorized":
                            status, code = 403, "forbidden"
                        elif error.code == "alert_candidate_not_found":
                            status, code = 404, "not_found"
                        elif error.code in {
                            "analyst_state_version_conflict",
                            "analyst_transition_identity_conflict",
                        }:
                            status, code = 409, "conflict"
                        elif error.code == "analyst_view_unavailable":
                            status, code = 503, "unavailable"
                        else:
                            status, code = 400, "request_invalid"
                    elif error.code == "authentication_failed":
                        status, code = 401, "authentication_failed"
                    else:
                        status, code = 400, "request_invalid"
                    connection.sendall(_response(status, {"error": code}))
                except Exception:
                    connection.sendall(_response(503, {"error": "unavailable"}))
        except (OSError, ssl.SSLError, TimeoutError):
            pass
        except Exception:
            # A failure before authorization or response construction closes the connection.
            # Never surface an unexpected credential, TLS, or storage exception here.
            pass
        finally:
            if accepted is not None:
                accepted.close()
            with self._state_lock:
                self._active = None
            self._process_lock.release()

    def close(self) -> None:
        with self._state_lock:
            listener, self._listener = self._listener, None
            active = self._active
        if listener is not None:
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            listener.close()
        if active is not None:
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            active.close()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
