"""Directly terminated loopback TLS transport for the producer v1 subset.

This is a deliberately small staged transport, not a general HTTP server and not an
orchestrator. Python object privacy and bearer capabilities are internal correctness
controls, not cryptographic authorization boundaries.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import socket
import ssl
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from threatfusion.api.producer_admission import (
    JSON_CONTENT_TYPE,
    MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_BYTES,
    TLS_VERSION,
    AdmittedProducer,
    CertificateRegistry,
    PeerCertificateEvidence,
    ProducerAdmissionError,
    ProducerResponse,
    decode_producer_response,
    serialize_producer_response,
)

LOOPBACK_BIND_HOST = "127.0.0.1"
TRANSPORT_REQUEST_METHOD = "POST"
TRANSPORT_REQUEST_TARGET = "/v1/producer-events"
TRANSPORT_HTTP_VERSION = "HTTP/1.1"
TRANSPORT_HOST = "threatfusion-loopback"
TRANSPORT_RESPONSE_SCHEMA_VERSION = "producer_transport_response_v1"

TLS_HANDSHAKE_TOTAL_SECONDS = 3.0
REQUEST_READ_TOTAL_SECONDS = 5.0
REQUEST_READ_IDLE_SECONDS = 1.0
RESPONSE_WRITE_TOTAL_SECONDS = 5.0
RESPONSE_WRITE_IDLE_SECONDS = 1.0
ACCEPT_TIMEOUT_SECONDS = 3.0
LISTEN_BACKLOG = 1

MAX_REQUEST_LINE_BYTES = 512
MAX_HEADER_FIELDS = 32
MAX_HEADER_BYTES = 16_384
MAX_HEADER_NAME_BYTES = 64
MAX_HEADER_VALUE_BYTES = 1_024
SOCKET_READ_CHUNK_BYTES = 8_192

_REQUEST_LINE = (
    f"{TRANSPORT_REQUEST_METHOD} {TRANSPORT_REQUEST_TARGET} {TRANSPORT_HTTP_VERSION}".encode(
        "ascii"
    )
)
_REQUIRED_HEADERS = frozenset({"host", "content-type", "content-length", "connection"})
_PROHIBITED_HEADERS = frozenset(
    {
        "transfer-encoding",
        "content-encoding",
        "trailer",
        "upgrade",
        "keep-alive",
        "proxy-connection",
        "expect",
        "te",
    }
)
_HEADER_NAME = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_CONTENT_LENGTH = re.compile(rb"(?:0|[1-9][0-9]*)\Z")
_RESPONSE_STATUS = {
    "request_completed": (200, "OK"),
    "request_rejected": (400, "Bad Request"),
    "request_in_progress": (409, "Conflict"),
    "request_replay_rejected": (409, "Conflict"),
    "outcome_unknown": (503, "Service Unavailable"),
    "alert_candidate_created": (200, "OK"),
    "alert_candidate_already_exists": (200, "OK"),
    "alert_candidate_identity_conflict": (409, "Conflict"),
    "inference_not_actionable": (200, "OK"),
    "registered_event_invalid": (400, "Bad Request"),
    "registered_event_unavailable": (503, "Service Unavailable"),
    "registered_event_rejected": (400, "Bad Request"),
}
_GENERIC_INTERNAL_BODY = (
    json.dumps(
        {
            "reason": "internal_failure",
            "schema_version": TRANSPORT_RESPONSE_SCHEMA_VERSION,
            "status": "unavailable",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    + b"\n"
)

STATE_AUTHENTICATED = "authenticated"
STATE_HEAD_VALIDATED = "head_validated"
STATE_BODY_READ = "body_read"
STATE_CLOSED = "closed"


class ProducerTlsTransportError(RuntimeError):
    """Fixed sanitized transport failure without socket, TLS, path, or peer details."""

    def __init__(self, code: str, *, status_code: int, reason: str) -> None:
        self.code = code
        self.status_code = status_code
        self.reason = reason
        super().__init__(code)

    def __repr__(self) -> str:
        return "<ProducerTlsTransportError>"


def _failure(code: str, status_code: int = 400, reason: str | None = None):
    return ProducerTlsTransportError(code, status_code=status_code, reason=reason or code)


def _is_uuid4(value: object) -> bool:
    if type(value) is not str or len(value) != 36:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _is_token(value: object) -> bool:
    if type(value) is not str or len(value) != 43:
        return False
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (TypeError, ValueError):
        return False
    return (
        len(decoded) == 32
        and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == value
    )


@dataclass(frozen=True, slots=True, repr=False)
class ProducerTlsConfiguration:
    """External certificate paths and the sole exact loopback bind configuration."""

    server_certificate_path: Path
    server_private_key_path: Path
    client_ca_path: Path
    bind_host: str = LOOPBACK_BIND_HOST
    bind_port: int = 0
    listen_backlog: int = LISTEN_BACKLOG

    def __post_init__(self) -> None:
        if (
            not isinstance(self.server_certificate_path, Path)
            or not isinstance(self.server_private_key_path, Path)
            or not isinstance(self.client_ca_path, Path)
            or self.bind_host != LOOPBACK_BIND_HOST
            or type(self.bind_port) is not int
            or not 0 <= self.bind_port <= 65_535
            or type(self.listen_backlog) is not int
            or self.listen_backlog != LISTEN_BACKLOG
        ):
            raise _failure("transport_configuration_invalid", 500, "internal_failure")

    def __repr__(self) -> str:
        return "<ProducerTlsConfiguration>"


@dataclass(frozen=True, slots=True, repr=False)
class TransportCapability:
    """Rotating bearer proof for one legal next step on one connection."""

    connection_id: str
    stage: str
    ownership_token: str

    def __copy__(self):
        raise ProducerTlsTransportError(
            "connection_capability_invalid", status_code=500, reason="internal_failure"
        )

    def __deepcopy__(self, memo):
        raise ProducerTlsTransportError(
            "connection_capability_invalid", status_code=500, reason="internal_failure"
        )

    def __repr__(self) -> str:
        return "<TransportCapability>"


@dataclass(frozen=True, slots=True, repr=False)
class ValidatedRequestHead:
    """Canonical fixed control headers; ignored extensions are never retained."""

    method: str
    target: str
    http_version: str
    host: str
    content_type: str
    content_length: int
    connection: str
    header_count: int
    total_header_bytes: int

    def __post_init__(self) -> None:
        if (
            self.method != TRANSPORT_REQUEST_METHOD
            or self.target != TRANSPORT_REQUEST_TARGET
            or self.http_version != TRANSPORT_HTTP_VERSION
            or self.host != TRANSPORT_HOST
            or self.content_type != JSON_CONTENT_TYPE
            or type(self.content_length) is not int
            or not 1 <= self.content_length <= MAX_REQUEST_BODY_BYTES
            or self.connection != "close"
            or type(self.header_count) is not int
            or not len(_REQUIRED_HEADERS) <= self.header_count <= MAX_HEADER_FIELDS
            or type(self.total_header_bytes) is not int
            or not 1 <= self.total_header_bytes <= MAX_HEADER_BYTES
        ):
            raise _failure("request_head_invalid")

    def __repr__(self) -> str:
        return "<ValidatedRequestHead>"


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedTlsSession:
    """One directly authenticated connection and its first staged capability."""

    connection: ProducerTlsConnection
    peer_evidence: PeerCertificateEvidence
    admitted_producer: AdmittedProducer
    capability: TransportCapability

    def __repr__(self) -> str:
        return "<AuthenticatedTlsSession>"


def _server_context(configuration: ProducerTlsConfiguration) -> ssl.SSLContext:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        context.load_cert_chain(
            certfile=configuration.server_certificate_path,
            keyfile=configuration.server_private_key_path,
        )
        context.load_verify_locations(cafile=configuration.client_ca_path)
        return context
    except (OSError, ssl.SSLError, ValueError):
        raise _failure("tls_configuration_unavailable", 500, "internal_failure") from None


def _uri_sans(decoded: dict[str, object]) -> tuple[str, ...]:
    names = decoded.get("subjectAltName", ())
    if type(names) is not tuple:
        return ()
    values = []
    for entry in names:
        if type(entry) is tuple and len(entry) == 2 and entry[0] == "URI" and type(entry[1]) is str:
            values.append(entry[1])
    return tuple(values)


def _remaining(now: float, started: float, total: float) -> float:
    remaining = total - (now - started)
    if remaining <= 0:
        raise _failure("request_total_timeout", 408, "request_timeout")
    return remaining


def _monotonic_value(clock: Callable[[], float]) -> float:
    try:
        value = clock()
    except Exception:
        raise _failure("monotonic_clock_invalid", 503, "internal_failure") from None
    if type(value) not in {int, float} or not 0 <= value < float("inf"):
        raise _failure("monotonic_clock_invalid", 503, "internal_failure")
    return float(value)


def _validate_plain_framing(buffer: bytes) -> None:
    for index, value in enumerate(buffer):
        if value == 10 and (index == 0 or buffer[index - 1] != 13):
            raise _failure("request_framing_invalid")
        if value == 13 and index + 1 < len(buffer) and buffer[index + 1] != 10:
            raise _failure("request_framing_invalid")


def _parse_request_head(raw: bytes) -> ValidatedRequestHead:
    if type(raw) is not bytes or not raw.endswith(b"\r\n\r\n"):
        raise _failure("request_framing_invalid")
    if len(raw) > MAX_HEADER_BYTES:
        raise _failure("request_headers_too_large", 431)
    _validate_plain_framing(raw)
    lines = raw[:-4].split(b"\r\n")
    if not lines or len(lines[0]) > MAX_REQUEST_LINE_BYTES:
        raise _failure("request_line_too_large", 400)
    try:
        lines[0].decode("ascii")
    except UnicodeDecodeError:
        raise _failure("request_line_invalid") from None
    if lines[0] != _REQUEST_LINE:
        raise _failure("request_line_invalid")
    header_lines = lines[1:]
    if not 1 <= len(header_lines) <= MAX_HEADER_FIELDS:
        raise _failure("request_header_count_invalid", 431)
    parsed: dict[str, bytes] = {}
    for line in header_lines:
        if not line or line[:1] in {b" ", b"\t"}:
            raise _failure("request_header_invalid")
        if b": " not in line:
            raise _failure("request_header_invalid")
        name, value = line.split(b": ", 1)
        if not 1 <= len(name) <= MAX_HEADER_NAME_BYTES or _HEADER_NAME.fullmatch(name) is None:
            raise _failure("request_header_invalid")
        canonical_name = name.decode("ascii").lower()
        value_is_valid = len(value) <= MAX_HEADER_VALUE_BYTES and all(
            32 <= character <= 126 for character in value
        )
        if canonical_name != "content-length":
            value_is_valid = (
                value_is_valid
                and bool(value)
                and value[:1] not in {b" ", b"\t"}
                and value[-1:] not in {b" ", b"\t"}
            )
        if not value_is_valid:
            raise _failure("request_header_invalid")
        if canonical_name in parsed:
            raise _failure("duplicate_header")
        if canonical_name in _PROHIBITED_HEADERS:
            raise _failure("unsupported_header")
        parsed[canonical_name] = value
    if not _REQUIRED_HEADERS.issubset(parsed):
        raise _failure("required_header_missing")
    if parsed["host"] != TRANSPORT_HOST.encode("ascii"):
        raise _failure("host_invalid")
    if parsed["content-type"] != JSON_CONTENT_TYPE.encode("ascii"):
        raise _failure("content_type_invalid")
    if parsed["connection"].lower() != b"close":
        raise _failure("connection_mode_invalid")
    content_length_bytes = parsed["content-length"]
    if _CONTENT_LENGTH.fullmatch(content_length_bytes) is None:
        raise _failure("content_length_invalid")
    content_length = int(content_length_bytes)
    if content_length == 0:
        raise _failure("empty_body")
    if content_length > MAX_REQUEST_BODY_BYTES:
        raise _failure("request_too_large", 413)
    return ValidatedRequestHead(
        TRANSPORT_REQUEST_METHOD,
        TRANSPORT_REQUEST_TARGET,
        TRANSPORT_HTTP_VERSION,
        TRANSPORT_HOST,
        JSON_CONTENT_TYPE,
        content_length,
        "close",
        len(header_lines),
        len(raw),
    )


class ProducerTlsConnection:
    """One request/response TLS state machine with rotating internal capabilities."""

    def __init__(
        self,
        tls_socket: ssl.SSLSocket,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        _read_total_seconds: float = REQUEST_READ_TOTAL_SECONDS,
        _read_idle_seconds: float = REQUEST_READ_IDLE_SECONDS,
    ) -> None:
        self._socket = tls_socket
        self._monotonic = monotonic
        self._read_total_seconds = _read_total_seconds
        self._read_idle_seconds = _read_idle_seconds
        self._connection_id = str(uuid.uuid4())
        self._stage = STATE_AUTHENTICATED
        self._token_sha256: str | None = None
        self._head: ValidatedRequestHead | None = None
        self._read_started: float | None = None
        self._last_progress: float | None = None

    def __repr__(self) -> str:
        return "<ProducerTlsConnection>"

    @property
    def closed(self) -> bool:
        return self._stage == STATE_CLOSED

    def _new_capability(self) -> TransportCapability:
        token = secrets.token_urlsafe(32)
        self._token_sha256 = hashlib.sha256(token.encode("ascii")).hexdigest()
        return TransportCapability(self._connection_id, self._stage, token)

    def initial_capability(self) -> TransportCapability:
        if self._token_sha256 is not None or self._stage != STATE_AUTHENTICATED:
            raise _failure("connection_state_invalid", 500, "internal_failure")
        return self._new_capability()

    def _require(self, capability: TransportCapability, *stages: str) -> None:
        if (
            type(capability) is not TransportCapability
            or capability.stage not in stages
            or capability.stage != self._stage
            or not _is_uuid4(capability.connection_id)
            or capability.connection_id != self._connection_id
            or not _is_token(capability.ownership_token)
            or self._token_sha256 is None
            or not hmac.compare_digest(
                self._token_sha256,
                hashlib.sha256(capability.ownership_token.encode("ascii")).hexdigest(),
            )
        ):
            raise _failure("connection_capability_invalid", 500, "internal_failure")

    def _read_timeout(self) -> float:
        now = _monotonic_value(self._monotonic)
        if self._read_started is None:
            self._read_started = now
            self._last_progress = now
        total_remaining = _remaining(now, self._read_started, self._read_total_seconds)
        idle_remaining = self._read_idle_seconds - (now - self._last_progress)
        if idle_remaining <= 0:
            raise _failure("request_idle_timeout", 408, "request_timeout")
        timeout = min(total_remaining, idle_remaining)
        self._socket.settimeout(timeout)
        return now

    def _recv(self, size: int) -> bytes:
        try:
            before = self._read_timeout()
            chunk = self._socket.recv(size)
        except ProducerTlsTransportError:
            raise
        except (TimeoutError, socket.timeout):
            try:
                now = self._monotonic()
            except Exception:
                raise _failure("monotonic_clock_invalid", 503, "internal_failure") from None
            if (
                self._read_started is not None
                and now - self._read_started >= self._read_total_seconds
            ):
                raise _failure("request_total_timeout", 408, "request_timeout") from None
            raise _failure("request_idle_timeout", 408, "request_timeout") from None
        except ssl.SSLEOFError:
            return b""
        except ssl.SSLError:
            return b""
        except OSError:
            return b""
        if chunk:
            after = _monotonic_value(self._monotonic)
            if after < before:
                raise _failure("monotonic_clock_invalid", 503, "internal_failure")
            _remaining(after, self._read_started, self._read_total_seconds)
            self._last_progress = after
        return chunk

    def _abort(self) -> None:
        self._token_sha256 = None
        self._stage = STATE_CLOSED
        try:
            self._socket.close()
        except OSError:
            pass

    def read_request_head(
        self, capability: TransportCapability
    ) -> tuple[ValidatedRequestHead, TransportCapability]:
        """Read only through CRLFCRLF; body bytes remain unread for later authorization."""
        try:
            self._require(capability, STATE_AUTHENTICATED)
        except ProducerTlsTransportError:
            self._abort()
            raise
        raw = bytearray()
        try:
            while not raw.endswith(b"\r\n\r\n"):
                chunk = self._recv(1)
                if not chunk:
                    raise _failure("request_head_incomplete")
                raw.extend(chunk)
                _validate_plain_framing(bytes(raw))
                if b"\r\n" not in raw and len(raw) > MAX_REQUEST_LINE_BYTES + 2:
                    raise _failure("request_line_too_large")
                if len(raw) > MAX_HEADER_BYTES:
                    raise _failure("request_headers_too_large", 431)
            head = _parse_request_head(bytes(raw))
            self._head = head
            self._stage = STATE_HEAD_VALIDATED
            return head, self._new_capability()
        except ProducerTlsTransportError:
            self._abort()
            raise

    def read_body(self, capability: TransportCapability) -> tuple[bytes, TransportCapability]:
        """Read the exact body only after the caller presents the post-head capability."""
        try:
            self._require(capability, STATE_HEAD_VALIDATED)
        except ProducerTlsTransportError:
            self._abort()
            raise
        if self._head is None:
            self._abort()
            raise _failure("connection_state_invalid", 500, "internal_failure")
        remaining = self._head.content_length
        chunks: list[bytes] = []
        try:
            while remaining:
                chunk = self._recv(min(SOCKET_READ_CHUNK_BYTES, remaining + 1))
                if not chunk:
                    raise _failure("body_incomplete")
                if len(chunk) > remaining:
                    raise _failure("unexpected_trailing_data")
                chunks.append(chunk)
                remaining -= len(chunk)
            if self._socket.pending():
                raise _failure("unexpected_trailing_data")
            body = b"".join(chunks)
            self._stage = STATE_BODY_READ
            return body, self._new_capability()
        except ProducerTlsTransportError:
            self._abort()
            raise
        except (OSError, ssl.SSLError):
            self._abort()
            raise _failure("request_read_failed") from None

    @staticmethod
    def _response_wire(body: bytes, status_code: int, phrase: str) -> bytes:
        head = (
            f"HTTP/1.1 {status_code} {phrase}\r\n"
            f"Content-Type: {JSON_CONTENT_TYPE}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        return head + body

    def _send_wire(self, wire: bytes) -> None:
        started = _monotonic_value(self._monotonic)
        try:
            now = _monotonic_value(self._monotonic)
            timeout = min(
                _remaining(now, started, RESPONSE_WRITE_TOTAL_SECONDS),
                RESPONSE_WRITE_IDLE_SECONDS,
            )
            self._socket.settimeout(timeout)
            self._socket.sendall(wire)
        except ProducerTlsTransportError:
            raise
        except (OSError, ssl.SSLError, TimeoutError, socket.timeout):
            raise _failure("response_write_failed", 503, "internal_failure") from None

    def write_response(
        self,
        capability: TransportCapability,
        response: ProducerResponse | bytes,
    ) -> None:
        """Write one validated bounded producer response, then always close the connection."""
        try:
            self._require(capability, STATE_HEAD_VALIDATED, STATE_BODY_READ)
        except ProducerTlsTransportError:
            self._abort()
            raise
        error: ProducerTlsTransportError | None = None
        try:
            try:
                if type(response) is ProducerResponse:
                    body = serialize_producer_response(response)
                    decoded = response
                elif type(response) is bytes and 1 <= len(response) <= MAX_RESPONSE_BYTES:
                    decoded = decode_producer_response(response)
                    body = bytes(response)
                else:
                    raise ProducerAdmissionError("response_invalid")
                status_code, phrase = _RESPONSE_STATUS[decoded.reason]
                self._send_wire(self._response_wire(body, status_code, phrase))
            except (KeyError, ProducerAdmissionError):
                error = _failure("response_invalid", 500, "internal_failure")
                self._send_wire(self._response_wire(_GENERIC_INTERNAL_BODY, 500, "Internal Error"))
        except ProducerTlsTransportError as exc:
            error = exc
        finally:
            self._abort()
        if error is not None:
            raise error

    def close(self, capability: TransportCapability) -> None:
        """Close without writing, invalidating the current capability."""
        try:
            self._require(capability, STATE_AUTHENTICATED, STATE_HEAD_VALIDATED, STATE_BODY_READ)
        except ProducerTlsTransportError:
            self._abort()
            raise
        self._abort()


class ProducerTlsListener:
    """Explicitly opened bounded-backlog loopback listener; it has no serving loop."""

    def __init__(
        self,
        configuration: ProducerTlsConfiguration,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        _handshake_seconds: float = TLS_HANDSHAKE_TOTAL_SECONDS,
        _read_total_seconds: float = REQUEST_READ_TOTAL_SECONDS,
        _read_idle_seconds: float = REQUEST_READ_IDLE_SECONDS,
    ) -> None:
        if type(configuration) is not ProducerTlsConfiguration or not callable(monotonic):
            raise _failure("transport_configuration_invalid", 500, "internal_failure")
        if (
            type(_handshake_seconds) not in {int, float}
            or not 0 < _handshake_seconds <= TLS_HANDSHAKE_TOTAL_SECONDS
            or type(_read_total_seconds) not in {int, float}
            or not 0 < _read_total_seconds <= REQUEST_READ_TOTAL_SECONDS
            or type(_read_idle_seconds) not in {int, float}
            or not 0 < _read_idle_seconds <= REQUEST_READ_IDLE_SECONDS
        ):
            raise _failure("transport_configuration_invalid", 500, "internal_failure")
        self._configuration = configuration
        self._context = _server_context(configuration)
        self._monotonic = monotonic
        self._handshake_seconds = float(_handshake_seconds)
        self._read_total_seconds = float(_read_total_seconds)
        self._read_idle_seconds = float(_read_idle_seconds)
        self._listener: socket.socket | None = None

    def __repr__(self) -> str:
        return "<ProducerTlsListener>"

    @property
    def address(self) -> tuple[str, int]:
        if self._listener is None:
            raise _failure("listener_not_open", 500, "internal_failure")
        address = self._listener.getsockname()
        return address[0], address[1]

    def open(self) -> None:
        if self._listener is not None:
            raise _failure("listener_state_invalid", 500, "internal_failure")
        listener = None
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind((self._configuration.bind_host, self._configuration.bind_port))
            listener.listen(self._configuration.listen_backlog)
            listener.settimeout(ACCEPT_TIMEOUT_SECONDS)
            self._listener = listener
        except OSError:
            if listener is not None:
                listener.close()
            raise _failure("listener_unavailable", 503, "internal_failure") from None

    def accept_authenticated(
        self,
        registry: CertificateRegistry,
        *,
        trusted_now: datetime,
    ) -> AuthenticatedTlsSession:
        if self._listener is None:
            raise _failure("listener_not_open", 500, "internal_failure")
        accepted: socket.socket | ssl.SSLSocket | None = None
        try:
            accepted, address = self._listener.accept()
            if address[0] != LOOPBACK_BIND_HOST:
                raise _failure("peer_not_loopback", 401, "authentication_failed")
            tls_socket = self._context.wrap_socket(
                accepted, server_side=True, do_handshake_on_connect=False
            )
            accepted = tls_socket
            started = _monotonic_value(self._monotonic)
            now = _monotonic_value(self._monotonic)
            tls_socket.settimeout(_remaining(now, started, self._handshake_seconds))
            tls_socket.do_handshake()
            if tls_socket.version() != TLS_VERSION:
                raise _failure("tls_version_invalid", 401, "authentication_failed")
            der = tls_socket.getpeercert(binary_form=True)
            decoded = tls_socket.getpeercert(binary_form=False)
            if type(der) is not bytes or not der or type(decoded) is not dict:
                raise _failure("client_certificate_missing", 401, "authentication_failed")
            evidence = PeerCertificateEvidence(
                tls_version=TLS_VERSION,
                chain_authenticated=True,
                client_auth_eku=True,
                certificate_sha256=hashlib.sha256(der).hexdigest(),
                uri_sans=_uri_sans(decoded),
            )
            try:
                producer = registry.authenticate(evidence, trusted_now=trusted_now)
            except ProducerAdmissionError as exc:
                raise _failure("authentication_rejected", 401, exc.security_event) from None
            connection = ProducerTlsConnection(
                tls_socket,
                monotonic=self._monotonic,
                _read_total_seconds=self._read_total_seconds,
                _read_idle_seconds=self._read_idle_seconds,
            )
            capability = connection.initial_capability()
            accepted = None
            return AuthenticatedTlsSession(connection, evidence, producer, capability)
        except ProducerTlsTransportError:
            if accepted is not None:
                accepted.close()
            raise
        except (TimeoutError, socket.timeout):
            if accepted is not None:
                accepted.close()
            raise _failure("authentication_timeout", 401, "authentication_timeout") from None
        except (OSError, ssl.SSLError):
            if accepted is not None:
                accepted.close()
            raise _failure("tls_authentication_failed", 401, "authentication_failed") from None

    def close(self) -> None:
        listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
