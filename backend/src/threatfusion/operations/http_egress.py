"""Pure-stdlib SSRF-hardened outbound HTTP egress validation and bounded urlopen."""

from __future__ import annotations

from collections.abc import Iterable
import ipaddress
import socket
import ssl
from typing import Any
import urllib.parse
import urllib.request

_DEFAULT_MAX_BYTES = 1_048_576
_ALWAYS_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("168.63.129.16/32"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::254/128"),
    ipaddress.ip_network("::/128"),
)
_INTERNAL_HOST_SUFFIXES: tuple[str, ...] = (
    ".local",
    ".internal",
    ".localhost",
    ".localdomain",
)


class EgressBlockedError(ValueError):
    """Raised when an outbound HTTP request violates SSRF, redirect, or size guardrails."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """HTTPRedirectHandler that fails closed on every HTTP 3xx redirect."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        raise EgressBlockedError(f"http_redirect_blocked:{int(code)}")

    def http_error_301(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        raise EgressBlockedError(f"http_redirect_blocked:{int(code)}")

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


def _unwrap_ip(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _check_ip_allowed(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_loopback: bool,
) -> None:
    ip = _unwrap_ip(addr)
    if ip.is_loopback:
        if allow_loopback:
            return
        raise EgressBlockedError("egress_loopback_blocked")
    if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise EgressBlockedError("egress_non_global_ip_blocked")
    for net in _ALWAYS_BLOCKED_NETWORKS:
        if ip.version == net.version and ip in net:
            raise EgressBlockedError("egress_blocked_ip_range")


def validate_egress_url(
    url: str,
    *,
    allowed_schemes: tuple[str, ...] = ("https", "http"),
    allow_loopback: bool = False,
    allowed_hosts: Iterable[str] = (),
) -> str:
    """Validate scheme, host, and resolved IPs against SSRF/IMDS/private networks."""
    raw = str(url or "").strip()
    if not raw or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise EgressBlockedError("egress_url_invalid")
    parsed = urllib.parse.urlsplit(raw)
    scheme = parsed.scheme.lower()
    allowed_scheme_set = {s.strip().lower() for s in allowed_schemes if s and s.strip()}
    if not scheme or scheme not in allowed_scheme_set:
        raise EgressBlockedError("egress_scheme_blocked")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise EgressBlockedError("egress_userinfo_rejected")
    hostname = parsed.hostname
    if not hostname:
        raise EgressBlockedError("egress_host_missing")
    host_lower = hostname.strip().lower().rstrip(".")
    if not host_lower or "%" in host_lower:
        raise EgressBlockedError("egress_host_missing")

    try:
        port = parsed.port
    except ValueError as exc:
        raise EgressBlockedError("egress_port_invalid") from exc

    allowlist = {str(h).strip().lower().rstrip(".") for h in allowed_hosts if str(h).strip()}
    if allowlist and host_lower not in allowlist:
        raise EgressBlockedError("egress_host_not_allowlisted")

    if host_lower.endswith(_INTERNAL_HOST_SUFFIXES):
        raise EgressBlockedError("egress_internal_hostname_blocked")

    direct_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        direct_ip = ipaddress.ip_address(host_lower)
    except ValueError:
        direct_ip = None

    if direct_ip is not None:
        _check_ip_allowed(direct_ip, allow_loopback=allow_loopback)
    else:
        if host_lower == "localhost" and not allow_loopback:
            raise EgressBlockedError("egress_loopback_blocked")
        if (
            "." not in host_lower
            and not (allow_loopback and host_lower == "localhost")
            and not allowlist
        ):
            raise EgressBlockedError("egress_single_label_host_blocked")

    lookup_port = port or (443 if scheme == "https" else 80)
    try:
        addr_infos = socket.getaddrinfo(host_lower, lookup_port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise EgressBlockedError("egress_dns_resolution_failed") from exc
    if not addr_infos:
        raise EgressBlockedError("egress_dns_resolution_failed")
    for info in addr_infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        resolved_str = str(sockaddr[0]).split("%", 1)[0]
        try:
            resolved_ip = ipaddress.ip_address(resolved_str)
        except ValueError as exc:
            raise EgressBlockedError("egress_dns_resolution_failed") from exc
        _check_ip_allowed(resolved_ip, allow_loopback=allow_loopback)

    return raw


class _BoundedHttpResponse:
    """Context-managed HTTP response wrapper enforcing a hard byte read ceiling."""

    def __init__(self, response: Any, *, max_bytes: int) -> None:
        self._response = response
        self._max_bytes = max(1, int(max_bytes))
        self._read_total = 0

    @property
    def status(self) -> int:
        return int(getattr(self._response, "status", None) or self._response.getcode() or 0)

    @property
    def headers(self) -> Any:
        return self._response.headers

    def getcode(self) -> int:
        return self.status

    def read(self, amt: int | None = None) -> bytes:
        remaining = self._max_bytes - self._read_total
        if remaining < 0:
            raise EgressBlockedError("egress_response_too_large")
        to_read = remaining + 1 if amt is None or amt < 0 else min(int(amt), remaining + 1)
        data = self._response.read(to_read)
        self._read_total += len(data)
        if self._read_total > self._max_bytes:
            raise EgressBlockedError("egress_response_too_large")
        return data

    def close(self) -> None:
        self._response.close()

    def __enter__(self) -> _BoundedHttpResponse:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


def safe_urlopen(
    req: urllib.request.Request | str,
    *,
    timeout: float = 5.0,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    allowed_schemes: tuple[str, ...] = ("https", "http"),
    allow_loopback: bool = False,
    allowed_hosts: Iterable[str] = (),
    ssl_context: ssl.SSLContext | None = None,
) -> _BoundedHttpResponse:
    """Validate egress URL, disable redirects/proxies, and enforce bounded response reads."""
    request = req if isinstance(req, urllib.request.Request) else urllib.request.Request(req)
    validate_egress_url(
        request.full_url,
        allowed_schemes=allowed_schemes,
        allow_loopback=allow_loopback,
        allowed_hosts=allowed_hosts,
    )
    handlers: list[urllib.request.BaseHandler] = [
        NoRedirectHandler(),
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=ssl_context),
    ]
    opener = urllib.request.build_opener(*handlers)
    resp = opener.open(request, timeout=timeout)
    content_length_raw = None
    try:
        content_length_raw = resp.headers.get("Content-Length") if resp.headers else None
    except AttributeError:
        content_length_raw = None
    if content_length_raw is not None:
        try:
            content_length = int(str(content_length_raw).strip())
        except ValueError:
            content_length = -1
        if content_length > max_bytes:
            resp.close()
            raise EgressBlockedError("egress_response_too_large")
    return _BoundedHttpResponse(resp, max_bytes=max_bytes)


__all__ = [
    "EgressBlockedError",
    "NoRedirectHandler",
    "safe_urlopen",
    "validate_egress_url",
]
