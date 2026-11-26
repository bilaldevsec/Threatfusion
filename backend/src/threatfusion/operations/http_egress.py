"""Pure-stdlib SSRF-hardened outbound HTTP egress validation and bounded urlopen."""

from __future__ import annotations

from collections.abc import Iterable
import http.client
import ipaddress
import socket
import ssl
from typing import Any
import urllib.parse
import urllib.request

_DEFAULT_MAX_BYTES = 1_048_576
# Cloud metadata / IMDS / link-local / unspecified ranges are NEVER allowed,
# even when a hostname is explicitly listed in allowed_hosts.
_METADATA_IMDS_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("168.63.129.16/32"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::254/128"),
    ipaddress.ip_network("::/128"),
)
# RFC1918 / CGNAT / ULA ranges are blocked by default and permitted ONLY for
# operator-configured hosts explicitly passed via allowed_hosts.
_PRIVATE_INTERNAL_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)
_SPECIAL_NON_GLOBAL_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("2001:db8::/32"),
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


def _unwrap_ips(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    if not isinstance(addr, ipaddress.IPv6Address):
        return (addr,)
    unwrapped: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    if addr.ipv4_mapped is not None:
        unwrapped.append(addr.ipv4_mapped)
    if addr.sixtofour is not None:
        unwrapped.append(addr.sixtofour)
    if addr.teredo is not None:
        unwrapped.extend(addr.teredo)
    unwrapped.append(addr)
    return tuple(unwrapped)


def _check_ip_allowed(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_loopback: bool,
    allow_private_internal: bool = False,
) -> None:
    for ip in _unwrap_ips(addr):
        # Cloud metadata / IMDS / link-local / multicast / reserved / unspecified are NEVER allowed.
        for net in _METADATA_IMDS_NETWORKS:
            if ip.version == net.version and ip in net:
                raise EgressBlockedError("egress_metadata_imds_blocked")
        # Check loopback before is_reserved because Python 3.11 marks IPv6 ::1 as is_reserved.
        if ip.is_loopback:
            if allow_loopback:
                continue
            raise EgressBlockedError("egress_loopback_blocked")
        if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise EgressBlockedError("egress_non_global_ip_blocked")
        if any(ip.version == net.version and ip in net for net in _PRIVATE_INTERNAL_NETWORKS):
            if allow_private_internal:
                continue
            raise EgressBlockedError("egress_blocked_ip_range")
        if any(ip.version == net.version and ip in net for net in _SPECIAL_NON_GLOBAL_NETWORKS):
            raise EgressBlockedError("egress_non_global_ip_blocked")
        if not ip.is_global:
            raise EgressBlockedError("egress_non_global_ip_blocked")


def _validate_and_resolve_egress(
    url: str,
    *,
    allowed_schemes: tuple[str, ...] = ("https", "http"),
    allow_loopback: bool = False,
    allowed_hosts: Iterable[str] = (),
) -> tuple[str, str, int, list[tuple[int, str]]]:
    """Validate scheme, host, and resolved IPs, returning pinned (family, ip) targets."""
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
    host_in_allowlist = bool(allowlist) and (host_lower in allowlist)
    if allowlist and not host_in_allowlist:
        raise EgressBlockedError("egress_host_not_allowlisted")

    if host_lower.endswith(_INTERNAL_HOST_SUFFIXES) and not host_in_allowlist:
        raise EgressBlockedError("egress_internal_hostname_blocked")

    direct_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        direct_ip = ipaddress.ip_address(host_lower)
    except ValueError:
        direct_ip = None

    if direct_ip is not None:
        _check_ip_allowed(
            direct_ip,
            allow_loopback=allow_loopback,
            allow_private_internal=host_in_allowlist,
        )
    else:
        if host_lower == "localhost" and not allow_loopback:
            raise EgressBlockedError("egress_loopback_blocked")
        if (
            "." not in host_lower
            and not (allow_loopback and host_lower == "localhost")
            and not host_in_allowlist
        ):
            raise EgressBlockedError("egress_single_label_host_blocked")

    lookup_port = port or (443 if scheme == "https" else 80)
    try:
        addr_infos = socket.getaddrinfo(host_lower, lookup_port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise EgressBlockedError("egress_dns_resolution_failed") from exc
    if not addr_infos:
        raise EgressBlockedError("egress_dns_resolution_failed")

    pinned_addrs: list[tuple[int, str]] = []
    seen_addrs: set[tuple[int, str]] = set()
    for info in addr_infos:
        family = int(info[0])
        sockaddr = info[4]
        if not sockaddr:
            continue
        resolved_str = str(sockaddr[0]).split("%", 1)[0]
        try:
            resolved_ip = ipaddress.ip_address(resolved_str)
        except ValueError as exc:
            raise EgressBlockedError("egress_dns_resolution_failed") from exc
        _check_ip_allowed(
            resolved_ip,
            allow_loopback=allow_loopback,
            allow_private_internal=host_in_allowlist,
        )
        key = (family, str(resolved_ip))
        if key not in seen_addrs:
            seen_addrs.add(key)
            pinned_addrs.append(key)

    if not pinned_addrs:
        raise EgressBlockedError("egress_dns_resolution_failed")
    return raw, host_lower, lookup_port, pinned_addrs


def validate_egress_url(
    url: str,
    *,
    allowed_schemes: tuple[str, ...] = ("https", "http"),
    allow_loopback: bool = False,
    allowed_hosts: Iterable[str] = (),
) -> str:
    """Validate scheme, host, and resolved IPs against SSRF/IMDS/private networks."""
    raw, _host, _port, _pinned = _validate_and_resolve_egress(
        url,
        allowed_schemes=allowed_schemes,
        allow_loopback=allow_loopback,
        allowed_hosts=allowed_hosts,
    )
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


def _connect_pinned_socket(
    pinned_addrs: list[tuple[int, str]],
    port: int,
    timeout: Any,
    source_address: tuple[str, int] | None,
) -> socket.socket:
    """Open a TCP socket directly to a pre-validated IP without re-resolving DNS."""
    last_err: OSError | None = None
    for family, ip_str in pinned_addrs:
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            if family == socket.AF_INET6:
                sock.connect((ip_str, int(port), 0, 0))
            else:
                sock.connect((ip_str, int(port)))
            return sock
        except OSError as exc:
            last_err = exc
            try:
                sock.close()
            except OSError:
                pass
    if last_err is not None:
        raise last_err
    raise OSError("egress_no_pinned_addresses")


def _normalize_conn_host(host: str) -> str:
    cleaned = str(host or "").strip().lower()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    return cleaned.rstrip(".")


def _build_pinned_handlers(
    *,
    pinned_host: str,
    pinned_port: int,
    pinned_addrs: list[tuple[int, str]],
    ssl_context: ssl.SSLContext | None,
) -> tuple[urllib.request.HTTPHandler, urllib.request.HTTPSHandler]:
    """Create HTTP/HTTPS handlers that connect only to validated pinned IPs."""

    class _PinnedHTTPConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            if _normalize_conn_host(self.host) != pinned_host or int(self.port) != pinned_port:
                raise EgressBlockedError("egress_pinned_host_mismatch")
            self.sock = _connect_pinned_socket(
                pinned_addrs, self.port, self.timeout, self.source_address
            )

    class _PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:
            if _normalize_conn_host(self.host) != pinned_host or int(self.port) != pinned_port:
                raise EgressBlockedError("egress_pinned_host_mismatch")
            raw_sock = _connect_pinned_socket(
                pinned_addrs, self.port, self.timeout, self.source_address
            )
            server_hostname = self._tunnel_host if self._tunnel_host else self.host
            try:
                self.sock = self._context.wrap_socket(raw_sock, server_hostname=server_hostname)
            except Exception:
                try:
                    raw_sock.close()
                except OSError:
                    pass
                raise

    class _PinnedHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req: urllib.request.Request) -> Any:
            return self.do_open(_PinnedHTTPConnection, req)

    class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
        def __init__(self, context: ssl.SSLContext | None = None) -> None:
            super().__init__(context=context)

        def https_open(self, req: urllib.request.Request) -> Any:
            return self.do_open(_PinnedHTTPSConnection, req, context=self._context)

    return _PinnedHTTPHandler(), _PinnedHTTPSHandler(context=ssl_context)


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
    """Validate egress URL, pin resolved IP, disable redirects/proxies, and cap reads."""
    request = req if isinstance(req, urllib.request.Request) else urllib.request.Request(req)
    _raw_url, pinned_host, pinned_port, pinned_addrs = _validate_and_resolve_egress(
        request.full_url,
        allowed_schemes=allowed_schemes,
        allow_loopback=allow_loopback,
        allowed_hosts=allowed_hosts,
    )
    pinned_http, pinned_https = _build_pinned_handlers(
        pinned_host=pinned_host,
        pinned_port=pinned_port,
        pinned_addrs=pinned_addrs,
        ssl_context=ssl_context,
    )
    handlers: list[urllib.request.BaseHandler] = [
        NoRedirectHandler(),
        urllib.request.ProxyHandler({}),
        pinned_http,
        pinned_https,
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
