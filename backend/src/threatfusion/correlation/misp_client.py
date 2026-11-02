"""Fail-closed address guard for external indicator lookups.

Non-address indicators, such as malware hashes, are left to the caller.
Anything that is an IP attempt and is not a global unicast address is refused.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

_INTEGER_ONLY = re.compile(r"^[0-9]+$")
_HEX_ENCODED = re.compile(r"^0x[0-9a-fA-F]+$")
_OCTAL_TOKEN = re.compile(r"^0[0-7]+$")
_DOTTED_LEADING_ZERO = re.compile(r"(^|\.)0[0-7]")


def _looks_like_ip_attempt(text: str) -> bool:
    lowered = text.lower()
    if lowered in {"localhost"}:
        return True
    if text.startswith("[") or text.endswith("]"):
        return True
    if _HEX_ENCODED.match(text) or _INTEGER_ONLY.match(text) or _OCTAL_TOKEN.match(text):
        return True
    if _DOTTED_LEADING_ZERO.search(text):
        return True
    return "." in text or ":" in text


def _evades_standard_formatting(text: str) -> bool:
    if text.startswith("[") or text.endswith("]"):
        return True
    if _HEX_ENCODED.match(text) or _INTEGER_ONLY.match(text) or _OCTAL_TOKEN.match(text):
        return True
    return _DOTTED_LEADING_ZERO.search(text) is not None


def external_lookup_allowed(raw_ip: str) -> bool:
    """Return True only for a strictly parsed global unicast address."""
    text = raw_ip.strip()
    if not text or not _looks_like_ip_attempt(text):
        return False
    if text.lower() == "localhost" or _evades_standard_formatting(text):
        return False
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return False
    mapped = parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) else None
    subjects = (parsed, mapped) if mapped is not None else (parsed,)
    for ip in subjects:
        if (
            not ip.is_global
            or ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
    return True


def private_ip_guard_response(value: str) -> tuple[int, dict[str, Any]]:
    """Return HTTP 422 for a refused address. Non-address text is not a lookup."""
    text = value.strip()
    if not _looks_like_ip_attempt(text):
        return 200, {
            "private_ip_guard_triggered": False,
            "external_lookup_performed": False,
            "matched": False,
            "value": text,
        }
    if external_lookup_allowed(text):
        return 200, {
            "private_ip_guard_triggered": False,
            "external_lookup_performed": False,
            "matched": False,
            "value": text,
        }
    return 422, {
        "error": "private_or_reserved_ip_rejected",
        "private_ip_guard_triggered": True,
        "external_lookup_performed": False,
        "value": text,
    }
