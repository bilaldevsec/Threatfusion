"""Lab-bridge addresses that are not the attacker/victim unicast path."""

from __future__ import annotations

import ipaddress

MDNS_PORT = 5353
_BROADCAST = ipaddress.ip_address("255.255.255.255")


def is_lab_bridge_noise(src: str, dst: str, src_port: int, dst_port: int) -> bool:
    """True for multicast, link-local, broadcast, or mDNS port 5353."""
    if src_port == MDNS_PORT or dst_port == MDNS_PORT:
        return True
    for raw in (src, dst):
        try:
            address = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            return True
        if address.is_multicast or address.is_link_local or address == _BROADCAST:
            return True
    return False
