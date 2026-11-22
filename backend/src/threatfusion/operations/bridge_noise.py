"""Lab-bridge addresses that are not the attacker/victim unicast path."""

from __future__ import annotations

import ipaddress

MDNS_PORT = 5353
_BROADCAST = ipaddress.ip_address("255.255.255.255")
_CLOUD_INFRA_IPS = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.169.253"),
        ipaddress.ip_address("169.254.169.123"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("168.63.129.16"),
        ipaddress.ip_address("fd00:ec2::254"),
        ipaddress.ip_address("100.100.100.200"),
    }
)


def is_lab_bridge_noise(src: str, dst: str, src_port: int, dst_port: int) -> bool:
    """True for multicast, link-local, broadcast, cloud infra probes, or mDNS port 5353."""
    if src_port == MDNS_PORT or dst_port == MDNS_PORT:
        return True
    for raw in (src, dst):
        try:
            address = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            return True
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if (
            address.is_multicast
            or address.is_link_local
            or address == _BROADCAST
            or address in _CLOUD_INFRA_IPS
        ):
            return True
    return False
