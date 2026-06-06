"""IP/MAC normalisation and internal-network membership helpers.

All functions are pure and total: malformed input yields a defined result
(``None``/``False``) rather than raising, because packet data is untrusted.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

# RFC1918 + link-local + unique-local — the default notion of "internal".
DEFAULT_PRIVATE_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",   # CGNAT, common on some home ISPs
    "fd00::/8",
    "fe80::/10",
)

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def normalize_mac(mac: str | bytes | None) -> str | None:
    """Return a canonical lowercase ``aa:bb:cc:dd:ee:ff`` MAC, or ``None``.

    Accepts colon/dash/dot separated strings or raw 6-byte values.
    """
    if mac is None:
        return None
    if isinstance(mac, (bytes, bytearray)):
        if len(mac) != 6:
            return None
        return ":".join(f"{b:02x}" for b in mac)
    text = str(mac).strip().lower().replace("-", ":").replace(".", ":")
    parts = [p for p in text.split(":") if p != ""]
    # Cisco-style 0011.2233.4455 collapses to three 4-char groups.
    if len(parts) == 3 and all(len(p) == 4 for p in parts):
        joined = "".join(parts)
        parts = [joined[i : i + 2] for i in range(0, 12, 2)]
    if len(parts) != 6:
        return None
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octets):
        return None
    return ":".join(f"{o:02x}" for o in octets)


def is_broadcast_mac(mac: str | None) -> bool:
    norm = normalize_mac(mac)
    return norm == BROADCAST_MAC


def is_multicast_mac(mac: str | None) -> bool:
    """True for IPv4/IPv6 multicast L2 addresses (LSB of first octet set)."""
    norm = normalize_mac(mac)
    if norm is None:
        return False
    first = int(norm.split(":")[0], 16)
    return bool(first & 0x01)


@lru_cache(maxsize=64)
def _parse_networks(cidrs: tuple[str, ...]) -> tuple[ipaddress._BaseNetwork, ...]:
    nets: list[ipaddress._BaseNetwork] = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def _parse_ip(ip: str | None):
    if not ip:
        return None
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def ip_in_cidrs(ip: str | None, cidrs: tuple[str, ...]) -> bool:
    addr = _parse_ip(ip)
    if addr is None:
        return False
    for net in _parse_networks(tuple(cidrs)):
        if addr.version == net.version and addr in net:
            return True
    return False


def is_internal_ip(ip: str | None, cidrs: tuple[str, ...] | None = None) -> bool:
    """True if ``ip`` is within the configured internal CIDRs."""
    return ip_in_cidrs(ip, tuple(cidrs) if cidrs else DEFAULT_PRIVATE_CIDRS)


def is_global_ip(ip: str | None) -> bool:
    """True if ``ip`` is a routable public address."""
    addr = _parse_ip(ip)
    return bool(addr and addr.is_global)


def is_multicast_ip(ip: str | None) -> bool:
    addr = _parse_ip(ip)
    return bool(addr and addr.is_multicast)


def is_usable_host_ip(ip: str | None) -> bool:
    """True for an ordinary unicast host address worth tracking.

    Excludes multicast, broadcast, unspecified and loopback noise.
    """
    addr = _parse_ip(ip)
    if addr is None:
        return False
    if addr.is_multicast or addr.is_unspecified or addr.is_loopback:
        return False
    if addr.version == 4 and ip and ip.endswith(".255"):
        return False
    return True
