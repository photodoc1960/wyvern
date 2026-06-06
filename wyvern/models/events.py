"""Normalised, immutable network events — the interface between the capture
layer (scapy/dpkt) and the detectors.

Detectors never see raw packets; they see these frozen dataclasses. That keeps
detection logic pure and trivially unit-testable without a live interface or
root privileges.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union


@dataclass(frozen=True, slots=True)
class ArpEvent:
    """An ARP request (op=1) or reply (op=2). Drives device discovery."""

    ts: float
    src_mac: str
    src_ip: str
    op: int = 1
    dst_ip: str | None = None
    dst_mac: str | None = None
    kind = "arp"


@dataclass(frozen=True, slots=True)
class ConnEvent:
    """A TCP/UDP flow observation (a connection attempt or datagram).

    For TCP we key off the SYN to model "device X tried to reach port P on
    host Y", which is what scanning, lateral movement and credential fan-out
    all look like at the network layer. ``ttl`` and ``window`` (from the SYN)
    feed passive OS fingerprinting.
    """

    ts: float
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str = "tcp"
    src_port: int = 0
    src_mac: str | None = None
    dst_mac: str | None = None
    flags: str = ""            # TCP flags as letters, e.g. "S", "SA", "RA", "PA"
    payload_len: int = 0
    ttl: int | None = None
    window: int | None = None
    kind = "conn"

    @property
    def is_syn(self) -> bool:
        return "S" in self.flags and "A" not in self.flags

    @property
    def is_synack(self) -> bool:
        return "S" in self.flags and "A" in self.flags

    @property
    def is_rst(self) -> bool:
        return "R" in self.flags

    @property
    def is_fin(self) -> bool:
        return "F" in self.flags

    @property
    def has_payload(self) -> bool:
        return self.payload_len > 0


@dataclass(frozen=True, slots=True)
class DnsEvent:
    """A DNS (or mDNS) query or response. ``rcode`` 3 == NXDOMAIN."""

    ts: float
    src_ip: str
    qname: str
    qtype: str = "A"
    is_response: bool = False
    rcode: int | None = None
    answers: tuple[str, ...] = ()
    src_mac: str | None = None
    dst_ip: str | None = None
    kind = "dns"

    @property
    def is_nxdomain(self) -> bool:
        return self.is_response and self.rcode == 3


@dataclass(frozen=True, slots=True)
class HttpEvent:
    """A cleartext HTTP request, or a TLS ClientHello (``tls=True``) from which
    only the SNI ``host`` is known. Used by the inference-proxy detector."""

    ts: float
    src_ip: str
    dst_ip: str
    dst_port: int
    method: str | None = None
    host: str | None = None
    path: str | None = None
    user_agent: str | None = None
    src_mac: str | None = None
    tls: bool = False
    kind = "http"


@dataclass(frozen=True, slots=True)
class DhcpEvent:
    """A DHCP request carrying a hostname and/or vendor/parameter fingerprint."""

    ts: float
    src_mac: str
    src_ip: str | None = None
    hostname: str | None = None
    vendor_class: str | None = None
    param_list: tuple[int, ...] = ()
    kind = "dhcp"


NetworkEvent = Union[ArpEvent, ConnEvent, DnsEvent, HttpEvent, DhcpEvent]

__all__ = [
    "ArpEvent",
    "ConnEvent",
    "DnsEvent",
    "HttpEvent",
    "DhcpEvent",
    "NetworkEvent",
]
