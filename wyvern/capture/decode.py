"""Frame decoding with dpkt — raw Ethernet bytes -> normalised events.

This module performs the packet *analysis*: it pulls L2/L3/L4 structure out of
each frame and, where the payload is application data we care about (HTTP
requests, TLS ClientHello SNI, DNS, DHCP), parses just enough to feed detection.

It depends only on ``dpkt`` and the standard library, so the entire detection
pipeline can be unit-tested by handing it crafted byte buffers — no live
interface, no root, no scapy.
"""

from __future__ import annotations

import socket

import dpkt

from ..models.events import (
    ArpEvent,
    ConnEvent,
    DhcpEvent,
    DnsEvent,
    HttpEvent,
    NetworkEvent,
    StreamSegmentEvent,
)

# DNS-like UDP ports we parse as DNS (53) or multicast DNS (5353).
_DNS_PORTS = {53, 5353}
_DHCP_PORTS = {67, 68}
# Ports where we attempt cleartext HTTP request parsing.
_HTTP_HINT_PORTS = {80, 631, 3000, 5000, 8000, 8080, 8081, 8161, 8888, 9100, 10000}
# HTTPS ports whose data segments we surface for passive stream-timing analysis.
_STREAM_PORTS = {443}


def _mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ip_to_str(raw: bytes) -> str | None:
    try:
        if len(raw) == 4:
            return socket.inet_ntop(socket.AF_INET, raw)
        if len(raw) == 16:
            return socket.inet_ntop(socket.AF_INET6, raw)
    except (ValueError, OSError):
        return None
    return None


def _tcp_flag_letters(flags: int) -> str:
    out = []
    if flags & dpkt.tcp.TH_FIN:
        out.append("F")
    if flags & dpkt.tcp.TH_SYN:
        out.append("S")
    if flags & dpkt.tcp.TH_RST:
        out.append("R")
    if flags & dpkt.tcp.TH_PUSH:
        out.append("P")
    if flags & dpkt.tcp.TH_ACK:
        out.append("A")
    if flags & dpkt.tcp.TH_URG:
        out.append("U")
    return "".join(out)


def decode_frame(raw: bytes, ts: float) -> list[NetworkEvent]:
    """Decode one Ethernet frame into zero or more :class:`NetworkEvent`.

    Never raises on malformed input — returns ``[]`` instead, because packet
    data is untrusted.
    """
    try:
        eth = dpkt.ethernet.Ethernet(raw)
    except (dpkt.dpkt.UnpackError, Exception):  # noqa: BLE001 - untrusted input
        return []

    src_mac = _mac_to_str(eth.src)
    dst_mac = _mac_to_str(eth.dst)
    l3 = eth.data

    if isinstance(l3, dpkt.arp.ARP):
        return _decode_arp(l3, ts)

    if isinstance(l3, dpkt.ip.IP):
        ttl = l3.ttl
    elif isinstance(l3, dpkt.ip6.IP6):
        ttl = getattr(l3, "hlim", None)
    else:
        return []

    src_ip = _ip_to_str(l3.src)
    dst_ip = _ip_to_str(l3.dst)
    if not src_ip or not dst_ip:
        return []

    l4 = l3.data
    if isinstance(l4, dpkt.tcp.TCP):
        return _decode_tcp(l4, ts, src_ip, dst_ip, src_mac, dst_mac, ttl)
    if isinstance(l4, dpkt.udp.UDP):
        return _decode_udp(l4, ts, src_ip, dst_ip, src_mac, dst_mac)
    return []


def _decode_arp(arp: dpkt.arp.ARP, ts: float) -> list[NetworkEvent]:
    src_ip = _ip_to_str(arp.spa)
    if not src_ip:
        return []
    return [
        ArpEvent(
            ts=ts,
            src_mac=_mac_to_str(arp.sha),
            src_ip=src_ip,
            op=int(arp.op),
            dst_ip=_ip_to_str(arp.tpa),
            dst_mac=_mac_to_str(arp.tha) if any(arp.tha) else None,
        )
    ]


def _decode_tcp(
    tcp: dpkt.tcp.TCP,
    ts: float,
    src_ip: str,
    dst_ip: str,
    src_mac: str,
    dst_mac: str,
    ttl: int | None,
) -> list[NetworkEvent]:
    flags = _tcp_flag_letters(tcp.flags)
    payload = bytes(tcp.data) if tcp.data else b""
    events: list[NetworkEvent] = []

    dport, sport = int(tcp.dport), int(tcp.sport)

    if payload:
        app = _parse_http_or_tls(payload, ts, src_ip, dst_ip, dport, src_mac)
        if app is not None:
            events.append(app)
        # Surface data-bearing HTTPS segments (metadata only) so the stream-timing
        # detector can measure inter-packet cadence on the response direction.
        if dport in _STREAM_PORTS or sport in _STREAM_PORTS:
            events.append(
                StreamSegmentEvent(
                    ts=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dport,
                    src_port=sport,
                    payload_len=len(payload),
                    to_client=sport in _STREAM_PORTS,
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                )
            )

    is_syn = ("S" in flags) and ("A" not in flags)
    is_synack = ("S" in flags) and ("A" in flags)
    is_rst = "R" in flags
    if is_syn or is_synack or is_rst:
        events.append(
            ConnEvent(
                ts=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=int(tcp.dport),
                proto="tcp",
                src_port=int(tcp.sport),
                src_mac=src_mac,
                dst_mac=dst_mac,
                flags=flags,
                payload_len=len(payload),
                ttl=ttl,
                window=int(tcp.win),
            )
        )
    return events


def _decode_udp(
    udp: dpkt.udp.UDP,
    ts: float,
    src_ip: str,
    dst_ip: str,
    src_mac: str,
    dst_mac: str,
) -> list[NetworkEvent]:
    sport, dport = int(udp.sport), int(udp.dport)
    payload = bytes(udp.data) if udp.data else b""

    if sport in _DNS_PORTS or dport in _DNS_PORTS:
        dns = _parse_dns(payload, ts, src_ip, dst_ip, src_mac)
        if dns is not None:
            return [dns]
    if sport in _DHCP_PORTS or dport in _DHCP_PORTS:
        dhcp = _parse_dhcp(payload, ts, src_mac, src_ip)
        if dhcp is not None:
            return [dhcp]

    return [
        ConnEvent(
            ts=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dport,
            proto="udp",
            src_port=sport,
            src_mac=src_mac,
            dst_mac=dst_mac,
            flags="",
            payload_len=len(payload),
        )
    ]


def _parse_http_or_tls(
    payload: bytes, ts: float, src_ip: str, dst_ip: str, dport: int, src_mac: str
) -> HttpEvent | None:
    # Cleartext HTTP request?
    if payload[:8].upper().split(b" ", 1)[0] in _HTTP_METHODS or dport in _HTTP_HINT_PORTS:
        http = _parse_http_request(payload)
        if http is not None:
            method, path, host, ua = http
            return HttpEvent(
                ts=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dport,
                method=method,
                host=host,
                path=path,
                user_agent=ua,
                src_mac=src_mac,
                tls=False,
            )
    # TLS ClientHello (record type 0x16, handshake type 0x01)?
    if len(payload) > 5 and payload[0] == 0x16:
        host = _extract_sni(payload)
        return HttpEvent(
            ts=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dport,
            method=None,
            host=host,
            path=None,
            user_agent=None,
            src_mac=src_mac,
            tls=True,
        )
    return None


_HTTP_METHODS = {
    b"GET",
    b"POST",
    b"PUT",
    b"HEAD",
    b"DELETE",
    b"OPTIONS",
    b"PATCH",
    b"CONNECT",
}


def _parse_http_request(payload: bytes) -> tuple[str, str, str | None, str | None] | None:
    try:
        req = dpkt.http.Request(payload)
    except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData, Exception):  # noqa: BLE001
        return None
    headers = {k.lower(): v for k, v in (req.headers or {}).items()}
    host = headers.get("host")
    ua = headers.get("user-agent")
    if isinstance(host, list):
        host = host[0] if host else None
    if isinstance(ua, list):
        ua = ua[0] if ua else None
    return (req.method, req.uri, host, ua)


def _extract_sni(data: bytes) -> str | None:
    """Best-effort SNI extraction from a TLS ClientHello. Returns host or None."""
    try:
        if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
            return None
        idx = 5 + 4 + 2 + 32  # record hdr + handshake hdr + version + random
        sid_len = data[idx]
        idx += 1 + sid_len
        cs_len = int.from_bytes(data[idx : idx + 2], "big")
        idx += 2 + cs_len
        cm_len = data[idx]
        idx += 1 + cm_len
        if idx + 2 > len(data):
            return None
        ext_total = int.from_bytes(data[idx : idx + 2], "big")
        idx += 2
        end = min(len(data), idx + ext_total)
        while idx + 4 <= end:
            etype = int.from_bytes(data[idx : idx + 2], "big")
            elen = int.from_bytes(data[idx + 2 : idx + 4], "big")
            idx += 4
            if etype == 0x0000:  # server_name extension
                j = idx + 2 + 1  # server_name_list len + name_type
                name_len = int.from_bytes(data[j : j + 2], "big")
                j += 2
                # Cap at the DNS max name length so a crafted ClientHello can't
                # inject a 64 KB "hostname" into the registry/DB/dashboard.
                name = data[j : j + min(name_len, 253)]
                return name.decode("ascii", errors="ignore") or None
            idx += elen
        return None
    except (IndexError, ValueError):
        return None


def _parse_dns(
    payload: bytes, ts: float, src_ip: str, dst_ip: str, src_mac: str
) -> DnsEvent | None:
    try:
        dns = dpkt.dns.DNS(payload)
    except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData, Exception):  # noqa: BLE001
        return None
    qname = ""
    qtype = "A"
    if dns.qd:
        q = dns.qd[0]
        qname = getattr(q, "name", "") or ""
        qtype = _DNS_TYPES.get(getattr(q, "type", 1), str(getattr(q, "type", 1)))
    is_response = bool(dns.qr)
    answers: list[str] = []
    if is_response and dns.an:
        for rr in dns.an:
            ans = _format_answer(rr)
            if ans:
                answers.append(ans)
    return DnsEvent(
        ts=ts,
        src_ip=src_ip,
        qname=qname,
        qtype=qtype,
        is_response=is_response,
        rcode=int(dns.rcode) if is_response else None,
        answers=tuple(answers),
        src_mac=src_mac,
        dst_ip=dst_ip,
    )


_DNS_TYPES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR", 33: "SRV", 2: "NS"}


def _format_answer(rr) -> str | None:
    try:
        if rr.type == 1 and len(rr.rdata) == 4:
            return socket.inet_ntop(socket.AF_INET, rr.rdata)
        if rr.type == 28 and len(rr.rdata) == 16:
            return socket.inet_ntop(socket.AF_INET6, rr.rdata)
        cname = getattr(rr, "cname", None)
        if cname:
            return cname
    except (ValueError, OSError, AttributeError):
        return None
    return None


def _parse_dhcp(payload: bytes, ts: float, src_mac: str, src_ip: str | None) -> DhcpEvent | None:
    try:
        dhcp = dpkt.dhcp.DHCP(payload)
    except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData, Exception):  # noqa: BLE001
        return None
    hostname = None
    vendor_class = None
    params: tuple[int, ...] = ()
    for code, val in dhcp.opts:
        if code == 12:  # hostname
            hostname = _safe_text(val)
        elif code == 60:  # vendor class identifier
            vendor_class = _safe_text(val)
        elif code == 55:  # parameter request list
            params = tuple(val)
    chaddr = dhcp.chaddr[:6] if dhcp.chaddr else b""
    client_mac = _mac_to_str(chaddr) if len(chaddr) == 6 else src_mac
    return DhcpEvent(
        ts=ts,
        src_mac=client_mac,
        src_ip=src_ip,
        hostname=hostname,
        vendor_class=vendor_class,
        param_list=params,
    )


def _safe_text(val: bytes, maxlen: int = 253) -> str | None:
    try:
        return val[:maxlen].decode("utf-8", errors="ignore").strip("\x00") or None
    except (AttributeError, UnicodeDecodeError):
        return None
