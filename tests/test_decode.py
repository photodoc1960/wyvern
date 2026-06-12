"""Tests for dpkt-based frame decoding."""

from __future__ import annotations

import socket

import dpkt

from wyvern.capture.decode import decode_frame
from wyvern.models.events import ArpEvent, ConnEvent, DhcpEvent, DnsEvent, HttpEvent

SMAC = b"\xaa\xbb\xcc\x00\x11\x22"
DMAC = b"\x00\x11\x22\x33\x44\x55"
A = socket.inet_aton("192.168.1.50")
B = socket.inet_aton("192.168.1.10")


def _eth(data, etype):
    return bytes(dpkt.ethernet.Ethernet(src=SMAC, dst=DMAC, type=etype, data=data))


def test_decode_tcp_syn():
    tcp = dpkt.tcp.TCP(sport=44000, dport=445, flags=dpkt.tcp.TH_SYN, win=64240)
    ip = dpkt.ip.IP(src=A, dst=B, p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    evs = decode_frame(_eth(ip, dpkt.ethernet.ETH_TYPE_IP), 1.0)
    conn = [e for e in evs if isinstance(e, ConnEvent)][0]
    assert conn.dst_port == 445 and conn.is_syn and conn.ttl == 64
    assert conn.src_mac == "aa:bb:cc:00:11:22"


def test_decode_arp():
    arp = dpkt.arp.ARP(sha=SMAC, spa=A, tha=b"\x00" * 6, tpa=B, op=1)
    evs = decode_frame(_eth(arp, dpkt.ethernet.ETH_TYPE_ARP), 1.0)
    assert isinstance(evs[0], ArpEvent) and evs[0].src_ip == "192.168.1.50"


def test_decode_dns_query_and_nxdomain():
    q = dpkt.dns.DNS(qd=[dpkt.dns.DNS.Q(name="example.com", type=1)])
    q.qr = 0
    udp = dpkt.udp.UDP(sport=5353, dport=53, data=q)
    ip = dpkt.ip.IP(src=A, dst=B, p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=udp)
    evs = decode_frame(_eth(ip, dpkt.ethernet.ETH_TYPE_IP), 1.0)
    assert isinstance(evs[0], DnsEvent) and evs[0].qname == "example.com"
    assert not evs[0].is_response

    r = dpkt.dns.DNS(qd=[dpkt.dns.DNS.Q(name="missing.example", type=1)])
    r.qr = 1
    r.rcode = 3
    udp2 = dpkt.udp.UDP(sport=53, dport=33333, data=r)
    ip2 = dpkt.ip.IP(src=B, dst=A, p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=udp2)
    evs2 = decode_frame(_eth(ip2, dpkt.ethernet.ETH_TYPE_IP), 2.0)
    assert evs2[0].is_nxdomain


def test_decode_http_inference():
    body = (
        b"POST /v1/chat/completions HTTP/1.1\r\nHost: gpu.local\r\nUser-Agent: requests\r\n\r\n{}"
    )
    tcp = dpkt.tcp.TCP(sport=40000, dport=8000, flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, data=body)
    ip = dpkt.ip.IP(src=A, dst=B, p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    evs = decode_frame(_eth(ip, dpkt.ethernet.ETH_TYPE_IP), 1.0)
    http = [e for e in evs if isinstance(e, HttpEvent)][0]
    assert http.path == "/v1/chat/completions" and http.host == "gpu.local"


def test_decode_dhcp_hostname():
    opts = [(12, b"my-printer"), (55, bytes([1, 3, 6]))]
    dhcp = dpkt.dhcp.DHCP(chaddr=SMAC + b"\x00" * 10, opts=opts)
    udp = dpkt.udp.UDP(sport=68, dport=67, data=dhcp)
    ip = dpkt.ip.IP(
        src=b"\x00\x00\x00\x00", dst=b"\xff\xff\xff\xff", p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=udp
    )
    evs = decode_frame(_eth(ip, dpkt.ethernet.ETH_TYPE_IP), 1.0)
    dh = [e for e in evs if isinstance(e, DhcpEvent)][0]
    assert dh.hostname == "my-printer" and dh.param_list == (1, 3, 6)


def test_decode_udp_generic():
    udp = dpkt.udp.UDP(sport=5000, dport=4444, data=b"beacon")
    ip = dpkt.ip.IP(src=A, dst=B, p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=udp)
    evs = decode_frame(_eth(ip, dpkt.ethernet.ETH_TYPE_IP), 1.0)
    assert isinstance(evs[0], ConnEvent) and evs[0].proto == "udp" and evs[0].dst_port == 4444


def test_decode_malformed_returns_empty():
    assert decode_frame(b"\x00\x01\x02", 1.0) == []
    assert decode_frame(b"", 1.0) == []
