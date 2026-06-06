"""Shared fixtures and event builders for the Wyvern test suite."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from wyvern.config import Config
from wyvern.detectors.base import DetectorContext, NullProfiles
from wyvern.models.events import (
    ArpEvent,
    ConnEvent,
    DhcpEvent,
    DnsEvent,
    HttpEvent,
)
from wyvern.tracking.registry import DeviceRegistry


@pytest.fixture
def config() -> Config:
    return Config.default()


@pytest.fixture
def registry(config) -> DeviceRegistry:
    return DeviceRegistry(config)


@pytest.fixture
def mk():
    """A namespace of concise event builders for tests."""

    def syn(src, dst, port, ts, *, mac=None, ttl=64, sport=40000):
        return ConnEvent(ts=ts, src_ip=src, dst_ip=dst, dst_port=port, src_port=sport,
                         src_mac=mac, flags="S", ttl=ttl, window=64240)

    def synack(src, dst, sport, ts, *, mac=None, ttl=64):
        return ConnEvent(ts=ts, src_ip=src, dst_ip=dst, dst_port=40000, src_port=sport,
                         src_mac=mac, flags="SA", ttl=ttl)

    def rst(src, dst, port, ts, *, mac=None):
        return ConnEvent(ts=ts, src_ip=src, dst_ip=dst, dst_port=port, src_mac=mac, flags="R")

    def udp(src, dst, port, ts, *, mac=None):
        return ConnEvent(ts=ts, src_ip=src, dst_ip=dst, dst_port=port, proto="udp",
                         src_mac=mac, flags="")

    def arp(mac, ip, ts, op=2):
        return ArpEvent(ts=ts, src_mac=mac, src_ip=ip, op=op)

    def dns(src, qname, ts, *, mac=None, qtype="A"):
        return DnsEvent(ts=ts, src_ip=src, src_mac=mac, qname=qname, qtype=qtype)

    def dns_nx(server, querier, qname, ts):
        return DnsEvent(ts=ts, src_ip=server, qname=qname, is_response=True, rcode=3,
                        dst_ip=querier)

    def http(src, dst, port, ts, *, path=None, host=None, method="GET", mac=None, tls=False):
        return HttpEvent(ts=ts, src_ip=src, dst_ip=dst, dst_port=port, method=method,
                         path=path, host=host, src_mac=mac, tls=tls)

    def infer(src, dst, ts, *, mac=None, port=8000):
        return HttpEvent(ts=ts, src_ip=src, dst_ip=dst, dst_port=port, method="POST",
                         path="/v1/chat/completions", host="vllm", src_mac=mac)

    def dhcp(mac, ip, ts, *, hostname=None):
        return DhcpEvent(ts=ts, src_mac=mac, src_ip=ip, hostname=hostname)

    return SimpleNamespace(
        syn=syn, synack=synack, rst=rst, udp=udp, arp=arp, dns=dns,
        dns_nx=dns_nx, http=http, infer=infer, dhcp=dhcp,
    )


@pytest.fixture
def feed(config, registry):
    """Feed events through a detector (observing into the registry first)."""

    def _feed(detector, events, profiles=None):
        alerts = []
        for ev in events:
            registry.observe(ev)
            ctx = DetectorContext(config, registry, profiles or NullProfiles(), now=ev.ts)
            alerts.extend(detector.inspect(ev, ctx))
        return alerts

    return _feed


@pytest.fixture
def sweep(config, registry):
    def _sweep(detector, now, profiles=None):
        ctx = DetectorContext(config, registry, profiles or NullProfiles(), now=now)
        return detector.sweep(ctx)

    return _sweep
