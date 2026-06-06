"""Tests for the DNS-anomaly detector."""

from __future__ import annotations

import dataclasses

from wyvern.config import Config
from wyvern.detectors.base import DetectorContext, NullProfiles
from wyvern.detectors.dns_anomaly import DnsAnomalyDetector
from wyvern.tracking.registry import DeviceRegistry


def _run(det, events, cfg):
    reg = DeviceRegistry(cfg)
    out = []
    for e in events:
        reg.observe(e)
        out.extend(det.inspect(e, DetectorContext(cfg, reg, NullProfiles(), now=e.ts)))
    return out


def _cfg(**th):
    base = Config.default()
    return dataclasses.replace(base, thresholds=dataclasses.replace(base.thresholds, **th))


def test_dga_domain_flagged(config, mk):
    det = DnsAnomalyDetector(config)
    alerts = _run(det, [mk.dns("192.168.1.50", "kq3z9x1m7wp4t.net", 1.0)], config)
    assert any("algorithmically" in a.title for a in alerts)


def test_benign_domain_quiet(config, mk):
    det = DnsAnomalyDetector(config)
    assert _run(det, [mk.dns("192.168.1.50", "www.google.com", 1.0)], config) == []


def test_query_spike(mk):
    cfg = _cfg(dns_rate_per_min=5, dns_window_s=60)
    det = DnsAnomalyDetector(cfg)
    events = [mk.dns("192.168.1.50", f"host{i}.example.com", 1000.0 + i) for i in range(10)]
    alerts = _run(det, events, cfg)
    assert any("query spike" in a.title for a in alerts)


def test_nxdomain_burst(mk):
    cfg = _cfg(dns_nxdomain_burst=4, dns_window_s=60)
    det = DnsAnomalyDetector(cfg)
    events = [mk.dns_nx("192.168.1.1", "192.168.1.50", f"bad{i}.tld", 1000.0 + i) for i in range(6)]
    alerts = _run(det, events, cfg)
    assert any("NXDOMAIN" in a.title for a in alerts)
