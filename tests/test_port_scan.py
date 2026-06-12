"""Tests for the port-scan detector."""

from __future__ import annotations

from wyvern.constants import STAGE_RECON
from wyvern.detectors.port_scan import PortScanDetector


def test_fires_above_threshold(config, feed, mk):
    det = PortScanDetector(config)
    events = [
        mk.syn("192.168.1.50", "192.168.1.10", p, 1000.0 + p * 0.1, mac="00:14:22:00:00:50")
        for p in range(1, 61)
    ]
    alerts = feed(det, events)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.stage == STAGE_RECON
    assert a.evidence["distinct_ports"] >= 50
    # ports 1..50 include worm-targeted services SSH(22), telnet(23), Exim(25)
    assert 22 in a.evidence.get("worm_service_ports", [])


def test_quiet_below_threshold(config, feed, mk):
    det = PortScanDetector(config)
    events = [
        mk.syn("192.168.1.50", "192.168.1.10", p, 1000.0 + p, mac="00:14:22:00:00:50")
        for p in range(1, 40)
    ]
    assert feed(det, events) == []


def test_external_source_ignored(config, feed, mk):
    det = PortScanDetector(config)
    events = [mk.syn("8.8.8.8", "192.168.1.10", p, 1000.0 + p * 0.1) for p in range(1, 61)]
    assert feed(det, events) == []
