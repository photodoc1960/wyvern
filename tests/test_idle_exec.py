"""Tests for the idle-device code-execution detector."""

from __future__ import annotations

from wyvern.constants import STAGE_REPLICATION
from wyvern.detectors.idle_exec import IdleDeviceExecDetector


def test_printer_originating_connections(config, feed, mk):
    det = IdleDeviceExecDetector(config)
    events = [mk.arp("00:80:77:aa:bb:cc", "192.168.1.30", 1.0)]
    events += [
        mk.syn("192.168.1.30", f"192.168.1.{h}", 445, 10.0 + h, mac="00:80:77:aa:bb:cc")
        for h in range(10, 15)
    ]
    alerts = feed(det, events)
    assert len(alerts) == 1
    assert alerts[0].stage == STAGE_REPLICATION
    assert alerts[0].evidence["role"] == "printer"


def test_workstation_not_flagged(config, feed, mk):
    det = IdleDeviceExecDetector(config)
    events = [mk.syn("192.168.1.50", "192.168.1.10", 445, 1.0, mac="00:14:22:00:00:50", ttl=128)]
    events += [
        mk.syn("192.168.1.50", f"192.168.1.{h}", 445, 10.0 + h, mac="00:14:22:00:00:50", ttl=128)
        for h in range(10, 16)
    ]
    assert feed(det, events) == []  # workstation is not an idle role
