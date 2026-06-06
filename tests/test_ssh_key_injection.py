"""Tests for the SSH key / credential propagation detector."""

from __future__ import annotations

from wyvern.constants import STAGE_SSH_KEY
from wyvern.detectors.ssh_key_injection import SshKeyInjectionDetector


def test_idle_device_ssh_fanout(config, feed, mk):
    det = SshKeyInjectionDetector(config)
    events = [mk.arp("00:80:77:aa:bb:cc", "192.168.1.30", 1.0)]   # printer
    events += [mk.syn("192.168.1.30", f"192.168.1.{h}", 22, 10.0 + h,
                      mac="00:80:77:aa:bb:cc") for h in range(10, 14)]
    alerts = feed(det, events)
    assert alerts and alerts[0].stage == STAGE_SSH_KEY
    assert alerts[0].evidence["idle_device"] is True


def test_many_hosts_fires_for_any_device(config, feed, mk):
    det = SshKeyInjectionDetector(config)
    events = [mk.syn("192.168.1.50", f"192.168.1.{h}", 22, 10.0 + h,
                     mac="00:14:22:00:00:50", ttl=128) for h in range(10, 16)]
    alerts = feed(det, events)
    assert alerts and alerts[0].evidence["distinct_hosts"] >= 5


def test_non_ssh_ignored(config, feed, mk):
    det = SshKeyInjectionDetector(config)
    events = [mk.syn("192.168.1.30", f"192.168.1.{h}", 23, 10.0 + h,
                     mac="00:80:77:aa:bb:cc") for h in range(10, 15)]
    assert feed(det, events) == []
