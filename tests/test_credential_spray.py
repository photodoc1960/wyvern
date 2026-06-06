"""Tests for the credential-spray / reuse detector."""

from __future__ import annotations

from wyvern.constants import STAGE_CREDENTIAL
from wyvern.detectors.credential_spray import CredentialSprayDetector


def test_reuse_across_hosts(config, feed, mk):
    det = CredentialSprayDetector(config)
    events = [mk.syn("192.168.1.50", f"192.168.1.{h}", 22, 1000.0 + h,
                     mac="00:14:22:00:00:50") for h in range(10, 16)]
    alerts = [a for a in feed(det, events) if "reuse across" in a.title]
    assert alerts and alerts[0].stage == STAGE_CREDENTIAL
    assert alerts[0].evidence["distinct_hosts"] >= 5


def test_repeated_attempts_one_host(config, feed, mk):
    det = CredentialSprayDetector(config)
    events = [mk.syn("192.168.1.50", "192.168.1.10", 3389, 1000.0 + i,
                     mac="00:14:22:00:00:50", sport=40000 + i) for i in range(10)]
    alerts = [a for a in feed(det, events) if "auth attempts" in a.title]
    assert alerts and alerts[0].evidence["attempts"] >= 8


def test_non_auth_ports_ignored(config, feed, mk):
    det = CredentialSprayDetector(config)
    events = [mk.syn("192.168.1.50", f"192.168.1.{h}", 80, 1000.0 + h,
                     mac="00:14:22:00:00:50") for h in range(10, 20)]
    assert feed(det, events) == []
