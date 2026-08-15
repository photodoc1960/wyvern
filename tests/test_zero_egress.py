"""Tests for the zero-egress detector.

A host declared as having *no* expected egress (an isolated / quarantined /
air-gapped device) must never reach an external network. The first outbound
connection to a novel external destination is a high-confidence tripwire — the
network-layer signal of a containment escape (issue #22, motivated by the
2026-07 autonomous sandbox-escape incident). The detector is inert unless such
hosts are configured, so it is off by default.
"""

from __future__ import annotations

from wyvern.config import Config
from wyvern.constants import STAGE_EGRESS
from wyvern.detectors.zero_egress import ZeroEgressDetector
from wyvern.models.alert import Severity


def _cfg(*hosts: str) -> Config:
    return Config(no_egress_hosts=hosts).validate()


def test_egress_from_no_egress_host_alerts(feed, mk):
    det = ZeroEgressDetector(_cfg("192.168.1.77"))
    alerts = feed(
        det, [mk.syn("192.168.1.77", "198.51.100.9", 443, 1000.0, mac="00:14:22:00:00:77")]
    )
    assert len(alerts) == 1
    a = alerts[0]
    assert a.stage == STAGE_EGRESS
    assert a.severity == Severity.CRITICAL
    assert a.src_ip == "192.168.1.77"
    assert a.dst_ip == "198.51.100.9"
    assert a.confidence >= 0.85
    assert a.recommendations  # manual remediation guidance present


def test_internal_traffic_not_egress(feed, mk):
    det = ZeroEgressDetector(_cfg("192.168.1.77"))
    # talking to another internal host is not egress (lateral_movement's concern)
    assert feed(det, [mk.syn("192.168.1.77", "192.168.1.10", 445, 1000.0)]) == []


def test_unlisted_host_not_flagged(feed, mk):
    det = ZeroEgressDetector(_cfg("192.168.1.77"))
    # a host that is NOT declared no-egress may talk to the internet freely
    assert feed(det, [mk.syn("192.168.1.50", "198.51.100.9", 443, 1000.0)]) == []


def test_udp_egress_flagged(feed, mk):
    # UDP/QUIC has no SYN; the detector must still catch it (does not gate on is_syn)
    det = ZeroEgressDetector(_cfg("192.168.1.77"))
    alerts = feed(det, [mk.udp("192.168.1.77", "198.51.100.9", 443, 1000.0)])
    assert len(alerts) == 1 and alerts[0].stage == STAGE_EGRESS


def test_repeat_same_destination_suppressed(feed, mk):
    det = ZeroEgressDetector(_cfg("192.168.1.77"))
    events = [
        mk.syn("192.168.1.77", "198.51.100.9", 443, 1000.0, sport=40001),
        mk.syn("192.168.1.77", "198.51.100.9", 443, 1005.0, sport=40002),
    ]
    assert len(feed(det, events)) == 1  # novel destination alerts once


def test_new_destination_alerts_again(feed, mk):
    det = ZeroEgressDetector(_cfg("192.168.1.77"))
    events = [
        mk.syn("192.168.1.77", "198.51.100.9", 443, 1000.0, sport=40001),
        mk.syn("192.168.1.77", "203.0.113.7", 443, 1005.0, sport=40002),
    ]
    assert len(feed(det, events)) == 2  # each novel external network alerts


def test_inbound_not_flagged(feed, mk):
    # external host connecting IN to the no-egress host is not that host's egress
    det = ZeroEgressDetector(_cfg("192.168.1.77"))
    assert feed(det, [mk.syn("198.51.100.9", "192.168.1.77", 22, 1000.0)]) == []


def test_multicast_not_egress(feed, mk):
    # mDNS / multicast is not egress to an external network
    det = ZeroEgressDetector(_cfg("192.168.1.77"))
    assert feed(det, [mk.udp("192.168.1.77", "224.0.0.251", 5353, 1000.0)]) == []


def test_disabled_when_no_hosts_configured(feed, mk):
    det = ZeroEgressDetector(Config.default())  # no no_egress_hosts
    assert feed(det, [mk.syn("192.168.1.77", "198.51.100.9", 443, 1000.0)]) == []


def test_match_by_mac(feed, mk):
    # a no-egress host may be declared by MAC as well as IP
    det = ZeroEgressDetector(_cfg("00:14:22:00:00:99"))
    alerts = feed(
        det, [mk.syn("192.168.1.88", "198.51.100.9", 443, 1000.0, mac="00:14:22:00:00:99")]
    )
    assert len(alerts) == 1 and alerts[0].stage == STAGE_EGRESS
