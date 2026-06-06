"""Tests for the immutable domain models."""

from __future__ import annotations

import pytest

from wyvern.models.alert import Alert, Severity, new_alert_id
from wyvern.models.device import Device, DeviceRole
from wyvern.models.events import ConnEvent
from wyvern.models.profile import DeviceProfile


def test_device_evolve_is_immutable():
    d = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=1.0)
    d2 = d.with_ip("192.168.1.5", 2.0)
    assert d.ip is None and d2.ip == "192.168.1.5"
    assert d2.last_seen == 2.0
    d3 = d2.with_open_port(22).with_open_port(22)
    assert d3.open_ports == (22,)
    assert d2.open_ports == ()


def test_device_label_and_idle():
    d = Device(mac="m", role=DeviceRole.PRINTER, hostname="hp-printer")
    assert d.label == "hp-printer"
    assert d.is_idle_role
    assert not Device(mac="m", role=DeviceRole.WORKSTATION).is_idle_role
    assert "role" in d.to_dict()


def test_severity_from_confidence():
    assert Severity.from_confidence(0.9) is Severity.CRITICAL
    assert Severity.from_confidence(0.7) is Severity.HIGH
    assert Severity.from_confidence(0.5) is Severity.MEDIUM
    assert Severity.from_confidence(0.1) is Severity.LOW


def test_alert_clamps_and_isolates_evidence():
    ev = {"a": 1}
    a = Alert(detector="d", title="t", severity=Severity.HIGH, confidence=5.0,
              description="x", evidence=ev)
    assert a.confidence == 1.0
    ev["a"] = 2
    assert a.evidence["a"] == 1   # copy isolated from caller
    assert a.id and len(a.id) == 12


def test_alert_round_trip_dict():
    a = Alert(detector="port_scan", title="scan", severity=Severity.MEDIUM,
              confidence=0.6, description="d", src_ip="1.2.3.4", stage="discovery",
              recommendations=("isolate",), ts=10.0)
    d = a.to_dict()
    a2 = Alert.from_dict(d)
    assert a2.detector == a.detector and a2.severity is Severity.MEDIUM
    assert a2.stage == "discovery" and a2.recommendations == ("isolate",)


def test_profile_round_trip_and_queries():
    p = DeviceProfile(mac="m", learned=True, known_ports=frozenset({22, 443}),
                      known_internal_peers=frozenset({"192.168.1.2"}),
                      known_domains=frozenset({"example.com"}), active_hours=frozenset({9, 10}))
    assert p.is_new_port(8080) and not p.is_new_port(22)
    assert p.is_new_peer("192.168.1.9")
    assert not p.is_new_domain("EXAMPLE.com")
    assert p.is_active_hour(9) and not p.is_active_hour(3)
    p2 = DeviceProfile.from_dict(p.to_dict())
    assert p2.known_ports == p.known_ports and p2.learned


def test_conn_event_flag_helpers():
    syn = ConnEvent(ts=0, src_ip="a", dst_ip="b", dst_port=1, flags="S")
    assert syn.is_syn and not syn.is_synack
    sa = ConnEvent(ts=0, src_ip="a", dst_ip="b", dst_port=1, flags="SA")
    assert sa.is_synack and not sa.is_syn
    assert ConnEvent(ts=0, src_ip="a", dst_ip="b", dst_port=1, flags="R").is_rst


def test_new_alert_id_unique():
    assert new_alert_id() != new_alert_id()
