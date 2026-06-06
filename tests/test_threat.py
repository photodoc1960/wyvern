"""Tests for threat assessment and remediation."""

from __future__ import annotations

from wyvern.assessment.remediation import recommendations_for
from wyvern.assessment.threat import ThreatAssessor
from wyvern.config import Config
from wyvern.models.alert import Alert, Severity
from wyvern.tracking.registry import DeviceRegistry


def _alert(detector, stage, sev, conf, ts, src="192.168.1.30"):
    return Alert(detector=detector, title=detector, severity=sev, confidence=conf,
                 description="d", src_ip=src, src_mac="00:80:77:aa:bb:cc",
                 stage=stage, ts=ts)


def test_empty_is_low():
    a = ThreatAssessor(Config.default()).assess([], DeviceRegistry(Config.default()))
    assert a.overall_level is Severity.LOW
    assert a.likely_compromised is None


def test_worm_composite_is_critical():
    cfg = Config.default()
    reg = DeviceRegistry(cfg)
    alerts = [
        _alert("port_scan", "discovery", Severity.MEDIUM, 0.6, 1),
        _alert("lateral_movement", "lateral_movement", Severity.HIGH, 0.8, 2),
        _alert("worm_signature", "worm", Severity.CRITICAL, 0.9, 3),
    ]
    a = ThreatAssessor(cfg).assess(alerts, reg, now=3)
    assert a.overall_level is Severity.CRITICAL
    top = a.device_threats[0]
    assert top.is_worm_suspect and top.recommendations
    assert "discovery" in top.stages and "lateral_movement" in top.stages
    assert a.likely_compromised


def test_single_low_alert_stays_low():
    cfg = Config.default()
    alerts = [_alert("dns_anomaly", None, Severity.LOW, 0.3, 1)]
    a = ThreatAssessor(cfg).assess(alerts, DeviceRegistry(cfg), now=1)
    assert a.overall_level is Severity.LOW
    assert not a.device_threats[0].is_worm_suspect


def test_recommendations_reference_device():
    a = _alert("lateral_movement", "lateral_movement", Severity.HIGH, 0.8, 1)
    recs = recommendations_for(a)
    assert any("192.168.1.30" in r for r in recs)
    assert any("Isolate" in r for r in recs)
