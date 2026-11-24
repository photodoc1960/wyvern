"""Tests for threat assessment and remediation."""

from __future__ import annotations

from wyvern.assessment.remediation import recommendations_for
from wyvern.assessment.threat import ThreatAssessor
from wyvern.config import Config
from wyvern.models.alert import Alert, Severity
from wyvern.tracking.registry import DeviceRegistry


def _alert(detector, stage, sev, conf, ts, src="192.168.1.30"):
    return Alert(
        detector=detector,
        title=detector,
        severity=sev,
        confidence=conf,
        description="d",
        src_ip=src,
        src_mac="00:80:77:aa:bb:cc",
        stage=stage,
        ts=ts,
    )


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


def _top(alerts, now):
    cfg = Config.default()
    return ThreatAssessor(cfg).assess(alerts, DeviceRegistry(cfg), now=now).device_threats[0]


def test_many_repeats_of_one_low_signal_stay_low():
    alerts = [_alert("dns_anomaly", None, Severity.LOW, 0.3, i) for i in range(300)]
    top = _top(alerts, now=300)
    assert top.level is Severity.LOW
    assert top.score < 30
    assert top.alert_count == 300


def test_repeats_of_one_high_signal_stay_high():
    alerts = [_alert("dns_anomaly", None, Severity.HIGH, 0.7, i) for i in range(200)]
    top = _top(alerts, now=200)
    assert top.level is Severity.HIGH


def test_chatty_workstation_is_high_not_critical():
    # The live case that motivated per-signal scoring: one HIGH DNS spike, two
    # MEDIUM DNS alerts and seven LOW stream_timing hints, zero worm stages.
    # Counting every alert scored 98 (Critical); it is one strong signal plus one
    # weak one, so High via the max-severity floor.
    alerts = [_alert("dns_anomaly", None, Severity.HIGH, 0.7, 1)]
    alerts += [_alert("dns_anomaly", None, Severity.MEDIUM, 0.5, 2 + i) for i in range(2)]
    alerts += [
        _alert("stream_timing", "inference_timing", Severity.LOW, 0.3, 4 + i) for i in range(7)
    ]
    top = _top(alerts, now=11)
    assert top.level is Severity.HIGH
    assert top.score < 80
    assert not top.is_worm_suspect


def test_distinct_worm_stages_still_escalate():
    two = [
        _alert("port_scan", "discovery", Severity.MEDIUM, 0.6, 1),
        _alert("lateral_movement", "lateral_movement", Severity.HIGH, 0.8, 2),
    ]
    assert _top(two, now=2).level is Severity.HIGH
    three = [*two, _alert("credential_spray", "credential_reuse", Severity.HIGH, 0.8, 3)]
    top = _top(three, now=3)
    assert top.level is Severity.CRITICAL
    assert top.is_worm_suspect


def test_composite_with_repeated_stage_alerts_is_critical():
    alerts = [_alert("port_scan", "discovery", Severity.MEDIUM, 0.6, i) for i in range(20)]
    alerts += [_alert("lateral_movement", "lateral_movement", Severity.HIGH, 0.8, 21)]
    alerts += [_alert("worm_signature", "worm", Severity.HIGH, 0.8, 22)]
    top = _top(alerts, now=22)
    assert top.level is Severity.CRITICAL
    assert top.is_worm_suspect


def test_recommendations_reference_device():
    a = _alert("lateral_movement", "lateral_movement", Severity.HIGH, 0.8, 1)
    recs = recommendations_for(a)
    assert any("192.168.1.30" in r for r in recs)
    assert any("Isolate" in r for r in recs)
