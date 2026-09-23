"""Tests for the beacon-callback detector (sweep-based)."""

from __future__ import annotations

from wyvern.constants import STAGE_BEACON
from wyvern.detectors.beacon import BeaconDetector
from wyvern.models.alert import Severity


def test_regular_callbacks_detected(config, feed, sweep, mk):
    det = BeaconDetector(config)
    base = 1000.0
    events = [
        mk.syn(
            "192.168.1.50",
            "203.0.113.5",
            4444,
            base + i * 60,
            mac="00:14:22:00:00:50",
            sport=50000 + i,
        )
        for i in range(8)
    ]
    assert feed(det, events) == []  # nothing on inspect
    alerts = sweep(det, now=base + 8 * 60)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.stage == STAGE_BEACON and a.dst_port == 4444
    assert a.evidence["jitter_cov"] <= 0.2 and a.evidence["callbacks"] >= 6


def test_irregular_traffic_not_beacon(config, feed, sweep, mk):
    det = BeaconDetector(config)
    base = 1000.0
    gaps = [0, 5, 70, 75, 300, 305, 900]  # bursty, high jitter
    events = [
        mk.syn(
            "192.168.1.50", "203.0.113.5", 4444, base + g, mac="00:14:22:00:00:50", sport=50000 + i
        )
        for i, g in enumerate(gaps)
    ]
    feed(det, events)
    assert sweep(det, now=base + 1000) == []


def test_jittered_beacon_is_weak_signal(config, feed, sweep, mk):
    """±30% jitter — the cheapest evasion of a 0.20 CoV cutoff — is still caught,
    but only as a LOW corroborating signal (Li 2026; Luo 2026)."""
    det = BeaconDetector(config)
    base = 1000.0
    gaps = [42, 78, 45, 75, 60, 80, 40]  # mean 60s, CoV ~0.27
    stamps = [base]
    for g in gaps:
        stamps.append(stamps[-1] + g)
    events = [
        mk.syn("192.168.1.50", "203.0.113.5", 4444, ts, mac="00:14:22:00:00:50", sport=50000 + i)
        for i, ts in enumerate(stamps)
    ]
    feed(det, events)
    alerts = sweep(det, now=stamps[-1] + 1)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.stage == STAGE_BEACON
    assert config.thresholds.beacon_tight_cov < a.evidence["jitter_cov"] <= 0.50
    assert a.evidence["cov_band"] == "jittered"
    # Weak on its own: it contributes a worm stage, never a standalone verdict.
    assert a.severity is Severity.LOW
    assert a.confidence < config.thresholds.beacon_jittered_confidence


def test_standard_port_excluded(config, feed, sweep, mk):
    det = BeaconDetector(config)
    base = 1000.0
    events = [
        mk.syn(
            "192.168.1.50",
            "203.0.113.5",
            443,
            base + i * 60,
            mac="00:14:22:00:00:50",
            sport=50000 + i,
        )
        for i in range(8)
    ]
    feed(det, events)
    assert sweep(det, now=base + 8 * 60) == []
