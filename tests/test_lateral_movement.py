"""Tests for the lateral-movement detector."""

from __future__ import annotations

from wyvern.constants import STAGE_LATERAL
from wyvern.detectors.lateral_movement import LateralMovementDetector


def test_fires_on_many_internal_peers(config, feed, mk):
    det = LateralMovementDetector(config)
    events = [mk.syn("192.168.1.50", f"192.168.1.{h}", 445, 1000.0 + h,
                     mac="00:14:22:00:00:50") for h in range(10, 24)]
    alerts = feed(det, events)
    assert len(alerts) == 1
    assert alerts[0].stage == STAGE_LATERAL
    assert alerts[0].evidence["distinct_internal_peers"] >= 10


def test_quiet_below_threshold(config, feed, mk):
    det = LateralMovementDetector(config)
    events = [mk.syn("192.168.1.50", f"192.168.1.{h}", 445, 1000.0 + h,
                     mac="00:14:22:00:00:50") for h in range(10, 18)]
    assert feed(det, events) == []


def test_external_destinations_excluded(config, feed, mk):
    det = LateralMovementDetector(config)
    events = [mk.syn("192.168.1.50", f"9.9.9.{h}", 445, 1000.0 + h,
                     mac="00:14:22:00:00:50") for h in range(10, 24)]
    assert feed(det, events) == []
