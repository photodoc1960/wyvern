"""Tests for the inference-proxy detector."""

from __future__ import annotations

from wyvern.constants import STAGE_INFERENCE
from wyvern.detectors.inference_api import InferenceApiDetector


def test_idle_device_inference_is_critical(config, feed, mk):
    det = InferenceApiDetector(config)
    events = [
        mk.arp("00:80:77:aa:bb:cc", "192.168.1.30", 1.0),  # printer
        mk.infer("192.168.1.30", "192.168.1.99", 2.0, mac="00:80:77:aa:bb:cc"),
    ]
    alerts = feed(det, events)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.stage == STAGE_INFERENCE and a.confidence >= 0.85
    assert a.evidence["client_role"] == "printer"
    assert a.evidence["client_gpu_capable"] is False


def test_gpu_workstation_not_flagged(config, feed, mk):
    det = InferenceApiDetector(config)
    # Dell workstation (gpu-capable role) making a single inference call -> quiet
    events = [
        mk.syn("192.168.1.50", "192.168.1.99", 443, 1.0, mac="00:14:22:00:00:50", ttl=128),
        mk.infer("192.168.1.50", "192.168.1.99", 2.0, mac="00:14:22:00:00:50"),
    ]
    assert feed(det, events) == []


def test_non_inference_http_ignored(config, feed, mk):
    det = InferenceApiDetector(config)
    events = [
        mk.http(
            "192.168.1.30",
            "192.168.1.99",
            80,
            1.0,
            path="/index.html",
            host="site",
            mac="00:80:77:aa:bb:cc",
        )
    ]
    assert feed(det, events) == []
