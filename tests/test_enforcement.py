"""Tests for the detection->enforcement bridge (issue #22, Piece 2).

The bridge is the *only* path by which Wyvern can trigger action in the outside
world, so its safety rails are the point of these tests: off by default,
high-confidence only, authenticated (HMAC), and fail-safe (a broken actuator
must never crash the monitor). Wyvern still never blocks packets itself — it
POSTs a signed finding to an external actuator that decides what to do.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from wyvern.alerting.enforcement import EnforcementBridge, build_bridge
from wyvern.config import ConfigError, EnforceConfig
from wyvern.models.alert import Alert, Severity


class FakeSender:
    """Records POSTs; optionally returns a status or raises (actuator down)."""

    def __init__(self, status: int = 200, raises: bool = False) -> None:
        self.calls: list[tuple[str, bytes, dict, float]] = []
        self.status = status
        self.raises = raises

    def __call__(self, url: str, body: bytes, headers: dict, timeout: float) -> int:
        self.calls.append((url, body, headers, timeout))
        if self.raises:
            raise OSError("actuator unreachable")
        return self.status


def _alert(severity: Severity = Severity.CRITICAL) -> Alert:
    return Alert(
        detector="zero_egress",
        title="Unexpected egress from isolated host",
        severity=severity,
        confidence=0.9,
        description="isolated host reached the internet",
        src_ip="192.168.1.77",
        dst_ip="198.51.100.9",
        dst_port=443,
        stage="unexpected_egress",
        ts=1000.0,
    )


def _cfg(**kw) -> EnforceConfig:
    base = {"enabled": True, "webhook_url": "https://actuator.example/hook", "min_severity": 4}
    base.update(kw)
    return EnforceConfig(**base)


def test_disabled_by_default_does_not_send():
    sender = FakeSender()
    bridge = EnforcementBridge(EnforceConfig(), sender=sender)  # defaults: disabled
    assert bridge.dispatch(_alert()) is False
    assert sender.calls == []


def test_critical_alert_is_posted():
    sender = FakeSender()
    bridge = EnforcementBridge(_cfg(), sender=sender)
    assert bridge.dispatch(_alert()) is True
    assert len(sender.calls) == 1
    url, body, headers, _timeout = sender.calls[0]
    assert url == "https://actuator.example/hook"
    payload = json.loads(body)
    assert payload["stage"] == "unexpected_egress" and payload["dst_ip"] == "198.51.100.9"
    assert headers["Content-Type"] == "application/json"


def test_below_min_severity_not_sent():
    sender = FakeSender()
    bridge = EnforcementBridge(_cfg(min_severity=4), sender=sender)
    assert bridge.dispatch(_alert(Severity.HIGH)) is False  # HIGH(3) < CRITICAL(4)
    assert sender.calls == []


def test_configurable_threshold_allows_high():
    sender = FakeSender()
    bridge = EnforcementBridge(_cfg(min_severity=3), sender=sender)
    assert bridge.dispatch(_alert(Severity.HIGH)) is True


def test_hmac_signature_present_and_correct():
    sender = FakeSender()
    secret = "s3cret"
    bridge = EnforcementBridge(_cfg(signing_secret=secret), sender=sender)
    bridge.dispatch(_alert())
    _url, body, headers, _timeout = sender.calls[0]
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert headers["X-Wyvern-Signature"] == expected


def test_no_signature_header_without_secret():
    sender = FakeSender()
    bridge = EnforcementBridge(_cfg(), sender=sender)  # no signing_secret
    bridge.dispatch(_alert())
    _url, _body, headers, _timeout = sender.calls[0]
    assert "X-Wyvern-Signature" not in headers


def test_actuator_failure_is_fail_safe():
    sender = FakeSender(raises=True)
    bridge = EnforcementBridge(_cfg(), sender=sender)
    # must not raise; returns False
    assert bridge.dispatch(_alert()) is False


def test_non_2xx_status_is_not_success():
    sender = FakeSender(status=500)
    bridge = EnforcementBridge(_cfg(), sender=sender)
    assert bridge.dispatch(_alert()) is False
    assert len(sender.calls) == 1  # it did attempt


def test_build_bridge_returns_none_when_disabled():
    assert build_bridge(EnforceConfig()) is None


def test_build_bridge_returns_instance_when_enabled():
    assert isinstance(build_bridge(_cfg()), EnforcementBridge)


def test_config_enabled_requires_url():
    with pytest.raises(ConfigError):
        EnforceConfig(enabled=True, webhook_url=None).validate()


def test_config_rejects_non_http_scheme():
    with pytest.raises(ConfigError):
        EnforceConfig(enabled=True, webhook_url="ftp://actuator/hook").validate()
