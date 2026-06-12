"""Tests for the composite worm-signature correlator."""

from __future__ import annotations

import dataclasses

from wyvern.config import Config
from wyvern.constants import (
    STAGE_BEACON,
    STAGE_CREDENTIAL,
    STAGE_LATERAL,
    STAGE_RECON,
)
from wyvern.detectors.base import DetectorContext, NullProfiles
from wyvern.detectors.worm_signature import WormSignatureCorrelator
from wyvern.models.alert import Alert, Severity
from wyvern.models.events import ArpEvent


def _alert(stage, ts, conf=0.7):
    return Alert(
        detector="x",
        title="t",
        severity=Severity.from_confidence(conf),
        confidence=conf,
        description="d",
        src_ip="192.168.1.30",
        src_mac="00:80:77:aa:bb:cc",
        stage=stage,
        ts=ts,
    )


def _ctx(cfg, registry):
    return DetectorContext(cfg, registry, NullProfiles(), now=0.0)


def test_escalates_high_then_critical(config, registry):
    registry.observe(ArpEvent(ts=0, src_mac="00:80:77:aa:bb:cc", src_ip="192.168.1.30", op=2))
    w = WormSignatureCorrelator(config)
    ctx = _ctx(config, registry)
    assert w.correlate([_alert(STAGE_RECON, 1)], ctx, 1) == []
    high = w.correlate([_alert(STAGE_LATERAL, 2)], ctx, 2)
    assert high and high[0].severity is Severity.HIGH
    crit = w.correlate([_alert(STAGE_CREDENTIAL, 3)], ctx, 3)
    assert crit and crit[0].severity is Severity.CRITICAL
    assert crit[0].evidence["stage_count"] == 3
    assert crit[0].evidence["likely_compromised"] == "192.168.1.30"


def test_duplicate_stage_not_double_counted(config, registry):
    w = WormSignatureCorrelator(config)
    ctx = _ctx(config, registry)
    w.correlate([_alert(STAGE_RECON, 1)], ctx, 1)
    out = w.correlate([_alert(STAGE_RECON, 2)], ctx, 2)
    assert out == []  # still only one distinct stage


def test_stage_pruning_resets(registry):
    cfg = dataclasses.replace(
        Config.default(),
        thresholds=dataclasses.replace(Config.default().thresholds, worm_window_s=100),
    )
    w = WormSignatureCorrelator(cfg)
    ctx = _ctx(cfg, registry)
    w.correlate([_alert(STAGE_RECON, 1)], ctx, 1)
    assert w.correlate([_alert(STAGE_LATERAL, 2)], ctx, 2)  # 2 stages -> HIGH
    # long after the window, only the fresh stage remains in scope
    assert w.active_stages("00:80:77:aa:bb:cc", 500) == []
    assert w.correlate([_alert(STAGE_BEACON, 500)], ctx, 500) == []
