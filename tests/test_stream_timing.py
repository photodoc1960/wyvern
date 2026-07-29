"""Tests for the passive stream-timing corroboration detector.

Positive: a sustained HTTPS response stream with an LLM-token-like inter-packet
cadence emits a weak signal. Negative (false-positive guards): bulk transfer,
interactive traffic, idle keep-alives, and constant-bitrate media must stay
silent. Plus the correlator corroboration ("raise confidence when both fire").
"""

from __future__ import annotations

import dataclasses

from wyvern.config import Config
from wyvern.constants import STAGE_INFERENCE, STAGE_INFERENCE_TIMING
from wyvern.detectors.base import DetectorContext, NullProfiles
from wyvern.detectors.stream_timing import StreamTimingDetector
from wyvern.detectors.worm_signature import WormSignatureCorrelator
from wyvern.models.alert import Alert, Severity
from wyvern.models.events import ArpEvent
from wyvern.tracking.registry import DeviceRegistry

CLIENT = "192.168.1.30"
SERVER = "203.0.113.5"


def _run(det, mk, *, n, gaps_ms, size=200, base=1000.0, feed=None, sweep=None):
    ts = base
    events = []
    for i in range(n):
        events.append(mk.stream(CLIENT, SERVER, ts, size=size))
        ts += gaps_ms[i % len(gaps_ms)] / 1000.0
    assert feed(det, events) == []  # nothing fires on inspect
    return sweep(det, now=ts + 1.0)


def test_streaming_cadence_flags_low_confidence(config, feed, sweep, mk):
    det = StreamTimingDetector(config)
    # ~50ms mean gap with realistic jitter, many small segments -> weak signal.
    alerts = _run(det, mk, n=45, gaps_ms=[30, 50, 70, 40, 60], size=200, feed=feed, sweep=sweep)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.stage == STAGE_INFERENCE_TIMING
    assert a.severity is Severity.LOW
    assert a.confidence == config.thresholds.stream_timing_confidence
    assert a.src_ip == CLIENT and a.dst_ip == SERVER
    assert 8 <= a.evidence["mean_gap_ms"] <= 120


def test_bulk_transfer_not_flagged(config, feed, sweep, mk):
    # Back-to-back MTU-sized segments: sub-ms gaps and large payloads.
    det = StreamTimingDetector(config)
    assert (
        _run(det, mk, n=60, gaps_ms=[0.2, 0.3, 0.1, 0.25], size=1400, feed=feed, sweep=sweep) == []
    )


def test_interactive_traffic_not_flagged(config, feed, sweep, mk):
    # Human-paced request/response: multi-second, irregular gaps.
    det = StreamTimingDetector(config)
    assert _run(det, mk, n=45, gaps_ms=[1500, 2200, 800, 3000], feed=feed, sweep=sweep) == []


def test_idle_keepalive_not_flagged(config, feed, sweep, mk):
    # Sparse keep-alives never reach the sustained-stream segment count.
    det = StreamTimingDetector(config)
    assert _run(det, mk, n=10, gaps_ms=[15000], feed=feed, sweep=sweep) == []


def test_constant_bitrate_media_not_flagged(config, feed, sweep, mk):
    # Perfectly regular pacing (CoV ~0) is media, not autoregressive streaming.
    det = StreamTimingDetector(config)
    assert _run(det, mk, n=45, gaps_ms=[50], size=200, feed=feed, sweep=sweep) == []


def test_request_direction_ignored(config, feed, sweep, mk):
    # Client -> server (to_client=False) carries no token cadence.
    det = StreamTimingDetector(config)
    ts = 1000.0
    events = []
    for _ in range(45):
        events.append(mk.stream(CLIENT, SERVER, ts, size=200, to_client=False))
        ts += 0.05
    feed(det, events)
    assert sweep(det, now=ts + 1.0) == []


def test_gpu_client_not_flagged(mk):
    # Streaming LLM output to a declared GPU host is expected, not suspicious.
    cfg = dataclasses.replace(Config.default(), gpu_hosts=("192.168.1.60",))
    reg = DeviceRegistry(cfg)
    reg.observe(ArpEvent(ts=0.0, src_mac="aa:bb:cc:dd:ee:60", src_ip="192.168.1.60", op=2))
    det = StreamTimingDetector(cfg)
    ts = 1000.0
    for i in range(45):
        ev = mk.stream("192.168.1.60", SERVER, ts, size=200)
        ctx = DetectorContext(cfg, reg, NullProfiles(), now=ts)
        det.inspect(ev, ctx)
        ts += 0.05 if i % 2 else 0.06
    ctx = DetectorContext(cfg, reg, NullProfiles(), now=ts)
    assert det.sweep(ctx) == []


# --------------------------------------------------------------- corroboration


def _inference_alert(ts, conf=0.70):
    return Alert(
        detector="inference_api",
        title="inference",
        severity=Severity.from_confidence(conf),
        confidence=conf,
        description="d",
        src_ip=CLIENT,
        src_mac="00:80:77:aa:bb:cc",
        stage=STAGE_INFERENCE,
        ts=ts,
    )


def _timing_alert(ts):
    return Alert(
        detector="stream_timing",
        title="timing",
        severity=Severity.LOW,
        confidence=0.30,
        description="d",
        src_ip=CLIENT,
        src_mac="00:80:77:aa:bb:cc",
        stage=STAGE_INFERENCE_TIMING,
        ts=ts,
    )


def test_corroboration_raises_confidence_when_both_fire(config, registry):
    w = WormSignatureCorrelator(config)
    ctx = DetectorContext(config, registry, NullProfiles(), now=0.0)
    # inference_proxy first (no timing yet) -> no corroboration
    assert w.correlate([_inference_alert(1.0)], ctx, 1.0) == []
    out = w.correlate([_timing_alert(2.0)], ctx, 2.0)
    corrob = [a for a in out if a.detector == "stream_timing"]
    assert len(corrob) == 1
    a = corrob[0]
    assert a.stage == STAGE_INFERENCE
    assert a.confidence > 0.70  # boosted above the base inference confidence
    assert a.evidence["corroborating_signals"] == ["inference_api", "stream_timing"]


def test_timing_signal_alone_does_not_corroborate(config, registry):
    w = WormSignatureCorrelator(config)
    ctx = DetectorContext(config, registry, NullProfiles(), now=0.0)
    # Only the weak timing hint, no inference_proxy stage -> nothing, and it is
    # NOT counted as a worm stage.
    assert w.correlate([_timing_alert(1.0)], ctx, 1.0) == []
    assert w.active_stages("00:80:77:aa:bb:cc", 1.0) == []
