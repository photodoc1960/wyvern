"""Tests for the beacon-callback detector (sweep-based)."""

from __future__ import annotations

from wyvern.constants import STAGE_BEACON, STAGE_BEACON_JITTERED, WORM_STAGES
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
    assert a.stage == STAGE_BEACON_JITTERED
    assert a.stage not in WORM_STAGES  # must not supply a worm stage (#35 follow-up)
    assert config.thresholds.beacon_tight_cov < a.evidence["jitter_cov"] <= 0.50
    assert a.evidence["cov_band"] == "jittered"
    # Weak on its own: low severity AND kept out of the worm stages.
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


def test_jittered_beacon_cannot_supply_a_worm_stage(config, registry, mk):
    """A jittered callback must not feed the worm correlator (#35 follow-up).

    The graded confidence the jittered band produces (~0.18) is *discarded* by the
    correlator, which floors a 2-stage verdict at 0.75
    (``worm_signature.py``: ``max(0.90 if critical else 0.75, ...)``). So grading
    confidence alone does not make the signal "weak" — only keeping it out of
    ``WORM_STAGES`` does. Benign jittered polling (update checks, telemetry,
    keep-alives) lives in the 0.20-0.50 band, so letting it count as a stage would
    let ordinary traffic supply half of a HIGH "AI worm" verdict.
    """
    from wyvern.constants import STAGE_RECON
    from wyvern.detectors.base import DetectorContext, NullProfiles
    from wyvern.detectors.loader import make_correlator
    from wyvern.models.alert import Alert, Severity

    ctx = DetectorContext(config, registry, NullProfiles(), now=2000.0)
    corr = make_correlator(config)

    def alert(stage, conf):
        return Alert(
            detector="x",
            title="t",
            severity=Severity.from_confidence(conf),
            confidence=conf,
            description="d",
            src_mac="00:11:22:33:44:99",
            src_ip="192.168.7.99",
            stage=stage,
            ts=2000.0,
        )

    # discovery + a *jittered* beacon => must NOT reach a worm verdict
    out = corr.correlate([alert(STAGE_RECON, 0.7), alert(STAGE_BEACON_JITTERED, 0.18)], ctx, 2000.0)
    assert out == [], "a jittered beacon must not count toward the worm verdict"

    # control: discovery + a *metronomic* beacon => still does
    corr2 = make_correlator(config)
    out2 = corr2.correlate([alert(STAGE_RECON, 0.7), alert(STAGE_BEACON, 0.8)], ctx, 2000.0)
    assert len(out2) == 1 and out2[0].stage == "worm"
