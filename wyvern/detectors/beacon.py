"""Beacon-callback detection — "beacon callbacks on non-standard ports" (§5).

A compromised host phones home on a regular cadence. We accumulate new-
connection timestamps per ``(source, destination, non-standard port)`` and, on a
periodic sweep, flag any pair whose inter-arrival gaps are *too regular* to be
human (low coefficient of variation) — the network signature of an automated
beacon. This is a sweep detector: periodicity only emerges over time.

The cutoff is graded over two bands rather than a single "metronomic or
nothing" test, because jitter is the cheapest possible evasion of a tight one
and needs no architectural change by the attacker:

* ``cov <= beacon_tight_cov`` (0.20) — near-constant cadence. The classic
  beacon signature; a standalone-strength alert, as before.
* ``cov <= beacon_max_cov`` (0.50) — jittered but still periodic, inside the
  empirical *autonomous-agent* dispersion band. Li (2026, "The Moltbook
  Illusion") separates autonomous (CoV < 0.5) from human-driven (CoV > 1.0)
  activity over 55,932 agents and notes agent-framework heartbeats are
  jittered rather than metronomic; Luo (2026, "Behavioral Grammar") measures
  CoV 0.31 for an agent actively mimicking benign cadence against 9.79 for
  benign activity. Moderately-jittered benign periodic traffic (update checks,
  vendor telemetry, keep-alives) also lives here, so this band emits a
  deliberately weak, LOW-severity signal: it contributes a ``beacon_callback``
  stage to the ``worm_signature`` correlator without carrying a verdict on its
  own.
"""

from __future__ import annotations

from ..constants import STAGE_BEACON
from ..indicators import is_nonstandard_port
from ..models.alert import Alert, Severity
from ..models.events import ConnEvent, NetworkEvent
from ..util.timewindow import (
    KeyedWindows,
    coefficient_of_variation,
    intervals,
)
from .base import Cooldown, Detector, DetectorContext, clamp01, source_id


class BeaconDetector(Detector):
    name = "beacon"

    def __init__(self, config) -> None:
        super().__init__(config)
        self._callbacks = KeyedWindows(self.t.beacon_window_s)
        self._cool = Cooldown(self.t.beacon_window_s)

    def inspect(self, event: NetworkEvent, ctx: DetectorContext) -> list[Alert]:
        if not isinstance(event, ConnEvent) or not event.is_syn:
            return []
        if not ctx.internal(event.src_ip):
            return []
        if not is_nonstandard_port(event.dst_port):
            return []
        key = (source_id(event), event.dst_ip, event.dst_port)
        self._callbacks.add(key, event.ts, event.ts)
        return []

    def sweep(self, ctx: DetectorContext) -> list[Alert]:
        now = ctx.now
        alerts: list[Alert] = []
        for key in self._callbacks.keys():
            stamps = self._callbacks.get(key).timestamps(now)
            if len(stamps) < self.t.beacon_min_callbacks:
                continue
            gaps = intervals(stamps)
            if not gaps:
                continue
            mean_gap = sum(gaps) / len(gaps)
            if mean_gap < self.t.beacon_min_interval_s:
                continue
            cov = coefficient_of_variation(gaps)
            if cov is None or cov > self.t.beacon_max_cov:
                continue
            if not self._cool.fire(key, now):
                continue
            alerts.append(self._make_alert(key, stamps, mean_gap, cov, ctx, now))
        self._callbacks.prune(now)
        return alerts

    def _confidence(self, cov: float) -> float:
        """Grade confidence over the two CoV bands (see module docstring)."""
        tight = self.t.beacon_tight_cov
        if cov <= tight:
            regularity = 1.0 - (cov / tight)
            return clamp01(0.60 + 0.30 * regularity)
        # Jittered band: decay linearly from the configured weak confidence at
        # the tight edge to half of it at the upper edge, where benign
        # dispersion starts to overlap.
        span = max(self.t.beacon_max_cov - tight, 1e-9)
        nearness = 1.0 - (cov - tight) / span
        return clamp01(self.t.beacon_jittered_confidence * (0.5 + 0.5 * nearness))

    def _make_alert(self, key, stamps, mean_gap, cov, ctx, now) -> Alert:
        sid, dst_ip, dst_port = key
        device = ctx.registry.get(sid) or ctx.registry.get_by_ip(sid)
        label = device.label if device else sid
        src_ip = device.ip if device else (sid if "." in str(sid) else None)
        jittered = cov > self.t.beacon_tight_cov
        confidence = self._confidence(cov)
        if jittered:
            cadence = (
                f"a jittered but periodic ~{int(mean_gap)}s interval (jitter {cov:.0%}) "
                "on a non-standard port — inside the inter-arrival dispersion band "
                "reported for autonomous agents, including ones mimicking benign "
                "cadence (Li 2026; Luo 2026). Benign jittered polling can look like "
                "this, so treat it as a weak corroborating signal, not a verdict."
            )
        else:
            cadence = (
                f"a near-constant ~{int(mean_gap)}s interval (jitter {cov:.0%}) on a "
                "non-standard port — automated beacon / C2 callback pattern."
            )
        return Alert(
            detector=self.name,
            title=(
                f"Jittered beacon callback every ~{int(mean_gap)}s to port {dst_port}"
                if jittered
                else f"Beacon callback every ~{int(mean_gap)}s to port {dst_port}"
            ),
            severity=Severity.from_confidence(confidence),
            confidence=confidence,
            stage=STAGE_BEACON,
            description=f"{label} contacted {dst_ip}:{dst_port} {len(stamps)} times at {cadence}",
            src_mac=device.mac if device else None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            ts=now,
            evidence={
                "callbacks": len(stamps),
                "mean_interval_s": round(mean_gap, 1),
                "jitter_cov": round(cov, 3),
                "cov_band": "jittered" if jittered else "metronomic",
                "dst_port": dst_port,
            },
        )
