"""Beacon-callback detection — "beacon callbacks on non-standard ports" (§5).

A compromised host phones home on a regular cadence. We accumulate new-
connection timestamps per ``(source, destination, non-standard port)`` and, on a
periodic sweep, flag any pair whose inter-arrival gaps are *too regular* to be
human (low coefficient of variation) — the network signature of an automated
beacon. This is a sweep detector: periodicity only emerges over time.
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

    def _make_alert(self, key, stamps, mean_gap, cov, ctx, now) -> Alert:
        sid, dst_ip, dst_port = key
        device = ctx.registry.get(sid) or ctx.registry.get_by_ip(sid)
        label = device.label if device else sid
        src_ip = device.ip if device else (sid if "." in str(sid) else None)
        regularity = 1.0 - (cov / self.t.beacon_max_cov)
        confidence = clamp01(0.60 + 0.30 * regularity)
        return Alert(
            detector=self.name,
            title=f"Beacon callback every ~{int(mean_gap)}s to port {dst_port}",
            severity=Severity.from_confidence(confidence),
            confidence=confidence,
            stage=STAGE_BEACON,
            description=(
                f"{label} contacted {dst_ip}:{dst_port} {len(stamps)} times at a "
                f"near-constant ~{int(mean_gap)}s interval (jitter {cov:.0%}) on a "
                f"non-standard port — automated beacon / C2 callback pattern."
            ),
            src_mac=device.mac if device else None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            ts=now,
            evidence={
                "callbacks": len(stamps),
                "mean_interval_s": round(mean_gap, 1),
                "jitter_cov": round(cov, 3),
                "dst_port": dst_port,
            },
        )
