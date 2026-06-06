"""Outbound port-scan detection — the worm's host/network *discovery* phase.

Per the brief: a device probing **>50 distinct ports in 5 minutes** is doing
worm-style reconnaissance. We count distinct destination ports a single source
opens SYNs to within the window.
"""

from __future__ import annotations

from ..constants import STAGE_RECON
from ..indicators import is_worm_service_port, worm_service_label
from ..models.alert import Alert, Severity
from ..models.events import ConnEvent, NetworkEvent
from ..util.timewindow import KeyedWindows
from .base import Cooldown, Detector, DetectorContext, clamp01, source_id


class PortScanDetector(Detector):
    name = "port_scan"

    def __init__(self, config) -> None:
        super().__init__(config)
        self._ports = KeyedWindows(self.t.scan_window_s)
        self._cool = Cooldown(self.t.scan_window_s)

    def inspect(self, event: NetworkEvent, ctx: DetectorContext) -> list[Alert]:
        if not isinstance(event, ConnEvent) or not event.is_syn:
            return []
        if not ctx.internal(event.src_ip):
            return []
        sid = source_id(event)
        if sid is None:
            return []

        win = self._ports.add(sid, event.ts, event.dst_port)
        distinct = win.distinct_count(event.ts)
        if distinct < self.t.scan_ports:
            return []
        if not self._cool.fire(sid, event.ts):
            return []

        ports = sorted(win.distinct(event.ts))
        worm_ports = [p for p in ports if is_worm_service_port(p)]
        device = ctx.device_for(event)
        label = device.label if device else event.src_ip

        confidence = clamp01(
            0.55 + 0.30 * min(1.0, (distinct - self.t.scan_ports) / self.t.scan_ports)
        )
        profile = ctx.profiles.get(device.mac) if device else None
        if profile and profile.learned and distinct > 3 * max(1, profile.max_ports_5m):
            confidence = clamp01(confidence + 0.10)

        return [
            Alert(
                detector=self.name,
                title=f"Outbound port scan — {distinct} ports in "
                f"{int(self.t.scan_window_s // 60)}m",
                severity=Severity.from_confidence(confidence),
                confidence=confidence,
                stage=STAGE_RECON,
                description=(
                    f"{label} opened SYNs to {distinct} distinct ports within the "
                    f"window — worm-style host/network reconnaissance."
                    + (
                        f" Includes worm-targeted services: "
                        f"{', '.join(worm_service_label(p) or str(p) for p in worm_ports[:6])}."
                        if worm_ports
                        else ""
                    )
                ),
                src_mac=device.mac if device else event.src_mac,
                src_ip=event.src_ip,
                ts=event.ts,
                evidence={
                    "distinct_ports": distinct,
                    "sample_ports": ports[:40],
                    "worm_service_ports": worm_ports[:20],
                    "window_seconds": self.t.scan_window_s,
                },
            )
        ]
