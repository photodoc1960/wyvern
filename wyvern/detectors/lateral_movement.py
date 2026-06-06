"""Lateral-movement detection.

Per the brief: a **single device contacting >10 other internal IPs in 1 hour**
is the worm spreading sideways. Idle-role devices (a printer reaching out to ten
hosts) are weighted up; routers — which legitimately talk to everyone — down.
"""

from __future__ import annotations

from ..constants import STAGE_LATERAL
from ..indicators import is_worm_service_port, worm_service_label
from ..models.alert import Alert, Severity
from ..models.device import DeviceRole
from ..models.events import ConnEvent, NetworkEvent
from ..util.timewindow import KeyedWindows
from .base import Cooldown, Detector, DetectorContext, clamp01, source_id


class LateralMovementDetector(Detector):
    name = "lateral_movement"

    def __init__(self, config) -> None:
        super().__init__(config)
        self._peers = KeyedWindows(self.t.lateral_window_s)
        self._services = KeyedWindows(self.t.lateral_window_s)
        self._cool = Cooldown(self.t.lateral_window_s / 4.0)

    def inspect(self, event: NetworkEvent, ctx: DetectorContext) -> list[Alert]:
        if not isinstance(event, ConnEvent) or not event.is_syn:
            return []
        if not ctx.internal(event.src_ip) or not ctx.internal(event.dst_ip):
            return []
        if event.src_ip == event.dst_ip:
            return []
        sid = source_id(event)
        if sid is None:
            return []

        win = self._peers.add(sid, event.ts, event.dst_ip)
        if is_worm_service_port(event.dst_port):
            self._services.add(sid, event.ts, event.dst_port)
        peers = win.distinct(event.ts)
        if len(peers) < self.t.lateral_peers:
            return []
        if not self._cool.fire(sid, event.ts):
            return []

        device = ctx.device_for(event)
        label = device.label if device else event.src_ip
        role = device.role if device else DeviceRole.UNKNOWN

        confidence = clamp01(
            0.55 + 0.25 * min(1.0, (len(peers) - self.t.lateral_peers) / self.t.lateral_peers)
        )
        if role in (DeviceRole.PRINTER, DeviceRole.CAMERA, DeviceRole.NAS, DeviceRole.IOT):
            confidence = clamp01(confidence + 0.20)   # idle device fanning out
        elif role is DeviceRole.ROUTER:
            confidence = clamp01(confidence - 0.25)    # routers legitimately fan out
        svc_ports = sorted(self._services.get(sid).distinct(event.ts))
        if svc_ports:
            confidence = clamp01(confidence + 0.10)

        return [
            Alert(
                detector=self.name,
                title=f"Lateral movement — {len(peers)} internal hosts in "
                f"{int(self.t.lateral_window_s // 60)}m",
                severity=Severity.from_confidence(confidence),
                confidence=confidence,
                stage=STAGE_LATERAL,
                description=(
                    f"{label} ({role.value}) initiated connections to {len(peers)} "
                    f"distinct internal hosts — consistent with worm propagation."
                    + (
                        f" Targeted worm services: "
                        f"{', '.join(worm_service_label(p) or str(p) for p in svc_ports[:6])}."
                        if svc_ports
                        else ""
                    )
                ),
                src_mac=device.mac if device else event.src_mac,
                src_ip=event.src_ip,
                ts=event.ts,
                evidence={
                    "distinct_internal_peers": len(peers),
                    "sample_peers": sorted(peers)[:30],
                    "worm_service_ports": svc_ports,
                    "window_seconds": self.t.lateral_window_s,
                },
            )
        ]
