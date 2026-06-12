"""Code-execution-on-idle-device detection — the worm's replication tell.

A printer, router, NAS, camera or ICS sensor is supposed to *answer* requests,
not *originate* connections. When such a normally-idle device starts initiating
outbound connections — especially to worm-targeted service ports — it strongly
suggests the worm has staged and launched code on it (Table 1: omikron printer,
sigma camera, aquila sensor, etc.).
"""

from __future__ import annotations

from ..constants import STAGE_REPLICATION
from ..indicators import is_worm_service_port, worm_service_label
from ..models.alert import Alert, Severity
from ..models.device import IDLE_ROLES
from ..models.events import ConnEvent, NetworkEvent
from ..util.timewindow import KeyedWindows
from .base import Cooldown, Detector, DetectorContext, clamp01


class IdleDeviceExecDetector(Detector):
    name = "idle_exec"

    def __init__(self, config) -> None:
        super().__init__(config)
        self._outbound = KeyedWindows(self.t.idle_window_s)
        self._cool = Cooldown(self.t.idle_window_s)

    def inspect(self, event: NetworkEvent, ctx: DetectorContext) -> list[Alert]:
        if not isinstance(event, ConnEvent) or not event.is_syn:
            return []
        if not ctx.internal(event.src_ip):
            return []
        device = ctx.device_for(event)
        if device is None or device.role not in IDLE_ROLES:
            return []

        win = self._outbound.add(device.mac, event.ts, (event.dst_ip, event.dst_port))
        targets = win.distinct(event.ts)
        if len(targets) < self.t.idle_outbound_conns:
            return []
        if not self._cool.fire(device.mac, event.ts):
            return []

        worm_ports = sorted({p for _, p in targets if is_worm_service_port(p)})
        confidence = clamp01(
            0.60
            + 0.20
            * min(
                1.0,
                (len(targets) - self.t.idle_outbound_conns) / max(1, self.t.idle_outbound_conns),
            )
        )
        if worm_ports:
            confidence = clamp01(confidence + 0.15)

        return [
            Alert(
                detector=self.name,
                title=f"Code execution on idle {device.role.value} ({len(targets)} outbound flows)",
                severity=Severity.from_confidence(confidence),
                confidence=confidence,
                stage=STAGE_REPLICATION,
                description=(
                    f"{device.label} is a {device.role.value} but initiated "
                    f"{len(targets)} outbound connections — a normally-idle device "
                    f"executing code, consistent with worm self-replication."
                    + (
                        f" Targeting worm services: "
                        f"{', '.join(worm_service_label(p) or str(p) for p in worm_ports[:6])}."
                        if worm_ports
                        else ""
                    )
                ),
                src_mac=device.mac,
                src_ip=event.src_ip,
                ts=event.ts,
                evidence={
                    "role": device.role.value,
                    "outbound_flows": len(targets),
                    "sample_targets": [f"{ip}:{p}" for ip, p in sorted(targets)[:20]],
                    "worm_service_ports": worm_ports,
                },
            )
        ]
