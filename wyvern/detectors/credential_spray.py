"""Credential spray / reuse detection.

Two patterns from the brief and the paper (§5, "systematic credential reuse
across hosts"):

* **Reuse across hosts** — one source hitting an authentication service
  (SSH/SMB/RDP/WinRM/...) on many distinct internal hosts in a short window.
* **Repeated attempts on one host** — rapid reconnections to a single auth
  service, the network shadow of failed-login / brute-force attempts.
"""

from __future__ import annotations

from ..constants import STAGE_CREDENTIAL
from ..indicators import auth_service, is_auth_port
from ..models.alert import Alert, Severity
from ..models.events import ConnEvent, NetworkEvent
from ..util.timewindow import KeyedWindows
from .base import Cooldown, Detector, DetectorContext, clamp01, source_id


class CredentialSprayDetector(Detector):
    name = "credential_spray"

    def __init__(self, config) -> None:
        super().__init__(config)
        self._hosts = KeyedWindows(self.t.cred_window_s)
        self._reconnects = KeyedWindows(self.t.cred_window_s)
        self._spray_cool = Cooldown(self.t.cred_window_s)
        self._fail_cool = Cooldown(self.t.cred_window_s)

    def inspect(self, event: NetworkEvent, ctx: DetectorContext) -> list[Alert]:
        if not isinstance(event, ConnEvent) or not event.is_syn:
            return []
        if not is_auth_port(event.dst_port) or not ctx.internal(event.src_ip):
            return []
        sid = source_id(event)
        if sid is None:
            return []

        alerts: list[Alert] = []
        device = ctx.device_for(event)
        label = device.label if device else event.src_ip
        service = auth_service(event.dst_port) or "auth"

        # --- reuse across hosts ---
        hwin = self._hosts.add(sid, event.ts, event.dst_ip)
        hosts = hwin.distinct(event.ts)
        if len(hosts) >= self.t.cred_distinct_hosts and self._spray_cool.fire(sid, event.ts):
            confidence = clamp01(
                0.55 + 0.30 * min(1.0, (len(hosts) - self.t.cred_distinct_hosts) / self.t.cred_distinct_hosts)
            )
            alerts.append(
                Alert(
                    detector=self.name,
                    title=f"Credential reuse across {len(hosts)} hosts ({service})",
                    severity=Severity.from_confidence(confidence),
                    confidence=confidence,
                    stage=STAGE_CREDENTIAL,
                    description=f"{label} authenticated to {service.upper()} on "
                    f"{len(hosts)} distinct internal hosts — systematic credential "
                    f"reuse, a hallmark of the worm's swarm propagation.",
                    src_mac=device.mac if device else event.src_mac,
                    src_ip=event.src_ip,
                    dst_port=event.dst_port,
                    ts=event.ts,
                    evidence={
                        "service": service,
                        "distinct_hosts": len(hosts),
                        "sample_hosts": sorted(hosts)[:30],
                    },
                )
            )

        # --- repeated attempts on one host (failed-auth shadow) ---
        rkey = (sid, event.dst_ip, event.dst_port)
        rwin = self._reconnects.add(rkey, event.ts, event.ts)
        if rwin.count(event.ts) >= self.t.cred_fail_reconnects and self._fail_cool.fire(rkey, event.ts):
            tries = rwin.count(event.ts)
            confidence = clamp01(
                0.40 + 0.30 * min(1.0, (tries - self.t.cred_fail_reconnects) / self.t.cred_fail_reconnects)
            )
            target = ctx.registry.get_by_ip(event.dst_ip)
            target_label = target.label if target else event.dst_ip
            alerts.append(
                Alert(
                    detector=self.name,
                    title=f"Repeated {service.upper()} auth attempts ({tries})",
                    severity=Severity.from_confidence(confidence),
                    confidence=confidence,
                    stage=STAGE_CREDENTIAL,
                    description=f"{label} made {tries} rapid {service.upper()} "
                    f"connections to {target_label} — possible failed-auth / "
                    f"brute-force or credential-spray attempt.",
                    src_mac=device.mac if device else event.src_mac,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    dst_port=event.dst_port,
                    ts=event.ts,
                    evidence={"service": service, "attempts": tries, "target": event.dst_ip},
                )
            )
        return alerts
