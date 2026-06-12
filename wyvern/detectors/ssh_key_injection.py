"""SSH key / credential propagation detection — "automated injection of SSH
public keys" (§5).

SSH traffic is encrypted, so we can't read the injected key. But the *pattern*
is observable: a device opening SSH (port 22) to several internal hosts in a
short window — particularly one that is a normally-idle device or that never
used SSH during baseline — matches the worm seeding keys / reusing credentials
to spread across Linux hosts (Table 1: many "credential reuse" / "SSH reuse
target" rows).
"""

from __future__ import annotations

from ..constants import STAGE_SSH_KEY
from ..models.alert import Alert, Severity
from ..models.device import IDLE_ROLES
from ..models.events import ConnEvent, NetworkEvent
from ..util.timewindow import KeyedWindows
from .base import Cooldown, Detector, DetectorContext, clamp01, source_id

SSH_PORT = 22
_FANOUT_FLOOR = 3  # SSH to >=3 internal hosts is the minimum propagation shape


class SshKeyInjectionDetector(Detector):
    name = "ssh_key_injection"

    def __init__(self, config) -> None:
        super().__init__(config)
        self._ssh = KeyedWindows(self.t.cred_window_s)
        self._cool = Cooldown(self.t.cred_window_s)

    def inspect(self, event: NetworkEvent, ctx: DetectorContext) -> list[Alert]:
        if not isinstance(event, ConnEvent) or not event.is_syn:
            return []
        if event.dst_port != SSH_PORT:
            return []
        if not ctx.internal(event.src_ip) or not ctx.internal(event.dst_ip):
            return []
        sid = source_id(event)
        if sid is None:
            return []

        win = self._ssh.add(sid, event.ts, event.dst_ip)
        hosts = win.distinct(event.ts)
        if len(hosts) < _FANOUT_FLOOR:
            return []

        device = ctx.device_for(event)
        profile = ctx.profiles.get(device.mac) if device else None
        idle = bool(device and device.role in IDLE_ROLES)
        never_ssh = bool(profile and profile.learned and SSH_PORT not in profile.known_ports)
        many = len(hosts) >= self.t.cred_distinct_hosts

        # Only fire when the SSH fan-out is genuinely anomalous, not for an admin
        # box that routinely SSHes around.
        if not (idle or never_ssh or many):
            return []
        if not self._cool.fire(sid, event.ts):
            return []

        confidence = 0.50
        if idle:
            confidence = max(confidence, 0.82)
        if never_ssh:
            confidence = max(confidence, 0.66)
        confidence = clamp01(confidence + 0.05 * (len(hosts) - _FANOUT_FLOOR))

        label = device.label if device else event.src_ip
        return [
            Alert(
                detector=self.name,
                title=f"SSH key/credential propagation — {len(hosts)} hosts",
                severity=Severity.from_confidence(confidence),
                confidence=confidence,
                stage=STAGE_SSH_KEY,
                description=(
                    f"{label} opened SSH to {len(hosts)} distinct internal hosts in a "
                    f"short window — consistent with automated SSH-key injection / "
                    f"credential reuse used by the worm to spread across Linux hosts."
                ),
                src_mac=device.mac if device else event.src_mac,
                src_ip=event.src_ip,
                dst_port=SSH_PORT,
                ts=event.ts,
                evidence={
                    "ssh_targets": sorted(hosts)[:30],
                    "distinct_hosts": len(hosts),
                    "idle_device": idle,
                    "never_ssh_in_baseline": never_ssh,
                },
            )
        ]
