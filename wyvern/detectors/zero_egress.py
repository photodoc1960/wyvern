"""Zero-egress detection — an isolated host reaching an external network.

A host declared in ``config.no_egress_hosts`` (an isolated / quarantined /
air-gapped segment) is expected to have **no** external egress at all. Its
*first* outbound connection to a novel external destination is therefore a
high-confidence tripwire: at the network layer this is the signal of a
containment escape (issue #22, motivated by the 2026-07 autonomous
sandbox-escape incident).

This is an ``inspect`` detector — the violation is a single event, not a
pattern that emerges over time. It deliberately does **not** gate on
``is_syn``, so UDP/QUIC egress is caught too. "Egress" means a usable unicast
destination outside the internal CIDRs; internal and multicast/broadcast
traffic is ignored. Repeats to the same destination are debounced so a
persistent violation alerts once per window, not per packet.

The detector is inert unless ``no_egress_hosts`` is set, so it is off by
default. Like every Wyvern detector it is passive: it raises a signal; it never
blocks (the enforcement bridge is the second, optional half of issue #22).
"""

from __future__ import annotations

from ..constants import STAGE_EGRESS
from ..models.alert import Alert, Severity
from ..models.events import ConnEvent, NetworkEvent
from ..util.nets import is_usable_host_ip
from .base import Cooldown, Detector, DetectorContext, source_id


class ZeroEgressDetector(Detector):
    name = "zero_egress"

    def __init__(self, config) -> None:
        super().__init__(config)
        # Debounce per (source, external destination): a novel destination alerts
        # once, then is suppressed until the window re-arms it.
        self._seen = Cooldown(self.t.no_egress_window_s)

    def inspect(self, event: NetworkEvent, ctx: DetectorContext) -> list[Alert]:
        if not isinstance(event, ConnEvent):
            return []
        if not self.config.is_no_egress_host(event.src_ip, event.src_mac):
            return []
        dst = event.dst_ip
        # Egress == a routable unicast destination outside our internal CIDRs.
        # Excludes internal traffic (lateral_movement's concern) and
        # multicast/broadcast (mDNS/SSDP are not egress).
        if not is_usable_host_ip(dst) or ctx.internal(dst):
            return []
        if not self._seen.fire((source_id(event), dst), event.ts):
            return []
        return [self._make_alert(event, ctx)]

    def _make_alert(self, event: ConnEvent, ctx: DetectorContext) -> Alert:
        device = ctx.device_for(event)
        label = device.label if device else (event.src_ip or event.src_mac)
        confidence = self.t.no_egress_confidence
        proto = event.proto.upper()
        return Alert(
            detector=self.name,
            title=f"Unexpected egress from isolated host to {event.dst_ip}",
            severity=Severity.from_confidence(confidence),
            confidence=confidence,
            stage=STAGE_EGRESS,
            description=(
                f"{label} is declared no-egress but opened a {proto} connection to "
                f"{event.dst_ip}:{event.dst_port}, an external address. An isolated "
                f"host reaching the internet is the network-layer signal of a "
                f"containment escape."
            ),
            src_mac=device.mac if device else event.src_mac,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            ts=event.ts,
            recommendations=(
                "Verify the host's egress policy — an isolated segment should have "
                "default-deny egress at the firewall/router, not rely on detection.",
                "Isolate or quarantine the host and inspect it for compromise.",
                "Confirm this destination is not an approved exception before "
                "reclassifying the host.",
            ),
            evidence={
                "dst_ip": event.dst_ip,
                "dst_port": event.dst_port,
                "proto": event.proto,
            },
        )
