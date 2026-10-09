"""Report what the sensor cannot see.

A 48-day production run looked clean. It was not: four of nine behavioural
detectors had raised zero alerts because the capture point — a WiFi client NIC on
a switched network — never receives other devices' unicast traffic. Of 86 learned
device profiles, exactly one (the monitoring host) had any external domain; the
rest held only multicast mDNS and reverse-DNS names.

Nothing in the product said so, which made a clean dashboard indistinguishable
from a blind sensor — the most dangerous failure mode a monitoring tool has. This
module measures which *traffic classes* are actually observed and derives which
detectors are structurally unable to fire, plus which ``no_egress_hosts``
declarations cannot be enforced because the host's traffic is never seen.

It is deliberately evidence-based rather than configured: nothing here asks the
operator to describe their deployment, because the whole problem is that the
operator cannot easily tell.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from ..models.events import ArpEvent, NetworkEvent
from ..util.nets import is_internal_ip, is_multicast_ip, is_usable_host_ip

CLASS_MULTICAST = "multicast"
CLASS_INTERNAL_UNICAST = "internal_unicast"
CLASS_EGRESS = "egress"
CLASS_OTHER = "other"

# What traffic class each detector needs in order to be able to fire at all.
DETECTOR_NEEDS: Mapping[str, str] = {
    "port_scan": CLASS_INTERNAL_UNICAST,
    "lateral_movement": CLASS_INTERNAL_UNICAST,
    "credential_spray": CLASS_INTERNAL_UNICAST,
    "ssh_key_injection": CLASS_INTERNAL_UNICAST,
    # idle_exec requires internal destinations as of the role-vs-idleness fix.
    "idle_exec": CLASS_INTERNAL_UNICAST,
    "beacon": CLASS_EGRESS,
    "inference_api": CLASS_EGRESS,
    "stream_timing": CLASS_EGRESS,
    "zero_egress": CLASS_EGRESS,
}

_SCOPE_NOTES = {
    "host-only": (
        "Only multicast traffic from other devices is reaching the sensor, so "
        "Wyvern is effectively monitoring one host. An absence of alerts is NOT "
        "evidence the network is clean. See docs/DEPLOYMENT.md section 2."
    ),
    "egress": (
        "WAN-bound traffic is visible for multiple devices, but device-to-device "
        "unicast is not — typical of a bridge/router placement on a consumer mesh. "
        "Intra-LAN worm stages (discovery, lateral movement, credential reuse, "
        "SSH-key injection) cannot be observed."
    ),
    "lan": "Both intra-LAN and WAN-bound unicast are visible for multiple devices.",
}


def classify_event(event: NetworkEvent, internal_cidrs: tuple[str, ...]) -> str:
    """Bucket an event by the traffic class it demonstrates visibility of."""
    if isinstance(event, ArpEvent):
        return CLASS_MULTICAST
    dst = getattr(event, "dst_ip", None)
    src = getattr(event, "src_ip", None)
    if dst is None or is_multicast_ip(dst) or not is_usable_host_ip(dst):
        return CLASS_MULTICAST
    if not is_internal_ip(src, internal_cidrs):
        return CLASS_OTHER
    if is_internal_ip(dst, internal_cidrs):
        return CLASS_INTERNAL_UNICAST
    return CLASS_EGRESS


@dataclass
class VisibilityCounters:
    """Mutable tally of observed traffic classes (one per Monitor)."""

    counts: dict[str, int] = field(default_factory=dict)
    unicast_sources: set[str] = field(default_factory=set)
    egress_sources: set[str] = field(default_factory=set)
    internal_unicast_sources: set[str] = field(default_factory=set)
    all_sources: set[str] = field(default_factory=set)

    def observe(self, event: NetworkEvent, internal_cidrs: tuple[str, ...]) -> str:
        cls = classify_event(event, internal_cidrs)
        self.counts[cls] = self.counts.get(cls, 0) + 1
        src = getattr(event, "src_ip", None) or getattr(event, "src_mac", None)
        if src:
            self.all_sources.add(src)
            if cls == CLASS_INTERNAL_UNICAST:
                self.unicast_sources.add(src)
                self.internal_unicast_sources.add(src)
            elif cls == CLASS_EGRESS:
                self.unicast_sources.add(src)
                self.egress_sources.add(src)
        return cls


@dataclass(frozen=True)
class VisibilityReport:
    scope: str
    note: str
    counts: Mapping[str, int]
    devices_seen: int
    devices_with_unicast: int
    devices_with_egress: int
    devices_with_internal_unicast: int
    dormant: tuple[str, ...]
    unenforceable_no_egress: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "scope": self.scope,
            "note": self.note,
            "counts": dict(self.counts),
            "devices_seen": self.devices_seen,
            "devices_with_unicast": self.devices_with_unicast,
            "devices_with_egress": self.devices_with_egress,
            "devices_with_internal_unicast": self.devices_with_internal_unicast,
            "dormant_detectors": list(self.dormant),
            "unenforceable_no_egress": list(self.unenforceable_no_egress),
        }


def assess_visibility(
    counters: VisibilityCounters,
    *,
    alert_counts: Mapping[str, int] | None = None,
    no_egress_hosts: tuple[str, ...] = (),
) -> VisibilityReport:
    """Derive the visibility report from observed traffic classes.

    A detector is reported dormant only when the class it needs has never been
    observed *and* it has never fired — observed evidence always beats the
    heuristic.
    """
    alert_counts = alert_counts or {}
    observed = {c for c, n in counters.counts.items() if n > 0}
    # Multiple sources are required before a class counts as genuinely visible:
    # a single source is usually just the capture host observing itself.
    multi_internal = len(counters.internal_unicast_sources) >= 2
    multi_egress = len(counters.egress_sources) >= 2
    if multi_internal and multi_egress:
        scope = "lan"
    elif multi_egress:
        scope = "egress"
    else:
        scope = "host-only"

    available = set()
    if multi_internal:
        available.add(CLASS_INTERNAL_UNICAST)
    if multi_egress:
        available.add(CLASS_EGRESS)
    if CLASS_MULTICAST in observed:
        available.add(CLASS_MULTICAST)

    dormant = tuple(
        sorted(
            name
            for name, need in DETECTOR_NEEDS.items()
            if need not in available and not alert_counts.get(name)
        )
    )
    # A declaration is unenforceable unless that host's own unicast traffic has
    # been seen — zero_egress can only fire on traffic that reaches the sensor.
    unenforceable = tuple(sorted(h for h in no_egress_hosts if h not in counters.unicast_sources))
    return VisibilityReport(
        scope=scope,
        note=_SCOPE_NOTES[scope],
        counts=dict(counters.counts),
        devices_seen=len(counters.all_sources),
        devices_with_unicast=len(counters.unicast_sources),
        devices_with_egress=len(counters.egress_sources),
        devices_with_internal_unicast=len(counters.internal_unicast_sources),
        dormant=dormant,
        unenforceable_no_egress=unenforceable,
    )
