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

# A traffic class is credited as visible only when at least this many distinct devices,
# and this share of all devices seen, are observed producing it.
_MIN_SOURCES = 3
_MIN_SOURCE_FRACTION = 0.25

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
    """Mutable tally of observed traffic classes (one per Monitor).

    Devices are identified by **MAC**, not by address. Keying on `src_ip` counted
    every IPv6 link-local and privacy address as its own device — 381 of them on a
    LAN of 92 — which inflated the denominator of the visible-share test until it
    demanded more sources than the network contains, so a fully-visible deployment
    would have reported every detector dormant forever.

    Addresses are tracked separately, because `no_egress_hosts` is configured by
    address and its enforceability has to be checked against what was declared.
    """

    counts: dict[str, int] = field(default_factory=dict)
    unicast_devices: set[str] = field(default_factory=set)
    egress_devices: set[str] = field(default_factory=set)
    internal_unicast_devices: set[str] = field(default_factory=set)
    all_devices: set[str] = field(default_factory=set)
    # Addresses observed sending unicast — used only for no_egress_hosts checks.
    unicast_addrs: set[str] = field(default_factory=set)

    def observe(self, event: NetworkEvent, internal_cidrs: tuple[str, ...]) -> str:
        cls = classify_event(event, internal_cidrs)
        self.counts[cls] = self.counts.get(cls, 0) + 1
        addr = getattr(event, "src_ip", None)
        # MAC first: one device with several addresses must count once.
        device = getattr(event, "src_mac", None) or addr
        if device:
            self.all_devices.add(device)
            if cls == CLASS_INTERNAL_UNICAST:
                self.unicast_devices.add(device)
                self.internal_unicast_devices.add(device)
            elif cls == CLASS_EGRESS:
                self.unicast_devices.add(device)
                self.egress_devices.add(device)
        if addr and cls in (CLASS_INTERNAL_UNICAST, CLASS_EGRESS):
            self.unicast_addrs.add(addr)
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
    capture: dict | None = None

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
            "capture": self.capture,
        }


def assess_visibility(
    counters: VisibilityCounters,
    *,
    alert_counts: Mapping[str, int] | None = None,
    no_egress_hosts: tuple[str, ...] = (),
    capture: dict | None = None,
) -> VisibilityReport:
    """Derive the visibility report from observed traffic classes.

    A detector is reported dormant only when the class it needs has never been
    observed *and* it has never fired — observed evidence always beats the
    heuristic.
    """
    alert_counts = alert_counts or {}
    observed = {c for c, n in counters.counts.items() if n > 0}
    # A traffic class counts as visible only when a real share of the devices on the
    # network demonstrate it. An earlier "two or more sources" floor was far too
    # lenient: a live run saw 39 devices with internal unicast from just 2 of them (the
    # capture host and the gateway) and duly reported the four intra-LAN detectors as
    # live, when they had raised zero alerts in 48 days. Two of thirty-nine is noise.
    seen = len(counters.all_devices)
    need = max(_MIN_SOURCES, int(seen * _MIN_SOURCE_FRACTION))
    multi_internal = len(counters.internal_unicast_devices) >= need
    multi_egress = len(counters.egress_devices) >= need
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
    unenforceable = tuple(sorted(h for h in no_egress_hosts if h not in counters.unicast_addrs))
    return VisibilityReport(
        scope=scope,
        note=_SCOPE_NOTES[scope],
        counts=dict(counters.counts),
        devices_seen=len(counters.all_devices),
        devices_with_unicast=len(counters.unicast_devices),
        devices_with_egress=len(counters.egress_devices),
        devices_with_internal_unicast=len(counters.internal_unicast_devices),
        dormant=dormant,
        unenforceable_no_egress=unenforceable,
        capture=capture,
    )
