"""Detector interface and shared helpers.

A detector is a stateful object that receives normalised events one at a time
(:meth:`inspect`) and periodically (:meth:`sweep`) and emits :class:`Alert`s.
Internal counters (sliding windows, cooldowns) are mutable accumulators — the
domain objects they read and the alerts they emit are immutable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..config import Config
from ..models.alert import Alert
from ..models.device import Device
from ..models.events import NetworkEvent
from ..models.profile import DeviceProfile
from ..tracking.registry import DeviceRegistry
from ..util.nets import is_internal_ip, is_link_local


class ProfileProvider(Protocol):
    def get(self, mac: str) -> DeviceProfile | None:  # pragma: no cover - protocol
        ...


class NullProfiles:
    """A profile provider that knows nothing (used before/without baselines)."""

    def get(self, mac: str) -> DeviceProfile | None:
        return None


@dataclass
class DetectorContext:
    config: Config
    registry: DeviceRegistry
    profiles: ProfileProvider = field(default_factory=NullProfiles)
    now: float = 0.0

    def internal(self, ip: str | None) -> bool:
        return is_internal_ip(ip, self.config.internal_cidrs)

    def device_for(self, event: NetworkEvent) -> Device | None:
        src_mac = getattr(event, "src_mac", None)
        src_ip = getattr(event, "src_ip", None)
        return self.registry.resolve(src_ip, src_mac)

    def profile_for(self, event: NetworkEvent) -> DeviceProfile | None:
        device = self.device_for(event)
        return self.profiles.get(device.mac) if device else None


def source_id(event: NetworkEvent) -> str | None:
    """A stable per-source key: MAC if known, else source IP."""
    mac = getattr(event, "src_mac", None)
    if mac:
        return mac
    return getattr(event, "src_ip", None)


def peer_id(event: NetworkEvent, ctx: DetectorContext) -> str | None:
    """A per-destination key that counts one peer once across its addresses.

    A dual-stack peer is reachable at its routable address *and* an IPv6
    link-local one; counting distinct destination addresses would count it twice
    and inflate fan-out detectors (lateral movement, credential spray) — three
    SMB hosts would look like six (issue #41). Link-local traffic never crosses a
    router, so the frame's destination MAC reliably identifies the peer: map it
    to that device's routable address. Routable destinations stay keyed by
    address, because behind a router the destination MAC is the router's.
    """
    dst = getattr(event, "dst_ip", None)
    if is_link_local(dst):
        device = ctx.registry.get(getattr(event, "dst_mac", None)) or ctx.registry.get_by_ip(dst)
        if device is not None and device.ip and not is_link_local(device.ip):
            return device.ip
    return dst


_COOLDOWN_PRUNE_FLOOR = 1024


class Cooldown:
    """Per-key debounce so a sustained condition alerts once, not every packet.

    Expired entries are dropped as the table grows. An expired entry and a
    missing one mean the same thing (ready to fire), so pruning never changes
    behaviour — it only stops a long-running sensor that sees many distinct
    flows or devices from growing the table without bound. Pruning runs when the
    table doubles past its last pruned size, so its cost is amortised O(1).
    """

    __slots__ = ("seconds", "_last", "_next_prune")

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self._last: dict[object, float] = {}
        self._next_prune = _COOLDOWN_PRUNE_FLOOR

    def __len__(self) -> int:
        return len(self._last)

    def ready(self, key: object, now: float) -> bool:
        last = self._last.get(key)
        return last is None or (now - last) >= self.seconds

    def stamp(self, key: object, now: float) -> None:
        self._last[key] = now
        if len(self._last) >= self._next_prune:
            self.prune(now)
            self._next_prune = max(_COOLDOWN_PRUNE_FLOOR, 2 * len(self._last))

    def prune(self, now: float) -> None:
        """Forget keys whose cooldown has elapsed."""
        horizon = now - self.seconds
        for key in [k for k, last in self._last.items() if last <= horizon]:
            del self._last[key]

    def fire(self, key: object, now: float) -> bool:
        """Convenience: return True (and stamp) iff the cooldown has elapsed."""
        if self.ready(key, now):
            self.stamp(key, now)
            return True
        return False


class Detector:
    """Base detector. Subclasses override :meth:`inspect` and/or :meth:`sweep`."""

    name: str = "detector"

    def __init__(self, config: Config) -> None:
        self.config = config
        self.t = config.thresholds

    def inspect(self, event: NetworkEvent, ctx: DetectorContext) -> list[Alert]:
        return []

    def sweep(self, ctx: DetectorContext) -> list[Alert]:
        return []


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))
