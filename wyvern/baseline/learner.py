"""The baseline learner — learns each device's "normal" over a learning window.

For the configured window (default 24 h from a device's first observation) the
learner records, per device, the ports it initiates to, the internal peers and
domains it talks to, its packet-rate envelope, the hours it is active, and the
binary facts "does it ever make inference calls?" / "does it ever fan out across
auth services?". After the window elapses it serves a *learned*
:class:`DeviceProfile`; before that, an *unlearned* one (so detectors fall back
to absolute thresholds).
"""

from __future__ import annotations

import time

from ..config import Config
from ..indicators import inference_confidence, is_auth_port
from ..models.events import (
    ConnEvent,
    DnsEvent,
    HttpEvent,
    NetworkEvent,
)
from ..models.profile import DeviceProfile
from ..tracking.registry import DeviceRegistry
from ..util.nets import is_internal_ip
from ..util.timewindow import SlidingWindow

_MIN_SAMPLES = 10  # don't call a profile "learned" on a handful of packets


class _Acc:
    """Mutable per-device accumulator (internal bookkeeping)."""

    __slots__ = (
        "mac",
        "started_at",
        "updated_at",
        "samples",
        "ports",
        "peers",
        "domains",
        "ports_win",
        "max_ports_5m",
        "peers_win",
        "max_peers_1h",
        "auth_win",
        "ever_auth_fanout",
        "ever_inference",
        "minute_counts",
        "active_hours",
    )

    def __init__(self, mac: str, started_at: float, t) -> None:
        self.mac = mac
        self.started_at = started_at
        self.updated_at = started_at
        self.samples = 0
        self.ports: set[int] = set()
        self.peers: set[str] = set()
        self.domains: set[str] = set()
        self.ports_win = SlidingWindow(t.scan_window_s)
        self.max_ports_5m = 0
        self.peers_win = SlidingWindow(t.lateral_window_s)
        self.max_peers_1h = 0
        self.auth_win = SlidingWindow(t.cred_window_s)
        self.ever_auth_fanout = False
        self.ever_inference = False
        self.minute_counts: dict[int, int] = {}
        self.active_hours: set[int] = set()


class BaselineLearner:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config.default()
        self.t = self.config.thresholds
        self.window_s = self.config.learning_window_hours * 3600.0
        self._accs: dict[str, _Acc] = {}
        self._now = 0.0

    # ------------------------------------------------------------- ingestion
    def observe(self, event: NetworkEvent, registry: DeviceRegistry) -> None:
        device = registry.resolve(getattr(event, "src_ip", None), getattr(event, "src_mac", None))
        if device is None:
            return
        ts = event.ts
        self._now = max(self._now, ts)
        acc = self._accs.get(device.mac)
        if acc is None:
            acc = _Acc(device.mac, ts, self.t)
            self._accs[device.mac] = acc
        acc.samples += 1
        acc.updated_at = ts
        acc.minute_counts[int(ts // 60)] = acc.minute_counts.get(int(ts // 60), 0) + 1
        acc.active_hours.add(time.localtime(ts).tm_hour)

        if isinstance(event, ConnEvent) and event.is_syn:
            self._learn_conn(acc, event)
        elif isinstance(event, DnsEvent) and not event.is_response and event.qname:
            acc.domains.add(event.qname.lower())
        elif isinstance(event, HttpEvent):
            if inference_confidence(event.host, event.path, event.dst_port) > 0:
                acc.ever_inference = True

        self._prune(acc, ts)

    def _learn_conn(self, acc: _Acc, ev: ConnEvent) -> None:
        acc.ports.add(ev.dst_port)
        acc.ports_win.add(ev.ts, ev.dst_port)
        acc.max_ports_5m = max(acc.max_ports_5m, acc.ports_win.distinct_count(ev.ts))
        if is_internal_ip(ev.dst_ip, self.config.internal_cidrs):
            acc.peers.add(ev.dst_ip)
            acc.peers_win.add(ev.ts, ev.dst_ip)
            acc.max_peers_1h = max(acc.max_peers_1h, acc.peers_win.distinct_count(ev.ts))
        if is_auth_port(ev.dst_port):
            acc.auth_win.add(ev.ts, ev.dst_ip)
            if acc.auth_win.distinct_count(ev.ts) >= self.t.cred_distinct_hosts:
                acc.ever_auth_fanout = True

    def _prune(self, acc: _Acc, now: float) -> None:
        horizon = int((now - self.window_s) // 60)
        if len(acc.minute_counts) > 2000:
            for minute in [m for m in acc.minute_counts if m < horizon]:
                acc.minute_counts.pop(minute, None)

    # --------------------------------------------------------------- queries
    def get(self, mac: str) -> DeviceProfile | None:
        acc = self._accs.get(mac)
        if acc is None:
            return None
        return self._build(acc)

    def is_learning(self) -> bool:
        """True while at least one device is still within its learning window."""
        return any(not self._learned(acc) for acc in self._accs.values())

    def progress(self) -> float:
        """Overall learning progress in [0, 1] across tracked devices."""
        if not self._accs:
            return 0.0
        fracs = [
            min(1.0, (self._now - acc.started_at) / self.window_s) if self.window_s else 1.0
            for acc in self._accs.values()
        ]
        return round(sum(fracs) / len(fracs), 3)

    def snapshot(self) -> dict[str, DeviceProfile]:
        return {mac: self._build(acc) for mac, acc in self._accs.items()}

    def _learned(self, acc: _Acc) -> bool:
        elapsed = self._now - acc.started_at
        return elapsed >= self.window_s and acc.samples >= _MIN_SAMPLES

    def _build(self, acc: _Acc) -> DeviceProfile:
        counts = sorted(acc.minute_counts.values())
        mean_rate = sum(counts) / len(counts) if counts else 0.0
        p95_rate = counts[min(len(counts) - 1, int(0.95 * len(counts)))] if counts else 0.0
        return DeviceProfile(
            mac=acc.mac,
            learned=self._learned(acc),
            samples=acc.samples,
            known_ports=frozenset(acc.ports),
            known_internal_peers=frozenset(acc.peers),
            known_domains=frozenset(acc.domains),
            max_ports_5m=acc.max_ports_5m,
            max_internal_peers_1h=acc.max_peers_1h,
            mean_pkt_rate=round(mean_rate, 2),
            p95_pkt_rate=float(p95_rate),
            active_hours=frozenset(acc.active_hours),
            ever_inference=acc.ever_inference,
            ever_auth_fanout=acc.ever_auth_fanout,
            started_at=acc.started_at,
            updated_at=acc.updated_at,
        )

    # ------------------------------------------------------------ persistence
    def seed(self, profiles: dict[str, DeviceProfile]) -> None:
        """Reconstitute learned baselines (e.g. loaded from disk) on startup."""
        for profile in profiles.values():
            self._now = max(self._now, profile.updated_at)
        for mac, profile in profiles.items():
            started = (self._now or profile.updated_at) - self.window_s - 1.0
            acc = _Acc(mac, started, self.t)
            acc.samples = max(profile.samples, _MIN_SAMPLES)
            acc.updated_at = profile.updated_at
            acc.ports = set(profile.known_ports)
            acc.peers = set(profile.known_internal_peers)
            acc.domains = set(profile.known_domains)
            acc.max_ports_5m = profile.max_ports_5m
            acc.max_peers_1h = profile.max_internal_peers_1h
            acc.active_hours = set(profile.active_hours)
            acc.ever_inference = profile.ever_inference
            acc.ever_auth_fanout = profile.ever_auth_fanout
            self._accs[mac] = acc
