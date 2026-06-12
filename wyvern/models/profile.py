"""The per-device behavioural baseline snapshot (:class:`DeviceProfile`).

The baseline learner observes a device for a learning window (default 24 h) and
freezes what "normal" looks like: which ports it initiates to, which internal
peers it talks to, which domains it resolves, its packet-rate envelope, the
hours it is active, and whether it *ever* makes inference calls or fans out
across auth services. Detectors consult the profile to turn raw activity into
*deviation from this device's own normal*.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DeviceProfile:
    mac: str
    learned: bool = False
    samples: int = 0
    known_ports: frozenset[int] = frozenset()
    known_internal_peers: frozenset[str] = frozenset()
    known_domains: frozenset[str] = frozenset()
    max_ports_5m: int = 0
    max_internal_peers_1h: int = 0
    mean_pkt_rate: float = 0.0
    p95_pkt_rate: float = 0.0
    active_hours: frozenset[int] = frozenset()
    ever_inference: bool = False
    ever_auth_fanout: bool = False
    started_at: float = 0.0
    updated_at: float = 0.0

    def is_new_port(self, port: int) -> bool:
        return self.learned and port not in self.known_ports

    def is_new_peer(self, ip: str) -> bool:
        return self.learned and ip not in self.known_internal_peers

    def is_new_domain(self, domain: str) -> bool:
        return self.learned and domain.lower() not in self.known_domains

    def is_active_hour(self, hour: int) -> bool:
        # Without a learned profile, assume every hour is plausible.
        return (not self.learned) or (hour in self.active_hours)

    def to_dict(self) -> dict:
        return {
            "mac": self.mac,
            "learned": self.learned,
            "samples": self.samples,
            "known_ports": sorted(self.known_ports),
            "known_internal_peers": sorted(self.known_internal_peers),
            "known_domains": sorted(self.known_domains),
            "max_ports_5m": self.max_ports_5m,
            "max_internal_peers_1h": self.max_internal_peers_1h,
            "mean_pkt_rate": self.mean_pkt_rate,
            "p95_pkt_rate": self.p95_pkt_rate,
            "active_hours": sorted(self.active_hours),
            "ever_inference": self.ever_inference,
            "ever_auth_fanout": self.ever_auth_fanout,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> DeviceProfile:
        return cls(
            mac=data["mac"],
            learned=bool(data.get("learned", False)),
            samples=int(data.get("samples", 0)),
            known_ports=frozenset(int(p) for p in data.get("known_ports", [])),
            known_internal_peers=frozenset(data.get("known_internal_peers", [])),
            known_domains=frozenset(d.lower() for d in data.get("known_domains", [])),
            max_ports_5m=int(data.get("max_ports_5m", 0)),
            max_internal_peers_1h=int(data.get("max_internal_peers_1h", 0)),
            mean_pkt_rate=float(data.get("mean_pkt_rate", 0.0)),
            p95_pkt_rate=float(data.get("p95_pkt_rate", 0.0)),
            active_hours=frozenset(int(h) for h in data.get("active_hours", [])),
            ever_inference=bool(data.get("ever_inference", False)),
            ever_auth_fanout=bool(data.get("ever_auth_fanout", False)),
            started_at=float(data.get("started_at", 0.0)),
            updated_at=float(data.get("updated_at", 0.0)),
        )
