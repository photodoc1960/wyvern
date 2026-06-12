"""The immutable :class:`Device` record and :class:`DeviceRole` taxonomy.

The registry replaces a device's record with an updated copy on every change
(``device.evolve(...)``) rather than mutating in place, so any code holding a
reference always sees a consistent snapshot.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from enum import Enum


class DeviceRole(str, Enum):
    UNKNOWN = "unknown"
    WORKSTATION = "workstation"
    SERVER = "server"
    ROUTER = "router"
    PRINTER = "printer"
    NAS = "nas"
    CAMERA = "camera"
    IOT = "iot"
    PHONE = "phone"
    GPU_HOST = "gpu_host"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


# Devices that should sit quietly: a printer/router/NAS/camera/sensor that
# suddenly originates code execution or fans out is the worm's replication tell.
IDLE_ROLES: frozenset[DeviceRole] = frozenset(
    {DeviceRole.PRINTER, DeviceRole.ROUTER, DeviceRole.NAS, DeviceRole.CAMERA, DeviceRole.IOT}
)

# Roles plausibly equipped with a GPU capable of hosting the worm's LLM.
GPU_PLAUSIBLE_ROLES: frozenset[DeviceRole] = frozenset(
    {DeviceRole.GPU_HOST, DeviceRole.WORKSTATION, DeviceRole.SERVER}
)


@dataclass(frozen=True, slots=True)
class Device:
    mac: str
    ip: str | None = None
    ips: tuple[str, ...] = ()
    vendor: str | None = None
    hostname: str | None = None
    role: DeviceRole = DeviceRole.UNKNOWN
    os_guess: str | None = None
    open_ports: tuple[int, ...] = ()
    gpu_capable: bool = False
    suspicious: bool = False  # user-flagged for deeper monitoring
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def label(self) -> str:
        """Human-friendly identifier for dashboards and alerts."""
        return self.hostname or self.ip or self.vendor or self.mac

    @property
    def is_idle_role(self) -> bool:
        return self.role in IDLE_ROLES

    def evolve(self, **changes) -> Device:
        """Return a new Device with ``changes`` applied (no mutation)."""
        return dataclasses.replace(self, **changes)

    def with_ip(self, ip: str | None, ts: float) -> Device:
        if not ip:
            return self.evolve(last_seen=max(self.last_seen, ts))
        # Keep only the most recent handful of IPs (bounds DHCP-churn growth).
        ips = self.ips if ip in self.ips else (*self.ips, ip)[-8:]
        return self.evolve(ip=ip, ips=ips, last_seen=max(self.last_seen, ts))

    def with_open_port(self, port: int) -> Device:
        if port in self.open_ports:
            return self
        return self.evolve(open_ports=tuple(sorted({*self.open_ports, port})))

    @classmethod
    def from_dict(cls, data: dict) -> Device:
        try:
            role = DeviceRole(data.get("role", "unknown"))
        except ValueError:
            role = DeviceRole.UNKNOWN
        return cls(
            mac=data["mac"],
            ip=data.get("ip"),
            ips=tuple(data.get("ips", ()) or ()),
            vendor=data.get("vendor"),
            hostname=data.get("hostname"),
            role=role,
            os_guess=data.get("os_guess"),
            open_ports=tuple(data.get("open_ports", ()) or ()),
            gpu_capable=bool(data.get("gpu_capable", False)),
            suspicious=bool(data.get("suspicious", False)),
            first_seen=float(data.get("first_seen", 0.0) or 0.0),
            last_seen=float(data.get("last_seen", 0.0) or 0.0),
        )

    def to_dict(self) -> dict:
        return {
            "mac": self.mac,
            "ip": self.ip,
            "ips": list(self.ips),
            "vendor": self.vendor,
            "hostname": self.hostname,
            "role": self.role.value,
            "os_guess": self.os_guess,
            "open_ports": list(self.open_ports),
            "gpu_capable": self.gpu_capable,
            "suspicious": self.suspicious,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "label": self.label,
        }
