"""The :class:`DeviceRegistry` — every device on the network and what we know.

Devices are keyed by MAC (falling back to an ``ip:<addr>`` pseudo-key when a
flow is only seen at L3). Records are immutable; each observation produces a new
:class:`Device` snapshot via ``evolve``. The registry also learns which hosts
*serve* an LLM inference endpoint — those are the worm's GPU "reasoning" nodes.
"""

from __future__ import annotations

from ..config import Config
from ..indicators import is_inference_endpoint
from ..models.device import GPU_PLAUSIBLE_ROLES, Device, DeviceRole
from ..models.events import (
    ArpEvent,
    ConnEvent,
    DhcpEvent,
    DnsEvent,
    HttpEvent,
    NetworkEvent,
)
from ..util import oui
from ..util.nets import is_internal_ip, is_usable_host_ip, normalize_mac
from . import fingerprint

# Bound memory against a flood of spoofed MACs on a shared segment. A home LAN
# rarely exceeds a few hundred devices; we keep the most-recently-seen ones.
_MAX_DEVICES = 4096


class DeviceRegistry:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config.default()
        self._by_mac: dict[str, Device] = {}
        self._ip_to_mac: dict[str, str] = {}

    # --------------------------------------------------------------- queries
    def __len__(self) -> int:
        return len(self._by_mac)

    def all(self) -> tuple[Device, ...]:
        return tuple(self._by_mac.values())

    def get(self, key: str | None) -> Device | None:
        if not key:
            return None
        norm = normalize_mac(key)
        if norm and norm in self._by_mac:
            return self._by_mac[norm]
        return self._by_mac.get(key)

    def get_by_ip(self, ip: str | None) -> Device | None:
        if not ip:
            return None
        mac = self._ip_to_mac.get(ip)
        return self._by_mac.get(mac) if mac else None

    def resolve(self, ip: str | None, mac: str | None) -> Device | None:
        return self.get(mac) or self.get_by_ip(ip)

    # ------------------------------------------------------------- mutation
    def mark_suspicious(self, identifier: str, value: bool = True) -> bool:
        """User action: flag a device for deeper monitoring (read-only otherwise)."""
        device = self.get(identifier) or self.get_by_ip(identifier)
        if device is None:
            return False
        self._store(device.evolve(suspicious=value))
        return True

    def observe(self, event: NetworkEvent) -> Device | None:
        """Fold one event into the registry; return the source device."""
        if isinstance(event, ArpEvent):
            return self._observe_arp(event)
        if isinstance(event, ConnEvent):
            return self._observe_conn(event)
        if isinstance(event, HttpEvent):
            return self._observe_http(event)
        if isinstance(event, DhcpEvent):
            return self._observe_dhcp(event)
        if isinstance(event, DnsEvent):
            return self._upsert(event.src_mac, event.src_ip, event.ts)
        return None

    # ------------------------------------------------------- event handlers
    def _observe_arp(self, ev: ArpEvent) -> Device | None:
        return self._upsert(ev.src_mac, ev.src_ip, ev.ts)

    def _observe_conn(self, ev: ConnEvent) -> Device | None:
        ttl = ev.ttl if ev.is_syn or ev.is_synack else None
        src = self._upsert(ev.src_mac, ev.src_ip, ev.ts, ttl=ttl, window=ev.window)
        # A SYN-ACK means the *source* of this packet serves the source port.
        if ev.is_synack and src is not None:
            src = self._store(self._reclassify(src.with_open_port(ev.src_port)))
        # Track internal peers so we know about quiet servers/printers too.
        if self._internal(ev.dst_ip):
            self._upsert(ev.dst_mac, ev.dst_ip, ev.ts)
        return src

    def _observe_http(self, ev: HttpEvent) -> Device | None:
        src = self._upsert(ev.src_mac, ev.src_ip, ev.ts, user_agent=ev.user_agent)
        if is_inference_endpoint(ev.host, ev.path, ev.dst_port) and self._internal(ev.dst_ip):
            self._mark_inference_server(ev.dst_ip, ev.ts)
        return src

    def _observe_dhcp(self, ev: DhcpEvent) -> Device | None:
        return self._upsert(ev.src_mac, ev.src_ip, ev.ts, hostname=ev.hostname)

    # ------------------------------------------------------------- internals
    def _internal(self, ip: str | None) -> bool:
        return is_internal_ip(ip, self.config.internal_cidrs)

    @staticmethod
    def _is_gateway(ip: str | None) -> bool:
        return bool(ip) and (ip.endswith(".1") or ip.endswith(".254"))

    def _key(self, mac: str | None, ip: str | None) -> str | None:
        norm = normalize_mac(mac)
        if norm:
            return norm
        if ip and is_usable_host_ip(ip):
            return f"ip:{ip}"
        return None

    def _store(self, device: Device) -> Device:
        self._by_mac[device.mac] = device
        if device.ip and is_usable_host_ip(device.ip):
            self._ip_to_mac[device.ip] = device.mac
        for ip in device.ips:
            self._ip_to_mac[ip] = device.mac
        if len(self._by_mac) > _MAX_DEVICES:
            self._evict_oldest(keep=device.mac)
        return device

    def _evict_oldest(self, keep: str) -> None:
        victim = min(
            (d for m, d in self._by_mac.items() if m != keep),
            key=lambda d: d.last_seen,
            default=None,
        )
        if victim is None:
            return
        self._by_mac.pop(victim.mac, None)
        for ip in (victim.ip, *victim.ips):
            if ip and self._ip_to_mac.get(ip) == victim.mac:
                self._ip_to_mac.pop(ip, None)

    def _upsert(
        self,
        mac: str | None,
        ip: str | None,
        ts: float,
        *,
        ttl: int | None = None,
        window: int | None = None,
        hostname: str | None = None,
        user_agent: str | None = None,
    ) -> Device | None:
        norm = normalize_mac(mac)
        key = norm
        if key is None:
            # No usable MAC — attach to an existing device for this IP if known,
            # otherwise fall back to an ip-keyed pseudo device.
            if ip:
                existing = self.get_by_ip(ip)
                if existing is not None:
                    key = existing.mac
            if key is None:
                key = self._key(mac, ip)
            if key is None:
                return None
        device = self._by_mac.get(key)
        if device is None:
            # Migrate an existing ip-keyed pseudo device to its real MAC,
            # refreshing the vendor now that we know the OUI.
            if norm and ip and self._ip_to_mac.get(ip, "").startswith("ip:"):
                device = self._by_mac.pop(self._ip_to_mac[ip], None)
                if device is not None:
                    device = device.evolve(mac=norm, vendor=device.vendor or oui.lookup_vendor(mac))
            if device is None:
                device = Device(
                    mac=key,
                    vendor=oui.lookup_vendor(mac),
                    first_seen=ts,
                    last_seen=ts,
                )

        if ip and is_usable_host_ip(ip):
            device = device.with_ip(ip, ts)
        else:
            device = device.evolve(last_seen=max(device.last_seen, ts))
        if hostname:
            device = device.evolve(hostname=hostname)
        if user_agent and not device.os_guess:
            os_from_ua = _os_from_user_agent(user_agent)
            if os_from_ua:
                device = device.evolve(os_guess=os_from_ua)

        device = self._reclassify(device, ttl=ttl)
        return self._store(device)

    def _reclassify(self, device: Device, *, ttl: int | None = None) -> Device:
        serves_inference = device.role is DeviceRole.GPU_HOST
        role = fingerprint.classify_role(
            current=device.role,
            vendor_role_hint=oui.role_hint(device.mac),
            hostname=device.hostname,
            open_ports=device.open_ports,
            ttl=ttl,
            is_gateway=self._is_gateway(device.ip),
            serves_inference=serves_inference,
        )
        declared = self.config.is_declared_gpu_host(device.ip, device.mac)
        gpu_capable = declared or role in GPU_PLAUSIBLE_ROLES
        os_guess = device.os_guess or fingerprint.os_from_ttl(ttl)
        return device.evolve(role=role, gpu_capable=gpu_capable, os_guess=os_guess)

    def _mark_inference_server(self, ip: str, ts: float) -> None:
        device = self.get_by_ip(ip)
        if device is None:
            device = Device(mac=f"ip:{ip}", ip=ip, ips=(ip,), first_seen=ts, last_seen=ts)
        device = device.evolve(role=DeviceRole.GPU_HOST, gpu_capable=True, last_seen=ts)
        self._store(device)

    def to_list(self) -> list[dict]:
        return [d.to_dict() for d in self._by_mac.values()]

    def import_devices(self, devices) -> None:
        """Load device snapshots (e.g. from storage) for label resolution."""
        for device in devices:
            self._store(device)


def _os_from_user_agent(ua: str) -> str | None:
    u = ua.lower()
    if "windows" in u:
        return "Windows"
    if "android" in u:
        return "Android"
    if "iphone" in u or "ipad" in u or "mac os" in u or "darwin" in u:
        return "Apple"
    if "linux" in u or "x11" in u:
        return "Linux/Unix"
    return None
