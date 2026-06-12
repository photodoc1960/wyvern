"""Passive OS and device-role fingerprinting.

Everything here is inferred from traffic we already see — no active probing.
The role classification matters because the worm's most alarming behaviour is
code execution on *normally-idle* devices (printers, routers, NAS, cameras,
ICS sensors). Getting the role right turns "a host made an outbound connection"
into "a printer just started scanning the network".
"""

from __future__ import annotations

from ..models.device import DeviceRole


# Initial-TTL fingerprints: observed TTL counts down from the OS default.
def os_from_ttl(ttl: int | None) -> str | None:
    if ttl is None or ttl <= 0:
        return None
    if ttl <= 64:
        return "Linux/Unix"
    if ttl <= 128:
        return "Windows"
    return "Network/Embedded"


# Hostname substrings -> role (checked in priority order below).
_HOSTNAME_KEYWORDS: tuple[tuple[DeviceRole, tuple[str, ...]], ...] = (
    (
        DeviceRole.PRINTER,
        ("printer", "print", "laserjet", "officejet", "mfp", "brother", "epson", "canon"),
    ),
    (
        DeviceRole.CAMERA,
        ("camera", "ipcam", "ip-cam", "ipc-", "hikvision", "dahua", "reolink", "nvr", "doorbell"),
    ),
    (DeviceRole.NAS, ("nas", "synology", "diskstation", "qnap", "truenas", "freenas", "readynas")),
    (
        DeviceRole.ROUTER,
        (
            "router",
            "gateway",
            "openwrt",
            "unifi",
            "fritz",
            "eero",
            "orbi",
            "mikrotik",
            "edgerouter",
        ),
    ),
    (DeviceRole.GPU_HOST, ("gpu", "cuda", "dgx", "jetson")),
    (DeviceRole.PHONE, ("iphone", "android", "galaxy", "pixel", "oneplus")),
)

# Served-port -> role hint (a host *serving* these is likely that role).
_PORT_ROLE: dict[int, DeviceRole] = {
    9100: DeviceRole.PRINTER,
    631: DeviceRole.PRINTER,
    515: DeviceRole.PRINTER,
    554: DeviceRole.CAMERA,
    2049: DeviceRole.NAS,
    548: DeviceRole.NAS,
    502: DeviceRole.IOT,
}


def role_from_hostname(hostname: str | None) -> DeviceRole | None:
    if not hostname:
        return None
    h = hostname.lower()
    for role, needles in _HOSTNAME_KEYWORDS:
        if any(n in h for n in needles):
            return role
    return None


def role_from_open_ports(ports: tuple[int, ...]) -> DeviceRole | None:
    for port in ports:
        role = _PORT_ROLE.get(port)
        if role is not None:
            return role
    return None


def classify_role(
    *,
    current: DeviceRole = DeviceRole.UNKNOWN,
    vendor_role_hint: str | None = None,
    hostname: str | None = None,
    open_ports: tuple[int, ...] = (),
    ttl: int | None = None,
    is_gateway: bool = False,
    serves_inference: bool = False,
) -> DeviceRole:
    """Infer a device role from the available passive signals.

    Stronger, more specific signals win over weaker, generic ones. An already
    confidently-classified device is only upgraded, never silently downgraded
    to ``UNKNOWN``.
    """
    if serves_inference:
        return DeviceRole.GPU_HOST

    by_host = role_from_hostname(hostname)
    if by_host is not None:
        return by_host

    by_port = role_from_open_ports(open_ports)
    if by_port is not None:
        return by_port

    if vendor_role_hint:
        try:
            return DeviceRole(vendor_role_hint)
        except ValueError:
            pass

    if is_gateway:
        return DeviceRole.ROUTER

    if current is not DeviceRole.UNKNOWN:
        return current

    # Fall back to a coarse guess from OS family.
    os_family = os_from_ttl(ttl)
    if os_family == "Windows":
        return DeviceRole.WORKSTATION
    if os_family == "Network/Embedded":
        return DeviceRole.IOT
    return DeviceRole.UNKNOWN
