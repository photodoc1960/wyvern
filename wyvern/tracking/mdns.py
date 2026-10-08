"""Device identification from mDNS service-discovery records (RFC 6763).

Wyvern already decodes DNS from UDP 5353, so these records arrive for free. Until
#40 they surfaced only as DGA false positives — which is how the device names on a
live network became visible at all. Suppressing that noise correctly also removed
the only identification signal, leaving an inventory of mostly ``unknown`` devices.
Parsing the names properly turns discarded data into identification.

An RFC 6763 name is ``<instance>._<service>._<proto>.local``, and the instance
label is human-chosen — ``hp envy photo 7800 series [4d46e5]``,
``rincon_949f3e623fdf01400@master bedroom`` — so it doubles as a device label.

Two deliberate restrictions:

* **Only responses identify their sender.** A *query* names a service the sender is
  looking *for* (a phone running the Sonos app queries ``_sonos._tcp``), so it says
  nothing about the sender. The caller is responsible for checking
  ``DnsEvent.is_response``.
* **Only distinctive services are mapped.** ``_ssh``, ``_http``, ``_device-info``
  and friends are announced by almost everything; inferring a role from them would
  recreate the confident-but-wrong labelling that #39 fixed. An unmapped service
  yields ``None`` and the device stays ``unknown``, which is the honest answer.
"""

from __future__ import annotations

from ..models.device import DeviceRole

_PROTO_LABELS = ("_tcp", "_udp")

# Distinctive service -> role. Generic services are intentionally absent.
SERVICE_ROLES: dict[str, DeviceRole] = {
    # printing (including 3D)
    "_ipp": DeviceRole.PRINTER,
    "_ipps": DeviceRole.PRINTER,
    "_printer": DeviceRole.PRINTER,
    "_pdl-datastream": DeviceRole.PRINTER,
    "_ultimaker": DeviceRole.PRINTER,
    "_octoprint": DeviceRole.PRINTER,
    # media / home automation appliances
    "_sonos": DeviceRole.IOT,
    "_spotify-connect": DeviceRole.IOT,
    "_googlecast": DeviceRole.IOT,
    "_airplay": DeviceRole.IOT,
    "_raop": DeviceRole.IOT,
    "_amzn-alexa": DeviceRole.IOT,
    "_hap": DeviceRole.IOT,
    "_matter": DeviceRole.IOT,
    "_matterc": DeviceRole.IOT,
    "_hue": DeviceRole.IOT,
    # cameras / NVR
    "_axis-video": DeviceRole.CAMERA,
    "_rtsp": DeviceRole.CAMERA,
    "_nvr": DeviceRole.CAMERA,
    # network storage
    "_afpovertcp": DeviceRole.NAS,
    "_adisk": DeviceRole.NAS,
    "_time-machine": DeviceRole.NAS,
    "_nfs": DeviceRole.NAS,
}


def parse_service_instance(qname: str | None) -> tuple[str, str] | None:
    """Split an mDNS name into ``(service, instance)``.

    ``"x._ipp._tcp.local"`` -> ``("_ipp", "x")``; a bare service-type enumeration
    such as ``"_ipp._tcp.local"`` yields an empty instance. Returns ``None`` for
    anything that is not an mDNS service name.
    """
    if not qname:
        return None
    name = qname.strip().rstrip(".")
    if not name.lower().endswith(".local"):
        return None
    labels = name.split(".")
    for i, label in enumerate(labels):
        if label.lower() in _PROTO_LABELS:
            if i == 0:
                return None
            service = labels[i - 1].lower()
            if not service.startswith("_"):
                return None
            return service, ".".join(labels[: i - 1])
    return None


def identify(qname: str | None) -> tuple[DeviceRole, str] | None:
    """Return ``(role, label)`` for a recognised mDNS service name, else ``None``.

    The caller must only pass names from mDNS *responses* (see module docstring).
    """
    parsed = parse_service_instance(qname)
    if parsed is None:
        return None
    service, instance = parsed
    role = SERVICE_ROLES.get(service)
    if role is None:
        return None
    return role, instance.strip() or service.lstrip("_")
