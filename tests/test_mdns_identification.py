"""Identify devices from mDNS service-discovery records.

Wyvern already receives these records (DNS is decoded from UDP 5353) and, until
#40, surfaced them only *accidentally* as DGA false positives — which is how the
device names on this network became visible at all. Suppressing that noise
correctly also removed the only identification signal, leaving an inventory of 79
`unknown` devices. RFC 6763 names are self-describing, so parsing them properly
turns discarded data into the identification layer that #39 (roles defaulting
badly when vendor and hostname lookup both fail) and #41 depend on.

Attribution matters: an mDNS *query* names a service the sender is looking *for*,
so it says nothing about the sender. Only a *response* identifies its sender as the
service owner. All names below were observed verbatim on the live network.
"""

from __future__ import annotations

from wyvern.models.device import DeviceRole
from wyvern.tracking.mdns import identify, parse_service_instance

SONOS = "rincon_949f3e623fdf01400@master bedroom._sonos._tcp.local"
PRINTER = "hp envy photo 7800 series [4d46e5]._ipp._tcp.local"
PRINTER2 = "hp envy photo 7800 series [4d46e5]._ipps._tcp.local"
ULTIMAKER = "ultimakersystem-ccbdd3001872._ultimaker._tcp.local"
CAST = "pyxis-tds-370635484532bad554743bb0e444c765._googlecast._tcp.local"
ALEXA = "irobot-d1d60afedee74c8fb725cebbe6c2294d._amzn-alexa._tcp.local"
SPOTIFY = "3a84f889-9282-51aa-b719-fccfd9d6fd78._spotify-connect._tcp.local"


def test_parses_service_and_instance():
    assert parse_service_instance(SONOS) == (
        "_sonos",
        "rincon_949f3e623fdf01400@master bedroom",
    )
    assert parse_service_instance(ULTIMAKER) == ("_ultimaker", "ultimakersystem-ccbdd3001872")
    # a bare service-type enumeration has no instance
    assert parse_service_instance("_sonos._tcp.local") == ("_sonos", "")
    assert parse_service_instance("_ipp._tcp.local.") == ("_ipp", "")  # trailing root dot


def test_rejects_non_mdns_names():
    assert parse_service_instance("example.com") is None
    assert (
        parse_service_instance("37063548-4532-bad5-5474-3bb0e444c765.local") is None
    )  # no service
    assert parse_service_instance("227.7.168.192.in-addr.arpa") is None
    assert parse_service_instance(None) is None
    assert parse_service_instance("") is None


def test_identifies_roles_from_distinctive_services():
    assert identify(PRINTER)[0] is DeviceRole.PRINTER
    assert identify(PRINTER2)[0] is DeviceRole.PRINTER
    assert identify(ULTIMAKER)[0] is DeviceRole.PRINTER
    assert identify(SONOS)[0] is DeviceRole.IOT
    assert identify(CAST)[0] is DeviceRole.IOT
    assert identify(ALEXA)[0] is DeviceRole.IOT
    assert identify(SPOTIFY)[0] is DeviceRole.IOT


def test_label_is_the_human_readable_instance():
    assert identify(PRINTER)[1] == "hp envy photo 7800 series [4d46e5]"
    assert identify(ULTIMAKER)[1] == "ultimakersystem-ccbdd3001872"
    # no instance -> fall back to the service name rather than an empty label
    assert identify("_sonos._tcp.local")[1] == "sonos"


def test_generic_services_are_not_used_for_identification():
    """_ssh/_http/_device-info are announced by everything; guessing from them
    would recreate the mislabelling #39 fixed."""
    for name in (
        "nas._ssh._tcp.local",
        "box._http._tcp.local",
        "thing._device-info._tcp.local",
        "x._workstation._tcp.local",
    ):
        assert identify(name) is None, name


# ------------------------------------------------------- registry integration
def test_response_identifies_the_sender(registry, mk):
    """An mDNS response identifies its sender as the service owner."""
    from dataclasses import replace

    ev = replace(mk.dns("192.168.4.60", PRINTER, 1000.0, mac="00:11:22:33:44:aa"), is_response=True)
    dev = registry.observe(ev)
    assert dev is not None
    assert dev.role is DeviceRole.PRINTER
    assert dev.hostname == "hp envy photo 7800 series [4d46e5]"


def test_query_does_not_identify_the_sender(registry, mk):
    """A query names a service the sender is *seeking* — e.g. a phone running the
    Sonos app querying _sonos._tcp is not a Sonos."""
    dev = registry.observe(mk.dns("192.168.4.61", SONOS, 1000.0, mac="00:11:22:33:44:bb"))
    assert dev is not None
    assert dev.role is not DeviceRole.IOT
    assert dev.hostname != "rincon_949f3e623fdf01400@master bedroom"
