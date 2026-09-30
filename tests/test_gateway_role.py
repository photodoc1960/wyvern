"""Gateway detection and role stickiness (#39).

A 41-day live run classified 13 of 85 devices as ``router`` when only one was a
real gateway — including an ordinary workstation, hosts with no open ports, IPv6
addresses and even a public IP. Because ``router`` is in ``IDLE_ROLES``, that one
mislabelled workstation alone produced 3,678 ``idle_exec`` false positives.

Two defects, covered here:
  1. The gateway guess was a ``.1``/``.254`` *suffix* test — wrong on any prefix
     but /24. On the observed /22 LAN three of the four ``.1`` addresses are
     ordinary hosts.
  2. A role was permanently sticky, so a transient ``router`` guess survived
     forever even once the evidence was gone.
"""

from __future__ import annotations

from wyvern.models.device import DeviceRole
from wyvern.tracking.fingerprint import classify_role
from wyvern.util.nets import is_gateway_ip

LAN22 = ("192.168.4.0/22",)  # the real dogfood LAN
LAN24 = ("192.168.1.0/24",)


def test_gateway_is_first_or_last_usable_host():
    assert is_gateway_ip("192.168.4.1", LAN22)  # first usable — the real gateway
    assert is_gateway_ip("192.168.7.254", LAN22)  # last usable
    assert is_gateway_ip("192.168.1.1", LAN24)
    assert is_gateway_ip("192.168.1.254", LAN24)


def test_suffix_lookalikes_on_a_22_are_not_gateways():
    # Regression (#39): the old `.1` suffix test flagged all of these.
    for ip in ("192.168.5.1", "192.168.6.1", "192.168.7.1"):
        assert not is_gateway_ip(ip, LAN22), f"{ip} is an ordinary host on a /22"
    assert not is_gateway_ip("192.168.7.227", LAN22)  # the mislabelled workstation


def test_addresses_outside_configured_lan_are_not_gateways():
    assert not is_gateway_ip("172.17.0.1", LAN22)  # docker bridge
    assert not is_gateway_ip("18.238.132.68", LAN22)  # public IP
    assert not is_gateway_ip(None, LAN22)
    assert not is_gateway_ip("not-an-ip", LAN22)


def test_router_guess_does_not_stick_without_gateway_evidence():
    # Regression (#39): a device previously guessed `router` must be re-derived
    # once it no longer looks like a gateway and has no other positive signal.
    role = classify_role(
        current=DeviceRole.ROUTER,
        vendor_role_hint=None,
        hostname="bc091b0ec284",  # de-dashed MAC: no signal
        open_ports=(22,),
        ttl=64,
        is_gateway=False,
    )
    assert role is not DeviceRole.ROUTER
    assert role not in {DeviceRole.PRINTER, DeviceRole.NAS, DeviceRole.CAMERA}


def test_real_gateway_still_classifies_as_router():
    assert classify_role(current=DeviceRole.UNKNOWN, is_gateway=True) is DeviceRole.ROUTER
    # and stays router while the evidence holds
    assert classify_role(current=DeviceRole.ROUTER, is_gateway=True) is DeviceRole.ROUTER


def test_positively_identified_roles_remain_sticky():
    # Only the weak gateway guess is provisional; evidence-backed roles persist.
    assert classify_role(current=DeviceRole.PRINTER, is_gateway=False) is DeviceRole.PRINTER
    assert classify_role(current=DeviceRole.NAS, is_gateway=False) is DeviceRole.NAS
    assert classify_role(current=DeviceRole.WORKSTATION, is_gateway=False) is DeviceRole.WORKSTATION
