"""Dual-stack identity (issue #41): one device, one identity.

A host on a dual-stack LAN has a routable address *and* an IPv6 link-local one.
It must count once as a device, once as a peer, and report alerts under its
routable address.
"""

from __future__ import annotations

from wyvern.config import Config
from wyvern.detectors.credential_spray import CredentialSprayDetector
from wyvern.detectors.lateral_movement import LateralMovementDetector
from wyvern.engine.monitor import Monitor
from wyvern.models.device import Device
from wyvern.models.events import ConnEvent
from wyvern.storage.db import WyvernDB
from wyvern.util.nets import is_link_local

SRC_MAC = "20:50:e7:8b:b6:38"
SRC_V4 = "192.168.7.136"
SRC_LL = "fe80::28eb:544f:963:88ff"


def _syn(src, dst, port, ts, *, src_mac=SRC_MAC, dst_mac=None):
    return ConnEvent(
        ts=ts, src_ip=src, dst_ip=dst, dst_port=port, src_mac=src_mac, dst_mac=dst_mac, flags="S"
    )


def _peer(i):
    """A LAN peer reachable at both a routable and a link-local address."""
    return f"192.168.7.{50 + i}", f"fe80::{50 + i:x}", f"aa:bb:cc:00:00:{50 + i:02x}"


def test_is_link_local():
    assert is_link_local("fe80::1") and is_link_local("169.254.3.4")
    assert not is_link_local("192.168.7.1") and not is_link_local("2001:db8::1")
    assert not is_link_local(None) and not is_link_local("not-an-ip")


def test_link_local_never_displaces_routable_primary():
    d = Device(mac=SRC_MAC).with_ip(SRC_V4, 1.0).with_ip(SRC_LL, 2.0)
    assert d.ip == SRC_V4
    assert SRC_LL in d.ips  # still recorded as a secondary address


def test_routable_address_replaces_link_local_primary():
    d = Device(mac=SRC_MAC).with_ip(SRC_LL, 1.0).with_ip(SRC_V4, 2.0)
    assert d.ip == SRC_V4


def test_registry_keeps_one_device_with_routable_primary(registry):
    registry.observe(_syn(SRC_V4, "192.168.7.1", 80, 1.0))
    registry.observe(_syn(SRC_LL, "fe80::1", 80, 2.0))
    dev = registry.get(SRC_MAC)
    assert dev.ip == SRC_V4
    assert registry.get_by_ip(SRC_LL) is dev  # link-local still resolves to it


def test_lateral_movement_counts_dual_stack_peer_once(config, feed):
    # 6 peers, each reached at both addresses: 12 destination addresses, 6 hosts.
    det = LateralMovementDetector(config)
    events, ts = [], 1.0
    for i in range(6):
        v4, ll, mac = _peer(i)
        events.append(_syn(SRC_V4, v4, 80, ts, dst_mac=mac))
        events.append(_syn(SRC_LL, ll, 80, ts + 0.5, dst_mac=mac))
        ts += 1.0
    assert feed(det, events) == []  # below the 10-peer threshold once deduplicated


def test_credential_spray_counts_dual_stack_host_once(config, feed):
    # SMB to 3 hosts over both stacks: 6 addresses would trip the 5-host threshold.
    det = CredentialSprayDetector(config)
    events, ts = [], 1.0
    for i in range(3):
        v4, ll, mac = _peer(i)
        events.append(_syn(SRC_V4, v4, 445, ts, dst_mac=mac))
        events.append(_syn(SRC_LL, ll, 445, ts + 0.5, dst_mac=mac))
        ts += 1.0
    assert feed(det, events) == []


def test_routed_destinations_still_counted_by_address(config, feed):
    # Behind a router every routable destination carries the router's MAC; they
    # are still distinct hosts and must not collapse into one peer.
    det = CredentialSprayDetector(config)
    router = "00:11:22:33:44:55"
    events = [_syn(SRC_V4, f"192.168.5.{10 + i}", 445, 1.0 + i, dst_mac=router) for i in range(5)]
    alerts = feed(det, events)
    assert alerts and alerts[0].detector == "credential_spray"


def test_alert_from_link_local_source_reports_routable_address(tmp_path):
    mon = Monitor(Config(data_dir=str(tmp_path)).validate(), learn=False, db=WyvernDB(":memory:"))
    mon.process_event(_syn(SRC_V4, "192.168.7.1", 80, 1.0))
    # Port scan entirely from the link-local address.
    for port in range(1000, 1060):
        mon.process_event(_syn(SRC_LL, "fe80::1", port, 2.0 + port / 1000))
    scan = [a for a in mon.recent_alerts() if a["detector"] == "port_scan"]
    assert scan, "expected a port-scan alert"
    assert scan[0]["src_ip"] == SRC_V4
    assert scan[0]["evidence"]["observed_src_ip"] == SRC_LL
