"""Wyvern must report what it cannot see.

A 48-day production run looked clean. It was not: four of nine behavioural
detectors (`port_scan`, `lateral_movement`, `credential_spray`,
`ssh_key_injection`) had raised zero alerts because the capture point — a WiFi
client NIC on a switched network — never receives other devices' unicast traffic.
Of 86 learned device profiles, exactly one (the monitoring host) had any external
domain; the other 85 held only multicast mDNS and reverse-DNS names.

Nothing in the product said so. A clean dashboard was indistinguishable from a
blind sensor, which is the most dangerous failure mode a monitoring tool has. This
measures the traffic classes actually observed and reports which detectors are
therefore structurally unable to fire, and which `no_egress_hosts` declarations are
unenforceable.
"""

from __future__ import annotations

from wyvern.assessment.visibility import (
    CLASS_EGRESS,
    CLASS_INTERNAL_UNICAST,
    CLASS_MULTICAST,
    VisibilityCounters,
    assess_visibility,
    classify_event,
)

CIDRS = ("192.168.4.0/22",)


def test_classifies_multicast_mdns(mk):
    ev = mk.udp("192.168.4.60", "224.0.0.251", 5353, 1.0, mac="00:11:22:33:44:01")
    assert classify_event(ev, CIDRS) == CLASS_MULTICAST


def test_classifies_broadcast_arp(mk):
    assert (
        classify_event(mk.arp("00:11:22:33:44:02", "192.168.4.61", 1.0), CIDRS) == CLASS_MULTICAST
    )


def test_classifies_internal_unicast(mk):
    ev = mk.syn("192.168.4.60", "192.168.4.10", 445, 1.0, mac="00:11:22:33:44:01")
    assert classify_event(ev, CIDRS) == CLASS_INTERNAL_UNICAST


def test_classifies_egress(mk):
    ev = mk.syn("192.168.4.60", "18.238.132.5", 443, 1.0, mac="00:11:22:33:44:01")
    assert classify_event(ev, CIDRS) == CLASS_EGRESS


# ------------------------------------------------------------------ the report
def _counters(events, cidrs=CIDRS):
    c = VisibilityCounters()
    for ev in events:
        c.observe(ev, cidrs)
    return c


def test_multicast_only_is_reported_as_host_only_scope(mk):
    """Reproduces the real deployment: every other device seen only via mDNS."""
    evs = [
        mk.udp(f"192.168.4.{i}", "224.0.0.251", 5353, float(i), mac=f"00:11:22:33:44:{i:02x}")
        for i in range(10, 40)
    ]
    rep = assess_visibility(_counters(evs), alert_counts={}, no_egress_hosts=())
    assert rep.scope == "host-only"
    assert rep.devices_with_unicast == 0
    # the four intra-LAN detectors cannot fire and must be named
    for d in ("port_scan", "lateral_movement", "credential_spray", "ssh_key_injection"):
        assert d in rep.dormant, d


def test_egress_visibility_activates_egress_detectors_but_not_lan(mk):
    """A bridge/router placement sees WAN-bound traffic from many devices, but on a
    consumer mesh still never sees device-to-device unicast."""
    evs = [
        mk.syn(f"192.168.4.{i}", "18.238.132.5", 443, float(i), mac=f"00:11:22:33:44:{i:02x}")
        for i in range(10, 30)
    ]
    rep = assess_visibility(_counters(evs), alert_counts={}, no_egress_hosts=())
    assert rep.scope == "egress"
    assert "zero_egress" not in rep.dormant
    assert "beacon" not in rep.dormant
    assert "lateral_movement" in rep.dormant  # intra-LAN still invisible


def test_full_lan_visibility_leaves_nothing_dormant(mk):
    evs = []
    for i in range(10, 30):
        evs.append(
            mk.syn(f"192.168.4.{i}", "192.168.4.5", 445, float(i), mac=f"00:11:22:33:44:{i:02x}")
        )
        evs.append(
            mk.syn(f"192.168.4.{i}", "18.238.132.5", 443, float(i), mac=f"00:11:22:33:44:{i:02x}")
        )
    rep = assess_visibility(_counters(evs), alert_counts={}, no_egress_hosts=())
    assert rep.scope == "lan"
    assert rep.dormant == ()


def test_a_detector_that_has_fired_is_never_called_dormant(mk):
    """Observed evidence beats the heuristic: if it fired, it clearly can."""
    evs = [mk.udp("192.168.4.60", "224.0.0.251", 5353, 1.0, mac="00:11:22:33:44:01")]
    rep = assess_visibility(
        _counters(evs), alert_counts={"lateral_movement": 3}, no_egress_hosts=()
    )
    assert "lateral_movement" not in rep.dormant


def test_undeclarable_no_egress_hosts_are_flagged(mk):
    """Declaring a host whose traffic is never seen makes zero_egress unenforceable
    — exactly the trap two threat-model entries walked into."""
    evs = [mk.udp("192.168.4.60", "224.0.0.251", 5353, 1.0, mac="00:11:22:33:44:01")]
    rep = assess_visibility(
        _counters(evs), alert_counts={}, no_egress_hosts=("192.168.4.77", "192.168.4.60")
    )
    assert "192.168.4.77" in rep.unenforceable_no_egress
    # 192.168.4.60 was seen, but only via multicast — still unenforceable
    assert "192.168.4.60" in rep.unenforceable_no_egress


def test_declared_host_with_observed_unicast_is_enforceable(mk):
    evs = [mk.syn("192.168.4.60", "18.238.132.5", 443, 1.0, mac="00:11:22:33:44:01")]
    rep = assess_visibility(_counters(evs), alert_counts={}, no_egress_hosts=("192.168.4.60",))
    assert rep.unenforceable_no_egress == ()
