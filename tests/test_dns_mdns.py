"""mDNS names must never be scored as DGA domains (#40).

A 41-day live run produced 18,548 "algorithmically-generated domain" alerts —
**78% of every alert raised**. 18,384 of them (99.1%) were ``.local`` mDNS names
and 68.5% were RFC 6763 service-discovery records (``_googlecast``,
``_spotify-connect``, ``_sonos``, ``_ipp``).

Scoring these for DGA is a category error: ``.local`` is reserved for multicast
DNS (RFC 6762) — resolved by link-local multicast on the LAN, never by a
recursive resolver — so a high-entropy ``.local`` name cannot act as a C2
rendezvous. RFC 6763 service names additionally embed UUIDs by design, which
guarantees a high entropy score.

The names below are verbatim from the live run (each scored 0.72-0.92 against a
0.62 threshold).
"""

from __future__ import annotations

from wyvern.detectors.dns_anomaly import DnsAnomalyDetector
from wyvern.indicators import is_mdns_name

GOOGLECAST = "pyxis-tds-370635484532bad554743bb0e444c765._googlecast._tcp.local"
SPOTIFY = "3a84f889-9282-51aa-b719-fccfd9d6fd78._spotify-connect._tcp.local"
CHROMECAST = "37063548-4532-bad5-5474-3bb0e444c765.local"
PRINTER = "hp envy photo 7800 series [4d46e5]._ipp._tcp.local"
SONOS = "rincon_949f3e623fdf01400@master bedroom._sonos._tcp.local"


def test_is_mdns_name_recognises_names_seen_in_production():
    for name in (GOOGLECAST, SPOTIFY, CHROMECAST, PRINTER, SONOS):
        assert is_mdns_name(name), name
    assert is_mdns_name("something.local.")  # trailing root dot
    assert is_mdns_name("_sonos._tcp.local")


def test_is_mdns_name_rejects_real_domains():
    assert not is_mdns_name("google.com")
    assert not is_mdns_name("xkvjqwmrtzbplnhdgf.com")  # a genuine DGA-looking name
    assert not is_mdns_name("udc-svc-prod-useast1-1784892384.us-east-1.elb.amazonaws.com")
    assert not is_mdns_name("notlocal.localdomain")  # must not match on substring
    assert not is_mdns_name(None)
    assert not is_mdns_name("")


def test_mdns_queries_raise_no_dga_alert(config, feed, mk):
    """Regression: these exact names produced ~18,400 CRITICAL/HIGH alerts."""
    det = DnsAnomalyDetector(config)
    events = [
        mk.dns("192.168.7.50", name, 1000.0 + i, mac="00:11:22:33:44:55")
        for i, name in enumerate((GOOGLECAST, SPOTIFY, CHROMECAST, PRINTER, SONOS))
    ]
    assert feed(det, events) == []


def test_genuine_dga_domain_still_alerts(config, feed, mk):
    """Detection of real DGA-style domains must be unaffected."""
    det = DnsAnomalyDetector(config)
    alerts = feed(
        det,
        [mk.dns("192.168.7.50", "xkvjqwmrtzbplnhdgf.com", 1000.0, mac="00:11:22:33:44:55")],
    )
    assert len(alerts) == 1
    assert "algorithmically-generated" in alerts[0].title
