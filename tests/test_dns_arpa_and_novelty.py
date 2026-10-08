"""Two DNS false-positive classes found in a week of live capture.

**Reverse DNS counted as C2 enumeration.** All 9 "NXDOMAIN burst" alerts raised in
the week came from PTR lookups on this host — IPv6 ``ip6.arpa`` nibble names and
its own ``in-addr.arpa`` record. ``.arpa`` is a reserved infrastructure zone
(RFC 3172); PTR misses for private and IPv6 addresses are entirely normal. This is
the same category error as scoring mDNS names for DGA (#40): a reverse lookup that
fails is not resolver-side domain enumeration, and the nibble strings are
high-entropy by construction.

**DGA with no novelty requirement.** 20 of the week's 23 DGA alerts were a single
domain — ``udc-svc-prod-useast1-...elb.amazonaws.com`` — re-alerting every cooldown
window. A C2 rendezvous is by nature a domain the device has not resolved before,
so a name already in the device's learned baseline should not raise a DGA alert.
Crucially this must not blind the detector during the 24h learning window.
"""

from __future__ import annotations

from wyvern.detectors.dns_anomaly import DnsAnomalyDetector
from wyvern.indicators import is_reverse_dns_name
from wyvern.models.profile import DeviceProfile

# observed verbatim in production
PTR6 = "e.7.2.4.4.b.4.0.2.7.c.7.f.6.b.0.1.0.0.0.6.8.0.1.7.e.f.f.ip6.arpa"
PTR4 = "227.7.168.192.in-addr.arpa"
AWS = "udc-svc-prod-useast1-1784892384.us-east-1.elb.amazonaws.com"
NOVEL = "xkvjqwmrtzbplnhdgf.com"  # dga_score 0.80
MAC = "00:11:22:33:44:77"


class Profiles:
    """Minimal ProfileProvider stub."""

    def __init__(self, profile: DeviceProfile | None = None, mac: str = MAC) -> None:
        self._by_mac = {mac: profile} if profile else {}

    def get(self, mac):
        return self._by_mac.get(mac)


# ----------------------------------------------------------------- .arpa
def test_recognises_reverse_dns_names():
    assert is_reverse_dns_name(PTR6)
    assert is_reverse_dns_name(PTR4)
    assert is_reverse_dns_name("1.0.0.127.in-addr.arpa.")  # trailing root dot
    assert is_reverse_dns_name("in-addr.arpa")


def test_rejects_ordinary_domains():
    assert not is_reverse_dns_name("example.com")
    assert not is_reverse_dns_name("arpa-industries.com")  # must not match substring
    assert not is_reverse_dns_name(NOVEL)
    assert not is_reverse_dns_name(None)
    assert not is_reverse_dns_name("")


def test_reverse_lookups_do_not_raise_dga(config, feed, mk):
    det = DnsAnomalyDetector(config)
    assert feed(det, [mk.dns("192.168.7.50", PTR6, 1000.0, mac=MAC)]) == []


def test_reverse_lookup_nxdomain_does_not_burst(config, feed, mk):
    """Regression: 9 of 9 NXDOMAIN bursts in the live week were PTR misses."""
    det = DnsAnomalyDetector(config)
    events = [
        mk.dns_nx("192.168.7.1", "192.168.7.50", f"{i}.7.168.192.in-addr.arpa", 1000.0 + i)
        for i in range(40)  # well past dns_nxdomain_burst = 25
    ]
    assert feed(det, events) == []


def test_real_nxdomain_burst_still_fires(config, feed, mk):
    """Genuine resolver-side enumeration must still be caught."""
    det = DnsAnomalyDetector(config)
    events = [
        mk.dns_nx("192.168.7.1", "192.168.7.50", f"{i}-kq3v9z7x1mwp4b8n.net", 1000.0 + i)
        for i in range(40)
    ]
    alerts = feed(det, events)
    assert alerts and "NXDOMAIN" in alerts[0].title


# ------------------------------------------------------------- DGA novelty
def test_known_domain_does_not_raise_dga(config, feed, mk):
    """20 of 23 live DGA alerts were one AWS ELB name the device resolves constantly."""
    det = DnsAnomalyDetector(config)
    learned = DeviceProfile(mac=MAC, learned=True, known_domains=frozenset({AWS.lower()}))
    out = feed(det, [mk.dns("192.168.7.50", AWS, 1000.0, mac=MAC)], profiles=Profiles(learned))
    assert out == []


def test_novel_high_entropy_domain_still_alerts(config, feed, mk):
    det = DnsAnomalyDetector(config)
    learned = DeviceProfile(mac=MAC, learned=True, known_domains=frozenset({"example.com"}))
    out = feed(det, [mk.dns("192.168.7.50", NOVEL, 1000.0, mac=MAC)], profiles=Profiles(learned))
    assert len(out) == 1 and "algorithmically-generated" in out[0].title


def test_unlearned_profile_does_not_blind_the_detector(config, feed, mk):
    """During the 24h learning window there is no baseline, so DGA must still fire."""
    det = DnsAnomalyDetector(config)
    unlearned = DeviceProfile(mac=MAC, learned=False)
    out = feed(det, [mk.dns("192.168.7.50", NOVEL, 1000.0, mac=MAC)], profiles=Profiles(unlearned))
    assert len(out) == 1
    det2 = DnsAnomalyDetector(config)
    assert (
        len(feed(det2, [mk.dns("192.168.7.50", NOVEL, 1000.0, mac=MAC)])) == 1
    )  # no profile at all
