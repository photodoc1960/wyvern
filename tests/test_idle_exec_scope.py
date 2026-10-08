"""idle_exec must key on worm behaviour, not on a device's label.

The detector's premise — "a printer/camera/NAS/router is normally idle, so
outbound connections imply code execution" — held for 2010-era LAN appliances. It
does not hold in 2026: Sonos streams from the internet, a Roomba is cloud
controlled, a printer does ePrint and firmware checks, a Powerwall reports
telemetry continuously. Role is not idleness.

Evidence: all 3,689 historical idle_exec alerts fired on *external* destinations —
Apple, Google, Cloudflare, AWS, archive.ubuntu.com — i.e. ordinary web and package
traffic from one mislabelled workstation. Zero had an internal destination.

#39 produced that flood from a *wrong* role. Identifying devices correctly (#51)
would have produced the same flood from *right* roles, because ~10 cloud-native
appliances were about to be labelled IOT/PRINTER. The detector is wrong either way.

Two gates fix it:
  * **Internal destinations only.** Self-replication reaches other hosts on the
    LAN. Outbound internet chatter is normal for these devices, and Wyvern keeps no
    learned baseline of external destinations, so it cannot distinguish normal from
    abnormal there — firing on it is guessing. Outbound-to-internet signals are
    already covered by beacon, inference_api, stream_timing and zero_egress.
  * **Novel peers only**, where a baseline exists: a device talking to the internal
    hosts it always talks to is not replicating.
"""

from __future__ import annotations

from dataclasses import replace

from wyvern.detectors.idle_exec import IdleDeviceExecDetector
from wyvern.models.device import DeviceRole
from wyvern.models.profile import DeviceProfile

PRINTER_MDNS = "hp envy photo 7800 series [4d46e5]._ipp._tcp.local"
MAC = "00:11:22:33:44:cc"
IP = "192.168.4.70"


class Profiles:
    def __init__(self, profile=None, mac=MAC):
        self._m = {mac: profile} if profile else {}

    def get(self, mac):
        return self._m.get(mac)


def _make_printer(registry, mk):
    """Use the mDNS identification from #51 to get a real PRINTER role."""
    ev = replace(mk.dns(IP, PRINTER_MDNS, 900.0, mac=MAC), is_response=True)
    dev = registry.observe(ev)
    assert dev.role is DeviceRole.PRINTER, dev.role
    return dev


def test_external_destinations_do_not_fire(registry, config, mk):
    """Regression: 3,689 historical alerts were all external cloud traffic."""
    _make_printer(registry, mk)
    det = IdleDeviceExecDetector(config)
    from wyvern.detectors.base import DetectorContext, NullProfiles

    out = []
    for i, dst in enumerate(["17.253.127.142", "104.18.23.112", "18.238.132.5", "91.189.91.59"]):
        ev = mk.syn(IP, dst, 443, 1000.0 + i, mac=MAC, sport=40000 + i)
        registry.observe(ev)
        ctx = DetectorContext(config, registry, NullProfiles(), now=ev.ts)
        out += det.inspect(ev, ctx)
    assert out == [], "ordinary outbound internet traffic must not look like replication"


def test_novel_internal_destinations_still_fire(registry, config, mk):
    """The genuine worm signal — an idle device reaching LAN hosts — is preserved."""
    _make_printer(registry, mk)
    det = IdleDeviceExecDetector(config)
    from wyvern.detectors.base import DetectorContext, NullProfiles

    out = []
    for i, dst in enumerate(["192.168.4.10", "192.168.4.11", "192.168.4.12", "192.168.4.13"]):
        ev = mk.syn(IP, dst, 445, 1000.0 + i, mac=MAC, sport=40000 + i)
        registry.observe(ev)
        ctx = DetectorContext(config, registry, NullProfiles(), now=ev.ts)
        out += det.inspect(ev, ctx)
    assert len(out) == 1
    assert out[0].stage and "idle" in out[0].title.lower()


def test_known_internal_peers_do_not_fire(registry, config, mk):
    """A device talking to the LAN hosts it always talks to is not replicating."""
    _make_printer(registry, mk)
    det = IdleDeviceExecDetector(config)
    from wyvern.detectors.base import DetectorContext

    peers = ["192.168.4.10", "192.168.4.11", "192.168.4.12", "192.168.4.13"]
    profile = DeviceProfile(mac=MAC, learned=True, known_internal_peers=frozenset(peers))
    profiles = Profiles(profile)
    out = []
    for i, dst in enumerate(peers):
        ev = mk.syn(IP, dst, 445, 1000.0 + i, mac=MAC, sport=40000 + i)
        registry.observe(ev)
        ctx = DetectorContext(config, registry, profiles, now=ev.ts)
        out += det.inspect(ev, ctx)
    assert out == []


def test_unlearned_profile_still_fires(registry, config, mk):
    """No baseline yet must not blind the detector during the 24h window."""
    _make_printer(registry, mk)
    det = IdleDeviceExecDetector(config)
    from wyvern.detectors.base import DetectorContext

    profiles = Profiles(DeviceProfile(mac=MAC, learned=False))
    out = []
    for i, dst in enumerate(["192.168.4.20", "192.168.4.21", "192.168.4.22", "192.168.4.23"]):
        ev = mk.syn(IP, dst, 445, 1000.0 + i, mac=MAC, sport=40000 + i)
        registry.observe(ev)
        ctx = DetectorContext(config, registry, profiles, now=ev.ts)
        out += det.inspect(ev, ctx)
    assert len(out) == 1
