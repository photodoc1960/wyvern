"""Generate a synthetic Toronto-AI-worm propagation trace on a fake home LAN.

The scenario: a Windows workstation is patient-zero. It scans, moves laterally,
reuses SSH credentials, injects keys, and beacons to an external C2. The worm
then lands on the (normally-idle) network printer, which begins executing code,
proxies LLM inference to a compromised GPU host, and itself scans and spreads.

Nothing here is an attack — it is a deterministic list of fabricated events used
to demonstrate and test detection.
"""

from __future__ import annotations

from typing import List

from ..models.events import ArpEvent, ConnEvent, DnsEvent, HttpEvent, NetworkEvent

# (mac, ip, vendor-role) — vendors chosen so OUI lookup classifies them.
FAKE_HOME = {
    "router": ("24:a4:3c:00:00:01", "192.168.1.1"),
    "ws":     ("00:14:22:00:00:50", "192.168.1.50"),   # Dell / Windows (patient zero)
    "laptop": ("00:1b:21:00:00:51", "192.168.1.51"),   # Intel / benign
    "gpu":    ("00:04:4b:00:00:99", "192.168.1.99"),   # NVIDIA / inference host
    "printer": ("00:80:77:00:00:30", "192.168.1.30"),  # Brother / idle (Gen-1)
    "camera": ("44:19:b6:00:00:31", "192.168.1.31"),   # Hikvision
    "nas":    ("00:11:32:00:00:40", "192.168.1.40"),   # Synology
    "sensor": ("24:0a:c4:00:00:60", "192.168.1.60"),   # Espressif / IoT
}
_IP_MAC = {ip: mac for mac, ip in FAKE_HOME.values()}
# generic internal targets (unknown vendor, locally-administered MACs)
_TARGETS = [(f"02:00:00:00:00:{i:02x}", f"192.168.1.{i}") for i in range(10, 23)]
for _mac, _ip in _TARGETS:
    _IP_MAC[_ip] = _mac

C2_IP = "203.0.113.7"
_BENIGN_DOMAINS = ["example.com", "update.microsoft.com", "cdn.cloudflare.net", "pool.ntp.org"]
_DGA_DOMAINS = ["kq3z9x1m7wp4t.net", "v8b2n6q1z9x7c.info"]


class _Clock:
    def __init__(self, start: float) -> None:
        self.t = start

    def tick(self, dt: float = 0.2) -> float:
        self.t += dt
        return self.t


def _syn(src_ip, dst_ip, dport, ts, *, ttl=64, sport=44000) -> ConnEvent:
    return ConnEvent(
        ts=ts, src_ip=src_ip, dst_ip=dst_ip, dst_port=dport, src_port=sport,
        src_mac=_IP_MAC.get(src_ip), dst_mac=_IP_MAC.get(dst_ip), flags="S", ttl=ttl,
        window=64240,
    )


def _synack(src_ip, dst_ip, sport, ts, *, ttl=64) -> ConnEvent:
    return ConnEvent(
        ts=ts, src_ip=src_ip, dst_ip=dst_ip, dst_port=44000, src_port=sport,
        src_mac=_IP_MAC.get(src_ip), dst_mac=_IP_MAC.get(dst_ip), flags="SA", ttl=ttl,
    )


def _arp(ip, ts) -> ArpEvent:
    return ArpEvent(ts=ts, src_mac=_IP_MAC[ip], src_ip=ip, op=2)


def _dns(src_ip, qname, ts) -> DnsEvent:
    return DnsEvent(ts=ts, src_ip=src_ip, src_mac=_IP_MAC.get(src_ip), qname=qname, qtype="A")


def _infer(src_ip, ts) -> HttpEvent:
    return HttpEvent(
        ts=ts, src_ip=src_ip, dst_ip=FAKE_HOME["gpu"][1], dst_port=8000,
        method="POST", path="/v1/chat/completions", host="vllm-node",
        src_mac=_IP_MAC.get(src_ip),
    )


def worm_scenario(start_ts: float = 1_000_000.0) -> List[NetworkEvent]:
    """Return a time-ordered list of events depicting the worm's spread."""
    ev: List[NetworkEvent] = []
    clk = _Clock(start_ts)
    ws = FAKE_HOME["ws"][1]
    printer = FAKE_HOME["printer"][1]
    gpu = FAKE_HOME["gpu"][1]

    # --- Phase 0: device discovery + benign baseline ---------------------
    for ip in [mac_ip[1] for mac_ip in FAKE_HOME.values()]:
        ev.append(_arp(ip, clk.tick()))
    for mac, ip in _TARGETS:
        ev.append(_arp(ip, clk.tick()))
    # printer & gpu advertise their services; benign hosts browse the web
    ev.append(_synack(printer, ws, 9100, clk.tick()))
    ev.append(_synack(gpu, ws, 8000, clk.tick()))
    for _ in range(3):
        for ip in (ws, FAKE_HOME["laptop"][1]):
            ev.append(_dns(ip, _BENIGN_DOMAINS[_ % len(_BENIGN_DOMAINS)] if False else _BENIGN_DOMAINS[0], clk.tick()))
            ev.append(_syn(ip, "93.184.216.34", 443, clk.tick(), ttl=128, sport=51000))

    # --- Phase 1: workstation (patient zero) goes active -----------------
    # reconnaissance: 60-port scan of one host
    for port in range(1, 61):
        ev.append(_syn(ws, "192.168.1.10", port, clk.tick(0.05), ttl=128))
    # lateral movement: 12 internal hosts on SMB
    for _mac, ip in _TARGETS[:12]:
        ev.append(_syn(ws, ip, 445, clk.tick(0.3), ttl=128))
    # credential reuse + SSH key propagation: SSH to several hosts
    for _mac, ip in _TARGETS[:6]:
        ev.append(_syn(ws, ip, 22, clk.tick(0.3), ttl=128))
    # a couple of DGA lookups
    for d in _DGA_DOMAINS:
        ev.append(_dns(ws, d, clk.tick()))
    # beacon to external C2 on a non-standard port, regular cadence
    beacon_t = clk.t + 5
    for i in range(8):
        ev.append(_syn(ws, C2_IP, 4444, beacon_t + i * 60, ttl=128, sport=50000 + i))
    clk.t = beacon_t + 8 * 60

    # --- Phase 2: worm lands on the printer (idle device) ----------------
    for port in range(1, 61):
        ev.append(_syn(printer, FAKE_HOME["camera"][1], port, clk.tick(0.05)))
    for _mac, ip in _TARGETS[:12]:
        ev.append(_syn(printer, ip, 445, clk.tick(0.3)))
    for _mac, ip in _TARGETS[:5]:
        ev.append(_syn(printer, ip, 22, clk.tick(0.3)))
    # the printer proxies LLM inference to the compromised GPU host
    for _ in range(8):
        ev.append(_infer(printer, clk.tick(0.5)))
    # printer beacons too
    bt = clk.t + 5
    for i in range(7):
        ev.append(_syn(printer, C2_IP, 4444, bt + i * 60, sport=50100 + i))
    clk.t = bt + 7 * 60

    ev.sort(key=lambda e: e.ts)
    return ev


# --------------------------------------------------------------------------- #
# Optional pcap output — uses scapy to craft real frames from the same events. #
# --------------------------------------------------------------------------- #
def _events_to_packets(events: List[NetworkEvent]):
    from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Ether, Raw  # lazy

    ROUTER = FAKE_HOME["router"][0]
    packets = []
    for e in events:
        if isinstance(e, ArpEvent):
            pkt = Ether(src=e.src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=e.op, hwsrc=e.src_mac, psrc=e.src_ip,
                pdst=e.dst_ip or e.src_ip,
            )
        elif isinstance(e, ConnEvent) and e.proto == "tcp":
            pkt = Ether(src=e.src_mac or ROUTER, dst=e.dst_mac or ROUTER) / IP(
                src=e.src_ip, dst=e.dst_ip, ttl=e.ttl or 64
            ) / TCP(sport=e.src_port or 40000, dport=e.dst_port, flags=e.flags or "S")
        elif isinstance(e, DnsEvent):
            pkt = Ether(src=e.src_mac or ROUTER, dst=ROUTER) / IP(
                src=e.src_ip, dst="192.168.1.1"
            ) / UDP(sport=51000, dport=53) / DNS(rd=1, qd=DNSQR(qname=e.qname))
        elif isinstance(e, HttpEvent):
            body = (
                f"{e.method or 'GET'} {e.path or '/'} HTTP/1.1\r\n"
                f"Host: {e.host or e.dst_ip}\r\nUser-Agent: wyvern-sim\r\n\r\n"
            ).encode()
            pkt = Ether(src=e.src_mac or ROUTER, dst=_IP_MAC.get(e.dst_ip, ROUTER)) / IP(
                src=e.src_ip, dst=e.dst_ip
            ) / TCP(sport=40000, dport=e.dst_port, flags="PA") / Raw(load=body)
        else:
            continue
        pkt.time = e.ts
        packets.append(pkt)
    return packets


def write_pcap(path: str, events: List[NetworkEvent] | None = None) -> int:
    """Write the scenario to a pcap file. Returns the number of packets."""
    from scapy.all import wrpcap  # lazy

    events = events if events is not None else worm_scenario()
    packets = _events_to_packets(events)
    wrpcap(path, packets)
    return len(packets)
