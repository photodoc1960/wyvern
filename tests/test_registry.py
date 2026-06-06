"""Tests for device tracking and passive fingerprinting."""

from __future__ import annotations

from wyvern.models.device import DeviceRole


def test_classifies_printer_from_oui(registry, mk):
    registry.observe(mk.arp("00:80:77:aa:bb:cc", "192.168.1.30", 1.0))
    d = registry.get("00:80:77:aa:bb:cc")
    assert d.role is DeviceRole.PRINTER and d.vendor == "Brother"
    assert not d.gpu_capable


def test_windows_workstation_ttl(registry, mk):
    registry.observe(mk.syn("192.168.1.50", "192.168.1.10", 445, 1.0,
                            mac="00:14:22:00:00:50", ttl=128))
    d = registry.get_by_ip("192.168.1.50")
    assert d.os_guess == "Windows" and d.role is DeviceRole.WORKSTATION


def test_open_ports_from_synack(registry, mk):
    registry.observe(mk.synack("192.168.1.10", "192.168.1.50", 22, 1.0,
                               mac="00:1b:21:00:00:10"))
    d = registry.get_by_ip("192.168.1.10")
    assert 22 in d.open_ports


def test_inference_server_marked_gpu(registry, mk):
    registry.observe(mk.infer("192.168.1.30", "192.168.1.99", 1.0,
                              mac="00:80:77:aa:bb:cc"))
    gpu = registry.get_by_ip("192.168.1.99")
    assert gpu.role is DeviceRole.GPU_HOST and gpu.gpu_capable


def test_no_duplicate_for_l3_only_peer(registry, mk):
    # workstation known by MAC; a later flow references it only by IP as dst
    registry.observe(mk.syn("192.168.1.50", "192.168.1.10", 80, 1.0, mac="00:14:22:00:00:50"))
    registry.observe(mk.syn("192.168.1.51", "192.168.1.50", 80, 2.0, mac="02:00:00:00:00:51"))
    # .50 still a single device keyed by its real MAC
    macs = [d.mac for d in registry.all() if d.ip == "192.168.1.50"]
    assert macs == ["00:14:22:00:00:50"]


def test_mark_suspicious(registry, mk):
    registry.observe(mk.arp("00:80:77:aa:bb:cc", "192.168.1.30", 1.0))
    assert registry.mark_suspicious("192.168.1.30", True)
    assert registry.get("00:80:77:aa:bb:cc").suspicious
    assert not registry.mark_suspicious("192.168.1.250", True)   # unknown


def test_device_cap_evicts_oldest(registry, mk, monkeypatch):
    import wyvern.tracking.registry as R
    monkeypatch.setattr(R, "_MAX_DEVICES", 3)
    for i in range(5):
        registry.observe(mk.arp(f"02:00:00:00:00:0{i}", f"192.168.1.{10 + i}", float(i)))
    assert len(registry.all()) <= 3
    assert registry.get("02:00:00:00:00:04") is not None      # newest survives
    assert registry.get("02:00:00:00:00:00") is None          # oldest evicted


def test_dhcp_hostname_classifies(registry, mk):
    registry.observe(mk.dhcp("02:11:22:33:44:55", "192.168.1.77", 1.0, hostname="synology-nas"))
    d = registry.get_by_ip("192.168.1.77")
    assert d.hostname == "synology-nas" and d.role is DeviceRole.NAS
