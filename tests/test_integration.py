"""End-to-end integration: the synthetic worm trace must be caught."""

from __future__ import annotations

import json

from wyvern.config import Config
from wyvern.engine.monitor import Monitor
from wyvern.simulate.worm_trace import worm_scenario
from wyvern.storage.db import WyvernDB
from wyvern.storage.export import export_forensic_bundle


def _monitor(tmp_path):
    cfg = Config(data_dir=str(tmp_path)).validate()
    return Monitor(cfg, learn=False, db=WyvernDB(":memory:"))


def test_scenario_raises_critical_worm_verdict(tmp_path):
    mon = _monitor(tmp_path)
    events = worm_scenario()
    mon.feed_events(events)

    assessment = mon.current_assessment()
    assert assessment.overall_level.label == "Critical"
    suspects = {t.ip for t in assessment.device_threats if t.is_worm_suspect}
    # patient-zero workstation and the printer should both be flagged
    assert "192.168.1.50" in suspects
    assert "192.168.1.30" in suspects
    assert assessment.likely_compromised


def test_scenario_detectors_cover_all_stages(tmp_path):
    mon = _monitor(tmp_path)
    mon.feed_events(worm_scenario())
    stages = {a["stage"] for a in mon.recent_alerts(limit=500) if a["stage"]}
    for expected in ("discovery", "lateral_movement", "credential_reuse",
                     "ssh_key_injection", "inference_proxy", "beacon_callback",
                     "idle_device_exec", "worm"):
        assert expected in stages, f"missing stage {expected}"


def test_dashboard_and_export_data(tmp_path):
    mon = _monitor(tmp_path)
    mon.feed_events(worm_scenario())

    devices = mon.devices()
    assert devices and any(d["worm_suspect"] for d in devices)
    topo = mon.topology()
    assert topo["nodes"] and topo["edges"]
    # a worm-service edge should be marked
    assert any(e["worm"] for e in topo["edges"])

    out = export_forensic_bundle(
        str(tmp_path / "f.json"), devices=mon.db.all_devices(),
        alerts=mon.db.all_alerts(), assessment=mon.current_assessment().to_dict(),
        generated_at=1.0)
    data = json.load(open(out))
    assert data["alert_count"] > 0


def test_mark_suspicious_through_monitor(tmp_path):
    mon = _monitor(tmp_path)
    mon.feed_events(worm_scenario())
    assert mon.mark_suspicious("192.168.1.30", True)
    dev = mon.registry.get_by_ip("192.168.1.30")
    assert dev.suspicious
