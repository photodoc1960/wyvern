"""Tests for the Prometheus /metrics endpoint."""

from __future__ import annotations

from wyvern.config import Config
from wyvern.engine.monitor import Monitor
from wyvern.simulate.worm_trace import worm_scenario
from wyvern.storage.db import WyvernDB
from wyvern.web.app import create_app


def _client(tmp_path):
    cfg = Config(data_dir=str(tmp_path)).validate()
    mon = Monitor(cfg, learn=False, db=WyvernDB(":memory:"))
    mon.feed_events(worm_scenario())
    return create_app(mon).test_client()


def test_metrics_exposition(tmp_path):
    r = _client(tmp_path).get("/metrics")
    assert r.status_code == 200
    assert r.mimetype == "text/plain"
    body = r.get_data(as_text=True)
    assert "wyvern_up 1" in body
    assert "# TYPE wyvern_devices gauge" in body
    assert "wyvern_threat_level 4" in body                       # Critical
    assert "wyvern_worm_suspects 2" in body
    assert 'wyvern_alerts_by_severity{severity="Critical"}' in body
    assert "wyvern_device_threat_score{" in body


def test_metrics_label_escaping(tmp_path):
    # device labels are network-derived; ensure they're rendered as valid samples
    body = _client(tmp_path).get("/metrics").get_data(as_text=True)
    for line in body.splitlines():
        if line.startswith("wyvern_device_threat_score{"):
            assert line.count('"') % 2 == 0      # balanced quotes
