"""Tests for the Flask dashboard API."""

from __future__ import annotations

import pytest

from wyvern.config import Config
from wyvern.engine.monitor import Monitor
from wyvern.simulate.worm_trace import worm_scenario
from wyvern.storage.db import WyvernDB
from wyvern.web.app import create_app


@pytest.fixture
def client(tmp_path):
    cfg = Config(data_dir=str(tmp_path)).validate()
    mon = Monitor(cfg, learn=False, db=WyvernDB(":memory:"))
    mon.feed_events(worm_scenario())
    return create_app(mon).test_client()


@pytest.mark.parametrize(
    "ep",
    [
        "/api/stats",
        "/api/devices",
        "/api/alerts",
        "/api/topology",
        "/api/assessment",
        "/healthz",
        "/",
    ],
)
def test_endpoints_ok(client, ep):
    assert client.get(ep).status_code == 200


def test_topology_has_worm_edges(client):
    topo = client.get("/api/topology").get_json()
    assert topo["nodes"] and any(e["worm"] for e in topo["edges"])


def test_assessment_is_critical(client):
    data = client.get("/api/assessment").get_json()
    assert data["overall_level_label"] == "Critical"
    assert data["likely_compromised"]


def test_mark_suspicious_and_404(client):
    ok = client.post("/api/devices/192.168.1.30/suspicious", json={"value": True})
    assert ok.get_json()["ok"]
    missing = client.post("/api/devices/10.0.0.254/suspicious", json={"value": True})
    assert missing.status_code == 404


def test_export_json_and_csv(client):
    j = client.get("/api/export?format=json")
    assert j.status_code == 200 and b"alerts" in j.data
    c = client.get("/api/export?format=csv")
    assert c.status_code == 200 and b"detector" in c.data
