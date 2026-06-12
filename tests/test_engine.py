"""Tests for the engine: event bus, monitor orchestration, and pcap replay."""

from __future__ import annotations

import queue

import pytest

from wyvern.config import Config
from wyvern.engine.bus import EventBus
from wyvern.engine.monitor import Monitor
from wyvern.simulate.worm_trace import worm_scenario, write_pcap
from wyvern.storage.db import WyvernDB


def test_event_bus_pub_sub_and_drop():
    bus = EventBus(maxsize=2)
    q = bus.subscribe()
    assert bus.subscriber_count == 1
    bus.publish("a")
    bus.publish("b")
    bus.publish("c")  # full -> oldest dropped
    items = [q.get_nowait() for _ in range(2)]
    assert items[-1] == "c"
    with __import__("pytest").raises(queue.Empty):
        q.get_nowait()
    bus.unsubscribe(q)
    assert bus.subscriber_count == 0


def test_event_bus_subscriber_cap():
    bus = EventBus(max_subscribers=2)
    bus.subscribe()
    bus.subscribe()
    with pytest.raises(RuntimeError):
        bus.subscribe()


def _mon(tmp_path):
    cfg = Config(data_dir=str(tmp_path)).validate()
    return Monitor(cfg, learn=False, db=WyvernDB(":memory:"))


def test_monitor_feed_and_views(tmp_path):
    mon = _mon(tmp_path)
    mon.feed_events(worm_scenario())
    assert mon.event_count > 0
    assert mon.devices() and mon.topology()["nodes"]
    stats = mon.stats()
    assert stats["overall_level"] == "Critical"
    assert mon.recent_alerts(limit=5)
    assert mon.mark_suspicious("192.168.1.30", True)


def test_monitor_publishes_to_bus(tmp_path):
    mon = _mon(tmp_path)
    q = mon.bus.subscribe()
    mon.feed_events(worm_scenario())
    msgs = []
    try:
        while True:
            msgs.append(q.get_nowait())
    except queue.Empty:
        pass
    kinds = {m["type"] for m in msgs}
    assert "alert" in kinds and "assessment" in kinds


def test_replay_pcap_round_trip(tmp_path):
    pcap = str(tmp_path / "s.pcap")
    n = write_pcap(pcap, worm_scenario())
    assert n > 0
    mon = _mon(tmp_path)
    count = mon.replay(pcap, realtime=False)
    assert count == n
    assert mon.current_assessment().overall_level.label == "Critical"
