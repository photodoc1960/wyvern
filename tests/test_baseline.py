"""Tests for the baseline learner and its persistence."""

from __future__ import annotations

from wyvern.baseline.learner import BaselineLearner
from wyvern.baseline.store import load_baselines, save_baselines
from wyvern.config import Config
from wyvern.tracking.registry import DeviceRegistry


def _short_cfg():
    return Config(learning_window_hours=2.0 / 3600.0).validate()  # 2-second window


def test_learns_after_window():
    cfg = _short_cfg()
    reg = DeviceRegistry(cfg)
    learner = BaselineLearner(cfg)
    from wyvern.models.events import ConnEvent

    for i in range(15):
        ev = ConnEvent(
            ts=100.0 + i,
            src_ip="192.168.1.50",
            dst_ip="192.168.1.10",
            dst_port=443,
            src_mac="00:14:22:00:00:50",
            flags="S",
            ttl=128,
        )
        reg.observe(ev)
        learner.observe(ev, reg)
    p = learner.get("00:14:22:00:00:50")
    assert p.learned and 443 in p.known_ports
    assert "192.168.1.10" in p.known_internal_peers
    assert not p.ever_inference


def test_tracks_inference_and_auth_fanout():
    cfg = _short_cfg()
    reg = DeviceRegistry(cfg)
    learner = BaselineLearner(cfg)
    from wyvern.models.events import ConnEvent, HttpEvent

    reg.observe(
        ConnEvent(
            ts=1,
            src_ip="192.168.1.50",
            dst_ip="192.168.1.99",
            dst_port=443,
            src_mac="00:14:22:00:00:50",
            flags="S",
        )
    )
    learner.observe(
        HttpEvent(
            ts=2,
            src_ip="192.168.1.50",
            dst_ip="192.168.1.99",
            dst_port=8000,
            method="POST",
            path="/v1/chat/completions",
            src_mac="00:14:22:00:00:50",
        ),
        reg,
    )
    for h in range(10, 17):
        ev = ConnEvent(
            ts=3 + h,
            src_ip="192.168.1.50",
            dst_ip=f"192.168.1.{h}",
            dst_port=22,
            src_mac="00:14:22:00:00:50",
            flags="S",
        )
        reg.observe(ev)
        learner.observe(ev, reg)
    p = learner.get("00:14:22:00:00:50")
    assert p.ever_inference and p.ever_auth_fanout


def test_persistence_round_trip(tmp_path):
    cfg = _short_cfg()
    reg = DeviceRegistry(cfg)
    learner = BaselineLearner(cfg)
    from wyvern.models.events import ConnEvent

    for i in range(12):
        ev = ConnEvent(
            ts=i,
            src_ip="192.168.1.50",
            dst_ip="192.168.1.10",
            dst_port=80,
            src_mac="00:14:22:00:00:50",
            flags="S",
        )
        reg.observe(ev)
        learner.observe(ev, reg)
    path = str(tmp_path / "bl.json")
    save_baselines(learner.snapshot(), path)
    loaded = load_baselines(path)
    assert "00:14:22:00:00:50" in loaded

    learner2 = BaselineLearner(cfg)
    learner2.seed(loaded)
    p = learner2.get("00:14:22:00:00:50")
    assert p.learned and 80 in p.known_ports


def test_missing_baseline_file_is_empty(tmp_path):
    assert load_baselines(str(tmp_path / "nope.json")) == {}
