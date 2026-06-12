"""Tests for configuration loading, validation and secret handling."""

from __future__ import annotations

import pytest

from wyvern.config import Config, ConfigError, NotifyConfig, Thresholds


def test_default_is_valid():
    cfg = Config.default()
    assert cfg.thresholds.scan_ports == 50
    assert cfg.db_path.endswith("wyvern.db")
    assert cfg.baseline_path.endswith("baselines.json")


def test_invalid_cidr_rejected():
    with pytest.raises(ConfigError):
        Config(internal_cidrs=("not-a-cidr",)).validate()


def test_invalid_thresholds_rejected():
    with pytest.raises(ConfigError):
        Thresholds(scan_ports=0).validate()
    with pytest.raises(ConfigError):
        Thresholds(worm_stages_critical=1, worm_stages_high=3).validate()


def test_email_requires_complete_config():
    with pytest.raises(ConfigError):
        NotifyConfig(email_enabled=True).validate()


def test_from_dict_ignores_file_secret():
    cfg = Config.from_dict(
        {
            "internal_cidrs": ["10.1.0.0/16"],
            "notify": {"smtp_password": "should-be-ignored", "smtp_host": "x"},
            "thresholds": {"scan_ports": 25},
        }
    )
    assert cfg.notify.smtp_password is None  # never taken from file
    assert cfg.thresholds.scan_ports == 25
    assert cfg.internal_cidrs == ("10.1.0.0/16",)


def test_env_overrides_secret(monkeypatch):
    monkeypatch.setenv("WYVERN_SMTP_PASSWORD", "from-env")
    cfg = Config.from_dict({"notify": {"smtp_host": "x", "email_enabled": False}})
    assert cfg.notify.smtp_password == "from-env"


def test_env_overrides_web_and_iface(monkeypatch):
    monkeypatch.setenv("WYVERN_WEB_HOST", "0.0.0.0")
    monkeypatch.setenv("WYVERN_WEB_PORT", "9999")
    monkeypatch.setenv("WYVERN_INTERFACE", "br-lan")
    cfg = Config.from_dict({})
    assert cfg.web_host == "0.0.0.0"
    assert cfg.web_port == 9999
    assert cfg.interface == "br-lan"


def test_declared_gpu_host():
    cfg = Config(gpu_hosts=("192.168.1.99", "00:04:4b:00:00:01")).validate()
    assert cfg.is_declared_gpu_host("192.168.1.99", None)
    assert cfg.is_declared_gpu_host(None, "00:04:4B:00:00:01")
    assert not cfg.is_declared_gpu_host("192.168.1.5", None)


def test_from_file(tmp_path):
    p = tmp_path / "cfg.yaml"
    p.write_text("web_port: 9000\nthresholds:\n  lateral_peers: 7\n")
    cfg = Config.from_file(str(p))
    assert cfg.web_port == 9000 and cfg.thresholds.lateral_peers == 7
