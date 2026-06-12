"""Tests for SQLite storage, the JSONL event log, and exporters."""

from __future__ import annotations

import json

from wyvern.models.alert import Alert, Severity
from wyvern.models.device import Device, DeviceRole
from wyvern.storage.db import WyvernDB
from wyvern.storage.eventlog import EventLog
from wyvern.storage.export import export_alerts_csv, export_forensic_bundle


def _alert(**kw):
    base = {
        "detector": "beacon",
        "title": "Beacon",
        "severity": Severity.CRITICAL,
        "confidence": 0.9,
        "description": "d",
        "src_ip": "192.168.1.30",
        "src_mac": "00:80:77:aa:bb:cc",
        "stage": "beacon_callback",
        "recommendations": ("Isolate it",),
        "evidence": {"dst_port": 4444},
        "ts": 10.0,
    }
    base.update(kw)
    return Alert(**base)


def test_db_insert_and_read():
    db = WyvernDB(":memory:")
    db.insert_alert(_alert())
    rows = db.recent_alerts()
    assert len(rows) == 1
    assert rows[0]["recommendations"] == ["Isolate it"]
    assert rows[0]["evidence"]["dst_port"] == 4444
    assert rows[0]["severity_label"] == "Critical"


def test_db_device_and_stats():
    db = WyvernDB(":memory:")
    db.upsert_device(
        Device(
            mac="00:80:77:aa:bb:cc",
            ip="192.168.1.30",
            role=DeviceRole.PRINTER,
            open_ports=(9100,),
            suspicious=True,
        )
    )
    db.insert_alert(_alert())
    db.insert_alert(_alert(severity=Severity.LOW, id="other"))
    devs = db.all_devices()
    assert devs[0]["suspicious"] is True and devs[0]["open_ports"] == [9100]
    s = db.stats()
    assert s["devices"] == 1 and s["alerts"] == 2
    assert s["alerts_by_severity"]["Critical"] == 1


def test_db_alerts_for_key():
    db = WyvernDB(":memory:")
    db.insert_alert(_alert())
    db.insert_alert(_alert(id="x2", src_ip="192.168.1.99", src_mac="00:04:4b:00:00:01"))
    assert len(db.alerts_for("192.168.1.30")) == 1
    assert len(db.alerts_for("00:04:4b:00:00:01")) == 1


def test_eventlog_round_trip(tmp_path):
    log = EventLog(str(tmp_path / "events.jsonl"))
    log.append_alert(_alert())
    log.append_alert(_alert(id="x2"))
    records = log.read_all()
    assert len(records) == 2 and records[0]["type"] == "alert"


def test_exporters(tmp_path):
    alerts = [_alert().to_dict()]
    devices = [Device(mac="m", ip="192.168.1.30").to_dict()]
    csv_path = export_alerts_csv(str(tmp_path / "a.csv"), alerts)
    assert "beacon" in open(csv_path).read()
    bundle_path = export_forensic_bundle(
        str(tmp_path / "b.json"),
        devices=devices,
        alerts=alerts,
        assessment={"overall_level_label": "Critical"},
        generated_at=1.0,
    )
    data = json.load(open(bundle_path))
    assert data["alert_count"] == 1 and data["tool"] == "wyvern"
