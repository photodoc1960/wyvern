"""SQLite-backed store for devices and alerts.

A single connection guarded by a lock (the write path is the capture thread; the
read path is the Flask dashboard). Schema is created on connect; all writes are
parameterised (no string interpolation) per the project's SQL-safety rules.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Iterable, Optional

from ..models.alert import Alert, Severity
from ..models.device import Device

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    detector    TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    confidence  REAL NOT NULL,
    src_mac     TEXT,
    src_ip      TEXT,
    dst_ip      TEXT,
    dst_port    INTEGER,
    stage       TEXT,
    description TEXT,
    recommendations TEXT,
    evidence    TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_mac, src_ip);
CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT,
    vendor      TEXT,
    hostname    TEXT,
    role        TEXT,
    os_guess    TEXT,
    gpu_capable INTEGER,
    suspicious  INTEGER,
    open_ports  TEXT,
    first_seen  REAL,
    last_seen   REAL
);
"""


class WyvernDB:
    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.commit()

    # ------------------------------------------------------------- writes
    def insert_alert(self, alert: Alert) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO alerts (id, ts, detector, title, severity, "
                "confidence, src_mac, src_ip, dst_ip, dst_port, stage, description, "
                "recommendations, evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    alert.id, alert.ts, alert.detector, alert.title, int(alert.severity),
                    alert.confidence, alert.src_mac, alert.src_ip, alert.dst_ip,
                    alert.dst_port, alert.stage, alert.description,
                    json.dumps(list(alert.recommendations)),
                    json.dumps(dict(alert.evidence)),
                ),
            )
            self._conn.commit()

    def upsert_device(self, device: Device) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO devices (mac, ip, vendor, hostname, role, "
                "os_guess, gpu_capable, suspicious, open_ports, first_seen, last_seen) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    device.mac, device.ip, device.vendor, device.hostname,
                    device.role.value, device.os_guess, int(device.gpu_capable),
                    int(device.suspicious), json.dumps(list(device.open_ports)),
                    device.first_seen, device.last_seen,
                ),
            )
            self._conn.commit()

    # ------------------------------------------------------------- reads
    def recent_alerts(self, limit: int = 200, since: Optional[float] = None) -> list[dict]:
        query = "SELECT * FROM alerts"
        params: list = []
        if since is not None:
            query += " WHERE ts >= ?"
            params.append(since)
        query += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._alert_row(r) for r in rows]

    def alerts_for(self, key: str, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM alerts WHERE src_mac = ? OR src_ip = ? "
                "ORDER BY ts DESC LIMIT ?",
                (key, key, limit),
            ).fetchall()
        return [self._alert_row(r) for r in rows]

    def all_alerts(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM alerts ORDER BY ts ASC").fetchall()
        return [self._alert_row(r) for r in rows]

    def all_devices(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM devices ORDER BY last_seen DESC"
            ).fetchall()
        return [self._device_row(r) for r in rows]

    def stats(self) -> dict:
        with self._lock:
            n_dev = self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            n_alert = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            by_sev = dict(
                self._conn.execute(
                    "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
                ).fetchall()
            )
        return {
            "devices": n_dev,
            "alerts": n_alert,
            "alerts_by_severity": {Severity(k).label: v for k, v in by_sev.items()},
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _alert_row(row: sqlite3.Row) -> dict:
        data = dict(row)
        data["severity_label"] = Severity(data["severity"]).label
        data["recommendations"] = _loads(data.get("recommendations"), [])
        data["evidence"] = _loads(data.get("evidence"), {})
        return data

    @staticmethod
    def _device_row(row: sqlite3.Row) -> dict:
        data = dict(row)
        data["gpu_capable"] = bool(data.get("gpu_capable"))
        data["suspicious"] = bool(data.get("suspicious"))
        data["open_ports"] = _loads(data.get("open_ports"), [])
        return data


def _loads(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default
