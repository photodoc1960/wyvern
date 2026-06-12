"""Forensic exporters — bundle the evidence for offline analysis."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .. import __version__

_CSV_FIELDS = [
    "ts",
    "id",
    "detector",
    "severity_label",
    "confidence",
    "stage",
    "src_mac",
    "src_ip",
    "dst_ip",
    "dst_port",
    "title",
    "description",
]


def export_forensic_bundle(
    path: str,
    *,
    devices: list[dict],
    alerts: list[dict],
    assessment: dict | None,
    generated_at: float,
) -> str:
    """Write a single JSON evidence bundle (devices + alerts + assessment)."""
    bundle = {
        "tool": "wyvern",
        "version": __version__,
        "generated_at": generated_at,
        "device_count": len(devices),
        "alert_count": len(alerts),
        "assessment": assessment,
        "devices": devices,
        "alerts": alerts,
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
    return str(target)


def export_alerts_csv(path: str, alerts: list[dict]) -> str:
    """Write alerts as CSV for spreadsheet / SIEM ingestion."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for alert in alerts:
            writer.writerow({k: alert.get(k, "") for k in _CSV_FIELDS})
    return str(target)
