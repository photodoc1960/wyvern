"""Append-only JSONL alert log for forensic analysis.

One JSON object per line, append-only, flushed on write. Being append-only and
separate from the SQLite store, it provides a tamper-evident timeline an analyst
can grep, diff, or feed into other tools.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from ..models.alert import Alert


class EventLog:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        Path(path).parent.mkdir(parents=True, exist_ok=True)

    def append_alert(self, alert: Alert) -> None:
        self.append({"type": "alert", **alert.to_dict()})

    def append(self, record: dict) -> None:
        line = json.dumps(record, separators=(",", ":"))
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def read_all(self) -> list[dict]:
        out: list[dict] = []
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return []
        return out
