"""Persist and load learned baselines as JSON.

Persistence lets the 24-hour learning survive restarts: on startup the engine
loads saved profiles and seeds the learner so detection benefits from prior
"normal" immediately.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from ..models.profile import DeviceProfile


def save_baselines(profiles: dict[str, DeviceProfile], path: str) -> None:
    """Atomically write profiles to ``path`` (temp file + rename)."""
    payload = {
        "version": 1,
        "profiles": [p.to_dict() for p in profiles.values()],
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".baselines-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, target)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_baselines(path: str) -> dict[str, DeviceProfile]:
    """Load profiles from ``path``; return ``{}`` if missing or unreadable."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    profiles: dict[str, DeviceProfile] = {}
    for entry in data.get("profiles", []):
        try:
            profile = DeviceProfile.from_dict(entry)
        except (KeyError, TypeError, ValueError):
            continue
        profiles[profile.mac] = profile
    return profiles
