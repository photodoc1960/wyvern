"""Alert delivery: desktop notifications and optional email digests."""

from __future__ import annotations

from .notifier import Notifier, build_notifier

__all__ = ["Notifier", "build_notifier"]
