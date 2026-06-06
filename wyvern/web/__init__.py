"""Flask dashboard for Wyvern."""

from __future__ import annotations

from .app import create_app, run_dashboard

__all__ = ["create_app", "run_dashboard"]
