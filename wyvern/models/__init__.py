"""Immutable domain models for Wyvern."""

from __future__ import annotations

from .alert import Alert, Severity, new_alert_id
from .device import (
    Device,
    DeviceRole,
    GPU_PLAUSIBLE_ROLES,
    IDLE_ROLES,
)
from .events import (
    ArpEvent,
    ConnEvent,
    DhcpEvent,
    DnsEvent,
    HttpEvent,
    NetworkEvent,
)
from .profile import DeviceProfile

__all__ = [
    "Alert",
    "Severity",
    "new_alert_id",
    "Device",
    "DeviceRole",
    "IDLE_ROLES",
    "GPU_PLAUSIBLE_ROLES",
    "ArpEvent",
    "ConnEvent",
    "DnsEvent",
    "HttpEvent",
    "DhcpEvent",
    "NetworkEvent",
    "DeviceProfile",
]
