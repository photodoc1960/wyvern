"""Data types for the Tier-1 response layer (issue #29).

All records are immutable; lifecycle transitions produce a new record via
:func:`dataclasses.replace` (see :mod:`wyvern.response.store`). Statuses are
plain string constants so they serialise cleanly to the DB/dashboard later.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


class Decision:
    """The outcome of :meth:`ResponseEngine.evaluate` for one alert."""

    IGNORED = "ignored"  # not a worm verdict / below threshold / no target
    SUPPRESSED_ALLOWLIST = "suppressed_allowlist"  # target is a protected asset
    SUPPRESSED_RATELIMIT = "suppressed_ratelimit"  # circuit breaker tripped
    PROPOSED = "proposed"  # eligible; observe/auto mode recorded (Phase 0: not enforced)
    PENDING = "pending"  # eligible; confirm mode — awaiting human approval


class QState:
    """Lifecycle of a quarantine record."""

    PROPOSED = "proposed"
    PENDING = "pending"
    ACTIVE = "active"  # enforced (Phase 1+)
    FAILED = "failed"  # responder attempted but the action did not apply
    EXPIRED = "expired"
    RELEASED = "released"


def new_id() -> str:
    return uuid.uuid4().hex[:12]


@dataclass(frozen=True, slots=True)
class QuarantineRecord:
    target: str  # the host key (MAC preferred, else IP)
    status: str
    reason: str
    mode: str
    proposed_at: float
    expires_at: float
    alert_id: str | None = None
    stage_count: int | None = None
    released_at: float | None = None
    ip: str | None = None  # for responders that act on an IP
    mac: str | None = None  # for responders that act on a MAC
    id: str = field(default_factory=new_id)

    def to_row(self) -> dict[str, Any]:
        """Flat, primitive mapping for DB persistence."""
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "reason": self.reason,
            "mode": self.mode,
            "proposed_at": self.proposed_at,
            "expires_at": self.expires_at,
            "alert_id": self.alert_id,
            "stage_count": self.stage_count,
            "released_at": self.released_at,
            "ip": self.ip,
            "mac": self.mac,
        }

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> QuarantineRecord:
        return cls(
            id=row["id"],
            target=row["target"],
            status=row["status"],
            reason=row["reason"],
            mode=row["mode"],
            proposed_at=row["proposed_at"],
            expires_at=row["expires_at"],
            alert_id=row.get("alert_id"),
            stage_count=row.get("stage_count"),
            released_at=row.get("released_at"),
            ip=row.get("ip"),
            mac=row.get("mac"),
        )


@dataclass(frozen=True, slots=True)
class ResponseDecision:
    status: str
    target: str | None = None
    eligible: bool = False  # passed every gate (a real action candidate)
    enforced: bool = False  # actually enforced — ALWAYS False in Phase 0
    reason: str = ""
    record: QuarantineRecord | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
