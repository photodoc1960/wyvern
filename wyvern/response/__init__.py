"""Tier-1 active-response layer (issue #29).

Phase 0 is observe-only: it decides and records what Wyvern *would* do, and
enforces nothing. Responders (firewall / VLAN quarantine / DNS sinkhole) arrive
in later phases behind the same safety gates.
"""

from __future__ import annotations

from .engine import ResponseEngine, build_response_engine
from .models import Decision, QState, QuarantineRecord, ResponseDecision
from .store import QuarantineStore

__all__ = [
    "ResponseEngine",
    "build_response_engine",
    "QuarantineStore",
    "QuarantineRecord",
    "ResponseDecision",
    "Decision",
    "QState",
]
