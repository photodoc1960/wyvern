"""The Tier-1 response engine — Phase 0 (observe-only).

The engine turns a high-confidence worm verdict into a *decision*: whether Wyvern
would contain the offending host, and — from Phase 1 — driving a responder to do
it. Phase 0 builds the whole decision + safety layer but enforces **nothing**:
``ResponseDecision.enforced`` is always ``False`` here.

Safety gates, in order (see issue #29):
  1. Trigger only on the ``worm_signature`` composite verdict, at/above the
     configured severity — never a single detector.
  2. **Allowlist** — a protected asset (gateway/DNS/self/operator-declared) can
     never be actioned.
  3. **Circuit breaker** — cap actions per window; a storm halts (defends against
     a worm weaponising the response into a self-DoS).
Eligible verdicts are recorded (PROPOSED in observe/auto, PENDING in confirm) and
audit-logged; enforcement is wired in Phase 1.
"""

from __future__ import annotations

import logging
from collections import deque

from ..config import ResponsePolicy
from ..detectors.worm_signature import COMPOSITE_STAGE
from ..models.alert import Alert
from .models import Decision, QState, QuarantineRecord, ResponseDecision
from .store import QuarantineStore

log = logging.getLogger("wyvern.response")

_WORM_DETECTOR = "worm_signature"


class ResponseEngine:
    def __init__(self, policy: ResponsePolicy, store: QuarantineStore | None = None) -> None:
        self.policy = policy
        self.store = store if store is not None else QuarantineStore()
        self._recent: deque[float] = deque()  # timestamps of eligible actions (circuit breaker)

    def evaluate(self, alert: Alert, now: float | None = None) -> ResponseDecision:
        """Decide what Wyvern would do about ``alert``. Never enforces (Phase 0)."""
        now = now if now is not None else (alert.ts or 0.0)

        # 1. Only the composite, multi-stage worm verdict — never a single detector.
        if alert.detector != _WORM_DETECTOR or alert.stage != COMPOSITE_STAGE:
            return ResponseDecision(status=Decision.IGNORED, reason="not a worm-signature verdict")
        if int(alert.severity) < self.policy.min_severity:
            return ResponseDecision(status=Decision.IGNORED, reason="below response.min_severity")
        target = alert.src_mac or alert.src_ip
        if not target:
            return ResponseDecision(status=Decision.IGNORED, reason="verdict has no target host")

        # 2. Allowlist — protected assets are never actionable, in any mode.
        if self._is_protected(alert):
            return ResponseDecision(
                status=Decision.SUPPRESSED_ALLOWLIST,
                target=target,
                reason="target is a protected asset (allowlist)",
            )

        # 3. Circuit breaker — halt action storms.
        if not self._breaker_ok(now):
            return ResponseDecision(
                status=Decision.SUPPRESSED_RATELIMIT,
                target=target,
                reason=f"circuit breaker: >{self.policy.max_actions_per_window} actions "
                f"in {int(self.policy.window_s)}s",
            )

        # Eligible. Record the intent; Phase 0 does NOT enforce.
        self._recent.append(now)
        status = QState.PENDING if self.policy.mode == "confirm" else QState.PROPOSED
        record = self.store.add(
            QuarantineRecord(
                target=target,
                status=status,
                reason=f"worm_signature verdict ({alert.evidence.get('stage_count', '?')} stages)",
                mode=self.policy.mode,
                proposed_at=now,
                expires_at=now + self.policy.quarantine_ttl_s,
                alert_id=alert.id,
                stage_count=alert.evidence.get("stage_count"),
            )
        )
        log.warning(
            "[response:%s] WOULD quarantine %s (alert %s) — enforcement not wired (Phase 0)",
            self.policy.mode,
            target,
            alert.id,
        )
        decision_status = Decision.PENDING if self.policy.mode == "confirm" else Decision.PROPOSED
        return ResponseDecision(
            status=decision_status,
            target=target,
            eligible=True,
            enforced=False,  # Phase 0: never enforce
            reason="eligible for quarantine",
            record=record,
        )

    # ------------------------------------------------------------------ gates
    def _is_protected(self, alert: Alert) -> bool:
        if not self.policy.protected_hosts:
            return False
        protected = {h.lower() for h in self.policy.protected_hosts}
        return any(v and v.lower() in protected for v in (alert.src_ip, alert.src_mac))

    def _breaker_ok(self, now: float) -> bool:
        cutoff = now - self.policy.window_s
        while self._recent and self._recent[0] < cutoff:
            self._recent.popleft()
        return len(self._recent) < self.policy.max_actions_per_window


def build_response_engine(policy: ResponsePolicy) -> ResponseEngine:
    """Always returns an engine; it is inert (observe) by default."""
    return ResponseEngine(policy)
