"""The Tier-1 response engine (issue #29).

The engine turns a high-confidence worm verdict into a *decision*: whether Wyvern
should contain the offending host, and — when a responder is configured — driving
it to do so. Enforcement is governed by ``policy.mode``:
  * ``observe`` (default) — record "would quarantine X"; never enforce.
  * ``confirm`` — record PENDING; a human calls :meth:`approve` to apply.
  * ``auto`` — apply immediately via the responder (requires one configured).

Safety gates, in order (all pass before anything is even recorded):
  1. Trigger only on the ``worm_signature`` composite verdict, at/above the
     configured severity — never a single detector.
  2. **Allowlist** — a protected asset (gateway/DNS/self/operator-declared) can
     never be actioned, in any mode.
  3. **Circuit breaker** — cap actions per window; a storm halts (defends against
     a worm weaponising the response into a self-DoS).
Quarantines are reversible (:meth:`release`) and auto-expiring
(:meth:`sweep_expired`). Durable persistence + restart reconciliation are Phase
1b; until then ``auto`` mode is not production-cleared (use ``confirm``).
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import replace

from ..config import ResponsePolicy
from ..detectors.worm_signature import COMPOSITE_STAGE
from ..models.alert import Alert
from .models import Decision, QState, QuarantineRecord, ResponseDecision
from .store import QuarantineStore

log = logging.getLogger("wyvern.response")

_WORM_DETECTOR = "worm_signature"


class ResponseEngine:
    def __init__(
        self,
        policy: ResponsePolicy,
        store: QuarantineStore | None = None,
        responder=None,
    ) -> None:
        self.policy = policy
        self.store = store if store is not None else QuarantineStore()
        self.responder = responder
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

        # Eligible. Record the intent.
        self._recent.append(now)
        record = self.store.add(
            QuarantineRecord(
                target=target,
                status=QState.PENDING if self.policy.mode == "confirm" else QState.PROPOSED,
                reason=f"worm_signature verdict ({alert.evidence.get('stage_count', '?')} stages)",
                mode=self.policy.mode,
                proposed_at=now,
                expires_at=now + self.policy.quarantine_ttl_s,
                alert_id=alert.id,
                stage_count=alert.evidence.get("stage_count"),
                ip=alert.src_ip,
                mac=alert.src_mac,
            )
        )

        enforced = False
        if self.policy.mode == "auto":
            record = self._enforce(record)
            enforced = record.status == QState.ACTIVE
        elif self.policy.mode == "confirm":
            log.warning(
                "[response:confirm] quarantine PENDING approval for %s (alert %s)", target, alert.id
            )
        else:  # observe
            log.warning("[response:observe] WOULD quarantine %s (alert %s)", target, alert.id)

        status = Decision.PENDING if self.policy.mode == "confirm" else Decision.PROPOSED
        return ResponseDecision(
            status=status,
            target=target,
            eligible=True,
            enforced=enforced,
            reason="eligible for quarantine",
            record=record,
        )

    # -------------------------------------------------------------- lifecycle
    def approve(self, record_id: str, now: float) -> QuarantineRecord | None:
        """Human-in-the-loop: apply a PENDING (confirm-mode) quarantine."""
        rec = self.store.get(record_id)
        if rec is None or rec.status != QState.PENDING:
            return rec
        return self._enforce(rec)

    def release(self, record_id: str, now: float) -> QuarantineRecord | None:
        """Lift a quarantine — revert the enforced rule (if any), then mark released."""
        rec = self.store.get(record_id)
        if rec is None:
            return None
        if rec.status == QState.ACTIVE and self.responder is not None:
            self.responder.revert(rec)
        return self.store.release(record_id, now)

    def sweep_expired(self, now: float) -> list[QuarantineRecord]:
        """Revert any past-TTL active rule, then mark due records EXPIRED."""
        live = {QState.PROPOSED, QState.PENDING, QState.ACTIVE}
        due = [r for r in self.store.all() if r.status in live and r.expires_at <= now]
        for r in due:
            if r.status == QState.ACTIVE and self.responder is not None:
                self.responder.revert(r)
        return self.store.expire_due(now)

    def _enforce(self, record: QuarantineRecord) -> QuarantineRecord:
        """Attempt to apply a quarantine via the responder. Updates the store."""
        if self.responder is None:
            log.warning(
                "[response] no responder configured; %s left as %s", record.target, record.status
            )
            return record
        ok = self.responder.apply(record)
        updated = replace(record, status=QState.ACTIVE if ok else QState.FAILED)
        self.store.add(updated)
        log.warning("[response] quarantine %s -> %s", record.target, "ACTIVE" if ok else "FAILED")
        return updated

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
    """Always returns an engine; it is inert (observe + no responder) by default."""
    responder = None
    if (
        policy.responder == "firewall"
        and policy.firewall_quarantine_cmd
        and policy.firewall_release_cmd
    ):
        from .responders import FirewallResponder

        responder = FirewallResponder(policy.firewall_quarantine_cmd, policy.firewall_release_cmd)
    return ResponseEngine(policy, responder=responder)
