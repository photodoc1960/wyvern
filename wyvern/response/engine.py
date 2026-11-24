"""The Tier-1 response engine (issue #29).

The engine turns a high-confidence worm verdict into a *decision*: whether Wyvern
should contain the offending host, and — when a responder is configured — driving
it to do so. Enforcement is governed by ``policy.mode``:
  * ``observe`` (default) — record "would quarantine X"; never enforce.
  * ``confirm`` — record PENDING; a human calls :meth:`approve` to apply
    (``wyvern quarantine approve`` / the dashboard, via the running monitor).
  * ``auto`` — apply immediately via the responder (requires one configured).

Safety gates, in order (all pass before anything is even recorded):
  1. Trigger only on the ``worm_signature`` composite verdict, at/above the
     configured severity — never a single detector.
  2. **Allowlist** — a protected asset (gateway/DNS/self/operator-declared) can
     never be actioned, in any mode.
  3. **Circuit breaker** — cap actions per window; a storm halts (defends against
     a worm weaponising the response into a self-DoS).
Approval re-runs gates 1-3 against the *current* policy (a host protected or a
severity threshold raised since the verdict still wins), and approvals have their
own circuit breaker. Quarantines are reversible (:meth:`release`) and
auto-expiring (:meth:`sweep_expired`). Durable persistence + restart
reconciliation are Phase 1b; until then ``auto`` mode is not production-cleared
(use ``confirm``).
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import replace

from ..config import ResponsePolicy
from ..detectors.worm_signature import COMPOSITE_STAGE
from ..models.alert import Alert
from .models import ActionRefusedError, Decision, QState, QuarantineRecord, ResponseDecision
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
        # Approvals are wall-clock while ``_recent`` is in alert time, so they get
        # their own breaker window rather than sharing one deque.
        self._approvals: deque[float] = deque()

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
        if self._is_protected(alert.src_ip, alert.src_mac):
            return ResponseDecision(
                status=Decision.SUPPRESSED_ALLOWLIST,
                target=target,
                reason="target is a protected asset (allowlist)",
            )

        # 3. Circuit breaker — halt action storms.
        if not self._breaker_ok(self._recent, now):
            return ResponseDecision(
                status=Decision.SUPPRESSED_RATELIMIT,
                target=target,
                reason=self._breaker_reason(),
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
                severity=int(alert.severity),
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
    def approve(self, record_id: str, now: float) -> QuarantineRecord:
        """Human-in-the-loop: apply a PENDING (confirm-mode) quarantine.

        Raises :class:`ActionRefusedError` unless the record is PENDING, unexpired, and
        still passes the severity gate, the allowlist and the approval circuit
        breaker under the current policy (still in ``confirm`` mode), and a
        responder is configured. Returns
        the updated record: ACTIVE, or FAILED if the responder's command failed.
        """
        rec = self._get(record_id)
        if rec.status != QState.PENDING:
            raise ActionRefusedError(
                f"only a pending quarantine can be approved (this is {rec.status})"
            )
        if self.policy.mode != "confirm":
            raise ActionRefusedError(
                f"response.mode is now {self.policy.mode!r}; approval needs 'confirm'"
            )
        if rec.expires_at <= now:
            raise ActionRefusedError("quarantine request has expired")
        if rec.severity is None:
            raise ActionRefusedError(
                "record predates severity tracking, so the severity gate can't be checked"
            )
        if rec.severity < self.policy.min_severity:
            raise ActionRefusedError("verdict is below response.min_severity")
        if self._is_protected(rec.ip, rec.mac, rec.target):
            raise ActionRefusedError("target is a protected asset (allowlist)")
        if self.responder is None:
            raise ActionRefusedError("no responder configured (set response.responder: firewall)")
        if not self._breaker_ok(self._approvals, now):
            raise ActionRefusedError(self._breaker_reason())
        self._approvals.append(now)
        return self._enforce(rec)

    def release(self, record_id: str, now: float) -> QuarantineRecord:
        """Lift a quarantine — revert the enforced rule (if any), then mark released.

        Releasing a PROPOSED/PENDING/FAILED record dismisses it. Raises
        :class:`ActionRefusedError` for an already-ended record, or when the release
        command fails or there is no responder to run it — the record then stays ACTIVE so the operator can retry
        rather than believe a still-blocked host is free.
        """
        rec = self._get(record_id)
        if rec.status in (QState.RELEASED, QState.EXPIRED):
            raise ActionRefusedError(f"quarantine has already ended ({rec.status})")
        if rec.status == QState.ACTIVE:
            if self.responder is None:
                raise ActionRefusedError(
                    "no responder configured to revert this rule; remove it by hand "
                    "(the record expires at its TTL)"
                )
            if not self.responder.revert(rec):
                raise ActionRefusedError("release command failed; the rule may still be in place")
        return self.store.release(record_id, now)

    def _get(self, record_id: str) -> QuarantineRecord:
        rec = self.store.get(record_id)
        if rec is None:
            raise ActionRefusedError(f"no quarantine record {record_id!r}", not_found=True)
        return rec

    def reconcile(self, now: float) -> list[QuarantineRecord]:
        """Restart reconciliation: expire stale records, then re-apply the rules
        for quarantines that were ACTIVE before the restart (firewall state may
        have been flushed on reboot). The store is already loaded from the DB.
        Returns the records whose rules were re-applied.
        """
        self.sweep_expired(now)
        reapplied: list[QuarantineRecord] = []
        for rec in self.store.all():
            if rec.status == QState.ACTIVE and self.responder is not None:
                self.responder.apply(rec)
                reapplied.append(rec)
        return reapplied

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
    def _is_protected(self, *hosts: str | None) -> bool:
        if not self.policy.protected_hosts:
            return False
        protected = {h.lower() for h in self.policy.protected_hosts}
        return any(v and v.lower() in protected for v in hosts)

    def _breaker_ok(self, window: deque[float], now: float) -> bool:
        cutoff = now - self.policy.window_s
        while window and window[0] < cutoff:
            window.popleft()
        return len(window) < self.policy.max_actions_per_window

    def _breaker_reason(self) -> str:
        return (
            f"circuit breaker: >{self.policy.max_actions_per_window} actions "
            f"in {int(self.policy.window_s)}s"
        )


def build_response_engine(policy: ResponsePolicy, db=None) -> ResponseEngine:
    """Always returns an engine; it is inert (observe + no responder) by default.

    When ``db`` is provided, quarantine state is persisted and reloaded through it
    (durable across restarts); the caller should then invoke :meth:`reconcile`.
    """
    responder = None
    if (
        policy.responder == "firewall"
        and policy.firewall_quarantine_cmd
        and policy.firewall_release_cmd
    ):
        from .responders import FirewallResponder

        responder = FirewallResponder(policy.firewall_quarantine_cmd, policy.firewall_release_cmd)
    return ResponseEngine(policy, store=QuarantineStore(db=db), responder=responder)
