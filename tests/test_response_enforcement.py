"""Tests for Phase 1 enforcement wiring in the ResponseEngine (issue #29).

Phase 0 proved the engine decides safely and enforces nothing. Phase 1 lets an
eligible verdict actually drive a responder — but only in confirm/auto with a
responder configured, and never for a protected asset. Release and expiry must
revert. A FakeResponder stands in for the firewall.
"""

from __future__ import annotations

from wyvern.config import ResponsePolicy
from wyvern.detectors.worm_signature import COMPOSITE_STAGE
from wyvern.models.alert import Alert, Severity
from wyvern.response import Decision, QState, QuarantineStore, ResponseEngine


class FakeResponder:
    def __init__(self, ok: bool = True) -> None:
        self.applied: list[str] = []
        self.reverted: list[str] = []
        self.ok = ok

    def apply(self, record) -> bool:
        self.applied.append(record.target)
        return self.ok

    def revert(self, record) -> bool:
        self.reverted.append(record.target)
        return self.ok


def _worm(sev=Severity.CRITICAL, ip="192.168.1.66", mac="00:11:22:33:44:66", ts=1000.0) -> Alert:
    return Alert(
        detector="worm_signature",
        title="worm",
        severity=sev,
        confidence=0.95,
        description="d",
        src_ip=ip,
        src_mac=mac,
        stage=COMPOSITE_STAGE,
        ts=ts,
        evidence={"stage_count": 3},
    )


def test_auto_mode_enforces_via_responder():
    resp = FakeResponder(ok=True)
    eng = ResponseEngine(ResponsePolicy(mode="auto"), responder=resp)
    d = eng.evaluate(_worm())
    assert d.enforced is True
    assert d.record.status == QState.ACTIVE
    assert resp.applied == ["00:11:22:33:44:66"]


def test_auto_without_responder_does_not_enforce():
    eng = ResponseEngine(ResponsePolicy(mode="auto"), responder=None)
    d = eng.evaluate(_worm())
    assert d.eligible is True and d.enforced is False
    assert d.record.status == QState.PROPOSED  # falls back to proposal


def test_observe_never_calls_responder():
    resp = FakeResponder()
    eng = ResponseEngine(ResponsePolicy(mode="observe"), responder=resp)
    d = eng.evaluate(_worm())
    assert d.enforced is False and resp.applied == []
    assert d.record.status == QState.PROPOSED


def test_confirm_requires_approval_then_enforces():
    resp = FakeResponder()
    eng = ResponseEngine(ResponsePolicy(mode="confirm"), responder=resp)
    d = eng.evaluate(_worm())
    assert d.status == Decision.PENDING and resp.applied == []  # not yet
    updated = eng.approve(d.record.id, now=1100.0)
    assert updated.status == QState.ACTIVE and resp.applied == ["00:11:22:33:44:66"]


def test_apply_failure_marks_failed():
    resp = FakeResponder(ok=False)
    eng = ResponseEngine(ResponsePolicy(mode="auto"), responder=resp)
    d = eng.evaluate(_worm())
    assert d.enforced is False and d.record.status == QState.FAILED


def test_release_reverts_active_rule():
    resp = FakeResponder()
    store = QuarantineStore()
    eng = ResponseEngine(ResponsePolicy(mode="auto"), store=store, responder=resp)
    rec = eng.evaluate(_worm()).record
    released = eng.release(rec.id, now=1200.0)
    assert released.status == QState.RELEASED
    assert resp.reverted == ["00:11:22:33:44:66"]


def test_expiry_reverts_active_rule():
    resp = FakeResponder()
    store = QuarantineStore()
    eng = ResponseEngine(
        ResponsePolicy(mode="auto", quarantine_ttl_s=100.0), store=store, responder=resp
    )
    rec = eng.evaluate(_worm(ts=1000.0)).record
    expired = eng.sweep_expired(now=1200.0)
    assert rec.id in [r.id for r in expired]
    assert resp.reverted == ["00:11:22:33:44:66"]  # rule was lifted on expiry
    assert store.get(rec.id).status == QState.EXPIRED


def test_protected_asset_never_reaches_responder_in_auto():
    resp = FakeResponder()
    eng = ResponseEngine(
        ResponsePolicy(mode="auto", protected_hosts=("192.168.1.66",)), responder=resp
    )
    d = eng.evaluate(_worm(ip="192.168.1.66"))
    assert d.status == Decision.SUPPRESSED_ALLOWLIST
    assert resp.applied == [] and d.enforced is False
