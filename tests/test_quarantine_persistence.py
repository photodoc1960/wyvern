"""Tests for Phase 1b — durable quarantine state + restart reconciliation (#29).

'State survives restart' is the acceptance gate for auto-action. These tests
prove quarantine records persist to the DB and that a fresh engine, on
reconcile, re-applies still-active rules and expires stale ones — i.e. a reboot
doesn't silently drop a quarantine or leave a dead one hanging.
"""

from __future__ import annotations

from wyvern.config import ResponsePolicy
from wyvern.detectors.worm_signature import COMPOSITE_STAGE
from wyvern.models.alert import Alert, Severity
from wyvern.response import QState, QuarantineStore, build_response_engine
from wyvern.response.models import QuarantineRecord
from wyvern.storage.db import WyvernDB


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


def _worm(ip="192.168.1.66", mac="00:11:22:33:44:66", ts=1000.0) -> Alert:
    return Alert(
        detector="worm_signature",
        title="worm",
        severity=Severity.CRITICAL,
        confidence=0.95,
        description="d",
        src_ip=ip,
        src_mac=mac,
        stage=COMPOSITE_STAGE,
        ts=ts,
        evidence={"stage_count": 3},
    )


def _rec(**kw) -> QuarantineRecord:
    base = {
        "target": "00:11:22:33:44:66",
        "status": QState.ACTIVE,
        "reason": "r",
        "mode": "auto",
        "proposed_at": 1000.0,
        "expires_at": 5000.0,
        "ip": "192.168.1.66",
        "mac": "00:11:22:33:44:66",
    }
    base.update(kw)
    return QuarantineRecord(**base)


# ------------------------------------------------------------------ DB layer
def test_db_quarantine_roundtrip():
    db = WyvernDB(":memory:")
    rec = _rec()
    db.upsert_quarantine(rec.to_row())
    rows = db.load_quarantines()
    assert len(rows) == 1
    loaded = QuarantineRecord.from_row(rows[0])
    assert loaded.id == rec.id and loaded.target == rec.target and loaded.status == QState.ACTIVE
    assert loaded.ip == "192.168.1.66"


def test_db_upsert_replaces():
    db = WyvernDB(":memory:")
    rec = _rec(status=QState.ACTIVE)
    db.upsert_quarantine(rec.to_row())
    from dataclasses import replace

    db.upsert_quarantine(replace(rec, status=QState.RELEASED).to_row())
    rows = db.load_quarantines()
    assert len(rows) == 1 and rows[0]["status"] == QState.RELEASED


# --------------------------------------------------------------- store <-> db
def test_store_persists_and_reloads():
    db = WyvernDB(":memory:")
    store = QuarantineStore(db=db)
    rec = store.add(_rec())
    # a fresh store on the same DB sees it (simulates restart)
    reloaded = QuarantineStore(db=db)
    assert reloaded.get(rec.id) is not None
    assert reloaded.get(rec.id).status == QState.ACTIVE


def test_store_release_persists():
    db = WyvernDB(":memory:")
    store = QuarantineStore(db=db)
    rec = store.add(_rec())
    store.release(rec.id, now=2000.0)
    assert QuarantineStore(db=db).get(rec.id).status == QState.RELEASED


# ------------------------------------------------------------- reconciliation
def test_reconcile_reapplies_active_after_restart():
    db = WyvernDB(":memory:")
    # engine 1 quarantines in auto
    eng1 = build_response_engine(ResponsePolicy(mode="auto"), db=db)
    eng1.responder = FakeResponder()
    rec = eng1.evaluate(_worm(ts=1000.0)).record
    assert rec.status == QState.ACTIVE

    # "restart": a brand-new engine on the same DB, fresh responder
    resp2 = FakeResponder()
    eng2 = build_response_engine(ResponsePolicy(mode="auto"), db=db)
    eng2.responder = resp2
    eng2.reconcile(now=1500.0)  # still within TTL
    assert resp2.applied == ["00:11:22:33:44:66"]  # rule re-applied after restart
    assert eng2.store.get(rec.id).status == QState.ACTIVE


def test_reconcile_expires_stale_after_restart():
    db = WyvernDB(":memory:")
    eng1 = build_response_engine(ResponsePolicy(mode="auto", quarantine_ttl_s=100.0), db=db)
    eng1.responder = FakeResponder()
    rec = eng1.evaluate(_worm(ts=1000.0)).record  # expires at 1100

    resp2 = FakeResponder()
    eng2 = build_response_engine(ResponsePolicy(mode="auto"), db=db)
    eng2.responder = resp2
    eng2.reconcile(now=2000.0)  # well past TTL
    assert eng2.store.get(rec.id).status == QState.EXPIRED
    assert resp2.reverted == ["00:11:22:33:44:66"]  # stale rule lifted, not re-applied
    assert resp2.applied == []
