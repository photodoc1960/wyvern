"""Tests for exposing confirm-mode approval and release (follow-up to #29).

``ResponseEngine.approve`` / ``release`` existed but nothing called them, so
``mode: confirm`` was inert. These tests cover the engine gates that approval
must still pass, the Monitor/API surface (with its loopback/JSON/origin guard),
and the ``wyvern quarantine`` CLI, which acts through the running monitor.
"""

from __future__ import annotations

import socket
import sqlite3
import threading
import time
from dataclasses import replace

import pytest
from werkzeug.serving import make_server

from wyvern.cli import main
from wyvern.config import Config, ResponsePolicy
from wyvern.detectors.worm_signature import COMPOSITE_STAGE
from wyvern.engine.monitor import Monitor
from wyvern.models.alert import Alert, Severity
from wyvern.response import (
    ActionRefusedError,
    QState,
    QuarantineRecord,
    ResponseEngine,
    build_response_engine,
)
from wyvern.storage.db import WyvernDB
from wyvern.web.app import create_app

MAC = "00:11:22:33:44:66"
IP = "192.168.1.66"


class FakeResponder:
    def __init__(self, ok: bool = True, revert_ok: bool = True) -> None:
        self.applied: list[str] = []
        self.reverted: list[str] = []
        self.ok = ok
        self.revert_ok = revert_ok

    def apply(self, record) -> bool:
        self.applied.append(record.target)
        return self.ok

    def revert(self, record) -> bool:
        self.reverted.append(record.target)
        return self.revert_ok


def _worm(ts: float = 1000.0, sev=Severity.CRITICAL, ip=IP, mac=MAC) -> Alert:
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


def _confirm_engine(responder=None, **policy) -> ResponseEngine:
    responder = responder if responder is not None else FakeResponder()
    return ResponseEngine(ResponsePolicy(mode="confirm", **policy), responder=responder)


def _pending(eng: ResponseEngine, ts: float = 1000.0, **kw) -> QuarantineRecord:
    rec = eng.evaluate(_worm(ts=ts, **kw)).record
    assert rec.status == QState.PENDING
    return rec


# ---------------------------------------------------------------- engine: approve
def test_approve_pending_applies_and_records_severity():
    resp = FakeResponder()
    eng = _confirm_engine(resp)
    rec = _pending(eng)
    assert rec.severity == int(Severity.CRITICAL)
    updated = eng.approve(rec.id, now=1100.0)
    assert updated.status == QState.ACTIVE
    assert resp.applied == [MAC]
    assert eng.store.get(rec.id).status == QState.ACTIVE


@pytest.mark.parametrize("status", [QState.PROPOSED, QState.ACTIVE, QState.RELEASED])
def test_approve_refuses_non_pending(status):
    resp = FakeResponder()
    eng = _confirm_engine(resp)
    rec = eng.store.add(replace(_pending(eng), status=status))
    with pytest.raises(ActionRefusedError, match="only a pending"):
        eng.approve(rec.id, now=1100.0)
    assert resp.applied == []


def test_approve_observe_mode_record_is_refused():
    resp = FakeResponder()
    eng = ResponseEngine(ResponsePolicy(mode="observe"), responder=resp)
    rec = eng.evaluate(_worm()).record
    with pytest.raises(ActionRefusedError):
        eng.approve(rec.id, now=1100.0)
    assert resp.applied == []


def test_approve_unknown_id_is_not_found():
    with pytest.raises(ActionRefusedError) as exc:
        _confirm_engine().approve("nope", now=1.0)
    assert exc.value.not_found


def test_approve_refuses_host_protected_since_the_verdict():
    """A restart with a newer allowlist must win over an older pending request."""
    db = WyvernDB(":memory:")
    eng1 = build_response_engine(ResponsePolicy(mode="confirm"), db=db)
    rec = _pending(eng1)

    resp = FakeResponder()
    eng2 = build_response_engine(ResponsePolicy(mode="confirm", protected_hosts=(IP,)), db=db)
    eng2.responder = resp
    with pytest.raises(ActionRefusedError, match="protected"):
        eng2.approve(rec.id, now=1100.0)
    assert resp.applied == []
    assert eng2.store.get(rec.id).status == QState.PENDING


def test_approve_refuses_below_current_min_severity():
    resp = FakeResponder()
    eng = _confirm_engine(resp, min_severity=3)
    rec = _pending(eng, sev=Severity.HIGH)
    eng.policy = replace(eng.policy, min_severity=4)  # threshold raised since
    with pytest.raises(ActionRefusedError, match="min_severity"):
        eng.approve(rec.id, now=1100.0)
    assert resp.applied == []


def test_approve_refuses_record_without_severity():
    """Records written before severity was tracked can't be checked — fail safe."""
    eng = _confirm_engine()
    rec = eng.store.add(replace(_pending(eng), severity=None))
    with pytest.raises(ActionRefusedError, match="severity tracking"):
        eng.approve(rec.id, now=1100.0)


@pytest.mark.parametrize("mode", ["observe", "auto"])
def test_approve_refuses_after_mode_changed_away_from_confirm(mode):
    """Switching to observe to stop enforcement must also stop old pending requests."""
    resp = FakeResponder()
    eng = _confirm_engine(resp)
    rec = _pending(eng)
    eng.policy = replace(eng.policy, mode=mode)
    with pytest.raises(ActionRefusedError, match="approval needs 'confirm'"):
        eng.approve(rec.id, now=1100.0)
    assert resp.applied == []


def test_approve_refuses_expired_request():
    eng = _confirm_engine(quarantine_ttl_s=100.0)
    rec = _pending(eng, ts=1000.0)
    with pytest.raises(ActionRefusedError, match="expired"):
        eng.approve(rec.id, now=1100.0)


def test_approve_refuses_without_responder():
    eng = ResponseEngine(ResponsePolicy(mode="confirm"), responder=None)
    rec = _pending(eng)
    with pytest.raises(ActionRefusedError, match="no responder"):
        eng.approve(rec.id, now=1100.0)
    assert eng.store.get(rec.id).status == QState.PENDING


def test_approve_circuit_breaker():
    resp = FakeResponder()
    eng = _confirm_engine(resp, max_actions_per_window=1, window_s=60.0)
    first = _pending(eng, ts=1000.0)
    second = _pending(eng, ts=1100.0, ip="192.168.1.67", mac="00:11:22:33:44:67")
    third = _pending(eng, ts=1200.0, ip="192.168.1.68", mac="00:11:22:33:44:68")
    eng.approve(first.id, now=1300.0)
    with pytest.raises(ActionRefusedError, match="circuit breaker"):
        eng.approve(second.id, now=1310.0)
    assert eng.store.get(second.id).status == QState.PENDING
    assert eng.approve(third.id, now=1400.0).status == QState.ACTIVE  # window passed
    assert resp.applied == [MAC, "00:11:22:33:44:68"]


def test_approve_command_failure_marks_failed():
    eng = _confirm_engine(FakeResponder(ok=False))
    rec = _pending(eng)
    assert eng.approve(rec.id, now=1100.0).status == QState.FAILED


# ---------------------------------------------------------------- engine: release
def test_release_approved_quarantine_reverts_rule():
    resp = FakeResponder()
    eng = _confirm_engine(resp)
    rec = _pending(eng)
    eng.approve(rec.id, now=1100.0)
    released = eng.release(rec.id, now=1200.0)
    assert released.status == QState.RELEASED and released.released_at == 1200.0
    assert resp.reverted == [MAC]


def test_release_pending_dismisses_without_revert():
    resp = FakeResponder()
    eng = _confirm_engine(resp)
    rec = _pending(eng)
    assert eng.release(rec.id, now=1100.0).status == QState.RELEASED
    assert resp.reverted == []
    with pytest.raises(ActionRefusedError, match="only a pending"):
        eng.approve(rec.id, now=1150.0)


@pytest.mark.parametrize("status", [QState.RELEASED, QState.EXPIRED])
def test_release_refuses_ended_record(status):
    eng = _confirm_engine()
    rec = eng.store.add(replace(_pending(eng), status=status))
    with pytest.raises(ActionRefusedError, match="already ended"):
        eng.release(rec.id, now=1100.0)


def test_release_failure_keeps_quarantine_active():
    resp = FakeResponder(revert_ok=False)
    eng = _confirm_engine(resp)
    rec = _pending(eng)
    eng.approve(rec.id, now=1100.0)
    with pytest.raises(ActionRefusedError, match="release command failed"):
        eng.release(rec.id, now=1200.0)
    assert eng.store.get(rec.id).status == QState.ACTIVE


def test_release_active_without_responder_is_refused():
    """With nothing to run the release command, don't claim the host is free."""
    eng = _confirm_engine()
    rec = _pending(eng)
    eng.approve(rec.id, now=1100.0)
    eng.responder = None  # e.g. responder config removed and the monitor restarted
    with pytest.raises(ActionRefusedError, match="no responder"):
        eng.release(rec.id, now=1200.0)
    assert eng.store.get(rec.id).status == QState.ACTIVE


# ------------------------------------------------------------------ persistence
def test_severity_survives_db_roundtrip():
    db = WyvernDB(":memory:")
    rec = _pending(build_response_engine(ResponsePolicy(mode="confirm"), db=db))
    reloaded = build_response_engine(ResponsePolicy(mode="confirm"), db=db).store.get(rec.id)
    assert reloaded.severity == int(Severity.CRITICAL)


def test_db_migrates_quarantines_table_without_severity(tmp_path):
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE quarantines (id TEXT PRIMARY KEY, target TEXT NOT NULL, "
        "status TEXT NOT NULL, reason TEXT, mode TEXT, proposed_at REAL, expires_at REAL, "
        "alert_id TEXT, stage_count INTEGER, released_at REAL, ip TEXT, mac TEXT)"
    )
    conn.execute(
        "INSERT INTO quarantines (id, target, status, reason, mode, proposed_at, expires_at) "
        "VALUES ('old1', ?, 'pending', 'r', 'confirm', 1.0, 2.0)",
        (MAC,),
    )
    conn.commit()
    conn.close()
    db = WyvernDB(path)
    rows = db.load_quarantines()
    assert rows[0]["id"] == "old1" and rows[0]["severity"] is None
    WyvernDB(path)  # re-opening an already-migrated DB is a no-op


# ----------------------------------------------------------------------- web API
@pytest.fixture
def web(tmp_path):
    cfg = Config(data_dir=str(tmp_path)).validate()
    resp = FakeResponder()
    db = WyvernDB(":memory:")
    eng = build_response_engine(ResponsePolicy(mode="confirm"), db=db)
    eng.responder = resp
    mon = Monitor(cfg, learn=False, db=db, response=eng)
    rec = _pending(mon.response, ts=time.time())
    return mon, resp, rec, create_app(mon).test_client()


def test_api_lists_quarantines_with_status_filter(web):
    _mon, _resp, rec, client = web
    data = client.get("/api/quarantines").get_json()
    assert [r["id"] for r in data] == [rec.id]
    assert data[0]["status"] == "pending" and data[0]["target"] == MAC
    assert client.get("/api/quarantines?status=active").get_json() == []


def test_api_approve_then_release(web):
    mon, resp, rec, client = web
    q = mon.bus.subscribe()
    r = client.post(f"/api/quarantines/{rec.id}/approve", json={})
    assert r.status_code == 200
    assert r.get_json()["record"]["status"] == "active" and resp.applied == [MAC]
    assert q.get_nowait()["type"] == "quarantine_update"

    r = client.post(f"/api/quarantines/{rec.id}/release", json={})
    assert r.status_code == 200
    assert r.get_json()["record"]["status"] == "released" and resp.reverted == [MAC]
    assert mon.db.load_quarantines()[0]["status"] == "released"  # persisted


def test_api_approve_refuses_non_pending(web):
    _mon, _resp, rec, client = web
    client.post(f"/api/quarantines/{rec.id}/approve", json={})
    r = client.post(f"/api/quarantines/{rec.id}/approve", json={})
    assert r.status_code == 409 and "only a pending" in r.get_json()["error"]


def test_api_unknown_record_is_404(web):
    client = web[3]
    assert client.post("/api/quarantines/nope/approve", json={}).status_code == 404
    assert client.post("/api/quarantines/nope/release", json={}).status_code == 404


def test_api_approve_command_failure_is_502(web):
    _mon, resp, rec, client = web
    resp.ok = False
    r = client.post(f"/api/quarantines/{rec.id}/approve", json={})
    assert r.status_code == 502 and r.get_json()["record"]["status"] == "failed"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"json": {}, "environ_base": {"REMOTE_ADDR": "192.168.1.66"}},  # LAN client
        {"data": "value=1", "content_type": "application/x-www-form-urlencoded"},  # form CSRF
        {"json": {}, "headers": {"Host": "evil.example:8787"}},  # DNS rebinding
        {"json": {}, "headers": {"Origin": "http://evil.example"}},  # cross-origin
        {"json": {}, "headers": {"Origin": "http://localhost:3000"}},  # other local app
    ],
)
def test_api_actions_refuse_untrusted_requests(web, kwargs):
    _mon, resp, rec, client = web
    for action in ("approve", "release"):
        assert client.post(f"/api/quarantines/{rec.id}/{action}", **kwargs).status_code == 403
    assert resp.applied == [] and resp.reverted == []


def test_api_accepts_ipv6_loopback(web):
    _mon, _resp, rec, client = web
    r = client.post(
        f"/api/quarantines/{rec.id}/approve",
        json={},
        environ_base={"REMOTE_ADDR": "::1"},
        headers={"Host": "[::1]:8787", "Origin": "http://[::1]:8787"},
    )
    assert r.status_code == 200


def test_api_accepts_dashboard_origin(web):
    _mon, _resp, rec, client = web
    r = client.post(
        f"/api/quarantines/{rec.id}/approve",
        json={},
        headers={"Origin": "http://127.0.0.1:8787", "Host": "127.0.0.1:8787"},
    )
    assert r.status_code == 200


# --------------------------------------------------------------------------- CLI
def _seed_db(tmp_path) -> list[QuarantineRecord]:
    cfg = Config(data_dir=str(tmp_path)).validate()
    cfg.ensure_data_dir()
    eng = build_response_engine(ResponsePolicy(mode="confirm"), db=WyvernDB(cfg.db_path))
    now = time.time()  # current stamps: a 1970 request would list as expired
    pending = _pending(eng, ts=now - 200)
    released = eng.store.release(
        _pending(eng, ts=now - 100, ip="192.168.1.67", mac="00:11:22:33:44:67").id, now=now
    )
    return [pending, released]


def test_cli_list(tmp_path, capsys):
    pending, released = _seed_db(tmp_path)
    assert main(["--data-dir", str(tmp_path), "quarantine", "list"]) == 0
    out = capsys.readouterr().out
    assert pending.id in out and released.id in out
    assert out.index(released.id) < out.index(pending.id)  # newest first


def test_cli_list_status_filter(tmp_path, capsys):
    pending, released = _seed_db(tmp_path)
    assert main(["--data-dir", str(tmp_path), "quarantine", "list", "--status", "pending"]) == 0
    out = capsys.readouterr().out
    assert pending.id in out and released.id not in out


def test_cli_list_empty(tmp_path, capsys):
    assert main(["--data-dir", str(tmp_path), "quarantine", "list"]) == 0
    assert "No quarantine records" in capsys.readouterr().out
    assert not list(tmp_path.glob("*.db"))  # listing doesn't create a database


def _free_port() -> int:
    """A loopback port that was free a moment ago (nothing listens on it)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def live_monitor(web):
    """Serve the web fixture's monitor on a real loopback port for the CLI."""
    mon, resp, rec, _client = web
    server = make_server("127.0.0.1", 0, create_app(mon), threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", resp, rec
    server.shutdown()
    thread.join(timeout=5)


def test_cli_approve_and_release_via_monitor(tmp_path, capsys, live_monitor):
    url, resp, rec = live_monitor
    base = ["--data-dir", str(tmp_path), "quarantine"]
    assert main([*base, "approve", rec.id, "--url", url]) == 0
    assert "-> active" in capsys.readouterr().out and resp.applied == [MAC]

    assert main([*base, "approve", rec.id, "--url", url]) == 1  # no longer pending
    assert "only a pending" in capsys.readouterr().err

    assert main([*base, "release", rec.id, "--url", url]) == 0
    assert "-> released" in capsys.readouterr().out and resp.reverted == [MAC]


def test_cli_ignores_http_proxy(tmp_path, capsys, live_monitor, monkeypatch):
    url, resp, rec = live_monitor
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{_free_port()}")  # nothing listens
    monkeypatch.setenv("no_proxy", "")
    rc = main(["--data-dir", str(tmp_path), "quarantine", "approve", rec.id, "--url", url])
    assert rc == 0 and resp.applied == [MAC]


def test_cli_action_without_running_monitor(tmp_path, capsys):
    url = f"http://127.0.0.1:{_free_port()}"
    rc = main(["--data-dir", str(tmp_path), "quarantine", "approve", "abc", "--url", url])
    assert rc == 1
    assert "could not reach the monitor" in capsys.readouterr().err


def test_cli_rejects_non_http_url(tmp_path, capsys):
    rc = main(["--data-dir", str(tmp_path), "quarantine", "release", "a", "--url", "file:///x"])
    assert rc == 2


# ------------------------------------------------------------- TTL enforcement
def test_sweep_expires_stale_pending_request(web):
    # The TTL used to take effect only at restart: a running monitor left an
    # unapproved request "pending" (with a live approve button) forever.
    mon, resp, rec, client = web
    q = mon.bus.subscribe()
    mon.sweep(now=rec.expires_at + 1)
    assert mon.response.store.get(rec.id).status == QState.EXPIRED
    assert resp.reverted == []  # nothing was ever applied, so nothing to revert
    updates = []
    while not q.empty():
        msg = q.get_nowait()
        if msg["type"] == "quarantine_update":
            updates.append(msg["quarantine"]["status"])
    assert updates == ["expired"]  # the dashboard is told to refresh
    assert client.get("/api/quarantines").get_json()[0]["status"] == "expired"


def test_sweep_reverts_applied_quarantine_at_ttl(web):
    # The documented auto-release: an applied rule must come off at its TTL
    # while the monitor is running, not at the next restart.
    mon, resp, rec, _client = web
    mon.approve_quarantine(rec.id)
    assert mon.response.store.get(rec.id).status == QState.ACTIVE
    mon.sweep(now=rec.expires_at + 1)
    assert resp.reverted == [MAC]
    assert mon.response.store.get(rec.id).status == QState.EXPIRED
    assert mon.db.load_quarantines()[0]["status"] == "expired"  # persisted


def test_sweep_leaves_unexpired_quarantine_alone(web):
    mon, resp, rec, _client = web
    mon.sweep(now=rec.expires_at - 1)
    assert mon.response.store.get(rec.id).status == QState.PENDING
    assert resp.reverted == []


def test_sweep_survives_expiry_failure(web, monkeypatch):
    mon, _resp, _rec, _client = web

    def boom(now):
        raise RuntimeError("store unavailable")

    monkeypatch.setattr(mon.response, "sweep_expired", boom)
    mon.sweep(now=time.time())  # must not raise


def test_lapsed_only_for_never_applied_requests_past_ttl():
    eng = _confirm_engine()
    rec = _pending(eng, ts=1000.0)
    assert not rec.lapsed(rec.expires_at - 1)
    assert rec.lapsed(rec.expires_at)
    active = replace(rec, status=QState.ACTIVE)
    assert not active.lapsed(rec.expires_at + 1)  # a rule still in place is not "expired"


def test_cli_list_shows_lapsed_request_as_expired(tmp_path, capsys):
    # No monitor running means no sweep; the CLI must not list a request whose
    # TTL has passed as pending.
    cfg = Config(data_dir=str(tmp_path)).validate()
    cfg.ensure_data_dir()
    eng = build_response_engine(ResponsePolicy(mode="confirm"), db=WyvernDB(cfg.db_path))
    stale = _pending(eng, ts=1000.0)
    assert main(["--data-dir", str(tmp_path), "quarantine", "list"]) == 0
    line = next(ln for ln in capsys.readouterr().out.splitlines() if stale.id in ln)
    assert "expired" in line and "pending" not in line
    assert main(["--data-dir", str(tmp_path), "quarantine", "list", "--status", "pending"]) == 0
    assert stale.id not in capsys.readouterr().out
