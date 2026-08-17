"""Tests for the Tier-1 response engine — Phase 0 (observe-only spine).

Phase 0 builds the entire decision + safety layer but enforces NOTHING: every
outcome is a proposal/record + audit log, never an action. These tests are the
safety contract — they must keep passing as responders are added in later phases:
  * only the multi-stage `worm_signature` verdict can trigger (never a single detector)
  * protected assets can NEVER be actioned (the allowlist is load-bearing)
  * the circuit breaker halts action storms
  * observe mode never enforces
  * quarantine records are reversible + auto-expiring
"""

from __future__ import annotations

import pytest

from wyvern.config import ConfigError, ResponsePolicy
from wyvern.detectors.worm_signature import COMPOSITE_STAGE
from wyvern.models.alert import Alert, Severity
from wyvern.response import Decision, QState, QuarantineStore, ResponseEngine, build_response_engine


def _worm(
    severity: Severity = Severity.CRITICAL,
    src_ip: str = "192.168.1.66",
    src_mac: str | None = "00:11:22:33:44:66",
    stage_count: int = 3,
    ts: float = 1000.0,
) -> Alert:
    return Alert(
        detector="worm_signature",
        title="Toronto AI worm signature",
        severity=severity,
        confidence=0.9,
        description="multi-stage worm verdict",
        src_ip=src_ip,
        src_mac=src_mac,
        stage=COMPOSITE_STAGE,
        ts=ts,
        evidence={"stage_count": stage_count},
    )


def _policy(**kw) -> ResponsePolicy:
    return ResponsePolicy(**kw)


def test_ignores_non_worm_alerts():
    eng = ResponseEngine(_policy())
    beacon = Alert(
        detector="beacon",
        title="beacon",
        severity=Severity.CRITICAL,
        confidence=0.9,
        description="d",
        src_ip="192.168.1.66",
        stage="beacon_callback",
        ts=1000.0,
    )
    d = eng.evaluate(beacon)
    assert d.status == Decision.IGNORED and d.eligible is False
    assert eng.store.all() == []


def test_observe_mode_proposes_but_does_not_enforce():
    eng = ResponseEngine(_policy(mode="observe"))
    d = eng.evaluate(_worm())
    assert d.status == Decision.PROPOSED
    assert d.eligible is True
    assert d.enforced is False  # Phase 0 never enforces
    assert d.target == "00:11:22:33:44:66"  # MAC preferred as the stable key
    assert d.record is not None and d.record.status == QState.PROPOSED


def test_below_min_severity_ignored():
    eng = ResponseEngine(_policy(min_severity=4))
    d = eng.evaluate(_worm(severity=Severity.HIGH))  # HIGH(3) < CRITICAL(4)
    assert d.status == Decision.IGNORED


def test_confirm_mode_is_pending():
    eng = ResponseEngine(_policy(mode="confirm"))
    d = eng.evaluate(_worm())
    assert d.status == Decision.PENDING and d.enforced is False
    assert d.record.status == QState.PENDING


def test_protected_host_never_actioned_even_in_auto():
    # The load-bearing safety test: an allowlisted asset is never eligible,
    # regardless of mode — not even in the most aggressive setting.
    eng = ResponseEngine(_policy(mode="auto", protected_hosts=("192.168.1.66",)))
    d = eng.evaluate(_worm(src_ip="192.168.1.66"))
    assert d.status == Decision.SUPPRESSED_ALLOWLIST
    assert d.eligible is False and d.enforced is False
    assert eng.store.all() == []


def test_protected_host_matched_by_mac():
    eng = ResponseEngine(_policy(protected_hosts=("00:11:22:33:44:66",)))
    d = eng.evaluate(_worm(src_mac="00:11:22:33:44:66"))
    assert d.status == Decision.SUPPRESSED_ALLOWLIST


def test_auto_mode_still_does_not_enforce_in_phase0():
    eng = ResponseEngine(_policy(mode="auto"))
    d = eng.evaluate(_worm())
    assert d.eligible is True and d.enforced is False  # no responder wired yet


def test_circuit_breaker_halts_action_storm():
    eng = ResponseEngine(_policy(max_actions_per_window=2, window_s=300.0))
    # distinct targets so the allowlist/dedupe don't interfere
    assert eng.evaluate(_worm(src_mac="00:00:00:00:00:01", ts=1.0)).eligible is True
    assert eng.evaluate(_worm(src_mac="00:00:00:00:00:02", ts=2.0)).eligible is True
    third = eng.evaluate(_worm(src_mac="00:00:00:00:00:03", ts=3.0))
    assert third.status == Decision.SUPPRESSED_RATELIMIT and third.eligible is False


def test_circuit_breaker_recovers_after_window():
    eng = ResponseEngine(_policy(max_actions_per_window=1, window_s=100.0))
    assert eng.evaluate(_worm(src_mac="00:00:00:00:00:01", ts=1.0)).eligible is True
    assert eng.evaluate(_worm(src_mac="00:00:00:00:00:02", ts=2.0)).eligible is False
    # after the window elapses, actions are allowed again
    assert eng.evaluate(_worm(src_mac="00:00:00:00:00:03", ts=200.0)).eligible is True


def test_no_target_ignored():
    eng = ResponseEngine(_policy())
    d = eng.evaluate(_worm(src_ip=None, src_mac=None))
    assert d.status == Decision.IGNORED


# --------------------------------------------------------- store lifecycle
def test_store_release_is_reversible():
    store = QuarantineStore()
    eng = ResponseEngine(_policy(), store=store)
    rec = eng.evaluate(_worm()).record
    store.release(rec.id, now=1500.0)
    assert store.get(rec.id).status == QState.RELEASED
    assert store.get(rec.id).released_at == 1500.0


def test_store_auto_expiry():
    store = QuarantineStore()
    eng = ResponseEngine(_policy(quarantine_ttl_s=600.0), store=store)
    rec = eng.evaluate(_worm(ts=1000.0)).record
    assert rec.expires_at == 1600.0
    expired = store.expire_due(now=1700.0)
    assert rec.id in [r.id for r in expired]
    assert store.get(rec.id).status == QState.EXPIRED
    assert store.active(now=1700.0) == []  # expired records are not active


# --------------------------------------------------------- config + builder
def test_build_response_engine_defaults_to_observe():
    eng = build_response_engine(ResponsePolicy())
    assert isinstance(eng, ResponseEngine)
    assert eng.policy.mode == "observe"


def test_config_rejects_bad_mode():
    with pytest.raises(ConfigError):
        ResponsePolicy(mode="nuke").validate()
