"""Tests for the FirewallResponder (issue #29, Phase 1).

The responder is a thin, safe executor: it substitutes the target into an
operator-supplied command template and runs it via an injectable runner — no
shell, no hardcoded firewall syntax, and it refuses malformed targets (injection
guard). Exact rule correctness is the operator's to verify in their topology;
these tests pin the mechanism and the safety properties.
"""

from __future__ import annotations

from wyvern.response.models import QState, QuarantineRecord
from wyvern.response.responders import FirewallResponder


class FakeRunner:
    def __init__(self, code: int = 0, raises: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.code = code
        self.raises = raises

    def __call__(self, args: list[str], timeout: float) -> int:
        self.calls.append(args)
        if self.raises:
            raise OSError("command failed to start")
        return self.code


def _rec(ip="198.51.100.5", mac="00:11:22:33:44:55") -> QuarantineRecord:
    return QuarantineRecord(
        target=mac or ip,
        status=QState.PROPOSED,
        reason="test",
        mode="auto",
        proposed_at=0.0,
        expires_at=1.0,
        ip=ip,
        mac=mac,
    )


def test_apply_substitutes_ip_and_runs():
    runner = FakeRunner(code=0)
    r = FirewallResponder(
        "nft add element inet wyvern quarantine {ip}",
        "nft delete element inet wyvern quarantine {ip}",
        runner=runner,
    )
    assert r.apply(_rec(ip="198.51.100.5")) is True
    assert runner.calls == [
        ["nft", "add", "element", "inet", "wyvern", "quarantine", "198.51.100.5"]
    ]


def test_revert_uses_release_template():
    runner = FakeRunner(code=0)
    r = FirewallResponder("q {ip}", "release {ip}", runner=runner)
    assert r.revert(_rec(ip="198.51.100.5")) is True
    assert runner.calls[-1] == ["release", "198.51.100.5"]


def test_nonzero_exit_is_failure():
    r = FirewallResponder("q {ip}", "r {ip}", runner=FakeRunner(code=1))
    assert r.apply(_rec()) is False


def test_runner_exception_is_fail_safe():
    r = FirewallResponder("q {ip}", "r {ip}", runner=FakeRunner(raises=True))
    assert r.apply(_rec()) is False  # must not raise


def test_mac_substitution_when_no_ip():
    runner = FakeRunner()
    r = FirewallResponder("q {mac}", "r {mac}", runner=runner)
    r.apply(_rec(ip=None, mac="00:11:22:33:44:55"))
    assert runner.calls[-1] == ["q", "00:11:22:33:44:55"]


def test_malformed_target_is_refused_no_exec():
    # injection guard: a target that is not a clean IP/MAC must never reach the runner
    runner = FakeRunner()
    r = FirewallResponder("q {ip}", "r {ip}", runner=runner)
    bad = QuarantineRecord(
        target="x",
        status=QState.PROPOSED,
        reason="t",
        mode="auto",
        proposed_at=0.0,
        expires_at=1.0,
        ip="8.8.8.8; rm -rf /",
        mac=None,
    )
    assert r.apply(bad) is False
    assert runner.calls == []  # never executed
