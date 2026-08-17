"""Responders — the objects that actually enforce a quarantine (issue #29, Phase 1).

`FirewallResponder` is a thin, safe executor: it substitutes the target into an
operator-supplied command template (`{ip}` / `{mac}`) and runs it via an
injectable runner — **no shell**, and it **refuses malformed targets** so a
crafted address can never be injected into a command. It hardcodes no firewall
syntax; the operator supplies the exact `nft`/`iptables`/gateway commands for
their topology. Failures are swallowed (return False) so enforcement never
crashes the monitor.
"""

from __future__ import annotations

import logging
import shlex
import subprocess
from collections.abc import Callable

from ..util.nets import is_usable_host_ip, normalize_mac
from .models import QuarantineRecord

log = logging.getLogger("wyvern.response")

# runner(args, timeout) -> exit code; raises on failure to start.
Runner = Callable[[list[str], float], int]


def _subprocess_runner(args: list[str], timeout: float) -> int:
    # A gated, off-by-default Tier-1 responder running operator-supplied firewall
    # commands: list args (no shell), target validated upstream.
    proc = subprocess.run(  # noqa: S603  invariant-ok(#29): gated active-response firewall command
        args, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
    )
    return proc.returncode


def _clean_ip(ip: str | None) -> str | None:
    return ip if is_usable_host_ip(ip) else None


def _clean_mac(mac: str | None) -> str | None:
    return normalize_mac(mac)


class FirewallResponder:
    def __init__(
        self,
        quarantine_cmd: str,
        release_cmd: str,
        *,
        runner: Runner | None = None,
        timeout_s: float = 5.0,
    ) -> None:
        self.quarantine_cmd = quarantine_cmd
        self.release_cmd = release_cmd
        self._run = runner or _subprocess_runner
        self.timeout_s = timeout_s

    def apply(self, record: QuarantineRecord) -> bool:
        return self._exec(self.quarantine_cmd, record)

    def revert(self, record: QuarantineRecord) -> bool:
        return self._exec(self.release_cmd, record)

    def _exec(self, template: str, record: QuarantineRecord) -> bool:
        args = self._build(template, record)
        if args is None:
            log.warning("firewall responder refused malformed target for %s", record.target)
            return False
        try:
            return self._run(args, self.timeout_s) == 0
        except Exception:  # noqa: BLE001 - a failing command must not crash the monitor
            log.warning("firewall command failed for %s", record.target, exc_info=True)
            return False

    def _build(self, template: str, record: QuarantineRecord) -> list[str] | None:
        ip = _clean_ip(record.ip)
        mac = _clean_mac(record.mac)
        # Substitute only validated values; if the template needs a field we don't
        # have a clean value for, refuse rather than run a half-formed command.
        needs_ip = "{ip}" in template
        needs_mac = "{mac}" in template
        if (needs_ip and ip is None) or (needs_mac and mac is None):
            return None
        filled = template.replace("{ip}", ip or "").replace("{mac}", mac or "")
        return shlex.split(filled)
