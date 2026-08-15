"""Detection->enforcement bridge (issue #22, Piece 2).

Wyvern is a passive sensor: it never blocks packets. This bridge is the one
place it *reaches out* — on a high-confidence alert it POSTs a signed finding to
an **external** actuator (firewall / egress controller / quarantine hook) that
decides whether to act. The sensor raises the signal; the actuator enforces.

Safety rails (all deliberate):
  * **Off by default** — inert unless ``enforce.enabled`` and a ``webhook_url``.
  * **High-confidence only** — gated on a configurable minimum severity
    (default CRITICAL), so weak/corroborating signals never trigger action.
  * **Authenticated** — the JSON body is HMAC-SHA256 signed with a secret taken
    from the environment (``WYVERN_ENFORCE_SECRET``) when set, so the actuator can
    verify the request really came from Wyvern.
  * **Fail-safe** — a slow or broken actuator is logged and swallowed; it must
    never crash or wedge the monitor. The POST is bounded by a short timeout.
  * **Auditable** — every dispatch logs the alert id and the outcome.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import urllib.request
from collections.abc import Callable

from ..config import EnforceConfig
from ..models.alert import Alert

log = logging.getLogger("wyvern.enforce")

# A sender POSTs the body and returns the HTTP status code (or raises on failure).
# Injectable so the bridge is unit-testable without a live endpoint.
Sender = Callable[[str, bytes, dict[str, str], float], int]


def _urllib_sender(url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310 - scheme is validated http(s) in EnforceConfig
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return int(getattr(resp, "status", 0) or resp.getcode())


class EnforcementBridge:
    def __init__(self, config: EnforceConfig, sender: Sender | None = None) -> None:
        self.cfg = config
        self._sender: Sender = sender or _urllib_sender

    def dispatch(self, alert: Alert) -> bool:
        """POST the alert to the actuator iff it qualifies. Returns True on 2xx.

        Never raises: a failing actuator must not affect detection.
        """
        if not self.cfg.enabled or not self.cfg.webhook_url:
            return False
        if int(alert.severity) < self.cfg.min_severity:
            return False

        body = json.dumps(alert.to_dict(), separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json", "X-Wyvern-Event": "alert"}
        if self.cfg.signing_secret:
            sig = hmac.new(
                self.cfg.signing_secret.encode("utf-8"), body, hashlib.sha256
            ).hexdigest()
            headers["X-Wyvern-Signature"] = f"sha256={sig}"

        try:
            status = self._sender(self.cfg.webhook_url, body, headers, self.cfg.timeout_s)
        except Exception:  # noqa: BLE001 - actuator/network failures must not crash the monitor
            log.warning("enforcement dispatch failed for alert %s", alert.id, exc_info=True)
            return False

        ok = 200 <= status < 300
        if ok:
            log.info(
                "enforcement dispatched alert %s -> %s (%s)", alert.id, self.cfg.webhook_url, status
            )
        else:
            log.warning("enforcement actuator returned %s for alert %s", status, alert.id)
        return ok


def build_bridge(config: EnforceConfig) -> EnforcementBridge | None:
    if not config.enabled:
        return None
    return EnforcementBridge(config)
