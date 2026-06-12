"""Desktop notifications and optional email digests.

Notifications are the only thing Wyvern *emits* outward, and even then only at or
above a configured severity. Email is disabled by default and only ever sends
when the operator explicitly configures SMTP (host, recipients) and supplies a
password via the environment — sending is the operator's choice, never automatic.
"""

from __future__ import annotations

import logging
import subprocess
from collections import deque

from ..config import NotifyConfig
from ..models.alert import Alert

log = logging.getLogger("wyvern.notify")


class Notifier:
    def __init__(self, config: NotifyConfig) -> None:
        self.cfg = config
        # Bounded so a persistent SMTP failure during an alert storm can't grow
        # the queue without limit; oldest pending alerts are dropped first.
        self._pending: deque[Alert] = deque(maxlen=500)
        self._last_digest = 0.0

    def notify(self, alert: Alert, device=None) -> None:
        if int(alert.severity) < self.cfg.min_severity:
            return
        if self.cfg.desktop_enabled:
            self._desktop(alert)
        if self.cfg.email_enabled:
            self._pending.append(alert)

    # ------------------------------------------------------------- desktop
    def _desktop(self, alert: Alert) -> None:
        title = f"Wyvern: {alert.severity.label} — {alert.title}"
        body = (alert.description or "")[:240]
        if self._notify_send(title, body) or self._plyer(title, body):
            return
        log.info("DESKTOP ALERT %s: %s", alert.severity.label, alert.title)

    @staticmethod
    def _notify_send(title: str, body: str) -> bool:
        try:
            subprocess.run(
                ["notify-send", "-a", "Wyvern", title, body],
                check=False,
                timeout=5,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def _plyer(title: str, body: str) -> bool:
        try:
            from plyer import notification  # type: ignore

            notification.notify(title=title, message=body, app_name="Wyvern", timeout=10)
            return True
        except Exception:  # noqa: BLE001 - plyer optional / backend may be absent
            return False

    # --------------------------------------------------------------- email
    def maybe_send_digest(self, now: float) -> bool:
        if not (self.cfg.email_enabled and self._pending):
            return False
        if now - self._last_digest < self.cfg.email_digest_min_s:
            return False
        sent = self._send_email(list(self._pending))
        if sent:
            self._pending.clear()
            self._last_digest = now
        return sent

    def _send_email(self, alerts: list[Alert]) -> bool:
        import smtplib
        from email.message import EmailMessage

        msg = EmailMessage()
        top = max(alerts, key=lambda a: int(a.severity))
        msg["Subject"] = f"[Wyvern] {top.severity.label}: {len(alerts)} alert(s)"
        msg["From"] = self.cfg.email_from or (self.cfg.smtp_user or "wyvern@localhost")
        msg["To"] = ", ".join(self.cfg.email_to)
        msg.set_content(_render_digest(alerts))
        try:
            with smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port, timeout=15) as server:
                server.starttls()
                if self.cfg.smtp_user and self.cfg.smtp_password:
                    server.login(self.cfg.smtp_user, self.cfg.smtp_password)
                server.send_message(msg)
            log.info("emailed digest of %d alerts", len(alerts))
            return True
        except Exception:  # noqa: BLE001 - network/SMTP failures must not crash
            log.warning("email digest failed", exc_info=True)
            return False


def _render_digest(alerts: list[Alert]) -> str:
    lines = ["Wyvern detected the following network anomalies:\n"]
    for a in sorted(alerts, key=lambda x: int(x.severity), reverse=True):
        lines.append(f"[{a.severity.label}] {a.title}")
        lines.append(f"    {a.description}")
        if a.recommendations:
            lines.append(f"    -> {a.recommendations[0]}")
        lines.append("")
    lines.append("Wyvern only observes and recommends; take any action manually.")
    return "\n".join(lines)


def build_notifier(config: NotifyConfig) -> Notifier | None:
    if not (config.desktop_enabled or config.email_enabled):
        return None
    return Notifier(config)
