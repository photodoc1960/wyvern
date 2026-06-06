"""Tests for the notifier (desktop + optional email)."""

from __future__ import annotations

from wyvern.alerting.notifier import Notifier, build_notifier
from wyvern.config import NotifyConfig
from wyvern.models.alert import Alert, Severity


def _alert(sev=Severity.CRITICAL):
    return Alert(detector="beacon", title="Beacon", severity=sev, confidence=0.9,
                 description="callback", recommendations=("Isolate it",))


def test_build_notifier_none_when_all_disabled():
    assert build_notifier(NotifyConfig(desktop_enabled=False, email_enabled=False)) is None
    assert build_notifier(NotifyConfig()) is not None


def test_below_min_severity_is_silent(monkeypatch):
    calls = []
    n = Notifier(NotifyConfig(min_severity=4))
    monkeypatch.setattr(Notifier, "_desktop", lambda self, a: calls.append(a))
    n.notify(_alert(Severity.HIGH))     # below Critical threshold -> ignored
    assert calls == []
    n.notify(_alert(Severity.CRITICAL))
    assert len(calls) == 1


def test_desktop_falls_back_to_log(monkeypatch):
    # notify-send missing and plyer absent -> must not raise
    monkeypatch.setattr(Notifier, "_notify_send", staticmethod(lambda t, b: False))
    monkeypatch.setattr(Notifier, "_plyer", staticmethod(lambda t, b: False))
    Notifier(NotifyConfig()).notify(_alert())


def test_email_digest(monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=0):
            sent["host"] = host

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            pass

        def login(self, u, p):
            sent["login"] = (u, p)

        def send_message(self, msg):
            sent["subject"] = msg["Subject"]

    import smtplib
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    cfg = NotifyConfig(email_enabled=True, smtp_host="smtp.test", smtp_user="u",
                       smtp_password="p", email_to=("you@example.com",), min_severity=1)
    n = Notifier(cfg)
    n.notify(_alert())
    assert n.maybe_send_digest(10_000.0)
    assert sent["host"] == "smtp.test" and "Critical" in sent["subject"]
    # second call within the digest window does nothing
    assert not n.maybe_send_digest(10_001.0)
