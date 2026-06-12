"""Manual remediation recommendations.

Every recommendation here is an action for a *human* to take. Wyvern never
performs any of them — it does not isolate hosts, kill processes, rotate
credentials or change settings. It only advises. The phrasing follows the
brief's examples ("Isolate [device]...", "Change credentials on [target]...",
"Reboot [device]", "Run process scan on [device]", "Check [device]'s recent
connections in system logs").
"""

from __future__ import annotations

import dataclasses

from ..constants import (
    STAGE_BEACON,
    STAGE_CREDENTIAL,
    STAGE_INFERENCE,
    STAGE_LATERAL,
    STAGE_RECON,
    STAGE_REPLICATION,
    STAGE_SSH_KEY,
)
from ..models.alert import Alert
from ..models.device import Device

_ISOLATE = (
    "Isolate {dev} from the network immediately (manually, e.g. unplug or block at the switch/AP)."
)
_PROC_SCAN = (
    "Run a process/anti-malware scan on {dev} and look for unexpected agents or LLM runtimes."
)
_CHECK_LOGS = "Check {dev}'s recent connections and authentication entries in its system logs."
_REBOOT = "Power-cycle / reboot {dev} after capturing evidence (note: a reboot may not remove persistence)."
_CHANGE_CREDS = "Change credentials on the targeted hosts ({targets}) and rotate any shared keys."
_CHECK_KEYS = "Inspect ~/.ssh/authorized_keys on the targeted hosts ({targets}) for injected keys."
_BLOCK_C2 = (
    "Investigate and block the external callback destination ({targets}) at your firewall/router."
)
_FIRMWARE = (
    "Treat {dev} as compromised firmware: factory-reset / re-flash it; do not trust a soft reboot."
)
_INVESTIGATE_DOMAIN = "Review the suspicious domains in {dev}'s DNS history; block them at your resolver if confirmed."

# stage -> ordered list of recommendation templates
_STAGE_RECS: dict[str, tuple[str, ...]] = {
    "worm": (_ISOLATE, _PROC_SCAN, _CHECK_LOGS, _CHANGE_CREDS, _REBOOT),
    STAGE_RECON: (_CHECK_LOGS, _PROC_SCAN),
    STAGE_LATERAL: (_ISOLATE, _PROC_SCAN, _CHECK_LOGS),
    STAGE_CREDENTIAL: (_CHANGE_CREDS, _ISOLATE, _CHECK_LOGS),
    STAGE_SSH_KEY: (_CHECK_KEYS, _CHANGE_CREDS, _ISOLATE),
    STAGE_INFERENCE: (_ISOLATE, _PROC_SCAN, _CHECK_LOGS),
    STAGE_BEACON: (_ISOLATE, _BLOCK_C2, _PROC_SCAN),
    STAGE_REPLICATION: (_ISOLATE, _FIRMWARE, _PROC_SCAN),
}

_DETECTOR_RECS: dict[str, tuple[str, ...]] = {
    "dns_anomaly": (_INVESTIGATE_DOMAIN, _CHECK_LOGS),
}


def recommendations_for(
    alert: Alert,
    device: Device | None = None,
    targets: str | None = None,
) -> tuple[str, ...]:
    """Return manual remediation steps for an alert, with placeholders filled."""
    dev_label = (device.label if device else None) or alert.src_ip or alert.src_mac or "the device"
    target_text = targets or _targets_from_alert(alert) or "the contacted hosts"

    templates = _STAGE_RECS.get(alert.stage or "") or _DETECTOR_RECS.get(alert.detector)
    if not templates:
        templates = (_CHECK_LOGS, _PROC_SCAN)

    out: list[str] = []
    for tmpl in templates:
        text = tmpl.format(dev=dev_label, targets=target_text)
        if text not in out:
            out.append(text)
    return tuple(out)


def enrich(alert: Alert, device: Device | None = None) -> Alert:
    """Return a copy of ``alert`` with remediation recommendations attached."""
    if alert.recommendations:
        return alert
    return dataclasses.replace(alert, recommendations=recommendations_for(alert, device))


def _targets_from_alert(alert: Alert) -> str | None:
    ev = alert.evidence or {}
    for key in ("sample_hosts", "ssh_targets", "sample_peers"):
        vals = ev.get(key)
        if vals:
            shown = ", ".join(str(v) for v in list(vals)[:5])
            return shown + (" …" if len(vals) > 5 else "")
    if alert.dst_ip:
        return alert.dst_ip
    target = ev.get("target") or ev.get("host")
    return str(target) if target else None
