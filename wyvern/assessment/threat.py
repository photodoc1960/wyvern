"""Threat assessment — aggregate alerts into per-device and network verdicts.

Turns a stream of individual alerts into the questions an operator actually
asks: *How bad is it? Which device is likely compromised? What do I do?* —
expressed as a Low/Medium/High/Critical level, a 0-100 score, the worm stages
seen, and a deduplicated list of manual remediation steps.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Optional

from ..config import Config
from ..constants import WORM_STAGES
from ..models.alert import Alert, Severity
from ..models.device import DeviceRole
from ..tracking.registry import DeviceRegistry
from .remediation import recommendations_for

_SEVERITY_WEIGHT = {
    Severity.LOW: 10.0,
    Severity.MEDIUM: 25.0,
    Severity.HIGH: 50.0,
    Severity.CRITICAL: 85.0,
}
_WORM_STAGE_SET = frozenset(WORM_STAGES)


def _level_from_score(score: float) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 55:
        return Severity.HIGH
    if score >= 30:
        return Severity.MEDIUM
    return Severity.LOW


@dataclass(frozen=True, slots=True)
class DeviceThreat:
    key: str
    label: str
    mac: Optional[str]
    ip: Optional[str]
    role: str
    level: Severity
    score: float
    confidence: float
    stages: tuple[str, ...]
    detectors: tuple[str, ...]
    alert_count: int
    last_alert_ts: float
    is_worm_suspect: bool
    recommendations: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "mac": self.mac,
            "ip": self.ip,
            "role": self.role,
            "level": int(self.level),
            "level_label": self.level.label,
            "score": round(self.score, 1),
            "confidence": round(self.confidence, 3),
            "stages": list(self.stages),
            "detectors": list(self.detectors),
            "alert_count": self.alert_count,
            "last_alert_ts": self.last_alert_ts,
            "is_worm_suspect": self.is_worm_suspect,
            "recommendations": list(self.recommendations),
        }


@dataclass(frozen=True, slots=True)
class NetworkAssessment:
    generated_at: float
    overall_level: Severity
    device_threats: tuple[DeviceThreat, ...]
    likely_compromised: Optional[str]
    summary: str

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "overall_level": int(self.overall_level),
            "overall_level_label": self.overall_level.label,
            "likely_compromised": self.likely_compromised,
            "summary": self.summary,
            "device_threats": [d.to_dict() for d in self.device_threats],
        }


class ThreatAssessor:
    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config.default()
        self.horizon = self.config.thresholds.worm_window_s

    def assess(
        self,
        alerts: Iterable[Alert],
        registry: DeviceRegistry,
        now: Optional[float] = None,
    ) -> NetworkAssessment:
        alerts = list(alerts)
        if not alerts:
            ts = now if now is not None else time.time()
            return NetworkAssessment(ts, Severity.LOW, (), None, "No active threats detected.")

        latest = max(a.ts for a in alerts if a.ts) or (now or time.time())
        ref = now if now is not None else latest
        cutoff = latest - self.horizon
        recent = [a for a in alerts if (a.ts or latest) >= cutoff]

        groups: dict[str, list[Alert]] = {}
        for alert in recent:
            key = alert.src_mac or alert.src_ip
            if not key:
                continue
            groups.setdefault(key, []).append(alert)

        threats = [self._assess_device(key, items, registry) for key, items in groups.items()]
        threats.sort(key=lambda t: (t.score, t.is_worm_suspect, t.alert_count), reverse=True)

        if not threats:
            return NetworkAssessment(ref, Severity.LOW, (), None, "No attributable threats.")

        overall = max((t.level for t in threats), default=Severity.LOW)
        top = threats[0]
        likely = top.label if (top.is_worm_suspect or top.level >= Severity.HIGH) else None
        return NetworkAssessment(
            generated_at=ref,
            overall_level=overall,
            device_threats=tuple(threats),
            likely_compromised=likely,
            summary=self._summary(overall, threats, likely),
        )

    def _assess_device(self, key: str, items: list[Alert], registry: DeviceRegistry) -> DeviceThreat:
        device = registry.get(key) or registry.get_by_ip(key)
        severities = [a.severity for a in items]
        weights = sorted((_SEVERITY_WEIGHT[s] for s in severities), reverse=True)
        worm_stages = sorted({a.stage for a in items if a.stage in _WORM_STAGE_SET})
        has_composite = any(a.detector == "worm_signature" for a in items)

        score = weights[0] if weights else 0.0
        score += 0.4 * sum(weights[1:])
        score += 6.0 * len(worm_stages)
        if has_composite:
            score += 15.0
        score = min(100.0, score)

        max_sev = max(severities, default=Severity.LOW)
        level = max(_level_from_score(score), max_sev)
        is_worm = has_composite or len(worm_stages) >= 2
        confidence = max((a.confidence for a in items), default=0.0)
        last_ts = max((a.ts for a in items), default=0.0)

        return DeviceThreat(
            key=key,
            label=(device.label if device else key),
            mac=device.mac if device else (key if ":" in key else None),
            ip=device.ip if device else (key if "." in key else None),
            role=(device.role.value if device else DeviceRole.UNKNOWN.value),
            level=level,
            score=score,
            confidence=confidence,
            stages=tuple(worm_stages),
            detectors=tuple(sorted({a.detector for a in items})),
            alert_count=len(items),
            last_alert_ts=last_ts,
            is_worm_suspect=is_worm,
            recommendations=self._merge_recommendations(items, device),
        )

    @staticmethod
    def _merge_recommendations(items: list[Alert], device) -> tuple[str, ...]:
        ordered = sorted(items, key=lambda a: (a.detector != "worm_signature", -int(a.severity)))
        seen: list[str] = []
        for alert in ordered:
            recs = alert.recommendations or recommendations_for(alert, device)
            for rec in recs:
                if rec not in seen:
                    seen.append(rec)
        return tuple(seen[:8])

    @staticmethod
    def _summary(overall: Severity, threats, likely: Optional[str]) -> str:
        worm_suspects = [t for t in threats if t.is_worm_suspect]
        if worm_suspects:
            names = ", ".join(t.label for t in worm_suspects[:3])
            return (
                f"{overall.label} threat: AI-worm propagation signatures on "
                f"{len(worm_suspects)} device(s) ({names}). "
                f"Likely compromised: {likely}. Isolate and investigate now."
            )
        active = [t for t in threats if t.level >= Severity.MEDIUM]
        if active:
            return (
                f"{overall.label} threat: {len(active)} device(s) showing "
                f"suspicious behaviour. Most notable: {threats[0].label}."
            )
        return f"{overall.label}: low-level anomalies only; continue monitoring."
