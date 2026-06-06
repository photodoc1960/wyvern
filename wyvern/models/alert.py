"""The :class:`Alert` record, :class:`Severity` scale, and helpers.

Alerts are advisory only. Every alert carries a confidence score, a worm-stage
tag (when applicable), human-readable evidence, and a list of **manual**
remediation recommendations. Wyvern never acts on them automatically.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Mapping


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_confidence(cls, confidence: float) -> "Severity":
        """Map a 0..1 confidence onto the four-level scale."""
        if confidence >= 0.85:
            return cls.CRITICAL
        if confidence >= 0.65:
            return cls.HIGH
        if confidence >= 0.40:
            return cls.MEDIUM
        return cls.LOW


def new_alert_id() -> str:
    return uuid.uuid4().hex[:12]


@dataclass(frozen=True, slots=True)
class Alert:
    detector: str
    title: str
    severity: Severity
    confidence: float
    description: str
    src_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    stage: str | None = None
    recommendations: tuple[str, ...] = ()
    evidence: Mapping[str, Any] = field(default_factory=dict)
    ts: float = 0.0
    id: str = field(default_factory=new_alert_id)

    def __post_init__(self) -> None:
        # Isolate evidence from the caller's dict and clamp confidence to [0,1].
        object.__setattr__(self, "evidence", dict(self.evidence))
        object.__setattr__(self, "confidence", max(0.0, min(1.0, float(self.confidence))))

    @property
    def severity_label(self) -> str:
        return self.severity.label

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        return cls(
            detector=data.get("detector", "unknown"),
            title=data.get("title", ""),
            severity=Severity(int(data.get("severity", 1))),
            confidence=float(data.get("confidence", 0.0)),
            description=data.get("description", ""),
            src_mac=data.get("src_mac"),
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            dst_port=data.get("dst_port"),
            stage=data.get("stage"),
            recommendations=tuple(data.get("recommendations", ()) or ()),
            evidence=data.get("evidence", {}) or {},
            ts=float(data.get("ts", 0.0)),
            id=data.get("id") or new_alert_id(),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts,
            "detector": self.detector,
            "title": self.title,
            "severity": int(self.severity),
            "severity_label": self.severity.label,
            "confidence": round(self.confidence, 3),
            "description": self.description,
            "src_mac": self.src_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "stage": self.stage,
            "recommendations": list(self.recommendations),
            "evidence": dict(self.evidence),
        }
