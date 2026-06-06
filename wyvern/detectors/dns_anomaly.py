"""DNS anomaly detection: query spikes, NXDOMAIN bursts, and DGA-style domains.

These are softer, supporting signals (C2 lookups, domain-generation algorithms)
rather than hard worm stages, so they raise a device's threat level and feed the
timeline without, on their own, asserting "worm".
"""

from __future__ import annotations

from ..models.alert import Alert, Severity
from ..models.events import DnsEvent, NetworkEvent
from ..util.entropy import dga_score
from ..util.timewindow import KeyedWindows
from .base import Cooldown, Detector, DetectorContext, clamp01


class DnsAnomalyDetector(Detector):
    name = "dns_anomaly"

    def __init__(self, config) -> None:
        super().__init__(config)
        self._queries = KeyedWindows(self.t.dns_window_s)
        self._nxdomain = KeyedWindows(self.t.dns_window_s)
        self._spike_cool = Cooldown(self.t.dns_window_s)
        self._nx_cool = Cooldown(self.t.dns_window_s)
        self._dga_cool = Cooldown(300.0)

    def inspect(self, event: NetworkEvent, ctx: DetectorContext) -> list[Alert]:
        if not isinstance(event, DnsEvent):
            return []
        if event.is_response:
            return self._inspect_response(event, ctx)
        return self._inspect_query(event, ctx)

    def _inspect_query(self, event: DnsEvent, ctx: DetectorContext) -> list[Alert]:
        querier = ctx.registry.resolve(event.src_ip, event.src_mac)
        qid = querier.mac if querier else event.src_ip
        label = querier.label if querier else event.src_ip
        alerts: list[Alert] = []

        win = self._queries.add(qid, event.ts, event.qname)
        count = win.count(event.ts)
        rate = count / (self.t.dns_window_s / 60.0)
        if rate >= self.t.dns_rate_per_min and self._spike_cool.fire(qid, event.ts):
            confidence = clamp01(
                0.40 + 0.30 * min(1.0, (rate - self.t.dns_rate_per_min) / self.t.dns_rate_per_min)
            )
            alerts.append(
                Alert(
                    detector=self.name,
                    title=f"DNS query spike — {int(rate)}/min",
                    severity=Severity.from_confidence(confidence),
                    confidence=confidence,
                    stage=None,
                    description=f"{label} issued {count} DNS queries in "
                    f"{int(self.t.dns_window_s)}s ({int(rate)}/min).",
                    src_mac=querier.mac if querier else event.src_mac,
                    src_ip=event.src_ip,
                    ts=event.ts,
                    evidence={"count": count, "rate_per_min": round(rate, 1)},
                )
            )

        score = dga_score(event.qname)
        if score >= self.t.dga_score and self._dga_cool.fire((qid, event.qname), event.ts):
            confidence = clamp01(0.30 + 0.45 * score)
            alerts.append(
                Alert(
                    detector=self.name,
                    title="Query to algorithmically-generated domain",
                    severity=Severity.from_confidence(confidence),
                    confidence=confidence,
                    stage=None,
                    description=f"{label} resolved {event.qname!r} "
                    f"(DGA score {score:.2f}) — possible C2 rendezvous.",
                    src_mac=querier.mac if querier else event.src_mac,
                    src_ip=event.src_ip,
                    ts=event.ts,
                    evidence={"domain": event.qname, "dga_score": score},
                )
            )
        return alerts

    def _inspect_response(self, event: DnsEvent, ctx: DetectorContext) -> list[Alert]:
        if not event.is_nxdomain or not event.dst_ip:
            return []
        querier = ctx.registry.get_by_ip(event.dst_ip)
        qid = querier.mac if querier else event.dst_ip
        label = querier.label if querier else event.dst_ip
        win = self._nxdomain.add(qid, event.ts, event.qname)
        count = win.count(event.ts)
        if count < self.t.dns_nxdomain_burst or not self._nx_cool.fire(qid, event.ts):
            return []
        confidence = clamp01(
            0.45 + 0.30 * min(1.0, (count - self.t.dns_nxdomain_burst) / self.t.dns_nxdomain_burst)
        )
        return [
            Alert(
                detector=self.name,
                title=f"NXDOMAIN burst — {count} failed lookups",
                severity=Severity.from_confidence(confidence),
                confidence=confidence,
                stage=None,
                description=f"{label} received {count} NXDOMAIN responses in "
                f"{int(self.t.dns_window_s)}s — DGA/C2 domain enumeration pattern.",
                src_mac=querier.mac if querier else None,
                src_ip=event.dst_ip,
                ts=event.ts,
                evidence={"nxdomain_count": count, "window_seconds": self.t.dns_window_s},
            )
        ]
