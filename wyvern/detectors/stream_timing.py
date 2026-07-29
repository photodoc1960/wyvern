"""Passive stream-timing corroboration for HTTPS-tunnelled LLM inference.

The ``inference_api`` detector matches known local inference ports and cleartext
HTTP/SNI patterns, so it is blind to a worm that routes its reasoning proxy over
standard HTTPS to an external API — port 443, encrypted payload, nothing to
match (see docs/THREAT_MODEL.md, "`inference_api` blind to LLM inference routed
over HTTPS").

Alhazbi et al. (2025, IEEE OJ-COMS) show that LLM autoregressive generation
leaves a distinctive *inter-packet timing* rhythm (~tens of ms between tokens)
on the streamed response, detectable through TLS **without any decryption** —
timing metadata only. This detector measures that cadence on long-lived HTTPS
response streams and emits a deliberately *weak, corroborating* signal. It is
never a standalone verdict: the worm-signature correlator only lets it reinforce
an existing ``inference_proxy`` finding (see ``worm_signature.py``).

Like the beacon detector, periodicity only emerges over time, so this is a
sweep detector: ``inspect`` accumulates per-flow arrival timestamps and
``sweep`` scores the cadence.
"""

from __future__ import annotations

from ..constants import STAGE_INFERENCE_TIMING
from ..models.alert import Alert, Severity
from ..models.events import NetworkEvent, StreamSegmentEvent
from ..util.timewindow import KeyedWindows, coefficient_of_variation, intervals
from .base import Cooldown, Detector, DetectorContext


class StreamTimingDetector(Detector):
    name = "stream_timing"

    def __init__(self, config) -> None:
        super().__init__(config)
        # key (client_ip, client_port, server_ip) -> window of (ts, payload_len)
        self._streams = KeyedWindows(self.t.stream_timing_window_s)
        self._cool = Cooldown(self.t.stream_timing_window_s)

    def inspect(self, event: NetworkEvent, ctx: DetectorContext) -> list[Alert]:
        if not isinstance(event, StreamSegmentEvent):
            return []
        # Only the response direction (server:443 -> client) carries the cadence.
        if not event.to_client or event.src_port not in self.t.stream_timing_ports:
            return []
        # The client receiving the stream must be an internal device that has no
        # business running models. Skip declared/ inferred GPU hosts and
        # workstations — streaming LLM output to them is expected.
        client_ip = event.dst_ip
        if not ctx.internal(client_ip):
            return []
        device = ctx.registry.get_by_ip(client_ip)
        if device is not None and device.gpu_capable:
            return []
        key = (client_ip, event.dst_port, event.src_ip)
        self._streams.add(key, event.ts, event.payload_len)
        return []

    def sweep(self, ctx: DetectorContext) -> list[Alert]:
        now = ctx.now
        alerts: list[Alert] = []
        for key in self._streams.keys():
            win = self._streams.get(key)
            stamps = win.timestamps(now)
            if len(stamps) < self.t.stream_timing_min_segments:
                continue
            gaps = intervals(stamps)
            if not gaps:
                continue
            mean_gap_ms = (sum(gaps) / len(gaps)) * 1000.0
            if not (
                self.t.stream_timing_min_gap_ms <= mean_gap_ms <= self.t.stream_timing_max_gap_ms
            ):
                continue
            cov = coefficient_of_variation(gaps)
            if cov is None or not (
                self.t.stream_timing_cov_lo <= cov <= self.t.stream_timing_cov_hi
            ):
                continue
            sizes = win.items(now)
            mean_size = sum(sizes) / len(sizes)
            if mean_size > self.t.stream_timing_max_payload_mean:
                continue
            if not self._cool.fire(key, now):
                continue
            alerts.append(self._make_alert(key, len(stamps), mean_gap_ms, cov, mean_size, ctx, now))
        self._streams.prune(now)
        return alerts

    def _make_alert(self, key, segments, mean_gap_ms, cov, mean_size, ctx, now) -> Alert:
        client_ip, client_port, server_ip = key
        device = ctx.registry.get_by_ip(client_ip)
        label = device.label if device else client_ip
        role = device.role.value if device else "unknown"
        confidence = self.t.stream_timing_confidence
        return Alert(
            detector=self.name,
            title="Token-streaming timing cadence on encrypted HTTPS",
            severity=Severity.LOW,
            confidence=confidence,
            stage=STAGE_INFERENCE_TIMING,
            description=(
                f"A long-lived HTTPS stream from {server_ip}:443 to {label} ({role}) "
                f"showed an inter-packet rhythm (~{int(mean_gap_ms)}ms mean gap, jitter "
                f"{cov:.0%}, {segments} small segments) consistent with LLM autoregressive "
                "token streaming. Passive timing only — no payload was inspected. This is a "
                "weak corroborating hint; it strengthens an inference-proxy finding for the "
                "same device but is not a standalone verdict."
            ),
            src_mac=device.mac if device else None,
            src_ip=client_ip,
            dst_ip=server_ip,
            dst_port=self.t.stream_timing_ports[0],
            ts=now,
            evidence={
                "segments": segments,
                "mean_gap_ms": round(mean_gap_ms, 1),
                "jitter_cov": round(cov, 3),
                "mean_payload_bytes": round(mean_size, 1),
                "server": server_ip,
                "detection": "passive inter-packet timing (no TLS interception)",
                "reference": "Alhazbi et al. 2025, IEEE OJ-COMS",
            },
        )
