"""The composite Toronto AI worm signature correlator.

No single behaviour proves an AI worm — scanning, lateral movement, credential
reuse, SSH-key propagation, inference-proxying, beaconing and idle-device code
execution each occur benignly on occasion. The worm is distinctive because **one
device exhibits several of these stages together**, in sequence, as it gains a
foothold and replicates (Figures 2-3 of the paper).

This correlator consumes the *alerts* emitted by the per-stage detectors and,
per device, tracks the set of distinct worm stages seen within a correlation
window. Crossing the configured stage counts escalates to a HIGH or CRITICAL
"AI worm" verdict that names the likely-compromised device.
"""

from __future__ import annotations

from ..constants import (
    PAPER_REFERENCE,
    STAGE_INFERENCE,
    STAGE_INFERENCE_TIMING,
    WORM_STAGES,
)
from ..models.alert import Alert, Severity
from ..models.device import DeviceRole
from .base import Cooldown, DetectorContext, clamp01

WORM_STAGE_SET = frozenset(WORM_STAGES)
COMPOSITE_STAGE = "worm"
# How much a matching token-timing rhythm lifts confidence in an inference-proxy
# finding when both fire on the same device (Alhazbi et al. 2025 corroboration).
_TIMING_CORROBORATION_BOOST = 0.15

# Friendly labels for stages in the verdict text.
_STAGE_LABELS = {
    "discovery": "network/host discovery (port scan)",
    "lateral_movement": "lateral movement",
    "exploit_attempt": "service exploitation",
    "credential_reuse": "credential reuse",
    "ssh_key_injection": "SSH key propagation",
    "inference_proxy": "LLM inference proxying",
    "beacon_callback": "beacon callback",
    "idle_device_exec": "idle-device code execution",
}


class WormSignatureCorrelator:
    """Fuses per-stage alerts into an AI-worm verdict per device."""

    name = "worm_signature"

    def __init__(self, config) -> None:
        self.config = config
        self.t = config.thresholds
        # key -> {stage: (ts, confidence, detector)}
        self._stages: dict[str, dict[str, tuple[float, float, str]]] = {}
        # key -> ts of the last token-timing corroboration signal (a weak hint
        # that is *not* an independent worm stage; see :meth:`_maybe_corroborate`)
        self._timing: dict[str, float] = {}
        self._last_count: dict[str, int] = {}
        self._cool = Cooldown(self.t.worm_window_s / 2.0)
        self._corrob_cool = Cooldown(self.t.worm_window_s / 2.0)

    def correlate(self, alerts: list[Alert], ctx: DetectorContext, now: float) -> list[Alert]:
        touched: set[str] = set()
        for alert in alerts:
            key = alert.src_mac or alert.src_ip
            if not key:
                continue
            if alert.stage == STAGE_INFERENCE_TIMING:
                # Weak corroborating hint — recorded on the side, never counted
                # as one of the distinct worm stages.
                self._timing[key] = alert.ts or now
                touched.add(key)
                continue
            if alert.stage not in WORM_STAGE_SET:
                continue
            self._stages.setdefault(key, {})[alert.stage] = (
                alert.ts or now,
                alert.confidence,
                alert.detector,
            )
            touched.add(key)

        out: list[Alert] = []
        for key in touched:
            self._prune(key, now)
            corrob = self._maybe_corroborate(key, ctx, now)
            if corrob is not None:
                out.append(corrob)
            stages = self._stages.get(key, {})
            count = len(stages)
            if count < self.t.worm_stages_high:
                continue
            last = self._last_count.get(key, 0)
            if count < last:  # stages expired; allow re-growth
                last = count
            # Fire on first reaching HIGH, on escalation to CRITICAL, and on any
            # further growth (rate-limited) — so an in-progress worm escalates.
            crossed_high = count >= self.t.worm_stages_high > last
            crossed_critical = count >= self.t.worm_stages_critical > last
            grew = count > last and self._cool.ready(key, now)
            if crossed_high or crossed_critical or grew:
                self._last_count[key] = count
                self._cool.stamp(key, now)
                out.append(self._compose(key, stages, ctx, now))
            else:
                self._last_count[key] = last
        return out

    def active_stages(self, key: str, now: float) -> list[str]:
        self._prune(key, now)
        return sorted(self._stages.get(key, {}).keys())

    def _maybe_corroborate(self, key: str, ctx: DetectorContext, now: float) -> Alert | None:
        """When a device shows *both* an inference-proxy finding and the token-
        timing rhythm within the window, emit a single boosted corroboration
        alert. This is the "raise confidence when both fire" path: the timing
        signal reinforces the existing detection rather than acting alone.
        """
        timing_ts = self._timing.get(key)
        if timing_ts is None or (now - timing_ts) > self.t.worm_window_s:
            return None
        inference = self._stages.get(key, {}).get(STAGE_INFERENCE)
        if inference is None:
            return None
        if not self._corrob_cool.fire(("corroborate", key), now):
            return None
        _inf_ts, inf_conf, _inf_det = inference
        confidence = clamp01(inf_conf + _TIMING_CORROBORATION_BOOST)
        device = ctx.registry.get(key) or ctx.registry.get_by_ip(key)
        label = device.label if device else key
        role = device.role.value if device else DeviceRole.UNKNOWN.value
        return Alert(
            detector="stream_timing",
            title=f"LLM inference over encrypted HTTPS corroborated on {label}",
            severity=Severity.from_confidence(confidence),
            confidence=confidence,
            stage=STAGE_INFERENCE,
            description=(
                f"{label} ({role}) produced an inference-proxy signal *and* a matching "
                "token-streaming timing rhythm on encrypted HTTPS. Two independent passive "
                "signals — port/URL and inter-packet cadence (Alhazbi et al. 2025) — now "
                "point at the same device routing LLM inference, raising confidence beyond "
                "either signal alone. No payload was decrypted."
            ),
            src_mac=device.mac if device else (key if ":" in str(key) else None),
            src_ip=device.ip if device else (key if "." in str(key) else None),
            ts=now,
            evidence={
                "corroborating_signals": ["inference_api", "stream_timing"],
                "base_confidence": round(inf_conf, 3),
                "boosted_confidence": round(confidence, 3),
                "reference": "Alhazbi et al. 2025, IEEE OJ-COMS",
            },
        )

    def _prune(self, key: str, now: float) -> None:
        horizon = now - self.t.worm_window_s
        timing_ts = self._timing.get(key)
        if timing_ts is not None and timing_ts < horizon:
            self._timing.pop(key, None)
        bucket = self._stages.get(key)
        if not bucket:
            return
        for stage in [s for s, (ts, *_rest) in bucket.items() if ts < horizon]:
            del bucket[stage]
        if not bucket:
            self._stages.pop(key, None)

    def _compose(self, key, stages, ctx: DetectorContext, now: float) -> Alert:
        n = len(stages)
        device = ctx.registry.get(key) or ctx.registry.get_by_ip(key)
        label = device.label if device else key
        role = device.role.value if device else DeviceRole.UNKNOWN.value
        max_conf = max(conf for _, conf, _ in stages.values())

        critical = n >= self.t.worm_stages_critical
        severity = Severity.CRITICAL if critical else Severity.HIGH
        confidence = clamp01(max(0.90 if critical else 0.75, 0.50 + 0.13 * n, max_conf))

        stage_names = sorted(stages.keys())
        stage_text = ", ".join(_STAGE_LABELS.get(s, s) for s in stage_names)
        return Alert(
            detector=self.name,
            title=f"Toronto AI worm signature — {n} propagation stages on {label}",
            severity=severity,
            confidence=confidence,
            stage=COMPOSITE_STAGE,
            description=(
                f"{label} ({role}) exhibited {n} distinct AI-worm propagation "
                f"stages within {int(self.t.worm_window_s // 60)} minutes: "
                f"{stage_text}. This composite pattern matches the AI-driven "
                f"adaptive computer worm characterised in {PAPER_REFERENCE}. "
                f"{label} is the most likely compromised device."
            ),
            src_mac=device.mac if device else (key if ":" in str(key) else None),
            src_ip=device.ip if device else (key if "." in str(key) else None),
            ts=now,
            evidence={
                "stage_count": n,
                "stages": stage_names,
                "contributing_detectors": sorted({d for _, _, d in stages.values()}),
                "likely_compromised": label,
                "paper_reference": PAPER_REFERENCE,
            },
        )
