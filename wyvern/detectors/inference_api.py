"""Inference / GPU-API query detection — the worm's "reasoning proxy".

The AI worm runs an open-weight LLM on compromised GPU hosts; agents on non-GPU
devices forward their reasoning to those hosts via an OpenAI-compatible API
(Figure 1). So an LLM inference request *originating from a device that has no
business running models* — a printer, camera, router, NAS, or ICS sensor — is a
high-signal indicator. We also flag inference from a device that never made such
calls during baseline, and sustained inference-rate spikes.
"""

from __future__ import annotations

from ..constants import STAGE_INFERENCE
from ..indicators import inference_confidence
from ..models.alert import Alert, Severity
from ..models.device import IDLE_ROLES, DeviceRole
from ..models.events import HttpEvent, NetworkEvent
from ..util.timewindow import KeyedWindows
from .base import Cooldown, Detector, DetectorContext, clamp01


class InferenceApiDetector(Detector):
    name = "inference_api"

    def __init__(self, config) -> None:
        super().__init__(config)
        self._rate = KeyedWindows(self.t.inference_window_s)
        self._cool = Cooldown(self.t.inference_window_s)

    def inspect(self, event: NetworkEvent, ctx: DetectorContext) -> list[Alert]:
        if not isinstance(event, HttpEvent):
            return []
        base = inference_confidence(event.host, event.path, event.dst_port)
        if base <= 0.0:
            return []

        device = ctx.device_for(event)
        sid = device.mac if device else event.src_ip
        label = device.label if device else event.src_ip
        role = device.role if device else DeviceRole.UNKNOWN
        gpu_capable = device.gpu_capable if device else False
        profile = ctx.profiles.get(device.mac) if device else None

        win = self._rate.add(sid, event.ts, event.ts)
        count = win.count(event.ts)
        rate = count / (self.t.inference_window_s / 60.0)

        idle = role in IDLE_ROLES
        non_gpu = not gpu_capable
        new_for_device = bool(profile and profile.learned and not profile.ever_inference)
        rate_spike = rate >= self.t.inference_rate_per_min

        # Don't alert on an ordinary GPU/workstation making its usual calls.
        if not (non_gpu or new_for_device or rate_spike):
            return []
        if not self._cool.fire(sid, event.ts):
            return []

        confidence = 0.45 * base
        if idle:
            confidence = max(confidence, 0.85)
        elif non_gpu:
            confidence = max(confidence, 0.70)
        if new_for_device:
            confidence = max(confidence, 0.60)
        if rate_spike:
            confidence = clamp01(confidence + 0.10)
        confidence = clamp01(confidence)

        target = event.host or event.dst_ip
        title = (
            "Inference/GPU API query from non-GPU device"
            if non_gpu
            else "Unusual LLM inference activity"
        )
        description = (
            f"{label} ({role.value}) sent LLM inference request(s) to "
            f"{target}:{event.dst_port} (endpoint {event.path or 'TLS/SNI'})."
        )
        if idle:
            description += (
                " A normally-idle device acting as a worm 'reasoning proxy' to a "
                "compromised GPU host."
            )

        return [
            Alert(
                detector=self.name,
                title=title,
                severity=Severity.from_confidence(confidence),
                confidence=confidence,
                stage=STAGE_INFERENCE,
                description=description,
                src_mac=device.mac if device else event.src_mac,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                dst_port=event.dst_port,
                ts=event.ts,
                evidence={
                    "endpoint": event.path,
                    "host": event.host,
                    "client_gpu_capable": gpu_capable,
                    "client_role": role.value,
                    "requests_in_window": count,
                    "rate_per_min": round(rate, 1),
                },
            )
        ]
