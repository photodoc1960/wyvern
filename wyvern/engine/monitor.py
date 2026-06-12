"""The Monitor — Wyvern's orchestrator.

It wires the pipeline together: capture -> decode -> device tracking + baseline
learning -> detection -> correlation -> threat assessment -> storage + alerting +
live dashboard updates. It is strictly *observational*: it reads and reasons, it
never acts on the network.

Two entry points drive everything:

* :meth:`process_event` — the unit of work, used by live capture, pcap replay,
  the simulator, and the tests alike.
* :meth:`sweep` — the periodic pass that runs time-window detectors (beaconing),
  recomputes the assessment, and persists state.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Iterable

from ..assessment.remediation import enrich
from ..assessment.threat import NetworkAssessment, ThreatAssessor
from ..baseline.learner import BaselineLearner
from ..baseline.store import load_baselines, save_baselines
from ..capture.decode import decode_frame
from ..config import Config
from ..detectors.base import DetectorContext
from ..detectors.loader import default_detectors, make_correlator
from ..models.alert import Alert, Severity
from ..models.events import ConnEvent, NetworkEvent
from ..storage.db import WyvernDB
from ..storage.eventlog import EventLog
from ..tracking.registry import DeviceRegistry
from .bus import EventBus

log = logging.getLogger("wyvern.monitor")
_MAX_EDGES = 4000


class Monitor:
    def __init__(
        self,
        config: Config,
        *,
        learn: bool = True,
        notifier=None,
        bus: EventBus | None = None,
        db: WyvernDB | None = None,
        eventlog: EventLog | None = None,
    ) -> None:
        self.config = config
        config.ensure_data_dir()
        self.registry = DeviceRegistry(config)
        self.baseline = BaselineLearner(config)
        self.detectors = default_detectors(config)
        self.correlator = make_correlator(config)
        self.assessor = ThreatAssessor(config)
        self.db = db if db is not None else WyvernDB(config.db_path)
        self.eventlog = eventlog if eventlog is not None else EventLog(config.eventlog_path)
        self.bus = bus if bus is not None else EventBus()
        self.notifier = notifier
        self.learn = learn

        self._recent_alerts: deque[Alert] = deque(maxlen=5000)
        self._edges: dict[tuple[str, str], dict] = {}
        # One re-entrant lock serialises the pipeline (capture thread), the
        # sweeper thread, and Flask read threads, so none ever iterates the
        # registry/edges while another mutates them.
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._sniffer = None
        self._sweeper: threading.Thread | None = None
        self.frame_count = 0
        self.event_count = 0

        saved = load_baselines(config.baseline_path)
        if saved:
            self.baseline.seed(saved)
            log.info("seeded %d baseline profiles from disk", len(saved))

    # ----------------------------------------------------------- core path
    def process_frame(self, raw: bytes, ts: float) -> None:
        self.frame_count += 1
        for event in decode_frame(raw, ts):
            self.process_event(event)

    def process_event(self, event: NetworkEvent) -> list[Alert]:
        with self._lock:
            return self._process_locked(event)

    def _process_locked(self, event: NetworkEvent) -> list[Alert]:
        self.event_count += 1
        self.registry.observe(event)
        if self.learn:
            self.baseline.observe(event, self.registry)
        self._track_edge(event)

        ctx = DetectorContext(self.config, self.registry, self.baseline, now=event.ts)
        produced: list[Alert] = []
        for detector in self.detectors:
            produced.extend(detector.inspect(event, ctx))
        produced.extend(self.correlator.correlate(produced, ctx, event.ts))

        for alert in produced:
            self._emit(alert)
        if produced:
            self._publish_assessment(event.ts)
        return produced

    def feed_events(self, events: Iterable[NetworkEvent]) -> list[Alert]:
        out: list[Alert] = []
        last_ts = 0.0
        for event in events:
            out.extend(self.process_event(event))
            last_ts = event.ts
        self.sweep(now=last_ts or None)
        return out

    def sweep(self, now: float | None = None) -> list[Alert]:
        with self._lock:
            return self._sweep_locked(now if now is not None else time.time())

    def _sweep_locked(self, now: float) -> list[Alert]:
        ctx = DetectorContext(self.config, self.registry, self.baseline, now=now)
        produced: list[Alert] = []
        for detector in self.detectors:
            produced.extend(detector.sweep(ctx))
        produced.extend(self.correlator.correlate(produced, ctx, now))
        for alert in produced:
            self._emit(alert)

        self._persist_devices()
        try:
            save_baselines(self.baseline.snapshot(), self.config.baseline_path)
        except OSError:
            log.debug("could not persist baselines", exc_info=True)
        if self.notifier is not None:
            try:
                self.notifier.maybe_send_digest(now)
            except Exception:  # noqa: BLE001
                log.debug("email digest failed", exc_info=True)
        self._publish_assessment(now)
        return produced

    # ----------------------------------------------------------- emission
    def _emit(self, alert: Alert) -> None:
        device = self.registry.resolve(alert.src_ip, alert.src_mac)
        alert = enrich(alert, device)
        with self._lock:
            self._recent_alerts.append(alert)
        try:
            self.db.insert_alert(alert)
            self.eventlog.append_alert(alert)
        except Exception:  # noqa: BLE001 - storage must not kill the pipeline
            log.warning("failed to persist alert %s", alert.id, exc_info=True)
        self.bus.publish({"type": "alert", "alert": alert.to_dict()})
        if self.notifier is not None:
            try:
                self.notifier.notify(alert, device)
            except Exception:  # noqa: BLE001
                log.debug("notifier error", exc_info=True)
        if alert.severity >= Severity.HIGH:
            log.warning("[%s] %s", alert.severity.label, alert.title)

    def _publish_assessment(self, now: float) -> None:
        assessment = self.current_assessment(now)
        self.bus.publish({"type": "assessment", "assessment": assessment.to_dict()})

    def current_assessment(self, now: float | None = None) -> NetworkAssessment:
        with self._lock:
            alerts = list(self._recent_alerts)
            return self.assessor.assess(alerts, self.registry, now=now)

    # ----------------------------------------------------------- topology
    def _track_edge(self, event: NetworkEvent) -> None:
        if not isinstance(event, ConnEvent) or not event.is_syn:
            return
        if not self.config.internal_cidrs:
            return
        from ..util.nets import is_internal_ip

        if not (
            is_internal_ip(event.src_ip, self.config.internal_cidrs)
            and is_internal_ip(event.dst_ip, self.config.internal_cidrs)
        ):
            return
        src = self.registry.resolve(event.src_ip, event.src_mac)
        dst = self.registry.get_by_ip(event.dst_ip)
        src_key = src.mac if src else event.src_ip
        dst_key = dst.mac if dst else event.dst_ip
        if src_key == dst_key:
            return
        key = (src_key, dst_key)
        edge = self._edges.get(key)
        from ..indicators import is_worm_service_port

        if edge is None:
            if len(self._edges) >= _MAX_EDGES:
                self._edges.pop(next(iter(self._edges)))
            edge = {"src": src_key, "dst": dst_key, "count": 0, "ports": set(), "worm": False}
            self._edges[key] = edge
        edge["count"] += 1
        edge["ports"].add(event.dst_port)
        if is_worm_service_port(event.dst_port):
            edge["worm"] = True
        edge["last_seen"] = event.ts

    def _persist_devices(self) -> None:
        for device in self.registry.all():
            try:
                self.db.upsert_device(device)
            except Exception:  # noqa: BLE001
                log.debug("device persist failed", exc_info=True)

    # ----------------------------------------------------------- dashboards
    def devices(self) -> list[dict]:
        with self._lock:
            return self._devices_locked()

    def _devices_locked(self) -> list[dict]:
        assessment = self.current_assessment()
        threat_by_key = {t.key: t for t in assessment.device_threats}
        out = []
        for device in self.registry.all():
            data = device.to_dict()
            threat = threat_by_key.get(device.mac) or (
                threat_by_key.get(device.ip) if device.ip else None
            )
            data["threat_level"] = threat.level.label if threat else "None"
            data["threat_score"] = round(threat.score, 1) if threat else 0.0
            data["worm_suspect"] = threat.is_worm_suspect if threat else False
            out.append(data)
        out.sort(key=lambda d: d["threat_score"], reverse=True)
        return out

    def topology(self) -> dict:
        with self._lock:
            return self._topology_locked()

    def _topology_locked(self) -> dict:
        assessment = self.current_assessment()
        threat_by_key = {t.key: t for t in assessment.device_threats}
        nodes = []
        for device in self.registry.all():
            threat = threat_by_key.get(device.mac) or (
                threat_by_key.get(device.ip) if device.ip else None
            )
            nodes.append(
                {
                    "id": device.mac,
                    "label": device.label,
                    "role": device.role.value,
                    "ip": device.ip,
                    "gpu_capable": device.gpu_capable,
                    "suspicious": device.suspicious,
                    "threat_level": threat.level.label if threat else "None",
                    "threat_score": round(threat.score, 1) if threat else 0.0,
                    "worm_suspect": threat.is_worm_suspect if threat else False,
                }
            )
        edges = [
            {
                "src": e["src"],
                "dst": e["dst"],
                "count": e["count"],
                "worm": e["worm"],
                "ports": sorted(e["ports"])[:8],
            }
            for e in self._edges.values()
        ]
        return {"nodes": nodes, "edges": edges}

    def recent_alerts(self, limit: int = 200) -> list[dict]:
        with self._lock:
            alerts = list(self._recent_alerts)[-limit:]
        return [a.to_dict() for a in reversed(alerts)]

    def stats(self) -> dict:
        assessment = self.current_assessment()
        return {
            "devices": len(self.registry),
            "events_processed": self.event_count,
            "frames_processed": self.frame_count,
            "alerts": len(self._recent_alerts),
            "learning": self.learn and self.baseline.is_learning(),
            "learning_progress": self.baseline.progress(),
            "overall_level": assessment.overall_level.label,
            "likely_compromised": assessment.likely_compromised,
        }

    def mark_suspicious(self, identifier: str, value: bool = True) -> bool:
        with self._lock:
            ok = self.registry.mark_suspicious(identifier, value)
        if ok:
            device = self.registry.get(identifier) or self.registry.get_by_ip(identifier)
            if device:
                self.db.upsert_device(device)
                self.bus.publish({"type": "device_update", "device": device.to_dict()})
        return ok

    # ----------------------------------------------------------- run loops
    def start_live(self) -> None:
        from ..capture.sniffer import LiveSniffer

        self._sniffer = LiveSniffer(
            self.config.interface, self.process_frame, self.config.bpf_filter
        )
        self._sniffer.start()
        self.start_sweeper()

    def start_sweeper(self) -> None:
        if self._sweeper is not None:
            return
        self._stop.clear()
        self._sweeper = threading.Thread(
            target=self._sweep_loop, daemon=True, name="wyvern-sweeper"
        )
        self._sweeper.start()

    def _sweep_loop(self) -> None:
        while not self._stop.wait(self.config.sweep_interval_s):
            try:
                self.sweep()
            except Exception:  # noqa: BLE001
                log.warning("sweep failed", exc_info=True)

    def replay(self, pcap_path: str, *, realtime: bool = False, speed: float = 1.0) -> int:
        from ..capture.sniffer import replay_pcap

        count = replay_pcap(pcap_path, self.process_frame, realtime=realtime, speed=speed)
        self.sweep()
        return count

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None:
            self._sniffer.stop()
        if self._sweeper is not None:
            self._sweeper.join(timeout=2.0)
            self._sweeper = None
