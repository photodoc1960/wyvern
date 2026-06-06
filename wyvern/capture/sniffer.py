"""Live capture (scapy) and offline replay (dpkt) packet sources.

Both sources are *read-only*: they observe frames and hand raw bytes plus a
timestamp to a callback. They never transmit. scapy is imported lazily so the
rest of Wyvern (and its tests) import cleanly without it, and so that the
import-time privilege/interface checks only happen when capture is requested.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional

FrameCallback = Callable[[bytes, float], None]

log = logging.getLogger("wyvern.capture")


class LiveSniffer:
    """Wraps scapy's :class:`AsyncSniffer` (passive, ``store=False``)."""

    def __init__(
        self,
        interface: Optional[str],
        callback: FrameCallback,
        bpf_filter: Optional[str] = None,
    ) -> None:
        self.interface = interface
        self.callback = callback
        self.bpf_filter = bpf_filter
        self._sniffer = None

    def start(self) -> None:
        try:
            from scapy.all import AsyncSniffer  # lazy import
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "scapy is required for live capture (pip install scapy)"
            ) from exc

        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter,
            store=False,
            prn=self._on_packet,
        )
        self._sniffer.start()
        log.info(
            "live capture started on %s (filter=%r)",
            self.interface or "default",
            self.bpf_filter,
        )

    def _on_packet(self, pkt) -> None:
        try:
            ts = float(getattr(pkt, "time", None) or time.time())
            self.callback(bytes(pkt), ts)
        except Exception:  # noqa: BLE001 - one bad packet must not kill capture
            log.debug("failed to handle a captured packet", exc_info=True)

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:  # noqa: BLE001
                log.debug("error stopping sniffer", exc_info=True)
            self._sniffer = None
            log.info("live capture stopped")


def replay_pcap(
    path: str,
    callback: FrameCallback,
    *,
    realtime: bool = False,
    speed: float = 1.0,
    limit: Optional[int] = None,
) -> int:
    """Replay a pcap/pcapng file through ``callback``. Returns frame count.

    ``realtime`` paces playback to the captured inter-frame timing (divided by
    ``speed``); otherwise frames are delivered as fast as possible. Uses dpkt's
    reader so replay needs no scapy and no privileges.
    """
    import dpkt  # local import keeps module import light

    count = 0
    last_ts: float | None = None
    try:
        with open(path, "rb") as fh:
            try:
                reader = dpkt.pcapng.Reader(fh)
            except (ValueError, dpkt.dpkt.UnpackError):
                fh.seek(0)
                reader = dpkt.pcap.Reader(fh)
            for ts, buf in reader:
                if realtime and last_ts is not None:
                    delay = (ts - last_ts) / max(speed, 1e-6)
                    if delay > 0:
                        time.sleep(min(delay, 5.0))
                last_ts = ts
                callback(bytes(buf), float(ts))
                count += 1
                if limit is not None and count >= limit:
                    break
    except OSError as exc:
        raise RuntimeError(f"cannot read pcap {path!r}: {exc}") from exc
    log.info("replayed %d frames from %s", count, path)
    return count
