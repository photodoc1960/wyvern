"""Capture-level packet accounting: what the kernel offered, and what we missed.

Capture runs as a Python callback behind an AF_PACKET socket. On a client-mode
interface that is free, but on a mirrored link carrying a household's whole
internet traffic it is tens of thousands of packets a second — past what scapy in
Python sustains. Socket-buffer overflow drops are **indiscriminate**: the SYNs and
DNS queries the detectors depend on are lost alongside the bulk payload whose
volume caused the overflow.

Unread, that is indistinguishable from a quiet network — the same failure the
visibility report exists to prevent, one layer further down. So the drop counter is
read, accumulated, and reported, and an unreadable counter is reported as *unknown*
rather than as zero.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace

log = logging.getLogger("wyvern.capture.stats")

# Linux: getsockopt(SOL_PACKET, PACKET_STATISTICS) returns struct tpacket_stats
# {unsigned tp_packets; unsigned tp_drops;} and RESETS the counters, so every read
# is a delta that has to be accumulated.
SOL_PACKET = 263
PACKET_STATISTICS = 6
_STATS_LEN = 8

DEFAULT_WARN_ABOVE = 0.02


@dataclass(frozen=True)
class CaptureStats:
    """Cumulative totals across all polls (immutable; `accumulate` returns a copy)."""

    packets: int = 0
    drops: int = 0
    polls: int = 0


def accumulate(stats: CaptureStats, *, packets: int, drops: int) -> CaptureStats:
    """Fold one delta into the totals, ignoring an implausible read.

    A failed `getsockopt` or an interface reset must never make the totals go
    backwards, because a shrinking denominator would quietly flatter the drop rate.
    """
    if packets < 0 or drops < 0:
        return stats
    return replace(
        stats,
        packets=stats.packets + packets,
        drops=stats.drops + drops,
        polls=stats.polls + 1,
    )


def poll_socket(sock) -> tuple[int, int] | None:
    """Read and reset one AF_PACKET socket's statistics, or None if unavailable."""
    try:
        import struct

        raw = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, _STATS_LEN)
        packets, drops = struct.unpack("II", raw)
        return int(packets), int(drops)
    except Exception:  # noqa: BLE001 - absence of the counter is not an error
        log.debug("capture statistics unavailable on this socket", exc_info=True)
        return None


def summarize(stats: CaptureStats | None, *, warn_above: float = DEFAULT_WARN_ABOVE) -> dict:
    """Render the totals for the visibility report.

    `drop_fraction` is over *offered* load (packets + drops): a drop is a packet the
    kernel held and we failed to take, so dividing by captured alone would
    understate it.
    """
    if stats is None:
        return {
            "available": False,
            "packets": None,
            "drops": None,
            "drop_fraction": None,
            "healthy": None,
            "warning": "Capture drop counters are unavailable, so packet loss "
            "cannot be ruled out on this deployment.",
        }
    offered = stats.packets + stats.drops
    fraction = (stats.drops / offered) if offered else 0.0
    healthy = fraction <= warn_above
    warning = None
    if not healthy:
        warning = (
            f"Dropping {fraction * 100:.1f}% of offered packets — capture cannot keep "
            f"up with this link. Drops are indiscriminate, so detector silence is "
            f"NOT evidence of a quiet network. Reduce load with a bpf_filter, or use "
            f"a faster capture host."
        )
    return {
        "available": True,
        "packets": stats.packets,
        "drops": stats.drops,
        "drop_fraction": round(fraction, 4),
        "healthy": healthy,
        "warning": warning,
    }
