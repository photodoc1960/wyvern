"""A sensor that cannot keep up must say so.

Capture is a Python callback behind an AF_PACKET socket. On a client-mode WiFi
interface that was free. On a mirrored 1 Gbps link it is ~83,000 packets/sec, well
past what scapy in Python sustains — and socket-buffer overflow drops are
*indiscriminate*, so the SYNs and DNS queries the detectors depend on are lost
alongside the bulk payload the drops were caused by.

Nothing read the kernel's drop counter, so that would have looked exactly like a
quiet network: the same failure the visibility report exists to prevent, one layer
further down.
"""

from __future__ import annotations

from wyvern.capture.stats import CaptureStats, accumulate, summarize

HIGH = 0.02  # the fraction of drops worth warning about


def test_starts_empty():
    s = CaptureStats()
    assert s.packets == 0 and s.drops == 0
    assert summarize(s)["drop_fraction"] == 0.0


def test_accumulates_successive_destructive_reads():
    """PACKET_STATISTICS resets on read, so each poll is a delta, not a total."""
    s = CaptureStats()
    s = accumulate(s, packets=1000, drops=0)
    s = accumulate(s, packets=1000, drops=50)
    assert s.packets == 2000
    assert s.drops == 50


def test_drop_fraction_is_over_offered_load_not_captured():
    """A drop is a packet the kernel had and we failed to take, so the denominator
    is packets + drops — reporting drops over captured would understate it."""
    s = accumulate(CaptureStats(), packets=900, drops=100)
    assert summarize(s)["drop_fraction"] == 0.10


def test_healthy_capture_is_not_flagged():
    s = accumulate(CaptureStats(), packets=100_000, drops=0)
    out = summarize(s, warn_above=HIGH)
    assert out["healthy"] is True
    assert out["warning"] is None


def test_lossy_capture_is_flagged_with_an_actionable_warning():
    """This is the whole point: the operator must be told, in the report, that the
    silence is not evidence."""
    s = accumulate(CaptureStats(), packets=800_000, drops=200_000)
    out = summarize(s, warn_above=HIGH)
    assert out["healthy"] is False
    assert out["warning"] and "20" in out["warning"]
    assert "not evidence" in out["warning"].lower()


def test_counters_never_go_backwards_on_a_bogus_read():
    """A failed getsockopt or an interface reset must not corrupt the totals."""
    s = accumulate(CaptureStats(), packets=5000, drops=10)
    s2 = accumulate(s, packets=-1, drops=-1)
    assert s2.packets == 5000 and s2.drops == 10


def test_unavailable_stats_are_reported_as_unknown_not_as_zero():
    """Claiming zero drops when we cannot read the counter would be the same lie in
    a different costume."""
    out = summarize(None)
    assert out["available"] is False
    assert out["drop_fraction"] is None
    assert out["healthy"] is None
