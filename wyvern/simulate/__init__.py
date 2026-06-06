"""Synthetic Toronto-worm traffic generation for demos and tests.

This produces *fabricated network events* describing what the worm's propagation
would look like on a small home network. It performs no real attack and touches
no real host — it only manufactures :class:`NetworkEvent` objects (and,
optionally, a pcap) so detectors and the dashboard can be exercised safely.
"""

from __future__ import annotations

from .worm_trace import FAKE_HOME, worm_scenario, write_pcap

__all__ = ["worm_scenario", "write_pcap", "FAKE_HOME"]
