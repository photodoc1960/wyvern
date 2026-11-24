"""Tests for the shared per-key Cooldown (issue #17: bounded keyspace)."""

from __future__ import annotations

from wyvern.detectors.base import Cooldown


def test_fire_debounces_within_window():
    c = Cooldown(10.0)
    assert c.fire("k", 0.0)
    assert not c.fire("k", 5.0)
    assert c.fire("k", 10.0)


def test_prune_drops_only_expired_keys():
    c = Cooldown(10.0)
    c.stamp("old", 0.0)
    c.stamp("fresh", 8.0)
    c.prune(12.0)
    assert len(c) == 1
    assert not c.ready("fresh", 12.0)  # still debouncing
    assert c.ready("old", 12.0)  # pruned == expired: same behaviour


def test_table_stays_bounded_over_many_distinct_keys():
    # A long-running sensor seeing a new flow every second must not grow forever.
    c = Cooldown(60.0)
    for i in range(50_000):
        c.fire(("flow", i), float(i))
    assert len(c) < 2_100  # ~60 live keys, plus at most one prune interval's growth
