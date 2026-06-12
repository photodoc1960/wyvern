"""Sliding-window counters used by stateful detectors.

Detectors keep per-device counters (distinct ports in 5 min, distinct internal
peers in 1 h, etc.). These structures are intentionally mutable accumulators —
the *domain* objects (events, alerts, devices) remain immutable; only these
internal bookkeeping aids change in place, which is the standard, efficient
pattern for streaming counters.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Hashable, Iterable
from typing import Any


class SlidingWindow:
    """A time-ordered window of ``(timestamp, item)`` pairs.

    Eviction is lazy: old entries are dropped whenever the window is queried
    with the current time, so memory stays bounded by the busiest window.
    """

    __slots__ = ("window", "_items")

    def __init__(self, window_seconds: float) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window = float(window_seconds)
        self._items: deque[tuple[float, Any]] = deque()

    def add(self, ts: float, item: Any = None) -> None:
        # Tolerate mildly out-of-order arrivals by appending; queries evict by age.
        self._items.append((ts, item))

    def _evict(self, now: float) -> None:
        horizon = now - self.window
        items = self._items
        while items and items[0][0] < horizon:
            items.popleft()

    def count(self, now: float) -> int:
        self._evict(now)
        return len(self._items)

    def items(self, now: float) -> list[Any]:
        self._evict(now)
        return [item for _, item in self._items]

    def timestamps(self, now: float) -> list[float]:
        self._evict(now)
        return [ts for ts, _ in self._items]

    def distinct(self, now: float) -> set[Any]:
        self._evict(now)
        return {item for _, item in self._items}

    def distinct_count(self, now: float) -> int:
        return len(self.distinct(now))

    def is_empty(self, now: float) -> bool:
        self._evict(now)
        return not self._items

    def __len__(self) -> int:  # length without eviction (raw size)
        return len(self._items)


class KeyedWindows:
    """A lazily-created family of :class:`SlidingWindow` keyed by some hashable.

    Example: one window of contacted ports per source IP.
    """

    __slots__ = ("window", "_by_key", "_max_keys")

    def __init__(self, window_seconds: float, max_keys: int = 100_000) -> None:
        self.window = float(window_seconds)
        self._by_key: dict[Hashable, SlidingWindow] = {}
        self._max_keys = max_keys

    def get(self, key: Hashable) -> SlidingWindow:
        win = self._by_key.get(key)
        if win is None:
            if len(self._by_key) >= self._max_keys:
                # Drop an arbitrary key to bound memory; counters self-heal.
                self._by_key.pop(next(iter(self._by_key)))
            win = SlidingWindow(self.window)
            self._by_key[key] = win
        return win

    def add(self, key: Hashable, ts: float, item: Any = None) -> SlidingWindow:
        win = self.get(key)
        win.add(ts, item)
        return win

    def keys(self) -> Iterable[Hashable]:
        return tuple(self._by_key.keys())

    def prune(self, now: float) -> None:
        """Forget keys whose windows have gone empty, freeing memory."""
        dead = [k for k, w in self._by_key.items() if w.is_empty(now)]
        for k in dead:
            self._by_key.pop(k, None)


def coefficient_of_variation(values: list[float]) -> float | None:
    """Return stddev/mean of ``values`` (a regularity score), or ``None``.

    Used by the beacon detector: near-constant inter-arrival gaps (low CoV)
    indicate automated, periodic callbacks rather than human traffic.
    """
    n = len(values)
    if n < 2:
        return None
    mean = sum(values) / n
    if mean == 0:
        return None
    var = sum((v - mean) ** 2 for v in values) / n
    return (var**0.5) / mean


def intervals(timestamps: list[float]) -> list[float]:
    """Inter-arrival gaps between sorted timestamps."""
    ordered = sorted(timestamps)
    return [b - a for a, b in zip(ordered, ordered[1:], strict=False)]
