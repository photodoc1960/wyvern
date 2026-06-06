"""A tiny in-process publish/subscribe bus for real-time dashboard updates.

Each subscriber gets its own bounded queue; the dashboard's Server-Sent-Events
endpoint drains one. Publishing never blocks the capture thread: if a slow
subscriber's queue is full, its oldest item is dropped.
"""

from __future__ import annotations

import queue
import threading
from typing import Any


class EventBus:
    def __init__(self, maxsize: int = 1000, max_subscribers: int = 64) -> None:
        self._maxsize = maxsize
        self._max_subscribers = max_subscribers
        self._subscribers: set[queue.Queue] = set()
        self._lock = threading.Lock()

    def subscribe(self) -> "queue.Queue[Any]":
        """Register a subscriber queue. Raises ``RuntimeError`` past the cap so a
        flood of dashboard connections cannot exhaust threads/memory."""
        q: queue.Queue[Any] = queue.Queue(maxsize=self._maxsize)
        with self._lock:
            if len(self._subscribers) >= self._max_subscribers:
                raise RuntimeError("SSE subscriber limit reached")
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: "queue.Queue[Any]") -> None:
        with self._lock:
            self._subscribers.discard(q)

    def publish(self, message: Any) -> None:
        with self._lock:
            targets = list(self._subscribers)
        for q in targets:
            try:
                q.put_nowait(message)
            except queue.Full:
                try:
                    q.get_nowait()        # drop oldest, make room
                    q.put_nowait(message)
                except queue.Empty:
                    pass

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)
