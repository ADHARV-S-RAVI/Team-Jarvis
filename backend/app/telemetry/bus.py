"""Bounded thread-safe telemetry event bus for SSE streaming."""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timezone
import itertools
import threading
from typing import Any


class TelemetryBus:
    """In-process bounded pub/sub bus for real-time SSE telemetry."""

    def __init__(self, maxlen: int = 200) -> None:
        self._lock = threading.Lock()
        self._history: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._subscribers: set[tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]] = set()
        self._seq = itertools.count(1)

    def publish(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        evt = {
            "id": next(self._seq),
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        with self._lock:
            self._history.append(evt)
            subs = list(self._subscribers)
        for loop, q in subs:
            try:
                loop.call_soon_threadsafe(q.put_nowait, evt)
            except Exception:
                pass
        return evt

    def recent(self, limit: int = 25) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._history)[-limit:]

    def subscribe(self, loop: asyncio.AbstractEventLoop) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        with self._lock:
            self._subscribers.add((loop, q))
        return q

    def unsubscribe(self, loop: asyncio.AbstractEventLoop, q: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            self._subscribers.discard((loop, q))


telemetry_bus = TelemetryBus()
