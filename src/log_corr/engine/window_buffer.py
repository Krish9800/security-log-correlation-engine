"""Thread-safe sliding time-window buffer for stateful event correlation."""

from collections import deque
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any

from log_corr.models.schemas import NormalizedLogEvent


class SlidingWindowBuffer:
    """In-memory, bounded sliding window buffer organized by entity correlation key."""

    def __init__(self, max_events_per_key: int = 5000) -> None:
        self._max_events_per_key = max_events_per_key
        # Key -> deque of (timestamp, NormalizedLogEvent)
        self._buffers: dict[str, deque[tuple[datetime, NormalizedLogEvent]]] = {}
        self._lock = RLock()

    def add_event(
        self,
        key: str,
        event: NormalizedLogEvent,
        max_retention_seconds: int = 3600,
    ) -> None:
        """Add event to the window buffer under the given entity key and evict stale events."""
        with self._lock:
            if key not in self._buffers:
                self._buffers[key] = deque()

            queue = self._buffers[key]
            queue.append((event.timestamp, event))

            # Evict events older than max_retention_seconds relative to newest event
            newest_ts = queue[-1][0]
            cutoff = newest_ts - timedelta(seconds=max_retention_seconds)

            while queue and queue[0][0] < cutoff:
                queue.popleft()

            # Bound buffer size per key
            while len(queue) > self._max_events_per_key:
                queue.popleft()

    def get_window_events(
        self,
        key: str,
        window_seconds: int,
        reference_time: datetime | None = None,
    ) -> list[NormalizedLogEvent]:
        """Retrieve all events within window_seconds prior to reference_time (or newest event)."""
        with self._lock:
            if key not in self._buffers:
                return []

            queue = self._buffers[key]
            if not queue:
                return []

            ref = reference_time or queue[-1][0]
            cutoff = ref - timedelta(seconds=window_seconds)

            # Return events within [cutoff, ref] in chronological order
            events = [ev for ts, ev in queue if cutoff <= ts <= ref]
            events.sort(key=lambda e: e.timestamp)
            return events

    def purge_expired(
        self, max_idle_seconds: int = 3600, reference_time: datetime | None = None
    ) -> int:
        """Purge buffers that are empty or have not received events within max_idle_seconds."""
        now = reference_time or datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=max_idle_seconds)
        keys_to_delete: list[str] = []

        with self._lock:
            for key, queue in self._buffers.items():
                if not queue or queue[-1][0] < cutoff:
                    keys_to_delete.append(key)

            for key in keys_to_delete:
                del self._buffers[key]

        return len(keys_to_delete)

    def clear(self) -> None:
        """Clear all buffered events across all keys."""
        with self._lock:
            self._buffers.clear()

    def get_active_entity_keys(self) -> list[str]:
        """Return list of all keys currently tracked."""
        with self._lock:
            return list(self._buffers.keys())

    def get_stats(self) -> dict[str, Any]:
        """Return operational statistics for monitoring."""
        with self._lock:
            total_events = sum(len(q) for q in self._buffers.values())
            return {
                "active_keys": len(self._buffers),
                "total_buffered_events": total_events,
                "max_events_per_key": self._max_events_per_key,
            }
