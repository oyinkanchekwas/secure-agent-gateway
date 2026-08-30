from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock


@dataclass(frozen=True)
class RateLimit:
    calls: int
    period_seconds: int

    def __post_init__(self) -> None:
        if self.calls < 1 or self.period_seconds < 1:
            raise ValueError("rate limits must be positive")


class SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._events: dict[tuple[str, str], deque[int]] = defaultdict(deque)
        self._lock = Lock()

    def consume(self, principal_id: str, tool: str, limit: RateLimit, *, now: int) -> bool:
        key = (principal_id, tool)
        boundary = now - limit.period_seconds
        with self._lock:
            events = self._events[key]
            while events and events[0] <= boundary:
                events.popleft()
            if len(events) >= limit.calls:
                return False
            events.append(now)
            return True
