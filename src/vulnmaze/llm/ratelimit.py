"""Defender-cost controls: per-attacker token bucket and a global concurrency cap.

A scripted attacker can send thousands of unique commands a minute; without
limits each one costs a model call. Over the limit, the gateway answers with
the deterministic fallback instead of queueing.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict


class TokenBuckets:
    def __init__(self, per_minute: float, burst: int, max_keys: int = 50_000):
        self.rate = per_minute / 60.0
        self.burst = burst
        self.max_keys = max_keys
        self._state: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        tokens, last = self._state.pop(key, (float(self.burst), now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        ok = tokens >= 1.0
        self._state[key] = (tokens - 1.0 if ok else tokens, now)
        if len(self._state) > self.max_keys:
            self._state.popitem(last=False)
        return ok


class Concurrency:
    def __init__(self, limit: int):
        self._sem = asyncio.Semaphore(limit)

    async def acquire(self, wait_s: float) -> bool:
        try:
            await asyncio.wait_for(self._sem.acquire(), timeout=wait_s)
            return True
        except TimeoutError:
            return False

    def release(self) -> None:
        self._sem.release()
