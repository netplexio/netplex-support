"""Shared in-memory sliding-window rate limiter (per-process; real deploy → Redis).

Extracted 2026-07-27 from app/routers/diagnostics.py (which had its own private
copy) so app/routers/licensing.py can use the SAME primitive instead of a second,
independently-drifting implementation - this module is the single source of truth
for "is this key over budget" across every intake surface in this service.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

_RATE_WINDOW = 60.0
_hits: dict[str, deque] = defaultdict(deque)


def rate_ok(key: str, limit: int) -> bool:
    """True if *key* has made fewer than *limit* calls in the trailing 60s window
    (and records this call if so)."""
    now = time.monotonic()
    q = _hits[key]
    while q and now - q[0] > _RATE_WINDOW:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    return True
