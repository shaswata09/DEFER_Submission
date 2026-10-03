"""Per-process throttling for cloud-LLM endpoints with strict RPM caps.

NVIDIA's NIM serverless tier (https://integrate.api.nvidia.com/v1) caps
nemotron-3-nano-omni-30b-a3b-reasoning at 40 requests/minute.  Bursts
beyond that return HTTP 404 (the function gets cold-evicted) rather
than a clean 429.  The token bucket here keeps callers under the cap
without coordination across processes -- if you want multi-process
coordination, gate the parallel runs externally.

Heuristic: if a request's URL contains "nvidia.com", subject it to a
40 RPM cap.  Other URLs (vLLM at localhost, Anthropic, OpenAI) get
no throttling.

Usage::

    from utils.rate_limiter import throttle_for_url, athrottle_for_url
    throttle_for_url("https://integrate.api.nvidia.com/v1")  # sync
    await athrottle_for_url("https://integrate.api.nvidia.com/v1")  # async
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import deque

# (url_substring, rpm_cap) pairs.  First match wins.
_RPM_RULES: list[tuple[str, int]] = [
    ("nvidia.com", 40),
]

_sync_lock = threading.Lock()
_async_lock = asyncio.Lock()
# Sliding window of recent call timestamps per URL prefix.
_history: dict[str, deque] = {}


def _rpm_for(url: str) -> int | None:
    for sub, rpm in _RPM_RULES:
        if sub in url:
            return rpm
    return None


def _wait_seconds(url: str, rpm: int) -> float:
    """Compute how long to sleep so the next call stays within the cap.

    Mutates the history deque as a side effect.
    """
    now = time.monotonic()
    window = 60.0
    bucket = _history.setdefault(url, deque())
    # Drop entries older than the window
    while bucket and bucket[0] <= now - window:
        bucket.popleft()
    if len(bucket) < rpm:
        bucket.append(now)
        return 0.0
    # Need to wait until the oldest call rolls out of the window
    sleep_for = bucket[0] + window - now
    # Schedule our call at that time
    bucket.append(now + sleep_for)
    bucket.popleft()
    return max(0.0, sleep_for)


def throttle_for_url(url: str) -> None:
    """Sync wrapper -- blocks the caller until safe to issue a request."""
    rpm = _rpm_for(url)
    if rpm is None:
        return
    with _sync_lock:
        wait = _wait_seconds(url, rpm)
    if wait > 0:
        time.sleep(wait)


async def athrottle_for_url(url: str) -> None:
    """Async wrapper -- awaits until safe to issue a request."""
    rpm = _rpm_for(url)
    if rpm is None:
        return
    async with _async_lock:
        wait = _wait_seconds(url, rpm)
    if wait > 0:
        await asyncio.sleep(wait)


# --------------------------------------------------------------------- #
# Retry-on-rate-limit wrappers
# --------------------------------------------------------------------- #
# Even with proactive throttling, NIM occasionally returns 404
# "Function not found" when its serverless instance cold-evicts mid-window,
# or 429 if our client clock drifts.  Both clear up within ~1.5s.

_RETRY_SUBSTRS = ("429", "404", "rate limit", "rate_limit", "Function", "not found")


def _is_rate_limit_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(s.lower() in msg for s in _RETRY_SUBSTRS)


def call_with_retry(fn, *, max_retries: int = 3, delay_seconds: float = 1.5):
    """Synchronous retry wrapper for cloud-LLM calls.

    Calls ``fn()`` and returns its result.  On a rate-limit-shaped
    exception (404 / 429 / 'rate limit'), sleeps ``delay_seconds`` and
    retries up to ``max_retries`` times.  Other exceptions propagate
    immediately.
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries - 1 and _is_rate_limit_error(exc):
                time.sleep(delay_seconds)
                continue
            raise
    assert last_exc is not None
    raise last_exc


async def acall_with_retry(coro_fn, *, max_retries: int = 3,
                            delay_seconds: float = 1.5):
    """Async variant of :func:`call_with_retry`.  ``coro_fn`` is called
    fresh on each attempt (so it must return a new coroutine each time).
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            return await coro_fn()
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries - 1 and _is_rate_limit_error(exc):
                await asyncio.sleep(delay_seconds)
                continue
            raise
    assert last_exc is not None
    raise last_exc
