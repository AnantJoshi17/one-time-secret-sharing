"""
Per-IP rate limiting for secret creation.

The algorithm is a sliding window, and it is deliberately the simplest thing
that works: for each IP we keep the timestamps of its recent requests, throw
away the ones older than the window, and reject the request if what is left
is already at the limit.

    window = 60s, limit = 10
    requests at t=0..9  -> all allowed, 10 timestamps stored
    request  at t=10    -> rejected, the 10 stored are all within 60s
    request  at t=61    -> allowed, the t=0 timestamp has aged out

WHY IN-MEMORY, AND WHAT IT COSTS

The brief rules out Redis, so state lives in a module-level dict. Be honest
about the two consequences, because an interviewer will ask:

  1. It is PER PROCESS. Run uvicorn with 4 workers and you get 4 independent
     counters, so the real limit is 4x what you configured. On Render's free
     tier there is a single worker, so the configured number is the real one.
  2. It is LOST ON RESTART. A deploy resets every counter.

For this service that is an acceptable trade. The limiter exists to stop one
IP from filling the table with junk, not to enforce a billing quota. The
moment you need it to be exact across processes, the fix is Redis with an
atomic INCR + EXPIRE -- not a smarter dict.

WHAT IT DOES NOT PROTECT AGAINST

Rate limiting by IP punishes everyone behind one office NAT together, and is
trivially sidestepped by anyone with a pool of addresses. It raises the cost
of abuse; it does not prevent it.
"""

import threading
import time
from collections import defaultdict, deque

from fastapi import Depends, HTTPException, Request, status

from app.config import settings
from app.dependencies import get_client_ip

# ip -> timestamps (seconds, monotonic) of that IP's recent requests.
#
# A deque is the right structure: old entries leave from the left, new ones
# arrive on the right, and both are O(1).
_hits: dict[str, deque[float]] = defaultdict(deque)

# uvicorn runs endpoints in a thread pool, so two requests really can touch
# this dict at the same instant. The lock makes check-then-append atomic;
# without it two simultaneous requests could both see "9 hits, room for one
# more" and both be allowed.
_lock = threading.Lock()


def _prune(timestamps: deque[float], now: float, window_seconds: int) -> None:
    """Drop the timestamps that have fallen out of the back of the window."""
    cutoff = now - window_seconds
    while timestamps and timestamps[0] <= cutoff:
        timestamps.popleft()


def check_rate_limit(
    client_ip: str,
    max_requests: int | None = None,
    window_seconds: int | None = None,
) -> tuple[bool, int]:
    """
    Record a request from `client_ip` and say whether it is allowed.

    Returns (allowed, retry_after_seconds). retry_after is 0 when allowed.
    This is a plain function with no FastAPI types in it so it can be unit
    tested directly, without spinning up a request.
    """
    if max_requests is None:
        max_requests = settings.rate_limit_max_requests
    if window_seconds is None:
        window_seconds = settings.rate_limit_window_seconds

    # time.monotonic(), not time.time(): it cannot jump backwards when the
    # machine syncs its clock, which would otherwise let requests through.
    now = time.monotonic()

    with _lock:
        timestamps = _hits[client_ip]
        _prune(timestamps, now, window_seconds)

        if len(timestamps) >= max_requests:
            # Tell the caller when the oldest hit will age out of the window.
            oldest = timestamps[0]
            retry_after = int(window_seconds - (now - oldest)) + 1
            return False, max(retry_after, 1)

        timestamps.append(now)
        return True, 0


def reset_rate_limits() -> None:
    """Forget every counter. Used by tests so they do not affect each other."""
    with _lock:
        _hits.clear()


def rate_limit_secret_creation(
    request: Request,
    client_ip: str = Depends(get_client_ip),
) -> None:
    """
    FastAPI dependency. Attach it to an endpoint to rate limit that endpoint.

    It returns nothing -- it is used purely for the side effect of raising 429
    when the caller has been too eager. `Retry-After` is a standard header
    that tells a well-behaved client how long to wait before trying again.
    """
    allowed, retry_after = check_rate_limit(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded: at most {settings.rate_limit_max_requests} "
                f"secrets per {settings.rate_limit_window_seconds} seconds per IP. "
                f"Try again in {retry_after} seconds."
            ),
            headers={"Retry-After": str(retry_after)},
        )
