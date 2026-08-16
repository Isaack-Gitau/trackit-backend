"""
TRACKIT Rate Limiting.

Provides lightweight in-memory rate limiting for development
and single-instance deployments.

Security goals:
- Protect authentication endpoints from brute-force abuse.
- Limit requests by client IP.
- Use configurable attempt/window values.
- Return HTTP 429 when a limit is exceeded.
- Provide Retry-After information to clients.
- Keep rate-limiting logic separate from routers and services.

Production note:
This implementation is intentionally in-memory.

When TRACKIT is deployed across multiple application instances,
replace the storage backend with Redis or another shared store.
"""

from __future__ import annotations

from collections import defaultdict
from threading import Lock
from time import monotonic


# ============================================================================
# INTERNAL STORAGE
# ============================================================================

_rate_limit_store: dict[str, list[float]] = defaultdict(list)

_rate_limit_lock = Lock()


# ============================================================================
# RESULT
# ============================================================================


class RateLimitResult:
    """
    Result returned by a rate-limit check.

    Attributes:
        allowed:
            True when the request is allowed.

        retry_after:
            Number of seconds the client should wait before retrying.

            This is zero when the request is allowed.
    """

    def __init__(
        self,
        *,
        allowed: bool,
        retry_after: int = 0,
    ) -> None:
        self.allowed = allowed
        self.retry_after = retry_after


# ============================================================================
# INTERNAL CLEANUP
# ============================================================================


def _cleanup_expired(
    now: float,
    window_seconds: int,
) -> None:
    """
    Remove expired rate-limit buckets.

    This prevents expired entries from remaining in memory forever.
    """

    expired_keys: list[str] = []

    for key, timestamps in _rate_limit_store.items():
        valid_timestamps = [
            timestamp
            for timestamp in timestamps
            if now - timestamp < window_seconds
        ]

        if valid_timestamps:
            _rate_limit_store[key] = valid_timestamps
        else:
            expired_keys.append(key)

    for key in expired_keys:
        del _rate_limit_store[key]


# ============================================================================
# RATE-LIMIT CHECK
# ============================================================================


def check_rate_limit(
    *,
    key: str,
    max_attempts: int,
    window_seconds: int,
) -> RateLimitResult:
    """
    Check whether a request is allowed.

    Args:
        key:
            Unique identifier for the rate-limit bucket.

            Examples:

                login:127.0.0.1
                register:127.0.0.1
                reset:127.0.0.1
                verification:127.0.0.1

        max_attempts:
            Maximum number of requests permitted within the window.

        window_seconds:
            Length of the rate-limit window in seconds.

    Returns:
        RateLimitResult.

    Raises:
        ValueError:
            If key, max_attempts, or window_seconds are invalid.
    """

    # ------------------------------------------------------------------
    # Validate configuration
    # ------------------------------------------------------------------

    if not key or not key.strip():
        raise ValueError(
            "Rate-limit key cannot be empty."
        )

    if max_attempts <= 0:
        raise ValueError(
            "max_attempts must be greater than zero."
        )

    if window_seconds <= 0:
        raise ValueError(
            "window_seconds must be greater than zero."
        )

    # ------------------------------------------------------------------
    # Current monotonic timestamp
    # ------------------------------------------------------------------

    now = monotonic()

    # ------------------------------------------------------------------
    # Thread-safe access
    # ------------------------------------------------------------------

    with _rate_limit_lock:

        # --------------------------------------------------------------
        # Get this bucket
        # --------------------------------------------------------------

        timestamps = _rate_limit_store[key]

        # --------------------------------------------------------------
        # Remove timestamps outside the current window
        # --------------------------------------------------------------

        timestamps[:] = [
            timestamp
            for timestamp in timestamps
            if now - timestamp < window_seconds
        ]

        # --------------------------------------------------------------
        # Limit exceeded
        # --------------------------------------------------------------

        if len(timestamps) >= max_attempts:
            oldest_timestamp = min(timestamps)

            elapsed = now - oldest_timestamp

            retry_after = max(
                1,
                int(window_seconds - elapsed),
            )

            return RateLimitResult(
                allowed=False,
                retry_after=retry_after,
            )

        # --------------------------------------------------------------
        # Record the request
        # --------------------------------------------------------------

        timestamps.append(now)

        return RateLimitResult(
            allowed=True,
            retry_after=0,
        )


# ============================================================================
# STORE RESET
# ============================================================================


def clear_rate_limit_store() -> None:
    """
    Clear all rate-limit buckets.

    Primarily used by:

    - automated tests
    - development
    - controlled application resets
    """

    with _rate_limit_lock:
        _rate_limit_store.clear()