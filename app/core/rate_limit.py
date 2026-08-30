"""
TRACKIT Rate Limiting.

Production-capable rate limiting with:

- Redis-backed shared storage
- In-memory development/test storage
- Atomic Redis Lua execution
- Configurable attempt/window values
- Retry-After calculation
- Fail-closed behaviour when Redis is unavailable
- Automatic Redis key expiration
- Thread-safe in-memory storage
- Safe test cleanup
- No Redis FLUSHDB usage

Security goals:

- Protect authentication endpoints from brute-force abuse.
- Apply limits consistently across multiple application instances.
- Avoid trusting unvalidated proxy headers.
- Prevent stale in-memory buckets from remaining forever.
- Fail closed when Redis is unavailable in production.
- Keep Redis operations atomic under concurrent requests.

Production configuration:

    RATE_LIMIT_BACKEND=redis
    REDIS_URL=redis://localhost:6379/0
    RATE_LIMIT_FAIL_CLOSED=true

Development/test configuration may use:

    RATE_LIMIT_BACKEND=memory
"""

from __future__ import annotations

from collections import defaultdict
from threading import Lock
from time import monotonic
from typing import Final

import redis
from redis.exceptions import RedisError

from app.core.config import settings


# ============================================================================
# CONSTANTS
# ============================================================================

REDIS_KEY_PREFIX: Final[str] = "trackit:rate-limit:"

# Redis Lua scripts use Redis TIME rather than the application clock.
#
# This keeps timestamps consistent when multiple TRACKIT workers are
# running on different processes or hosts.
REDIS_RATE_LIMIT_SCRIPT: Final[str] = """
local key = KEYS[1]

local max_attempts = tonumber(ARGV[1])
local window_seconds = tonumber(ARGV[2])
local member = ARGV[3]

local redis_time = redis.call("TIME")

local now_seconds = tonumber(redis_time[1])
local window_start = now_seconds - window_seconds

redis.call(
    "ZREMRANGEBYSCORE",
    key,
    "-inf",
    window_start
)

local current_count = redis.call(
    "ZCARD",
    key
)

if current_count >= max_attempts then

    local oldest = redis.call(
        "ZRANGE",
        key,
        0,
        0,
        "WITHSCORES"
    )

    if #oldest == 0 then
        return {1, 0}
    end

    local oldest_timestamp = tonumber(oldest[2])
    local retry_after = window_seconds - (now_seconds - oldest_timestamp)

    if retry_after < 1 then
        retry_after = 1
    end

    return {0, retry_after}
end

redis.call(
    "ZADD",
    key,
    now_seconds,
    member
)

redis.call(
    "EXPIRE",
    key,
    window_seconds + 1
)

return {1, 0}
"""


# ============================================================================
# INTERNAL MEMORY STORAGE
# ============================================================================

_memory_rate_limit_store: dict[str, list[float]] = defaultdict(list)

_memory_rate_limit_lock = Lock()


# ============================================================================
# REDIS CLIENT
# ============================================================================

_redis_client: redis.Redis | None = None

_redis_client_lock = Lock()


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

            Zero when the request is allowed.
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
# REDIS CLIENT
# ============================================================================


def _get_redis_client() -> redis.Redis:
    """
    Return the shared Redis client.

    The connection is created lazily.

    Redis connectivity is verified with PING before the client
    is returned.

    Raises:
        RedisError:
            When Redis cannot be reached.
    """

    global _redis_client

    if _redis_client is not None:
        return _redis_client

    with _redis_client_lock:

        if _redis_client is not None:
            return _redis_client

        client = redis.Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
            health_check_interval=30,
        )

        client.ping()

        _redis_client = client

        return _redis_client


def _reset_redis_client() -> None:
    """
    Close and remove the cached Redis client.

    This allows the next request to establish a fresh connection
    after a connection failure.
    """

    global _redis_client

    with _redis_client_lock:

        client = _redis_client

        _redis_client = None

        if client is not None:

            try:
                client.close()

            except Exception:
                pass


# ============================================================================
# MEMORY RATE LIMITING
# ============================================================================


def _cleanup_memory_store(
    now: float,
    window_seconds: int,
) -> None:
    """
    Remove expired in-memory buckets.

    This prevents stale buckets from accumulating indefinitely.
    """

    expired_keys: list[str] = []

    for key, timestamps in _memory_rate_limit_store.items():

        valid_timestamps = [
            timestamp
            for timestamp in timestamps
            if now - timestamp < window_seconds
        ]

        if valid_timestamps:

            _memory_rate_limit_store[key] = valid_timestamps

        else:

            expired_keys.append(key)

    for key in expired_keys:
        del _memory_rate_limit_store[key]


def _check_memory_rate_limit(
    *,
    key: str,
    max_attempts: int,
    window_seconds: int,
) -> RateLimitResult:
    """
    Check a rate limit using local in-memory storage.

    Used for development and tests.
    """

    now = monotonic()

    with _memory_rate_limit_lock:

        timestamps = _memory_rate_limit_store[key]

        timestamps[:] = [
            timestamp
            for timestamp in timestamps
            if now - timestamp < window_seconds
        ]

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

        timestamps.append(now)

        # Prevent uncontrolled growth if many unique keys are used
        # during development or testing.
        if len(_memory_rate_limit_store) > 1000:

            _cleanup_memory_store(
                now,
                window_seconds,
            )

        return RateLimitResult(
            allowed=True,
            retry_after=0,
        )


# ============================================================================
# REDIS RATE LIMITING
# ============================================================================


def _check_redis_rate_limit(
    *,
    key: str,
    max_attempts: int,
    window_seconds: int,
) -> RateLimitResult:
    """
    Check a rate limit using Redis.

    The entire operation is performed inside one Redis-side
    Lua script.

    This makes the following operations atomic:

        1. Remove expired requests.
        2. Count active requests.
        3. Check the limit.
        4. Add the new request.
        5. Set key expiration.

    This prevents concurrent TRACKIT workers from racing each
    other and exceeding the configured limit.
    """

    client = _get_redis_client()

    redis_key = f"{REDIS_KEY_PREFIX}{key}"

    # Unique member so two requests occurring during the same
    # Redis second cannot overwrite each other.
    member = f"{monotonic()}:{id(object())}"

    try:

        result = client.eval(
            REDIS_RATE_LIMIT_SCRIPT,
            1,
            redis_key,
            max_attempts,
            window_seconds,
            member,
        )

    except RedisError:

        # Throw away a potentially broken connection so the
        # next request gets a fresh client.
        _reset_redis_client()

        raise

    if not result or len(result) != 2:
        raise RedisError(
            "Invalid response received from Redis rate-limit script."
        )

    allowed = bool(int(result[0]))

    retry_after = int(result[1])

    return RateLimitResult(
        allowed=allowed,
        retry_after=retry_after,
    )


# ============================================================================
# PUBLIC RATE-LIMIT CHECK
# ============================================================================


def check_rate_limit(
    *,
    key: str,
    max_attempts: int,
    window_seconds: int,
) -> RateLimitResult:
    """
    Check whether a request is allowed.

    Backend selection is controlled by:

        settings.RATE_LIMIT_BACKEND

    Supported backends:

        memory
        redis

    Redis failure behaviour is controlled by:

        settings.RATE_LIMIT_FAIL_CLOSED

    When fail-closed is enabled:

        Redis unavailable
            ↓
        RedisError raised
            ↓
        protected endpoint rejects the request

    When fail-closed is disabled:

        Redis unavailable
            ↓
        request is allowed

    Raises:
        ValueError:
            Invalid rate-limit parameters or unsupported backend.

        RedisError:
            Redis is configured but unavailable while fail-closed
            mode is enabled.
    """

    # ------------------------------------------------------------------
    # Validate key
    # ------------------------------------------------------------------

    if not key or not key.strip():

        raise ValueError(
            "Rate-limit key cannot be empty."
        )

    # ------------------------------------------------------------------
    # Validate attempt limit
    # ------------------------------------------------------------------

    if max_attempts <= 0:

        raise ValueError(
            "max_attempts must be greater than zero."
        )

    # ------------------------------------------------------------------
    # Validate window
    # ------------------------------------------------------------------

    if window_seconds <= 0:

        raise ValueError(
            "window_seconds must be greater than zero."
        )

    # ------------------------------------------------------------------
    # Select backend
    # ------------------------------------------------------------------

    backend = settings.RATE_LIMIT_BACKEND.strip().lower()

    # ------------------------------------------------------------------
    # Memory backend
    # ------------------------------------------------------------------

    if backend == "memory":

        return _check_memory_rate_limit(
            key=key,
            max_attempts=max_attempts,
            window_seconds=window_seconds,
        )

    # ------------------------------------------------------------------
    # Redis backend
    # ------------------------------------------------------------------

    if backend == "redis":

        try:

            return _check_redis_rate_limit(
                key=key,
                max_attempts=max_attempts,
                window_seconds=window_seconds,
            )

        except RedisError:

            if settings.RATE_LIMIT_FAIL_CLOSED:

                raise

            # Explicit fail-open mode.
            #
            # This should generally NOT be used for authentication
            # endpoints in production.
            return RateLimitResult(
                allowed=True,
                retry_after=0,
            )

    # ------------------------------------------------------------------
    # Unsupported backend
    # ------------------------------------------------------------------

    raise ValueError(
        "Unsupported rate-limit backend. "
        "Expected 'memory' or 'redis'."
    )


# ============================================================================
# TEST / DEVELOPMENT CLEANUP
# ============================================================================


def clear_rate_limit_store() -> None:
    """
    Clear rate-limit state safely.

    Memory backend:
        Clears all in-memory buckets.

    Redis backend:
        Deletes only Redis keys belonging to TRACKIT rate limiting.

    This function deliberately does NOT use:

        FLUSHDB
        FLUSHALL

    because those commands could destroy unrelated application
    or development data stored in Redis.

    Intended primarily for automated tests and controlled
    development resets.
    """

    # ------------------------------------------------------------------
    # Always clear local memory.
    # ------------------------------------------------------------------

    with _memory_rate_limit_lock:
        _memory_rate_limit_store.clear()

    # ------------------------------------------------------------------
    # Only clear Redis when Redis is the configured backend.
    # ------------------------------------------------------------------

    backend = settings.RATE_LIMIT_BACKEND.strip().lower()

    if backend != "redis":
        return

    try:

        client = _get_redis_client()

        cursor = 0

        while True:

            cursor, keys = client.scan(
                cursor=cursor,
                match=f"{REDIS_KEY_PREFIX}*",
                count=100,
            )

            if keys:

                client.delete(*keys)

            if cursor == 0:
                break

    except RedisError:

        # Cleanup should not hide the original test failure or
        # application error.

        _reset_redis_client()


# ============================================================================
# REDIS HEALTH CHECK
# ============================================================================


def check_redis_health() -> bool:
    """
    Check whether the configured Redis backend is reachable.

    Returns:

        True:
            Redis is available.

        False:
            Redis is unavailable.

    This function does not modify rate-limit state.
    """

    try:

        client = _get_redis_client()

        return bool(client.ping())

    except RedisError:

        _reset_redis_client()

        return False


# ============================================================================
# REDIS CLIENT RESET
# ============================================================================


def reset_redis_rate_limit_client() -> None:
    """
    Reset the cached Redis connection.

    Primarily intended for automated tests.
    """

    _reset_redis_client()
