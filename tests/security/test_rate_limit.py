"""
TRACKIT Rate-Limit Security Tests.
"""

import time

import pytest

from app.core.rate_limit import (
    check_rate_limit,
    clear_rate_limit_store,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """
    Ensure every test starts with a clean rate-limit store.
    """

    clear_rate_limit_store()

    yield

    clear_rate_limit_store()


# ============================================================================
# Basic Behaviour
# ============================================================================


def test_requests_are_allowed_until_limit():
    """
    Requests should be allowed until max_attempts is reached.
    """

    for _ in range(5):
        result = check_rate_limit(
            key="login:127.0.0.1",
            max_attempts=5,
            window_seconds=300,
        )

        assert result.allowed is True
        assert result.retry_after == 0


def test_request_after_limit_is_blocked():
    """
    Requests beyond the configured limit should be rejected.
    """

    for _ in range(5):
        check_rate_limit(
            key="login:127.0.0.1",
            max_attempts=5,
            window_seconds=300,
        )

    result = check_rate_limit(
        key="login:127.0.0.1",
        max_attempts=5,
        window_seconds=300,
    )

    assert result.allowed is False
    assert result.retry_after > 0


def test_different_keys_have_independent_limits():
    """
    Different clients/buckets should not share counters.
    """

    for _ in range(5):
        result = check_rate_limit(
            key="login:127.0.0.1",
            max_attempts=5,
            window_seconds=300,
        )

        assert result.allowed is True

    blocked = check_rate_limit(
        key="login:127.0.0.1",
        max_attempts=5,
        window_seconds=300,
    )

    allowed = check_rate_limit(
        key="login:127.0.0.2",
        max_attempts=5,
        window_seconds=300,
    )

    assert blocked.allowed is False
    assert allowed.allowed is True


# ============================================================================
# Expiration
# ============================================================================


def test_rate_limit_expires_after_window():
    """
    Requests should become available again after the window expires.
    """

    for _ in range(2):
        result = check_rate_limit(
            key="login:test",
            max_attempts=2,
            window_seconds=1,
        )

        assert result.allowed is True

    blocked = check_rate_limit(
        key="login:test",
        max_attempts=2,
        window_seconds=1,
    )

    assert blocked.allowed is False

    time.sleep(1.1)

    allowed = check_rate_limit(
        key="login:test",
        max_attempts=2,
        window_seconds=1,
    )

    assert allowed.allowed is True


# ============================================================================
# Validation
# ============================================================================


def test_empty_key_is_rejected():
    with pytest.raises(ValueError):
        check_rate_limit(
            key="",
            max_attempts=5,
            window_seconds=300,
        )


def test_invalid_attempt_limit_is_rejected():
    with pytest.raises(ValueError):
        check_rate_limit(
            key="test",
            max_attempts=0,
            window_seconds=300,
        )


def test_invalid_window_is_rejected():
    with pytest.raises(ValueError):
        check_rate_limit(
            key="test",
            max_attempts=5,
            window_seconds=0,
        )


# ============================================================================
# Store Reset
# ============================================================================


def test_clear_rate_limit_store():
    """
    Clearing the store should restore request availability.
    """

    for _ in range(2):
        check_rate_limit(
            key="login:test",
            max_attempts=2,
            window_seconds=300,
        )

    blocked = check_rate_limit(
        key="login:test",
        max_attempts=2,
        window_seconds=300,
    )

    assert blocked.allowed is False

    clear_rate_limit_store()

    allowed = check_rate_limit(
        key="login:test",
        max_attempts=2,
        window_seconds=300,
    )

    assert allowed.allowed is True