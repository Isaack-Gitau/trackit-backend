"""
TRACKIT Email Service Unit Tests.

Tests transactional email generation and delivery behavior.

Coverage:
- account reactivation email
- reactivation timestamp formatting
- optional suspension reason
- HTML escaping
- recipient validation
- SMTP delivery delegation
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from app.services.email import (
    send_account_reactivation_email,
)


# ============================================================================
# TEST CONSTANTS
# ============================================================================

TEST_RECIPIENT = "user@trackit.test"

TEST_REACTIVATED_AT = datetime(
    2026,
    9,
    10,
    12,
    30,
    0,
    tzinfo=timezone.utc,
)

TEST_REASON = "Repeatedly submitting misleading claims."


# ============================================================================
# ACCOUNT REACTIVATION EMAIL
# ============================================================================


def test_send_account_reactivation_email_successfully_sends_email():
    """
    A valid reactivation notification should be passed to the
    existing email delivery function.
    """

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        asyncio.run(
            send_account_reactivation_email(
                recipient=TEST_RECIPIENT,
                reactivated_at=TEST_REACTIVATED_AT,
                reason=TEST_REASON,
            )
        )

    mock_send_email.assert_awaited_once()

    await_args = mock_send_email.await_args

    assert await_args is not None

    call_kwargs = await_args.kwargs

    # ------------------------------------------------------------------------
    # Recipient and subject
    # ------------------------------------------------------------------------

    assert call_kwargs["recipient"] == TEST_RECIPIENT

    assert (
        call_kwargs["subject"]
        == "Your TRACKIT account has been reactivated"
    )

    # ------------------------------------------------------------------------
    # HTML email
    # ------------------------------------------------------------------------

    html_body = call_kwargs["html_body"]

    assert "Your TRACKIT account has been reactivated" in (
        html_body
    )

    assert "Your temporary account suspension has expired." in (
        html_body
    )

    assert "Repeatedly submitting misleading claims." in (
        html_body
    )

    assert "September 10, 2026" in (
        html_body
    )

    # ------------------------------------------------------------------------
    # Plain-text email
    # ------------------------------------------------------------------------

    text_body = call_kwargs["text_body"]

    assert "TRACKIT Account Reactivated" in (
        text_body
    )

    assert "Your TRACKIT account is now active again" in (
        text_body
    )

    assert "September 10, 2026" in (
        text_body
    )

    assert "Repeatedly submitting misleading claims." in (
        text_body
    )


def test_send_account_reactivation_email_without_reason():
    """
    A reactivation email should still be sent when the original
    suspension had no reason.
    """

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        asyncio.run(
            send_account_reactivation_email(
                recipient=TEST_RECIPIENT,
                reactivated_at=TEST_REACTIVATED_AT,
                reason=None,
            )
        )

    mock_send_email.assert_awaited_once()

    await_args = mock_send_email.await_args

    assert await_args is not None

    call_kwargs = await_args.kwargs

    assert call_kwargs["recipient"] == TEST_RECIPIENT

    assert (
        call_kwargs["subject"]
        == "Your TRACKIT account has been reactivated"
    )

    assert "Original suspension reason:" not in (
        call_kwargs["html_body"]
    )

    assert "Original suspension reason:" not in (
        call_kwargs["text_body"]
    )


def test_send_account_reactivation_email_escapes_html_reason():
    """
    HTML-sensitive characters in the suspension reason must be
    escaped before being inserted into the HTML email.
    """

    malicious_reason = (
        '<script>alert("xss")</script> '
        "& administrator review"
    )

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        asyncio.run(
            send_account_reactivation_email(
                recipient=TEST_RECIPIENT,
                reactivated_at=TEST_REACTIVATED_AT,
                reason=malicious_reason,
            )
        )

    mock_send_email.assert_awaited_once()

    await_args = mock_send_email.await_args

    assert await_args is not None

    call_kwargs = await_args.kwargs

    html_body = call_kwargs["html_body"]
    text_body = call_kwargs["text_body"]

    assert "<script>" not in html_body
    assert "</script>" not in html_body

    assert "&lt;script&gt;" in html_body
    assert "&lt;/script&gt;" in html_body
    assert "&amp; administrator review" in html_body

    # Plain-text email should preserve the original text.
    assert malicious_reason in text_body


def test_send_account_reactivation_email_normalizes_blank_reason():
    """
    A reason containing only whitespace should not appear in the
    generated email.
    """

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        asyncio.run(
            send_account_reactivation_email(
                recipient=TEST_RECIPIENT,
                reactivated_at=TEST_REACTIVATED_AT,
                reason="   ",
            )
        )

    mock_send_email.assert_awaited_once()

    await_args = mock_send_email.await_args

    assert await_args is not None

    call_kwargs = await_args.kwargs

    assert "Original suspension reason:" not in (
        call_kwargs["html_body"]
    )

    assert "Original suspension reason:" not in (
        call_kwargs["text_body"]
    )


# ============================================================================
# VALIDATION
# ============================================================================


def test_send_account_reactivation_email_rejects_empty_recipient():
    """
    An empty recipient should be rejected before attempting delivery.
    """

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        try:
            asyncio.run(
                send_account_reactivation_email(
                    recipient="   ",
                    reactivated_at=TEST_REACTIVATED_AT,
                )
            )
        except ValueError as exc:
            assert str(exc) == (
                "Recipient email cannot be empty."
            )
        else:
            raise AssertionError(
                "Expected ValueError for empty recipient."
            )

    mock_send_email.assert_not_awaited()


# ============================================================================
# DELIVERY ERROR PROPAGATION
# ============================================================================


def test_send_account_reactivation_email_propagates_delivery_failure():
    """
    SMTP delivery failures should propagate to the caller rather than
    being silently swallowed.
    """

    mock_send_email = AsyncMock(
        side_effect=RuntimeError(
            "SMTP delivery failed."
        )
    )

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        try:
            asyncio.run(
                send_account_reactivation_email(
                    recipient=TEST_RECIPIENT,
                    reactivated_at=TEST_REACTIVATED_AT,
                    reason=TEST_REASON,
                )
            )
        except RuntimeError as exc:
            assert str(exc) == "SMTP delivery failed."
        else:
            raise AssertionError(
                "Expected SMTP delivery failure."
            )

    mock_send_email.assert_awaited_once()

