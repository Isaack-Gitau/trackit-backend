"""
TRACKIT Email Service Unit Tests.

Tests transactional email generation and delivery behavior.

Coverage:
- account deactivation email
- account reactivation email
- reactivation timestamp formatting
- optional suspension reason
- HTML escaping
- recipient validation
- SMTP delivery delegation
- administrator custom email
- custom email subject/message normalization
- custom email HTML escaping
- custom email header-injection protection
- custom email delivery failure propagation
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from app.services.email import (
    send_account_deactivation_email,
    send_account_reactivation_email,
    send_admin_custom_email,
)


# ============================================================================
# TEST CONSTANTS
# ============================================================================

TEST_RECIPIENT = "user@trackit.test"

TEST_DEACTIVATED_AT = datetime(
    2026,
    9,
    10,
    12,
    30,
    0,
    tzinfo=timezone.utc,
)

TEST_DEACTIVATED_UNTIL = datetime(
    2026,
    9,
    17,
    12,
    30,
    0,
    tzinfo=timezone.utc,
)

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
# ACCOUNT DEACTIVATION EMAIL
# ============================================================================


def test_send_account_deactivation_email_successfully_sends_email():
    """
    A valid deactivation notification should be passed to the
    existing email delivery function.
    """

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        asyncio.run(
            send_account_deactivation_email(
                recipient=TEST_RECIPIENT,
                deactivated_at=TEST_DEACTIVATED_AT,
                deactivated_until=TEST_DEACTIVATED_UNTIL,
                reason=TEST_REASON,
            )
        )

    mock_send_email.assert_awaited_once()

    await_args = mock_send_email.await_args

    assert await_args is not None

    call_kwargs = await_args.kwargs

    assert call_kwargs["recipient"] == TEST_RECIPIENT

    assert (
        call_kwargs["subject"]
        == "Your TRACKIT account has been temporarily deactivated"
    )

    html_body = call_kwargs["html_body"]
    text_body = call_kwargs["text_body"]

    assert (
        "Your TRACKIT account has been temporarily deactivated"
        in html_body
    )
    assert "September 10, 2026" in html_body
    assert "September 17, 2026" in html_body
    assert "Repeatedly submitting misleading claims." in html_body

    assert "TRACKIT Account Temporarily Deactivated" in text_body
    assert "September 10, 2026" in text_body
    assert "September 17, 2026" in text_body
    assert "Repeatedly submitting misleading claims." in text_body


def test_send_account_deactivation_email_without_reason():
    """
    A deactivation email should still be sent when no reason was provided.
    """

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        asyncio.run(
            send_account_deactivation_email(
                recipient=TEST_RECIPIENT,
                deactivated_at=TEST_DEACTIVATED_AT,
                deactivated_until=TEST_DEACTIVATED_UNTIL,
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
        == "Your TRACKIT account has been temporarily deactivated"
    )
    assert "Reason provided by TrackIt administration:" not in (
        call_kwargs["html_body"]
    )
    assert "Reason provided by TrackIt administration:" not in (
        call_kwargs["text_body"]
    )


def test_send_account_deactivation_email_escapes_html_reason():
    """
    HTML-sensitive characters in the deactivation reason must be
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
            send_account_deactivation_email(
                recipient=TEST_RECIPIENT,
                deactivated_at=TEST_DEACTIVATED_AT,
                deactivated_until=TEST_DEACTIVATED_UNTIL,
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

    assert malicious_reason in text_body


def test_send_account_deactivation_email_normalizes_blank_reason():
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
            send_account_deactivation_email(
                recipient=TEST_RECIPIENT,
                deactivated_at=TEST_DEACTIVATED_AT,
                deactivated_until=TEST_DEACTIVATED_UNTIL,
                reason="   ",
            )
        )

    mock_send_email.assert_awaited_once()

    await_args = mock_send_email.await_args

    assert await_args is not None

    call_kwargs = await_args.kwargs

    assert "Reason provided by TrackIt administration:" not in (
        call_kwargs["html_body"]
    )
    assert "Reason provided by TrackIt administration:" not in (
        call_kwargs["text_body"]
    )


def test_send_account_deactivation_email_rejects_empty_recipient():
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
                send_account_deactivation_email(
                    recipient="   ",
                    deactivated_at=TEST_DEACTIVATED_AT,
                    deactivated_until=TEST_DEACTIVATED_UNTIL,
                )
            )
        except ValueError as exc:
            assert str(exc) == "Recipient email cannot be empty."
        else:
            raise AssertionError(
                "Expected ValueError for empty recipient."
            )

    mock_send_email.assert_not_awaited()


def test_send_account_deactivation_email_propagates_delivery_failure():
    """
    SMTP delivery failures should propagate to the caller rather than
    being silently swallowed.
    """

    mock_send_email = AsyncMock(
        side_effect=RuntimeError("SMTP delivery failed.")
    )

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        try:
            asyncio.run(
                send_account_deactivation_email(
                    recipient=TEST_RECIPIENT,
                    deactivated_at=TEST_DEACTIVATED_AT,
                    deactivated_until=TEST_DEACTIVATED_UNTIL,
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
# ACCOUNT REACTIVATION VALIDATION
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
# ACCOUNT REACTIVATION DELIVERY ERROR
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


# ============================================================================
# ADMINISTRATOR CUSTOM EMAIL
# ============================================================================


def test_send_admin_custom_email_successfully_sends_email():
    """
    A valid administrator custom email should be passed to the
    existing shared email delivery function.
    """

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        asyncio.run(
            send_admin_custom_email(
                recipient=TEST_RECIPIENT,
                subject="TRACKIT Service Update",
                message="The TRACKIT service will be unavailable briefly.",
            )
        )

    mock_send_email.assert_awaited_once()

    await_args = mock_send_email.await_args

    assert await_args is not None

    call_kwargs = await_args.kwargs

    assert call_kwargs["recipient"] == TEST_RECIPIENT

    assert call_kwargs["subject"] == "TRACKIT Service Update"

    assert "TRACKIT Service Update" in call_kwargs["html_body"]

    assert (
        "The TRACKIT service will be unavailable briefly."
        in call_kwargs["html_body"]
    )

    assert (
        "The TRACKIT service will be unavailable briefly."
        in call_kwargs["text_body"]
    )

    assert "TRACKIT Administration" in call_kwargs["text_body"]


def test_send_admin_custom_email_normalizes_recipient_subject_and_message():
    """
    Leading and trailing whitespace should be removed from the
    recipient, subject, and message.
    """

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        asyncio.run(
            send_admin_custom_email(
                recipient="   user@trackit.test   ",
                subject="   Service Update   ",
                message="   Please read this update.   ",
            )
        )

    mock_send_email.assert_awaited_once()

    await_args = mock_send_email.await_args

    assert await_args is not None

    call_kwargs = await_args.kwargs

    assert call_kwargs["recipient"] == TEST_RECIPIENT

    assert call_kwargs["subject"] == "Service Update"

    assert "Please read this update." in call_kwargs["text_body"]


def test_send_admin_custom_email_escapes_html_content():
    """
    Administrator-authored content must be HTML-escaped before
    being inserted into the HTML email body.
    """

    malicious_subject = (
        '<script>alert("subject")</script>'
    )

    malicious_message = (
        '<script>alert("message")</script> '
        '<img src="javascript:alert(1)"> '
        "& administrator review"
    )

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        asyncio.run(
            send_admin_custom_email(
                recipient=TEST_RECIPIENT,
                subject=malicious_subject,
                message=malicious_message,
            )
        )

    mock_send_email.assert_awaited_once()

    await_args = mock_send_email.await_args

    assert await_args is not None

    call_kwargs = await_args.kwargs

    html_body = call_kwargs["html_body"]

    assert "<script>" not in html_body
    assert "</script>" not in html_body
    assert "<img" not in html_body

    assert "&lt;script&gt;" in html_body
    assert "&lt;/script&gt;" in html_body
    assert "&lt;img" in html_body
    assert "&amp; administrator review" in html_body


def test_send_admin_custom_email_preserves_newlines_in_plain_text():
    """
    Message line breaks should be represented as HTML breaks while
    remaining readable in the plain-text email.
    """

    message = (
        "First paragraph.\n"
        "\n"
        "Second paragraph.\n"
        "Final line."
    )

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        asyncio.run(
            send_admin_custom_email(
                recipient=TEST_RECIPIENT,
                subject="Message",
                message=message,
            )
        )

    mock_send_email.assert_awaited_once()

    await_args = mock_send_email.await_args

    assert await_args is not None

    call_kwargs = await_args.kwargs

    html_body = call_kwargs["html_body"]
    text_body = call_kwargs["text_body"]

    assert "<br>" in html_body

    assert "First paragraph.\n" in text_body
    assert "Second paragraph.\n" in text_body
    assert "Final line." in text_body


# ============================================================================
# ADMINISTRATOR CUSTOM EMAIL VALIDATION
# ============================================================================


def test_send_admin_custom_email_rejects_empty_recipient():
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
                send_admin_custom_email(
                    recipient="   ",
                    subject="Service Update",
                    message="Please read this update.",
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


def test_send_admin_custom_email_rejects_empty_subject():
    """
    An empty subject should be rejected before attempting delivery.
    """

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        try:
            asyncio.run(
                send_admin_custom_email(
                    recipient=TEST_RECIPIENT,
                    subject="   ",
                    message="Please read this update.",
                )
            )
        except ValueError as exc:
            assert str(exc) == (
                "Email subject cannot be empty."
            )
        else:
            raise AssertionError(
                "Expected ValueError for empty subject."
            )

    mock_send_email.assert_not_awaited()


def test_send_admin_custom_email_rejects_empty_message():
    """
    An empty message should be rejected before attempting delivery.
    """

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        try:
            asyncio.run(
                send_admin_custom_email(
                    recipient=TEST_RECIPIENT,
                    subject="Service Update",
                    message="   ",
                )
            )
        except ValueError as exc:
            assert str(exc) == (
                "Email message cannot be empty."
            )
        else:
            raise AssertionError(
                "Expected ValueError for empty message."
            )

    mock_send_email.assert_not_awaited()


def test_send_admin_custom_email_rejects_subject_newline_injection():
    """
    Newline characters in the subject must be rejected to prevent
    email header injection.
    """

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        try:
            asyncio.run(
                send_admin_custom_email(
                    recipient=TEST_RECIPIENT,
                    subject="Legitimate Subject\nBcc: attacker@example.com",
                    message="Message body.",
                )
            )
        except ValueError as exc:
            assert str(exc) == (
                "Email subject cannot contain newline characters."
            )
        else:
            raise AssertionError(
                "Expected ValueError for subject newline injection."
            )

    mock_send_email.assert_not_awaited()


def test_send_admin_custom_email_rejects_subject_carriage_return_injection():
    """
    Carriage returns in the subject must also be rejected to prevent
    email header injection.
    """

    mock_send_email = AsyncMock()

    with patch(
        "app.services.email._send_email",
        mock_send_email,
    ):
        try:
            asyncio.run(
                send_admin_custom_email(
                    recipient=TEST_RECIPIENT,
                    subject="Legitimate Subject\rBcc: attacker@example.com",
                    message="Message body.",
                )
            )
        except ValueError as exc:
            assert str(exc) == (
                "Email subject cannot contain newline characters."
            )
        else:
            raise AssertionError(
                "Expected ValueError for subject carriage-return injection."
            )

    mock_send_email.assert_not_awaited()


# ============================================================================
# ADMINISTRATOR CUSTOM EMAIL DELIVERY ERROR
# ============================================================================


def test_send_admin_custom_email_propagates_delivery_failure():
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
                send_admin_custom_email(
                    recipient=TEST_RECIPIENT,
                    subject="Service Update",
                    message="Please read this update.",
                )
            )
        except RuntimeError as exc:
            assert str(exc) == "SMTP delivery failed."
        else:
            raise AssertionError(
                "Expected SMTP delivery failure."
            )

    mock_send_email.assert_awaited_once()
