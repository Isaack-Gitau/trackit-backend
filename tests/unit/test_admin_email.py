import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.admin_email import (
    AdminEmailDeliveryResult,
    send_admin_email_to_users,
)


def make_user(
    user_id: int,
    email: str,
    *,
    is_active: bool = True,
) -> MagicMock:
    return MagicMock(
        id=user_id,
        email=email,
        is_active=is_active,
    )


def test_send_admin_email_to_users_sends_individual_emails():
    users = [
        make_user(3, "three@example.com"),
        make_user(1, "one@example.com"),
        make_user(2, "two@example.com"),
    ]

    mock_sender = AsyncMock()

    with (
        patch(
            "app.services.admin_email.get_users_by_ids",
            return_value=users,
        ),
        patch(
            "app.services.admin_email.send_admin_custom_email",
            mock_sender,
        ),
    ):
        results = asyncio.run(
            send_admin_email_to_users(
                MagicMock(),
                user_ids=[1, 2, 3],
                subject="TRACKIT Update",
                message="Important administrative message.",
            )
        )

    assert results == [
        AdminEmailDeliveryResult(
            user_id=1,
            success=True,
        ),
        AdminEmailDeliveryResult(
            user_id=2,
            success=True,
        ),
        AdminEmailDeliveryResult(
            user_id=3,
            success=True,
        ),
    ]

    assert mock_sender.await_count == 3

    assert mock_sender.await_args_list[0].kwargs == {
        "recipient": "one@example.com",
        "subject": "TRACKIT Update",
        "message": "Important administrative message.",
    }

    assert mock_sender.await_args_list[1].kwargs == {
        "recipient": "two@example.com",
        "subject": "TRACKIT Update",
        "message": "Important administrative message.",
    }

    assert mock_sender.await_args_list[2].kwargs == {
        "recipient": "three@example.com",
        "subject": "TRACKIT Update",
        "message": "Important administrative message.",
    }


def test_inactive_users_are_allowed_to_receive_admin_email():
    users = [
        make_user(
            10,
            "inactive@example.com",
            is_active=False,
        ),
    ]

    mock_sender = AsyncMock()

    with (
        patch(
            "app.services.admin_email.get_users_by_ids",
            return_value=users,
        ),
        patch(
            "app.services.admin_email.send_admin_custom_email",
            mock_sender,
        ),
    ):
        results = asyncio.run(
            send_admin_email_to_users(
                MagicMock(),
                user_ids=[10],
                subject="Account Notice",
                message="This is an administrative notice.",
            )
        )

    assert results == [
        AdminEmailDeliveryResult(
            user_id=10,
            success=True,
        )
    ]

    mock_sender.assert_awaited_once_with(
        recipient="inactive@example.com",
        subject="Account Notice",
        message="This is an administrative notice.",
    )


def test_missing_users_are_rejected_before_any_email_is_sent():
    users = [
        make_user(1, "one@example.com"),
    ]

    mock_sender = AsyncMock()

    with (
        patch(
            "app.services.admin_email.get_users_by_ids",
            return_value=users,
        ),
        patch(
            "app.services.admin_email.send_admin_custom_email",
            mock_sender,
        ),
    ):
        with pytest.raises(
            ValueError,
            match=r"User\(s\) not found: 2\.",
        ):
            asyncio.run(
                send_admin_email_to_users(
                    MagicMock(),
                    user_ids=[1, 2],
                    subject="TRACKIT Update",
                    message="Message",
                )
            )

    mock_sender.assert_not_awaited()


def test_users_without_email_are_rejected_before_any_email_is_sent():
    users = [
        make_user(1, "one@example.com"),
        make_user(2, "   "),
    ]

    mock_sender = AsyncMock()

    with (
        patch(
            "app.services.admin_email.get_users_by_ids",
            return_value=users,
        ),
        patch(
            "app.services.admin_email.send_admin_custom_email",
            mock_sender,
        ),
    ):
        with pytest.raises(
            ValueError,
            match="do not have a registered email address: 2",
        ):
            asyncio.run(
                send_admin_email_to_users(
                    MagicMock(),
                    user_ids=[1, 2],
                    subject="TRACKIT Update",
                    message="Message",
                )
            )

    mock_sender.assert_not_awaited()


def test_delivery_failure_does_not_stop_other_recipients():
    users = [
        make_user(1, "one@example.com"),
        make_user(2, "two@example.com"),
        make_user(3, "three@example.com"),
    ]

    async def send_side_effect(
        *,
        recipient: str,
        subject: str,
        message: str,
    ) -> None:
        if recipient == "two@example.com":
            raise RuntimeError("SMTP failure")

    mock_sender = AsyncMock(
        side_effect=send_side_effect,
    )

    with (
        patch(
            "app.services.admin_email.get_users_by_ids",
            return_value=users,
        ),
        patch(
            "app.services.admin_email.send_admin_custom_email",
            mock_sender,
        ),
    ):
        results = asyncio.run(
            send_admin_email_to_users(
                MagicMock(),
                user_ids=[1, 2, 3],
                subject="TRACKIT Update",
                message="Message",
            )
        )

    assert results == [
        AdminEmailDeliveryResult(
            user_id=1,
            success=True,
        ),
        AdminEmailDeliveryResult(
            user_id=2,
            success=False,
            error="Email delivery failed.",
        ),
        AdminEmailDeliveryResult(
            user_id=3,
            success=True,
        ),
    ]

    assert mock_sender.await_count == 3


def test_duplicate_user_ids_are_rejected():
    mock_sender = AsyncMock()

    with patch(
        "app.services.admin_email.send_admin_custom_email",
        mock_sender,
    ):
        with pytest.raises(
            ValueError,
            match="Duplicate recipient user IDs are not allowed",
        ):
            asyncio.run(
                send_admin_email_to_users(
                    MagicMock(),
                    user_ids=[1, 1],
                    subject="TRACKIT Update",
                    message="Message",
                )
            )

    mock_sender.assert_not_awaited()


def test_empty_recipient_list_is_rejected():
    mock_sender = AsyncMock()

    with patch(
        "app.services.admin_email.send_admin_custom_email",
        mock_sender,
    ):
        with pytest.raises(
            ValueError,
            match="At least one recipient user ID is required",
        ):
            asyncio.run(
                send_admin_email_to_users(
                    MagicMock(),
                    user_ids=[],
                    subject="TRACKIT Update",
                    message="Message",
                )
            )

    mock_sender.assert_not_awaited()