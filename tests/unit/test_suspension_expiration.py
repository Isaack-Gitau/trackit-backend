from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.constants import UserRole
from app.models.user import User
from app.services.user import suspend_user
from app.tasks.suspension_expiration import (
    SuspensionExpirationContext,
    reactivate_expired_suspensions,
    run_suspension_expiration_task,
    send_reactivation_emails,
)


def test_reactivate_expired_suspensions_service_reactivates_expired_account(
    db,
):
    admin_user = User(
        username="expiration-admin",
        first_name="Expiration",
        last_name="Admin",
        email="expiration-admin@example.com",
        password_hash="hashed",
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )
    target_user = User(
        username="expired-user",
        first_name="Expired",
        last_name="User",
        email="expired-user@example.com",
        password_hash="hashed",
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
    )

    db.add_all([admin_user, target_user])
    db.flush()

    suspend_user(
        db,
        target_user=target_user,
        acting_admin=admin_user,
        duration_hours=1,
        reason="Temporary suspension",
    )

    expiration_time = target_user.deactivated_until
    assert expiration_time is not None

    reactivation_time = expiration_time + timedelta(seconds=1)

    contexts = reactivate_expired_suspensions(
        db,
        now=reactivation_time,
    )

    assert len(contexts) == 1
    assert contexts[0].user_id == target_user.id
    assert contexts[0].email == target_user.email
    assert contexts[0].reason == "Temporary suspension"
    assert contexts[0].expired_at == expiration_time
    assert contexts[0].reactivated_at == reactivation_time

    assert target_user.is_active is True
    assert target_user.deactivated_at is None
    assert target_user.deactivated_until is None
    assert target_user.deactivation_reason is None


def test_reactivate_expired_suspensions_service_leaves_future_suspension_untouched(
    db,
):
    admin_user = User(
        username="future-admin",
        first_name="Future",
        last_name="Admin",
        email="future-admin@example.com",
        password_hash="hashed",
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )
    target_user = User(
        username="future-user",
        first_name="Future",
        last_name="User",
        email="future-user@example.com",
        password_hash="hashed",
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
    )

    db.add_all([admin_user, target_user])
    db.flush()

    suspend_user(
        db,
        target_user=target_user,
        acting_admin=admin_user,
        duration_hours=1,
        reason="Future suspension",
    )

    future_expiration = target_user.deactivated_until
    assert future_expiration is not None

    contexts = reactivate_expired_suspensions(
        db,
        now=future_expiration - timedelta(seconds=1),
    )

    assert contexts == []
    assert target_user.is_active is False
    assert target_user.deactivated_until == future_expiration
    assert target_user.deactivation_reason == "Future suspension"


def test_reactivate_expired_suspensions_service_processes_multiple_accounts(
    db,
):
    admin_user = User(
        username="multiple-admin",
        first_name="Multiple",
        last_name="Admin",
        email="multiple-admin@example.com",
        password_hash="hashed",
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )
    first_user = User(
        username="multiple-first",
        first_name="Multiple",
        last_name="First",
        email="multiple-first@example.com",
        password_hash="hashed",
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
    )
    second_user = User(
        username="multiple-second",
        first_name="Multiple",
        last_name="Second",
        email="multiple-second@example.com",
        password_hash="hashed",
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
    )

    db.add_all([admin_user, first_user, second_user])
    db.flush()

    suspend_user(
        db,
        target_user=first_user,
        acting_admin=admin_user,
        duration_hours=1,
        reason="First suspension",
    )
    suspend_user(
        db,
        target_user=second_user,
        acting_admin=admin_user,
        duration_hours=1,
        reason="Second suspension",
    )

    first_expiration = first_user.deactivated_until
    second_expiration = second_user.deactivated_until

    assert first_expiration is not None
    assert second_expiration is not None

    expiration_time = min(first_expiration, second_expiration)
    reactivation_time = expiration_time + timedelta(seconds=1)

    contexts = reactivate_expired_suspensions(
        db,
        now=reactivation_time,
    )

    assert len(contexts) == 2
    assert {context.user_id for context in contexts} == {
        first_user.id,
        second_user.id,
    }

    assert all(
        context.reactivated_at == reactivation_time
        for context in contexts
    )

    assert first_user.is_active is True
    assert second_user.is_active is True


def test_reactivate_expired_suspensions_service_ignores_unscheduled_inactive_account(
    db,
):
    target_user = User(
        username="unscheduled-user",
        first_name="Unscheduled",
        last_name="User",
        email="unscheduled-user@example.com",
        password_hash="hashed",
        role=UserRole.USER,
        is_active=False,
        is_verified=True,
    )

    db.add(target_user)
    db.flush()

    contexts = reactivate_expired_suspensions(
        db,
        now=datetime.now(timezone.utc),
    )

    assert contexts == []
    assert target_user.is_active is False


def test_suspend_and_activate_service_changes_can_be_rolled_back(
    db,
):
    admin_user = User(
        username="rollback-admin",
        first_name="Rollback",
        last_name="Admin",
        email="rollback-admin@example.com",
        password_hash="hashed",
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )
    target_user = User(
        username="rollback-user",
        first_name="Rollback",
        last_name="User",
        email="rollback-user@example.com",
        password_hash="hashed",
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
    )

    db.add_all([admin_user, target_user])
    db.commit()

    original_token_version = target_user.token_version

    suspend_user(
        db,
        target_user=target_user,
        acting_admin=admin_user,
        duration_hours=1,
        reason="Rollback test",
    )

    assert target_user.is_active is False

    db.rollback()
    db.expire_all()

    refreshed_user = db.get(User, target_user.id)
    assert refreshed_user is not None
    assert refreshed_user.is_active is True
    assert refreshed_user.deactivated_at is None
    assert refreshed_user.deactivated_until is None
    assert refreshed_user.deactivation_reason is None
    assert refreshed_user.token_version == original_token_version


def test_run_suspension_expiration_task_commits_and_closes_session():
    reactivated = [
        SuspensionExpirationContext(
            user_id=1,
            email="user@example.com",
            reason="Temporary suspension",
            expired_at=datetime.now(timezone.utc),
            reactivated_at=datetime.now(timezone.utc),
        )
    ]

    mock_session = MagicMock()

    with (
        patch(
            "app.tasks.suspension_expiration.SessionLocal",
            return_value=mock_session,
        ),
        patch(
            "app.tasks.suspension_expiration.reactivate_expired_suspensions",
            return_value=reactivated,
        ),
        patch(
            "app.tasks.suspension_expiration.send_reactivation_emails",
            new_callable=AsyncMock,
        ) as mock_send_emails,
    ):
        result = __import__("asyncio").run(
            run_suspension_expiration_task()
        )

    assert result == reactivated
    mock_session.commit.assert_called_once()
    mock_session.rollback.assert_not_called()
    mock_session.close.assert_called_once()
    mock_send_emails.assert_awaited_once_with(reactivated)


def test_run_suspension_expiration_task_rolls_back_on_database_error():
    mock_session = MagicMock()

    with (
        patch(
            "app.tasks.suspension_expiration.SessionLocal",
            return_value=mock_session,
        ),
        patch(
            "app.tasks.suspension_expiration.reactivate_expired_suspensions",
            side_effect=RuntimeError("database error"),
        ),
    ):
        with pytest.raises(RuntimeError, match="database error"):
            __import__("asyncio").run(
                run_suspension_expiration_task()
            )

    mock_session.commit.assert_not_called()
    mock_session.rollback.assert_called_once()
    mock_session.close.assert_called_once()


def test_run_suspension_expiration_task_rolls_back_when_commit_fails():
    mock_session = MagicMock()
    mock_session.commit.side_effect = RuntimeError("commit failed")

    with (
        patch(
            "app.tasks.suspension_expiration.SessionLocal",
            return_value=mock_session,
        ),
        patch(
            "app.tasks.suspension_expiration.reactivate_expired_suspensions",
            return_value=[],
        ),
    ):
        with pytest.raises(RuntimeError, match="commit failed"):
            __import__("asyncio").run(
                run_suspension_expiration_task()
            )

    mock_session.commit.assert_called_once()
    mock_session.rollback.assert_called_once()
    mock_session.close.assert_called_once()


def test_send_reactivation_emails_sends_email_to_all_users():
    first_time = datetime.now(timezone.utc)
    second_time = first_time + timedelta(minutes=5)

    contexts = [
        SuspensionExpirationContext(
            user_id=1,
            email="first@example.com",
            reason="First reason",
            expired_at=first_time,
            reactivated_at=first_time,
        ),
        SuspensionExpirationContext(
            user_id=2,
            email="second@example.com",
            reason=None,
            expired_at=second_time,
            reactivated_at=second_time,
        ),
    ]

    async_mock = AsyncMock()

    with patch(
        "app.tasks.suspension_expiration.send_account_reactivation_email",
        async_mock,
    ):
        __import__("asyncio").run(
            send_reactivation_emails(contexts)
        )

    assert async_mock.await_count == 2
    async_mock.assert_any_await(
        recipient="first@example.com",
        reactivated_at=first_time,
        reason="First reason",
    )
    async_mock.assert_any_await(
        recipient="second@example.com",
        reactivated_at=second_time,
        reason=None,
    )


def test_send_reactivation_emails_continues_after_delivery_failure():
    first_time = datetime.now(timezone.utc)
    second_time = first_time + timedelta(minutes=5)

    contexts = [
        SuspensionExpirationContext(
            user_id=1,
            email="failed@example.com",
            reason="Failed delivery",
            expired_at=first_time,
            reactivated_at=first_time,
        ),
        SuspensionExpirationContext(
            user_id=2,
            email="success@example.com",
            reason=None,
            expired_at=second_time,
            reactivated_at=second_time,
        ),
    ]

    async_mock = AsyncMock(
        side_effect=[
            RuntimeError("email delivery failed"),
            None,
        ]
    )

    with patch(
        "app.tasks.suspension_expiration.send_account_reactivation_email",
        async_mock,
    ):
        __import__("asyncio").run(
            send_reactivation_emails(contexts)
        )

    assert async_mock.await_count == 2

