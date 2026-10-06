from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.repositories.users import get_users_by_ids
from app.services.email import send_admin_custom_email


@dataclass(frozen=True)
class AdminEmailDeliveryResult:
    """
    Result of attempting to deliver an administrator-authored
    email to one TRACKIT user.
    """

    user_id: int
    success: bool
    error: str | None = None


async def send_admin_email_to_users(
    db: Session,
    *,
    user_ids: list[int],
    subject: str,
    message: str,
) -> list[AdminEmailDeliveryResult]:
    """
    Send an administrator-authored email to multiple TRACKIT users.

    Recipients are resolved from registered user IDs. Inactive or
    suspended users are still eligible to receive administrative
    communication.

    Validation of all requested recipients happens before any email
    is
    sent. This prevents a missing user or invalid registered email
    address from causing a partial delivery.

    Each recipient receives an individual email. Recipients therefore
    cannot see the email addresses of other selected users.

    Email delivery failures are isolated per recipient. A failure for one user
    does not prevent delivery attempts to the remaining users.

    Args:
        db:
            Active SQLAlchemy database session.

        user_ids:
            IDs of the TRACKIT users who should receive the email.

        subject:
            Email subject.

        message:
            Plain-text administrator-authored message.

    Returns:
        One delivery result for every requested user, preserving the
        order supplied in user_ids.

    Raises:
        ValueError:
            If a requested user does not exist or does not have a
            registered email address.
    """

    if not user_ids:
        raise ValueError(
            "At least one recipient user ID is required."
        )

    if len(user_ids) != len(set(user_ids)):
        raise ValueError(
            "Duplicate recipient user IDs are not allowed."
        )

    users = get_users_by_ids(
        db,
        user_ids,
    )

    users_by_id = {
        user.id: user
        for user in users
    }

    missing_user_ids = [
        user_id
        for user_id in user_ids
        if user_id not in users_by_id
    ]

    if missing_user_ids:
        formatted_ids = ", ".join(
            str(user_id)
            for user_id in missing_user_ids
        )

        raise ValueError(
            f"User(s) not found: {formatted_ids}."
        )

    recipients = [
        users_by_id[user_id]
        for user_id in user_ids
    ]

    users_without_email = [
        user.id
        for user in recipients
        if not user.email or not user.email.strip()
    ]

    if users_without_email:
        formatted_ids = ", ".join(
            str(user_id)
            for user_id in users_without_email
        )

        raise ValueError(
            "The following user(s) do not have a registered "
            f"email address: {formatted_ids}."
        )

    results: list[AdminEmailDeliveryResult] = []

    for user in recipients:
        try:
            await send_admin_custom_email(
                recipient=user.email,
                subject=subject,
                message=message,
            )
        except Exception:
            results.append(
                AdminEmailDeliveryResult(
                    user_id=user.id,
                    success=False,
                    error="Email delivery failed.",
                )
            )
        else:
            results.append(
                AdminEmailDeliveryResult(
                    user_id=user.id,
                    success=True,
                )
            )

    return results
