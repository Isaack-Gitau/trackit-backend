"""
TRACKIT Temporary Suspension Expiration Task.

Reactivates TRACKIT accounts whose temporary suspensions have expired.

This task is designed to run from an independent scheduler such as:

- cron
- systemd timer
- a deployment/platform scheduler
- a dedicated worker process

It must NOT run as an in-process FastAPI scheduler because the
application may run multiple workers.

Transaction boundary:

1. Find expired suspended accounts.
2. Capture suspension metadata needed for audit/email.
3. Reactivate the accounts.
4. Create automated audit records.
5. Commit the database transaction.
6. Send reactivation emails after the successful commit.

Email delivery failures are intentionally isolated from the database
transaction. A failed email must never roll back a successful account
reactivation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.repositories.users import get_expired_suspended_users
from app.services.audit_log import (
    AUDIT_ADMIN_ACTION,
    create_audit_log,
)
from app.services.email import send_account_reactivation_email
from app.services.user import activate_suspended_user

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SuspensionExpirationContext:
    user_id: int
    email: str
    reason: str | None
    expired_at: datetime
    reactivated_at: datetime


def reactivate_expired_suspensions(
    db: Session,
    *,
    now: datetime | None = None,
) -> list[SuspensionExpirationContext]:
    if now is None:
        now = datetime.now(timezone.utc)

    expired_users = get_expired_suspended_users(db, now=now)
    reactivated: list[SuspensionExpirationContext] = []

    for user in expired_users:
        if user.deactivated_until is None:
            continue

        # Capture all suspension metadata before activation clears it.
        expired_at = user.deactivated_until
        reason = user.deactivation_reason
        email = user.email
        user_id = user.id

        activate_suspended_user(db, user)

        create_audit_log(
            db,
            event_type=AUDIT_ADMIN_ACTION,
            success=True,
            description=(
                "Automatically reactivated user "
                f"{user_id} after temporary suspension expired."
            ),
            user_id=None,
            subject_user_id=user_id,
            resource_type="user",
            resource_id=user_id,
        )

        reactivated.append(
            SuspensionExpirationContext(
                user_id=user_id,
                email=email,
                reason=reason,
                expired_at=expired_at,
                reactivated_at=now,
            )
        )

    return reactivated


async def send_reactivation_emails(
    reactivated_users: list[SuspensionExpirationContext],
) -> None:
    for context in reactivated_users:
        try:
            await send_account_reactivation_email(
                recipient=context.email,
                reactivated_at=context.reactivated_at,
                reason=context.reason,
            )
        except Exception:
            logger.exception(
                "Failed to send automatic reactivation email "
                "for user_id=%s recipient=%s.",
                context.user_id,
                context.email,
            )


async def run_suspension_expiration_task(
    *,
    now: datetime | None = None,
) -> list[SuspensionExpirationContext]:
    db = SessionLocal()

    try:
        reactivated = reactivate_expired_suspensions(
            db,
            now=now,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    await send_reactivation_emails(reactivated)

    return reactivated

if __name__ == "__main__":
    import asyncio

    asyncio.run(run_suspension_expiration_task())