from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.user import User


def get_user_by_id(
    db: Session,
    user_id: int,
) -> User | None:
    result = db.execute(
        select(User).where(User.id == user_id)
    )

    return result.scalar_one_or_none()


def get_user_by_username(
    db: Session,
    username: str,
) -> User | None:
    username = username.strip().lower()

    result = db.execute(
        select(User).where(
            User.username == username
        )
    )

    return result.scalar_one_or_none()


def get_user_by_email(
    db: Session,
    email: str,
) -> User | None:
    email = email.strip().lower()

    result = db.execute(
        select(User).where(
            User.email == email
        )
    )

    return result.scalar_one_or_none()


def get_user_by_login(
    db: Session,
    login: str,
) -> User | None:
    login = login.strip().lower()

    result = db.execute(
        select(User).where(
            or_(
                User.username == login,
                User.email == login,
            )
        )
    )

    return result.scalar_one_or_none()


def username_exists(
    db: Session,
    username: str,
) -> bool:
    return get_user_by_username(
        db,
        username,
    ) is not None


def email_exists(
    db: Session,
    email: str,
) -> bool:
    return get_user_by_email(
        db,
        email,
    ) is not None


def create_user(
    db: Session,
    *,
    username: str,
    first_name: str,
    last_name: str,
    email: str,
    password_hash: str,
) -> User:

    user = User(
        username=username.strip().lower(),
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        email=email.strip().lower(),
        password_hash=password_hash,
        role="user",
        is_active=True,
        is_verified=False,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user