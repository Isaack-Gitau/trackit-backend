"""
TRACKIT Pytest Configuration.

Shared fixtures for unit and integration tests.

Test architecture:

    Unit tests
        ↓
    Service / Repository tests

    Integration tests
        ↓
    FastAPI application
        ↓
    Dependencies
        ↓
    Services / Repositories
        ↓
    Test PostgreSQL database
"""

import pytest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.dependencies import get_db
from app.main import app


# ============================================================================
# TEST DATABASE
# ============================================================================

TEST_DATABASE_URL = (
    settings.DATABASE_URL.rsplit("/", 1)[0]
    + "/trackit_test_db"
)


# ============================================================================
# DATABASE FIXTURE
# ============================================================================
@pytest.fixture
def db():
    """
    Provide an isolated database session for each test.

    The database connection is wrapped in an outer transaction owned
    by the pytest fixture.

    The SQLAlchemy Session uses create_savepoint mode so that normal
    application calls to db.commit() and db.rollback() operate inside
    SAVEPOINTs rather than destroying the fixture's outer transaction.

    This preserves test isolation while allowing production code to
    use normal transaction behavior.
    """

    engine = create_engine(
        TEST_DATABASE_URL,
        future=True,
    )

    connection = engine.connect()

    outer_transaction = connection.begin()

    TestingSessionLocal = sessionmaker(
        bind=connection,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )

    session: Session = TestingSessionLocal()

    try:
        yield session

    finally:
        session.close()

        if outer_transaction.is_active:
            outer_transaction.rollback()

        connection.close()

        engine.dispose()


@pytest.fixture
def admin_user(db: Session):
    """
    Provide a test administrator for moderation tests.
    """

    from app.models.user import User

    user = User(
        id=99,
        username="testadmin99",
        first_name="Test",
        last_name="Admin",
        email="testadmin99@trackit.test",
        password_hash="test-password-hash",
        role="admin",
        is_active=True,
        is_verified=True,
    )

    db.add(user)
    db.flush()

    return user


# ============================================================================
# FASTAPI DATABASE OVERRIDE
# ============================================================================


@pytest.fixture
def client(db: Session):
    """
    Provide a FastAPI TestClient using a separate API session.

    The test/setup session and API session share the same database
    connection and outer transaction.

    Before the API session is created, the test session commits its
    current SAVEPOINT. This keeps test-created data inside the outer
    transaction while ensuring that an application-level rollback
    cannot remove the test setup data.

    The API session uses its own SAVEPOINT through
    join_transaction_mode="create_savepoint".
    """

    connection = db.get_bind()

    if connection is None:
        raise RuntimeError(
            "Test database session is not bound to a connection."
        )

    # Preserve all test setup performed through `db` inside the
    # outer pytest transaction before handing the connection to
    # the API session.
    db.commit()

    ApiSessionLocal = sessionmaker(
        bind=connection,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )

    api_db: Session = ApiSessionLocal()

    def override_get_db():
        yield api_db

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as test_client:
            yield test_client

    finally:
        app.dependency_overrides.clear()

        api_db.close()


# ============================================================================
# BASIC TEST ENVIRONMENT
# ============================================================================


@pytest.fixture
def test_marker() -> str:
    """
    Basic fixture proving that the TRACKIT test environment loads.
    """

    return "TRACKIT"