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

    Tests are allowed to call db.commit() normally.

    The fixture wraps the connection in an outer transaction.
    Everything performed by the test is rolled back after the test
    completes.
    """

    engine = create_engine(
        TEST_DATABASE_URL,
        future=True,
    )

    connection = engine.connect()

    transaction = connection.begin()

    TestingSessionLocal = sessionmaker(
        bind=connection,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    session: Session = TestingSessionLocal()

    try:
        yield session

    finally:
        session.close()

        transaction.rollback()

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
    Provide a FastAPI TestClient using the isolated test database.

    This ensures API integration tests never accidentally use
    the development database.
    """

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as test_client:
            yield test_client

    finally:
        app.dependency_overrides.clear()


# ============================================================================
# BASIC TEST ENVIRONMENT
# ============================================================================


@pytest.fixture
def test_marker() -> str:
    """
    Basic fixture proving that the TRACKIT test environment loads.
    """

    return "TRACKIT"