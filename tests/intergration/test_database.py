"""
TRACKIT Database Integration Tests.

These tests verify that:

- TRACKIT can connect to PostgreSQL.
- The expected database is being used.
- The expected database user is being used.
- Required tables exist.
- Required columns exist.
- Security-related user fields exist.
- Item relationships are correct.
- Authentication-token relationships are correct.
- Required UNIQUE constraints exist.
- ON DELETE CASCADE is configured correctly.
- Alembic migrations are applied to the expected revision.

These tests intentionally inspect the real PostgreSQL database.
They do not create or modify application data.
"""

from sqlalchemy import inspect, text

from app.db.session import engine


# ============================================================================
# DATABASE CONNECTION
# ============================================================================


def test_database_connection():
    """
    Verify that TRACKIT can connect to PostgreSQL using the configured
    application database credentials.
    """

    with engine.connect() as connection:
        result = connection.execute(
            text(
                """
                SELECT current_database(), current_user
                """
            )
        )

        row = result.fetchone()

    assert row is not None

    database, user = row

    assert database == "trackit_db"
    assert user == "trackit_app"


# ============================================================================
# REQUIRED TABLES
# ============================================================================


def test_required_tables_exist():
    """
    Verify that all core TRACKIT tables exist.
    """

    inspector = inspect(engine)

    tables = set(inspector.get_table_names())

    required_tables = {
        "users",
        "items",
        "auth_tokens",
    }

    assert required_tables.issubset(tables)


# ============================================================================
# USERS TABLE
# ============================================================================


def test_users_table_contains_required_columns():
    """
    Verify that the users table contains all required identity,
    authentication, authorization, account-status, and security fields.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]
        for column in inspector.get_columns("users")
    }

    required_columns = {
        "id",
        "username",
        "first_name",
        "last_name",
        "email",
        "password_hash",
        "role",
        "is_active",
        "is_verified",
        "password_changed_at",
        "token_version",
        "created_at",
        "updated_at",
    }

    assert required_columns.issubset(columns)


def test_users_table_has_unique_username_and_email():
    """
    Verify that usernames and email addresses are unique.

    TRACKIT requires these identities to be unique at the database level.
    """

    inspector = inspect(engine)

    indexes = inspector.get_indexes("users")

    unique_columns = set()

    for index in indexes:
        if index.get("unique") is True:
            unique_columns.update(index.get("column_names", []))

    assert "username" in unique_columns
    assert "email" in unique_columns


def test_users_security_defaults():
    """
    Verify security-related default values on the users table.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]: column
        for column in inspector.get_columns("users")
    }

    assert columns["role"]["default"] is not None
    assert "user" in columns["role"]["default"]

    assert columns["is_active"]["default"] is not None
    assert "true" in columns["is_active"]["default"].lower()

    assert columns["is_verified"]["default"] is not None
    assert "false" in columns["is_verified"]["default"].lower()

    assert columns["token_version"]["default"] is not None
    assert "0" in columns["token_version"]["default"]


# ============================================================================
# ITEMS TABLE
# ============================================================================


def test_items_table_contains_required_columns():
    """
    Verify that the items table contains all required lost-and-found
    item fields.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]
        for column in inspector.get_columns("items")
    }

    required_columns = {
        "id",
        "user_id",
        "title",
        "description",
        "type",
        "category",
        "location",
        "image",
        "status",
        "created_at",
        "updated_at",
    }

    assert required_columns.issubset(columns)


def test_items_status_has_pending_default():
    """
    Verify that newly created items default to pending moderation.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]: column
        for column in inspector.get_columns("items")
    }

    status_default = columns["status"]["default"]

    assert status_default is not None
    assert "pending" in status_default


# ============================================================================
# AUTHENTICATION TOKENS
# ============================================================================


def test_auth_tokens_table_contains_required_columns():
    """
    Verify that the authentication-token table contains the fields
    required for secure verification and password-reset flows.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]
        for column in inspector.get_columns("auth_tokens")
    }

    required_columns = {
        "id",
        "user_id",
        "token_hash",
        "token_type",
        "expires_at",
        "created_at",
        "used_at",
    }

    assert required_columns.issubset(columns)


def test_auth_tokens_hash_is_unique():
    """
    Verify that token hashes are unique at the database level.

    Raw authentication tokens are never stored. Only their hashes
    are persisted.
    """

    inspector = inspect(engine)

    indexes = inspector.get_indexes("auth_tokens")

    token_hash_unique = any(
        index.get("unique") is True
        and "token_hash" in index.get("column_names", [])
        for index in indexes
    )

    assert token_hash_unique


# ============================================================================
# FOREIGN KEYS
# ============================================================================


def test_required_foreign_keys_exist():
    """
    Verify that items.user_id and auth_tokens.user_id reference users.id.
    """

    inspector = inspect(engine)

    # ------------------------------------------------------------------
    # Items
    # ------------------------------------------------------------------

    item_foreign_keys = inspector.get_foreign_keys("items")

    item_fk_exists = any(
        foreign_key["referred_table"] == "users"
        and "user_id" in foreign_key["constrained_columns"]
        and "id" in foreign_key["referred_columns"]
        for foreign_key in item_foreign_keys
    )

    assert item_fk_exists, (
        "items.user_id must reference users.id"
    )

    # ------------------------------------------------------------------
    # Authentication tokens
    # ------------------------------------------------------------------

    auth_token_foreign_keys = inspector.get_foreign_keys(
        "auth_tokens"
    )

    auth_token_fk_exists = any(
        foreign_key["referred_table"] == "users"
        and "user_id" in foreign_key["constrained_columns"]
        and "id" in foreign_key["referred_columns"]
        for foreign_key in auth_token_foreign_keys
    )

    assert auth_token_fk_exists, (
        "auth_tokens.user_id must reference users.id"
    )


# ============================================================================
# CASCADE DELETE
# ============================================================================


def test_required_cascade_delete_relationships_exist():
    """
    Verify that deleting a user cascades to dependent records.

    Required TRACKIT relationships:

        users -> items
        users -> auth_tokens

    Both relationships must use:

        ON DELETE CASCADE

    This test uses PostgreSQL's system catalog instead of indexing
    SQLAlchemy's typed Inspector dictionary, avoiding TypedDict issues.
    """

    with engine.connect() as connection:

        result = connection.execute(
            text(
                """
                SELECT
                    conrelid::regclass AS table_name,
                    pg_get_constraintdef(oid) AS constraint_definition
                FROM pg_constraint
                WHERE contype = 'f'
                  AND conrelid::regclass::text IN (
                      'items',
                      'auth_tokens'
                  )
                  AND confrelid::regclass::text = 'users'
                """
            )
        )

        constraints = result.fetchall()

    assert constraints, (
        "No foreign-key constraints from items/auth_tokens to users were found."
    )

    item_cascade = False
    auth_token_cascade = False

    for table_name, constraint_definition in constraints:

        definition = str(constraint_definition).upper()

        if table_name == "items":
            if "ON DELETE CASCADE" in definition:
                item_cascade = True

        if table_name == "auth_tokens":
            if "ON DELETE CASCADE" in definition:
                auth_token_cascade = True

    assert item_cascade, (
        "items.user_id must use ON DELETE CASCADE."
    )

    assert auth_token_cascade, (
        "auth_tokens.user_id must use ON DELETE CASCADE."
    )


# ============================================================================
# ALEMBIC MIGRATION STATE
# ============================================================================


def test_alembic_migrations_are_current():
    """
    Verify that the database has an Alembic migration revision.

    The exact revision is intentionally checked against the current
    migration head so this test catches an out-of-date database.
    """

    with engine.connect() as connection:

        result = connection.execute(
            text(
                """
                SELECT version_num
                FROM alembic_version
                """
            )
        )

        rows = result.fetchall()

    assert len(rows) == 1

    current_revision = rows[0][0]

    assert current_revision == "102fb0f3321c"