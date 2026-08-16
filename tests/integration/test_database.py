"""
TRACKIT Database Integration Tests.

These tests verify the production PostgreSQL schema used by TRACKIT.

Coverage:

- Database connectivity
- Database identity
- Required tables
- Required columns
- Security-related user fields
- Item schema
- Authentication-token schema
- Audit-log schema
- Foreign keys
- ON DELETE behavior
- Database defaults
- Unique constraints
- Alembic migration state

These tests intentionally inspect the PostgreSQL database directly.
They do not create or modify application data.
"""

from pathlib import Path

from sqlalchemy import inspect, text

from app.db.session import engine


# ============================================================================
# DATABASE CONNECTION
# ============================================================================


def test_database_connection():
    """
    Verify that TRACKIT connects to the expected PostgreSQL
    database using the expected application database role.
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
    Verify that all required TRACKIT database tables exist.
    """

    inspector = inspect(engine)

    tables = set(
        inspector.get_table_names()
    )

    required_tables = {
        "users",
        "items",
        "auth_tokens",
        "audit_logs",
    }

    assert required_tables.issubset(tables)


# ============================================================================
# USERS TABLE
# ============================================================================


def test_users_table_contains_required_columns():
    """
    Verify the complete security-sensitive users schema.
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
    Username and email must be unique at the database level.
    """

    inspector = inspect(engine)

    indexes = inspector.get_indexes("users")

    unique_columns = set()

    for index in indexes:
        if index.get("unique") is True:
            unique_columns.update(
                index.get("column_names", [])
            )

    assert "username" in unique_columns
    assert "email" in unique_columns


def test_users_security_defaults():
    """
    Verify security-related database defaults.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]: column
        for column in inspector.get_columns("users")
    }

    assert columns["role"]["default"] is not None
    assert "user" in str(
        columns["role"]["default"]
    ).lower()

    assert columns["is_active"]["default"] is not None
    assert "true" in str(
        columns["is_active"]["default"]
    ).lower()

    assert columns["is_verified"]["default"] is not None
    assert "false" in str(
        columns["is_verified"]["default"]
    ).lower()

    assert columns["token_version"]["default"] is not None
    assert "0" in str(
        columns["token_version"]["default"]
    )


# ============================================================================
# ITEMS TABLE
# ============================================================================


def test_items_table_contains_required_columns():
    """
    Verify the complete lost-and-found item schema.
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
    New items must default to pending moderation.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]: column
        for column in inspector.get_columns("items")
    }

    status_default = columns["status"]["default"]

    assert status_default is not None
    assert "pending" in str(
        status_default
    ).lower()


# ============================================================================
# AUTHENTICATION TOKENS
# ============================================================================


def test_auth_tokens_table_contains_required_columns():
    """
    Verify the authentication-token schema.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]
        for column in inspector.get_columns(
            "auth_tokens"
        )
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
    Token hashes must be unique at the database level.

    TRACKIT never stores raw authentication tokens.
    """

    inspector = inspect(engine)

    indexes = inspect(
        engine
    ).get_indexes("auth_tokens")

    token_hash_unique = any(
        index.get("unique") is True
        and "token_hash"
        in index.get("column_names", [])
        for index in indexes
    )

    assert token_hash_unique


# ============================================================================
# AUDIT LOGS
# ============================================================================


def test_audit_logs_table_contains_required_columns():
    """
    Verify the TRACKIT audit-log schema.

    Audit logs intentionally use the event-oriented design:

        event_type
        success
        description
        user_id
        ip_address
        user_agent
        created_at

    These are the fields actually represented by the
    AuditLog SQLAlchemy model.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]
        for column in inspector.get_columns(
            "audit_logs"
        )
    }

    required_columns = {
        "id",
        "event_type",
        "success",
        "description",
        "user_id",
        "ip_address",
        "user_agent",
        "created_at",
    }

    assert required_columns.issubset(columns)


def test_audit_logs_success_has_true_default():
    """
    Audit events should default to successful unless explicitly
    recorded otherwise.

    This must be a PostgreSQL server-side default, not merely
    a Python/SQLAlchemy default.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]: column
        for column in inspector.get_columns(
            "audit_logs"
        )
    }

    success_default = columns["success"]["default"]

    assert success_default is not None

    normalized_default = str(
        success_default
    ).lower()

    assert (
        "true" in normalized_default
        or "1" in normalized_default
    )


def test_audit_logs_user_id_is_nullable():
    """
    Audit records must remain after account deletion.

    The user association is therefore nullable so that
    PostgreSQL can apply ON DELETE SET NULL.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]: column
        for column in inspector.get_columns(
            "audit_logs"
        )
    }

    assert columns["user_id"]["nullable"] is True


# ============================================================================
# FOREIGN KEYS
# ============================================================================


def test_items_user_foreign_key_exists():
    """
    items.user_id must reference users.id.
    """

    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys(
        "items"
    )

    exists = any(
        fk["referred_table"] == "users"
        and "user_id" in fk["constrained_columns"]
        and "id" in fk["referred_columns"]
        for fk in foreign_keys
    )

    assert exists


def test_auth_tokens_user_foreign_key_exists():
    """
    auth_tokens.user_id must reference users.id.
    """

    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys(
        "auth_tokens"
    )

    exists = any(
        fk["referred_table"] == "users"
        and "user_id" in fk["constrained_columns"]
        and "id" in fk["referred_columns"]
        for fk in foreign_keys
    )

    assert exists


def test_audit_logs_user_foreign_key_exists():
    """
    audit_logs.user_id must reference users.id.
    """

    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys(
        "audit_logs"
    )

    exists = any(
        fk["referred_table"] == "users"
        and "user_id" in fk["constrained_columns"]
        and "id" in fk["referred_columns"]
        for fk in foreign_keys
    )

    assert exists


# ============================================================================
# FOREIGN KEY DELETE BEHAVIOR
# ============================================================================


def test_items_user_foreign_key_cascades_on_delete():
    """
    Deleting a user must cascade to their item records.
    """

    with engine.connect() as connection:
        result = connection.execute(
            text(
                """
                SELECT pg_get_constraintdef(oid)
                FROM pg_constraint
                WHERE contype = 'f'
                  AND conrelid = 'items'::regclass
                  AND confrelid = 'users'::regclass
                """
            )
        )

        definitions = [
            str(row[0]).upper()
            for row in result.fetchall()
        ]

    assert definitions

    assert any(
        "ON DELETE CASCADE" in definition
        for definition in definitions
    )


def test_auth_tokens_user_foreign_key_cascades_on_delete():
    """
    Deleting a user must cascade to authentication tokens.
    """

    with engine.connect() as connection:
        result = connection.execute(
            text(
                """
                SELECT pg_get_constraintdef(oid)
                FROM pg_constraint
                WHERE contype = 'f'
                  AND conrelid = 'auth_tokens'::regclass
                  AND confrelid = 'users'::regclass
                """
            )
        )

        definitions = [
            str(row[0]).upper()
            for row in result.fetchall()
        ]

    assert definitions

    assert any(
        "ON DELETE CASCADE" in definition
        for definition in definitions
    )


def test_audit_logs_user_foreign_key_sets_null_on_delete():
    """
    Audit history must survive user deletion.

    Therefore audit_logs.user_id uses ON DELETE SET NULL.
    """

    with engine.connect() as connection:
        result = connection.execute(
            text(
                """
                SELECT pg_get_constraintdef(oid)
                FROM pg_constraint
                WHERE contype = 'f'
                  AND conrelid = 'audit_logs'::regclass
                  AND confrelid = 'users'::regclass
                """
            )
        )

        definitions = [
            str(row[0]).upper()
            for row in result.fetchall()
        ]

    assert definitions

    assert any(
        "ON DELETE SET NULL" in definition
        for definition in definitions
    )


# ============================================================================
# ALEMBIC
# ============================================================================


def get_repository_head() -> str:
    """
    Determine the current Alembic repository head.

    This reads the migration files instead of hard-coding
    a specific revision ID into the tests.
    """

    versions_directory = (
        Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
    )

    revisions = {}

    for migration_file in versions_directory.glob(
        "*.py"
    ):
        if migration_file.name == "__init__.py":
            continue

        source = migration_file.read_text(
            encoding="utf-8"
        )

        revision = None
        down_revision = None

        for line in source.splitlines():
            stripped = line.strip()

            if stripped.startswith(
                "revision ="
            ):
                revision = stripped.split(
                    "=", 1
                )[1].strip().strip(
                    "\"'"
                )

            elif stripped.startswith(
                "down_revision ="
            ):
                value = stripped.split(
                    "=", 1
                )[1].strip()

                if value in {
                    "None",
                    "None,",
                }:
                    down_revision = None
                else:
                    down_revision = (
                        value.strip(
                            "\"'"
                        )
                    )

        if revision:
            revisions[revision] = (
                down_revision
            )

    assert revisions, (
        "No Alembic migration revisions found."
    )

    referenced_revisions = {
        revision
        for revision in revisions.values()
        if revision is not None
    }

    heads = set(revisions) - referenced_revisions

    assert len(heads) == 1, (
        "TRACKIT must have exactly one Alembic head. "
        f"Found: {heads}"
    )

    return heads.pop()


def test_alembic_migration_is_at_head():
    """
    Verify that PostgreSQL is running the current
    Alembic repository head.
    """

    expected_head = get_repository_head()

    with engine.connect() as connection:
        result = connection.execute(
            text(
                """
                SELECT version_num
                FROM alembic_version
                """
            )
        )

        versions = {
            str(row[0])
            for row in result.fetchall()
        }

    assert versions == {
        expected_head
    }, (
        "TRACKIT database migration state does not "
        "match the current Alembic repository head. "
        f"Expected: {expected_head}; "
        f"Found: {versions}"
    )