
"""
TRACKIT Database Integration Tests.

These tests verify the PostgreSQL schema used by TRACKIT.

Coverage
--------
- Database connectivity
- Database identity
- Required tables
- Required columns
- Primary keys
- Unique constraints
- Foreign keys
- ON DELETE behavior
- Database server defaults
- Required indexes
- Alembic migration state

These tests inspect the database schema directly.

They do not create, modify, or delete application records.
"""


from sqlalchemy import inspect, text

from app.db.session import engine


# ============================================================================
# EXPECTED DATABASE CONFIGURATION
# ============================================================================

EXPECTED_DATABASE = "trackit_db"
EXPECTED_DATABASE_USER = "trackit_app"
EXPECTED_ALEMBIC_HEAD = "20467d589245"


# ============================================================================
# DATABASE CONNECTION
# ============================================================================


def test_database_connection():
    """
    Verify that TRACKIT can connect to PostgreSQL using the
    configured application database connection.
    """

    with engine.connect() as connection:
        result = connection.execute(
            text(
                """
                SELECT current_database(), current_user
                """
            )
        )

        database, user = result.one()

    assert database == EXPECTED_DATABASE
    assert user == EXPECTED_DATABASE_USER


# ============================================================================
# REQUIRED TABLES
# ============================================================================


def test_required_tables_exist():
    """
    Verify that all required TRACKIT tables exist.
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
        "claims",
    }

    assert required_tables.issubset(tables)


# ============================================================================
# USERS TABLE
# ============================================================================


def test_users_table_contains_required_columns():
    """
    Verify the complete users table schema.
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


def test_users_username_is_unique():
    """
    Username must have a database-level unique constraint/index.
    """

    inspector = inspect(engine)

    unique_columns = set()

    for constraint in inspector.get_unique_constraints("users"):
        unique_columns.update(
            constraint.get("column_names") or []
        )

    for index in inspector.get_indexes("users"):
        if index.get("unique"):
            unique_columns.update(
                index.get("column_names") or []
            )

    assert "username" in unique_columns


def test_users_email_is_unique():
    """
    Email must have a database-level unique constraint/index.
    """

    inspector = inspect(engine)

    unique_columns = set()

    for constraint in inspector.get_unique_constraints("users"):
        unique_columns.update(
            constraint.get("column_names") or []
        )

    for index in inspector.get_indexes("users"):
        if index.get("unique"):
            unique_columns.update(
                index.get("column_names") or []
            )

    assert "email" in unique_columns


def test_users_security_defaults():
    """
    Verify important PostgreSQL defaults on the users table.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]: column
        for column in inspector.get_columns("users")
    }

    assert columns["role"]["default"] is not None
    assert columns["is_active"]["default"] is not None
    assert columns["is_verified"]["default"] is not None
    assert columns["token_version"]["default"] is not None


# ============================================================================
# ITEMS TABLE
# ============================================================================


def test_items_table_contains_required_columns():
    """
    Verify the complete items table schema.
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


def test_items_user_foreign_key_exists():
    """
    Every item must reference its owner.
    """

    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("items")

    user_foreign_key = next(
        (
            fk
            for fk in foreign_keys
            if fk.get("referred_table") == "users"
            and "user_id" in (
                fk.get("constrained_columns") or []
            )
        ),
        None,
    )

    assert user_foreign_key is not None


def test_items_user_foreign_key_has_cascade_delete():
    """
    Deleting a user must delete their items.
    """

    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("items")

    user_foreign_key = next(
        (
            fk
            for fk in foreign_keys
            if fk.get("referred_table") == "users"
            and "user_id" in (
                fk.get("constrained_columns") or []
            )
        ),
        None,
    )

    assert user_foreign_key is not None

    options = user_foreign_key.get("options") or {}

    assert options.get("ondelete") == "CASCADE"


def test_items_status_has_server_default():
    """
    Newly created items should default to pending.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]: column
        for column in inspector.get_columns("items")
    }

    assert columns["status"]["default"] is not None


# ============================================================================
# AUTH TOKENS TABLE
# ============================================================================


def test_auth_tokens_table_contains_required_columns():
    """
    Verify the authentication-token schema.
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
        "used_at",
        "created_at",
    }

    assert required_columns.issubset(columns)


def test_auth_tokens_user_foreign_key_exists():
    """
    Authentication tokens must belong to a user.
    """

    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("auth_tokens")

    user_foreign_key = next(
        (
            fk
            for fk in foreign_keys
            if fk.get("referred_table") == "users"
            and "user_id" in (
                fk.get("constrained_columns") or []
            )
        ),
        None,
    )

    assert user_foreign_key is not None


def test_auth_tokens_user_foreign_key_has_cascade_delete():
    """
    Deleting a user must remove their authentication tokens.
    """

    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("auth_tokens")

    user_foreign_key = next(
        (
            fk
            for fk in foreign_keys
            if fk.get("referred_table") == "users"
            and "user_id" in (
                fk.get("constrained_columns") or []
            )
        ),
        None,
    )

    assert user_foreign_key is not None

    options = user_foreign_key.get("options") or {}

    assert options.get("ondelete") == "CASCADE"


# ============================================================================
# AUDIT LOGS TABLE
# ============================================================================


def test_audit_logs_table_contains_required_columns():
    """
    Verify the actual TRACKIT audit-log schema.

    Audit logs intentionally store event metadata only.
    Authentication secrets must never be stored here.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]
        for column in inspector.get_columns("audit_logs")
    }

    required_columns = {
        "id",
        "action",
        "success",
        "details",
        "resource_type",
        "resource_id",
        "user_id",
        "ip_address",
        "user_agent",
        "created_at",
    }

    assert required_columns.issubset(columns)


def test_audit_logs_user_foreign_key_exists():
    """
    Audit logs may optionally reference the responsible user.
    """

    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("audit_logs")

    user_foreign_key = next(
        (
            fk
            for fk in foreign_keys
            if fk.get("referred_table") == "users"
            and "user_id" in (
                fk.get("constrained_columns") or []
            )
        ),
        None,
    )

    assert user_foreign_key is not None


def test_audit_logs_user_foreign_key_has_set_null_delete():
    """
    Deleting a user must preserve the audit record while
    removing the user reference.
    """

    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("audit_logs")

    user_foreign_key = next(
        (
            fk
            for fk in foreign_keys
            if fk.get("referred_table") == "users"
            and "user_id" in (
                fk.get("constrained_columns") or []
            )
        ),
        None,
    )

    assert user_foreign_key is not None

    options = user_foreign_key.get("options") or {}

    assert options.get("ondelete") == "SET NULL"


def test_audit_logs_success_has_server_default():
    """
    The success field must have a PostgreSQL server default.

    This guarantees that audit records default to successful
    unless explicitly marked otherwise.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]: column
        for column in inspector.get_columns("audit_logs")
    }

    assert columns["success"]["default"] is not None


# ============================================================================
# CLAIMS TABLE
# ============================================================================


def test_claims_table_contains_required_columns():
    """
    Verify the complete claims schema.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]
        for column in inspector.get_columns("claims")
    }

    required_columns = {
        "id",
        "item_id",
        "claimant_id",
        "reason",
        "status",
        "rejection_reason",
        "reviewed_by",
        "reviewed_at",
        "created_at",
        "updated_at",
    }

    assert required_columns.issubset(columns)


def test_claims_status_has_server_default():
    """
    Newly created claims must default to pending.
    """

    inspector = inspect(engine)

    columns = {
        column["name"]: column
        for column in inspector.get_columns("claims")
    }

    assert columns["status"]["default"] is not None


def test_claims_item_foreign_key_has_cascade_delete():
    """
    Deleting an item must delete its associated claims.
    """

    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("claims")

    item_foreign_key = next(
        (
            fk
            for fk in foreign_keys
            if fk.get("referred_table") == "items"
            and "item_id" in (
                fk.get("constrained_columns") or []
            )
        ),
        None,
    )

    assert item_foreign_key is not None

    options = item_foreign_key.get("options") or {}

    assert options.get("ondelete") == "CASCADE"


def test_claims_claimant_foreign_key_has_cascade_delete():
    """
    Deleting a claimant must delete their claims.
    """

    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("claims")

    claimant_foreign_key = next(
        (
            fk
            for fk in foreign_keys
            if fk.get("referred_table") == "users"
            and "claimant_id" in (
                fk.get("constrained_columns") or []
            )
        ),
        None,
    )

    assert claimant_foreign_key is not None

    options = claimant_foreign_key.get("options") or {}

    assert options.get("ondelete") == "CASCADE"


def test_claims_reviewer_foreign_key_has_set_null_delete():
    """
    Deleting a reviewer must preserve the claim while
    removing the reviewer reference.
    """

    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("claims")

    reviewer_foreign_key = next(
        (
            fk
            for fk in foreign_keys
            if fk.get("referred_table") == "users"
            and "reviewed_by" in (
                fk.get("constrained_columns") or []
            )
        ),
        None,
    )

    assert reviewer_foreign_key is not None

    options = reviewer_foreign_key.get("options") or {}

    assert options.get("ondelete") == "SET NULL"


# ============================================================================
# CLAIM INDEXES
# ============================================================================


def test_claims_have_required_indexes():
    """
    Verify indexes required for common claim queries.
    """

    inspector = inspect(engine)

    indexes = inspector.get_indexes("claims")

    index_map = {
        index["name"]: tuple(
            index.get("column_names") or []
        )
        for index in indexes
    }

    assert (
        "ix_claims_item_status" in index_map
    )

    assert index_map["ix_claims_item_status"] == (
        "item_id",
        "status",
    )

    assert (
        "ix_claims_claimant_status" in index_map
    )

    assert index_map["ix_claims_claimant_status"] == (
        "claimant_id",
        "status",
    )


# ============================================================================
# ALEMBIC MIGRATION STATE
# ============================================================================


def test_alembic_version_table_exists():
    """
    Verify that Alembic has initialized its version table.
    """

    inspector = inspect(engine)

    tables = set(
        inspector.get_table_names()
    )

    assert "alembic_version" in tables


def test_alembic_is_at_expected_head():
    """
    Verify that the database is migrated to the expected
    TRACKIT schema revision.
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

        versions = {
            row[0]
            for row in result.fetchall()
        }

    assert versions == {
        EXPECTED_ALEMBIC_HEAD
    }


# ============================================================================
# DATABASE SAFETY CHECKS
# ============================================================================


def test_required_tables_have_primary_keys():
    """
    Every core TRACKIT table must have a primary key.
    """

    inspector = inspect(engine)

    required_tables = {
        "users",
        "items",
        "auth_tokens",
        "audit_logs",
        "claims",
    }

    for table_name in required_tables:
        primary_key = inspector.get_pk_constraint(
            table_name
        )

        assert primary_key["constrained_columns"], (
            f"{table_name} must have a primary key"
        )


def test_claims_status_index_exists():
    """
    Verify that claim status is indexed for moderation
    and filtering queries.
    """

    inspector = inspect(engine)

    indexes = inspector.get_indexes("claims")

    assert any(
        "status" in (
            index.get("column_names") or []
        )
        for index in indexes
    )
