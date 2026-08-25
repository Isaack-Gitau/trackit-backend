
"""
TRACKIT Alembic Environment Configuration.

This module configures Alembic for TRACKIT database migrations.

Responsibilities:

- Load TRACKIT application database settings.
- Register every SQLAlchemy model with Base.metadata.
- Support offline migrations.
- Support online migrations.
- Compare SQLAlchemy model types against the database schema.
- Compare server defaults against the database schema.

Important:

Alembic must know about every TRACKIT model before autogenerate
is executed. Importing all models below ensures that their tables
are registered in Base.metadata.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import settings
from app.db.base import Base

# ============================================================================
# MODEL REGISTRATION
# ============================================================================
#
# Import every database model here.
#
# These imports are intentionally explicit. Alembic's autogenerate feature
# compares Base.metadata against the current database schema. If a model
# has not been imported, its table will not exist in Base.metadata and
# Alembic cannot detect it.
#
# Keep this list synchronized with app/models/__init__.py.
#

from app.models import (
    User,
    Item,
    AuthToken,
    Claim,
    AuditLog,
    Report,
    Notification,
)


# ============================================================================
# ALEMBIC CONFIGURATION
# ============================================================================

config = context.config


# ============================================================================
# LOGGING
# ============================================================================

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


# ============================================================================
# SQLALCHEMY METADATA
# ============================================================================

target_metadata = Base.metadata


# ============================================================================
# DATABASE URL
# ============================================================================

def get_database_url() -> str:
    """
    Return the database URL used by TRACKIT.

    The application settings are the single source of truth for
    the database connection rather than relying on a hard-coded
    URL inside alembic.ini.
    """

    return settings.DATABASE_URL


# ============================================================================
# OFFLINE MIGRATIONS
# ============================================================================

def run_migrations_offline() -> None:
    """
    Run migrations without establishing a live database connection.

    Alembic generates SQL statements using the configured database URL.
    This mode is useful for reviewing or exporting migration SQL.
    """

    database_url = get_database_url()

    context.configure(
        url=database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={
            "paramstyle": "named",
        },
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ============================================================================
# ONLINE MIGRATIONS
# ============================================================================

def run_migrations_online() -> None:
    """
    Run migrations using a live database connection.

    Alembic obtains the database connection from TRACKIT's application
    configuration and executes migrations transactionally.
    """

    database_url = get_database_url()

    # Keep alembic.ini's general engine configuration while explicitly
    # overriding the database URL with TRACKIT's application setting.
    config.set_main_option(
        "sqlalchemy.url",
        database_url,
    )

    configuration = config.get_section(
        config.config_ini_section,
    )

    if configuration is None:
        raise RuntimeError(
            "Alembic SQLAlchemy configuration section could not be loaded."
        )

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


# ============================================================================
# ENTRY POINT
# ============================================================================

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
