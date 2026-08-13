"""
TRACKIT Database Session Management.

Provides the SQLAlchemy engine and session factory.

Database request dependencies are defined in:
    app.db.dependencies
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings


# =============================================================================
# DATABASE ENGINE
# =============================================================================

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
)


# =============================================================================
# SESSION FACTORY
# =============================================================================

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)