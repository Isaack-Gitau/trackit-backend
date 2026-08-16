
"""
TRACKIT System API Router.

Contains system-level API endpoints that are independent
of specific application resources.

Current endpoints:

    GET /api/health
"""

from datetime import datetime, timezone

from fastapi import APIRouter

from app.core.config import settings


# ============================================================================
# ROUTER
# ============================================================================

router = APIRouter(
    prefix="/api",
    tags=["System"],
)


# ============================================================================
# HEALTH CHECK
# ============================================================================


@router.get(
    "/health",
    summary="Health check",
)
def health_check() -> dict:
    """
    Basic TRACKIT API health check.

    This endpoint does not require authentication so that
    infrastructure and deployment systems can verify that
    the API process is alive.
    """

    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

