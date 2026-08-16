"""
TRACKIT FastAPI Application.

Main application entry point.

Router architecture:

    FastAPI
       │
       ├── Global Security Middleware
       │
       ├── /api/health
       │
       ├── /api/items
       │
       ├── /api/items/me/items
       │
       ├── /api/items/{item_id}
       │
       ├── /api/auth/...
       │
       └── /
"""

from fastapi import FastAPI

from app.core.config import settings
from app.middleware.security import configure_security_middleware
from app.routers.api import router as api_router
from app.routers.auth import router as auth_router
from app.routers.items import router as items_router


# ============================================================================
# APPLICATION
# ============================================================================

app = FastAPI(
    title=settings.APP_NAME,
    description="TRACKIT - Lost and Found System API",
    version="1.0.0",
    debug=settings.DEBUG,
)


# ============================================================================
# GLOBAL SECURITY MIDDLEWARE
# ============================================================================

configure_security_middleware(app)


# ============================================================================
# SYSTEM API
# ============================================================================

app.include_router(
    api_router,
)


# ============================================================================
# ITEM API
# ============================================================================

app.include_router(
    items_router,
    prefix="/api",
)


# ============================================================================
# AUTHENTICATION API
# ============================================================================

app.include_router(
    auth_router,
)


# ============================================================================
# ROOT ENDPOINT
# ============================================================================


@app.get(
    "/",
    tags=["System"],
    summary="TRACKIT API root",
)
def root() -> dict:
    """
    Return basic information about the running TRACKIT API.
    """

    return {
        "service": settings.APP_NAME,
        "status": "online",
    }