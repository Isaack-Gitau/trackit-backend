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
       ├── /api/claims/...
       │
       ├── /api/reports/...
       │
       ├── /api/notifications/...
       │
       ├── /api/profile/...
       │
       ├── /api/matches/...
       │
       ├── /auth/...
       │
       └── /
"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.core.config import settings
from app.middleware.security import configure_security_middleware
from app.routers.api import router as api_router
from app.routers.auth import router as auth_router
from app.routers.claims import router as claims_router
from app.routers.comments import router as comments_router
from app.routers.items import router as items_router
from app.routers.matches import router as matches_router
from app.routers.notifications import router as notifications_router
from app.routers.profile import router as profile_router
from app.routers.reports import router as reports_router



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
# MEDIA FILES
# ============================================================================

# Uploaded item images and profile pictures are stored beneath the
# configured media root. The image utility is responsible for validating
# and sanitizing uploaded files before they reach this directory.
app.mount(
    settings.MEDIA_URL.rstrip("/"),
    StaticFiles(
        directory=settings.MEDIA_ROOT,
    ),
    name="media",
)


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
# CLAIM API
# ============================================================================

app.include_router(
    claims_router,
    prefix="/api",
)

# ============================================================================
# COMMENT API
# ============================================================================

app.include_router(
    comments_router,
    prefix="/api",
)


# ============================================================================
# REPORT API
# ============================================================================

app.include_router(
    reports_router,
    prefix="/api",
)


# ============================================================================
# NOTIFICATION API
# ============================================================================

app.include_router(
    notifications_router,
    prefix="/api",
)


# ============================================================================
# PROFILE API
# ============================================================================

app.include_router(
    profile_router,
    prefix="/api",
)


# ============================================================================
# MATCH API
# ============================================================================

app.include_router(
    matches_router,
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