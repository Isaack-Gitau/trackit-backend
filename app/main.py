from fastapi import FastAPI

from app.core.config import settings
from app.routers.api import router as api_router
from app.routers.auth import router as auth_router


app = FastAPI(
    title=settings.APP_NAME,
    description="TRACKIT - Lost and Found System API",
    version="1.0.0",
)


# ============================================================================
# Routers
# ============================================================================

app.include_router(api_router)
app.include_router(auth_router)


# ============================================================================
# Root endpoint
# ============================================================================

@app.get(
    "/",
    tags=["System"],
)
def root() -> dict:
    """
    TRACKIT API root endpoint.
    """

    return {
        "service": settings.APP_NAME,
        "status": "online",
    }