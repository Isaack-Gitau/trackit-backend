"""
TRACKIT Health API Integration Tests.

Tests the publicly accessible system health endpoint.
"""

from fastapi.testclient import TestClient

from app.core.config import settings


# ============================================================================
# HEALTH CHECK
# ============================================================================


def test_health_check(client: TestClient):
    """
    The health endpoint should confirm that the TRACKIT API is alive.
    """

    response = client.get("/api/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ok"
    assert data["service"] == settings.APP_NAME
    assert "timestamp" in data


# ============================================================================
# ROOT ENDPOINT
# ============================================================================


def test_root_endpoint(client: TestClient):
    """
    The API root should report that TRACKIT is online.
    """

    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["service"] == settings.APP_NAME
    assert data["status"] == "online"