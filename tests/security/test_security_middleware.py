
"""
TRACKIT Security Middleware Tests.

Tests:

- Security response headers
- Trusted host protection
- CORS policy
- CORS rejection of unauthorized origins
- Authorization header support
- Retry-After exposure on actual rate-limit responses
"""

from fastapi.testclient import TestClient


# ============================================================================
# SECURITY HEADERS
# ============================================================================


def test_security_headers_are_present(
    client: TestClient,
):
    """
    TRACKIT responses should contain the configured
    defensive security headers.
    """

    response = client.get("/")

    assert response.status_code == 200

    headers = response.headers

    assert (
        headers["X-Content-Type-Options"]
        == "nosniff"
    )

    assert (
        headers["X-Frame-Options"]
        == "DENY"
    )

    assert (
        headers["Referrer-Policy"]
        == "strict-origin-when-cross-origin"
    )

    assert (
        headers["Permissions-Policy"]
        == (
            "camera=(), "
            "microphone=(), "
            "geolocation=()"
        )
    )

    assert (
        headers["Content-Security-Policy"]
         == (
             "default-src 'self'; "
             "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
             "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
             "img-src 'self' data: https://fastapi.tiangolo.com https://res.cloudinary.com; "
             "connect-src 'self'; "
             "frame-ancestors 'none'; "
             "base-uri 'self'; "
             "form-action 'self'"
        )
    )




# ============================================================================
# SECURITY HEADERS ON API RESPONSES
# ============================================================================


def test_security_headers_are_present_on_api_response(
    client: TestClient,
):
    """
    Security headers should also be applied to API responses,
    not only the root endpoint.
    """

    response = client.get("/api/health")

    assert response.status_code == 200

    assert (
        response.headers["X-Content-Type-Options"]
        == "nosniff"
    )

    assert (
        response.headers["X-Frame-Options"]
        == "DENY"
    )


# ============================================================================
# TRUSTED HOST
# ============================================================================


def test_trusted_host_allows_testserver(
    client: TestClient,
):
    """
    The test environment should allow the TestClient host.
    """

    response = client.get(
        "/",
        headers={
            "Host": "testserver",
        },
    )

    assert response.status_code == 200


def test_trusted_host_rejects_unknown_host(
    client: TestClient,
):
    """
    Requests using an untrusted Host header should be rejected.
    """

    response = client.get(
        "/",
        headers={
            "Host": "malicious.example",
        },
    )

    assert response.status_code == 400


# ============================================================================
# CORS
# ============================================================================


def test_cors_allows_configured_frontend_origin(
    client: TestClient,
):
    """
    The configured TRACKIT frontend origin should receive
    the appropriate CORS response headers.
    """

    response = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200

    assert (
        response.headers["access-control-allow-origin"]
        == "http://localhost:5173"
    )

    assert (
        response.headers["access-control-allow-credentials"]
        == "true"
    )


def test_cors_rejects_untrusted_origin(
    client: TestClient,
):
    """
    An unauthorized frontend origin should not be granted
    CORS access.
    """

    response = client.options(
        "/api/health",
        headers={
            "Origin": "https://malicious.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 400


# ============================================================================
# CORS AUTHORIZATION HEADER
# ============================================================================


def test_cors_allows_authorization_header(
    client: TestClient,
):
    """
    TRACKIT's CORS configuration should allow the Authorization
    header required for Bearer JWT authentication.
    """

    response = client.options(
        "/api/auth/me",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )

    assert response.status_code == 200

    allowed_headers = (
        response.headers
        .get(
            "access-control-allow-headers",
            "",
        )
        .lower()
    )

    assert "authorization" in allowed_headers


# ============================================================================
# RATE-LIMIT RESPONSE
# ============================================================================


def test_rate_limit_response_exposes_retry_after_header(
    client: TestClient,
):
    """
    A rate-limit response should expose Retry-After to the
    configured frontend origin.

    This test intentionally exhausts the login rate limit,
    then verifies the actual HTTP 429 response.
    """

    origin = "http://localhost:5173"

    login_payload = {
        "identifier": "middleware-test@example.com",
        "password": "WrongPassword1!",
    }

    # ------------------------------------------------------------------------
    # Exhaust the configured login rate limit.
    # ------------------------------------------------------------------------

    for _ in range(5):
        response = client.post(
            "/api/auth/login",
            json=login_payload,
            headers={
                "Origin": origin,
            },
        )

        assert response.status_code in {
            401,
            429,
        }

    # ------------------------------------------------------------------------
    # The next request must be rate limited.
    # ------------------------------------------------------------------------

    response = client.post(
        "/api/auth/login",
        json=login_payload,
        headers={
            "Origin": origin,
        },
    )

    assert response.status_code == 429

    # ------------------------------------------------------------------------
    # Retry-After must be returned.
    # ------------------------------------------------------------------------

    assert "retry-after" in response.headers

    assert (
        int(response.headers["retry-after"])
        > 0
    )

    # ------------------------------------------------------------------------
    # The frontend must be allowed to read Retry-After.
    # ------------------------------------------------------------------------

    exposed_headers = (
        response.headers
        .get(
            "access-control-expose-headers",
            "",
        )
        .lower()
    )

    assert "retry-after" in exposed_headers

