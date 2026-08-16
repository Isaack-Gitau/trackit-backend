
"""
TRACKIT Security Middleware.

Provides global HTTP security protections:

- CORS enforcement
- Trusted-host protection
- Security response headers
- Content Security Policy
- Swagger UI compatibility

Authentication-specific protections such as JWT validation
and authentication rate limiting remain in their respective
modules.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import settings


# ============================================================================
# Configuration Helpers
# ============================================================================


def _parse_csv(value: str) -> list[str]:
    """
    Convert a comma-separated configuration value into
    a normalized list.

    Empty values are ignored.
    """

    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


# ============================================================================
# Security Headers Middleware
# ============================================================================


class SecurityHeadersMiddleware:
    """
    Add security-related HTTP response headers.

    These headers reduce exposure to common browser-based
    attacks such as:

    - clickjacking
    - MIME sniffing
    - unnecessary referrer leakage
    - unwanted browser capabilities
    - unauthorized resource loading
    """

    def __init__(
        self,
        app: Callable,
    ) -> None:
        self.app = app

    async def __call__(
        self,
        scope,
        receive,
        send,
    ):
        if scope["type"] != "http":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                headers = list(
                    message.get("headers", [])
                )

                existing_headers = {
                    key.lower()
                    for key, _ in headers
                }

                security_headers = {
                    # Prevent MIME-type sniffing.
                    b"x-content-type-options": b"nosniff",

                    # Prevent clickjacking.
                    b"x-frame-options": b"DENY",

                    # Restrict referrer information.
                    b"referrer-policy": (
                        settings.REFERRER_POLICY.encode()
                    ),

                    # Restrict browser capabilities.
                    b"permissions-policy": (
                        settings.PERMISSIONS_POLICY.encode()
                    ),

                    # Content Security Policy.
                    b"content-security-policy": (
                        settings.CONTENT_SECURITY_POLICY.encode()
                    ),
                }

                for key, value in security_headers.items():
                    if key not in existing_headers:
                        headers.append(
                            (key, value)
                        )

                message["headers"] = headers

            await send(message)

        await self.app(
            scope,
            receive,
            send_with_security_headers,
        )


# ============================================================================
# Middleware Registration
# ============================================================================


def configure_security_middleware(
    app: FastAPI,
) -> None:
    """
    Configure TRACKIT's global security middleware.

    Middleware order is intentionally controlled here.

    TrustedHostMiddleware:
        Rejects unexpected Host headers.

    CORSMiddleware:
        Restricts browser cross-origin access.

    SecurityHeadersMiddleware:
        Adds defensive HTTP security headers.

    Swagger UI:
        The CSP permits the external resources required by
        FastAPI's default /docs interface.
    """

    trusted_hosts = _parse_csv(
        settings.TRUSTED_HOSTS
    )

    allowed_origins = _parse_csv(
        settings.CORS_ALLOWED_ORIGINS
    )

    # ------------------------------------------------------------------------
    # Trusted Hosts
    # ------------------------------------------------------------------------

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=trusted_hosts,
    )

    # ------------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------------

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=[
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
        ],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Accept",
        ],
        expose_headers=[
            "Retry-After",
        ],
    )

    # ------------------------------------------------------------------------
    # Security Headers
    # ------------------------------------------------------------------------

    if settings.SECURITY_HEADERS_ENABLED:
        app.add_middleware(
            SecurityHeadersMiddleware,
        )

