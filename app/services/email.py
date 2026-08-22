"""
TRACKIT Email Service.

Handles transactional emails for:

- Email verification
- Password reset

Uses SMTP through aiosmtplib.

Security principles:

- Raw authentication tokens are never stored in PostgreSQL.
- Tokens are included only in transactional email links.
- SMTP credentials come exclusively from application settings.
- Credentials and tokens are never logged by this service.
- Both HTML and plain-text email versions are provided.
"""

from __future__ import annotations

from email.message import EmailMessage
from html import escape
from urllib.parse import quote

from aiosmtplib import SMTP

from app.core.config import settings


# ============================================================================
# SMTP
# ============================================================================


async def _send_email(
    *,
    recipient: str,
    subject: str,
    html_body: str,
    text_body: str,
) -> None:
    """
    Send a transactional email through the configured SMTP server.

    Raises:
        ValueError:
            When the recipient is empty.

        Exception:
            When SMTP connection, authentication, or delivery fails.
    """

    if not recipient or not recipient.strip():
        raise ValueError(
            "Recipient email cannot be empty."
        )

    message = EmailMessage()

    message["From"] = (
        f"{settings.SMTP_FROM_NAME} "
        f"<{settings.SMTP_FROM_EMAIL}>"
    )

    message["To"] = recipient.strip()
    message["Subject"] = subject

    # Plain-text fallback
    message.set_content(text_body)

    # HTML version
    message.add_alternative(
        html_body,
        subtype="html",
    )

    smtp = SMTP(
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        start_tls=settings.SMTP_USE_TLS,
    )

    try:
        await smtp.connect()

        await smtp.login(
            settings.SMTP_USERNAME,
            settings.SMTP_PASSWORD,
        )

        await smtp.send_message(message)

    finally:
        if smtp.is_connected:
            await smtp.quit()


# ============================================================================
# EMAIL VERIFICATION
# ============================================================================


async def send_verification_email(
    *,
    recipient: str,
    token: str,
) -> None:
    """
    Send an email verification message.

    The raw token is placed inside the verification URL.

    The token itself is never logged by this service.
    """

    if not token:
        raise ValueError(
            "Verification token cannot be empty."
        )

    encoded_token = quote(
        token,
        safe="",
    )

    verification_url = (
        f"{settings.FRONTEND_URL.rstrip('/')}"
        f"/verify-email?token={encoded_token}"
    )

    safe_url = escape(
        verification_url,
        quote=True,
    )

    html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify your TRACKIT account</title>
</head>

<body style="
    margin:0;
    padding:0;
    background:#f8fafc;
    font-family:Arial,Helvetica,sans-serif;
    color:#0f172a;
">

    <div style="
        max-width:600px;
        margin:40px auto;
        background:#ffffff;
        border-radius:12px;
        padding:40px;
        box-shadow:0 4px 20px rgba(15,23,42,0.08);
    ">

        <h1 style="
            margin-top:0;
            color:#4f46e5;
            font-size:28px;
        ">
            Welcome to TRACKIT
        </h1>

        <p style="font-size:16px;line-height:1.6;">
            Thank you for creating your TRACKIT account.
        </p>

        <p style="font-size:16px;line-height:1.6;">
            Please verify your email address by clicking
            the button below.
        </p>

        <p style="margin:30px 0;">
            <a
                href="{safe_url}"
                style="
                    display:inline-block;
                    padding:14px 24px;
                    background:#4f46e5;
                    color:#ffffff;
                    text-decoration:none;
                    border-radius:8px;
                    font-weight:bold;
                "
            >
                Verify my email
            </a>
        </p>

        <p style="
            font-size:14px;
            line-height:1.6;
            color:#64748b;
        ">
            This verification link expires in 30 minutes.
        </p>

        <p style="
            font-size:14px;
            line-height:1.6;
            color:#64748b;
        ">
            If the button does not work, copy and paste the
            following link into your browser:
        </p>

        <p style="
            font-size:13px;
            line-height:1.5;
            word-break:break-all;
            color:#475569;
        ">
            {safe_url}
        </p>

        <hr style="
            border:none;
            border-top:1px solid #e2e8f0;
            margin:30px 0;
        ">

        <p style="
            font-size:13px;
            color:#64748b;
        ">
            If you did not create a TRACKIT account,
            you can safely ignore this email.
        </p>

        <p style="
            font-size:14px;
            color:#475569;
        ">
            — TRACKIT
        </p>

    </div>

</body>
</html>
"""

    text_body = f"""
Welcome to TRACKIT.

Thank you for creating your TRACKIT account.

Please verify your email address using the link below:

{verification_url}

This verification link expires in 30 minutes.

If you did not create a TRACKIT account,
you can safely ignore this email.

— TRACKIT
"""

    await _send_email(
        recipient=recipient,
        subject="Verify your TRACKIT email address",
        html_body=html_body,
        text_body=text_body,
    )


# ============================================================================
# PASSWORD RESET
# ============================================================================


async def send_password_reset_email(
    *,
    recipient: str,
    token: str,
) -> None:
    """
    Send a password-reset email.

    The raw token is placed inside the password-reset URL.

    The token itself is never logged by this service.
    """

    if not token:
        raise ValueError(
            "Password-reset token cannot be empty."
        )

    encoded_token = quote(
        token,
        safe="",
    )

    reset_url = (
        f"{settings.FRONTEND_URL.rstrip('/')}"
        f"/reset-password?token={encoded_token}"
    )

    safe_url = escape(
        reset_url,
        quote=True,
    )

    html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset your TRACKIT password</title>
</head>

<body style="
    margin:0;
    padding:0;
    background:#f8fafc;
    font-family:Arial,Helvetica,sans-serif;
    color:#0f172a;
">

    <div style="
        max-width:600px;
        margin:40px auto;
        background:#ffffff;
        border-radius:12px;
        padding:40px;
        box-shadow:0 4px 20px rgba(15,23,42,0.08);
    ">

        <h1 style="
            margin-top:0;
            color:#4f46e5;
            font-size:28px;
        ">
            Password Reset
        </h1>

        <p style="font-size:16px;line-height:1.6;">
            We received a request to reset your TRACKIT password.
        </p>

        <p style="font-size:16px;line-height:1.6;">
            Click the button below to choose a new password.
        </p>

        <p style="margin:30px 0;">
            <a
                href="{safe_url}"
                style="
                    display:inline-block;
                    padding:14px 24px;
                    background:#4f46e5;
                    color:#ffffff;
                    text-decoration:none;
                    border-radius:8px;
                    font-weight:bold;
                "
            >
                Reset my password
            </a>
        </p>

        <p style="
            font-size:14px;
            line-height:1.6;
            color:#64748b;
        ">
            This password-reset link expires in 30 minutes
            and can only be used once.
        </p>

        <p style="
            font-size:14px;
            line-height:1.6;
            color:#64748b;
        ">
            If the button does not work, copy and paste the
            following link into your browser:
        </p>

        <p style="
            font-size:13px;
            line-height:1.5;
            word-break:break-all;
            color:#475569;
        ">
            {safe_url}
        </p>

        <hr style="
            border:none;
            border-top:1px solid #e2e8f0;
            margin:30px 0;
        ">

        <p style="
            font-size:13px;
            color:#64748b;
        ">
            If you did not request a password reset,
            you can safely ignore this email.
            Your password will remain unchanged.
        </p>

        <p style="
            font-size:14px;
            color:#475569;
        ">
            — TRACKIT
        </p>

    </div>

</body>
</html>
"""

    text_body = f"""
TRACKIT Password Reset

We received a request to reset your TRACKIT password.

Use the link below to choose a new password:

{reset_url}

This password-reset link expires in 30 minutes
and can only be used once.

If you did not request a password reset,
you can safely ignore this email.
Your password will remain unchanged.

— TRACKIT
"""

    await _send_email(
        recipient=recipient,
        subject="Reset your TRACKIT password",
        html_body=html_body,
        text_body=text_body,
    )