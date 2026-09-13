"""
TRACKIT Email Service.

Handles transactional emails for:

- Email verification
- Password reset
- Account reactivation
- Administrator custom messages

Uses SMTP through aiosmtplib.

Security principles:

- Raw authentication tokens are never stored in PostgreSQL.
- Tokens are included only in transactional email links.
- SMTP credentials come exclusively from application settings.
- Credentials and tokens are never logged by this service.
- Both HTML and plain-text email versions are provided.
- Administrator message content is HTML-escaped before being
  inserted into HTML email bodies.
"""

from __future__ import annotations

from datetime import datetime
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


# ============================================================================
# ACCOUNT REACTIVATION
# ============================================================================


async def send_account_reactivation_email(
    *,
    recipient: str,
    reactivated_at: datetime,
    reason: str | None = None,
) -> None:
    """
    Send an email notifying a user that their temporary suspension
    has expired and their TRACKIT account has been reactivated.

    The email contains the reactivation timestamp and, when
    available, the reason that was recorded for the suspension.
    """

    if not recipient or not recipient.strip():
        raise ValueError(
            "Recipient email cannot be empty."
        )

    formatted_reactivated_at = reactivated_at.astimezone().strftime(
        "%B %d, %Y at %I:%M %p %Z"
    )

    safe_reactivated_at = escape(
        formatted_reactivated_at
    )

    safe_reason = None

    if reason is not None:
        normalized_reason = reason.strip()

        if normalized_reason:
            safe_reason = escape(
                normalized_reason
            )

    reason_html = ""

    if safe_reason is not None:
        reason_html = f"""
        <p style="font-size:16px;line-height:1.6;">
            <strong>Original suspension reason:</strong><br>
            {safe_reason}
        </p>
        """

    reason_text = ""

    if reason is not None and reason.strip():
        reason_text = (
            "\nOriginal suspension reason:\n"
            f"{reason.strip()}\n"
        )

    html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Your TRACKIT account has been reactivated</title>
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
            Your TRACKIT account has been reactivated
        </h1>

        <p style="font-size:16px;line-height:1.6;">
            Your temporary account suspension has expired.
        </p>

        <p style="font-size:16px;line-height:1.6;">
            Your TRACKIT account is now active again and you
            can sign in normally.
        </p>

        <div style="
            margin:25px 0;
            padding:20px;
            background:#f8fafc;
            border-radius:8px;
        ">
            <p style="
                margin:0;
                font-size:14px;
                color:#64748b;
            ">
                Reactivated
            </p>

            <p style="
                margin:6px 0 0;
                font-size:16px;
                color:#0f172a;
            ">
                {safe_reactivated_at}
            </p>
        </div>

        {reason_html}

        <hr style="
            border:none;
            border-top:1px solid #e2e8f0;
            margin:30px 0;
        ">

        <p style="
            font-size:14px;
            line-height:1.6;
            color:#64748b;
        ">
            If you did not expect your account to be reactivated,
            please contact TRACKIT support.
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
TRACKIT Account Reactivated

Your temporary account suspension has expired.

Your TRACKIT account is now active again and you can sign
in normally.

Reactivated:
{formatted_reactivated_at}
{reason_text}
If you did not expect your account to be reactivated,
please contact TRACKIT support.

— TRACKIT
"""

    await _send_email(
        recipient=recipient,
        subject="Your TRACKIT account has been reactivated",
        html_body=html_body,
        text_body=text_body,
    )


# ============================================================================
# ADMIN CUSTOM EMAIL
# ============================================================================


async def send_admin_custom_email(
    *,
    recipient: str,
    subject: str,
    message: str,
) -> None:
    """
    Send a custom administrator-authored email to one recipient.

    The recipient is supplied by the caller after resolving a
    registered TRACKIT user from the database.

    The message is treated as plain text. It is HTML-escaped
    before being placed into the HTML email body so that
    administrator-authored content cannot inject arbitrary HTML.

    Raises:
        ValueError:
            When the recipient, subject, or message is invalid.

        Exception:
            When SMTP connection, authentication, or delivery fails.
    """

    if not recipient or not recipient.strip():
        raise ValueError(
            "Recipient email cannot be empty."
        )

    if not subject or not subject.strip():
        raise ValueError(
            "Email subject cannot be empty."
        )

    if "\r" in subject or "\n" in subject:
        raise ValueError(
            "Email subject cannot contain newline characters."
        )

    if not message or not message.strip():
        raise ValueError(
            "Email message cannot be empty."
        )

    normalized_recipient = recipient.strip()
    normalized_subject = subject.strip()
    normalized_message = message.strip()

    safe_subject = escape(
        normalized_subject
    )

    safe_message = escape(
        normalized_message
    ).replace(
        "\r\n",
        "<br>",
    ).replace(
        "\n",
        "<br>",
    ).replace(
        "\r",
        "<br>",
    )

    html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{safe_subject}</title>
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
            {safe_subject}
        </h1>

        <div style="
            font-size:16px;
            line-height:1.7;
            color:#0f172a;
        ">
            {safe_message}
        </div>

        <hr style="
            border:none;
            border-top:1px solid #e2e8f0;
            margin:30px 0;
        ">

        <p style="
            font-size:14px;
            color:#475569;
        ">
            — TRACKIT Administration
        </p>

    </div>

</body>
</html>
"""

    text_body = f"""
TRACKIT Administration

{normalized_subject}

{normalized_message}

— TRACKIT Administration
"""

    await _send_email(
        recipient=normalized_recipient,
        subject=normalized_subject,
        html_body=html_body,
        text_body=text_body,
    )
