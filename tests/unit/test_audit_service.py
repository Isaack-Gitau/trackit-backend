
"""
TRACKIT Audit Service Unit Tests.

Tests:

- Audit event creation
- Event type normalization
- Empty event type rejection
- Description sanitization
- IP address sanitization
- User-agent sanitization
- Success flag handling
"""

from unittest.mock import MagicMock

import pytest

from app.models.audit_log import AuditLog
from app.services.audit import (
    MAX_DESCRIPTION_LENGTH,
    MAX_IP_ADDRESS_LENGTH,
    MAX_USER_AGENT_LENGTH,
    record_audit_event,
)


# ============================================================================
# AUDIT EVENT CREATION
# ============================================================================


def test_record_audit_event_creates_audit_log():
    db = MagicMock()

    audit_log = record_audit_event(
        db,
        event_type="login_success",
        success=True,
        description="User logged in successfully.",
        user_id=123,
        ip_address="127.0.0.1",
        user_agent="TestClient/1.0",
    )

    assert isinstance(audit_log, AuditLog)

    assert audit_log.event_type == "LOGIN_SUCCESS"
    assert audit_log.success is True
    assert (
        audit_log.description
        == "User logged in successfully."
    )
    assert audit_log.user_id == 123
    assert audit_log.ip_address == "127.0.0.1"
    assert audit_log.user_agent == "TestClient/1.0"

    db.add.assert_called_once_with(audit_log)
    db.flush.assert_called_once()


# ============================================================================
# EVENT TYPE
# ============================================================================


def test_event_type_is_normalized():
    db = MagicMock()

    audit_log = record_audit_event(
        db,
        event_type="  login_success  ",
    )

    assert audit_log.event_type == "LOGIN_SUCCESS"


def test_empty_event_type_is_rejected():
    db = MagicMock()

    with pytest.raises(ValueError):
        record_audit_event(
            db,
            event_type="   ",
        )

    db.add.assert_not_called()
    db.flush.assert_not_called()


# ============================================================================
# DESCRIPTION
# ============================================================================


def test_description_is_trimmed():
    db = MagicMock()

    audit_log = record_audit_event(
        db,
        event_type="TEST_EVENT",
        description="   test description   ",
    )

    assert audit_log.description == "test description"


def test_description_is_truncated():
    db = MagicMock()

    description = "A" * (
        MAX_DESCRIPTION_LENGTH + 100
    )

    audit_log = record_audit_event(
        db,
        event_type="TEST_EVENT",
        description=description,
    )

    assert audit_log.description is not None
    assert len(audit_log.description) == MAX_DESCRIPTION_LENGTH


# ============================================================================
# REQUEST METADATA
# ============================================================================


def test_ip_address_is_truncated():
    db = MagicMock()

    ip_address = "1" * (
        MAX_IP_ADDRESS_LENGTH + 100
    )

    audit_log = record_audit_event(
        db,
        event_type="TEST_EVENT",
        ip_address=ip_address,
    )

    assert audit_log.ip_address is not None
    assert len(audit_log.ip_address) == MAX_IP_ADDRESS_LENGTH


def test_user_agent_is_truncated():
    db = MagicMock()

    user_agent = "A" * (
        MAX_USER_AGENT_LENGTH + 100
    )

    audit_log = record_audit_event(
        db,
        event_type="TEST_EVENT",
        user_agent=user_agent,
    )

    assert audit_log.user_agent is not None
    assert len(audit_log.user_agent) == MAX_USER_AGENT_LENGTH


# ============================================================================
# SUCCESS FLAG
# ============================================================================


def test_failed_audit_event_is_supported():
    db = MagicMock()

    audit_log = record_audit_event(
        db,
        event_type="LOGIN_FAILURE",
        success=False,
        description="Authentication failed.",
    )

    assert audit_log.success is False

