"""
TRACKIT Audit Logging Service Tests.

Tests:

- Audit log creation
- Successful events
- Failed events
- Anonymous events
- User-associated events
- Request metadata
- Safe handling of optional fields
"""

from app.models.audit_log import AuditLog
from app.services.audit_log import (
    AUDIT_LOGIN_FAILURE,
    AUDIT_LOGIN_SUCCESS,
    AUDIT_REGISTER_SUCCESS,
    create_audit_log,
)


# ============================================================================
# AUDIT LOG CREATION
# ============================================================================


def test_create_audit_log():
    """
    An audit log should be created with the supplied metadata.
    """

    # The test only verifies object construction here.
    # Database persistence is covered by integration tests.
    audit_log = AuditLog(
        event_type=AUDIT_LOGIN_SUCCESS,
        success=True,
        description="User login successful.",
        user_id=1,
        ip_address="127.0.0.1",
        user_agent="TRACKIT-TestClient",
    )

    assert audit_log.event_type == AUDIT_LOGIN_SUCCESS
    assert audit_log.success is True
    assert audit_log.description == "User login successful."
    assert audit_log.user_id == 1
    assert audit_log.ip_address == "127.0.0.1"
    assert audit_log.user_agent == "TRACKIT-TestClient"


# ============================================================================
# FAILURE EVENTS
# ============================================================================


def test_failed_audit_event():
    """
    Failed security events must be recorded as unsuccessful.
    """

    audit_log = AuditLog(
        event_type=AUDIT_LOGIN_FAILURE,
        success=False,
        description="Login attempt failed.",
        ip_address="127.0.0.1",
    )

    assert audit_log.event_type == AUDIT_LOGIN_FAILURE
    assert audit_log.success is False


# ============================================================================
# ANONYMOUS EVENTS
# ============================================================================


def test_anonymous_audit_event():
    """
    Audit events may occur before a user is authenticated.
    """

    audit_log = AuditLog(
        event_type=AUDIT_REGISTER_SUCCESS,
        success=True,
        description="User registration completed.",
        user_id=None,
        ip_address="127.0.0.1",
    )

    assert audit_log.user_id is None
    assert audit_log.ip_address == "127.0.0.1"


# ============================================================================
# SERVICE OBJECT CREATION
# ============================================================================


def test_create_audit_log_service_adds_record(db):
    """
    create_audit_log should add an AuditLog instance to the session.
    """

    audit_log = create_audit_log(
        db,
        event_type=AUDIT_LOGIN_SUCCESS,
        success=True,
        description="User login successful.",
        user_id=1,
        ip_address="127.0.0.1",
        user_agent="TRACKIT-TestClient",
    )

    assert isinstance(audit_log, AuditLog)
    assert audit_log.event_type == AUDIT_LOGIN_SUCCESS
    assert audit_log.success is True
    assert audit_log.description == "User login successful."
    assert audit_log.user_id == 1
    assert audit_log.ip_address == "127.0.0.1"
    assert audit_log.user_agent == "TRACKIT-TestClient"