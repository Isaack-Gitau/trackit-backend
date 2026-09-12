"""
TRACKIT Audit Logging Service Tests.

Tests:

- Audit log creation
- Successful events
- Failed events
- Anonymous events
- User-associated events
- Resource-associated events
- Automated system events
- Request metadata
- Safe handling of optional fields
"""

from app.models.audit_log import AuditLog
from app.models.user import User
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
# RESOURCE METADATA
# ============================================================================


def test_audit_log_supports_resource_metadata():
    """
    Audit logs should support structured information about the
    resource affected by an event.
    """

    audit_log = AuditLog(
        event_type="admin_action",
        success=True,
        description="User account was automatically reactivated.",
        user_id=None,
        resource_type="user",
        resource_id=42,
    )

    assert audit_log.resource_type == "user"
    assert audit_log.resource_id == 42
    assert audit_log.user_id is None


# ============================================================================
# SERVICE OBJECT CREATION
# ============================================================================


def test_create_audit_log_service_adds_record(db):
    """
    create_audit_log should add an AuditLog instance to the session.
    """

    user = User(
        id=1,
        username="audit_test_user",
        first_name="Audit",
        last_name="Tester",
        email="audit_test_user@trackit.test",
        password_hash="test-password-hash",
        role="user",
        is_active=True,
        is_verified=True,
    )

    db.add(user)
    db.flush()

    audit_log = create_audit_log(
        db,
        event_type=AUDIT_LOGIN_SUCCESS,
        success=True,
        description="User login successful.",
        user_id=user.id,
        ip_address="127.0.0.1",
        user_agent="TRACKIT-TestClient",
    )

    assert isinstance(audit_log, AuditLog)
    assert audit_log.event_type == AUDIT_LOGIN_SUCCESS
    assert audit_log.success is True
    assert audit_log.description == "User login successful."
    assert audit_log.user_id == user.id
    assert audit_log.resource_type is None
    assert audit_log.resource_id is None
    assert audit_log.ip_address == "127.0.0.1"
    assert audit_log.user_agent == "TRACKIT-TestClient"


def test_create_audit_log_service_supports_resource_metadata(db):
    """
    create_audit_log should persist structured resource metadata.
    """

    user = User(
        id=1,
        username="audit_resource_user",
        first_name="Audit",
        last_name="Resource",
        email="audit_resource_user@trackit.test",
        password_hash="test-password-hash",
        role="user",
        is_active=True,
        is_verified=True,
    )

    db.add(user)
    db.flush()

    audit_log = create_audit_log(
        db,
        event_type="admin_action",
        success=True,
        description=(
            "Automatically reactivated user after "
            "temporary suspension expired."
        ),
        user_id=None,
        resource_type="user",
        resource_id=user.id,
    )

    assert isinstance(audit_log, AuditLog)
    assert audit_log.event_type == "admin_action"
    assert audit_log.success is True
    assert audit_log.user_id is None
    assert audit_log.resource_type == "user"
    assert audit_log.resource_id == user.id


def test_create_audit_log_supports_automated_system_event(db):
    """
    Automated system events should not impersonate an administrator.

    The affected user is represented as the resource while user_id
    remains None because there is no authenticated human actor.
    """

    audit_log = create_audit_log(
        db,
        event_type="admin_action",
        success=True,
        description=(
            "Automatically reactivated user 42 after "
            "temporary suspension expired."
        ),
        user_id=None,
        resource_type="user",
        resource_id=42,
    )

    assert isinstance(audit_log, AuditLog)
    assert audit_log.user_id is None
    assert audit_log.resource_type == "user"
    assert audit_log.resource_id == 42
    assert audit_log.success is True