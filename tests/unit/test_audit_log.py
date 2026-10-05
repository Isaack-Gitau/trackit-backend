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

from datetime import datetime, timezone

import pytest

from app.models.audit_log import AuditLog
from app.models.user import User
from app.repositories.audit_logs import iter_audit_logs
from app.services.audit_log import (
    AUDIT_ADMIN_ACTION,
    AUDIT_ACCOUNT_DISABLED,
    AUDIT_ACCOUNT_ENABLED,
    AUDIT_ADMIN_COMMENT_DELETED,
    AUDIT_CLAIM_CREATED,
    AUDIT_CLAIM_UPDATED,
    AUDIT_COMMENT_CREATED,
    AUDIT_COMMENT_DELETED,
    AUDIT_COMMENT_UPDATED,
    AUDIT_EMAIL_VERIFICATION_FAILURE,
    AUDIT_EMAIL_VERIFICATION_SUCCESS,
    AUDIT_ITEM_CREATED,
    AUDIT_ITEM_DELETED,
    AUDIT_ITEM_UPDATED,
    AUDIT_LOGIN_FAILURE,
    AUDIT_LOGIN_SUCCESS,
    AUDIT_LOGOUT,
    AUDIT_PASSWORD_RESET_FAILURE,
    AUDIT_PASSWORD_RESET_REQUEST,
    AUDIT_PASSWORD_RESET_SUCCESS,
    AUDIT_REGISTER_FAILURE,
    AUDIT_REGISTER_SUCCESS,
    get_audit_action_category,
    get_audit_actions_for_category,
    create_audit_log,
    preview_audit_logs_for_admin,
)



# ============================================================================
# AUDIT ACTION CATEGORY
# ============================================================================


def test_audit_action_categories_cover_all_defined_actions():
    """
    Every defined audit action must resolve to a known category.
    """

    action_categories = {
        AUDIT_LOGIN_SUCCESS: "authentication",
        AUDIT_LOGIN_FAILURE: "authentication",
        AUDIT_REGISTER_SUCCESS: "authentication",
        AUDIT_REGISTER_FAILURE: "authentication",
        AUDIT_EMAIL_VERIFICATION_SUCCESS: "authentication",
        AUDIT_EMAIL_VERIFICATION_FAILURE: "authentication",
        AUDIT_PASSWORD_RESET_REQUEST: "authentication",
        AUDIT_PASSWORD_RESET_SUCCESS: "authentication",
        AUDIT_PASSWORD_RESET_FAILURE: "authentication",
        AUDIT_ACCOUNT_DISABLED: "account",
        AUDIT_ACCOUNT_ENABLED: "account",
        AUDIT_LOGOUT: "account",
        AUDIT_ITEM_CREATED: "items",
        AUDIT_ITEM_UPDATED: "items",
        AUDIT_ITEM_DELETED: "items",
        AUDIT_CLAIM_CREATED: "claims",
        AUDIT_CLAIM_UPDATED: "claims",
        AUDIT_COMMENT_CREATED: "comments",
        AUDIT_COMMENT_UPDATED: "comments",
        AUDIT_COMMENT_DELETED: "comments",
        AUDIT_ADMIN_COMMENT_DELETED: "comments",
        AUDIT_ADMIN_ACTION: "administration",
    }

    for action, expected_category in action_categories.items():
        assert get_audit_action_category(action) == expected_category


def test_unknown_audit_action_maps_to_other():
    """
    Custom or future actions must remain valid and use the fallback category.
    """

    assert (
        get_audit_action_category("custom_future_event")
        == "other"
    )


def test_blank_audit_action_maps_to_other():
    """
    Empty action values are treated as unknown for categorization.
    """

    assert get_audit_action_category("") == "other"
    assert get_audit_action_category("   ") == "other"


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


def test_get_audit_actions_for_category_returns_matching_actions():
    """
    A known category should resolve to every audit action assigned to it.
    """

    actions = get_audit_actions_for_category("authentication")

    assert set(actions) == {
        AUDIT_LOGIN_SUCCESS,
        AUDIT_LOGIN_FAILURE,
        AUDIT_REGISTER_SUCCESS,
        AUDIT_REGISTER_FAILURE,
        AUDIT_EMAIL_VERIFICATION_SUCCESS,
        AUDIT_EMAIL_VERIFICATION_FAILURE,
        AUDIT_PASSWORD_RESET_REQUEST,
        AUDIT_PASSWORD_RESET_SUCCESS,
        AUDIT_PASSWORD_RESET_FAILURE,
    }


def test_get_audit_actions_for_category_unknown_returns_empty():
    """
    Unknown categories should not produce arbitrary database filters.
    """

    assert get_audit_actions_for_category("not_a_category") == []
    assert get_audit_actions_for_category("") == []
    assert get_audit_actions_for_category("   ") == []


def test_get_audit_actions_for_category_other_returns_empty():
    """
    The special 'other' category represents actions outside the known map.
    """

    assert get_audit_actions_for_category("other") == []


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

def test_create_audit_log_supports_subject_user_id(db):
    """
    create_audit_log should store the affected user separately
    from the user who performed the action.
    """

    actor = User(
        id=1,
        username="audit_actor_user",
        first_name="Audit",
        last_name="Actor",
        email="audit_actor_user@trackit.test",
        password_hash="test-password-hash",
        role="administrator",
        is_active=True,
        is_verified=True,
    )

    subject = User(
        id=2,
        username="audit_subject_user",
        first_name="Audit",
        last_name="Subject",
        email="audit_subject_user@trackit.test",
        password_hash="test-password-hash",
        role="user",
        is_active=True,
        is_verified=True,
    )

    db.add_all([actor, subject])
    db.flush()

    audit_log = create_audit_log(
        db,
        event_type="admin_action",
        success=True,
        description="Administrator suspended user.",
        user_id=actor.id,
        subject_user_id=subject.id,
        resource_type="user",
        resource_id=subject.id,
    )

    assert audit_log.user_id == actor.id
    assert audit_log.subject_user_id == subject.id
    assert audit_log.resource_type == "user"
    assert audit_log.resource_id == subject.id


# ============================================================================
# AUDIT LOG PREVIEW SERVICE
# ============================================================================


def test_preview_audit_logs_for_admin_returns_count_and_normalized_filters(
    db,
):
    """
    The preview service returns only the filtered count and normalized
    shared filter metadata.
    """

    user = User(
        id=9170,
        username="preview_service_user",
        first_name="Preview",
        last_name="Service",
        email="preview_service_user@trackit.test",
        password_hash="test-password-hash",
        role="user",
        is_active=True,
        is_verified=True,
    )

    db.add(user)
    db.flush()

    db.add_all(
        [
            AuditLog(
                action="login_success",
                success=True,
                user_id=user.id,
            ),
            AuditLog(
                action="login_failure",
                success=False,
                user_id=user.id,
            ),
            AuditLog(
                action="item_created",
                success=True,
                user_id=user.id,
            ),
        ]
    )
    db.flush()

    total, filters = preview_audit_logs_for_admin(
        db,
        category=" AUTHENTICATION ",
        success=False,
        user_id=user.id,
        resource_type="   ",
    )

    assert total == 1
    assert filters["action"] is None
    assert filters["category"] == "authentication"
    assert filters["actions"] is not None
    assert set(filters["actions"]) == {
        AUDIT_LOGIN_SUCCESS,
        AUDIT_LOGIN_FAILURE,
        AUDIT_REGISTER_SUCCESS,
        AUDIT_REGISTER_FAILURE,
        AUDIT_EMAIL_VERIFICATION_SUCCESS,
        AUDIT_EMAIL_VERIFICATION_FAILURE,
        AUDIT_PASSWORD_RESET_REQUEST,
        AUDIT_PASSWORD_RESET_SUCCESS,
        AUDIT_PASSWORD_RESET_FAILURE,
    }
    assert filters["exclude_actions"] is None
    assert filters["user_id"] == user.id
    assert filters["subject_user_id"] is None
    assert filters["resource_type"] is None
    assert filters["resource_id"] is None
    assert filters["created_from"] is None
    assert filters["created_to"] is None


# ============================================================================
# AUDIT LOG REPOSITORY STREAMING
# ============================================================================


def test_iter_audit_logs_streams_filtered_results(db):
    """
    The repository iterator applies filters and preserves deterministic
    newest-first ordering without materializing the full result set.
    """

    db.add_all(
        [
            AuditLog(
                action="stream_test",
                success=True,
                created_at=datetime(
                    2026,
                    9,
                    1,
                    10,
                    0,
                    tzinfo=timezone.utc,
                ),
            ),
            AuditLog(
                action="stream_test",
                success=False,
                created_at=datetime(
                    2026,
                    9,
                    3,
                    10,
                    0,
                    tzinfo=timezone.utc,
                ),
            ),
            AuditLog(
                action="stream_test",
                success=True,
                created_at=datetime(
                    2026,
                    9,
                    2,
                    10,
                    0,
                    tzinfo=timezone.utc,
                ),
            ),
            AuditLog(
                action="different_action",
                success=False,
                created_at=datetime(
                    2026,
                    9,
                    4,
                    10,
                    0,
                    tzinfo=timezone.utc,
                ),
            ),
        ]
    )
    db.flush()

    streamed = list(
        iter_audit_logs(
            db,
            action="stream_test",
            batch_size=1,
        )
    )

    assert len(streamed) == 3

    assert [
        log.created_at
        for log in streamed
    ] == [
        datetime(
            2026,
            9,
            3,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        datetime(
            2026,
            9,
            2,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        datetime(
            2026,
            9,
            1,
            10,
            0,
            tzinfo=timezone.utc,
        ),
    ]

    assert all(
        log.action == "stream_test"
        for log in streamed
    )


def test_iter_audit_logs_rejects_invalid_batch_size(db):
    """
    The streaming repository rejects non-positive batch sizes.
    """

    with pytest.raises(
        ValueError,
        match="batch_size must be at least 1",
    ):
        list(
            iter_audit_logs(
                db,
                batch_size=0,
            )
        )
