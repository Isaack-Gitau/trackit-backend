"""
TRACKIT Comment API Integration Tests.

Tests HTTP-level behavior for:
- comment creation
- public comment visibility
- authentication requirements
- verified-user requirements
- comment ownership
- IDOR protection
- comment updates
- comment deletion
- administrator deletion
- content validation
- hidden-item protection
- comment response structure
"""

from app.core.security import create_access_token
from app.models.comment import Comment
from app.models.item import Item
from app.models.user import User


# ============================================================================
# HELPERS
# ============================================================================


def create_user(
    db,
    *,
    user_id: int,
    username: str,
    role: str = "user",
    is_verified: bool = True,
):
    """
    Create a test user using the same fields expected by production auth.
    """

    user = User(
        id=user_id,
        username=username,
        first_name="Test",
        last_name="User",
        email=f"{username}@trackit.test",
        password_hash="test-password-hash",
        role=role,
        is_active=True,
        is_verified=is_verified,
        token_version=0,
    )

    db.add(user)
    db.flush()

    return user


def create_item(
    db,
    *,
    owner_id: int,
    status: str = "approved",
    item_type: str = "lost",
):
    """
    Create a test item.
    """

    item = Item(
        user_id=owner_id,
        title="Test Lost Phone",
        description="A test item used for comment API integration tests.",
        type=item_type,
        category="Electronics",
        location="Main Library",
        status=status,
    )

    db.add(item)
    db.flush()

    return item


def create_comment(
    db,
    *,
    item_id: int,
    user_id: int,
    content: str = "This is a useful comment.",
):
    """
    Create a comment directly for authorization and retrieval tests.
    """

    comment = Comment(
        item_id=item_id,
        user_id=user_id,
        content=content,
    )

    db.add(comment)
    db.flush()

    return comment


def auth_headers(user: User) -> dict[str, str]:
    """
    Generate a real TRACKIT access token using the same JWT structure
    expected by the production authentication dependencies.
    """

    token = create_access_token(
        data={
            "sub": str(user.id),
            "role": user.role,
            "token_version": user.token_version,
        }
    )

    return {
        "Authorization": f"Bearer {token}",
    }


# ============================================================================
# COMMENT CREATION
# ============================================================================


def test_unauthenticated_user_cannot_create_comment(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2001,
        username="commentowner1",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.post(
        f"/api/items/{item.id}/comments",
        json={
            "content": "Unauthenticated comment.",
        },
    )

    assert response.status_code == 401


def test_unverified_user_cannot_create_comment(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2002,
        username="commentowner2",
    )

    unverified_user = create_user(
        db,
        user_id=2003,
        username="unverifiedcommenter",
        is_verified=False,
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.post(
        f"/api/items/{item.id}/comments",
        headers=auth_headers(unverified_user),
        json={
            "content": "This should not be accepted.",
        },
    )

    assert response.status_code == 403


def test_verified_user_can_create_comment(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2004,
        username="commentowner3",
    )

    commenter = create_user(
        db,
        user_id=2005,
        username="commenter1",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.post(
        f"/api/items/{item.id}/comments",
        headers=auth_headers(commenter),
        json={
            "content": "I think this item may have been found nearby.",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["item_id"] == item.id
    assert data["user_id"] == commenter.id
    assert data["content"] == "I think this item may have been found nearby."
    assert data["id"] > 0
    assert data["created_at"] is not None
    assert data["updated_at"] is not None


def test_comment_creation_strips_surrounding_whitespace(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2006,
        username="commentowner4",
    )

    commenter = create_user(
        db,
        user_id=2007,
        username="commenter2",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.post(
        f"/api/items/{item.id}/comments",
        headers=auth_headers(commenter),
        json={
            "content": "   Useful information here.   ",
        },
    )

    assert response.status_code == 201
    assert response.json()["content"] == "Useful information here."


def test_comment_creation_rejects_blank_content(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2008,
        username="commentowner5",
    )

    commenter = create_user(
        db,
        user_id=2009,
        username="commenter3",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.post(
        f"/api/items/{item.id}/comments",
        headers=auth_headers(commenter),
        json={
            "content": "   ",
        },
    )

    assert response.status_code == 422


def test_comment_creation_rejects_content_over_2000_characters(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2010,
        username="commentowner6",
    )

    commenter = create_user(
        db,
        user_id=2011,
        username="commenter4",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.post(
        f"/api/items/{item.id}/comments",
        headers=auth_headers(commenter),
        json={
            "content": "x" * 2001,
        },
    )

    assert response.status_code == 422


def test_user_cannot_create_comment_for_nonexistent_item(
    client,
    db,
):
    commenter = create_user(
        db,
        user_id=2012,
        username="commenter5",
    )

    response = client.post(
        "/api/items/999999/comments",
        headers=auth_headers(commenter),
        json={
            "content": "Comment on nonexistent item.",
        },
    )

    assert response.status_code == 400


def test_user_cannot_create_comment_on_pending_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2013,
        username="commentowner7",
    )

    commenter = create_user(
        db,
        user_id=2014,
        username="commenter6",
    )

    item = create_item(
        db,
        owner_id=owner.id,
        status="pending",
    )

    response = client.post(
        f"/api/items/{item.id}/comments",
        headers=auth_headers(commenter),
        json={
            "content": "Comment on pending item.",
        },
    )

    assert response.status_code == 403


def test_user_cannot_create_comment_on_rejected_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2015,
        username="commentowner8",
    )

    commenter = create_user(
        db,
        user_id=2016,
        username="commenter7",
    )

    item = create_item(
        db,
        owner_id=owner.id,
        status="rejected",
    )

    response = client.post(
        f"/api/items/{item.id}/comments",
        headers=auth_headers(commenter),
        json={
            "content": "Comment on rejected item.",
        },
    )

    assert response.status_code == 403


# ============================================================================
# PUBLIC COMMENT LISTING
# ============================================================================


def test_anonymous_user_can_list_comments_on_approved_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2017,
        username="commentowner9",
    )

    commenter = create_user(
        db,
        user_id=2018,
        username="commenter8",
    )

    item = create_item(
        db,
        owner_id=owner.id,
        status="approved",
    )

    create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
        content="First public comment.",
    )

    create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
        content="Second public comment.",
    )

    response = client.get(
        f"/api/items/{item.id}/comments",
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 2
    assert data[0]["content"] == "Second public comment."
    assert data[1]["content"] == "First public comment."


def test_anonymous_user_can_list_comments_on_claimed_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2019,
        username="commentowner10",
    )

    commenter = create_user(
        db,
        user_id=2020,
        username="commenter9",
    )

    item = create_item(
        db,
        owner_id=owner.id,
        status="claimed",
    )

    create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
        content="Comment on claimed item.",
    )

    response = client.get(
        f"/api/items/{item.id}/comments",
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["content"] == "Comment on claimed item."


def test_anonymous_user_cannot_list_comments_on_pending_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2021,
        username="commentowner11",
    )

    commenter = create_user(
        db,
        user_id=2022,
        username="commenter10",
    )

    item = create_item(
        db,
        owner_id=owner.id,
        status="pending",
    )

    create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
        content="Hidden pending comment.",
    )

    response = client.get(
        f"/api/items/{item.id}/comments",
    )

    assert response.status_code == 403


def test_anonymous_user_cannot_list_comments_on_rejected_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2023,
        username="commentowner12",
    )

    commenter = create_user(
        db,
        user_id=2024,
        username="commenter11",
    )

    item = create_item(
        db,
        owner_id=owner.id,
        status="rejected",
    )

    create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
        content="Hidden rejected comment.",
    )

    response = client.get(
        f"/api/items/{item.id}/comments",
    )

    assert response.status_code == 403


def test_comment_list_for_nonexistent_item_returns_bad_request(
    client,
    db,
):
    response = client.get(
        "/api/items/999998/comments",
    )

    assert response.status_code == 400


def test_comment_list_returns_empty_list_when_item_has_no_comments(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2025,
        username="commentowner13",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.get(
        f"/api/items/{item.id}/comments",
    )

    assert response.status_code == 200
    assert response.json() == []


# ============================================================================
# SINGLE COMMENT RETRIEVAL
# ============================================================================


def test_anonymous_user_can_get_comment_on_public_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2026,
        username="commentowner14",
    )

    commenter = create_user(
        db,
        user_id=2027,
        username="commenter12",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
        content="Public comment detail.",
    )

    response = client.get(
        f"/api/comments/{comment.id}",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == comment.id
    assert data["item_id"] == item.id
    assert data["user_id"] == commenter.id
    assert data["content"] == "Public comment detail."


def test_nonexistent_comment_returns_not_found(
    client,
    db,
):
    response = client.get(
        "/api/comments/999997",
    )

    assert response.status_code == 404


def test_comment_on_pending_item_is_hidden_from_anonymous_user(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2028,
        username="commentowner15",
    )

    commenter = create_user(
        db,
        user_id=2029,
        username="commenter13",
    )

    item = create_item(
        db,
        owner_id=owner.id,
        status="pending",
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
        content="Secret pending comment.",
    )

    response = client.get(
        f"/api/comments/{comment.id}",
    )

    # Do not leak the existence of comments belonging to hidden items.
    assert response.status_code == 404


def test_comment_on_rejected_item_is_hidden_from_anonymous_user(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2030,
        username="commentowner16",
    )

    commenter = create_user(
        db,
        user_id=2031,
        username="commenter14",
    )

    item = create_item(
        db,
        owner_id=owner.id,
        status="rejected",
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
        content="Secret rejected comment.",
    )

    response = client.get(
        f"/api/comments/{comment.id}",
    )

    assert response.status_code == 404


# ============================================================================
# COMMENT UPDATE
# ============================================================================


def test_comment_owner_can_update_comment(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2032,
        username="commentowner17",
    )

    commenter = create_user(
        db,
        user_id=2033,
        username="commenter15",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
        content="Original comment.",
    )

    response = client.patch(
        f"/api/comments/{comment.id}",
        headers=auth_headers(commenter),
        json={
            "content": "Updated comment.",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == comment.id
    assert data["user_id"] == commenter.id
    assert data["content"] == "Updated comment."


def test_comment_update_strips_surrounding_whitespace(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2034,
        username="commentowner18",
    )

    commenter = create_user(
        db,
        user_id=2035,
        username="commenter16",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.patch(
        f"/api/comments/{comment.id}",
        headers=auth_headers(commenter),
        json={
            "content": "   Cleaned update.   ",
        },
    )

    assert response.status_code == 200
    assert response.json()["content"] == "Cleaned update."


def test_comment_owner_cannot_update_comment_with_blank_content(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2036,
        username="commentowner19",
    )

    commenter = create_user(
        db,
        user_id=2037,
        username="commenter17",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.patch(
        f"/api/comments/{comment.id}",
        headers=auth_headers(commenter),
        json={
            "content": "   ",
        },
    )

    assert response.status_code == 422


def test_comment_owner_cannot_update_comment_over_2000_characters(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2038,
        username="commentowner20",
    )

    commenter = create_user(
        db,
        user_id=2039,
        username="commenter18",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.patch(
        f"/api/comments/{comment.id}",
        headers=auth_headers(commenter),
        json={
            "content": "x" * 2001,
        },
    )

    assert response.status_code == 422


def test_unauthenticated_user_cannot_update_comment(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2040,
        username="commentowner21",
    )

    commenter = create_user(
        db,
        user_id=2041,
        username="commenter19",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.patch(
        f"/api/comments/{comment.id}",
        json={
            "content": "Unauthorized update.",
        },
    )

    assert response.status_code == 401


def test_unverified_user_cannot_update_comment(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2042,
        username="commentowner22",
    )

    commenter = create_user(
        db,
        user_id=2043,
        username="commenter20",
        is_verified=True,
    )

    unverified_user = create_user(
        db,
        user_id=2044,
        username="unverifiedcommenter2",
        is_verified=False,
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.patch(
        f"/api/comments/{comment.id}",
        headers=auth_headers(unverified_user),
        json={
            "content": "Unauthorized update.",
        },
    )

    assert response.status_code == 403


def test_non_owner_cannot_update_comment(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2045,
        username="commentowner23",
    )

    commenter = create_user(
        db,
        user_id=2046,
        username="commenter21",
    )

    other_user = create_user(
        db,
        user_id=2047,
        username="othercommenter",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
        content="Owner's original comment.",
    )

    response = client.patch(
        f"/api/comments/{comment.id}",
        headers=auth_headers(other_user),
        json={
            "content": "IDOR attempt.",
        },
    )

    assert response.status_code == 403


def test_update_nonexistent_comment_returns_not_found(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2048,
        username="commenter22",
    )

    response = client.patch(
        "/api/comments/999996",
        headers=auth_headers(user),
        json={
            "content": "Update nonexistent comment.",
        },
    )

    assert response.status_code == 404


# ============================================================================
# COMMENT DELETION
# ============================================================================


def test_comment_owner_can_delete_comment(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2049,
        username="commentowner24",
    )

    commenter = create_user(
        db,
        user_id=2050,
        username="commenter23",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.delete(
        f"/api/comments/{comment.id}",
        headers=auth_headers(commenter),
    )

    assert response.status_code == 204
    assert response.content == b""

    db.expire_all()

    assert db.get(Comment, comment.id) is None


def test_unauthenticated_user_cannot_delete_comment(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2051,
        username="commentowner25",
    )

    commenter = create_user(
        db,
        user_id=2052,
        username="commenter24",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.delete(
        f"/api/comments/{comment.id}",
    )

    assert response.status_code == 401


def test_unverified_user_cannot_delete_comment(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2053,
        username="commentowner26",
    )

    commenter = create_user(
        db,
        user_id=2054,
        username="commenter25",
    )

    unverified_user = create_user(
        db,
        user_id=2055,
        username="unverifiedcommenter3",
        is_verified=False,
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.delete(
        f"/api/comments/{comment.id}",
        headers=auth_headers(unverified_user),
    )

    assert response.status_code == 403


def test_non_owner_cannot_delete_comment(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2056,
        username="commentowner27",
    )

    commenter = create_user(
        db,
        user_id=2057,
        username="commenter26",
    )

    other_user = create_user(
        db,
        user_id=2058,
        username="othercommenter2",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.delete(
        f"/api/comments/{comment.id}",
        headers=auth_headers(other_user),
    )

    assert response.status_code == 403

    db.expire_all()

    assert db.get(Comment, comment.id) is not None


def test_delete_nonexistent_comment_returns_not_found(
    client,
    db,
):
    user = create_user(
        db,
        user_id=2059,
        username="commenter27",
    )

    response = client.delete(
        "/api/comments/999995",
        headers=auth_headers(user),
    )

    assert response.status_code == 404


# ============================================================================
# ADMIN COMMENT DELETION
# ============================================================================


def test_admin_can_delete_any_comment(
    client,
    db,
    admin_user,
):
    owner = create_user(
        db,
        user_id=2060,
        username="commentowner28",
    )

    commenter = create_user(
        db,
        user_id=2061,
        username="commenter28",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
        content="Comment that admin will remove.",
    )

    response = client.delete(
        f"/api/admin/comments/{comment.id}",
        headers=auth_headers(admin_user),
    )

    assert response.status_code == 204
    assert response.content == b""

    db.expire_all()

    assert db.get(Comment, comment.id) is None


def test_regular_user_cannot_use_admin_comment_delete(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2062,
        username="commentowner29",
    )

    commenter = create_user(
        db,
        user_id=2063,
        username="commenter29",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.delete(
        f"/api/admin/comments/{comment.id}",
        headers=auth_headers(commenter),
    )

    assert response.status_code == 403

    db.expire_all()

    assert db.get(Comment, comment.id) is not None


def test_unauthenticated_user_cannot_use_admin_comment_delete(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=2064,
        username="commentowner30",
    )

    commenter = create_user(
        db,
        user_id=2065,
        username="commenter30",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    comment = create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.delete(
        f"/api/admin/comments/{comment.id}",
    )

    assert response.status_code == 401


def test_admin_delete_nonexistent_comment_returns_not_found(
    client,
    db,
    admin_user,
):
    response = client.delete(
        "/api/admin/comments/999994",
        headers=auth_headers(admin_user),
    )

    assert response.status_code == 404
