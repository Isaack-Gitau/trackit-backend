"""
TRACKIT Comment Author API Integration Tests.

Tests the safe author representation returned with public comments.

These tests intentionally verify that:
- author identity is included;
- only safe identity fields are exposed;
- profile-picture privacy is respected;
- comment visibility remains public for approved items.
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
    profile_picture: str | None = None,
    preferences: dict | None = None,
):
    user = User(
        id=user_id,
        username=username,
        first_name="Test",
        last_name="User",
        email=f"{username}@trackit.test",
        password_hash="test-password-hash",
        role="user",
        is_active=True,
        is_verified=True,
        token_version=0,
        profile_picture=profile_picture,
        preferences=preferences or {},
    )

    db.add(user)
    db.flush()

    return user


def create_item(
    db,
    *,
    owner_id: int,
):
    item = Item(
        user_id=owner_id,
        title="Test Lost Phone",
        description="A test item used for comment author tests.",
        type="lost",
        category="Electronics",
        location="Main Library",
        status="approved",
    )

    db.add(item)
    db.flush()

    return item


def create_comment(
    db,
    *,
    item_id: int,
    user_id: int,
    content: str = "This is a public comment.",
):
    comment = Comment(
        item_id=item_id,
        user_id=user_id,
        content=content,
    )

    db.add(comment)
    db.flush()

    return comment


def auth_headers(user: User) -> dict[str, str]:
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
# AUTHOR REPRESENTATION
# ============================================================================


def test_public_comment_includes_safe_author_identity(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=3101,
        username="commentitemowner",
    )

    commenter = create_user(
        db,
        user_id=3102,
        username="commentauthor",
        profile_picture="/media/profile/commentauthor.jpg",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.get(
        f"/api/items/{item.id}/comments",
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1

    author = data[0]["author"]

    assert author["id"] == commenter.id
    assert author["username"] == "commentauthor"
    assert (
        author["profile_picture"]
        == "/media/profile/commentauthor.jpg"
    )

    assert "email" not in author
    assert "phone_number" not in author
    assert "role" not in author
    assert "is_active" not in author
    assert "preferences" not in author


def test_public_comment_hides_private_profile_picture(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=3103,
        username="privatepictureowner",
    )

    commenter = create_user(
        db,
        user_id=3104,
        username="privatepictureauthor",
        profile_picture="/media/profile/private.jpg",
        preferences={
            "privacy": {
                "profile_picture": False,
            }
        },
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    create_comment(
        db,
        item_id=item.id,
        user_id=commenter.id,
    )

    response = client.get(
        f"/api/items/{item.id}/comments",
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1

    author = data[0]["author"]

    assert author["id"] == commenter.id
    assert author["username"] == "privatepictureauthor"
    assert author["profile_picture"] is None


def test_single_public_comment_includes_author(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=3105,
        username="singlecommentowner",
    )

    commenter = create_user(
        db,
        user_id=3106,
        username="singlecommentauthor",
        profile_picture="/media/profile/single.jpg",
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

    response = client.get(
        f"/api/comments/{comment.id}",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == comment.id
    assert data["user_id"] == commenter.id
    assert data["author"]["id"] == commenter.id
    assert data["author"]["username"] == "singlecommentauthor"
    assert (
        data["author"]["profile_picture"]
        == "/media/profile/single.jpg"
    )


def test_comment_creation_response_includes_author(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=3107,
        username="createcommentowner",
    )

    commenter = create_user(
        db,
        user_id=3108,
        username="createcommentauthor",
        profile_picture="/media/profile/create.jpg",
    )

    item = create_item(
        db,
        owner_id=owner.id,
    )

    response = client.post(
        f"/api/items/{item.id}/comments",
        headers=auth_headers(commenter),
        json={
            "content": "Created with author data.",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["user_id"] == commenter.id
    assert data["author"]["id"] == commenter.id
    assert data["author"]["username"] == "createcommentauthor"
    assert (
        data["author"]["profile_picture"]
        == "/media/profile/create.jpg"
    )