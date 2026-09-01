"""
TRACKIT Match API Integration Tests.

Tests the HTTP/API layer for:
- authentication
- verified-user authorization
- listing matches
- retrieving one match
- item-specific match listing
- match ownership
- dismissing matches
- restoring matches
- dismissed-match filtering
- not-found behavior
"""

from datetime import datetime, timezone

from app.core.security import create_access_token
from app.models.item import Item
from app.models.match import Match
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
    is_active: bool = True,
    token_version: int = 0,
):
    user = User(
        id=user_id,
        username=username,
        first_name="Test",
        last_name="User",
        email=f"{username}@trackit.test",
        password_hash="test-password-hash",
        role=role,
        is_active=is_active,
        is_verified=is_verified,
        token_version=token_version,
    )

    db.add(user)
    db.flush()

    return user


def create_item(
    db,
    *,
    owner_id: int,
    item_type: str,
    title: str = "Test Phone",
    description: str = "Black smartphone with a cracked screen.",
    category: str = "Electronics",
    location: str = "Main Library",
    status: str = "approved",
):
    item = Item(
        user_id=owner_id,
        title=title,
        description=description,
        type=item_type,
        category=category,
        location=location,
        status=status,
    )

    db.add(item)
    db.flush()

    return item


def create_match(
    db,
    *,
    lost_item_id: int,
    found_item_id: int,
    score: int = 90,
    match_level: str = "strong",
    category_score: int = 25,
    title_score: int = 18,
    description_score: int = 27,
    location_score: int = 12,
    time_score: int = 8,
    reason: str = (
        "exact category match; strong title similarity; "
        "strong description similarity; similar location; "
        "items reported close together in time."
    ),
    is_dismissed: bool = False,
):
    match = Match(
        lost_item_id=lost_item_id,
        found_item_id=found_item_id,
        score=score,
        match_level=match_level,
        category_score=category_score,
        title_score=title_score,
        description_score=description_score,
        location_score=location_score,
        time_score=time_score,
        reason=reason,
        is_dismissed=is_dismissed,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    db.add(match)
    db.flush()

    return match


def auth_headers(user):
    """
    Generate a real TRACKIT access token using the
    same JWT structure as the production login flow.
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
# AUTHENTICATION
# ============================================================================


def test_unauthenticated_user_cannot_list_matches(
    client,
    db,
):
    response = client.get(
        "/api/matches",
    )

    assert response.status_code == 401


def test_unverified_user_cannot_list_matches(
    client,
    db,
):
    user = create_user(
        db,
        user_id=3001,
        username="match_unverified",
        is_verified=False,
    )

    response = client.get(
        "/api/matches",
        headers=auth_headers(user),
    )

    assert response.status_code == 403


# ============================================================================
# LIST MATCHES
# ============================================================================


def test_verified_user_can_list_own_matches(
    client,
    db,
):
    lost_owner = create_user(
        db,
        user_id=3002,
        username="match_list_lost_owner",
    )

    found_owner = create_user(
        db,
        user_id=3003,
        username="match_list_found_owner",
    )

    lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
    )

    found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
    )

    match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    response = client.get(
        "/api/matches",
        headers=auth_headers(lost_owner),
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == match.id
    assert data[0]["lost_item_id"] == lost_item.id
    assert data[0]["found_item_id"] == found_item.id
    assert data[0]["score"] == 90
    assert data[0]["match_level"] == "strong"
    assert data[0]["is_dismissed"] is False


def test_user_can_see_match_involving_owned_found_item(
    client,
    db,
):
    lost_owner = create_user(
        db,
        user_id=3004,
        username="match_found_visibility_lost",
    )

    found_owner = create_user(
        db,
        user_id=3005,
        username="match_found_visibility_owner",
    )

    lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
    )

    found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
    )

    match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    response = client.get(
        "/api/matches",
        headers=auth_headers(found_owner),
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == match.id


def test_user_cannot_see_matches_not_involving_owned_items(
    client,
    db,
):
    owner_one = create_user(
        db,
        user_id=3006,
        username="match_private_owner_one",
    )

    owner_two = create_user(
        db,
        user_id=3007,
        username="match_private_owner_two",
    )

    outsider = create_user(
        db,
        user_id=3008,
        username="match_private_outsider",
    )

    lost_item = create_item(
        db,
        owner_id=owner_one.id,
        item_type="lost",
    )

    found_item = create_item(
        db,
        owner_id=owner_two.id,
        item_type="found",
    )

    create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    response = client.get(
        "/api/matches",
        headers=auth_headers(outsider),
    )

    assert response.status_code == 200
    assert response.json() == []


# ============================================================================
# SINGLE MATCH
# ============================================================================


def test_user_can_retrieve_own_match(
    client,
    db,
):
    lost_owner = create_user(
        db,
        user_id=3009,
        username="match_get_lost_owner",
    )

    found_owner = create_user(
        db,
        user_id=3010,
        username="match_get_found_owner",
    )

    lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
    )

    found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
    )

    match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    response = client.get(
        f"/api/matches/{match.id}",
        headers=auth_headers(lost_owner),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == match.id
    assert data["lost_item_id"] == lost_item.id
    assert data["found_item_id"] == found_item.id
    assert data["score"] == 90
    assert data["category_score"] == 25
    assert data["title_score"] == 18
    assert data["description_score"] == 27
    assert data["location_score"] == 12
    assert data["time_score"] == 8
    assert data["reason"]


def test_user_cannot_retrieve_another_users_match(
    client,
    db,
):
    lost_owner = create_user(
        db,
        user_id=3011,
        username="match_private_lost",
    )

    found_owner = create_user(
        db,
        user_id=3012,
        username="match_private_found",
    )

    outsider = create_user(
        db,
        user_id=3013,
        username="match_private_getter",
    )

    lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
    )

    found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
    )

    match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    response = client.get(
        f"/api/matches/{match.id}",
        headers=auth_headers(outsider),
    )

    assert response.status_code == 404


def test_nonexistent_match_returns_404(
    client,
    db,
):
    user = create_user(
        db,
        user_id=3014,
        username="match_missing_user",
    )

    response = client.get(
        "/api/matches/999999999",
        headers=auth_headers(user),
    )

    assert response.status_code == 404


# ============================================================================
# ITEM MATCHES
# ============================================================================


def test_user_can_list_matches_for_owned_lost_item(
    client,
    db,
):
    lost_owner = create_user(
        db,
        user_id=3015,
        username="match_item_lost_owner",
    )

    found_owner = create_user(
        db,
        user_id=3016,
        username="match_item_found_owner",
    )

    lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
    )

    found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
    )

    match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    response = client.get(
        f"/api/matches/items/{lost_item.id}",
        headers=auth_headers(lost_owner),
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == match.id
    assert data[0]["lost_item_id"] == lost_item.id


def test_user_can_list_matches_for_owned_found_item(
    client,
    db,
):
    lost_owner = create_user(
        db,
        user_id=3017,
        username="match_item_found_lost",
    )

    found_owner = create_user(
        db,
        user_id=3018,
        username="match_item_found_owner_two",
    )

    lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
    )

    found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
    )

    match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    response = client.get(
        f"/api/matches/items/{found_item.id}",
        headers=auth_headers(found_owner),
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == match.id
    assert data[0]["found_item_id"] == found_item.id


def test_user_cannot_list_matches_for_another_users_item(
    client,
    db,
):
    owner = create_user(
        db,
        user_id=3019,
        username="match_item_private_owner",
    )

    outsider = create_user(
        db,
        user_id=3020,
        username="match_item_private_outsider",
    )

    item = create_item(
        db,
        owner_id=owner.id,
        item_type="lost",
    )

    response = client.get(
        f"/api/matches/items/{item.id}",
        headers=auth_headers(outsider),
    )

    assert response.status_code == 404


def test_nonexistent_item_returns_404_for_item_matches(
    client,
    db,
):
    user = create_user(
        db,
        user_id=3021,
        username="match_missing_item_user",
    )

    response = client.get(
        "/api/matches/items/999999999",
        headers=auth_headers(user),
    )

    assert response.status_code == 404


# ============================================================================
# DISMISS / RESTORE
# ============================================================================


def test_user_can_dismiss_own_match(
    client,
    db,
):
    lost_owner = create_user(
        db,
        user_id=3022,
        username="match_dismiss_lost",
    )

    found_owner = create_user(
        db,
        user_id=3023,
        username="match_dismiss_found",
    )

    lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
    )

    found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
    )

    match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    response = client.patch(
        f"/api/matches/{match.id}/dismiss",
        headers=auth_headers(lost_owner),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == match.id
    assert data["is_dismissed"] is True


def test_user_can_restore_own_dismissed_match(
    client,
    db,
):
    lost_owner = create_user(
        db,
        user_id=3024,
        username="match_restore_lost",
    )

    found_owner = create_user(
        db,
        user_id=3025,
        username="match_restore_found",
    )

    lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
    )

    found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
    )

    match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
        is_dismissed=True,
    )

    response = client.patch(
        f"/api/matches/{match.id}/restore",
        headers=auth_headers(lost_owner),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == match.id
    assert data["is_dismissed"] is False


def test_user_cannot_dismiss_another_users_match(
    client,
    db,
):
    lost_owner = create_user(
        db,
        user_id=3026,
        username="match_dismiss_private_lost",
    )

    found_owner = create_user(
        db,
        user_id=3027,
        username="match_dismiss_private_found",
    )

    outsider = create_user(
        db,
        user_id=3028,
        username="match_dismiss_private_outsider",
    )

    lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
    )

    found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
    )

    match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
    )

    response = client.patch(
        f"/api/matches/{match.id}/dismiss",
        headers=auth_headers(outsider),
    )

    assert response.status_code == 404


def test_user_cannot_restore_another_users_match(
    client,
    db,
):
    lost_owner = create_user(
        db,
        user_id=3029,
        username="match_restore_private_lost",
    )

    found_owner = create_user(
        db,
        user_id=3030,
        username="match_restore_private_found",
    )

    outsider = create_user(
        db,
        user_id=3031,
        username="match_restore_private_outsider",
    )

    lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
    )

    found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
    )

    match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
        is_dismissed=True,
    )

    response = client.patch(
        f"/api/matches/{match.id}/restore",
        headers=auth_headers(outsider),
    )

    assert response.status_code == 404


# ============================================================================
# DISMISSED MATCH FILTERING
# ============================================================================


def test_dismissed_matches_are_excluded_from_normal_listing(
    client,
    db,
):
    lost_owner = create_user(
        db,
        user_id=3032,
        username="match_filter_lost",
    )

    found_owner = create_user(
        db,
        user_id=3033,
        username="match_filter_found",
    )

    lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
    )

    found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
    )

    active_match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=found_item.id,
        score=90,
        is_dismissed=False,
    )

    dismissed_lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
        title="Dismissed Test Laptop",
    )

    dismissed_found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
        title="Dismissed Test Laptop",
    )

    dismissed_match = create_match(
        db,
        lost_item_id=dismissed_lost_item.id,
        found_item_id=dismissed_found_item.id,
        score=95,
        is_dismissed=True,
    )

    response = client.get(
        "/api/matches",
        headers=auth_headers(lost_owner),
    )

    assert response.status_code == 200

    data = response.json()

    returned_ids = {item["id"] for item in data}

    assert active_match.id in returned_ids
    assert dismissed_match.id not in returned_ids


def test_dismissed_matches_are_excluded_from_item_listing(
    client,
    db,
):
    lost_owner = create_user(
        db,
        user_id=3034,
        username="match_item_filter_lost",
    )

    found_owner = create_user(
        db,
        user_id=3035,
        username="match_item_filter_found",
    )

    lost_item = create_item(
        db,
        owner_id=lost_owner.id,
        item_type="lost",
    )

    active_found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
        title="Active Match Phone",
    )

    dismissed_found_item = create_item(
        db,
        owner_id=found_owner.id,
        item_type="found",
        title="Dismissed Match Phone",
    )

    active_match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=active_found_item.id,
        score=90,
        is_dismissed=False,
    )

    dismissed_match = create_match(
        db,
        lost_item_id=lost_item.id,
        found_item_id=dismissed_found_item.id,
        score=95,
        is_dismissed=True,
    )

    response = client.get(
        f"/api/matches/items/{lost_item.id}",
        headers=auth_headers(lost_owner),
    )

    assert response.status_code == 200

    data = response.json()

    returned_ids = {item["id"] for item in data}

    assert active_match.id in returned_ids
    assert dismissed_match.id not in returned_ids