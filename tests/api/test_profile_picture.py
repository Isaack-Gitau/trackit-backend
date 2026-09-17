"""
TRACKIT Profile Picture API Tests.

Coverage:

- Profile picture upload requires authentication.
- Valid profile pictures are accepted.
- Uploaded profile pictures are stored beneath profiles/.
- The authenticated user's profile_picture is updated.
- Invalid image uploads are rejected.
- Replacing a profile picture removes the previous stored image.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.user import User
from tests.api.test_profile import authenticated_headers
from tests.api.test_profile import create_test_user


# ============================================================================
# TEST HELPERS
# ============================================================================


def make_png_bytes() -> bytes:
    """
    Create a small valid PNG image in memory.
    """

    import io

    image = Image.new(
        "RGBA",
        (100, 100),
        color="red",
    )

    buffer = io.BytesIO()

    try:
        image.save(
            buffer,
            format="PNG",
        )
    finally:
        image.close()

    return buffer.getvalue()


# ============================================================================
# AUTHENTICATION
# ============================================================================


def test_upload_profile_picture_requires_authentication(
    client: TestClient,
):
    """
    Profile picture upload requires authentication.
    """

    response = client.post(
        "/api/profile/picture",
        files={
            "image": (
                "profile.png",
                make_png_bytes(),
                "image/png",
            )
        },
    )

    assert response.status_code == 401


# ============================================================================
# SUCCESSFUL UPLOAD
# ============================================================================


def test_upload_profile_picture_stores_profile_image(
    client: TestClient,
    db: Session,
    monkeypatch,
    tmp_path: Path,
):
    """
    A valid profile picture is sanitized, stored under profiles/,
    and saved on the authenticated user's profile.
    """

    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    user = create_test_user(
        db,
        user_id=1201,
        username="pictureuser",
        email="pictureuser@example.com",
    )

    response = client.post(
        "/api/profile/picture",
        headers=authenticated_headers(user),
        files={
            "image": (
                "avatar.png",
                make_png_bytes(),
                "image/png",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == user.id
    assert data["profile_picture"] is not None
    assert data["profile_picture"].startswith("profiles/")
    assert data["profile_picture"].endswith(".png")

    stored_key = data["profile_picture"]
    stored_path = tmp_path / stored_key

    assert stored_path.exists()
    assert stored_path.is_file()

    db.refresh(user)

    assert user.profile_picture == stored_key


def test_upload_profile_picture_ignores_client_filename(
    client: TestClient,
    db: Session,
    monkeypatch,
    tmp_path: Path,
):
    """
    The original client-provided filename is never used as the
    storage filename.
    """

    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    user = create_test_user(
        db,
        user_id=1202,
        username="filenameuser",
        email="filenameuser@example.com",
    )

    response = client.post(
        "/api/profile/picture",
        headers=authenticated_headers(user),
        files={
            "image": (
                "../../avatar.png",
                make_png_bytes(),
                "image/png",
            )
        },
    )

    assert response.status_code == 200

    stored_key = response.json()["profile_picture"]

    assert stored_key.startswith("profiles/")
    assert "../../" not in stored_key
    assert stored_key != "profiles/avatar.png"

    assert (tmp_path / stored_key).is_file()


# ============================================================================
# INVALID UPLOAD
# ============================================================================


def test_upload_profile_picture_rejects_invalid_image(
    client: TestClient,
    db: Session,
    monkeypatch,
    tmp_path: Path,
):
    """
    Invalid image content is rejected with HTTP 400 and does not
    modify the user's existing profile picture.
    """

    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    user = create_test_user(
        db,
        user_id=1203,
        username="invalidpicture",
        email="invalidpicture@example.com",
    )

    user.profile_picture = "profiles/existing.png"
    db.flush()

    response = client.post(
        "/api/profile/picture",
        headers=authenticated_headers(user),
        files={
            "image": (
                "not-an-image.png",
                b"this is not an image",
                "image/png",
            )
        },
    )

    assert response.status_code == 400

    db.refresh(user)

    assert user.profile_picture == "profiles/existing.png"

    profiles_directory = tmp_path / "profiles"

    if profiles_directory.exists():
        assert list(profiles_directory.iterdir()) == []


# ============================================================================
# REPLACEMENT
# ============================================================================


def test_upload_profile_picture_replaces_previous_image(
    client: TestClient,
    db: Session,
    monkeypatch,
    tmp_path: Path,
):
    """
    Replacing a profile picture updates the database reference and
    removes the previous stored image after a successful commit.
    """

    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    profiles_directory = tmp_path / "profiles"
    profiles_directory.mkdir(parents=True)

    previous_path = profiles_directory / "old-profile.png"
    previous_path.write_bytes(make_png_bytes())

    user = create_test_user(
        db,
        user_id=1204,
        username="replacepicture",
        email="replacepicture@example.com",
    )

    user.profile_picture = "profiles/old-profile.png"
    db.flush()

    response = client.post(
        "/api/profile/picture",
        headers=authenticated_headers(user),
        files={
            "image": (
                "new-profile.png",
                make_png_bytes(),
                "image/png",
            )
        },
    )

    assert response.status_code == 200

    new_key = response.json()["profile_picture"]

    assert new_key.startswith("profiles/")
    assert new_key != "profiles/old-profile.png"

    assert not previous_path.exists()
    assert (tmp_path / new_key).is_file()

    db.refresh(user)

    assert user.profile_picture == new_key


# ============================================================================
# DELETE
# ============================================================================


def test_delete_profile_picture_requires_authentication(
    client: TestClient,
):
    """
    Profile picture deletion requires authentication.
    """

    response = client.delete(
        "/api/profile/picture",
    )

    assert response.status_code == 401


def test_delete_profile_picture_removes_database_reference_and_file(
    client: TestClient,
    db: Session,
    monkeypatch,
    tmp_path: Path,
):
    """
    Deleting a profile picture clears the database reference and
    removes the physical stored image after the successful commit.
    """

    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    profiles_directory = tmp_path / "profiles"
    profiles_directory.mkdir(parents=True)

    picture_path = profiles_directory / "profile-to-delete.png"
    picture_path.write_bytes(make_png_bytes())

    user = create_test_user(
        db,
        user_id=1205,
        username="deletepicture",
        email="deletepicture@example.com",
    )

    user.profile_picture = "profiles/profile-to-delete.png"
    db.flush()

    assert picture_path.exists()

    response = client.delete(
        "/api/profile/picture",
        headers=authenticated_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == user.id
    assert data["profile_picture"] is None

    db.refresh(user)

    assert user.profile_picture is None
    assert not picture_path.exists()


def test_delete_profile_picture_without_existing_picture(
    client: TestClient,
    db: Session,
    monkeypatch,
    tmp_path: Path,
):
    """
    Deleting a profile picture when none exists is a successful
    no-op and does not create or remove any files.
    """

    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    user = create_test_user(
        db,
        user_id=1206,
        username="nopicture",
        email="nopicture@example.com",
    )

    assert user.profile_picture is None

    response = client.delete(
        "/api/profile/picture",
        headers=authenticated_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == user.id
    assert data["profile_picture"] is None

    db.refresh(user)

    assert user.profile_picture is None

    profiles_directory = tmp_path / "profiles"

    if profiles_directory.exists():
        assert list(profiles_directory.iterdir()) == []