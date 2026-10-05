from io import BytesIO
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError

from app.core.config import settings
from app.utils.storage import (
    CloudinaryStorageBackend,
    LocalStorageBackend,
    R2StorageBackend,
    StorageError,
    get_storage_backend,
)


def test_save_and_get_url(tmp_path):
    backend = LocalStorageBackend(
        media_root=str(tmp_path),
        media_url="/media",
    )

    source = BytesIO(b"trackit-test-image")

    backend.save(source, "items/example.webp")

    stored_path = tmp_path / "items" / "example.webp"

    assert stored_path.exists()
    assert stored_path.read_bytes() == b"trackit-test-image"
    assert backend.get_url("items/example.webp") == (
        "/media/items/example.webp"
    )


def test_save_creates_nested_directories(tmp_path):
    backend = LocalStorageBackend(
        media_root=str(tmp_path),
        media_url="/media",
    )

    backend.save(
        BytesIO(b"profile-data"),
        "profiles/example.webp",
    )

    stored_path = tmp_path / "profiles" / "example.webp"

    assert stored_path.exists()
    assert stored_path.read_bytes() == b"profile-data"


def test_delete_is_idempotent(tmp_path):
    backend = LocalStorageBackend(
        media_root=str(tmp_path),
        media_url="/media",
    )

    backend.save(
        BytesIO(b"delete-me"),
        "items/example.webp",
    )

    stored_path = tmp_path / "items" / "example.webp"
    assert stored_path.exists()

    backend.delete("items/example.webp")
    assert not stored_path.exists()

    backend.delete("items/example.webp")
    assert not stored_path.exists()


@pytest.mark.parametrize(
    "storage_key",
    [
        "",
        "/items/example.webp",
        r"items\\example.webp",
        "../secret.webp",
        "../../secret.webp",
        "items/../secret.webp",
        "items/../../secret.webp",
    ],
)
def test_rejects_unsafe_storage_keys(tmp_path, storage_key):
    backend = LocalStorageBackend(
        media_root=str(tmp_path),
        media_url="/media",
    )

    with pytest.raises(StorageError):
        backend.save(
            BytesIO(b"unsafe"),
            storage_key,
        )


def test_get_url_rejects_unsafe_storage_key(tmp_path):
    backend = LocalStorageBackend(
        media_root=str(tmp_path),
        media_url="/media",
    )

    with pytest.raises(StorageError):
        backend.get_url("../secret.webp")


def test_delete_rejects_unsafe_storage_key(tmp_path):
    backend = LocalStorageBackend(
        media_root=str(tmp_path),
        media_url="/media",
    )

    with pytest.raises(StorageError):
        backend.delete("../secret.webp")


def test_r2_requires_complete_configuration():
    with pytest.raises(
        StorageError,
        match="Missing R2 configuration",
    ):
        R2StorageBackend(
            account_id="",
            access_key_id="access-key",
            secret_access_key="secret-key",
            bucket_name="trackit",
            public_base_url="https://media.example.com",
        )


@patch("app.utils.storage.boto3.client")
def test_r2_initializes_s3_client(mock_boto_client):
    mock_client = Mock()
    mock_boto_client.return_value = mock_client

    backend = R2StorageBackend(
        account_id="account123",
        access_key_id="access-key",
        secret_access_key="secret-key",
        bucket_name="trackit-media",
        public_base_url="https://media.example.com",
    )

    assert backend.bucket_name == "trackit-media"
    assert backend.public_base_url == "https://media.example.com"

    mock_boto_client.assert_called_once_with(
        "s3",
        endpoint_url=(
            "https://account123.r2.cloudflarestorage.com"
        ),
        aws_access_key_id="access-key",
        aws_secret_access_key="secret-key",
        region_name="auto",
    )


@patch("app.utils.storage.boto3.client")
def test_r2_save_uploads_object(mock_boto_client):
    mock_client = Mock()
    mock_boto_client.return_value = mock_client

    backend = R2StorageBackend(
        account_id="account123",
        access_key_id="access-key",
        secret_access_key="secret-key",
        bucket_name="trackit-media",
        public_base_url="https://media.example.com",
    )

    source = BytesIO(b"sanitized-image")

    backend.save(
        source,
        "items/example.webp",
    )

    mock_client.upload_fileobj.assert_called_once_with(
        source,
        "trackit-media",
        "items/example.webp",
    )


@patch("app.utils.storage.boto3.client")
def test_r2_save_uploads_object_with_content_type(mock_boto_client):
    mock_client = Mock()
    mock_boto_client.return_value = mock_client

    backend = R2StorageBackend(
        account_id="account123",
        access_key_id="access-key",
        secret_access_key="secret-key",
        bucket_name="trackit-media",
        public_base_url="https://media.example.com",
    )

    source = BytesIO(b"sanitized-webp")

    backend.save(
        source,
        "items/example.webp",
        content_type="image/webp",
    )

    mock_client.upload_fileobj.assert_called_once_with(
        source,
        "trackit-media",
        "items/example.webp",
        ExtraArgs={
            "ContentType": "image/webp",
        },
    )


@patch("app.utils.storage.boto3.client")
def test_r2_delete_deletes_object(mock_boto_client):
    mock_client = Mock()
    mock_boto_client.return_value = mock_client

    backend = R2StorageBackend(
        account_id="account123",
        access_key_id="access-key",
        secret_access_key="secret-key",
        bucket_name="trackit-media",
        public_base_url="https://media.example.com",
    )

    backend.delete("items/example.webp")

    mock_client.delete_object.assert_called_once_with(
        Bucket="trackit-media",
        Key="items/example.webp",
    )


@patch("app.utils.storage.boto3.client")
def test_r2_get_url_does_not_call_storage(mock_boto_client):
    mock_client = Mock()
    mock_boto_client.return_value = mock_client

    backend = R2StorageBackend(
        account_id="account123",
        access_key_id="access-key",
        secret_access_key="secret-key",
        bucket_name="trackit-media",
        public_base_url="https://media.example.com/",
    )

    url = backend.get_url(
        "items/example.webp"
    )

    assert url == (
        "https://media.example.com/items/example.webp"
    )
    mock_client.assert_not_called()


@patch("app.utils.storage.boto3.client")
def test_r2_save_converts_client_error_to_storage_error(
    mock_boto_client,
):
    mock_client = Mock()
    mock_boto_client.return_value = mock_client

    mock_client.upload_fileobj.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "PutObject",
    )

    backend = R2StorageBackend(
        account_id="account123",
        access_key_id="access-key",
        secret_access_key="secret-key",
        bucket_name="trackit-media",
        public_base_url="https://media.example.com",
    )

    with pytest.raises(
        StorageError,
        match="Failed to store object in R2.",
    ):
        backend.save(
            BytesIO(b"image"),
            "items/example.webp",
        )


@patch("app.utils.storage.boto3.client")
def test_r2_delete_converts_client_error_to_storage_error(
    mock_boto_client,
):
    mock_client = Mock()
    mock_boto_client.return_value = mock_client

    mock_client.delete_object.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "DeleteObject",
    )

    backend = R2StorageBackend(
        account_id="account123",
        access_key_id="access-key",
        secret_access_key="secret-key",
        bucket_name="trackit-media",
        public_base_url="https://media.example.com",
    )

    with pytest.raises(
        StorageError,
        match="Failed to delete object from R2.",
    ):
        backend.delete(
            "items/example.webp"
        )


def test_cloudinary_requires_complete_configuration():
    with pytest.raises(
        StorageError,
        match="Missing Cloudinary configuration",
    ):
        CloudinaryStorageBackend(
            cloud_name="",
            api_key="api-key",
            api_secret="api-secret",
        )


@patch("app.utils.storage.cloudinary.config")
def test_cloudinary_initializes_configuration(mock_cloudinary_config):
    backend = CloudinaryStorageBackend(
        cloud_name="trackit-cloud",
        api_key="api-key",
        api_secret="api-secret",
    )

    assert backend.cloud_name == "trackit-cloud"
    assert backend.api_key == "api-key"
    assert backend.api_secret == "api-secret"

    mock_cloudinary_config.assert_called_once_with(
        cloud_name="trackit-cloud",
        api_key="api-key",
        api_secret="api-secret",
        secure=True,
    )


@patch("app.utils.storage.cloudinary.uploader.upload")
def test_cloudinary_save_uploads_image(mock_upload):
    backend = CloudinaryStorageBackend(
        cloud_name="trackit-cloud",
        api_key="api-key",
        api_secret="api-secret",
    )

    source = BytesIO(b"sanitized-image")

    backend.save(
        source,
        "items/example.webp",
        content_type="image/webp",
    )

    mock_upload.assert_called_once_with(
        source,
        public_id="items/example",
        resource_type="image",
        overwrite=False,
    )


@patch("app.utils.storage.cloudinary.uploader.destroy")
def test_cloudinary_delete_deletes_image(mock_destroy):
    mock_destroy.return_value = {
        "result": "ok",
    }

    backend = CloudinaryStorageBackend(
        cloud_name="trackit-cloud",
        api_key="api-key",
        api_secret="api-secret",
    )

    backend.delete("items/example.webp")

    mock_destroy.assert_called_once_with(
        "items/example",
        resource_type="image",
        type="upload",
        invalidate=True,
    )


@patch("app.utils.storage.cloudinary.utils.cloudinary_url")
def test_cloudinary_get_url_generates_url_without_network(
    mock_cloudinary_url,
):
    mock_cloudinary_url.return_value = (
        "https://res.cloudinary.com/trackit/image/upload/"
        "items/example",
        {},
    )

    backend = CloudinaryStorageBackend(
        cloud_name="trackit-cloud",
        api_key="api-key",
        api_secret="api-secret",
    )

    url = backend.get_url("items/example.webp")

    assert url == (
        "https://res.cloudinary.com/trackit/image/upload/"
        "items/example"
    )

    mock_cloudinary_url.assert_called_once_with(
        "items/example",
        resource_type="image",
        type="upload",
        secure=True,
    )


@pytest.mark.parametrize(
    "storage_key",
    [
        "",
        "/items/example.webp",
        r"items\\example.webp",
        "../secret.webp",
        "../../secret.webp",
        "items/../secret.webp",
        "items/../../secret.webp",
        "documents/example.webp",
        "items/example.txt",
    ],
)
def test_cloudinary_rejects_unsafe_storage_keys(storage_key):
    backend = CloudinaryStorageBackend(
        cloud_name="trackit-cloud",
        api_key="api-key",
        api_secret="api-secret",
    )

    with pytest.raises(StorageError):
        backend.get_url(storage_key)


@patch("app.utils.storage.CloudinaryStorageBackend")
def test_storage_factory_selects_cloudinary(mock_cloudinary_backend):
    original_backend = settings.STORAGE_BACKEND

    settings.STORAGE_BACKEND = "cloudinary"

    try:
        backend = get_storage_backend()
    finally:
        settings.STORAGE_BACKEND = original_backend

    mock_cloudinary_backend.assert_called_once_with(
        cloud_name=settings.CLOUDINARY_CLOUD_NAME,
        api_key=settings.CLOUDINARY_API_KEY,
        api_secret=settings.CLOUDINARY_API_SECRET,
    )

    assert backend is mock_cloudinary_backend.return_value


@patch("app.utils.storage.R2StorageBackend")
def test_storage_factory_selects_r2(mock_r2_backend):
    original_backend = settings.STORAGE_BACKEND

    settings.STORAGE_BACKEND = "r2"

    try:
        backend = get_storage_backend()
    finally:
        settings.STORAGE_BACKEND = original_backend

    mock_r2_backend.assert_called_once_with(
        account_id=settings.R2_ACCOUNT_ID,
        access_key_id=settings.R2_ACCESS_KEY_ID,
        secret_access_key=settings.R2_SECRET_ACCESS_KEY,
        bucket_name=settings.R2_BUCKET_NAME,
        public_base_url=settings.R2_PUBLIC_BASE_URL,
    )

    assert backend is mock_r2_backend.return_value
