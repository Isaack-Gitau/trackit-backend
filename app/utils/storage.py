"""
TRACKIT Media Storage Abstraction.

This module separates image storage from image validation and
sanitization.

The image security pipeline remains responsible for validating,
decoding, sanitizing, and generating storage keys. Storage backends
are responsible only for persisting already-sanitized image data.

Development and tests use the local filesystem backend.
Production can use an object-storage backend such as Cloudflare R2.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import BinaryIO

import boto3
import cloudinary
import cloudinary.uploader
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import settings


class StorageError(RuntimeError):
    """
    Base exception for storage backend failures.
    """


class StorageBackend(ABC):
    """
    Interface implemented by media storage backends.
    """

    @abstractmethod
    def save(
        self,
        source: BinaryIO,
        storage_key: str,
        content_type: str | None = None,
    ) -> None:
        """
        Persist an already-sanitized file under the given storage key.

        ``content_type`` is optional so storage backends can preserve the
        trusted MIME type of the sanitized object when supported.
        """

    @abstractmethod
    def delete(
        self,
        storage_key: str,
    ) -> None:
        """
        Delete a stored object.

        Deletion should be idempotent.
        """

    @abstractmethod
    def get_url(
        self,
        storage_key: str,
    ) -> str:
        """
        Return the browser-accessible URL for a stored object.
        """


class LocalStorageBackend(StorageBackend):
    """
    Local filesystem storage backend.

    Used by development and tests.

    Files are stored beneath MEDIA_ROOT using the supplied relative
    storage key.
    """

    def __init__(
        self,
        media_root: str,
        media_url: str,
    ) -> None:
        self.media_root = Path(
            media_root
        ).expanduser().resolve()

        self.media_url = media_url.rstrip("/")

    def _safe_path(
        self,
        storage_key: str,
    ) -> Path:
        """
        Resolve a storage key and ensure it remains inside MEDIA_ROOT.
        """

        if not storage_key:
            raise StorageError(
                "Storage key is required."
            )

        if "\\" in storage_key:
            raise StorageError(
                "Invalid storage key."
            )

        if storage_key.startswith("/"):
            raise StorageError(
                "Invalid storage key."
            )

        if ".." in Path(storage_key).parts:
            raise StorageError(
                "Invalid storage key."
            )

        path = (
            self.media_root / storage_key
        ).resolve()

        try:
            path.relative_to(
                self.media_root
            )
        except ValueError as exc:
            raise StorageError(
                "Unsafe storage path."
            ) from exc

        return path

    def save(
        self,
        source: BinaryIO,
        storage_key: str,
        content_type: str | None = None,
    ) -> None:
        """
        Persist an already-sanitized file.

        Local filesystem storage does not need MIME metadata, but accepts
        the optional content type to keep the backend interface consistent.

        The write uses a temporary file followed by an atomic replace.
        """

        del content_type

        destination = self._safe_path(
            storage_key
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temporary_path = destination.with_name(
            f".{destination.name}.tmp"
        )

        try:
            with temporary_path.open(
                "wb"
            ) as target:
                while True:
                    chunk = source.read(
                        64 * 1024
                    )

                    if not chunk:
                        break

                    if not isinstance(
                        chunk,
                        bytes,
                    ):
                        raise StorageError(
                            "Storage source must provide binary data."
                        )

                    target.write(chunk)

                target.flush()

            temporary_path.replace(
                destination
            )

        except StorageError:
            try:
                temporary_path.unlink(
                    missing_ok=True
                )
            except OSError:
                pass

            raise

        except OSError as exc:
            try:
                temporary_path.unlink(
                    missing_ok=True
                )
            except OSError:
                pass

            raise StorageError(
                "Failed to store object."
            ) from exc

    def delete(
        self,
        storage_key: str,
    ) -> None:
        """
        Delete a stored object.

        Missing files are ignored.
        """

        path = self._safe_path(
            storage_key
        )

        try:
            path.unlink(
                missing_ok=True
            )
        except OSError as exc:
            raise StorageError(
                "Failed to delete stored object."
            ) from exc

    def get_url(
        self,
        storage_key: str,
    ) -> str:
        """
        Convert a storage key into the local public media URL.
        """

        self._safe_path(
            storage_key
        )

        normalized_key = storage_key.lstrip("/")

        return (
            f"{self.media_url}/"
            f"{normalized_key}"
        )


class R2StorageBackend(StorageBackend):
    """
    Cloudflare R2 storage backend using the S3-compatible API.

    R2 credentials and bucket configuration are supplied through application
    settings. The boto3 client is created locally and network operations only
    occur when objects are uploaded or deleted.
    """

    def __init__(
        self,
        account_id: str,
        access_key_id: str,
        secret_access_key: str,
        bucket_name: str,
        public_base_url: str,
    ) -> None:
        values = {
            "R2_ACCOUNT_ID": account_id,
            "R2_ACCESS_KEY_ID": access_key_id,
            "R2_SECRET_ACCESS_KEY": secret_access_key,
            "R2_BUCKET_NAME": bucket_name,
            "R2_PUBLIC_BASE_URL": public_base_url,
        }

        missing = [
            name
            for name, value in values.items()
            if not value.strip()
        ]

        if missing:
            raise StorageError(
                "Missing R2 configuration: "
                + ", ".join(missing)
            )

        self.bucket_name = bucket_name.strip()
        self.public_base_url = public_base_url.rstrip("/")

        endpoint_url = (
            f"https://{account_id.strip()}.r2.cloudflarestorage.com"
        )

        try:
            self.client = boto3.client(
                "s3",
                endpoint_url=endpoint_url,
                aws_access_key_id=access_key_id.strip(),
                aws_secret_access_key=secret_access_key.strip(),
                region_name="auto",
            )
        except (BotoCoreError, ClientError) as exc:
            raise StorageError(
                "Failed to initialize R2 storage client."
            ) from exc

    def save(
        self,
        source: BinaryIO,
        storage_key: str,
        content_type: str | None = None,
    ) -> None:
        """
        Upload an already-sanitized object to R2.

        When supplied, ``content_type`` is stored as the object's HTTP
        Content-Type metadata.
        """

        try:
            if content_type is None:
                self.client.upload_fileobj(
                    source,
                    self.bucket_name,
                    storage_key,
                )
            else:
                self.client.upload_fileobj(
                    source,
                    self.bucket_name,
                    storage_key,
                    ExtraArgs={
                        "ContentType": content_type,
                    },
                )
        except (BotoCoreError, ClientError, OSError) as exc:
            raise StorageError(
                "Failed to store object in R2."
            ) from exc

    def delete(
        self,
        storage_key: str,
    ) -> None:
        """
        Delete an object from R2.

        R2/S3 object deletion is treated as idempotent.
        """

        try:
            self.client.delete_object(
                Bucket=self.bucket_name,
                Key=storage_key,
            )
        except (BotoCoreError, ClientError, OSError) as exc:
            raise StorageError(
                "Failed to delete object from R2."
            ) from exc

    def get_url(
        self,
        storage_key: str,
    ) -> str:
        """
        Return the public URL for an R2 object.

        No network request is made.
        """

        normalized_base_url = self.public_base_url.rstrip("/")

        return (
            f"{normalized_base_url}/"
            f"{storage_key.lstrip('/')}"
        )


class CloudinaryStorageBackend(StorageBackend):
    """
    Cloudinary image storage backend.

    Cloudinary uses a public ID rather than a filesystem path. TrackIt
    continues to store its normal storage key, while this backend maps
    that key to a Cloudinary public ID by removing the image extension.
    """

    def __init__(
        self,
        cloud_name: str,
        api_key: str,
        api_secret: str,
    ) -> None:
        values = {
            "CLOUDINARY_CLOUD_NAME": cloud_name,
            "CLOUDINARY_API_KEY": api_key,
            "CLOUDINARY_API_SECRET": api_secret,
        }

        missing = [
            name
            for name, value in values.items()
            if not value.strip()
        ]

        if missing:
            raise StorageError(
                "Missing Cloudinary configuration: "
                + ", ".join(missing)
            )

        self.cloud_name = cloud_name.strip()
        self.api_key = api_key.strip()
        self.api_secret = api_secret.strip()

        try:
            cloudinary.config(
                cloud_name=self.cloud_name,
                api_key=self.api_key,
                api_secret=self.api_secret,
                secure=True,
            )
        except Exception as exc:
            raise StorageError(
                "Failed to initialize Cloudinary storage."
            ) from exc

    @staticmethod
    def _public_id(
        storage_key: str,
    ) -> str:
        """
        Convert a TrackIt storage key into a Cloudinary public ID.
        """

        if not storage_key:
            raise StorageError(
                "Storage key is required."
            )

        if "\\" in storage_key:
            raise StorageError(
                "Invalid storage key."
            )

        if storage_key.startswith("/"):
            raise StorageError(
                "Invalid storage key."
            )

        parts = Path(storage_key).parts

        if len(parts) != 2:
            raise StorageError(
                "Invalid storage key."
            )

        if parts[0] not in {"items", "profiles"}:
            raise StorageError(
                "Invalid storage key."
            )

        filename = parts[1]

        if not filename or filename in {".", ".."}:
            raise StorageError(
                "Invalid storage key."
            )

        if Path(filename).suffix.lower() not in {
            ".jpg",
            ".jpeg",
            ".png",
            ".webp",
        }:
            raise StorageError(
                "Invalid storage key."
            )

        return str(Path(parts[0]) / Path(filename).stem)

    def save(
        self,
        source: BinaryIO,
        storage_key: str,
        content_type: str | None = None,
    ) -> None:
        """
        Upload an already-sanitized image to Cloudinary.
        """

        del content_type

        public_id = self._public_id(
            storage_key
        )

        try:
            source.seek(0)

            cloudinary.uploader.upload(
                source,
                public_id=public_id,
                resource_type="image",
                overwrite=False,
            )
        except Exception as exc:
            raise StorageError(
                "Failed to store object in Cloudinary."
            ) from exc

    def delete(
        self,
        storage_key: str,
    ) -> None:
        """
        Delete a Cloudinary image.

        Missing assets are treated as an idempotent delete.
        """

        public_id = self._public_id(
            storage_key
        )

        try:
            result = cloudinary.uploader.destroy(
                public_id,
                resource_type="image",
                type="upload",
                invalidate=True,
            )

            if result.get("result") not in {
                "ok",
                "not found",
            }:
                raise StorageError(
                    "Failed to delete object from Cloudinary."
                )
        except StorageError:
            raise
        except Exception as exc:
            raise StorageError(
                "Failed to delete object from Cloudinary."
            ) from exc

    def get_url(
        self,
        storage_key: str,
    ) -> str:
        """
        Return the browser-accessible Cloudinary URL.

        No network request is made.
        """

        public_id = self._public_id(
            storage_key
        )

        try:
            url, _ = cloudinary.utils.cloudinary_url(
                public_id,
                resource_type="image",
                type="upload",
                secure=True,
            )
        except Exception as exc:
            raise StorageError(
                "Failed to generate Cloudinary URL."
            ) from exc

        return url



def get_storage_backend() -> StorageBackend:
    """
    Return the configured media storage backend.
    """

    backend = settings.STORAGE_BACKEND.strip().lower()

    if backend == "local":
        return LocalStorageBackend(
            media_root=settings.MEDIA_ROOT,
            media_url=settings.MEDIA_URL,
        )

    if backend == "r2":
        return R2StorageBackend(
            account_id=settings.R2_ACCOUNT_ID,
            access_key_id=settings.R2_ACCESS_KEY_ID,
            secret_access_key=settings.R2_SECRET_ACCESS_KEY,
            bucket_name=settings.R2_BUCKET_NAME,
            public_base_url=settings.R2_PUBLIC_BASE_URL,
        )

    if backend == "cloudinary":
        return CloudinaryStorageBackend(
            cloud_name=settings.CLOUDINARY_CLOUD_NAME,
            api_key=settings.CLOUDINARY_API_KEY,
            api_secret=settings.CLOUDINARY_API_SECRET,
        )

    raise StorageError(
        f"Unsupported storage backend: {settings.STORAGE_BACKEND}"
    )
