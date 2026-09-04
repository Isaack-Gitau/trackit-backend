"""
TRACKIT Image Upload Security Utilities.

Provides secure validation, sanitization, naming, and storage
for user-uploaded images.

Security principles:
- Never trust the original filename.
- Never trust the client-provided MIME type.
- Enforce upload size before image processing.
- Decode images with Pillow.
- Restrict accepted image formats.
- Enforce image dimension and pixel limits.
- Fully decode uploaded images.
- Rebuild images from decoded pixel data.
- Remove original metadata by re-encoding.
- Generate cryptographically random server-side filenames.
- Store only relative storage keys in the database.
- Prevent path traversal.
- Clean up partial files when processing fails.
"""

from __future__ import annotations

import io
import secrets
import warnings
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from PIL import Image, UnidentifiedImageError
from PIL.Image import DecompressionBombError, DecompressionBombWarning

from app.core.config import settings


# ============================================================================
# Exceptions
# ============================================================================


class ImageUploadError(ValueError):
    """
    Base exception for invalid or unsafe image uploads.
    """


class ImageTooLargeError(ImageUploadError):
    """
    Raised when the uploaded file exceeds the configured byte limit.
    """


class ImageFormatError(ImageUploadError):
    """
    Raised when the uploaded file is not an allowed image format.
    """


class ImageDimensionsError(ImageUploadError):
    """
    Raised when an image exceeds the configured dimensions or pixel limit.
    """


class ImageProcessingError(ImageUploadError):
    """
    Raised when Pillow cannot safely decode or process an image.
    """


# ============================================================================
# Configuration Helpers
# ============================================================================


def _allowed_formats() -> set[str]:
    """
    Return the configured set of allowed Pillow image formats.

    The configuration is stored as a comma-separated environment value,
    for example:

        JPEG,PNG,WEBP
    """

    return {
        image_format.strip().upper()
        for image_format in settings.IMAGE_ALLOWED_FORMATS.split(",")
        if image_format.strip()
    }


def _extension_for_format(image_format: str) -> str:
    """
    Return the safe file extension corresponding to a Pillow format.
    """

    extensions = {
        "JPEG": ".jpg",
        "PNG": ".png",
        "WEBP": ".webp",
    }

    try:
        return extensions[image_format.upper()]
    except KeyError as exc:
        raise ImageFormatError(
            f"Unsupported image format: {image_format}"
        ) from exc


def _pillow_format(image_format: str) -> str:
    """
    Normalize a Pillow image format name.

    Only explicitly configured formats are allowed.
    """

    normalized = image_format.strip().upper()

    if normalized not in _allowed_formats():
        raise ImageFormatError(
            f"Unsupported image format: {image_format}"
        )

    return normalized


# ============================================================================
# Byte Validation
# ============================================================================


def validate_image_size(data: bytes) -> None:
    """
    Enforce the configured maximum upload size.

    This checks the actual number of bytes received rather than relying
    on a client-provided Content-Length header.
    """

    if len(data) > settings.IMAGE_MAX_SIZE_BYTES:
        raise ImageTooLargeError(
            "Image exceeds the maximum allowed upload size."
        )


def _read_upload(
    source: bytes | bytearray | BinaryIO,
) -> bytes:
    """
    Read upload data into memory while enforcing the configured size limit.

    When a binary stream is supplied, the limit is enforced while reading.
    """

    maximum = settings.IMAGE_MAX_SIZE_BYTES

    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
        validate_image_size(data)
        return data

    if not hasattr(source, "read"):
        raise ImageProcessingError(
            "Image source must be bytes or a readable binary stream."
        )

    chunks: list[bytes] = []
    total_size = 0
    chunk_size = 64 * 1024

    while True:
        try:
            chunk = source.read(chunk_size)
        except Exception as exc:
            raise ImageProcessingError(
                "Failed to read image source."
            ) from exc

        if not chunk:
            break

        if not isinstance(chunk, bytes):
            raise ImageProcessingError(
                "Image source must provide binary data."
            )

        total_size += len(chunk)

        if total_size > maximum:
            raise ImageTooLargeError(
                "Image exceeds the maximum allowed upload size."
            )

        chunks.append(chunk)

    return b"".join(chunks)


# ============================================================================
# Pillow Security Configuration
# ============================================================================


def _configure_pillow_limits() -> None:
    """
    Configure Pillow's decompression-bomb protection.

    TRACKIT also performs an explicit pixel-limit check after decoding.
    """

    Image.MAX_IMAGE_PIXELS = settings.IMAGE_MAX_PIXELS


# ============================================================================
# Image Decoding
# ============================================================================


def _open_image(
    data: bytes,
) -> tuple[Image.Image, str]:
    """
    Decode image bytes with Pillow and return:

        (decoded_image, detected_format)

    The detected format is returned separately because Pillow image copies
    do not necessarily preserve the original ``image.format`` attribute.
    """

    _configure_pillow_limits()

    try:
        # Treat Pillow's decompression-bomb warning as an error.
        #
        # This ensures images exceeding the configured pixel limit are
        # rejected rather than merely producing a warning.
        with warnings.catch_warnings():
            warnings.simplefilter("error", DecompressionBombWarning)

            with Image.open(io.BytesIO(data)) as image:
                image_format = image.format

                if not image_format:
                    raise ImageFormatError(
                        "Unable to determine the image format."
                    )

                normalized_format = image_format.upper()

                if normalized_format not in _allowed_formats():
                    raise ImageFormatError(
                        "Image format is not allowed."
                    )

                # Force complete decoding while the original byte stream
                # remains available.
                image.load()

                # Make a detached pixel-data copy. The format is returned
                # separately because image.copy() may set .format to None.
                decoded = image.copy()

    except ImageFormatError:
        raise

    except (DecompressionBombError, DecompressionBombWarning) as exc:
        raise ImageDimensionsError(
            "Image exceeds the maximum safe pixel limit."
        ) from exc

    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ImageProcessingError(
            "The uploaded file is not a valid image."
        ) from exc

    return decoded, normalized_format


# ============================================================================
# Dimension Validation
# ============================================================================


def validate_image_dimensions(image: Image.Image) -> None:
    """
    Enforce maximum width, height, and total pixel count.
    """

    width, height = image.size

    if width <= 0 or height <= 0:
        raise ImageDimensionsError(
            "Image dimensions are invalid."
        )

    if width > settings.IMAGE_MAX_WIDTH:
        raise ImageDimensionsError(
            "Image width exceeds the maximum allowed dimension."
        )

    if height > settings.IMAGE_MAX_HEIGHT:
        raise ImageDimensionsError(
            "Image height exceeds the maximum allowed dimension."
        )

    pixel_count = width * height

    if pixel_count > settings.IMAGE_MAX_PIXELS:
        raise ImageDimensionsError(
            "Image contains too many pixels."
        )


# ============================================================================
# Image Normalization
# ============================================================================


def _normalize_image(
    image: Image.Image,
    output_format: str,
) -> Image.Image:
    """
    Normalize an image before safe re-encoding.

    The resulting image contains pixel data only. Original EXIF, ICC,
    XMP, comments, thumbnails, and other metadata are not copied.
    """

    output_format = _pillow_format(output_format)

    # ------------------------------------------------------------------------
    # JPEG
    # ------------------------------------------------------------------------

    if output_format == "JPEG":
        # JPEG cannot store alpha channels.
        if image.mode in ("RGBA", "LA"):
            background = Image.new(
                "RGB",
                image.size,
                "white",
            )

            alpha = image.getchannel("A")
            background.paste(
                image,
                mask=alpha,
            )

            return background

        # Palette images may contain transparency.
        if image.mode == "P":
            converted = image.convert("RGBA")

            background = Image.new(
                "RGB",
                converted.size,
                "white",
            )

            alpha = converted.getchannel("A")

            background.paste(
                converted,
                mask=alpha,
            )

            converted.close()

            return background

        if image.mode != "RGB":
            return image.convert("RGB")

        return image.copy()

    # ------------------------------------------------------------------------
    # PNG / WebP
    # ------------------------------------------------------------------------

    if image.mode in ("RGB", "RGBA"):
        return image.copy()

    if image.mode == "P":
        return image.convert("RGBA")

    return image.convert("RGBA")


# ============================================================================
# Filename Generation
# ============================================================================


def generate_image_filename(image_format: str) -> str:
    """
    Generate a cryptographically random server-side filename.

    The original client filename is never used.

    Example:

        4f9c3e...a8.webp
    """

    normalized_format = _pillow_format(image_format)
    extension = _extension_for_format(normalized_format)

    # 32 random bytes = 256 bits of randomness.
    random_name = secrets.token_hex(32)

    return f"{random_name}{extension}"


# ============================================================================
# Storage Path Security
# ============================================================================


def _media_root() -> Path:
    """
    Return the resolved media root directory.
    """

    return Path(settings.MEDIA_ROOT).expanduser().resolve()


def _items_directory() -> Path:
    """
    Return the directory used for item images.

    Images are stored beneath:

        MEDIA_ROOT/items/
    """

    return (_media_root() / "items").resolve()


def _ensure_safe_path(
    path: Path,
    root: Path,
) -> Path:
    """
    Ensure a resolved path remains inside the expected storage root.
    """

    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ImageProcessingError(
            "Unsafe image storage path."
        ) from exc

    return path


def _safe_storage_path(filename: str) -> Path:
    """
    Construct and validate the filesystem path for an image filename.

    Only a single filename component is accepted.
    """

    if (
        not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
    ):
        raise ImageProcessingError(
            "Invalid image filename."
        )

    pure_path = PurePosixPath(filename)

    if len(pure_path.parts) != 1:
        raise ImageProcessingError(
            "Invalid image filename."
        )

    root = _items_directory()
    path = (root / filename).resolve()

    return _ensure_safe_path(path, root)


# ============================================================================
# Safe Image Saving
# ============================================================================


def _save_sanitized_image(
    image: Image.Image,
    image_format: str,
) -> tuple[str, Path]:
    """
    Re-encode and safely store an image.

    The output is written using a newly generated filename.
    Existing files are never intentionally overwritten.
    """

    normalized_format = _pillow_format(image_format)
    sanitized_image = _normalize_image(
        image,
        normalized_format,
    )

    directory = _items_directory()
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        # Try several times in the extremely unlikely event of a
        # filename collision.
        for _ in range(10):
            filename = generate_image_filename(
                normalized_format
            )

            destination = _safe_storage_path(filename)

            if destination.exists():
                continue

            # Temporary files are still placed beneath MEDIA_ROOT/items/.
            temporary_name = f".{secrets.token_hex(16)}.tmp"
            temporary_path = _safe_storage_path(temporary_name)

            try:
                save_kwargs: dict[str, object] = {
                    "format": normalized_format,
                }

                if normalized_format == "JPEG":
                    save_kwargs.update(
                        {
                            "quality": 90,
                            "optimize": True,
                        }
                    )

                elif normalized_format == "WEBP":
                    save_kwargs.update(
                        {
                            "quality": 90,
                            "method": 6,
                        }
                    )

                elif normalized_format == "PNG":
                    save_kwargs.update(
                        {
                            "optimize": True,
                        }
                    )

                # Deliberately do not pass:
                # - EXIF
                # - ICC
                # - XMP
                # - comments
                # - thumbnails
                # - arbitrary metadata
                sanitized_image.save(
                    temporary_path,
                    **save_kwargs,
                )

                # The generated destination name is random. Replacing
                # an existing file is therefore extremely unlikely.
                temporary_path.replace(destination)

                return (
                    f"items/{filename}",
                    destination,
                )

            except Exception as exc:
                try:
                    temporary_path.unlink(
                        missing_ok=True
                    )
                except OSError:
                    pass

                raise ImageProcessingError(
                    "Failed to safely store the image."
                ) from exc

        raise ImageProcessingError(
            "Unable to generate a unique image filename."
        )

    finally:
        sanitized_image.close()


# ============================================================================
# Public API
# ============================================================================


def sanitize_and_store_image(
    source: bytes | bytearray | BinaryIO,
) -> str:
    """
    Validate, sanitize, and securely store an uploaded image.

    Parameters
    ----------
    source:
        Raw image bytes or a readable binary stream.

    Returns
    -------
    str
        A safe relative storage key suitable for storing in the database.

    Example
    -------
        items/4f7a...91.webp

    Security behavior
    -----------------
    - Enforces the actual upload byte limit.
    - Ignores client filenames.
    - Ignores client MIME types.
    - Validates the actual image format with Pillow.
    - Rejects unsupported formats such as SVG.
    - Enforces width and height limits.
    - Enforces total pixel limits.
    - Fully decodes the image.
    - Removes original metadata by rebuilding the image.
    - Re-encodes into a known safe image format.
    - Generates a cryptographically random filename.
    - Stores the file beneath MEDIA_ROOT/items/.
    - Returns only a relative storage key.
    """

    data = _read_upload(source)

    if not data:
        raise ImageProcessingError(
            "Uploaded image is empty."
        )

    image, detected_format = _open_image(data)

    try:
        validate_image_dimensions(image)

        # _open_image() has already validated this format against the
        # configured allow-list. Keeping this explicit check makes the
        # public function defensive if the decoder is changed later.
        normalized_format = _pillow_format(
            detected_format
        )

        storage_key, _ = _save_sanitized_image(
            image,
            normalized_format,
        )

        return storage_key

    finally:
        image.close()


# ============================================================================
# Stored Image Deletion
# ============================================================================


def delete_stored_image(
    storage_key: str,
) -> None:
    """
    Safely delete an image using its relative storage key.

    The supplied value must point to an image inside:

        MEDIA_ROOT/items/

    Example:

        items/4f7a...91.webp

    Invalid or empty storage keys are rejected.
    """

    if not storage_key:
        raise ImageProcessingError(
            "Image storage key is required."
        )

    # Backslashes are never accepted as a legitimate storage-key separator.
    if "\\" in storage_key:
        raise ImageProcessingError(
            "Invalid image storage key."
        )

    # Absolute-style paths are rejected.
    if storage_key.startswith("/"):
        raise ImageProcessingError(
            "Invalid image storage key."
        )

    parts = PurePosixPath(storage_key).parts

    if len(parts) != 2 or parts[0] != "items":
        raise ImageProcessingError(
            "Invalid image storage key."
        )

    filename = parts[1]

    if (
        not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
    ):
        raise ImageProcessingError(
            "Invalid image storage key."
        )

    path = _safe_storage_path(filename)

    try:
        path.unlink(
            missing_ok=True
        )
    except OSError as exc:
        raise ImageProcessingError(
            "Failed to delete stored image."
        ) from exc


# ============================================================================
# Storage Key → URL
# ============================================================================


def image_storage_key_to_url(
    storage_key: str,
) -> str:
    """
    Convert a safe relative storage key into a public media URL.

    Example:

        items/abc123.webp
        ->
        /media/items/abc123.webp

    Absolute paths and traversal attempts are rejected.
    """

    if not storage_key:
        raise ImageProcessingError(
            "Image storage key is required."
        )

    # Do not normalize away an invalid leading slash.
    if storage_key.startswith("/"):
        raise ImageProcessingError(
            "Invalid image storage key."
        )

    # Backslashes are not valid storage-key separators.
    if "\\" in storage_key:
        raise ImageProcessingError(
            "Invalid image storage key."
        )

    parts = PurePosixPath(storage_key).parts

    if len(parts) != 2 or parts[0] != "items":
        raise ImageProcessingError(
            "Invalid image storage key."
        )

    filename = parts[1]

    if (
        not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
    ):
        raise ImageProcessingError(
            "Invalid image storage key."
        )

    # Validate that the filename maps to a safe location even though this
    # function only constructs a URL.
    _safe_storage_path(filename)

    media_url = settings.MEDIA_URL.rstrip("/")

    return (
        f"{media_url}/"
        f"{parts[0]}/"
        f"{filename}"
    )