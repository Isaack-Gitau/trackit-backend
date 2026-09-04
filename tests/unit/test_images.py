"""
Unit tests for TRACKIT image upload security utilities.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from PIL import Image

from app.utils.images import (
    ImageDimensionsError,
    ImageFormatError,
    ImageProcessingError,
    ImageTooLargeError,
    delete_stored_image,
    generate_image_filename,
    image_storage_key_to_url,
    sanitize_and_store_image,
    validate_image_dimensions,
    validate_image_size,
)


# ============================================================================
# Test Helpers
# ============================================================================


def make_image_bytes(
    image_format: str = "PNG",
    size: tuple[int, int] = (100, 100),
    mode: str = "RGB",
    **save_kwargs: object,
) -> bytes:
    """
    Create an in-memory test image.
    """

    image = Image.new(mode, size, color="red")

    buffer = io.BytesIO()

    try:
        image.save(
            buffer,
            format=image_format,
            **save_kwargs,
        )
    finally:
        image.close()

    return buffer.getvalue()


def make_jpeg_bytes(
    size: tuple[int, int] = (100, 100),
) -> bytes:
    """
    Create a JPEG image for testing.
    """

    return make_image_bytes(
        image_format="JPEG",
        size=size,
        mode="RGB",
    )


def make_png_bytes(
    size: tuple[int, int] = (100, 100),
) -> bytes:
    """
    Create a PNG image for testing.
    """

    return make_image_bytes(
        image_format="PNG",
        size=size,
        mode="RGBA",
    )


def make_webp_bytes(
    size: tuple[int, int] = (100, 100),
) -> bytes:
    """
    Create a WebP image for testing.
    """

    return make_image_bytes(
        image_format="WEBP",
        size=size,
        mode="RGB",
    )


# ============================================================================
# Size Validation
# ============================================================================


def test_validate_image_size_accepts_image_under_limit():
    data = b"x" * 100

    validate_image_size(data)


def test_validate_image_size_rejects_image_over_limit(monkeypatch):
    monkeypatch.setattr(
        "app.utils.images.settings.IMAGE_MAX_SIZE_BYTES",
        100,
    )

    data = b"x" * 101

    with pytest.raises(ImageTooLargeError):
        validate_image_size(data)


def test_sanitize_and_store_rejects_oversized_stream(monkeypatch):
    monkeypatch.setattr(
        "app.utils.images.settings.IMAGE_MAX_SIZE_BYTES",
        100,
    )

    oversized_stream = io.BytesIO(b"x" * 101)

    with pytest.raises(ImageTooLargeError):
        sanitize_and_store_image(oversized_stream)


# ============================================================================
# Valid Image Formats
# ============================================================================


@pytest.mark.parametrize(
    ("image_format", "image_factory"),
    [
        ("JPEG", make_jpeg_bytes),
        ("PNG", make_png_bytes),
        ("WEBP", make_webp_bytes),
    ],
)
def test_valid_image_formats_are_accepted(
    monkeypatch,
    tmp_path: Path,
    image_format: str,
    image_factory,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    data = image_factory()

    storage_key = sanitize_and_store_image(data)

    assert storage_key.startswith("items/")
    assert storage_key.endswith(
        {
            "JPEG": ".jpg",
            "PNG": ".png",
            "WEBP": ".webp",
        }[image_format]
    )

    stored_file = tmp_path / storage_key

    assert stored_file.exists()
    assert stored_file.is_file()


def test_valid_image_stream_is_accepted(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    data = make_png_bytes()
    stream = io.BytesIO(data)

    storage_key = sanitize_and_store_image(stream)

    assert storage_key.startswith("items/")
    assert (tmp_path / storage_key).exists()


# ============================================================================
# Format Validation
# ============================================================================


def test_fake_image_extension_does_not_bypass_validation(
    monkeypatch,
    tmp_path: Path,
):
    """
    The utility must inspect actual image bytes rather than trusting
    the original filename.

    Since the utility accepts raw bytes and does not use filenames,
    a PNG payload remains a PNG regardless of any external filename.
    """

    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    png_data = make_png_bytes()

    storage_key = sanitize_and_store_image(png_data)

    assert storage_key.endswith(".png")


def test_non_image_bytes_are_rejected(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    data = b"This is not an image."

    with pytest.raises(ImageProcessingError):
        sanitize_and_store_image(data)


def test_empty_upload_is_rejected(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    with pytest.raises(ImageProcessingError):
        sanitize_and_store_image(b"")


def test_svg_payload_is_rejected(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    svg = b"""
    <svg xmlns="http://www.w3.org/2000/svg">
        <script>alert('xss')</script>
        <rect width="100" height="100"/>
    </svg>
    """

    with pytest.raises((ImageFormatError, ImageProcessingError)):
        sanitize_and_store_image(svg)


def test_gif_payload_is_rejected(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    gif_data = make_image_bytes("GIF")

    with pytest.raises(ImageFormatError):
        sanitize_and_store_image(gif_data)


# ============================================================================
# Dimension Validation
# ============================================================================


def test_validate_image_dimensions_accepts_normal_image():
    image = Image.new("RGB", (100, 100))

    try:
        validate_image_dimensions(image)
    finally:
        image.close()


def test_validate_image_dimensions_rejects_width_over_limit(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.utils.images.settings.IMAGE_MAX_WIDTH",
        100,
    )

    image = Image.new("RGB", (101, 100))

    try:
        with pytest.raises(ImageDimensionsError):
            validate_image_dimensions(image)
    finally:
        image.close()


def test_validate_image_dimensions_rejects_height_over_limit(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.utils.images.settings.IMAGE_MAX_HEIGHT",
        100,
    )

    image = Image.new("RGB", (100, 101))

    try:
        with pytest.raises(ImageDimensionsError):
            validate_image_dimensions(image)
    finally:
        image.close()


def test_validate_image_dimensions_rejects_total_pixels_over_limit(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.utils.images.settings.IMAGE_MAX_PIXELS",
        10_000,
    )

    image = Image.new("RGB", (101, 100))

    try:
        with pytest.raises(ImageDimensionsError):
            validate_image_dimensions(image)
    finally:
        image.close()


def test_sanitize_and_store_rejects_excessive_dimensions(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )
    monkeypatch.setattr(
        "app.utils.images.settings.IMAGE_MAX_WIDTH",
        100,
    )

    data = make_png_bytes(size=(101, 100))

    with pytest.raises(ImageDimensionsError):
        sanitize_and_store_image(data)


# ============================================================================
# Sanitization
# ============================================================================


def test_sanitized_image_removes_exif_metadata(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    image = Image.new("RGB", (100, 100), color="blue")

    exif = image.getexif()
    exif[270] = "TRACKIT TEST METADATA"

    buffer = io.BytesIO()

    try:
        image.save(
            buffer,
            format="JPEG",
            exif=exif.tobytes(),
        )
    finally:
        image.close()

    storage_key = sanitize_and_store_image(buffer.getvalue())

    stored_path = tmp_path / storage_key

    with Image.open(stored_path) as sanitized:
        sanitized_exif = sanitized.getexif()

        assert sanitized_exif.get(270) is None


def test_sanitized_image_is_a_valid_decoded_image(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    original = make_png_bytes(size=(200, 150))

    storage_key = sanitize_and_store_image(original)

    stored_path = tmp_path / storage_key

    with Image.open(stored_path) as image:
        image.load()

        assert image.size == (200, 150)
        assert image.format == "PNG"


def test_jpeg_transparency_is_safely_flattened(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    image = Image.new("RGBA", (100, 100), color=(255, 0, 0, 128))

    buffer = io.BytesIO()

    try:
        image.save(buffer, format="PNG")
    finally:
        image.close()

    # The detected source format is PNG, so this verifies PNG sanitization.
    storage_key = sanitize_and_store_image(buffer.getvalue())

    stored_path = tmp_path / storage_key

    with Image.open(stored_path) as sanitized:
        sanitized.load()

        assert sanitized.format == "PNG"
        assert sanitized.size == (100, 100)


# ============================================================================
# Server-Generated Filenames
# ============================================================================


@pytest.mark.parametrize(
    ("image_format", "expected_extension"),
    [
        ("JPEG", ".jpg"),
        ("PNG", ".png"),
        ("WEBP", ".webp"),
    ],
)
def test_generate_image_filename_uses_safe_extension(
    image_format: str,
    expected_extension: str,
):
    filename = generate_image_filename(image_format)

    assert filename.endswith(expected_extension)
    assert "/" not in filename
    assert "\\" not in filename
    assert filename != expected_extension


def test_generated_image_filenames_are_unique():
    first = generate_image_filename("PNG")
    second = generate_image_filename("PNG")

    assert first != second


def test_original_filename_cannot_influence_storage_filename(
    monkeypatch,
    tmp_path: Path,
):
    """
    The storage API receives image bytes only, so client filenames cannot
    become filesystem paths.
    """

    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    data = make_png_bytes()

    storage_key = sanitize_and_store_image(data)

    assert ".." not in storage_key
    assert "/" in storage_key
    assert storage_key.startswith("items/")


# ============================================================================
# Storage Security
# ============================================================================


def test_storage_directory_is_created_automatically(
    monkeypatch,
    tmp_path: Path,
):
    media_root = tmp_path / "media"

    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(media_root),
    )

    assert not (media_root / "items").exists()

    storage_key = sanitize_and_store_image(make_png_bytes())

    assert (media_root / "items").is_dir()
    assert (media_root / storage_key).is_file()


def test_stored_image_is_inside_media_root(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    storage_key = sanitize_and_store_image(make_png_bytes())

    stored_path = (tmp_path / storage_key).resolve()

    assert stored_path.is_relative_to(tmp_path.resolve())


def test_delete_stored_image_removes_valid_file(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    storage_key = sanitize_and_store_image(make_png_bytes())

    stored_path = tmp_path / storage_key

    assert stored_path.exists()

    delete_stored_image(storage_key)

    assert not stored_path.exists()


def test_delete_stored_image_is_idempotent(
    monkeypatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_ROOT",
        str(tmp_path),
    )

    storage_key = sanitize_and_store_image(make_png_bytes())

    delete_stored_image(storage_key)
    delete_stored_image(storage_key)


@pytest.mark.parametrize(
    "malicious_key",
    [
        "../secret.txt",
        "../../secret.txt",
        "items/../secret.txt",
        "items/../../secret.txt",
        "/etc/passwd",
        "items/../../etc/passwd",
        "items\\..\\secret.txt",
        "items/",
        "items/.",
        "items/..",
    ],
)
def test_delete_stored_image_rejects_path_traversal(
    malicious_key: str,
):
    with pytest.raises(ImageProcessingError):
        delete_stored_image(malicious_key)


@pytest.mark.parametrize(
    "invalid_key",
    [
        "image.png",
        "users/image.png",
        "items/a/b.png",
        "",
    ],
)
def test_delete_stored_image_rejects_invalid_storage_keys(
    invalid_key: str,
):
    with pytest.raises(ImageProcessingError):
        delete_stored_image(invalid_key)


# ============================================================================
# Public URL Construction
# ============================================================================


def test_image_storage_key_to_url_returns_media_url():
    url = image_storage_key_to_url(
        "items/example-image.webp"
    )

    assert url == "/media/items/example-image.webp"


def test_image_storage_key_to_url_respects_custom_media_url(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.utils.images.settings.MEDIA_URL",
        "/uploads",
    )

    url = image_storage_key_to_url(
        "items/example-image.webp"
    )

    assert url == "/uploads/items/example-image.webp"


@pytest.mark.parametrize(
    "invalid_key",
    [
        "../example.webp",
        "/items/example.webp",
        "users/example.webp",
        "items/a/b.webp",
        "",
    ],
)
def test_image_storage_key_to_url_rejects_invalid_keys(
    invalid_key: str,
):
    with pytest.raises(ImageProcessingError):
        image_storage_key_to_url(invalid_key)


# ============================================================================
# Stream Handling
# ============================================================================


def test_stream_reading_does_not_accept_more_than_configured_limit(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.utils.images.settings.IMAGE_MAX_SIZE_BYTES",
        100,
    )

    stream = io.BytesIO(b"x" * 101)

    with pytest.raises(ImageTooLargeError):
        sanitize_and_store_image(stream)


def test_invalid_source_type_is_rejected():
    with pytest.raises(ImageProcessingError):
        sanitize_and_store_image(123)  # type: ignore[arg-type]