"""
TRACKIT Item API Routes.

HTTP endpoints for the lost-and-found item system.

Architecture:

    Request
        ↓
    Router
        ↓
    Authentication / Authorization
        ↓
    Pydantic Validation
        ↓
    Image Sanitization / Storage
        ↓
    Item Service
        ↓
    Item Repository
        ↓
    PostgreSQL

Security principles:
- Authenticated identity comes from the JWT.
- Clients cannot provide or override user_id.
- Verified accounts are required for item management.
- Ownership checks remain in the service layer.
- Public item browsing exposes only publicly visible items.
- Pending and rejected items are not publicly accessible.
- Uploaded images are validated and sanitized server-side.
- Clients cannot choose the image storage path.
- Stored images use server-generated storage keys.
- Failed database operations clean up newly stored images.
- JSON image values are never treated as storage paths.
"""

from typing import Any, Literal

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from sqlalchemy.orm import Session
from starlette.datastructures import FormData, UploadFile

from app.api.deps import (
    get_current_moderator,
    get_current_verified_user,
)
from app.db.dependencies import get_db
from app.models.user import User
from app.repositories.items import IMAGE_UNSET
from app.schemas.item import (
    ItemCreate,
    ItemReject,
    ItemResponse,
    ItemUpdate,
)
from app.services.item import (
    approve_item,
    create_item,
    delete_item,
    get_item,
    get_public_item,
    list_public_items,
    list_user_items,
    reject_item,
    update_item,
)
from app.utils.images import (
    ImageUploadError,
    delete_stored_image,
    sanitize_and_store_image,
)


router = APIRouter(
    prefix="/items",
    tags=["Items"],
)


# ============================================================================
# HELPERS
# ============================================================================


def _delete_stored_image_safely(
    storage_key: str | None,
) -> None:
    """
    Best-effort cleanup for an image that was newly stored during
    a request but could not be associated with the database record.
    """
    if not storage_key:
        return

    try:
        delete_stored_image(storage_key)
    except Exception:
        # Cleanup must never hide the original request/database error.
        pass


def _get_required_form_text(
    form: FormData,
    field_name: str,
) -> str:
    """
    Extract a required text field from multipart form data.

    Starlette's FormData values may be either strings or UploadFile
    objects. This helper narrows the value to str and rejects files
    supplied where text is expected.
    """
    value = form.get(field_name)

    if value is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"The {field_name} field is required.",
        )

    if isinstance(value, UploadFile):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"The {field_name} field must be text.",
        )

    return value


def _get_optional_form_text(
    form: FormData,
    field_name: str,
) -> str | None:
    """
    Extract an optional text field from multipart form data.

    Returns None when the field is absent and rejects uploaded files
    where text is expected.
    """
    value = form.get(field_name)

    if value is None:
        return None

    if isinstance(value, UploadFile):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"The {field_name} field must be text.",
        )

    return value


def _get_required_item_type(
    form: FormData,
) -> Literal["lost", "found"]:
    """
    Extract and validate the required item type from multipart form data.

    The ItemCreate schema uses Literal["lost", "found"], so this helper
    explicitly narrows the runtime string to the exact Literal type
    expected by Pydantic and Pyright.
    """
    value = _get_required_form_text(
        form,
        "type",
    )

    if value == "lost":
        return "lost"

    if value == "found":
        return "found"

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="The type field must be either 'lost' or 'found'.",
    )


def _get_optional_item_type(
    form: FormData,
) -> Literal["lost", "found"] | None:
    """
    Extract and validate an optional item type from multipart form data.
    """
    value = _get_optional_form_text(
        form,
        "type",
    )

    if value is None:
        return None

    if value == "lost":
        return "lost"

    if value == "found":
        return "found"

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="The type field must be either 'lost' or 'found'.",
    )


def _get_form_boolean(
    form: FormData,
    field_name: str,
    default: bool = False,
) -> bool:
    """
    Extract a boolean value from multipart form data.

    Accepted true values:
        true, 1, yes, on

    Accepted false values:
        false, 0, no, off

    An omitted field uses the supplied default.
    """
    value = form.get(field_name)

    if value is None:
        return default

    if isinstance(value, UploadFile):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"The {field_name} field must be text.",
        )

    normalized_value = value.strip().lower()

    if normalized_value in {
        "true",
        "1",
        "yes",
        "on",
    }:
        return True

    if normalized_value in {
        "false",
        "0",
        "no",
        "off",
        "",
    }:
        return False

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=(
            f"The {field_name} field must be a boolean "
            "(true/false, 1/0, yes/no, or on/off)."
        ),
    )


async def _parse_create_request(
    request: Request,
) -> tuple[ItemCreate, UploadFile | None]:
    """
    Parse an item creation request.

    Supported content types:

        application/json
            Normal item creation without an uploaded image.

        multipart/form-data
            Item creation with optional image upload.

    JSON image values are deliberately rejected because clients must
    not be able to provide arbitrary filesystem storage keys or URLs.
    """
    content_type = request.headers.get("content-type", "").lower()

    if content_type.startswith("application/json"):
        try:
            payload_data = await request.json()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid JSON request body.",
            ) from exc

        if not isinstance(payload_data, dict):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Request body must be a JSON object.",
            )

        if "image" in payload_data and payload_data["image"] is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Images must be uploaded using multipart/form-data.",
            )

        try:
            payload = ItemCreate.model_validate(payload_data)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        return payload, None

    if content_type.startswith("multipart/form-data"):
        form = await request.form()

        try:
            payload = ItemCreate(
                title=_get_required_form_text(
                    form,
                    "title",
                ),
                description=_get_required_form_text(
                    form,
                    "description",
                ),
                type=_get_required_item_type(form),
                category=_get_required_form_text(
                    form,
                    "category",
                ),
                location=_get_required_form_text(
                    form,
                    "location",
                ),
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        image_value = form.get("image")

        if image_value is None:
            return payload, None

        if not isinstance(image_value, UploadFile):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="The image field must be a file.",
            )

        return payload, image_value

    raise HTTPException(
        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        detail=(
            "Unsupported content type. "
            "Use application/json or multipart/form-data."
        ),
    )


async def _parse_update_request(
    request: Request,
) -> tuple[ItemUpdate, UploadFile | None, bool]:
    """
    Parse an item update request.

    Supported content types:

        application/json
            Normal text-only update.

        multipart/form-data
            Text update with optional image replacement/removal.

    Returns:

        (validated payload, uploaded image, remove_image)
    """
    content_type = request.headers.get("content-type", "").lower()

    if content_type.startswith("application/json"):
        try:
            payload_data = await request.json()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid JSON request body.",
            ) from exc

        if not isinstance(payload_data, dict):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Request body must be a JSON object.",
            )

        if "image" in payload_data and payload_data["image"] is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Images must be uploaded using multipart/form-data.",
            )

        if "remove_image" in payload_data and payload_data["remove_image"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Image removal must use multipart/form-data.",
            )

        try:
            payload = ItemUpdate.model_validate(payload_data)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        return payload, None, False

    if content_type.startswith("multipart/form-data"):
        form = await request.form()

        payload_data: dict[str, Any] = {}

        for field_name in (
            "title",
            "description",
            "category",
            "location",
        ):
            if field_name in form:
                payload_data[field_name] = _get_optional_form_text(
                    form,
                    field_name,
                )

        if "type" in form:
            payload_data["type"] = _get_optional_item_type(form)

        try:
            payload = ItemUpdate.model_validate(payload_data)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        image_value = form.get("image")

        if image_value is not None and not isinstance(
            image_value,
            UploadFile,
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="The image field must be a file.",
            )

        remove_image = _get_form_boolean(
            form,
            "remove_image",
            default=False,
        )

        return payload, image_value, remove_image

    raise HTTPException(
        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        detail=(
            "Unsupported content type. "
            "Use application/json or multipart/form-data."
        ),
    )


# ============================================================================
# CREATE
# ============================================================================


@router.post(
    "",
    response_model=ItemResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a lost or found item",
)
async def create_item_endpoint(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Create a new lost or found item.

    Supports:

    - application/json for normal item creation
    - multipart/form-data when an image is uploaded

    The authenticated user automatically becomes the owner.

    user_id is deliberately NOT accepted as an authority source.
    """

    payload, image = await _parse_create_request(request)

    stored_image: str | None = None

    try:
        if image is not None:
            stored_image = sanitize_and_store_image(image.file)

        return create_item(
            db,
            user_id=current_user.id,
            title=payload.title,
            description=payload.description,
            item_type=payload.type,
            category=payload.category,
            location=payload.location,
            image=stored_image,
        )

    except ImageUploadError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception:
        _delete_stored_image_safely(stored_image)
        raise


# ============================================================================
# LIST PUBLIC ITEMS
# ============================================================================


@router.get(
    "",
    response_model=list[ItemResponse],
    summary="List publicly visible lost and found items",
)
def list_items_endpoint(
    search: str | None = Query(
        default=None,
        max_length=100,
        description="Search item title or description.",
    ),
    item_type: str | None = Query(
        default=None,
        alias="type",
        pattern="^(lost|found)$",
        description="Filter by item type.",
    ),
    category: str | None = Query(
        default=None,
        max_length=100,
        description="Filter by category.",
    ),
    location: str | None = Query(
        default=None,
        max_length=255,
        description="Filter by location.",
    ),
    page: int = Query(
        default=1,
        ge=1,
        description="Page number.",
    ),
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Number of items per page.",
    ),
    db: Session = Depends(get_db),
):
    """
    Retrieve publicly visible lost/found items.

    Public browsing is restricted to approved and claimed items.
    """

    return list_public_items(
        db,
        search=search,
        item_type=item_type,
        category=category,
        location=location,
        page=page,
        limit=limit,
    )


# ============================================================================
# CURRENT USER ITEMS
# ============================================================================


@router.get(
    "/me/items",
    response_model=list[ItemResponse],
    summary="List the authenticated user's items",
)
def list_my_items_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Retrieve all items belonging to the authenticated user.
    """

    return list_user_items(
        db,
        user_id=current_user.id,
    )


# ============================================================================
# MODERATOR / ADMIN MODERATION — APPROVE
# ============================================================================


@router.patch(
    "/{item_id}/approve",
    response_model=ItemResponse,
    summary="Approve an item",
)
def approve_item_endpoint(
    item_id: int,
    db: Session = Depends(get_db),
    current_moderator: User = Depends(get_current_moderator),
):
    """
    Approve a pending item.

    Moderator or administrator authorization is required.
    """

    item = get_item(
        db,
        item_id=item_id,
    )

    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found.",
        )

    try:
        return approve_item(
            db,
            item=item,
            admin_user_id=current_moderator.id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


# ============================================================================
# MODERATOR / ADMIN MODERATION — REJECT
# ============================================================================


@router.patch(
    "/{item_id}/reject",
    response_model=ItemResponse,
    summary="Reject a pending item",
)
def reject_item_endpoint(
    item_id: int,
    payload: ItemReject,
    db: Session = Depends(get_db),
    current_moderator: User = Depends(get_current_moderator),
):
    """
    Reject a pending item.

    Moderator or administrator authorization is required.
    A rejection reason is mandatory.
    """

    item = get_item(
        db,
        item_id=item_id,
    )

    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found.",
        )

    try:
        return reject_item(
            db,
            item=item,
            admin_user_id=current_moderator.id,
            reason=payload.reason,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


# ============================================================================
# GET SINGLE PUBLIC ITEM
# ============================================================================


@router.get(
    "/{item_id}",
    response_model=ItemResponse,
    summary="Get a publicly visible item",
)
def get_item_endpoint(
    item_id: int,
    db: Session = Depends(get_db),
):
    """
    Retrieve a publicly visible item by ID.

    Only approved and claimed items are exposed.
    """

    item = get_public_item(
        db,
        item_id=item_id,
    )

    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found.",
        )

    return item


# ============================================================================
# UPDATE
# ============================================================================


@router.patch(
    "/{item_id}",
    response_model=ItemResponse,
    summary="Update an owned item",
)
async def update_item_endpoint(
    item_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Update an item belonging to the authenticated user.

    Supports:

    - application/json for text-only updates
    - multipart/form-data for text updates with image replacement
    - multipart/form-data with remove_image=true to clear an image
    """

    item = get_item(
        db,
        item_id=item_id,
    )

    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found.",
        )

    payload, image, remove_image = await _parse_update_request(
        request,
    )

    image_storage_key: str | None | object = IMAGE_UNSET
    stored_image: str | None = None

    try:
        if image is not None:
            stored_image = sanitize_and_store_image(image.file)
            image_storage_key = stored_image

        elif remove_image:
            image_storage_key = None

        return update_item(
            db,
            item=item,
            user_id=current_user.id,
            title=payload.title,
            description=payload.description,
            item_type=payload.type,
            category=payload.category,
            location=payload.location,
            image=image_storage_key,
        )

    except ImageUploadError as exc:
        _delete_stored_image_safely(stored_image)

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except PermissionError as exc:
        _delete_stored_image_safely(stored_image)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to modify this item.",
        ) from exc

    except ValueError as exc:
        _delete_stored_image_safely(stored_image)

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception:
        _delete_stored_image_safely(stored_image)
        raise


# ============================================================================
# DELETE
# ============================================================================


@router.delete(
    "/{item_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an owned item",
)
def delete_item_endpoint(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_verified_user),
):
    """
    Delete an item belonging to the authenticated user.

    The service layer handles ownership validation and stored-image
    cleanup.
    """

    item = get_item(
        db,
        item_id=item_id,
    )

    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found.",
        )

    try:
        delete_item(
            db,
            item=item,
            user_id=current_user.id,
        )

    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    return None
