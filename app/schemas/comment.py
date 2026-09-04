"""
TRACKIT Comment Schemas.
Pydantic schemas used by the comment API.
Security principles:
- user_id is never accepted from the client.
- item_id is never accepted from the client when creating a comment.
- Comment ownership is derived from the authenticated user.
- Comment content is treated as untrusted plain text.
- Empty and whitespace-only comments are rejected.
- Comment content is limited to 2,000 characters.
- Database identifiers are controlled by the application route/service.
- Response schemas expose only fields required by the API.
"""
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator
# ============================================================================
# CONSTANTS
# ============================================================================
COMMENT_MAX_LENGTH = 2000
# ============================================================================
# CREATE COMMENT
# ============================================================================
class CommentCreate(BaseModel):
    """
    Data required to create a comment.
    The authenticated user's identity and target item are obtained
    from the request/authentication context and route, respectively.
    They are deliberately not accepted as request-body fields.
    """
    content: str = Field(
        ...,
        min_length=1,
        max_length=COMMENT_MAX_LENGTH,
    )
    @field_validator("content")
    @classmethod
    def normalize_content(cls, value: str) -> str:
        """
        Remove leading/trailing whitespace and reject empty content.
        Internal whitespace is preserved.
        Comment content remains untrusted plain text. Any HTML or
        JavaScript supplied by a client must be safely handled by
        the presentation layer and must never be interpreted as
        trusted application markup.
        """
        value = value.strip()
        if not value:
            raise ValueError(
                "Comment content cannot be empty."
            )
        return value
# ============================================================================
# UPDATE COMMENT
# ============================================================================
class CommentUpdate(BaseModel):
    """
    Data required to update an existing comment.
    Only the comment content can be changed.
    Ownership, comment ID, item ID, and user identity are controlled
    by the application and are never accepted from the client.
    """
    content: str = Field(
        ...,
        min_length=1,
        max_length=COMMENT_MAX_LENGTH,
    )
    @field_validator("content")
    @classmethod
    def normalize_content(cls, value: str) -> str:
        """
        Remove leading/trailing whitespace and reject empty content.
        """
        value = value.strip()
        if not value:
            raise ValueError(
                "Comment content cannot be empty."
            )
        return value
# ============================================================================
# COMMENT RESPONSE
# ============================================================================
class CommentResponse(BaseModel):
    """
    API representation of a comment.
    SQLAlchemy model attributes can be used directly because
    from_attributes is enabled.
    """
    model_config = ConfigDict(
        from_attributes=True,
    )
    id: int
    item_id: int
    user_id: int
    content: str
    created_at: datetime
    updated_at: datetime
