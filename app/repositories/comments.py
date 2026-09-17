"""
TRACKIT Comment Repository.

Database access layer for comments attached to public item posts.

Business rules, authorization, moderation, and visibility decisions
belong in the service layer.

This module is responsible only for querying and persisting Comment
records.
"""

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.models.comment import Comment


# ============================================================================
# CREATE
# ============================================================================


def create_comment(
    db: Session,
    *,
    item_id: int,
    user_id: int,
    content: str,
) -> Comment:
    """
    Create and persist a new comment.

    Authorization and business-rule validation must be performed
    by the service layer before this function is called.
    """

    comment = Comment(
        item_id=item_id,
        user_id=user_id,
        content=content,
    )

    db.add(comment)
    db.flush()

    return comment


# ============================================================================
# READ — SINGLE COMMENT
# ============================================================================


def get_comment_by_id(
    db: Session,
    comment_id: int,
) -> Comment | None:
    """
    Retrieve one comment by its primary key.

    The associated user is eagerly loaded because the public comment
    response includes safe author information.
    """

    return db.scalar(
        select(Comment)
        .options(
            joinedload(Comment.user),
        )
        .where(
            Comment.id == comment_id,
        )
    )


# ============================================================================
# READ — ITEM COMMENTS
# ============================================================================


def get_comments_by_item(
    db: Session,
    *,
    item_id: int,
) -> list[Comment]:
    """
    Retrieve all comments belonging to a specific item.

    Results are returned newest first.

    The associated users are eagerly loaded so serializing the public
    author information does not cause an N+1 query pattern.
    """

    statement = (
        select(Comment)
        .options(
            joinedload(Comment.user),
        )
        .where(
            Comment.item_id == item_id,
        )
        .order_by(
            Comment.created_at.desc(),
            Comment.id.desc(),
        )
    )

    return list(
        db.scalars(statement).all()
    )


# ============================================================================
# COUNT — ITEM COMMENTS
# ============================================================================


def count_comments_by_item(
    db: Session,
    *,
    item_id: int,
) -> int:
    """
    Count comments belonging to a specific item.
    """

    statement = select(
        func.count(Comment.id)
    ).where(
        Comment.item_id == item_id,
    )

    return int(
        db.scalar(statement) or 0
    )


# ============================================================================
# UPDATE — COMMENT
# ============================================================================


def update_comment(
    db: Session,
    comment: Comment,
    *,
    content: str,
) -> Comment:
    """
    Update the content of an existing comment.

    Authorization and validation must be performed by the
    service layer before this function is called.
    """

    comment.content = content

    db.flush()

    return comment


# ============================================================================
# DELETE — COMMENT
# ============================================================================


def delete_comment(
    db: Session,
    comment: Comment,
) -> None:
    """
    Delete one comment.

    Authorization must be performed by the service layer before
    this function is called.
    """

    db.delete(comment)
    db.flush()
