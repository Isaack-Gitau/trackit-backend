"""
TRACKIT database models.

Importing this package registers every model with
SQLAlchemy's Base.metadata.
"""

from app.models.user import User
from app.models.item import Item
from app.models.auth_token import AuthToken
from app.models.claim import Claim
from app.models.audit_log import AuditLog
from app.models.report import Report
from app.models.notification import Notification
from app.models.match import Match

__all__ = [
    "User",
    "Item",
    "AuthToken",
    "AuditLog",
    "Claim",
    "Report",
    "Notification",
    "Match"
]