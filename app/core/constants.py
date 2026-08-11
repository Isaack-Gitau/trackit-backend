class UserRole:
    USER = "user"
    ADMIN = "admin"


class ItemType:
    LOST = "lost"
    FOUND = "found"


class ItemStatus:
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ClaimStatus:
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ReportStatus:
    PENDING = "pending"
    REVIEWED = "reviewed"
    RESOLVED = "resolved"


class TokenType:
    ACCESS = "access"
    REFRESH = "refresh"
