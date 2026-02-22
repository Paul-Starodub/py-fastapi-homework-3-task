import secrets
from datetime import datetime, timezone


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token.

    Returns:
        str: Securely generated token.
    """
    return secrets.token_urlsafe(length)


def ensure_utc(dt: datetime) -> datetime:
    """
    Ensure that datetime is timezone-aware (UTC).
    If datetime is naive, attach UTC timezone.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
