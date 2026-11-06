from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.config import Settings
from backend.core.errors import AuthenticationError, TooManyAttemptsError, ValidationFailed
from backend.core.login_throttle import login_throttle
from backend.core.security import create_access_token, decode_access_token, hash_password, verify_password
from backend.models import User


def authenticate(db: Session, username: str, password: str, client_ip: str | None = None) -> User:
    key = login_throttle.key(username, client_ip)
    wait = login_throttle.locked_for(key)
    if wait:
        minutes = max(1, -(-wait // 60))
        raise TooManyAttemptsError(
            f"Too many failed login attempts. Try again in {minutes} minute{'s' if minutes > 1 else ''}.",
            headers={"Retry-After": str(wait)})
    user = db.scalar(select(User).where(User.username == username.strip()))
    if user is None or not user.is_active or not verify_password(password, user.password_hash):
        login_throttle.record_failure(key)
        raise AuthenticationError("Invalid username or password")
    login_throttle.record_success(key)
    return user


def issue_token(user: User, settings: Settings) -> str:
    return create_access_token(user.id, settings.secret_key, settings.token_expire_minutes, user.token_version or 0)


def user_from_token(db: Session, token: str | None, settings: Settings) -> User:
    if not token:
        raise AuthenticationError("Not authenticated")
    claims = decode_access_token(token, settings.secret_key)
    user = db.get(User, claims[0]) if claims is not None else None
    # A token issued before the last logout or password change carries an older version.
    if user is None or not user.is_active or claims[1] != (user.token_version or 0):
        raise AuthenticationError("Session expired or invalid. Please log in again.")
    return user


def revoke_tokens(db: Session, user: User) -> None:
    """Invalidate every token issued to this user so far (logout)."""
    user.token_version = (user.token_version or 0) + 1
    db.commit()


def ensure_default_user(db: Session, settings: Settings) -> User:
    """Seed the demo login, or migrate only the unchanged legacy demo account.

    Renaming the legacy row preserves network ownership and its other records.
    Its new name makes the migration one-time; changed passwords, custom users
    and an existing admin account are never reset by application startup.
    """
    existing = db.scalar(select(User).order_by(User.id).limit(1))
    if existing is not None:
        if settings.default_username == "admin" and settings.default_password == "admin":
            admin = db.scalar(select(User).where(User.username == "admin"))
            if admin is not None:
                _label_builtin_admin(db, admin)
                return admin
            legacy = db.scalar(select(User).where(User.username == "engineer"))
            if (legacy is not None and legacy.role in ("Network Engineer", "Network Engineers")
                    and verify_password("netguard123", legacy.password_hash)):
                legacy.username = "admin"
                legacy.password_hash = hash_password("admin")
                legacy.token_version = (legacy.token_version or 0) + 1
                db.commit()
                _label_builtin_admin(db, legacy)
                return legacy
        return existing
    from backend.models import UserGroup
    group = db.scalar(select(UserGroup).where(UserGroup.name == settings.default_role))
    user = User(
        username=settings.default_username,
        password_hash=hash_password(settings.default_password),
        role=settings.default_role, group_id=group.id if group else None,
    )
    db.add(user)
    db.commit()
    return user


def _label_builtin_admin(db: Session, admin: User) -> None:
    """The built-in admin always has administrator rights; show the old default role label as Administrator.

    Only the earlier seed label is updated. A role another administrator chose is kept, and the password,
    sessions and owned records are untouched.
    """
    if admin.role in ("Network Engineer", "Network Engineers") and admin.group_id is None:
        admin.role = "Administrators"
        db.commit()


def change_password(db: Session, user: User, current_password: str, new_password: str) -> None:
    if not verify_password(current_password, user.password_hash):
        raise ValidationFailed("Current password is incorrect")
    user.password_hash = hash_password(new_password)
    user.token_version = (user.token_version or 0) + 1  # sessions using the old password end
    db.commit()
