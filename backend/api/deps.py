"""Shared FastAPI dependencies."""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session

from backend.core import permissions
from backend.core.config import Settings, get_settings
from backend.core.errors import ForbiddenError
from backend.database.session import get_db
from backend.models import User
from backend.services import auth_service

DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]


def get_current_user(
    request: Request,
    db: DbSession,
    settings: AppSettings,
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    user = auth_service.user_from_token(db, token, settings)
    needed = permissions.required_permission(request.method, request.url.path)
    if needed is not None and not permissions.has(user, needed):
        raise ForbiddenError(f"Your user group does not have the permission: {permissions.PERMISSIONS[needed]}.")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
