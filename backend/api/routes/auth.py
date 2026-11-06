from fastapi import APIRouter, Request

from backend.api.deps import AppSettings, CurrentUser, DbSession
from backend.schemas.auth import LoginRequest, PasswordChange, TokenResponse, UserOut
from backend.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: DbSession, settings: AppSettings):
    client_ip = request.client.host if request.client else None
    user = auth_service.authenticate(db, payload.username, payload.password, client_ip)
    return TokenResponse(
        access_token=auth_service.issue_token(user, settings),
        expires_in=settings.token_expire_minutes * 60,
        user=UserOut.model_validate(user),
    )


@router.post("/logout")
def logout(db: DbSession, user: CurrentUser) -> dict:
    # Revokes every token of this user (all sessions); the client also discards its token.
    auth_service.revoke_tokens(db, user)
    return {"status": "logged_out"}


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser):
    return user


@router.put("/password")
def change_password(payload: PasswordChange, db: DbSession, user: CurrentUser, settings: AppSettings) -> dict:
    auth_service.change_password(db, user, payload.current_password, payload.new_password)
    # Older tokens (other sessions) are now invalid; this session continues with a new token.
    return {"status": "password_changed", "access_token": auth_service.issue_token(user, settings),
            "token_type": "bearer", "expires_in": settings.token_expire_minutes * 60}
