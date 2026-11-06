from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str = Field(validation_alias="group_name")
    group_id: int | None = None
    permissions: list[str] = []
    is_active: bool = True
    created_at: datetime

    @model_validator(mode="before")
    @classmethod
    def _permissions(cls, data):
        if hasattr(data, "username") and not isinstance(data, dict):
            from backend.core.permissions import PERMISSIONS, permissions_of
            granted = permissions_of(data)
            return {"id": data.id, "username": data.username, "group_name": data.group_name, "group_id": data.group_id,
                    "permissions": [p for p in PERMISSIONS if p in granted], "is_active": data.is_active,
                    "created_at": data.created_at}
        return data


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)
