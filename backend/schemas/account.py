from pydantic import BaseModel, Field, field_validator

from backend.core.permissions import PERMISSIONS


class AccountCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_.-]+$')
    password: str = Field(min_length=8, max_length=128, repr=False)
    group_id: int


class AccountUpdate(BaseModel):
    group_id: int | None = None
    is_active: bool | None = None


class GroupIn(BaseModel):
    name: str = Field(min_length=2, max_length=50)
    description: str | None = Field(default=None, max_length=200)
    permissions: list[str] = Field(default_factory=list)

    @field_validator('name')
    @classmethod
    def clean_name(cls, value):
        value = ' '.join(value.split())
        if len(value) < 2:
            raise ValueError('Enter a group name')
        return value

    @field_validator('permissions')
    @classmethod
    def known(cls, value):
        unknown = sorted(set(value) - set(PERMISSIONS))
        if unknown:
            raise ValueError(f"Unknown permission: {', '.join(unknown)}")
        return sorted(set(value), key=list(PERMISSIONS).index)
