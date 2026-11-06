from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.session import Base


class UserGroup(Base):
    """A named set of permissions (backend/core/permissions.py) that accounts belong to."""

    __tablename__ = "user_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(200))
    permissions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())

    members: Mapped[list["User"]] = relationship(back_populates="group")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    # Name of the user group at the time of the last change (kept for history displays and older records).
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="Network Engineers")
    group_id: Mapped[int | None] = mapped_column(ForeignKey("user_groups.id", ondelete="SET NULL"))
    # Part of every login token; raised on logout and password change to revoke older tokens.
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())

    group: Mapped[UserGroup | None] = relationship(back_populates="members", lazy="joined")

    @property
    def group_name(self) -> str:
        return self.group.name if self.group is not None else self.role
