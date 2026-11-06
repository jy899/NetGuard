from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.session import Base


class SavedLogin(Base):
    """A device login kept because the engineer ticked Remember password.

    kind 'read' is a read-only discovery login for a subnet (target = the subnet); kind 'config' is a login with
    configuration rights for a network. New targets are prefixed with the owner ID
    while APIs expose the plain target. Owned legacy targets remain reusable.
    The password is stored encrypted (core.vault).
    """

    __tablename__ = "saved_logins"
    __table_args__ = (UniqueConstraint("kind", "target", name="uq_saved_login"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    target: Mapped[str] = mapped_column(String(64), nullable=False)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    password_enc: Mapped[str] = mapped_column("password", Text, nullable=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    @property
    def password(self) -> str | None:
        from backend.core.vault import decrypt

        return decrypt(self.password_enc)

    @password.setter
    def password(self, value: str) -> None:
        from backend.core.vault import encrypt

        self.password_enc = encrypt(value)
