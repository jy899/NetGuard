"""Encrypted, user-owned device credentials; independent of NetGuard accounts."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.vault import decrypt, encrypt
from backend.database.session import Base


class CredentialProfile(Base):
    __tablename__ = "credential_profiles"
    __table_args__ = (UniqueConstraint("created_by", "name", name="uq_credential_profile_owner_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    password_enc: Mapped[str] = mapped_column(Text, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    notes: Mapped[str | None] = mapped_column(String(200))
    # Authentication method this profile is for: ssh, https-api or snmpv3. SNMPv3 stores its authentication
    # passphrase in password_enc and its privacy passphrase in priv_password_enc.
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="ssh", server_default="ssh")
    snmp_auth_protocol: Mapped[str | None] = mapped_column(String(16))
    snmp_priv_protocol: Mapped[str | None] = mapped_column(String(16))
    priv_password_enc: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    @property
    def password(self) -> str | None:
        return decrypt(self.password_enc)

    @password.setter
    def password(self, value: str) -> None:
        self.password_enc = encrypt(value)

    @property
    def priv_password(self) -> str | None:
        return decrypt(self.priv_password_enc)

    @priv_password.setter
    def priv_password(self, value: str | None) -> None:
        self.priv_password_enc = encrypt(value) if value else None


class CredentialAssignment(Base):
    __tablename__ = "credential_assignments"
    __table_args__ = (UniqueConstraint("user_id", "device_id", name="uq_credential_assignment_owner_device"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    profile_id: Mapped[int | None] = mapped_column(ForeignKey("credential_profiles.id", ondelete="SET NULL"))
    username: Mapped[str | None] = mapped_column(String(64))
    password_enc: Mapped[str | None] = mapped_column(Text)
    scope: Mapped[str] = mapped_column(String(16), nullable=False, default="individual")
    auth_status: Mapped[str] = mapped_column(String(16), nullable=False, default="untested")
    detail: Mapped[str | None] = mapped_column(String(200))
    tested_at: Mapped[datetime | None] = mapped_column(DateTime)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    @property
    def password(self) -> str | None:
        return decrypt(self.password_enc)

    @password.setter
    def password(self, value: str | None) -> None:
        self.password_enc = encrypt(value)
