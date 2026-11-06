"""Configuration snapshots collected from devices and change executions on laboratory devices.

Configuration text can contain password hashes and SNMP community strings, so it is stored encrypted
(core.vault) together with its SHA-256 digest, which identifies the snapshot in reports.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.vault import decrypt, encrypt
from backend.database.session import Base


class DeviceConfig(Base):
    __tablename__ = "device_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="collected")  # collected | backup | post-change
    source: Mapped[str] = mapped_column(String(32), nullable=False)  # ssh, lab-console, eve-ng-startup, import
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    text_enc: Mapped[str] = mapped_column(Text, nullable=False)
    collected_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())

    @property
    def text(self) -> str | None:
        return decrypt(self.text_enc)

    @text.setter
    def text(self, value: str) -> None:
        self.text_enc = encrypt(value)


class ChangeExecution(Base):
    """One approved change applied to a laboratory device: backup, commands, verification and rollback."""

    __tablename__ = "change_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    change_id: Mapped[int] = mapped_column(ForeignKey("changes.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    device_name: Mapped[str] = mapped_column(String(64), nullable=False)
    transport: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # applied, rolled_back, failed, rollback_failed
    backup_config_id: Mapped[int | None] = mapped_column(ForeignKey("device_configs.id", ondelete="SET NULL"))
    commands: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    rollback_commands: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    verification: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    log: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    executed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
