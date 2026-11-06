from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.session import Base

if TYPE_CHECKING:
    from backend.models.config import NetworkIntent
    from backend.models.device import Device
    from backend.models.link import Link
    from backend.models.user import User


class Network(Base):
    __tablename__ = "networks"
    # IDs are never reused, so nothing left over from a deleted network can attach to a new one.
    __table_args__ = {"sqlite_autoincrement": True}

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    network_type: Mapped[str] = mapped_column(String(50), nullable=False, default="Enterprise")
    environment: Mapped[str] = mapped_column(String(16), nullable=False, default="manual")
    source: Mapped[str] = mapped_column(String(24), nullable=False, default="manual")
    is_simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Observations and adapter provenance only. Credentials never belong in this field.
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    # Not in the brief's minimum schema; used to order "Recent Networks".
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )

    creator: Mapped["User | None"] = relationship()
    devices: Mapped[list["Device"]] = relationship(
        back_populates="network", cascade="all, delete-orphan", passive_deletes=True
    )
    links: Mapped[list["Link"]] = relationship(
        back_populates="network", cascade="all, delete-orphan", passive_deletes=True
    )
    intents: Mapped[list["NetworkIntent"]] = relationship(
        back_populates="network", cascade="all, delete-orphan", passive_deletes=True, order_by="NetworkIntent.id"
    )
