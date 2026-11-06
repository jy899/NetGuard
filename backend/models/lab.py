from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.session import Base


class Lab(Base):
    """A Lab Studio lab. Images, nodes and links are kept as JSON in `data`.
    A twin lab points at the network it was built from."""

    __tablename__ = "labs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), index=True)
    data: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )
