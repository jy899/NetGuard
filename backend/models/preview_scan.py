from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.session import Base


class PreviewScan(Base):
    """The state of a Scan & Identify run on the sample office network (one per user).
    What was found, which devices were read and with which login, cables and the attempt log are JSON in `data`."""

    __tablename__ = "preview_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, unique=True)
    subnet: Mapped[str] = mapped_column(String(43), nullable=False)
    data: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())
