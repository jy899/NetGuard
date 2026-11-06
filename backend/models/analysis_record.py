"""Immutable, credential-free scan, analysis and report snapshots."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.session import Base


class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id", ondelete="SET NULL"), index=True)
    network_name: Mapped[str] = mapped_column(String(100), nullable=False)
    kind: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(150), nullable=False)
    summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    snapshot: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    creator = relationship("User")
