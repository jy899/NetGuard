"""Advisory AI records: stored insights and change outcomes (prediction at analysis, result after execution)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.session import Base


class AiInsight(Base):
    """The last AI insight computed for a network (anomalies, root causes, ranked fixes) or a change."""
    __tablename__ = "ai_insights"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), nullable=False, index=True)
    change_id: Mapped[int | None] = mapped_column(ForeignKey("changes.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # network / change
    model_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())


class ChangeOutcome(Base):
    """One analysed change: the model's forecast and, once executed on a laboratory device, what happened.

    Executed outcomes become local training rows (scripts/train_models.py --include-local)."""
    __tablename__ = "change_outcomes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), nullable=False, index=True)
    change_id: Mapped[int] = mapped_column(ForeignKey("changes.id", ondelete="CASCADE"), nullable=False, unique=True)
    change_type: Mapped[str] = mapped_column(String(32), nullable=False)
    features: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    model_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    predicted_harm: Mapped[float | None] = mapped_column(Float)
    predicted_endpoints: Mapped[float | None] = mapped_column(Float)
    simulated_harmful: Mapped[int | None] = mapped_column(Integer)
    simulated_endpoints: Mapped[int | None] = mapped_column(Integer)
    actual_harmful: Mapped[int | None] = mapped_column(Integer)  # set after a laboratory execution
    actual: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    executed_at: Mapped[datetime | None] = mapped_column(DateTime)
