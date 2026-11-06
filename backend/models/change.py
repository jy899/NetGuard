"""Proposed changes and their assessment results (brief section 9.1)."""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.session import Base

if TYPE_CHECKING:
    from backend.models.device import Device
    from backend.models.interface import Interface
    from backend.models.network import Network
    from backend.models.user import User

CHANGE_STATUSES = ("draft", "analyzed", "saved", "pending_approval", "approved", "rejected", "applied", "rolled_back",
                   "failed", "awaiting_confirm")


class Change(Base):
    __tablename__ = "changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), nullable=False, index=True)
    # SET NULL keeps change history when a device is later deleted.
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), index=True)
    interface_id: Mapped[int | None] = mapped_column(ForeignKey("interfaces.id", ondelete="SET NULL"))
    device_name: Mapped[str] = mapped_column(String(64), nullable=False)  # snapshot for history
    target_name: Mapped[str | None] = mapped_column(String(100))  # e.g. "G0/0", "ACL seq 5"
    category: Mapped[str] = mapped_column(String(20), nullable=False)
    change_type: Mapped[str] = mapped_column(String(30), nullable=False)
    current_value: Mapped[str | None] = mapped_column(String(255))
    proposed_value: Mapped[str | None] = mapped_column(String(255))
    parameters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    reason: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    # Approval (separation of duties): an engineer submits, an IT Manager decides.
    submitted_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime)
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
    decision_note: Mapped[str | None] = mapped_column(String(300))
    approved_assessment_id: Mapped[int | None] = mapped_column(Integer)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    network: Mapped["Network"] = relationship()
    device: Mapped["Device | None"] = relationship()
    interface: Mapped["Interface | None"] = relationship()
    creator: Mapped["User | None"] = relationship(foreign_keys=[created_by])
    submitter: Mapped["User | None"] = relationship(foreign_keys=[submitted_by])
    decider: Mapped["User | None"] = relationship(foreign_keys=[decided_by])
    assessments: Mapped[list["Assessment"]] = relationship(
        back_populates="change", cascade="all, delete-orphan", passive_deletes=True, order_by="Assessment.id"
    )


class Assessment(Base):
    """One analysis run of a change. Re-analysis creates a new row."""

    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    change_id: Mapped[int] = mapped_column(ForeignKey("changes.id", ondelete="CASCADE"), nullable=False, index=True)
    configuration_score: Mapped[int] = mapped_column(Integer, nullable=False)
    connectivity_score: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol_score: Mapped[int] = mapped_column(Integer, nullable=False)
    service_score: Mapped[int] = mapped_column(Integer, nullable=False)
    total_risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    # Transparent risk factors: Score = 100 x S x (1 + I + E) / 24.
    risk_severity: Mapped[int | None] = mapped_column(Integer)
    risk_impact: Mapped[int | None] = mapped_column(Integer)
    risk_exposure: Mapped[int | None] = mapped_column(Integer)
    evidence_confidence: Mapped[str | None] = mapped_column(String(10))
    risk_level: Mapped[str] = mapped_column(String(10), nullable=False)
    recommendation: Mapped[str] = mapped_column(String(30), nullable=False)
    validation_result: Mapped[str] = mapped_column(String(10), nullable=False)  # PASS / FAIL
    primary_issue: Mapped[str | None] = mapped_column(String(50))
    change_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    findings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    checks: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    actions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    affected_devices: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    affected_links: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # Decision text, affected paths, pre-existing/resolved issues, flow counts.
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    analysis_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    saved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    saved_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())

    change: Mapped["Change"] = relationship(back_populates="assessments")
    creator: Mapped["User | None"] = relationship()
    impacts: Mapped[list["Impact"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", passive_deletes=True, order_by="Impact.id"
    )


class Impact(Base):
    """Effect of a change on one evaluated flow (affected or unaffected)."""

    __tablename__ = "impacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    service: Mapped[str] = mapped_column(String(100), nullable=False)
    source_device: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_device: Mapped[str] = mapped_column(String(64), nullable=False)
    protocol: Mapped[str | None] = mapped_column(String(10))
    port: Mapped[int | None] = mapped_column(Integer)
    criticality: Mapped[str | None] = mapped_column(String(10))
    impact_type: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # broken/violation/restored/rerouted/unchanged
    affected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    baseline_status: Mapped[str] = mapped_column(String(20), nullable=False)
    candidate_status: Mapped[str] = mapped_column(String(20), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    path: Mapped[list] = mapped_column(JSON, nullable=False, default=list)  # device names
    path_device_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    path_link_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    failure_link_id: Mapped[int | None] = mapped_column(Integer)
    failure_device: Mapped[str | None] = mapped_column(String(64))

    assessment: Mapped["Assessment"] = relationship(back_populates="impacts")
