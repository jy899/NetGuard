from __future__ import annotations

from typing import TYPE_CHECKING

import json

from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.session import Base

if TYPE_CHECKING:
    from backend.models.device import Device
    from backend.models.interface import Interface
    from backend.models.network import Network


class Link(Base):
    """A physical/logical connection between two devices.

    Interfaces are optional so that devices without modelled interfaces
    (e.g. the Internet cloud) can still be connected. Deleting an interface
    keeps the link but clears the interface reference.
    """

    __tablename__ = "links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network_id: Mapped[int] = mapped_column(
        ForeignKey("networks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_interface_id: Mapped[int | None] = mapped_column(
        ForeignKey("interfaces.id", ondelete="SET NULL")
    )
    destination_device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    destination_interface_id: Mapped[int | None] = mapped_column(
        ForeignKey("interfaces.id", ondelete="SET NULL")
    )
    kind: Mapped[str | None] = mapped_column(String(16))
    state: Mapped[str | None] = mapped_column(String(16))
    confidence: Mapped[float | None] = mapped_column(Float)
    evidence_json: Mapped[str | None] = mapped_column(Text)
    speed_mbps: Mapped[int | None] = mapped_column(Integer)

    def _observations(self) -> dict:
        try:
            data = json.loads(self.evidence_json) if self.evidence_json else {}
        except (ValueError, TypeError):
            return {}
        return data if isinstance(data, dict) else {"evidence": data} if isinstance(data, list) else {}

    @property
    def evidence(self) -> list:
        return self._observations().get("evidence") or []

    @property
    def missing(self) -> list:
        return self._observations().get("missing") or []

    @property
    def media(self) -> str | None:
        """'wireless' for an 802.11 association; otherwise the cable media come from the port information."""
        return self._observations().get("media") or ("wireless" if self.kind == "wireless" else None)

    @property
    def discovery_status(self) -> str:
        grade = self.evidence_grade
        if grade == "Confirmed" and (self.source_interface_id and self.destination_interface_id or self.kind == "wireless"):
            return "observed"
        if grade == "Inferred":
            return "inferred"
        if grade == "Logical":
            return "logical"
        return "manual" if grade == "Manual" else "unknown"

    @property
    def evidence_grade(self) -> str:
        """Confirmed, Inferred, Logical, Unknown (discovered links) or Manual (drawn or imported by a user)."""
        grade = self._observations().get("grade")
        if grade in ("Confirmed", "Inferred", "Logical", "Unknown"):
            return grade
        if self.kind in ("lab", "inventory"):
            return "Confirmed"
        if self.kind in ("lldp", "cdp"):
            status = self._observations().get("status")
            return "Inferred" if status == "inferred" else "Confirmed"
        if self.kind in ("mac", "inferred", "stp"):
            return "Inferred"
        if self.kind in ("subnet", "logical", "segment", "route"):
            return "Logical"
        return "Manual" if not self.kind else "Unknown"

    network: Mapped["Network"] = relationship(back_populates="links")
    source_device: Mapped["Device"] = relationship(foreign_keys=[source_device_id])
    destination_device: Mapped["Device"] = relationship(foreign_keys=[destination_device_id])
    source_interface: Mapped["Interface | None"] = relationship(foreign_keys=[source_interface_id])
    destination_interface: Mapped["Interface | None"] = relationship(
        foreign_keys=[destination_interface_id]
    )
