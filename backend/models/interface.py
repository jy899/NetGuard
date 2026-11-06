from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import JSON, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.session import Base

if TYPE_CHECKING:
    from backend.models.device import Device

INTERFACE_STATUSES = ("up", "down", "admin-down")
SWITCHPORT_MODES = ("access", "trunk")


class Interface(Base):
    __tablename__ = "interfaces"
    __table_args__ = (UniqueConstraint("device_id", "name", name="uq_interface_name_per_device"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(String(120))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    subnet_mask: Mapped[str | None] = mapped_column(String(45))
    # Switch ports: access VLAN. Router sub-interfaces (e.g. Gi0/0/1.10): 802.1Q tag.
    vlan_id: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="up")
    # Router/firewall interfaces: OSPF area this interface's network is advertised in (None = not in OSPF).
    ospf_area: Mapped[int | None] = mapped_column(Integer)
    # Switch ports: "access" or "trunk". None = derived (VLAN set -> access, otherwise trunk).
    mode: Mapped[str | None] = mapped_column(String(10))
    speed_mbps: Mapped[int | None] = mapped_column(Integer)
    allowed_vlans: Mapped[list | None] = mapped_column(JSON)
    native_vlan: Mapped[int | None] = mapped_column(Integer)
    stp_state: Mapped[str | None] = mapped_column(String(16))
    duplex: Mapped[str | None] = mapped_column(String(8))
    mtu: Mapped[int | None] = mapped_column(Integer)
    ospf_hello: Mapped[int | None] = mapped_column(Integer)
    ospf_dead: Mapped[int | None] = mapped_column(Integer)
    acl_in: Mapped[str | None] = mapped_column(String(64))
    acl_out: Mapped[str | None] = mapped_column(String(64))
    # Input plus output error counters from the last collection (None = not collected).
    error_count: Mapped[int | None] = mapped_column(Integer)

    device: Mapped["Device"] = relationship(back_populates="interfaces")
