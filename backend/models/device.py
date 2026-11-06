from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.session import Base

if TYPE_CHECKING:
    from backend.models.config import AclRule, StaticRoute, Vlan
    from backend.models.interface import Interface
    from backend.models.network import Network

# Supported device types for NetGuard.
DEVICE_TYPES = ("router", "switch", "firewall", "pc", "server", "internet")
L3_TYPES = ("router", "firewall")
HOST_TYPES = ("pc", "server")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("network_id", "name", name="uq_device_name_per_network"), {"sqlite_autoincrement": True})

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network_id: Mapped[int] = mapped_column(
        ForeignKey("networks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    device_type: Mapped[str] = mapped_column(String(20), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(64))
    model: Mapped[str | None] = mapped_column(String(64))
    management_ip: Mapped[str | None] = mapped_column(String(45))
    x_position: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    y_position: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Hosts (PC/server): default gateway used by the IP/gateway checks.
    default_gateway: Mapped[str | None] = mapped_column(String(45))
    # Laboratory device (imported from EVE-NG or GNS3): the only kind NetGuard may change, after approval.
    is_lab: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")
    platform: Mapped[str | None] = mapped_column(String(16))  # cisco-ios, cisco-iosxe, frr
    # Security and hygiene facts parsed from the running configuration; never secrets themselves.
    config_facts: Mapped[dict | None] = mapped_column(JSON)
    # How NetGuard reaches the device: lab console, lab node reference, SSH port. No credentials.
    access: Mapped[dict | None] = mapped_column(JSON)
    # Operational telemetry from the last collection: recent syslog messages and interface counters.
    telemetry: Mapped[dict | None] = mapped_column(JSON)

    @property
    def role(self) -> str:
        """Display role from stored discovery evidence; device type stays unchanged."""
        facts = ((self.network.metadata_json or {}).get("discovery", {}).get(str(self.id), {})
                 if self.network else {})
        role = str(facts.get("role") or "").lower()
        if facts.get("identity_unknown"):
            return "unknown"
        if facts.get("identity_source") == "user supplied":
            return self.device_type
        for word, icon in (("printer", "printer"), ("camera", "camera"), ("phone", "phone"),
                           ("wireless", "ap"), ("access point", "ap"), ("guest", "guest"),
                           ("unknown", "unknown"), ("laptop", "laptop")):
            if word in role:
                return icon
        # The scan's generic "laptop" icon is not evidence of a laptop; keep the device type (e.g. PC).
        icon = facts.get("icon")
        return icon if icon in ("printer", "camera", "phone", "ap", "unknown") else self.device_type

    network: Mapped["Network"] = relationship(back_populates="devices")
    interfaces: Mapped[list["Interface"]] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True, order_by="Interface.id"
    )
    vlans: Mapped[list["Vlan"]] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True, order_by="Vlan.vlan_id"
    )
    static_routes: Mapped[list["StaticRoute"]] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True, order_by="StaticRoute.id"
    )
    acl_rules: Mapped[list["AclRule"]] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True, order_by="AclRule.sequence"
    )
