"""Simplified device configuration used by the Prototype rule engine.

Filled by hand in the Configuration dialog, or by the config import
(config_import.py) from Cisco show running-config output.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.session import Base

if TYPE_CHECKING:
    from backend.models.device import Device
    from backend.models.network import Network

ACL_ACTIONS = ("permit", "deny")
PROTOCOLS = ("ip", "tcp", "udp", "icmp")
INTENT_ACTIONS = ("allow", "deny")
CRITICALITIES = ("low", "medium", "high", "critical")


class Vlan(Base):
    """VLAN database entry on a switch."""

    __tablename__ = "vlans"
    __table_args__ = (UniqueConstraint("device_id", "vlan_id", name="uq_vlan_per_device"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    vlan_id: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str | None] = mapped_column(String(64))

    device: Mapped["Device"] = relationship(back_populates="vlans")


class StaticRoute(Base):
    __tablename__ = "static_routes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    destination: Mapped[str] = mapped_column(String(50), nullable=False)  # CIDR, e.g. 0.0.0.0/0
    next_hop: Mapped[str] = mapped_column(String(45), nullable=False)

    device: Mapped["Device"] = relationship(back_populates="static_routes")


class AclRule(Base):
    """One entry of an access list on a router, firewall or multilayer switch, evaluated in sequence order.

    Named entries (acl_name) belong to an access list that filters only where an interface applies it
    (`ip access-group NAME in|out`), in that direction. Entries without a name form the device's unnamed rule list,
    which filters all traffic routed through the device (models built by hand). First match wins; an access list
    with entries ends with an implicit deny.
    """

    __tablename__ = "acl_rules"
    __table_args__ = (UniqueConstraint("device_id", "acl_name", "sequence", name="uq_acl_sequence_per_list"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    acl_name: Mapped[str | None] = mapped_column(String(64))
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(10), nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="ip")
    source: Mapped[str] = mapped_column(String(50), nullable=False, default="any")  # "any" or CIDR
    destination: Mapped[str] = mapped_column(String(50), nullable=False, default="any")
    port: Mapped[int | None] = mapped_column(Integer)  # destination port, tcp/udp only

    device: Mapped["Device"] = relationship(back_populates="acl_rules")


class NetworkIntent(Base):
    """A required flow (allow) or required isolation (deny) between two devices.

    Listed under the Final schema in the brief, but brief Scenario B needs
    "Finance -> ERP TCP/443 = ALLOW", so a simple form exists in the Prototype.
    """

    __tablename__ = "network_intents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    destination_device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="ip")
    port: Mapped[int | None] = mapped_column(Integer)
    expected_action: Mapped[str] = mapped_column(String(10), nullable=False, default="allow")
    criticality: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")

    network: Mapped["Network"] = relationship(back_populates="intents")
    source_device: Mapped["Device"] = relationship(foreign_keys=[source_device_id])
    destination_device: Mapped["Device"] = relationship(foreign_keys=[destination_device_id])
