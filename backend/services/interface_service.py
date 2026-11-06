from __future__ import annotations

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

import ipaddress

from backend.core.errors import ConflictError, NotFoundError, ValidationFailed
from backend.models import L3_TYPES, Interface, Link
from backend.schemas.interface import InterfaceCreate, InterfaceUpdate
from backend.services import device_service, network_service


def get_interface(db: Session, interface_id: int) -> Interface:
    interface = db.get(Interface, interface_id)
    if interface is None:
        raise NotFoundError(f"Interface {interface_id} not found")
    return interface


def list_interfaces(db: Session, device_id: int) -> list[Interface]:
    device_service.get_device(db, device_id)
    return list(db.scalars(select(Interface).where(Interface.device_id == device_id).order_by(Interface.id)))


def _ensure_unique_name(db: Session, device_id: int, name: str, exclude_id: int | None = None) -> None:
    query = select(Interface.id).where(
        Interface.device_id == device_id, func.lower(Interface.name) == name.lower()
    )
    if exclude_id is not None:
        query = query.where(Interface.id != exclude_id)
    if db.scalar(query) is not None:
        raise ConflictError(f"Interface '{name}' already exists on this device")


def _ensure_no_overlap(db: Session, device, data, exclude_id: int | None = None) -> None:
    """Like IOS, a router or firewall cannot have two interfaces in overlapping subnets."""
    if device.device_type not in L3_TYPES or not data.ip_address or not data.subnet_mask:
        return
    network = ipaddress.IPv4Interface(f"{data.ip_address}/{data.subnet_mask}").network
    for other in device.interfaces:
        if other.id == exclude_id or not other.ip_address or not other.subnet_mask:
            continue
        other_net = ipaddress.IPv4Interface(f"{other.ip_address}/{other.subnet_mask}").network
        if network.overlaps(other_net):
            raise ValidationFailed(f"{network} overlaps {other.name} ({other.ip_address}/{other_net.prefixlen})")


def create_interface(db: Session, device_id: int, data: InterfaceCreate) -> Interface:
    device = device_service.get_device(db, device_id)
    _ensure_unique_name(db, device_id, data.name)
    _ensure_no_overlap(db, device, data)
    interface = Interface(device_id=device_id, **data.model_dump())
    db.add(interface)
    network_service.touch(device.network)
    db.commit()
    db.refresh(interface)
    return interface


def update_interface(db: Session, interface_id: int, data: InterfaceUpdate) -> Interface:
    interface = get_interface(db, interface_id)
    _ensure_unique_name(db, interface.device_id, data.name, exclude_id=interface_id)
    _ensure_no_overlap(db, interface.device, data, exclude_id=interface_id)
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(interface, key, value)
    network_service.touch(interface.device.network)
    db.commit()
    db.refresh(interface)
    return interface


def delete_interface(db: Session, interface_id: int) -> None:
    """Delete an interface; links that used it are kept with the interface cleared."""
    interface = get_interface(db, interface_id)
    db.execute(
        update(Link).where(Link.source_interface_id == interface_id).values(source_interface_id=None)
    )
    db.execute(
        update(Link)
        .where(Link.destination_interface_id == interface_id)
        .values(destination_interface_id=None)
    )
    network = interface.device.network
    meta = network.metadata_json or {}
    facts = (meta.get("discovery") or {}).get(str(interface.device_id))
    if facts and facts.get("iface_ids"):
        # Discovery remembers interface ids by observed port name; a deleted id may be reused by SQLite.
        discovery = {key: dict(value) for key, value in meta["discovery"].items()}
        discovery[str(interface.device_id)]["iface_ids"] = {name: iid for name, iid in facts["iface_ids"].items()
                                                            if iid != interface_id}
        network.metadata_json = {**meta, "discovery": discovery}
    network_service.touch(network)
    db.delete(interface)
    db.commit()
