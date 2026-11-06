from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from backend.core.errors import ConflictError, NotFoundError
from backend.models import Device, Link
from backend.schemas.device import DeviceCreate, DeviceUpdate
from backend.services import network_service


def get_device(db: Session, device_id: int) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise NotFoundError(f"Device {device_id} not found")
    return device


def list_devices(db: Session, network_id: int) -> list[Device]:
    network_service.get_network(db, network_id)
    return list(
        db.scalars(
            select(Device)
            .where(Device.network_id == network_id)
            .options(
                selectinload(Device.interfaces),
                selectinload(Device.vlans),
                selectinload(Device.static_routes),
                selectinload(Device.acl_rules),
            )
            .order_by(Device.id)
        )
    )


def _ensure_unique_name(db: Session, network_id: int, name: str, exclude_id: int | None = None) -> None:
    query = select(Device.id).where(
        Device.network_id == network_id, func.lower(Device.name) == name.lower()
    )
    if exclude_id is not None:
        query = query.where(Device.id != exclude_id)
    if db.scalar(query) is not None:
        raise ConflictError(f"A device named '{name}' already exists in this network")


def create_device(db: Session, network_id: int, data: DeviceCreate) -> Device:
    network = network_service.get_network(db, network_id)
    _ensure_unique_name(db, network_id, data.name)
    device = Device(network_id=network_id, **data.model_dump())
    db.add(device)
    network_service.touch(network)
    db.commit()
    db.refresh(device)
    return device


def update_device(db: Session, device_id: int, data: DeviceUpdate) -> Device:
    device = get_device(db, device_id)
    _ensure_unique_name(db, device.network_id, data.name, exclude_id=device_id)
    values = data.model_dump()
    for key in ("x_position", "y_position"):
        if values[key] is None:
            values.pop(key)
    for key, value in values.items():
        setattr(device, key, value)
    metadata = dict(device.network.metadata_json or {})
    discovery = dict(metadata.get('discovery', {}))
    facts = dict(discovery.get(str(device.id), {}))
    if facts.get('identity_unknown'):
        facts.update(identity_unknown=False, display_type=data.device_type, identity_source='user supplied')
        facts['evidence'] = list(facts.get('evidence', [])) + ['Device identity was entered manually in the stored model.']
        discovery[str(device.id)] = facts
        metadata['discovery'] = discovery
        device.network.metadata_json = metadata
    network_service.touch(device.network)
    db.commit()
    db.refresh(device)
    return device


def delete_device(db: Session, device_id: int) -> None:
    device = get_device(db, device_id)
    # Remove attached links explicitly (DB-level cascade is a safety net).
    for link in db.scalars(
        select(Link).where(or_(Link.source_device_id == device_id, Link.destination_device_id == device_id))
    ):
        db.delete(link)
    network_service.touch(device.network)
    db.delete(device)
    db.commit()
