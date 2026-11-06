from __future__ import annotations

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, selectinload

from backend.core.errors import ConflictError, NotFoundError, ValidationFailed
from backend.models import Device, Interface, Link
from backend.schemas.link import LinkCreate, LinkOut
from backend.services import network_service
from backend.services.interface_naming import port_info

_LINK_LOAD_OPTIONS = (
    selectinload(Link.source_device),
    selectinload(Link.destination_device),
    selectinload(Link.source_interface),
    selectinload(Link.destination_interface),
)


def to_out(link: Link) -> LinkOut:
    out = LinkOut.model_validate(link)
    out.source_device_name = link.source_device.name if link.source_device else None
    out.destination_device_name = link.destination_device.name if link.destination_device else None
    out.source_interface_name = link.source_interface.name if link.source_interface else None
    out.destination_interface_name = link.destination_interface.name if link.destination_interface else None
    for side in ("source", "destination"):
        device = getattr(link, f"{side}_device")
        interface = getattr(link, f"{side}_interface")
        if device and interface:
            setattr(out, f"{side}_port_info", port_info(device.vendor, device.model, device.device_type, interface.name))
            setattr(out, f"{side}_interface_description", interface.description)
    a_media = (out.source_port_info or {}).get("media")
    b_media = (out.destination_port_info or {}).get("media")
    out.media = link.media or (a_media if a_media and a_media == b_media else None)
    interfaces = [i for i in (link.source_interface, link.destination_interface) if i]
    if link.state not in ("suspended", "down", "unknown"):
        out.state = "down" if any(i.status != "up" for i in interfaces) else "blocked" if any(
            i.stp_state in ("blocking", "discarding") for i in interfaces) else "up" if len(interfaces) == 2 or (
            interfaces and link.kind in ("wireless", "segment", "route", "stp", "mac")) else "unknown"
    speeds = [i.speed_mbps for i in interfaces if i.speed_mbps]
    out.speed_mbps = min(speeds) if speeds else link.speed_mbps
    if a_media and b_media and a_media != b_media:
        out.state = "down"
    return out


def get_link(db: Session, link_id: int) -> Link:
    link = db.get(Link, link_id)
    if link is None:
        raise NotFoundError(f"Link {link_id} not found")
    return link


def list_links(db: Session, network_id: int) -> list[Link]:
    network_service.get_network(db, network_id)
    return list(
        db.scalars(
            select(Link).where(Link.network_id == network_id).options(*_LINK_LOAD_OPTIONS).order_by(Link.id)
        )
    )


def _device_in_network(db: Session, device_id: int, network_id: int, role: str) -> Device:
    device = db.get(Device, device_id)
    if device is None or device.network_id != network_id:
        raise ValidationFailed(f"{role} device {device_id} does not belong to this network")
    return device


def _interface_on_device(db: Session, interface_id: int | None, device: Device, role: str) -> Interface | None:
    if interface_id is None:
        return None
    interface = db.get(Interface, interface_id)
    if interface is None or interface.device_id != device.id:
        raise ValidationFailed(f"{role} interface does not belong to device {device.name}")
    in_use = db.scalar(
        select(Link.id).where(
            or_(Link.source_interface_id == interface_id, Link.destination_interface_id == interface_id)
        )
    )
    if in_use is not None:
        raise ConflictError(f"Interface {device.name} {interface.name} is already connected")
    return interface


def create_link(db: Session, network_id: int, data: LinkCreate) -> Link:
    network = network_service.get_network(db, network_id)
    if data.source_device_id == data.destination_device_id:
        raise ValidationFailed("A link must connect two different devices")

    source = _device_in_network(db, data.source_device_id, network_id, "Source")
    destination = _device_in_network(db, data.destination_device_id, network_id, "Destination")
    _interface_on_device(db, data.source_interface_id, source, "Source")
    _interface_on_device(db, data.destination_interface_id, destination, "Destination")

    # Without interfaces, only one plain link is allowed between the same two devices.
    if data.source_interface_id is None and data.destination_interface_id is None:
        pair = or_(
            and_(Link.source_device_id == source.id, Link.destination_device_id == destination.id),
            and_(Link.source_device_id == destination.id, Link.destination_device_id == source.id),
        )
        duplicate = db.scalar(
            select(Link.id).where(
                pair, Link.source_interface_id.is_(None), Link.destination_interface_id.is_(None)
            )
        )
        if duplicate is not None:
            raise ConflictError(f"{source.name} and {destination.name} are already connected without interfaces")

    link = Link(network_id=network_id, **data.model_dump())
    db.add(link)
    network_service.touch(network)
    db.commit()
    return db.scalars(select(Link).where(Link.id == link.id).options(*_LINK_LOAD_OPTIONS)).one()


def delete_link(db: Session, link_id: int) -> None:
    link = get_link(db, link_id)
    network_service.touch(link.network)
    db.delete(link)
    db.commit()
