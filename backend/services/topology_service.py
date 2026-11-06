"""Topology read/save operations.

Path finding for analysis lives in forwarding.py; this module only loads the
topology for the UI and persists the layout.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.errors import ValidationFailed
from backend.models import Device
from backend.schemas.config import IntentOut
from backend.schemas.device import DeviceOut
from backend.schemas.topology import DevicePosition, TopologyOut
from backend.services import config_service, device_service, link_service, network_service


def get_topology(db: Session, network_id: int) -> TopologyOut:
    network = network_service.get_network(db, network_id)
    devices = device_service.list_devices(db, network_id)
    links = link_service.list_links(db, network_id)
    device_rows = [DeviceOut.model_validate(d) for d in devices]
    discovery = (network.metadata_json or {}).get('discovery', {})
    for row in device_rows:
        if discovery.get(str(row.id), {}).get('identity_unknown'):
            # Shown as an unidentified device; its addresses and MAC vendor are evidence and stay visible.
            row.device_type = 'unknown'
    return TopologyOut(
        network=network_service.to_out(db, network),
        devices=device_rows,
        links=[link_service.to_out(link) for link in links],
        intents=[IntentOut.model_validate(i) for i in config_service.list_intents(db, network_id)],
    )


def save_positions(db: Session, network_id: int, positions: list[DevicePosition]) -> int:
    network = network_service.get_network(db, network_id)
    if not positions:
        return 0
    ids = {p.device_id for p in positions}
    devices = {d.id: d for d in db.scalars(select(Device).where(Device.id.in_(ids)))}
    foreign = [i for i in ids if i not in devices or devices[i].network_id != network_id]
    if foreign:
        raise ValidationFailed(f"Devices {sorted(foreign)} do not belong to this network")
    moved = []
    for position in positions:
        device = devices[position.device_id]
        x, y = round(position.x, 2), round(position.y, 2)
        if (round(device.x_position or 0, 2), round(device.y_position or 0, 2)) != (x, y):
            moved.append(device.id)
        device.x_position = x
        device.y_position = y
    meta = network.metadata_json or {}
    if moved and meta.get("method") == "smart":
        # The frontend sends every node on Save; only devices the user actually moved stop auto-placement.
        discovery = {key: dict(value) for key, value in meta.get("discovery", {}).items()}
        for device_id in moved:
            if str(device_id) in discovery:
                discovery[str(device_id)]["position_source"] = "user"
        network.metadata_json = {**meta, "discovery": discovery}
    network_service.touch(network)
    db.commit()
    return len(positions)
