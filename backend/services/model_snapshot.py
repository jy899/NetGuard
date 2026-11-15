"""Before/after snapshots of the stored network model, so an applied fix can be undone.

`take` records every device's modelled state (interfaces, VLANs, static routes, ACL rules, gateway, facts) and the
interfaces each cable uses. `changed` keeps only what a fix altered (its "before" state), which is stored with the
execution. `restore` writes that state back. Device positions, names and other devices are never touched.
"""
from __future__ import annotations

from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from backend.models import AclRule, Device, Interface, Link, StaticRoute, Vlan

_ROWS = (("interfaces", Interface), ("vlans", Vlan), ("routes", StaticRoute), ("acl", AclRule))
_DEVICE_FIELDS = ("default_gateway", "config_facts")
_LINK_FIELDS = ("source_interface_id", "destination_interface_id", "evidence_json")


def _columns(model) -> list[str]:
    return [attr.key for attr in inspect(model).mapper.column_attrs]


def _row(obj, model) -> dict:
    return {key: getattr(obj, key) for key in _columns(model)}


def take(db: Session, network_id: int) -> dict:
    db.flush()
    devices = {}
    for device in db.scalars(select(Device).where(Device.network_id == network_id)):
        state = {"device": {f: getattr(device, f) for f in _DEVICE_FIELDS}}
        for key, model in _ROWS:
            rows = db.scalars(select(model).where(model.device_id == device.id).order_by(model.id))
            state[key] = [_row(r, model) for r in rows]
        devices[str(device.id)] = state
    links = {str(link.id): {f: getattr(link, f) for f in _LINK_FIELDS}
             for link in db.scalars(select(Link).where(Link.network_id == network_id))}
    return {"devices": devices, "links": links}


def changed(before: dict, after: dict) -> dict:
    """The "before" state of only the devices and cables that differ after the fix."""
    return {"devices": {k: v for k, v in before["devices"].items() if after["devices"].get(k) != v},
            "links": {k: v for k, v in before["links"].items() if after["links"].get(k) != v}}


def restore(db: Session, snapshot: dict) -> list[str]:
    """Write the recorded state back; returns the names of the devices restored."""
    # Cables first: a cable may still use an interface the fix added, which is removed below.
    for link_id, values in (snapshot or {}).get("links", {}).items():
        link = db.get(Link, int(link_id))
        if link is not None:
            for field, value in values.items():
                setattr(link, field, value)
    db.flush()
    names = []
    for device_id, state in (snapshot or {}).get("devices", {}).items():
        device = db.get(Device, int(device_id))
        if device is None:
            continue  # deleted since: nothing to restore
        for field, value in state["device"].items():
            setattr(device, field, value)
        for key, model in _ROWS:
            saved = {row["id"]: row for row in state[key]}
            current = {r.id: r for r in db.scalars(select(model).where(model.device_id == device.id))}
            for row_id, obj in current.items():
                if row_id not in saved:
                    db.delete(obj)  # added by the fix
            db.flush()
            for row_id, values in saved.items():
                obj = current.get(row_id)
                if obj is None:
                    db.add(model(**values))  # removed by the fix: put it back with its original id
                else:
                    for column, value in values.items():
                        if column != "id":
                            setattr(obj, column, value)
        names.append(device.name)
    db.flush()
    db.expire_all()
    return names
