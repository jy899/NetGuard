"""What is connected to each port of a switch that NetGuard has read (its MAC address table, resolved).

Every learned MAC address is listed under the port it was learned on, with the IP address (from this computer's
ARP cache and from every router ARP table that was read), the vendor (OUI) and the discovered device when there
is one. A port that leads to another network device is marked as an uplink: the addresses on it are behind that
device, not cabled to this port. Clients with no IP address still appear, by MAC address.
"""
from __future__ import annotations

import re
from collections import defaultdict

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.models import Device, Interface, Link, Network

INFRASTRUCTURE = ("router", "switch", "firewall")
UPLINK_MACS = 8  # more addresses than this on a port with no known neighbour: probably an unmanaged switch or AP


def _natural(name: str):
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", name or "")]


def table(db: Session, device: Device) -> dict:
    from backend.collectors import netutil

    network = db.get(Network, device.network_id)
    meta = (network.metadata_json or {}) if network else {}
    observations = meta.get("observations", [])
    discovery = meta.get("discovery", {})
    ip = (discovery.get(str(device.id)) or {}).get("ip") or device.management_ip
    read = next((o for o in observations if o.get("authenticated") and o.get("observed_by") == ip
                 and o.get("technique") == "mac-table"), None)
    if read is None:
        return {"device_id": device.id, "read": False, "ports": [], "clients": 0,
                "note": "Sign in to this switch (SSH or SNMP) to see what is connected to each port."}
    mac_ip: dict[str, str] = {}
    for o in observations:
        if o.get("technique") == "arp" and (o.get("facts") or {}).get("mac"):
            mac_ip.setdefault(o["facts"]["mac"].lower(), o["subject"])
    for o in observations:
        if o.get("authenticated") and o.get("technique") == "arp-table":
            for row in o["facts"].get("entries", []):
                if row.get("mac") and row.get("ip"):
                    mac_ip.setdefault(row["mac"].lower(), row["ip"])
    devices = {d.id: d for d in db.scalars(select(Device).where(Device.network_id == device.network_id))}
    by_ip = {facts.get("ip"): devices[int(did)] for did, facts in discovery.items() if int(did) in devices}
    names = {i.id: i.name for i in db.scalars(select(Interface).where(Interface.device_id == device.id))}
    neighbour: dict[str, dict] = {}
    for link in db.scalars(select(Link).where(or_(Link.source_device_id == device.id, Link.destination_device_id == device.id))):
        mine, other = ((link.source_interface_id, link.destination_device_id) if link.source_device_id == device.id
                       else (link.destination_interface_id, link.source_device_id))
        peer = devices.get(other)
        if mine in names and peer is not None:
            neighbour[names[mine]] = {"name": peer.name, "id": peer.id, "infrastructure": peer.device_type in INFRASTRUCTURE,
                                      "grade": link.evidence_grade}
    by_port = defaultdict(list)
    for row in read["facts"].get("rows", []):
        mac = str(row.get("mac") or "").lower()
        address = mac_ip.get(mac)
        known = by_ip.get(address)
        by_port[row.get("port") or "?"].append({
            "mac": mac, "vlan": row.get("vlan"), "ip": address, "vendor": netutil.oui_vendor(mac),
            "device_id": known.id if known is not None and known.id != device.id else None,
            "name": known.name if known is not None and known.id != device.id else None})
    ports, total = [], 0
    for port in sorted(by_port, key=_natural):
        clients = sorted(by_port[port], key=lambda c: (c["ip"] is None, _natural(c["ip"] or c["mac"])))
        peer = neighbour.get(port)
        uplink = bool(peer and peer["infrastructure"])
        kind = "uplink" if uplink else "shared" if len(clients) > UPLINK_MACS else "edge"
        if not uplink:
            total += len(clients)
        ports.append({"port": port, "kind": kind, "neighbour": peer["name"] if peer else None,
                      "grade": peer["grade"] if peer else None, "count": len(clients), "clients": clients[:60]})
    return {"device_id": device.id, "read": True, "ports": ports, "clients": total, "method": read.get("method"),
            "note": None}
