"""Import an EVE-NG lab or GNS3 project as a NetGuard workspace.

The lab definition is the authoritative cabling record: every cable becomes a Confirmed link. Devices are marked
as laboratory devices, the only devices NetGuard may change (after IT Manager approval). Startup configurations
stored in an EVE-NG lab are parsed as a first configuration baseline; running configurations are collected from the
node consoles or over SSH with collection_service. Lab server credentials are used for the request only.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.collectors import labs
from backend.core.errors import ValidationFailed
from backend.models import Device, Interface, Link, Network
from backend.services import device_state, history_service, network_service
from backend.services.demo_topology import _available_name

PROVIDER_LABEL = {"eve-ng": "EVE-NG", "gns3": "GNS3", "packet-tracer": "Packet Tracer"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def _client(provider: str, server: str, username: str, password: str, verify_tls: bool):
    try:
        return labs.client(provider, server, username, password, verify_tls)
    except labs.LabError as exc:
        raise ValidationFailed(str(exc)) from None


def connect(provider: str, server: str, username: str, password: str, verify_tls: bool = False) -> dict:
    client = _client(provider, server, username, password, verify_tls)
    try:
        client.login()
        found = client.labs()
    except labs.LabAuthError as exc:
        return {"provider": provider, "server": client.server, "connected": False, "labs": [], "message": str(exc)}
    except labs.LabError as exc:
        raise ValidationFailed(str(exc)) from None
    return {"provider": provider, "server": client.server, "connected": True, "labs": found,
            "message": f"Connected to {PROVIDER_LABEL[provider]} at {client.server}: {len(found)} lab(s) found."}


def _layout(topology: labs.LabTopology) -> dict[str, tuple[float, float]]:
    coords = {n.ref: (n.x, n.y) for n in topology.nodes if n.x is not None and n.y is not None}
    if len(coords) == len(topology.nodes) and coords:
        scale = 12.0 if max(max(abs(x), abs(y)) for x, y in coords.values()) <= 100 else 1.0  # EVE-NG percentages
        return {ref: (x * scale, y * scale) for ref, (x, y) in coords.items()}
    return {n.ref: ((i % 6) * 200.0, (i // 6) * 180.0) for i, n in enumerate(topology.nodes)}


def import_lab(db: Session, user, provider: str, server: str, username: str, password: str, lab_id: str,
               verify_tls: bool = False, name: str | None = None) -> Network:
    client = _client(provider, server, username, password, verify_tls)
    try:
        client.login()
        topology = client.topology(lab_id, with_configs=True)
    except labs.LabError as exc:
        raise ValidationFailed(str(exc)) from None
    label = PROVIDER_LABEL[provider]
    network = Network(
        name=_available_name(db, name or f"{label}: {topology.name}"), network_type="Lab",
        description=f"{label} lab '{topology.name}' imported from {client.server}.", created_by=user.id,
        environment="virtual", source=provider, is_simulated=False,
        metadata_json={"provider": provider, "server": client.server, "lab_id": topology.lab_id,
                       "lab_name": topology.name, "verify_tls": verify_tls, "imported_at": _now(),
                       "interface_naming_version": 1, "live_device_contact": True,
                       "scope": {"authorised": [], "excluded": [], "untrusted": []}})
    db.add(network)
    db.flush()
    _sync(db, user, network, topology)
    db.commit()
    out = network_service.to_out(db, network).model_dump(mode="json")
    history_service.record(db, user, network.id, "connection", f"{label} lab imported",
                           {"device_count": out["device_count"], "link_count": out["link_count"], "status": "completed"},
                           {"server": client.server, "lab": topology.name, "nodes": len(topology.nodes),
                            "links": len(topology.links), "startup_configs": len(topology.configs)})
    return network


def refresh_lab(db: Session, user, network: Network, username: str, password: str) -> Network:
    meta = network.metadata_json or {}
    if network.source not in PROVIDER_LABEL:
        raise ValidationFailed("This network was not imported from EVE-NG or GNS3.")
    client = _client(network.source, meta.get("server", ""), username, password, meta.get("verify_tls", False))
    try:
        client.login()
        topology = client.topology(meta.get("lab_id", ""), with_configs=False)
    except labs.LabError as exc:
        raise ValidationFailed(str(exc)) from None
    _sync(db, user, network, topology)
    db.commit()
    return network


def _sync(db: Session, user, network: Network, topology: labs.LabTopology, lab: bool = True) -> None:
    """Create or update devices and lab cables; reviewed device names and positions are kept.

    lab=False: a project file (no running lab behind it): devices are not laboratory devices and have no console."""
    label = PROVIDER_LABEL[topology.provider]
    devices = {d.access.get("node"): d for d in db.scalars(select(Device).where(Device.network_id == network.id))
               if d.access and d.access.get("node")}
    positions = _layout(topology)
    taken = {d.name for d in devices.values()}
    warnings: list[str] = []
    for node in topology.nodes:
        device = devices.get(node.ref)
        access = {"lab": topology.provider, "node": node.ref, "console": node.console, "template": node.template,
                  "platform": node.platform, "status": node.status, "bridge": node.bridge}
        if device is None:
            name = node.name if node.name not in taken else f"{node.name}-{node.ref}"
            taken.add(name)
            x, y = positions.get(node.ref, (0.0, 0.0))
            device = Device(network_id=network.id, name=name[:64], device_type=node.kind,
                            vendor="Cisco" if node.platform == "cisco-ios" else "FRRouting" if node.platform == "frr" else None,
                            model=node.template, x_position=x, y_position=y, is_lab=lab and not node.bridge,
                            platform=node.platform, access=access if lab else {**access, "console": None})
            db.add(device)
            db.flush()
            devices[node.ref] = device
        else:
            device.access = access if lab else {**access, "console": None}
        existing = {i.name for i in db.scalars(select(Interface).where(Interface.device_id == device.id))}
        for port in node.interfaces:
            if port and port not in existing:
                db.add(Interface(device_id=device.id, name=port[:64], status="up"))
                existing.add(port)
    db.flush()
    # Startup configurations from the lab definition give a first configuration baseline (endpoints too).
    endpoint_configs = {}
    for ref, text in topology.configs.items():
        device = devices.get(ref)
        if device is None:
            continue
        if device.device_type in ("pc", "server"):
            endpoint_configs[ref] = text  # applied once the cables (and so the NIC names) exist
            continue
        dev, warn = device_state.parse_one(text, device.name)
        if dev is not None and device.device_type in ("router", "switch"):
            device.device_type = "switch" if device_state.has_switchports(text) else device.device_type
        if dev is not None:
            device_state.apply_config(db, device, dev, warnings)
            device_state.store_config(db, device, text, f"{topology.provider}-startup", "startup", user)
        warnings += warn
    for link in db.scalars(select(Link).where(Link.network_id == network.id, Link.kind == "lab")):
        db.delete(link)
    db.flush()
    ifaces = {(i.device_id, i.name): i for i in db.scalars(select(Interface).join(Device)
                                                           .where(Device.network_id == network.id))}
    for cable in topology.links:
        a, b = devices.get(cable.a), devices.get(cable.b)
        if a is None or b is None:
            continue

        def port(dev, name):
            if not name:
                return None
            row = ifaces.get((dev.id, name))
            if row is None:
                row = Interface(device_id=dev.id, name=name[:64], status="up")
                db.add(row)
                db.flush()
                ifaces[(dev.id, name)] = row
            return row
        ia, ib = port(a, cable.a_port), port(b, cable.b_port)
        evidence = {"evidence": [f"{label} lab definition '{topology.name}': {a.name} {cable.a_port or '?'} is cabled to "
                                 f"{b.name} {cable.b_port or '?'}."],
                    "missing": [], "origin": topology.provider, "connectivity": "physical", "status": "confirmed",
                    "grade": "Confirmed"}
        db.add(Link(network_id=network.id, source_device_id=a.id, source_interface_id=ia.id if ia else None,
                    destination_device_id=b.id, destination_interface_id=ib.id if ib else None, kind="lab", state="up",
                    confidence=1.0, evidence_json=json.dumps(evidence)))
    db.flush()
    for ref, text in endpoint_configs.items():
        if not device_state.apply_endpoint(db, devices[ref], text):
            warnings.append(f"{devices[ref].name}: no IPv4 address found in its configuration.")
    meta = dict(network.metadata_json or {})
    meta.update(lab_refreshed_at=_now(), lab_warnings=warnings[:50],
                startup_configs=len(topology.configs), lab_nodes=len(topology.nodes))
    network.metadata_json = meta
    db.flush()
