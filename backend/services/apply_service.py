"""Records an approved change that the engineer deployed outside NetGuard in the stored network model.

Used for devices NetGuard must not change itself (anything that is not a laboratory device). NetGuard re-analyses
the change first and refuses anything it rates Do not deploy. Laboratory devices are changed by
remediation_service with backup, verification and rollback.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.errors import ConflictError, NotFoundError
from backend.models import AclRule, Assessment, Change, Device, Interface, StaticRoute, User, Vlan
from backend.services import analysis_service, network_service


def _get(db: Session, model, item_id, label: str):
    item = db.get(model, item_id) if item_id is not None else None
    if item is None:
        raise NotFoundError(f"{label} no longer exists")
    return item


def _mutate(db: Session, change: Change) -> None:
    p = change.parameters
    kind = change.change_type
    device = _get(db, Device, change.device_id, "Device")
    iface = _get(db, Interface, change.interface_id, "Interface") if change.interface_id else None
    if kind == "ip_address":
        iface.ip_address, iface.subnet_mask = p["ip_address"], p["subnet_mask"]
    elif kind == "default_gateway":
        device.default_gateway = p["gateway"]
    elif kind == "interface_status":
        iface.status = p["status"]
    elif kind == "ospf_area":
        iface.ospf_area = p["area"]
    elif kind == "ospf_network":
        iface.ospf_area = p["area"] if p["action"] == "advertise" else None
    elif kind == "static_route":
        if p["action"] == "add":
            db.add(StaticRoute(device_id=device.id, destination=p["destination"], next_hop=p["next_hop"]))
        else:
            route = _get(db, StaticRoute, p["route_id"], "Static route")
            if p["action"] == "remove":
                db.delete(route)
            else:
                route.destination, route.next_hop = p["destination"], p["next_hop"]
    elif kind == "acl_add":
        db.add(AclRule(device_id=device.id, acl_name=p.get("acl_name"), sequence=p["sequence"], action=p["action"],
                       protocol=p["protocol"], source=p["source"], destination=p["destination"], port=p.get("port")))
    elif kind == "acl_remove":
        db.delete(_get(db, AclRule, p["rule_id"], "ACL rule"))
    elif kind == "access_vlan":
        iface.vlan_id, iface.mode = p["vlan_id"], "access"
    elif kind == "vlan_database":
        if p["action"] == "add":
            db.add(Vlan(device_id=device.id, vlan_id=p["vlan_id"], name=p.get("name")))
        else:
            vlan = db.scalar(select(Vlan).where(Vlan.device_id == device.id, Vlan.vlan_id == p["vlan_id"]))
            if vlan is not None:
                db.delete(vlan)
    elif kind in ("interface_settings", "trunk_settings", "isolate_endpoint", "acl_reference", "stp_root",
                  "mgmt_hardening", "physical_remediation"):
        _mutate_from_model(db, change, device)
    network_service.touch(device.network)


def _mutate_from_model(db: Session, change: Change, device: Device) -> None:
    """Apply the change to the in-memory model (same code as the analysis), then store the affected fields."""
    import json

    from backend.models import Link
    from backend.services import change_detector
    from backend.services.network_model import load_model

    model = load_model(db, change.network_id)
    detected = change_detector.detect(model, change.device_id, change.interface_id, change.change_type, change.parameters)
    candidate = change_detector.apply(model, detected)
    touched, new_ids = {change.device_id}, {}
    if change.change_type == "stp_root":
        touched = set(candidate.devices)  # port roles change on every switch of the VLAN
    for device_id in touched:
        dev_m, row = candidate.device(device_id), db.get(Device, device_id)
        row.config_facts = dict(dev_m.facts) if dev_m.facts else row.config_facts
        existing = {i.id: i for i in db.scalars(select(Interface).where(Interface.device_id == device_id))}
        for iface_m in dev_m.interfaces.values():
            iface = existing.get(iface_m.id)
            if iface is None:
                iface = Interface(device_id=device_id, name=iface_m.name)
                db.add(iface)
                db.flush()
                new_ids[iface_m.id] = iface.id
                existing[iface.id] = iface
            for attr, column in (("ip", "ip_address"), ("mask", "subnet_mask"), ("vlan", "vlan_id"), ("mode", "mode"),
                                 ("status", "status"), ("ospf_area", "ospf_area"), ("speed_mbps", "speed_mbps"),
                                 ("allowed_vlans", "allowed_vlans"), ("native_vlan", "native_vlan"),
                                 ("stp_state", "stp_state"), ("duplex", "duplex"), ("mtu", "mtu"),
                                 ("ospf_hello", "ospf_hello"), ("ospf_dead", "ospf_dead"), ("acl_in", "acl_in"),
                                 ("acl_out", "acl_out"), ("error_count", "error_count"), ("description", "description")):
                setattr(iface, column, getattr(iface_m, attr))
        current = {v.vlan_id: v for v in db.scalars(select(Vlan).where(Vlan.device_id == device_id))}
        for vlan_id, name in dev_m.vlans.items():
            if vlan_id not in current:
                db.add(Vlan(device_id=device_id, vlan_id=vlan_id, name=name))
        if change.change_type in ("acl_reference", "mgmt_hardening"):
            stored = {r.id for r in db.scalars(select(AclRule).where(AclRule.device_id == device_id))}
            for rule in dev_m.acl:
                if rule.id not in stored:
                    db.add(AclRule(device_id=device_id, acl_name=rule.acl_name, sequence=rule.sequence,
                                   action=rule.action, protocol=rule.protocol, source=rule.source,
                                   destination=rule.destination, port=rule.port))
    for link_m in candidate.links.values():
        row = db.get(Link, link_m.id)
        if row is None:
            continue
        before = (row.source_interface_id, row.destination_interface_id)
        a_if, b_if = new_ids.get(link_m.a_if, link_m.a_if), new_ids.get(link_m.b_if, link_m.b_if)
        if link_m.observation.get("media_override") and not row._observations().get("media_override"):
            evidence = json.loads(row.evidence_json) if row.evidence_json else {}
            evidence = evidence if isinstance(evidence, dict) else {"evidence": evidence}
            evidence["media_override"] = True
            row.evidence_json = json.dumps(evidence)
        if before != (a_if, b_if) and a_if and b_if:
            row.source_interface_id, row.destination_interface_id = a_if, b_if


def apply_change(db: Session, change: Change, user: User | None) -> tuple[Change, Assessment]:
    """Record an approved change as deployed outside NetGuard (the engineer applied the commands himself)."""
    if change.status in ("applied", "rolled_back", "failed"):
        raise ConflictError("This change has already been executed")
    if change.status != "approved":
        raise ConflictError("Only an approved change can be recorded as deployed. Submit it for IT Manager approval first.")
    assessment = analysis_service.analyze_change(db, change, user)  # fresh analysis on the current network
    if assessment.recommendation == "DO_NOT_DEPLOY":
        raise ConflictError(
            f"NetGuard recommends DO NOT DEPLOY ({assessment.risk_level} {assessment.total_risk_score}/100). "
            "Modify the change before applying it.")
    _mutate(db, change)
    change.status = "applied"
    assessment.saved = True
    assessment.saved_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    db.refresh(change)
    return change, analysis_service.get_assessment(db, assessment.id)
