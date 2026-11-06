"""CRUD for simplified device configuration (VLANs, static routes, ACL) and required flows."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.errors import ConflictError, NotFoundError, ValidationFailed
from backend.models import L3_TYPES, AclRule, Device, NetworkIntent, StaticRoute, Vlan
from backend.schemas.config import AclRuleCreate, IntentCreate, StaticRouteCreate, VlanCreate
from backend.services import device_service, network_service


def _get(db: Session, model, item_id: int, label: str):
    item = db.get(model, item_id)
    if item is None:
        raise NotFoundError(f"{label} {item_id} not found")
    return item


def _require_type(device: Device, types: tuple[str, ...], what: str) -> None:
    if device.device_type not in types:
        raise ValidationFailed(f"{what} can only be configured on: {', '.join(types)}")


def _commit(db: Session, device: Device, item):
    network_service.touch(device.network)
    db.commit()
    db.refresh(item)
    return item


# ------------------------------------------------------------------ VLANs
def create_vlan(db: Session, device_id: int, data: VlanCreate) -> Vlan:
    device = device_service.get_device(db, device_id)
    _require_type(device, ("switch",), "VLANs")
    if db.scalar(select(Vlan.id).where(Vlan.device_id == device_id, Vlan.vlan_id == data.vlan_id)):
        raise ConflictError(f"VLAN {data.vlan_id} already exists on {device.name}")
    vlan = Vlan(device_id=device_id, **data.model_dump())
    db.add(vlan)
    return _commit(db, device, vlan)


def update_vlan(db: Session, vlan_id: int, data: VlanCreate) -> Vlan:
    vlan = _get(db, Vlan, vlan_id, "VLAN")
    clash = db.scalar(
        select(Vlan.id).where(Vlan.device_id == vlan.device_id, Vlan.vlan_id == data.vlan_id, Vlan.id != vlan_id)
    )
    if clash:
        raise ConflictError(f"VLAN {data.vlan_id} already exists on this switch")
    vlan.vlan_id, vlan.name = data.vlan_id, data.name
    return _commit(db, vlan.device, vlan)


def delete_vlan(db: Session, vlan_id: int) -> None:
    vlan = _get(db, Vlan, vlan_id, "VLAN")
    network_service.touch(vlan.device.network)
    db.delete(vlan)
    db.commit()


# ----------------------------------------------------------- static routes
def create_route(db: Session, device_id: int, data: StaticRouteCreate) -> StaticRoute:
    device = device_service.get_device(db, device_id)
    _require_type(device, L3_TYPES, "Static routes")
    if db.scalar(
        select(StaticRoute.id).where(StaticRoute.device_id == device_id, StaticRoute.destination == data.destination)
    ):
        raise ConflictError(f"{device.name} already has a static route to {data.destination}")
    route = StaticRoute(device_id=device_id, **data.model_dump())
    db.add(route)
    return _commit(db, device, route)


def update_route(db: Session, route_id: int, data: StaticRouteCreate) -> StaticRoute:
    route = _get(db, StaticRoute, route_id, "Static route")
    clash = db.scalar(
        select(StaticRoute.id).where(
            StaticRoute.device_id == route.device_id,
            StaticRoute.destination == data.destination,
            StaticRoute.id != route_id,
        )
    )
    if clash:
        raise ConflictError(f"A static route to {data.destination} already exists")
    route.destination, route.next_hop = data.destination, data.next_hop
    return _commit(db, route.device, route)


def delete_route(db: Session, route_id: int) -> None:
    route = _get(db, StaticRoute, route_id, "Static route")
    network_service.touch(route.device.network)
    db.delete(route)
    db.commit()


# --------------------------------------------------------------------- ACL
def create_acl_rule(db: Session, device_id: int, data: AclRuleCreate) -> AclRule:
    device = device_service.get_device(db, device_id)
    if device.device_type not in L3_TYPES and not (device.device_type == "switch" and (device.config_facts or {}).get("ip_routing")):
        _require_type(device, L3_TYPES, "ACL rules")
    if db.scalar(select(AclRule.id).where(AclRule.device_id == device_id, AclRule.sequence == data.sequence,
                                          AclRule.acl_name.is_(None) if data.acl_name is None else AclRule.acl_name == data.acl_name)):
        raise ConflictError(f"Sequence {data.sequence} is already used in this access list on {device.name}")
    rule = AclRule(device_id=device_id, **data.model_dump())
    db.add(rule)
    return _commit(db, device, rule)


def update_acl_rule(db: Session, rule_id: int, data: AclRuleCreate) -> AclRule:
    rule = _get(db, AclRule, rule_id, "ACL rule")
    clash = db.scalar(
        select(AclRule.id).where(
            AclRule.device_id == rule.device_id, AclRule.sequence == data.sequence, AclRule.id != rule_id,
            AclRule.acl_name.is_(None) if data.acl_name is None else AclRule.acl_name == data.acl_name,
        )
    )
    if clash:
        raise ConflictError(f"Sequence {data.sequence} is already used on this device")
    for key, value in data.model_dump().items():
        setattr(rule, key, value)
    return _commit(db, rule.device, rule)


def delete_acl_rule(db: Session, rule_id: int) -> None:
    rule = _get(db, AclRule, rule_id, "ACL rule")
    network_service.touch(rule.device.network)
    db.delete(rule)
    db.commit()


# ---------------------------------------------------------- required flows
def list_intents(db: Session, network_id: int) -> list[NetworkIntent]:
    network_service.get_network(db, network_id)
    return list(db.scalars(select(NetworkIntent).where(NetworkIntent.network_id == network_id).order_by(NetworkIntent.id)))


def _check_intent_devices(db: Session, network_id: int, data: IntentCreate) -> None:
    for device_id in (data.source_device_id, data.destination_device_id):
        device = db.get(Device, device_id)
        if device is None or device.network_id != network_id:
            raise ValidationFailed(f"Device {device_id} does not belong to this network")


def create_intent(db: Session, network_id: int, data: IntentCreate) -> NetworkIntent:
    network = network_service.get_network(db, network_id)
    _check_intent_devices(db, network_id, data)
    intent = NetworkIntent(network_id=network_id, **data.model_dump())
    db.add(intent)
    network_service.touch(network)
    db.commit()
    db.refresh(intent)
    return intent


def update_intent(db: Session, intent_id: int, data: IntentCreate) -> NetworkIntent:
    intent = _get(db, NetworkIntent, intent_id, "Required flow")
    _check_intent_devices(db, intent.network_id, data)
    for key, value in data.model_dump().items():
        setattr(intent, key, value)
    network_service.touch(intent.network)
    db.commit()
    db.refresh(intent)
    return intent


def delete_intent(db: Session, intent_id: int) -> None:
    intent = _get(db, NetworkIntent, intent_id, "Required flow")
    network_service.touch(intent.network)
    db.delete(intent)
    db.commit()
