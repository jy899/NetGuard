"""Device configuration (VLANs, static routes, ACL) and network required flows."""
from fastapi import APIRouter, Response, status

from backend.api.deps import CurrentUser, DbSession
from backend.schemas.config import (
    AclRuleCreate,
    AclRuleOut,
    IntentCreate,
    IntentOut,
    StaticRouteCreate,
    StaticRouteOut,
    VlanCreate,
    VlanOut,
)
from backend.services import config_service

router = APIRouter(tags=["configuration"])
NO_CONTENT = status.HTTP_204_NO_CONTENT


@router.post("/devices/{device_id}/vlans", response_model=VlanOut, status_code=201)
def create_vlan(device_id: int, payload: VlanCreate, db: DbSession, _: CurrentUser):
    return config_service.create_vlan(db, device_id, payload)


@router.put("/vlans/{vlan_id}", response_model=VlanOut)
def update_vlan(vlan_id: int, payload: VlanCreate, db: DbSession, _: CurrentUser):
    return config_service.update_vlan(db, vlan_id, payload)


@router.delete("/vlans/{vlan_id}", status_code=NO_CONTENT)
def delete_vlan(vlan_id: int, db: DbSession, _: CurrentUser):
    config_service.delete_vlan(db, vlan_id)
    return Response(status_code=NO_CONTENT)


@router.post("/devices/{device_id}/static-routes", response_model=StaticRouteOut, status_code=201)
def create_route(device_id: int, payload: StaticRouteCreate, db: DbSession, _: CurrentUser):
    return config_service.create_route(db, device_id, payload)


@router.put("/static-routes/{route_id}", response_model=StaticRouteOut)
def update_route(route_id: int, payload: StaticRouteCreate, db: DbSession, _: CurrentUser):
    return config_service.update_route(db, route_id, payload)


@router.delete("/static-routes/{route_id}", status_code=NO_CONTENT)
def delete_route(route_id: int, db: DbSession, _: CurrentUser):
    config_service.delete_route(db, route_id)
    return Response(status_code=NO_CONTENT)


@router.post("/devices/{device_id}/acl-rules", response_model=AclRuleOut, status_code=201)
def create_acl_rule(device_id: int, payload: AclRuleCreate, db: DbSession, _: CurrentUser):
    return config_service.create_acl_rule(db, device_id, payload)


@router.put("/acl-rules/{rule_id}", response_model=AclRuleOut)
def update_acl_rule(rule_id: int, payload: AclRuleCreate, db: DbSession, _: CurrentUser):
    return config_service.update_acl_rule(db, rule_id, payload)


@router.delete("/acl-rules/{rule_id}", status_code=NO_CONTENT)
def delete_acl_rule(rule_id: int, db: DbSession, _: CurrentUser):
    config_service.delete_acl_rule(db, rule_id)
    return Response(status_code=NO_CONTENT)


@router.get("/networks/{network_id}/intents", response_model=list[IntentOut])
def list_intents(network_id: int, db: DbSession, _: CurrentUser):
    return config_service.list_intents(db, network_id)


@router.post("/networks/{network_id}/intents", response_model=IntentOut, status_code=201)
def create_intent(network_id: int, payload: IntentCreate, db: DbSession, _: CurrentUser):
    return config_service.create_intent(db, network_id, payload)


@router.put("/intents/{intent_id}", response_model=IntentOut)
def update_intent(intent_id: int, payload: IntentCreate, db: DbSession, _: CurrentUser):
    return config_service.update_intent(db, intent_id, payload)


@router.delete("/intents/{intent_id}", status_code=NO_CONTENT)
def delete_intent(intent_id: int, db: DbSession, _: CurrentUser):
    config_service.delete_intent(db, intent_id)
    return Response(status_code=NO_CONTENT)
