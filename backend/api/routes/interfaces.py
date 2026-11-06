from fastapi import APIRouter, Response, status

from backend.api.deps import CurrentUser, DbSession
from backend.schemas.interface import InterfaceCreate, InterfaceOut, InterfaceUpdate
from backend.services import interface_service

router = APIRouter(tags=["interfaces"])


@router.get("/devices/{device_id}/interfaces", response_model=list[InterfaceOut])
def list_interfaces(device_id: int, db: DbSession, _: CurrentUser):
    return interface_service.list_interfaces(db, device_id)


@router.post("/devices/{device_id}/interfaces", response_model=InterfaceOut, status_code=status.HTTP_201_CREATED)
def create_interface(device_id: int, payload: InterfaceCreate, db: DbSession, _: CurrentUser):
    return interface_service.create_interface(db, device_id, payload)


@router.put("/interfaces/{interface_id}", response_model=InterfaceOut)
def update_interface(interface_id: int, payload: InterfaceUpdate, db: DbSession, _: CurrentUser):
    return interface_service.update_interface(db, interface_id, payload)


@router.delete("/interfaces/{interface_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_interface(interface_id: int, db: DbSession, _: CurrentUser):
    interface_service.delete_interface(db, interface_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
