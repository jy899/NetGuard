from fastapi import APIRouter, Response, status

from backend.api.deps import CurrentUser, DbSession
from backend.models import DEVICE_TYPES
from backend.schemas.device import DeviceCreate, DeviceOut, DeviceUpdate
from backend.services import device_service

router = APIRouter(tags=["devices"])


@router.get("/device-types", response_model=list[str])
def device_types(_: CurrentUser):
    return list(DEVICE_TYPES)


@router.get("/networks/{network_id}/devices", response_model=list[DeviceOut])
def list_devices(network_id: int, db: DbSession, _: CurrentUser):
    return device_service.list_devices(db, network_id)


@router.post("/networks/{network_id}/devices", response_model=DeviceOut, status_code=status.HTTP_201_CREATED)
def create_device(network_id: int, payload: DeviceCreate, db: DbSession, _: CurrentUser):
    return device_service.create_device(db, network_id, payload)


@router.get("/devices/{device_id}", response_model=DeviceOut)
def get_device(device_id: int, db: DbSession, _: CurrentUser):
    return device_service.get_device(db, device_id)


@router.put("/devices/{device_id}", response_model=DeviceOut)
def update_device(device_id: int, payload: DeviceUpdate, db: DbSession, _: CurrentUser):
    return device_service.update_device(db, device_id, payload)


@router.delete("/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(device_id: int, db: DbSession, _: CurrentUser):
    device_service.delete_device(db, device_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
