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


# ------------------------------------------------------------------ configuration backups
def _may_read_configs(user) -> None:
    from backend.core.errors import ForbiddenError
    from backend.core.permissions import AUTO_FIX, EDIT, EXECUTE, has

    if not any(has(user, p) for p in (EDIT, EXECUTE, AUTO_FIX)):
        raise ForbiddenError("Your user group may not read device configurations.")


def _backup_out(row) -> dict:
    return {"id": row.id, "device_id": row.device_id, "sha256": row.sha256, "source": row.source,
            "created_at": row.created_at,
            "origin": "model" if row.source.endswith("-model") else "stored"}


@router.get("/devices/{device_id}/backups")
def list_backups(device_id: int, db: DbSession, user: CurrentUser) -> list[dict]:
    from sqlalchemy import select

    from backend.models import DeviceConfig

    device_service.get_device(db, device_id)
    _may_read_configs(user)
    rows = db.scalars(select(DeviceConfig).where(DeviceConfig.device_id == device_id, DeviceConfig.kind == "backup")
                      .order_by(DeviceConfig.id.desc()))
    return [_backup_out(row) for row in rows]


@router.post("/devices/{device_id}/backups", status_code=status.HTTP_201_CREATED)
def create_backup(device_id: int, db: DbSession, user: CurrentUser) -> dict:
    """Back up now: a copy of the configuration NetGuard holds for the device (nothing is sent to it)."""
    from backend.models import Device
    from backend.services import remediation_service

    device_service.get_device(db, device_id)
    _may_read_configs(user)
    row, _ = remediation_service.backup_device(db, user, db.get(Device, device_id), source="manual")
    db.commit()
    return _backup_out(row)


def _text_download(text: str, filename: str) -> Response:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in filename)
    return Response(content=text, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{safe}"'})


@router.get("/backups/{backup_id}/download")
def download_backup(backup_id: int, db: DbSession, user: CurrentUser) -> Response:
    from backend.core.errors import NotFoundError
    from backend.models import Device, DeviceConfig

    _may_read_configs(user)
    row = db.get(DeviceConfig, backup_id)
    if row is None or row.kind != "backup":
        raise NotFoundError("Backup not found")
    device = db.get(Device, row.device_id)
    stamp = row.created_at.strftime("%Y%m%d-%H%M%S") if row.created_at else str(row.id)
    return _text_download(row.text or "", f"{device.name if device else 'device'}-backup-{stamp}.cfg")


@router.get("/devices/{device_id}/config/download")
def download_config(device_id: int, db: DbSession, user: CurrentUser) -> Response:
    """The configuration NetGuard holds for the device now (stored, or written from the model)."""
    from backend.models import Device
    from backend.services import remediation_service

    device_service.get_device(db, device_id)
    _may_read_configs(user)
    device = db.get(Device, device_id)
    text, _ = remediation_service.device_config_text(db, device)
    return _text_download(text, f"{device.name}-config.cfg")
