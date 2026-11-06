"""EVE-NG and GNS3 laboratory integration and read-only configuration collection."""
from typing import Literal

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from backend.api.deps import CurrentUser, DbSession
from backend.services import collection_service, credential_service, lab_import_service, network_service

router = APIRouter(tags=["laboratories and collection"])


class LabServerIn(BaseModel):
    provider: Literal["eve-ng", "gns3"]
    server: str = Field(min_length=1, max_length=200)
    username: str = Field(default="", max_length=64)
    password: str = Field(default="", max_length=128, repr=False)
    verify_tls: bool = False  # lab servers use self-signed certificates


class LabImportIn(LabServerIn):
    lab_id: str = Field(min_length=1, max_length=300)
    name: str | None = Field(default=None, max_length=100)


class LabRefreshIn(BaseModel):
    username: str = Field(default="", max_length=64)
    password: str = Field(default="", max_length=128, repr=False)


class CollectIn(BaseModel):
    device_ids: list[int] = Field(min_length=1, max_length=128)
    transport: Literal["auto", "ssh", "console"] = "auto"
    username: str = Field(default="", max_length=64)
    password: str = Field(default="", max_length=128, repr=False)
    secret: str = Field(default="", max_length=128, repr=False)
    profile_id: int | None = None
    port: int = Field(default=22, ge=1, le=65535)


@router.post("/labs/connect")
def connect(body: LabServerIn, _: CurrentUser):
    return lab_import_service.connect(body.provider, body.server, body.username, body.password, body.verify_tls)


@router.post("/labs/import", status_code=status.HTTP_201_CREATED)
def import_lab(body: LabImportIn, db: DbSession, user: CurrentUser):
    network = lab_import_service.import_lab(db, user, body.provider, body.server, body.username, body.password,
                                            body.lab_id, body.verify_tls, body.name)
    return {"network_id": network.id, "network": network_service.to_out(db, network).model_dump(mode="json")}


@router.post("/labs/{network_id}/refresh")
def refresh_lab(network_id: int, body: LabRefreshIn, db: DbSession, user: CurrentUser):
    network = credential_service.network_for(db, user, network_id, manage=True)
    lab_import_service.refresh_lab(db, user, network, body.username, body.password)
    return network_service.to_out(db, network).model_dump(mode="json")


@router.post("/networks/{network_id}/collect")
def collect(network_id: int, body: CollectIn, db: DbSession, user: CurrentUser):
    network = credential_service.network_for(db, user, network_id)
    return collection_service.collect(db, user, network, body.device_ids, body.transport, body.username, body.password,
                                      body.secret or None, body.profile_id, body.port)
