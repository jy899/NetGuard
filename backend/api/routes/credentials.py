"""Encrypted device credential profiles and per-device assignments (used for collection and lab changes)."""
from typing import Literal

from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field

from backend.api.deps import CurrentUser, DbSession
from backend.services import credential_service

router = APIRouter(prefix="/credential-profiles", tags=["network credentials"])


class ProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    username: str = Field(default="", max_length=64)  # required except for SNMPv2c (community only)
    password: str = Field(default="", max_length=128, repr=False)
    port: int = Field(default=22, ge=1, le=65535)
    priority: int = Field(default=100, ge=1, le=1000)
    notes: str = Field(default="", max_length=200)
    method: Literal["ssh", "snmpv3", "snmpv2c"] = "ssh"
    snmp_auth_protocol: Literal["SHA-256", "SHA-512", ""] = ""
    snmp_priv_protocol: Literal["AES-128", "AES-256", ""] = ""
    priv_password: str = Field(default="", max_length=128, repr=False)


class AssignIn(BaseModel):
    network_id: int
    scope: Literal["all", "selected", "individual"] = "all"
    device_ids: list[int] = Field(default_factory=list, max_length=256)
    profile_id: int | None = None
    username: str = Field(default="", max_length=64)
    password: str = Field(default="", max_length=128, repr=False)


class TestIn(BaseModel):
    network_id: int
    device_ids: list[int] = Field(default_factory=list, max_length=256)


@router.get("")
def profiles(db: DbSession, user: CurrentUser):
    return credential_service.list_profiles(db, user)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_profile(body: ProfileIn, db: DbSession, user: CurrentUser):
    return credential_service.save_profile(db, user, body.model_dump())


@router.get("/assignments")
def assignments(network_id: int, db: DbSession, user: CurrentUser):
    return credential_service.list_assignments(db, user, network_id)


@router.post("/assign")
def assign(body: AssignIn, db: DbSession, user: CurrentUser):
    return credential_service.assign(db, user, body.model_dump())


@router.post("/test")
def test(body: TestIn, db: DbSession, user: CurrentUser):
    return credential_service.test_assignments(db, user, body.network_id, body.device_ids)


@router.delete("/assignments/{assignment_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_assignment(assignment_id: int, db: DbSession, user: CurrentUser):
    credential_service.remove_assignment(db, user, assignment_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/{profile_id}")
def update_profile(profile_id: int, body: ProfileIn, db: DbSession, user: CurrentUser):
    return credential_service.save_profile(db, user, body.model_dump(), profile_id)


@router.delete("/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_profile(profile_id: int, db: DbSession, user: CurrentUser):
    credential_service.delete_profile(db, user, profile_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
