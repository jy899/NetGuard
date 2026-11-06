"""Credential-minimal discovery of an authorised IPv4 range, optional authentication and the discovery report."""
from typing import Literal

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from backend.api.deps import CurrentUser, DbSession
from backend.services import discovery_api

router = APIRouter(prefix="/discovery", tags=["discovery"])


class ScanIn(BaseModel):
    target: str = Field(default="", max_length=43)  # empty: this computer's own subnet
    name: str | None = Field(default=None, max_length=100)
    authorized_scope: bool = False
    excluded: list[str] = Field(default_factory=list, max_length=64)
    untrusted: list[str] = Field(default_factory=list, max_length=64)
    auto_credentials: bool = False
    follow_neighbours: bool = False
    max_depth: int = Field(default=3, ge=0, le=3)


class CrawlIn(BaseModel):
    follow_neighbours: bool | None = None
    max_depth: int = Field(default=3, ge=1, le=3)


class AuthenticateIn(BaseModel):
    device_ids: list[int] = Field(min_length=1, max_length=64)
    method: Literal["ssh", "snmpv3", "snmpv2c"]
    username: str = Field(default="", max_length=64)
    password: str = Field(default="", max_length=128, repr=False)
    priv_password: str = Field(default="", max_length=128, repr=False)
    snmp_auth_protocol: Literal["SHA-256", "SHA-512"] = "SHA-256"
    snmp_priv_protocol: Literal["AES-128", "AES-256"] = "AES-128"
    profile_id: int | None = None
    remember: bool = False
    profile_name: str | None = Field(default=None, max_length=60)
    continue_discovery: bool = True  # follow the neighbours the read reveals, with the same credentials


class SkipIn(BaseModel):
    device_ids: list[int] = Field(default_factory=list, max_length=256)
    all: bool = False


class ConfirmationIn(BaseModel):
    action: Literal["shown", "continue"]


@router.get("/local-networks")
def local_networks(user: CurrentUser):
    return discovery_api.local_networks()


@router.post("/jobs", status_code=status.HTTP_202_ACCEPTED)
def start_scan(body: ScanIn, db: DbSession, user: CurrentUser):
    return discovery_api.start_scan(db, user, **body.model_dump())


@router.get("/jobs/{job_id}")
def scan_job(job_id: str, user: CurrentUser):
    return discovery_api.job_status(user, job_id)


@router.post("/scan", status_code=status.HTTP_201_CREATED)
def scan(body: ScanIn, db: DbSession, user: CurrentUser):
    return discovery_api.scan(db, user, **body.model_dump())


@router.get("/{network_id}")
def result(network_id: int, db: DbSession, user: CurrentUser):
    return discovery_api.result(db, user, network_id)


@router.post("/{network_id}/crawl")
def crawl(network_id: int, body: CrawlIn, db: DbSession, user: CurrentUser):
    return discovery_api.crawl(db, user, network_id, body.follow_neighbours, body.max_depth)


@router.post("/{network_id}/refresh")
def refresh(network_id: int, db: DbSession, user: CurrentUser):
    return discovery_api.refresh(db, user, network_id)


@router.post("/{network_id}/authenticate")
def authenticate(network_id: int, body: AuthenticateIn, db: DbSession, user: CurrentUser):
    return discovery_api.authenticate(db, user, network_id, body.model_dump())


@router.post("/{network_id}/skip")
def skip(network_id: int, body: SkipIn, db: DbSession, user: CurrentUser):
    return discovery_api.skip(db, user, network_id, body.device_ids, body.all)


@router.post("/{network_id}/confirmation")
def confirmation(network_id: int, body: ConfirmationIn, db: DbSession, user: CurrentUser):
    return discovery_api.confirmation(db, user, network_id, body.action)
