from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.schemas.validators import clean_optional_text, clean_required_text

NETWORK_TYPES = ("Enterprise", "Campus", "Data Center", "Branch", "Lab", "Other")


class NetworkBase(BaseModel):
    name: str = Field(max_length=100)
    description: str | None = Field(default=None, max_length=1000)
    network_type: str = "Enterprise"
    environment: Literal["manual", "virtual", "real"] = "manual"
    source: Literal["manual", "sample", "eve-ng", "gns3", "discovery", "config-import"] = "manual"
    is_simulated: bool = False

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return clean_required_text(value, "Network name")

    @field_validator("description")
    @classmethod
    def _description(cls, value: str | None) -> str | None:
        return clean_optional_text(value)

    @field_validator("network_type")
    @classmethod
    def _network_type(cls, value: str) -> str:
        if value not in NETWORK_TYPES:
            raise ValueError(f"Network type must be one of: {', '.join(NETWORK_TYPES)}")
        return value


class NetworkCreate(NetworkBase):
    pass


class NetworkUpdate(NetworkBase):
    pass


class NetworkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    network_type: str
    environment: str = "manual"
    source: str = "manual"
    is_simulated: bool = False
    metadata_json: dict = Field(default_factory=dict)
    created_by: int | None
    created_by_username: str | None = None
    created_at: datetime
    updated_at: datetime
    device_count: int = 0
    link_count: int = 0


class NetworkImport(BaseModel):
    name: str = Field(default="Imported network", max_length=100)
    configs: str = Field(min_length=1, max_length=2_000_000)
    endpoints: str = Field(default="", max_length=200_000)
    flows: str = Field(default="", max_length=200_000)
    dry_run: bool = False


class ImportSummary(BaseModel):
    devices: int
    interfaces: int
    links: int
    vlans: int
    routes: int
    acl_rules: int
    flows: int
    by_type: dict[str, int]


class ImportResult(BaseModel):
    network_id: int | None
    summary: ImportSummary
    warnings: list[str]
