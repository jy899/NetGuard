from __future__ import annotations

import math

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.models.device import DEVICE_TYPES
from backend.schemas.config import AclRuleOut, StaticRouteOut, VlanOut
from backend.schemas.interface import InterfaceOut
from backend.schemas.validators import clean_optional_text, clean_required_text, validate_ipv4


def _check_coordinate(value: float | None) -> float | None:
    if value is not None and (math.isnan(value) or math.isinf(value) or abs(value) > 1_000_000):
        raise ValueError("Position must be a finite number")
    return value


class DeviceBase(BaseModel):
    name: str = Field(max_length=64)
    device_type: str
    vendor: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=64)
    management_ip: str | None = None
    default_gateway: str | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return clean_required_text(value, "Device name")

    @field_validator("device_type")
    @classmethod
    def _type(cls, value: str) -> str:
        value = (value or "").strip().lower()
        if value not in DEVICE_TYPES:
            raise ValueError(f"Device type must be one of: {', '.join(DEVICE_TYPES)}")
        return value

    @field_validator("vendor", "model")
    @classmethod
    def _optional(cls, value: str | None) -> str | None:
        return clean_optional_text(value)

    @field_validator("management_ip", "default_gateway")
    @classmethod
    def _ipv4(cls, value: str | None) -> str | None:
        return validate_ipv4(value)


class DeviceCreate(DeviceBase):
    x_position: float = 0.0
    y_position: float = 0.0

    @field_validator("x_position", "y_position")
    @classmethod
    def _coords(cls, value: float | None) -> float | None:
        return _check_coordinate(value)


class DeviceUpdate(DeviceBase):
    """Full update of device attributes. Position is optional here."""

    x_position: float | None = None
    y_position: float | None = None

    @field_validator("x_position", "y_position")
    @classmethod
    def _coords(cls, value: float | None) -> float | None:
        return _check_coordinate(value)


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    network_id: int
    name: str
    device_type: str
    role: str = "unknown"
    vendor: str | None
    model: str | None
    management_ip: str | None
    x_position: float
    y_position: float
    default_gateway: str | None = None
    is_lab: bool = False
    platform: str | None = None
    config_facts: dict | None = None
    access: dict | None = None
    interfaces: list[InterfaceOut] = []
    vlans: list[VlanOut] = []
    static_routes: list[StaticRouteOut] = []
    acl_rules: list[AclRuleOut] = []
