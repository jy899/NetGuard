"""Schemas for simplified device configuration and required flows."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.models.config import ACL_ACTIONS, CRITICALITIES, INTENT_ACTIONS, PROTOCOLS
from backend.schemas.validators import (
    clean_optional_text,
    clean_required_text,
    validate_acl_address,
    validate_cidr,
    validate_ipv4,
    validate_port,
)


def _choice(value: str, options: tuple[str, ...], label: str) -> str:
    value = (value or "").strip().lower()
    if value not in options:
        raise ValueError(f"{label} must be one of: {', '.join(options)}")
    return value


class VlanCreate(BaseModel):
    vlan_id: int = Field(ge=1, le=4094)
    # Cisco IOS and ArubaOS-Switch both limit VLAN names to 32 characters.
    name: str | None = Field(default=None, max_length=32)

    @field_validator("name")
    @classmethod
    def _name(cls, value):
        return clean_optional_text(value)


class VlanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    device_id: int
    vlan_id: int
    name: str | None


class StaticRouteCreate(BaseModel):
    destination: str
    next_hop: str

    @field_validator("destination")
    @classmethod
    def _dest(cls, value):
        return validate_cidr(value, "Destination")

    @field_validator("next_hop")
    @classmethod
    def _nh(cls, value):
        result = validate_ipv4(value)
        if result is None:
            raise ValueError("Next hop is required")
        return result


class StaticRouteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    device_id: int
    destination: str
    next_hop: str


class AclRuleCreate(BaseModel):
    acl_name: str | None = Field(default=None, max_length=64)
    sequence: int = Field(ge=1, le=9999)
    action: str
    protocol: str = "ip"
    source: str = "any"
    destination: str = "any"
    port: int | None = None

    @field_validator("acl_name")
    @classmethod
    def _acl_name(cls, value):
        value = (value or "").strip() or None
        if value is not None and (" " in value or not value.isprintable()):
            raise ValueError("ACL name must be one word (letters, digits, - or _)")
        return value

    @field_validator("action")
    @classmethod
    def _action(cls, value):
        return _choice(value, ACL_ACTIONS, "Action")

    @field_validator("protocol")
    @classmethod
    def _protocol(cls, value):
        return _choice(value, PROTOCOLS, "Protocol")

    @field_validator("source", "destination")
    @classmethod
    def _address(cls, value):
        return validate_acl_address(value)

    @model_validator(mode="after")
    def _port(self):
        self.port = validate_port(self.port, self.protocol)
        return self


class AclRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    device_id: int
    acl_name: str | None = None
    sequence: int
    action: str
    protocol: str
    source: str
    destination: str
    port: int | None


class IntentCreate(BaseModel):
    name: str = Field(max_length=100)
    source_device_id: int
    destination_device_id: int
    protocol: str = "ip"
    port: int | None = None
    expected_action: str = "allow"
    criticality: str = "medium"

    @field_validator("name")
    @classmethod
    def _name(cls, value):
        return clean_required_text(value, "Name")

    @field_validator("protocol")
    @classmethod
    def _protocol(cls, value):
        return _choice(value, PROTOCOLS, "Protocol")

    @field_validator("expected_action")
    @classmethod
    def _expected(cls, value):
        return _choice(value, INTENT_ACTIONS, "Expected action")

    @field_validator("criticality")
    @classmethod
    def _criticality(cls, value):
        return _choice(value, CRITICALITIES, "Criticality")

    @model_validator(mode="after")
    def _check(self):
        self.port = validate_port(self.port, self.protocol)
        if self.source_device_id == self.destination_device_id:
            raise ValueError("Source and destination must be different devices")
        return self


class IntentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    network_id: int
    name: str
    source_device_id: int
    destination_device_id: int
    protocol: str
    port: int | None
    expected_action: str
    criticality: str
