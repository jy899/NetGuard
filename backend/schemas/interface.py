from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.models.interface import INTERFACE_STATUSES, SWITCHPORT_MODES
from backend.schemas.validators import (
    clean_required_text,
    validate_host_address,
    validate_ipv4,
    validate_subnet_mask,
)


class InterfaceBase(BaseModel):
    name: str = Field(max_length=64)
    description: str | None = Field(default=None, max_length=120)
    ip_address: str | None = None
    subnet_mask: str | None = None
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    status: str = "up"
    ospf_area: int | None = Field(default=None, ge=0, le=65535)
    mode: str | None = None
    speed_mbps: int | None = Field(default=None, ge=1, le=800000)
    allowed_vlans: list[int] | None = Field(default=None, max_length=4094)
    native_vlan: int | None = Field(default=None, ge=1, le=4094)
    stp_state: str | None = Field(default=None, pattern="^(forwarding|blocking|discarding|learning|disabled|unknown)$")

    @field_validator("allowed_vlans")
    @classmethod
    def _allowed_vlans(cls, value):
        if value is not None and any(v < 1 or v > 4094 for v in value):
            raise ValueError("Allowed VLAN IDs must be between 1 and 4094")
        return sorted(set(value)) if value is not None else None

    @field_validator("mode")
    @classmethod
    def _mode(cls, value: str | None) -> str | None:
        value = (value or "").strip().lower() or None
        if value is not None and value not in SWITCHPORT_MODES:
            raise ValueError(f"Mode must be one of: {', '.join(SWITCHPORT_MODES)}")
        return value

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return clean_required_text(value, "Interface name")

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, value: str | None) -> str | None:
        return validate_ipv4(value)

    @field_validator("subnet_mask")
    @classmethod
    def _mask(cls, value: str | None) -> str | None:
        return validate_subnet_mask(value)

    @field_validator("status")
    @classmethod
    def _status(cls, value: str) -> str:
        value = (value or "").strip().lower()
        if value not in INTERFACE_STATUSES:
            raise ValueError(f"Status must be one of: {', '.join(INTERFACE_STATUSES)}")
        return value

    @model_validator(mode="after")
    def _ip_and_mask_together(self):
        if self.ip_address and not self.subnet_mask:
            raise ValueError("Subnet mask is required when an IP address is set")
        if self.subnet_mask and not self.ip_address:
            raise ValueError("IP address is required when a subnet mask is set")
        validate_host_address(self.ip_address, self.subnet_mask)
        return self


class InterfaceCreate(InterfaceBase):
    pass


class InterfaceUpdate(InterfaceBase):
    pass


class InterfaceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: int
    name: str
    description: str | None = None
    ip_address: str | None
    subnet_mask: str | None
    vlan_id: int | None
    status: str
    ospf_area: int | None = None
    mode: str | None = None
    speed_mbps: int | None = None
    allowed_vlans: list[int] | None = None
    native_vlan: int | None = None
    stp_state: str | None = None
    duplex: str | None = None
    mtu: int | None = None
    ospf_hello: int | None = None
    ospf_dead: int | None = None
    acl_in: str | None = None
    acl_out: str | None = None
    error_count: int | None = None
