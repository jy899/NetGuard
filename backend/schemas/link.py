from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class LinkCreate(BaseModel):
    source_device_id: int
    source_interface_id: int | None = None
    destination_device_id: int
    destination_interface_id: int | None = None


class LinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    network_id: int
    source_device_id: int
    source_interface_id: int | None
    destination_device_id: int
    destination_interface_id: int | None
    source_device_name: str | None = None
    source_interface_name: str | None = None
    destination_device_name: str | None = None
    destination_interface_name: str | None = None
    kind: str | None = None
    state: str | None = None
    confidence: float | None = None
    evidence: list = []
    missing: list = []
    discovery_status: str = "manual"
    evidence_grade: str = "Manual"
    speed_mbps: int | None = None
    source_port_info: dict | None = None
    destination_port_info: dict | None = None
    source_interface_description: str | None = None
    destination_interface_description: str | None = None
    media: str | None = None
