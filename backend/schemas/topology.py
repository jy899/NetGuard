from __future__ import annotations

import math

from pydantic import BaseModel, Field, field_validator

from backend.schemas.config import IntentOut
from backend.schemas.device import DeviceOut
from backend.schemas.link import LinkOut
from backend.schemas.network import NetworkOut


class TopologyOut(BaseModel):
    network: NetworkOut
    devices: list[DeviceOut]
    links: list[LinkOut]
    intents: list[IntentOut] = []


class DevicePosition(BaseModel):
    device_id: int
    x: float
    y: float

    @field_validator("x", "y")
    @classmethod
    def _finite(cls, value: float) -> float:
        if math.isnan(value) or math.isinf(value) or abs(value) > 1_000_000:
            raise ValueError("Position must be a finite number")
        return value


class PositionsUpdate(BaseModel):
    positions: list[DevicePosition] = Field(max_length=2000)


class PositionsSaved(BaseModel):
    updated: int
