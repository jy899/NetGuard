from __future__ import annotations

from datetime import datetime

from typing import Any

from pydantic import BaseModel, Field, field_validator

from backend.schemas.validators import clean_optional_text


class ChangeCreate(BaseModel):
    device_id: int
    change_type: str
    interface_id: int | None = None
    parameters: dict = Field(default_factory=dict)
    reason: str | None = Field(default=None, max_length=1000)

    @field_validator("reason")
    @classmethod
    def _reason(cls, value):
        return clean_optional_text(value)


class ApplyRequest(BaseModel):
    """Body of POST /changes/{id}/apply: the user's explicit approval ({"confirm": true})."""

    confirm: Any = None


class AssessmentBrief(BaseModel):
    id: int
    total_risk_score: int
    risk_level: str
    recommendation: str
    validation_result: str
    saved: bool
    created_at: datetime


class ChangeOut(BaseModel):
    id: int
    network_id: int
    network_name: str | None = None
    device_id: int | None
    device_name: str
    interface_id: int | None
    target_name: str | None
    category: str
    category_label: str
    change_type: str
    change_type_label: str
    current_value: str | None
    proposed_value: str | None
    parameters: dict
    reason: str | None
    status: str
    created_by_username: str | None = None
    created_at: datetime
    updated_at: datetime
    approval: dict = Field(default_factory=dict)
    lab_device: bool = False
    self_healing: dict = Field(default_factory=dict)
    assessment_count: int = 0
    latest_assessment: AssessmentBrief | None = None


class ImpactOut(BaseModel):
    expected: str | None = None
    result: str = "unknown"
    reason: str | None = None
    service: str
    kind: str | None = None
    source_device: str
    destination_device: str
    protocol: str | None
    port: int | None
    protocol_label: str | None = None
    criticality: str | None
    impact_type: str
    status: str
    affected: bool
    baseline_status: str
    candidate_status: str
    explanation: str
    path: list
    path_device_ids: list
    path_link_ids: list
    failure_link_id: int | None
    failure_device: str | None
    failure_reason: str | None = None


class AssessmentOut(BaseModel):
    ai: dict = Field(default_factory=dict)  # advisory machine-learning forecast
    hybrid: dict = Field(default_factory=dict)  # rules + AI blended risk (never below the rules score)
    advisories: list = Field(default_factory=list)
    coverage_notes: list[str] = Field(default_factory=list)
    evidence_scope: str = "Stored network model."
    risk_factors: dict | None = None
    evidence_confidence: str | None = None
    id: int
    change_id: int
    network_id: int
    network_name: str | None
    change: dict
    scores: dict
    risk_score: int
    total_risk_score: int
    risk_level: str
    issue: str | None
    recommendation: str
    recommendation_label: str
    recommendation_summary: str
    validation_result: str
    explanation: str
    findings: list
    checks: list
    actions: list
    affected_devices: list
    affected_device_ids: list
    affected_links: list
    affected_paths: list
    existing_issues: list
    resolved_issues: list
    baseline_configuration: dict = Field(default_factory=dict)
    candidate_configuration: dict = Field(default_factory=dict)
    configuration_diff: list = Field(default_factory=list)
    counts: dict
    impacts: list[ImpactOut]
    saved: bool
    saved_at: datetime | None
    created_at: datetime
    created_by_username: str | None
    analysis_ms: int
