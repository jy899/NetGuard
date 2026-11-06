from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class RecentNetwork(BaseModel):
    id: int
    name: str
    network_type: str
    device_count: int
    link_count: int
    updated_at: datetime


class RecentAssessment(BaseModel):
    id: int
    change_id: int
    network_id: int
    network_name: str
    device_name: str
    change_label: str
    total_risk_score: int
    risk_level: str
    recommendation: str
    saved: bool
    created_at: datetime


class DashboardSummary(BaseModel):
    networks: int
    devices: int
    interfaces: int
    links: int
    pending_changes: int = 0
    high_critical_changes: int = 0
    saved_assessments: int = 0
    risk_distribution: dict[str, int] = {}
    recent_assessments: list[RecentAssessment] = []
    devices_by_type: dict[str, int]
    recent_networks: list[RecentNetwork]
    detected_issues: int = 0
    analysis_runs: int = 0
    recent_activity: list[dict] = []
