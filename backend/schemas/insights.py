from datetime import datetime

from pydantic import BaseModel, Field


class HistorySummary(BaseModel):
    id: int
    network_id: int | None
    network_name: str
    kind: str
    title: str
    summary: dict
    created_at: datetime
    issue_count: int = 0
    status: str = "completed"
    simulated: bool = False


class HistoryDetail(HistorySummary):
    snapshot: dict
    created_by_username: str | None = None


class ReportIn(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=150)


class DemoScenarioIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    scenario: str = "mixed"
    provider: str | None = Field(default=None, max_length=16)  # accepted for older clients; ignored
