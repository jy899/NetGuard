import json
from typing import Literal

from fastapi import APIRouter, Body, Query, Response, status
from pydantic import BaseModel, Field

from backend.api.deps import CurrentUser, DbSession
from backend.schemas.insights import DemoScenarioIn, HistoryDetail, HistorySummary, ReportIn
from backend.schemas.network import NetworkOut
from backend.services import demo_topology, history_service, network_service, report_service


class ScopeIn(BaseModel):
    authorised: list[str] = Field(default_factory=list, max_length=64)
    excluded: list[str] = Field(default_factory=list, max_length=256)
    untrusted: list[str] = Field(default_factory=list, max_length=64)

router = APIRouter(tags=["analysis and history"])


@router.post("/networks/scenario", response_model=NetworkOut, status_code=status.HTTP_201_CREATED)
def create_scenario(body: DemoScenarioIn, db: DbSession, user: CurrentUser):
    return network_service.to_out(db, demo_topology.create_analysis_demo(db, user, body.name, body.scenario))


@router.post("/networks/samples", status_code=status.HTTP_201_CREATED)
def create_sample(body: DemoScenarioIn, db: DbSession, user: CurrentUser):
    """An offline example network built from sample configurations (for learning and demonstrations)."""
    network = demo_topology.create_analysis_demo(db, user, body.name, body.scenario)
    out = network_service.to_out(db, network).model_dump(mode="json")
    history_service.record(db, user, network.id, "network", "Example network created",
                           {"device_count": out["device_count"], "link_count": out["link_count"], "status": "completed"},
                           {"network": out, "scenario": body.scenario})
    return {"network": out, "network_id": network.id}


@router.post("/networks/{network_id}/analyze", response_model=HistoryDetail)
def analyze_network(network_id: int, db: DbSession, user: CurrentUser):
    return history_service.analyze(db, user, network_id)


@router.post("/networks/{network_id}/reports", response_model=HistoryDetail, status_code=status.HTTP_201_CREATED)
def create_report(network_id: int, db: DbSession, user: CurrentUser, body: ReportIn | None = Body(default=None)):
    return history_service.analyze(db, user, network_id, kind="report", title=body.title if body else None)


@router.get("/history", response_model=list[HistorySummary])
def list_history(db: DbSession, _: CurrentUser, network_id: int | None = None, kind: str | None = None,
                 limit: int = Query(default=100, ge=1, le=500)):
    return [history_service.to_out(row) for row in history_service.list_records(db, network_id, kind, limit)]


@router.get("/history/{record_id}", response_model=HistoryDetail)
def get_history(record_id: int, db: DbSession, _: CurrentUser):
    return history_service.to_out(history_service.get(db, record_id), detail=True)


@router.get("/history/{record_id}/export")
def export_history(record_id: int, db: DbSession, _: CurrentUser,
                   format: Literal["json", "html", "pdf"] = "json"):
    row = history_service.get(db, record_id)
    data = history_service.to_out(row, detail=True)
    if format == "json":
        return Response(data.model_dump_json(indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="netguard-report-{record_id}.json"'})
    return report_service.response(report_service.from_history(row, data.snapshot), format, f"netguard-report-{record_id}")


@router.put("/networks/{network_id}/scope")
def update_scope(network_id: int, body: ScopeIn, db: DbSession, user: CurrentUser):
    """Authorised ranges, excluded addresses and untrusted segments of a workspace (used by the scope guard
    and the exposure factor of the risk score)."""
    from backend.services import credential_service
    from backend.services.discovery.service import parse_scope

    network = credential_service.network_for(db, user, network_id, manage=True)
    scope = {"authorised": parse_scope(body.authorised, "Authorised ranges"),
             "excluded": parse_scope(body.excluded, "Excluded addresses"),
             "untrusted": parse_scope(body.untrusted, "Untrusted segments")}
    old = (network.metadata_json or {}).get("scope", {})
    if network.source == "discovery" and old.get("authorised") and scope["authorised"] != old["authorised"]:
        from backend.core.errors import ValidationFailed
        raise ValidationFailed("The authorised range of a discovery is fixed; start a new discovery for another range.")
    network.metadata_json = {**(network.metadata_json or {}), "scope": scope}
    db.commit()
    return scope
