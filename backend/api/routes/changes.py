"""Proposed changes, analysis and assessments (brief 9.2)."""
from fastapi import APIRouter, Body, Query, Response, status

from backend.api.deps import CurrentUser, DbSession
from backend.core.errors import NetGuardError
from backend.schemas.change import ApplyRequest, AssessmentOut, ChangeCreate, ChangeOut
from typing import Literal

from pydantic import BaseModel, Field

from backend.services import (analysis_service, apply_service, approval_service, change_detector, change_service,
                              health_service, remediation_service, rules)
from backend.models import ChangeExecution
from sqlalchemy import select


class DecisionIn(BaseModel):
    note: str | None = Field(default=None, max_length=300)


class ExecuteIn(BaseModel):
    confirm: bool = False
    transport: Literal["auto", "ssh", "console"] = "auto"
    profile_id: int | None = None
    username: str = Field(default="", max_length=64)
    password: str = Field(default="", max_length=128, repr=False)
    secret: str = Field(default="", max_length=128, repr=False)
    port: int = Field(default=22, ge=1, le=65535)

router = APIRouter(tags=["changes"])


@router.get("/change-types")
def change_types(_: CurrentUser) -> list[dict]:
    return change_detector.catalogue()


@router.get("/rules")
def rule_catalogue(_: CurrentUser) -> list[dict]:
    return rules.catalogue()


@router.get("/changes", response_model=list[ChangeOut])
def list_changes(db: DbSession, _: CurrentUser, network_id: int | None = None, status: str | None = None):
    change_service.ensure_network(db, network_id)
    return [change_service.to_out(db, c) for c in change_service.list_changes(db, network_id, status)]


@router.post("/changes", response_model=ChangeOut, status_code=status.HTTP_201_CREATED)
def create_change(payload: ChangeCreate, db: DbSession, user: CurrentUser):
    return change_service.to_out(db, change_service.create_change(db, payload, user))


@router.get("/changes/{change_id}", response_model=ChangeOut)
def get_change(change_id: int, db: DbSession, _: CurrentUser):
    return change_service.to_out(db, change_service.get_change(db, change_id))


@router.put("/changes/{change_id}", response_model=ChangeOut)
def update_change(change_id: int, payload: ChangeCreate, db: DbSession, _: CurrentUser):
    return change_service.to_out(db, change_service.update_change(db, change_id, payload))


@router.delete("/changes/{change_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_change(change_id: int, db: DbSession, _: CurrentUser):
    change_service.delete_change(db, change_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/changes/{change_id}/analyze", response_model=AssessmentOut)
def analyze_change(change_id: int, db: DbSession, user: CurrentUser):
    change = change_service.get_change(db, change_id)
    assessment = analysis_service.analyze_change(db, change, user)
    return analysis_service.to_out(analysis_service.get_assessment(db, assessment.id))


@router.get("/assessments", response_model=list[AssessmentOut])
def list_assessments(
    db: DbSession, _: CurrentUser, network_id: int | None = None, saved: bool | None = None,
    change_id: int | None = None, limit: int = Query(default=100, ge=1, le=500),
):
    return [analysis_service.to_out(a) for a in analysis_service.list_assessments(db, network_id, saved, change_id, limit)]


@router.get("/assessments/{assessment_id}", response_model=AssessmentOut)
def get_assessment(assessment_id: int, db: DbSession, _: CurrentUser):
    return analysis_service.to_out(analysis_service.get_assessment(db, assessment_id))


@router.get("/assessments/{assessment_id}/export")
def export_assessment(assessment_id: int, db: DbSession, _: CurrentUser,
                      format: Literal["json", "html", "pdf"] = "json"):
    from backend.services import report_service
    out = analysis_service.to_out(analysis_service.get_assessment(db, assessment_id))
    return report_service.response(report_service.from_assessment(out), format, f"netguard-assessment-{assessment_id}",
                                   raw=out.model_dump(mode="json"))


@router.post("/assessments/{assessment_id}/save", response_model=AssessmentOut)
def save_assessment(assessment_id: int, db: DbSession, _: CurrentUser):
    return analysis_service.to_out(analysis_service.save_assessment(db, assessment_id))


@router.post("/changes/{change_id}/submit", response_model=ChangeOut)
def submit_change(change_id: int, db: DbSession, user: CurrentUser):
    return change_service.to_out(db, approval_service.submit(db, change_service.get_change(db, change_id), user))


@router.post("/changes/{change_id}/approve", response_model=ChangeOut)
def approve_change(change_id: int, db: DbSession, user: CurrentUser, body: DecisionIn | None = Body(default=None)):
    change = approval_service.decide(db, change_service.get_change(db, change_id), user, True, body.note if body else None)
    return change_service.to_out(db, change)


@router.post("/changes/{change_id}/reject", response_model=ChangeOut)
def reject_change(change_id: int, db: DbSession, user: CurrentUser, body: DecisionIn | None = Body(default=None)):
    change = approval_service.decide(db, change_service.get_change(db, change_id), user, False, body.note if body else None)
    return change_service.to_out(db, change)


@router.post("/changes/{change_id}/execute")
def execute_change(change_id: int, body: ExecuteIn, db: DbSession, user: CurrentUser) -> dict:
    """Apply an approved change to its laboratory device with backup, verification and automatic rollback."""
    if body.confirm is not True:
        raise NetGuardError('Executing a change on a device needs confirmation: send {"confirm": true}.')
    change = change_service.get_change(db, change_id)
    execution = remediation_service.execute(db, user, change, body.model_dump())
    return {"execution": remediation_service.execution_out(execution), "change": change_service.to_out(db, change)}


@router.post("/changes/{change_id}/confirm")
def confirm_change(change_id: int, db: DbSession, user: CurrentUser, body: ExecuteIn | None = Body(default=None)) -> dict:
    """Keep a verified production change (cancels the dead-man's switch and saves the configuration)."""
    change = change_service.get_change(db, change_id)
    execution = remediation_service.confirm(db, user, change, body.model_dump() if body else {})
    return {"execution": remediation_service.execution_out(execution), "change": change_service.to_out(db, change)}


@router.post("/changes/{change_id}/rollback")
def rollback_change(change_id: int, db: DbSession, user: CurrentUser, body: ExecuteIn | None = Body(default=None)) -> dict:
    """Roll back a production change during its confirmation window."""
    change = change_service.get_change(db, change_id)
    execution = remediation_service.rollback_now(db, user, change, body.model_dump() if body else {})
    return {"execution": remediation_service.execution_out(execution), "change": change_service.to_out(db, change)}


@router.get("/settings/self-healing")
def get_self_healing(_: CurrentUser) -> dict:
    return remediation_service.self_healing_settings()


@router.put("/settings/self-healing")
def put_self_healing(body: dict, user: CurrentUser) -> dict:
    return remediation_service.update_self_healing(user, body)


@router.get("/changes/{change_id}/executions")
def change_executions(change_id: int, db: DbSession, _: CurrentUser) -> list[dict]:
    change_service.get_change(db, change_id)
    rows = db.scalars(select(ChangeExecution).where(ChangeExecution.change_id == change_id).order_by(ChangeExecution.id.desc()))
    return [remediation_service.execution_out(row) for row in rows]


@router.post("/changes/{change_id}/apply")
def apply_change(change_id: int, db: DbSession, user: CurrentUser,
                 payload: ApplyRequest | None = Body(default=None)) -> dict:
    """Record an approved change as deployed outside NetGuard: updates the network model (not the device).

    The request must carry {"confirm": true}, sent by the frontend once the user confirms the dialog.
    """
    if payload is None or payload.confirm is not True:
        raise NetGuardError('Applying a change needs the user\'s confirmation: send {"confirm": true} '
                            "after the user has approved it. Nothing was changed.")
    change = change_service.get_change(db, change_id)
    change, assessment = apply_service.apply_change(db, change, user)
    return {"change": change_service.to_out(db, change), "assessment": analysis_service.to_out(assessment)}


@router.get("/networks/{network_id}/health-check")
def health_check(network_id: int, db: DbSession, _: CurrentUser) -> dict:
    return health_service.run_health_check(db, network_id)
