"""Proposed change CRUD. Analysis lives in analysis_service."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from backend.core.errors import ConflictError, NotFoundError, ValidationFailed
from backend.models import Assessment, Change, Device, User
from backend.schemas.change import AssessmentBrief, ChangeCreate, ChangeOut
from backend.services import change_detector, network_service
from backend.services.network_model import load_model
from backend.services.rules import CATEGORY_LABELS


def get_change(db: Session, change_id: int) -> Change:
    change = db.get(Change, change_id)
    if change is None:
        raise NotFoundError(f"Change {change_id} not found")
    return change


def to_out(db: Session, change: Change) -> ChangeOut:
    latest = db.scalar(select(Assessment).where(Assessment.change_id == change.id).order_by(Assessment.id.desc()).limit(1))
    count = db.scalar(select(func.count(Assessment.id)).where(Assessment.change_id == change.id)) or 0
    return ChangeOut(
        id=change.id, network_id=change.network_id, network_name=change.network.name if change.network else None,
        device_id=change.device_id, device_name=change.device_name, interface_id=change.interface_id,
        target_name=change.target_name, category=change.category,
        category_label=CATEGORY_LABELS.get(change.category, change.category), change_type=change.change_type,
        change_type_label=change_detector.CHANGE_TYPES.get(change.change_type, {}).get("label", change.change_type),
        current_value=change.current_value, proposed_value=change.proposed_value, parameters=change.parameters or {},
        reason=change.reason, status=change.status,
        created_by_username=change.creator.username if change.creator else None,
        created_at=change.created_at, updated_at=change.updated_at, assessment_count=count,
        approval={"submitted_by": change.submitter.username if change.submitter else None,
                  "submitted_at": change.submitted_at, "decided_by": change.decider.username if change.decider else None,
                  "decided_at": change.decided_at, "note": change.decision_note,
                  "assessment_id": change.approved_assessment_id},
        lab_device=bool(change.device and change.device.is_lab),
        self_healing=_self_healing(db, change),
        latest_assessment=AssessmentBrief(
            id=latest.id, total_risk_score=latest.total_risk_score, risk_level=latest.risk_level,
            recommendation=latest.recommendation, validation_result=latest.validation_result,
            saved=latest.saved, created_at=latest.created_at,
        ) if latest else None,
    )


def _self_healing(db, change) -> dict:
    from backend.models import ChangeExecution
    from backend.services import remediation_service

    settings = remediation_service.self_healing_settings()
    latest = db.scalar(select(ChangeExecution).where(ChangeExecution.change_id == change.id)
                       .order_by(ChangeExecution.id.desc()).limit(1))
    return {"production": not bool(change.device and change.device.is_lab), "enabled": settings["enabled"],
            "confirm_minutes": settings["confirm_minutes"],
            "confirm_by": (latest.verification or {}).get("confirm_by") if latest is not None and latest.status == "awaiting_confirm" else None}


def list_changes(db: Session, network_id: int | None = None, status: str | None = None) -> list[Change]:
    query = select(Change).options(selectinload(Change.network), selectinload(Change.creator))
    if network_id is not None:
        query = query.where(Change.network_id == network_id)
    if status:
        query = query.where(Change.status == status)
    return list(db.scalars(query.order_by(Change.updated_at.desc(), Change.id.desc())))


def _detect(db: Session, network_id: int, data: ChangeCreate):
    model = load_model(db, network_id)
    return change_detector.detect(model, data.device_id, data.interface_id, data.change_type, data.parameters)


def _apply_detected(change: Change, detected, reason: str | None) -> None:
    change.device_id = detected.device_id
    change.device_name = detected.device_name
    change.interface_id = detected.interface_id
    change.target_name = detected.target_name
    change.category = detected.category
    change.change_type = detected.change_type
    change.parameters = detected.parameters
    change.current_value = detected.current_value
    change.proposed_value = detected.proposed_value
    change.reason = reason


def create_change(db: Session, data: ChangeCreate, user: User | None) -> Change:
    device = db.get(Device, data.device_id)
    if device is None:
        raise ValidationFailed(f"Device {data.device_id} not found")
    detected = _detect(db, device.network_id, data)
    change = Change(network_id=device.network_id, status="draft", created_by=user.id if user else None)
    _apply_detected(change, detected, data.reason)
    db.add(change)
    db.commit()
    db.refresh(change)
    return change


def update_change(db: Session, change_id: int, data: ChangeCreate) -> Change:
    """Modify a proposed change (brief: 'Modify Change -> Re-analyze')."""
    change = get_change(db, change_id)
    if change.status in ("applied", "rolled_back", "failed"):
        raise ConflictError("This change has already been executed; propose a new change instead")
    device = db.get(Device, data.device_id)
    if device is None or device.network_id != change.network_id:
        raise ValidationFailed("The device must belong to the change's network")
    detected = _detect(db, change.network_id, data)
    _apply_detected(change, detected, data.reason)
    change.status = "draft"
    change.approved_assessment_id = None
    db.commit()
    db.refresh(change)
    return change


def delete_change(db: Session, change_id: int) -> None:
    change = get_change(db, change_id)
    if change.status in ("applied", "rolled_back", "failed"):
        raise ConflictError("An executed change is part of the audit history and cannot be deleted")
    db.delete(change)
    db.commit()


def ensure_network(db: Session, network_id: int | None) -> None:
    if network_id is not None:
        network_service.get_network(db, network_id)
