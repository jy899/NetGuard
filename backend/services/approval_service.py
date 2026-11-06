"""Separation of duties for changes: an engineer submits an analysed change, an IT Manager approves or rejects it.

Only a change whose latest assessment is complete and not rated Do not deploy can be submitted; approval is bound
to that assessment. Changing or re-analysing the change afterwards withdraws the approval.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.errors import ConflictError, ForbiddenError, ValidationFailed
from backend.core.permissions import can_approve, can_modify
from backend.models import Assessment, Change
from backend.services import history_service


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def latest_assessment(db: Session, change: Change) -> Assessment | None:
    return db.scalar(select(Assessment).where(Assessment.change_id == change.id).order_by(Assessment.id.desc()).limit(1))


def submit(db: Session, change: Change, user) -> Change:
    if not can_modify(user):
        raise ForbiddenError("Your user group does not have the permission to propose and submit changes.")
    if change.status in ("applied", "rolled_back", "failed"):
        raise ConflictError("This change has already been executed; propose a new change.")
    if change.status == "pending_approval":
        raise ConflictError("This change is already waiting for approval.")
    if change.status == "approved":
        raise ConflictError("This change is already approved.")
    assessment = latest_assessment(db, change)
    if assessment is None:
        raise ValidationFailed("Validate the change before submitting it for approval.")
    if assessment.validation_result == "INCOMPLETE":
        raise ValidationFailed("The assessment is incomplete (configuration evidence is missing); collect the "
                               "configuration and validate again.")
    if assessment.recommendation == "DO_NOT_DEPLOY":
        raise ValidationFailed("NetGuard rates this change Do not deploy; only verified changes can be submitted.")
    change.status = "pending_approval"
    change.submitted_by, change.submitted_at = user.id, _now()
    change.decided_by = change.decided_at = change.decision_note = None
    change.approved_assessment_id = assessment.id
    db.commit()
    history_service.record(db, user, change.network_id, "approval", f"Change submitted for approval: {change.device_name}",
                           {"change_id": change.id, "risk_level": assessment.risk_level, "status": "pending"},
                           {"assessment_id": assessment.id})
    return change


def decide(db: Session, change: Change, user, approve: bool, note: str | None) -> Change:
    if not can_approve(user):
        raise ForbiddenError("Your user group does not have the permission to approve or reject changes.")
    if change.status != "pending_approval":
        raise ConflictError("Only a change that is waiting for approval can be approved or rejected.")
    if change.submitted_by == user.id:
        raise ForbiddenError("A change cannot be approved by the account that submitted it.")
    assessment = latest_assessment(db, change)
    if assessment is None or assessment.id != change.approved_assessment_id:
        raise ConflictError("The change was re-analysed after submission; it must be submitted again.")
    if not approve and not (note or "").strip():
        raise ValidationFailed("Give a reason when rejecting a change.")
    change.status = "approved" if approve else "rejected"
    change.decided_by, change.decided_at = user.id, _now()
    change.decision_note = (note or "").strip()[:300] or None
    db.commit()
    history_service.record(db, user, change.network_id, "approval",
                           f"Change {'approved' if approve else 'rejected'}: {change.device_name}",
                           {"change_id": change.id, "status": change.status}, {"note": change.decision_note})
    return change


def withdraw_if_changed(change: Change) -> None:
    """Called when a change is edited or re-analysed: an approval only covers the assessment it was given for."""
    if change.status in ("pending_approval", "approved", "rejected"):
        change.status = "analyzed"
        change.approved_assessment_id = None
