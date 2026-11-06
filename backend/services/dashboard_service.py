from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.models import DEVICE_TYPES, Assessment, Change, Device, Interface, Link, Network
from backend.models.analysis_record import AnalysisRecord
from backend.schemas.dashboard import DashboardSummary, RecentAssessment, RecentNetwork
from backend.services import change_detector
from backend.services import network_service


def _latest_levels(db: Session) -> dict[int, str]:
    """Risk level of the most recent assessment of every change."""
    latest_ids = select(func.max(Assessment.id)).group_by(Assessment.change_id)
    rows = db.execute(select(Assessment.change_id, Assessment.risk_level).where(Assessment.id.in_(latest_ids))).all()
    return dict(rows)


def _recent_assessments(db: Session, limit: int = 6) -> list[RecentAssessment]:
    rows = db.scalars(select(Assessment).join(Change).order_by(Assessment.id.desc()).limit(limit)).all()
    result = []
    for a in rows:
        change = a.change
        snap = a.change_snapshot or {}  # values as analysed (the change may have been modified since)
        label = change_detector.CHANGE_TYPES.get(change.change_type, {}).get("label", change.change_type)
        target = f" {snap.get('target') or change.target_name}" if (snap.get("target") or change.target_name) else ""
        current = snap.get("current_value", change.current_value)
        proposed = snap.get("proposed_value", change.proposed_value)
        result.append(RecentAssessment(
            id=a.id, change_id=change.id, network_id=change.network_id, network_name=change.network.name,
            device_name=change.device_name, change_label=f"{label}{target}: {current} → {proposed}",
            total_risk_score=a.total_risk_score, risk_level=a.risk_level, recommendation=a.recommendation,
            saved=a.saved, created_at=a.created_at,
        ))
    return result


def get_summary(db: Session, recent_limit: int = 5) -> DashboardSummary:
    latest = _latest_levels(db)
    by_type = dict(db.execute(select(Device.device_type, func.count(Device.id)).group_by(Device.device_type)).all())
    recent = list(
        db.scalars(select(Network).order_by(Network.updated_at.desc(), Network.id.desc()).limit(recent_limit))
    )
    records = list(db.scalars(select(AnalysisRecord).order_by(AnalysisRecord.id.desc())))
    latest_analysis = {}
    for row in records:
        if row.network_id is not None and row.kind in ("analysis", "report"):
            latest_analysis.setdefault(row.network_id, row)
    from backend.services import history_service
    activity = [history_service.to_out(row).model_dump(mode="json") for row in records[:10]]
    for item in _recent_assessments(db, limit=6):
        activity.append({"id": f"assessment-{item.id}", "assessment_id": item.id,
                         "network_id": item.network_id, "network_name": item.network_name, "kind": "change",
                         "title": item.change_label, "summary": {"risk_level": item.risk_level},
                         "created_at": item.created_at.isoformat(), "issue_count": 0,
                         "status": item.recommendation, "simulated": False})
    activity.sort(key=lambda row: row["created_at"], reverse=True)
    return DashboardSummary(
        networks=db.scalar(select(func.count(Network.id))) or 0,
        devices=db.scalar(select(func.count(Device.id))) or 0,
        interfaces=db.scalar(select(func.count(Interface.id))) or 0,
        links=db.scalar(select(func.count(Link.id))) or 0,
        pending_changes=db.scalar(select(func.count(Change.id)).where(Change.status.in_(("draft", "analyzed")))) or 0,
        high_critical_changes=sum(1 for level in latest.values() if level in ("HIGH", "CRITICAL")),
        saved_assessments=db.scalar(select(func.count(Assessment.id)).where(Assessment.saved.is_(True))) or 0,
        risk_distribution={lvl: sum(1 for v in latest.values() if v == lvl) for lvl in ("LOW", "MEDIUM", "HIGH", "CRITICAL")},
        recent_assessments=_recent_assessments(db),
        detected_issues=sum(row.summary.get("issue_count", 0) for row in latest_analysis.values()),
        analysis_runs=sum(1 for row in records if row.kind == "analysis"), recent_activity=activity[:8],
        devices_by_type={t: by_type.get(t, 0) for t in DEVICE_TYPES},
        recent_networks=[
            RecentNetwork(
                id=n.id,
                name=n.name,
                network_type=n.network_type,
                device_count=n.device_count,
                link_count=n.link_count,
                updated_at=n.updated_at,
            )
            for n in network_service.to_out_many(db, recent)
        ],
    )
