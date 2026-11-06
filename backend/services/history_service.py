"""Persistence boundary for simulated providers and common analysis reports."""
from __future__ import annotations

import json
from datetime import date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.errors import NotFoundError
from backend.models.analysis_record import AnalysisRecord
from backend.schemas.insights import HistoryDetail, HistorySummary
from backend.services import health_service, network_service, topology_service


def _safe(value):
    """Defense in depth: adapters must not include secrets in a report snapshot."""
    if isinstance(value, dict):
        return {str(key): _safe(item) for key, item in value.items()
                if not any(term in str(key).lower() for term in
                           ("password", "secret", "token", "community", "credential", "private_key"))}
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def record(db: Session, user, network_id: int, kind: str, title: str, summary: dict, snapshot: dict) -> AnalysisRecord:
    network = network_service.get_network(db, network_id)
    row = AnalysisRecord(network_id=network.id, network_name=network.name, kind=kind, title=title[:150],
                         summary=_safe(summary), snapshot=_safe(snapshot), simulated=network.is_simulated,
                         created_by=user.id if user else None)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def to_out(row: AnalysisRecord, detail: bool = False):
    values = {key: getattr(row, key) for key in
              ("id", "network_id", "network_name", "kind", "title", "summary", "created_at", "simulated")}
    values.update(issue_count=row.summary.get("issue_count", 0), status=row.summary.get("status", "completed"))
    if detail:
        return HistoryDetail(**values, snapshot=_safe(row.snapshot),
                             created_by_username=row.creator.username if row.creator else None)
    return HistorySummary(**values)


def get(db: Session, record_id: int) -> AnalysisRecord:
    row = db.get(AnalysisRecord, record_id)
    if row is None:
        raise NotFoundError("History record not found")
    return row


def list_records(db: Session, network_id: int | None = None, kind: str | None = None, limit: int = 100):
    query = select(AnalysisRecord)
    if network_id is not None:
        query = query.where(AnalysisRecord.network_id == network_id)
    if kind:
        query = query.where(AnalysisRecord.kind == kind)
    return list(db.scalars(query.order_by(AnalysisRecord.id.desc()).limit(limit)))


def analyze(db: Session, user, network_id: int, kind: str = "analysis", title: str | None = None):
    network = network_service.get_network(db, network_id)
    analysis = health_service.run_health_check(db, network_id)
    topology = topology_service.get_topology(db, network_id).model_dump(mode="json")
    summary = {"issue_count": analysis["issue_count"], "status": analysis["status"], "advisory_count": analysis["advisory_count"],
               "device_count": analysis["devices_checked"], "link_count": analysis["links_checked"],
               "failing_flow_count": analysis["failing_flow_count"]}
    row = record(db, user, network_id, kind, title or f"{network.name} — {'Analysis Report' if kind == 'report' else 'Network Analysis'}",
                 summary, {"network": topology["network"], "topology": topology, "analysis": analysis})
    return to_out(row, detail=True)
