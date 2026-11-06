"""Advisory AI: model status, network insights, syslog classification and retraining."""
from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.api.deps import CurrentUser, DbSession
from backend.services import ai_engine, health_service, network_service

router = APIRouter(prefix="/ai", tags=["ai"])


class SyslogIn(BaseModel):
    lines: list[str] = Field(min_length=1, max_length=500)


class RetrainIn(BaseModel):
    include_local: bool = True


@router.get("/status")
def status(db: DbSession, user: CurrentUser):
    return ai_engine.status(db)


@router.get("/networks/{network_id}/insights")
def insights(network_id: int, db: DbSession, user: CurrentUser):
    network_service.get_network(db, network_id)
    report = health_service.run_health_check(db, network_id, verify_fixes=True)
    return _store(db, network_id, report)


@router.post("/networks/{network_id}/insights")
def refresh_insights(network_id: int, db: DbSession, user: CurrentUser):
    return insights(network_id, db, user)


@router.post("/syslog/classify")
def classify(body: SyslogIn, user: CurrentUser):
    return {"rows": ai_engine.classify_syslog([line[:1000] for line in body.lines]), "advisory": ai_engine.ADVISORY}


@router.post("/retrain")
def retrain(body: RetrainIn, db: DbSession, user: CurrentUser):
    manifest = ai_engine.retrain(db, body.include_local)
    return {"metrics": manifest["metrics"], "local_outcomes": manifest["local_outcomes"],
            "trained_at": manifest["trained_at"], "status": ai_engine.status(db)}


def _store(db, network_id: int, report: dict) -> dict:
    from sqlalchemy import delete
    from backend.models import AiInsight
    ai = report.get("ai") or {}
    db.execute(delete(AiInsight).where(AiInsight.network_id == network_id, AiInsight.kind == "network"))
    db.add(AiInsight(network_id=network_id, kind="network", model_version=ai.get("model_version") or 0, payload=ai))
    db.commit()
    names = {i["rule_id"] + "|" + i["subject"]: i for i in report.get("issues", [])}
    return {**ai, "network_id": network_id, "issue_count": report.get("issue_count", 0),
            "fixes": [{"issue": key, "name": issue["name"], "fixes": [
                {"label": f["label"], "verdict": (f.get("verification") or {}).get("verdict"), "ai": f.get("ai")}
                for f in issue.get("fixes", [])]} for key, issue in names.items()]}
