from fastapi import APIRouter

from backend.api.deps import CurrentUser, DbSession
from backend.schemas.dashboard import DashboardSummary
from backend.services import dashboard_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def summary(db: DbSession, _: CurrentUser):
    return dashboard_service.get_summary(db)
