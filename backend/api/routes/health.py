from fastapi import APIRouter

from backend.api.deps import AppSettings

router = APIRouter(tags=["health"])


@router.get("/health")
def health(settings: AppSettings) -> dict:
    return {"status": "ok", "application": settings.app_name}
