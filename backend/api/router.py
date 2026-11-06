"""Aggregates all API routers under /api."""
from fastapi import APIRouter

from backend.api.routes import auth, changes, config, dashboard, devices, health, interfaces, labs, links, networks
from backend.api.routes import accounts
from backend.api.routes import credentials, discovery, insights
from backend.api.routes import ai
from backend.api.routes import terminal

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(accounts.router)
api_router.include_router(credentials.router)
api_router.include_router(insights.router)
api_router.include_router(discovery.router)
api_router.include_router(dashboard.router)
api_router.include_router(networks.router)
api_router.include_router(devices.router)
api_router.include_router(interfaces.router)
api_router.include_router(links.router)
api_router.include_router(config.router)
api_router.include_router(changes.router)
api_router.include_router(labs.router)
api_router.include_router(ai.router)
api_router.include_router(terminal.router)
