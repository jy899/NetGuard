"""NetGuard FastAPI application entry point.

Run from the project root:
    uvicorn backend.main:app --reload
"""
from __future__ import annotations

import logging
import mimetypes
from urllib.parse import parse_qsl, urlencode, urlsplit
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from backend.api.router import api_router
from backend.core.access import access_middleware
from backend.core.config import FRONTEND_DIR, get_settings
from backend.core.errors import register_error_handlers
from backend.database.init_db import init_db

# Windows can map .js to text/plain via the registry, which breaks ES modules.
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

PAGES_DIR = FRONTEND_DIR / "pages"
# URL path -> HTML page.
PAGE_ROUTES = {
    "/login": "login.html",
    "/dashboard": "dashboard.html",
    "/networks": "networks.html",
    "/topology": "topology.html",
    "/changes": "changes.html",
    "/reports": "reports.html",
    "/settings": "settings.html",
}
LEGACY_ROUTES = {
    "/learning": "/networks?environment=virtual",
    "/lab": "/networks?environment=virtual",
    "/networks/lab": "/networks?environment=virtual",
    "/scan": "/networks?environment=real",
    "/discover": "/topology",
    "/validation": "/changes?tab=validation",
}

# The frontend loads every script, stylesheet and font from /static (no CDN, no inline
# <script>). Inline styles stay allowed: pages and Cytoscape set style attributes.
# Node icons are data: SVG images.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; "
    "frame-ancestors 'none'"
)
# FastAPI's Swagger UI (/docs) and ReDoc load their assets from a CDN with an inline script.
DOCS_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; img-src 'self' data: https://fastapi.tiangolo.com https://cdn.redoc.ly; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://fonts.gstatic.com; "
    "worker-src 'self' blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}
DOCS_PATHS = ("/docs", "/redoc")


async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    docs = request.url.path.startswith(DOCS_PATHS)
    response.headers.setdefault("Content-Security-Policy",
                                DOCS_CONTENT_SECURITY_POLICY if docs else CONTENT_SECURITY_POLICY)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.url.path.startswith("/static/") and not request.url.path.startswith("/static/vendor/"):
        # App modules change between versions; revalidate (ETag) so an upgrade never runs stale JS/CSS.
        response.headers.setdefault("Cache-Control", "no-cache")
    return response


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()  # idempotent: creates missing tables and the default user
    try:
        from backend.services import remediation_service

        remediation_service.recover_pending()  # production changes left awaiting confirmation by a restart
    except Exception:  # noqa: BLE001 - recovery must never prevent NetGuard from starting
        import logging

        logging.getLogger("netguard").exception("Recovery of pending production changes failed")
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=f"{settings.app_name} API",
        description="Credential-minimal discovery, evidence-graded topology, validation and approved laboratory remediation.",
        lifespan=lifespan,
    )
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    app.middleware("http")(add_security_headers)
    app.middleware("http")(access_middleware)  # added last, so it runs first
    register_error_handlers(app)
    app.include_router(api_router)

    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse(url="/login")

    def make_page_handler(filename: str):
        def handler():
            return FileResponse(PAGES_DIR / filename, headers={"Cache-Control": "no-cache"})

        return handler

    for path, filename in PAGE_ROUTES.items():
        app.add_api_route(path, make_page_handler(filename), methods=["GET"], include_in_schema=False)

    def make_legacy_handler(destination):
        def handler(request: Request):
            parts = urlsplit(destination)
            params = dict(request.query_params)
            params.update(dict(parse_qsl(parts.query)))
            query = urlencode(params)
            return RedirectResponse(parts.path + ('?' + query if query else ''), status_code=307)
        return handler

    for path, destination in LEGACY_ROUTES.items():
        app.add_api_route(path, make_legacy_handler(destination), methods=["GET"], include_in_schema=False)

    return app


app = create_app()
