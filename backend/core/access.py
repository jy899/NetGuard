"""Local-only access controls for the NetGuard service.

* Host-header validation: only 127.0.0.1 / localhost are accepted, which defeats DNS-rebinding attacks from a
  web page that resolves its own domain to 127.0.0.1.
* Desktop gate: the Windows desktop application starts the service with a per-launch key and opens its window
  with that key. Browser access to the same local service is disabled by default and is enabled only when an
  administrator turns on web access with a command (see backend/cli.py), stored in data/settings.json.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from backend.core.config import get_settings

DESKTOP_COOKIE = "netguard_desktop"


def read_app_settings() -> dict:
    path = Path(get_settings().settings_file)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_app_settings(**values) -> dict:
    path = Path(get_settings().settings_file)
    data = {**read_app_settings(), **values}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    return data


def web_access_enabled() -> bool:
    return bool(read_app_settings().get("web_access", False))


def _host_ok(request: Request) -> bool:
    host = (request.headers.get("host") or "").strip().lower()
    if host.startswith("["):  # [::1]:port
        name = host[1:].split("]", 1)[0]
        name = "localhost" if name == "::1" else name
    else:
        name = host.rsplit(":", 1)[0] if ":" in host else host
    return name in {h.lower() for h in get_settings().allowed_hosts}


async def access_middleware(request: Request, call_next):
    settings = get_settings()
    if not _host_ok(request):
        return JSONResponse(status_code=421, content={"error": "invalid_host",
                                                      "detail": "NetGuard only answers requests addressed to 127.0.0.1 or localhost."})
    key = settings.desktop_key
    if key:
        if request.url.path == "/desktop-session":
            supplied = request.query_params.get("key", "")
            if secrets.compare_digest(supplied, key):
                response = RedirectResponse(url="/login", status_code=303)
                response.set_cookie(DESKTOP_COOKIE, key, httponly=True, samesite="strict", path="/")
                return response
            return HTMLResponse("Invalid desktop session.", status_code=403)
        cookie = request.cookies.get(DESKTOP_COOKIE, "")
        if not secrets.compare_digest(cookie, key) and not web_access_enabled():
            message = ("Web access to NetGuard is disabled. Use the NetGuard desktop application, or ask an "
                       "administrator to run: NetGuard --enable-web-access")
            if request.url.path.startswith("/api/"):
                return JSONResponse(status_code=403, content={"error": "web_access_disabled", "detail": message})
            return HTMLResponse(f"<!doctype html><title>NetGuard</title><p style='font-family:sans-serif'>{message}</p>",
                                status_code=403)
    return await call_next(request)
