"""Domain exceptions and their JSON error handlers.

Services raise these exceptions; routes stay thin. Every error response has
the shape ``{"error": "<code>", "detail": "<human readable message>"}``.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("netguard")


class NetGuardError(Exception):
    status_code = status.HTTP_400_BAD_REQUEST
    code = "bad_request"

    def __init__(self, detail: str, headers: dict | None = None):
        super().__init__(detail)
        self.detail = detail
        self.headers = headers


class NotFoundError(NetGuardError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"


class ConflictError(NetGuardError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"


class ValidationFailed(NetGuardError):
    status_code = 422
    code = "validation_error"


class AuthenticationError(NetGuardError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "unauthorized"


class ForbiddenError(NetGuardError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "forbidden"


class TooManyAttemptsError(NetGuardError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "too_many_attempts"


def _error(status_code: int, code: str, detail: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": code, "detail": detail}, headers=headers)


def _format_validation_errors(exc: RequestValidationError) -> str:
    messages = []
    for err in exc.errors():
        location = [str(part) for part in err.get("loc", ()) if part not in ("body", "query", "path")]
        field = ".".join(location)
        message = str(err.get("msg", "Invalid value")).removeprefix("Value error, ")
        messages.append(f"{field}: {message}" if field else message)
    return "; ".join(messages) or "Invalid request"


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(NetGuardError)
    async def handle_domain_error(_: Request, exc: NetGuardError):
        headers = {"WWW-Authenticate": "Bearer"} if isinstance(exc, AuthenticationError) else exc.headers
        return _error(exc.status_code, exc.code, exc.detail, headers)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(_: Request, exc: RequestValidationError):
        return _error(422, "validation_error", _format_validation_errors(exc))

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(_: Request, exc: StarletteHTTPException):
        return _error(exc.status_code, "http_error", str(exc.detail))

    @app.exception_handler(OverflowError)
    async def handle_overflow(_: Request, exc: OverflowError):
        # An identifier or number larger than SQLite's 64-bit integers cannot match any stored record.
        return _error(422, "validation_error", "A numeric identifier or value is out of range.")

    @app.exception_handler(Exception)
    async def handle_unexpected(_: Request, exc: Exception):
        logger.exception("Unhandled server error: %s", exc)
        return _error(status.HTTP_500_INTERNAL_SERVER_ERROR, "server_error", "An unexpected server error occurred.")
