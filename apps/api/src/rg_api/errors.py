"""全局错误处理与安全头。"""

from __future__ import annotations

import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from rg_contracts.errors import AppError
from rg_contracts.logging_setup import bind_request_id, get_logger, get_request_id
from starlette.middleware.base import BaseHTTPMiddleware

logger = get_logger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex[:16]
        bind_request_id(rid)
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response


def install_error_handlers(app: FastAPI) -> None:
    app.add_middleware(RequestContextMiddleware)

    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        payload = exc.to_dict()
        payload["request_id"] = get_request_id()
        logger.warning(
            "app_error",
            extra={"extra_fields": {"code": exc.code, "status": exc.http_status}},
        )
        return JSONResponse(status_code=exc.http_status, content=payload)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled_error")
        return JSONResponse(
            status_code=500,
            content={
                "code": "internal_error",
                "message": "服务内部错误",
                "request_id": get_request_id(),
            },
        )
