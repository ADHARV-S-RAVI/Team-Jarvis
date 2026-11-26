"""FastAPI application factory for Q-SHIELD Stage 2 Backend Foundation."""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging
import uuid

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.v1.router import router as v1_router
from backend.app.config import get_settings
from backend.app.crypto.provider import run_crypto_self_test
from backend.app.datalab.worker import background_worker
from backend.app.db.session import SessionLocal
from backend.app.devices.service import DomainPermissionError
from backend.app.services.foundation_service import (
    DomainConflictError,
    DomainNotFoundError,
    DomainValidationError,
)


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    _configure_logging(settings.log_level)
    run_crypto_self_test()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        background_worker.start(SessionLocal)
        try:
            yield
        finally:
            background_worker.stop()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def correlation_id_middleware(request: Request, call_next):
        cid = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        request.state.correlation_id = cid
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = cid
        return response

    @app.exception_handler(DomainConflictError)
    async def handle_conflict(request: Request, exc: DomainConflictError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "error": "conflict",
                "message": str(exc),
                "correlation_id": getattr(request.state, "correlation_id", "unknown"),
            },
        )

    @app.exception_handler(DomainNotFoundError)
    async def handle_not_found(request: Request, exc: DomainNotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "error": "not_found",
                "message": str(exc),
                "correlation_id": getattr(request.state, "correlation_id", "unknown"),
            },
        )

    @app.exception_handler(DomainValidationError)
    async def handle_domain_validation(request: Request, exc: DomainValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "validation_error",
                "message": str(exc),
                "correlation_id": getattr(request.state, "correlation_id", "unknown"),
            },
        )

    @app.exception_handler(DomainPermissionError)
    async def handle_domain_permission(request: Request, exc: DomainPermissionError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "forbidden",
                "message": str(exc),
                "correlation_id": getattr(request.state, "correlation_id", "unknown"),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation(request: Request, _exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "invalid_request",
                "message": "Request validation failed",
                "correlation_id": getattr(request.state, "correlation_id", "unknown"),
            },
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "internal_error",
                "message": "An unexpected internal error occurred",
                "correlation_id": getattr(request.state, "correlation_id", "unknown"),
            },
        )

    app.include_router(v1_router)
    return app


app = create_app()
