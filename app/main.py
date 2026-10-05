"""App factory del gateway LLM."""
from __future__ import annotations

import logging
import secrets
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.chat import router as chat_router
from app.config import Settings, get_settings
from app.core.prompt_builder import PromptBuilder
from app.observability.secure_logger import setup_logging
from app.providers.clients import build_provider
from app.resilience.errors import problem
from app.security.auth import ClientRegistry
from app.security.output_guard import OutputGuard
from app.security.rate_limit import ClientRateLimiter


def create_app(settings: Settings | None = None,
               upstream_transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = settings or get_settings()
    setup_logging(settings)
    canary = settings.canary_token.get_secret_value() or f"CANARY-{secrets.token_hex(8)}"
    provider = build_provider(settings, upstream_transport)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        await provider.aclose()

    production = settings.environment == "production"
    app = FastAPI(
        title="LLM Gateway",
        # Linea base vulnerable: debug=True devuelve trazas al cliente.
        debug=not settings.safe_errors_on,
        docs_url=None if production else "/docs",
        redoc_url=None,
        openapi_url=None if production else "/openapi.json",
        lifespan=lifespan,
    )
    s = app.state
    s.settings = settings
    s.registry = ClientRegistry(settings)
    s.limiter = ClientRateLimiter(settings.rate_limit_default, settings.rate_limit_storage_uri)
    s.prompt_builder = PromptBuilder(settings.system_prompt_file, canary)
    s.output_guard = OutputGuard(s.prompt_builder.system_prompt, canary, settings.leak_ngram_words)
    s.provider = provider
    s.ops_log = logging.getLogger("gateway.ops")

    if settings.safe_errors_on:
        @app.exception_handler(Exception)
        async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
            rid = uuid.uuid4().hex[:16]
            s.ops_log.error("error no controlado request_id=%s", rid, exc_info=exc)
            return problem(500, "INTERNAL_ERROR", "Error interno del gateway.", rid)

    @app.get("/health")
    async def health():
        return {"status": "ok", "profile": settings.gateway_profile,
                "circuit": provider.breaker.state}

    app.include_router(chat_router)
    return app


